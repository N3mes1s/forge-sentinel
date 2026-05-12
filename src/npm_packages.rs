use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::cli::NpmPackageInspectArgs;
use crate::detection_model::{FactorKind, factor_meta, humanize_factor};

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex")
}

static GITHUB_OPTIONAL_DEP_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)^(?:git\+)?https://github\.com/[^#\s]+#[0-9a-f]{7,40}$|^github:[^#\s]+#[0-9a-f]{7,40}$",
    )
});
static LIFECYCLE_PAYLOAD_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)\b(node|bun|deno|bash|sh|python|perl|ruby|curl|wget|powershell|pwsh)\b"));
static CREDENTIAL_HARVEST_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|GITHUB_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|CLOUDFLARE_API_TOKEN|\.npmrc|\.pypirc|\.ssh|id_rsa|git-credentials|\.docker/config\.json|kubeconfig|169\.254\.169\.254)",
    )
});
static RUNNER_MEMORY_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?i)(/proc/[^ \n\r]*/(mem|maps|cmdline)|Runner\.(Worker|Listener)|isSecret)")
});
static PACKAGE_OIDC_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token|registry\.npmjs\.org/-/npm/v1/oidc/token)",
    )
});
static SESSION_EXFIL_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(filev2\.getsession\.org|seed[0-9]+\.getsession\.org|getsession\.org|session(?:\.js|app|get-session)|oxen|0x0\.st|transfer\.sh|bashupload|file\.io|oshi\.at|discord(?:app)?\.com/api/webhooks|api\.telegram\.org)",
    )
});

static NPM_CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("forge-sentinel/0.1 native-rust"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(45))
        .build()
        .expect("valid npm HTTP client")
});

#[derive(Debug, Serialize)]
struct NpmFinding {
    target: String,
    score: i32,
    factors: Vec<String>,
    evidence: Vec<String>,
    evidence_files: Vec<String>,
}

#[derive(Debug)]
struct PackageVersionMetadata {
    target: String,
    name: String,
    version: String,
    tarball_url: String,
    publish_time: Option<String>,
    version_metadata: Value,
}

#[derive(Debug)]
struct PackageSnapshot {
    target: String,
    package_json: Option<Value>,
    files: Vec<PackageFile>,
}

#[derive(Debug)]
struct PackageFile {
    path: String,
    text: Option<String>,
    size: usize,
}

pub(crate) fn run_inspect(args: NpmPackageInspectArgs) -> Result<i32> {
    let mut findings = Vec::new();
    let evidence_dir = args.evidence_dir.as_deref();
    let metadata_files = load_metadata_files(&args.metadata_files)?;

    for package_spec in &args.package_specs {
        let metadata =
            if let Some(metadata_value) = metadata_for_spec(package_spec, &metadata_files) {
                resolve_package_spec_from_metadata(package_spec, metadata_value.clone())?
            } else {
                resolve_package_spec(package_spec)?
            };
        let mut evidence_files = Vec::new();
        snapshot_metadata(evidence_dir, &metadata, &mut evidence_files)?;
        if metadata.tarball_url.is_empty() {
            let mut finding = unavailable_tarball_finding(
                &metadata,
                "version metadata or tarball URL is absent from captured npm metadata",
                args.show_evidence,
            );
            finding.evidence_files = evidence_files;
            snapshot_finding(evidence_dir, &finding)?;
            findings.push(finding);
            continue;
        }
        let bytes = match fetch_bytes(&metadata.tarball_url) {
            Ok(bytes) => bytes,
            Err(error) => {
                let mut finding =
                    unavailable_tarball_finding(&metadata, &error.to_string(), args.show_evidence);
                finding.evidence_files = evidence_files;
                snapshot_finding(evidence_dir, &finding)?;
                findings.push(finding);
                continue;
            }
        };
        snapshot_tarball(evidence_dir, &metadata.target, &bytes, &mut evidence_files)?;
        let snapshot = inspect_tarball_bytes(&metadata.target, &bytes)?;
        if let Some(finding) = analyze_package(snapshot, args.show_evidence) {
            let mut finding = finding;
            if !evidence_files.is_empty() {
                add_factor(&mut finding, 0, "npm_package_metadata_snapshot");
                add_factor(&mut finding, 0, "npm_package_tarball_snapshot");
                finding.evidence_files = evidence_files;
            }
            snapshot_finding(evidence_dir, &finding)?;
            findings.push(finding);
        }
    }

    for tarball in &args.tarballs {
        let bytes = if tarball.starts_with("http://") || tarball.starts_with("https://") {
            fetch_bytes(tarball)?
        } else {
            fs::read(tarball).with_context(|| format!("read tarball {tarball}"))?
        };
        let target = Path::new(tarball)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(tarball)
            .to_string();
        let mut evidence_files = Vec::new();
        snapshot_raw_tarball(evidence_dir, &target, &bytes, &mut evidence_files)?;
        let snapshot = inspect_tarball_bytes(&target, &bytes)?;
        if let Some(finding) = analyze_package(snapshot, args.show_evidence) {
            let mut finding = finding;
            if !evidence_files.is_empty() {
                add_factor(&mut finding, 0, "npm_package_tarball_snapshot");
                finding.evidence_files = evidence_files;
            }
            snapshot_finding(evidence_dir, &finding)?;
            findings.push(finding);
        }
    }

    let mut exit_code = 0;
    for finding in findings
        .iter()
        .filter(|finding| finding.score >= args.min_score)
    {
        if args.json {
            println!("{}", serde_json::to_string(finding)?);
        } else {
            print_finding(finding, args.explain);
        }
        if finding.score >= 10 {
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn resolve_package_spec(spec: &str) -> Result<PackageVersionMetadata> {
    let (name, _) = parse_package_spec(spec);
    let encoded_name = if name.starts_with('@') {
        name.replacen('@', "%40", 1)
    } else {
        urlencoding::encode(&name).to_string()
    };
    let url = format!("https://registry.npmjs.org/{encoded_name}");
    let metadata: Value = NPM_CLIENT
        .get(&url)
        .send()
        .with_context(|| format!("fetch npm metadata for {name}"))?
        .error_for_status()
        .with_context(|| format!("npm metadata request failed for {name}"))?
        .json()
        .with_context(|| format!("parse npm metadata for {name}"))?;

    resolve_package_spec_from_metadata(spec, metadata)
}

fn resolve_package_spec_from_metadata(
    spec: &str,
    metadata: Value,
) -> Result<PackageVersionMetadata> {
    let (name, requested_version) = parse_package_spec(spec);
    let metadata_name = metadata
        .get("name")
        .or_else(|| metadata.get("_id"))
        .and_then(Value::as_str)
        .unwrap_or(&name);
    if metadata_name != name {
        bail!("metadata name {metadata_name} does not match requested package {name}");
    }
    let version = requested_version
        .map(str::to_string)
        .or_else(|| {
            metadata
                .get("dist-tags")
                .and_then(|tags| tags.get("latest"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .with_context(|| format!("resolve version for {spec}"))?;

    let publish_time = metadata
        .get("time")
        .and_then(|time| time.get(&version))
        .and_then(Value::as_str)
        .map(str::to_string);
    let version_metadata = metadata
        .get("versions")
        .and_then(|versions| versions.get(&version))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "metadata_removed": true,
                "note": "package root metadata has a publish time for this version but no version entry"
            })
        });
    let tarball = version_metadata
        .get("dist")
        .and_then(|dist| dist.get("tarball"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if tarball.is_empty() && publish_time.is_none() {
        bail!("resolve metadata for {name}@{version}");
    }

    Ok(PackageVersionMetadata {
        target: format!("{name}@{version}"),
        name,
        version,
        tarball_url: tarball.to_string(),
        publish_time,
        version_metadata,
    })
}

fn load_metadata_files(paths: &[PathBuf]) -> Result<Vec<Value>> {
    paths
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path)
                .with_context(|| format!("read metadata file {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parse metadata file {}", path.display()))
        })
        .collect()
}

fn metadata_for_spec<'a>(spec: &str, metadata_files: &'a [Value]) -> Option<&'a Value> {
    let (name, _) = parse_package_spec(spec);
    metadata_files.iter().find(|metadata| {
        metadata
            .get("name")
            .or_else(|| metadata.get("_id"))
            .and_then(Value::as_str)
            .is_some_and(|metadata_name| metadata_name == name)
    })
}

fn parse_package_spec(spec: &str) -> (String, Option<&str>) {
    if let Some(rest) = spec.strip_prefix('@') {
        if let Some(slash_index) = rest.find('/') {
            let after_name = &rest[slash_index + 1..];
            if let Some(version_index) = after_name.rfind('@') {
                let name_end = 1 + slash_index + 1 + version_index;
                return (
                    spec[..name_end].to_string(),
                    Some(&after_name[version_index + 1..]),
                );
            }
        }
        return (spec.to_string(), None);
    }

    if let Some(version_index) = spec.rfind('@') {
        if version_index > 0 {
            return (
                spec[..version_index].to_string(),
                Some(&spec[version_index + 1..]),
            );
        }
    }
    (spec.to_string(), None)
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    let response = NPM_CLIENT
        .get(url)
        .send()
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("request failed for {url}"))?;
    Ok(response.bytes()?.to_vec())
}

fn inspect_tarball_bytes(target: &str, bytes: &[u8]) -> Result<PackageSnapshot> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut package_json = None;
    let mut files = Vec::new();

    for entry in archive.entries().context("read npm tarball entries")? {
        let mut entry = entry.context("read npm tarball entry")?;
        let path = entry
            .path()
            .context("read tarball entry path")?
            .to_string_lossy()
            .to_string();
        let size = entry.size() as usize;
        let mut raw = Vec::new();
        if size <= 8_000_000 {
            entry.read_to_end(&mut raw)?;
        }
        let text = String::from_utf8(raw).ok();
        if path.ends_with("package.json") {
            if let Some(text) = &text {
                package_json = serde_json::from_str(text).ok();
            }
        }
        files.push(PackageFile { path, text, size });
    }

    if files.is_empty() {
        bail!("tarball has no readable entries");
    }

    Ok(PackageSnapshot {
        target: target.to_string(),
        package_json,
        files,
    })
}

fn analyze_package(snapshot: PackageSnapshot, show_evidence: bool) -> Option<NpmFinding> {
    let mut finding = NpmFinding {
        target: snapshot.target,
        score: 0,
        factors: Vec::new(),
        evidence: Vec::new(),
        evidence_files: Vec::new(),
    };

    let scripts = snapshot
        .package_json
        .as_ref()
        .and_then(|package| package.get("scripts"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let lifecycle_scripts = ["preinstall", "install", "postinstall", "prepare"]
        .iter()
        .filter_map(|name| {
            scripts
                .get(*name)
                .and_then(Value::as_str)
                .map(|value| (*name, value))
        })
        .collect::<Vec<_>>();
    let has_lifecycle_payload = lifecycle_scripts
        .iter()
        .any(|(_, script)| LIFECYCLE_PAYLOAD_RE.is_match(script));

    let github_optional_dependencies = snapshot
        .package_json
        .as_ref()
        .and_then(|package| package.get("optionalDependencies"))
        .and_then(Value::as_object)
        .map(|dependencies| {
            dependencies
                .iter()
                .filter_map(|(name, value)| {
                    let spec = value.as_str()?;
                    GITHUB_OPTIONAL_DEP_RE
                        .is_match(spec)
                        .then(|| format!("{name}@{spec}"))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !github_optional_dependencies.is_empty() {
        add_factor(
            &mut finding,
            8,
            "npm_package_github_optional_dependency_payload",
        );
        if show_evidence {
            finding.evidence.extend(
                github_optional_dependencies
                    .iter()
                    .take(5)
                    .map(|dependency| format!("optionalDependency: {dependency}")),
            );
        }
    }

    if has_lifecycle_payload {
        add_factor(
            &mut finding,
            2,
            "npm_package_lifecycle_script_executes_payload",
        );
        if !github_optional_dependencies.is_empty() {
            add_factor(
                &mut finding,
                5,
                "npm_package_optional_dependency_install_chain",
            );
        }
        if show_evidence {
            finding.evidence.extend(
                lifecycle_scripts
                    .iter()
                    .take(5)
                    .map(|(name, script)| format!("script {name}: {script}")),
            );
        }
    }

    let joined_text = snapshot
        .files
        .iter()
        .filter_map(|file| file.text.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    let credential_hits = CREDENTIAL_HARVEST_RE.find_iter(&joined_text).count();
    if credential_hits >= 3 {
        add_factor(&mut finding, 7, "npm_package_credential_harvesting_payload");
    }
    if RUNNER_MEMORY_RE.is_match(&joined_text) && PACKAGE_OIDC_RE.is_match(&joined_text) {
        add_factor(&mut finding, 7, "npm_package_runner_memory_oidc_harvesting");
    }
    if SESSION_EXFIL_RE.is_match(&joined_text) && credential_hits > 0 {
        add_factor(&mut finding, 6, "npm_package_session_network_exfiltration");
    }

    for file in &snapshot.files {
        let root_js = file.path.matches('/').count() <= 1 && file.path.ends_with(".js");
        if root_js && file.size >= 100_000 {
            add_factor(&mut finding, 2, "npm_package_large_root_javascript_payload");
            if show_evidence {
                finding.evidence.push(format!(
                    "large root JavaScript: {} bytes {}",
                    file.size, file.path
                ));
            }
        }
    }

    let package_files = snapshot
        .package_json
        .as_ref()
        .and_then(|package| package.get("files"))
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !package_files.is_empty()
        && snapshot.files.iter().any(|file| {
            file.path.matches('/').count() <= 1
                && file.path.ends_with(".js")
                && !package_files
                    .iter()
                    .any(|allowed| file.path.ends_with(allowed))
        })
    {
        add_factor(&mut finding, 1, "npm_package_unlisted_root_payload");
    }

    if finding.score > 0 {
        Some(finding)
    } else {
        None
    }
}

fn unavailable_tarball_finding(
    metadata: &PackageVersionMetadata,
    error: &str,
    show_evidence: bool,
) -> NpmFinding {
    let mut finding = NpmFinding {
        target: metadata.target.clone(),
        score: 8,
        factors: Vec::new(),
        evidence: Vec::new(),
        evidence_files: Vec::new(),
    };
    add_factor(&mut finding, 0, "npm_package_tarball_unavailable_forensics");
    add_factor(&mut finding, 0, "npm_package_metadata_snapshot");
    if show_evidence {
        if let Some(publish_time) = &metadata.publish_time {
            finding
                .evidence
                .push(format!("publish_time: {publish_time}"));
        }
        finding
            .evidence
            .push(format!("tarball_url: {}", metadata.tarball_url));
        finding.evidence.push(format!("fetch_error: {error}"));
        if let Some(time) = metadata.version_metadata.get("_npmUser") {
            finding.evidence.push(format!("npm_user: {time}"));
        }
        if let Some(git_head) = metadata
            .version_metadata
            .get("gitHead")
            .and_then(Value::as_str)
        {
            finding.evidence.push(format!("gitHead: {git_head}"));
        }
    }
    finding
}

fn add_factor(finding: &mut NpmFinding, score: i32, factor: &str) {
    finding.score += score;
    if !finding.factors.iter().any(|existing| existing == factor) {
        finding.factors.push(factor.to_string());
    }
}

fn snapshot_metadata(
    evidence_dir: Option<&Path>,
    metadata: &PackageVersionMetadata,
    evidence_files: &mut Vec<String>,
) -> Result<()> {
    let Some(evidence_dir) = evidence_dir else {
        return Ok(());
    };
    let package_dir = package_evidence_dir(evidence_dir, &metadata.target);
    fs::create_dir_all(&package_dir)?;
    let metadata_path = package_dir.join("metadata.json");
    let value = serde_json::json!({
        "target": metadata.target,
        "name": metadata.name,
        "version": metadata.version,
        "publish_time": metadata.publish_time,
        "tarball_url": metadata.tarball_url,
        "version_metadata": metadata.version_metadata,
    });
    fs::write(&metadata_path, serde_json::to_vec_pretty(&value)?)?;
    evidence_files.push(metadata_path.display().to_string());
    Ok(())
}

fn snapshot_tarball(
    evidence_dir: Option<&Path>,
    target: &str,
    bytes: &[u8],
    evidence_files: &mut Vec<String>,
) -> Result<()> {
    let Some(evidence_dir) = evidence_dir else {
        return Ok(());
    };
    snapshot_raw_tarball(evidence_dir.into(), target, bytes, evidence_files)
}

fn snapshot_raw_tarball(
    evidence_dir: Option<&Path>,
    target: &str,
    bytes: &[u8],
    evidence_files: &mut Vec<String>,
) -> Result<()> {
    let Some(evidence_dir) = evidence_dir else {
        return Ok(());
    };
    let package_dir = package_evidence_dir(evidence_dir, target);
    fs::create_dir_all(&package_dir)?;
    let sha256 = sha256_hex(bytes);
    let tarball_path = package_dir.join(format!("{sha256}.tgz"));
    fs::write(&tarball_path, bytes)?;
    let digest_path = package_dir.join("tarball.sha256");
    fs::write(
        &digest_path,
        format!("{sha256}  {}\n", tarball_path.display()),
    )?;
    evidence_files.push(tarball_path.display().to_string());
    evidence_files.push(digest_path.display().to_string());
    Ok(())
}

fn snapshot_finding(evidence_dir: Option<&Path>, finding: &NpmFinding) -> Result<()> {
    let Some(evidence_dir) = evidence_dir else {
        return Ok(());
    };
    let package_dir = package_evidence_dir(evidence_dir, &finding.target);
    fs::create_dir_all(&package_dir)?;
    let finding_path = package_dir.join("finding.json");
    fs::write(&finding_path, serde_json::to_vec_pretty(finding)?)?;
    Ok(())
}

fn package_evidence_dir(root: &Path, target: &str) -> PathBuf {
    root.join("npm").join(sanitize_filename(target))
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn print_finding(finding: &NpmFinding, explain: bool) {
    let severity = if finding.score >= 10 {
        "CRITICAL"
    } else if finding.score >= 7 {
        "HIGH"
    } else {
        "SUSPICIOUS"
    };
    println!("{severity} score={} {}", finding.score, finding.target);
    println!("  factors: {}", finding.factors.join(", "));
    if !finding.evidence.is_empty() {
        println!("  evidence:");
        for item in &finding.evidence {
            println!("    - {item}");
        }
    }
    if !finding.evidence_files.is_empty() {
        println!("  evidence_files:");
        for item in &finding.evidence_files {
            println!("    - {item}");
        }
    }
    if explain {
        println!("  explanation:");
        for factor in &finding.factors {
            if let Some(meta) = factor_meta(factor) {
                println!(
                    "    - {} [{}]: {}",
                    meta.name,
                    meta.kind.as_str(),
                    meta.description
                );
            } else {
                println!("    - {factor}: {}", humanize_factor(factor));
            }
        }
        let core_count = finding
            .factors
            .iter()
            .filter(|factor| {
                factor_meta(factor)
                    .map(|meta| meta.kind == FactorKind::Core)
                    .unwrap_or(false)
            })
            .count();
        println!("    core_signals: {core_count}");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::{
        PackageFile, PackageSnapshot, PackageVersionMetadata, analyze_package, metadata_for_spec,
        package_evidence_dir, parse_package_spec, resolve_package_spec_from_metadata, sha256_hex,
        snapshot_metadata, snapshot_raw_tarball, unavailable_tarball_finding,
    };
    use serde_json::{Value, json};
    use std::fs;

    #[test]
    fn parses_scoped_and_unscoped_package_specs() {
        assert_eq!(
            parse_package_spec("@scope/name@1.2.3"),
            ("@scope/name".to_string(), Some("1.2.3"))
        );
        assert_eq!(
            parse_package_spec("@scope/name"),
            ("@scope/name".to_string(), None)
        );
        assert_eq!(
            parse_package_spec("left-pad@1.3.0"),
            ("left-pad".to_string(), Some("1.3.0"))
        );
    }

    #[test]
    fn detects_github_optional_dependency_install_chain() {
        let snapshot = PackageSnapshot {
            target: "pkg@1.0.0".to_string(),
            package_json: Some(json!({
                "scripts": {"postinstall": "node setup.js"},
                "optionalDependencies": {
                    "payload": "https://github.com/owner/repo#1234567890abcdef"
                }
            })),
            files: vec![PackageFile {
                path: "package/setup.js".to_string(),
                text: Some(
                    "console.log(process.env.GITHUB_TOKEN); fetch('https://file.io')".to_string(),
                ),
                size: 80,
            }],
        };
        let finding = analyze_package(snapshot, true).expect("finding");
        assert!(finding.score >= 10);
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_github_optional_dependency_payload")
        );
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_optional_dependency_install_chain")
        );
    }

    #[test]
    fn detects_tanstack_style_optional_dependency_payload() {
        let snapshot = PackageSnapshot {
            target: "@tanstack/history@1.161.9".to_string(),
            package_json: Some(json!({
                "name": "@tanstack/history",
                "version": "1.161.9",
                "files": ["dist"],
                "optionalDependencies": {
                    "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                }
            })),
            files: vec![PackageFile {
                path: "package/router_init.js".to_string(),
                text: Some("obfuscated payload".to_string()),
                size: 2_300_000,
            }],
        };
        let finding = analyze_package(snapshot, true).expect("finding");

        assert!(finding.score >= 10);
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_github_optional_dependency_payload")
        );
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_large_root_javascript_payload")
        );
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_unlisted_root_payload")
        );
    }

    #[test]
    fn detects_runner_memory_oidc_and_session_exfiltration() {
        let snapshot = PackageSnapshot {
            target: "pkg@1.0.0".to_string(),
            package_json: Some(json!({
                "name": "pkg",
                "version": "1.0.0"
            })),
            files: vec![PackageFile {
                path: "package/index.js".to_string(),
                text: Some(
                    "/proc/123/mem Runner.Worker ACTIONS_ID_TOKEN_REQUEST_TOKEN filev2.getsession.org GITHUB_TOKEN".to_string(),
                ),
                size: 100,
            }],
        };
        let finding = analyze_package(snapshot, true).expect("finding");

        assert!(finding.score >= 10);
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_runner_memory_oidc_harvesting")
        );
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_session_network_exfiltration")
        );
    }

    #[test]
    fn emits_removed_tarball_forensic_finding() {
        let metadata = PackageVersionMetadata {
            target: "@tanstack/history@1.161.12".to_string(),
            name: "@tanstack/history".to_string(),
            version: "1.161.12".to_string(),
            tarball_url: "https://registry.npmjs.org/@tanstack/history/-/history-1.161.12.tgz"
                .to_string(),
            publish_time: Some("2026-05-11T19:26:14.690Z".to_string()),
            version_metadata: json!({
                "gitHead": "b1c061a",
                "_npmUser": {"name": "GitHub Actions"}
            }),
        };

        let finding = unavailable_tarball_finding(&metadata, "404 Not Found", true);

        assert_eq!(finding.score, 8);
        assert!(
            finding
                .factors
                .iter()
                .any(|factor| factor == "npm_package_tarball_unavailable_forensics")
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.contains("publish_time"))
        );
        assert!(finding.evidence.iter().any(|item| item.contains("gitHead")));
    }

    #[test]
    fn resolves_package_version_from_captured_metadata() {
        let metadata = json!({
            "name": "@tanstack/history",
            "dist-tags": {"latest": "1.161.6"},
            "versions": {
                "1.161.12": {
                    "gitHead": "b1c061a",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.12.tgz"
                    }
                }
            },
            "time": {
                "1.161.12": "2026-05-11T19:26:14.690Z"
            }
        });

        assert!(metadata_for_spec("@tanstack/history@1.161.12", &[metadata.clone()]).is_some());
        let resolved =
            resolve_package_spec_from_metadata("@tanstack/history@1.161.12", metadata).unwrap();

        assert_eq!(resolved.target, "@tanstack/history@1.161.12");
        assert_eq!(
            resolved.publish_time.as_deref(),
            Some("2026-05-11T19:26:14.690Z")
        );
        assert!(resolved.tarball_url.ends_with("history-1.161.12.tgz"));
    }

    #[test]
    fn resolves_removed_version_from_publish_time_only_metadata() {
        let metadata = json!({
            "name": "@tanstack/history",
            "dist-tags": {"latest": "1.161.6"},
            "versions": {
                "1.161.6": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.6.tgz"
                    }
                }
            },
            "time": {
                "1.161.12": "2026-05-11T19:26:14.690Z"
            }
        });

        let resolved =
            resolve_package_spec_from_metadata("@tanstack/history@1.161.12", metadata).unwrap();

        assert_eq!(resolved.target, "@tanstack/history@1.161.12");
        assert_eq!(resolved.tarball_url, "");
        assert_eq!(
            resolved
                .version_metadata
                .get("metadata_removed")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn snapshots_package_evidence_with_hashes() {
        let root = std::env::temp_dir().join(format!("forge-sentinel-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let metadata = PackageVersionMetadata {
            target: "pkg@1.0.0".to_string(),
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            tarball_url: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".to_string(),
            publish_time: Some("2026-05-12T00:00:00.000Z".to_string()),
            version_metadata: json!({"dist": {"shasum": "abc"}}),
        };
        let mut evidence_files = Vec::new();

        snapshot_metadata(Some(&root), &metadata, &mut evidence_files).expect("metadata snapshot");
        snapshot_raw_tarball(
            Some(&root),
            &metadata.target,
            b"tarball",
            &mut evidence_files,
        )
        .expect("tarball snapshot");

        let package_dir = package_evidence_dir(&root, &metadata.target);
        assert!(package_dir.join("metadata.json").exists());
        assert!(package_dir.join("tarball.sha256").exists());
        assert!(evidence_files.iter().any(|path| path.ends_with(".tgz")));
        assert_eq!(
            sha256_hex(b"tarball"),
            "db4b4d0d1cb480bf9aeea253771c00febe627f236765fa37d6a5614f079a3aa0"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ignores_plain_package_manifest() {
        let snapshot = PackageSnapshot {
            target: "plain@1.0.0".to_string(),
            package_json: Some(json!({
                "name": "plain",
                "version": "1.0.0",
                "scripts": {"test": "node test.js"}
            })),
            files: vec![PackageFile {
                path: "package/index.js".to_string(),
                text: Some("console.log('ok')".to_string()),
                size: 100,
            }],
        };

        assert!(analyze_package(snapshot, true).is_none());
    }
}
