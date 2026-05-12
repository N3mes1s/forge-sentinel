use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Serialize;
use serde_json::Value;
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
        .http1_only()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("valid npm HTTP client")
});

#[derive(Debug, Serialize)]
struct NpmFinding {
    target: String,
    score: i32,
    factors: Vec<String>,
    evidence: Vec<String>,
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

    for package_spec in &args.package_specs {
        let (target, tarball_url) = resolve_package_spec(package_spec)?;
        let bytes = fetch_bytes(&tarball_url)?;
        let snapshot = inspect_tarball_bytes(&target, &bytes)?;
        if let Some(finding) = analyze_package(snapshot, args.show_evidence) {
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
        let snapshot = inspect_tarball_bytes(&target, &bytes)?;
        if let Some(finding) = analyze_package(snapshot, args.show_evidence) {
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

fn resolve_package_spec(spec: &str) -> Result<(String, String)> {
    let (name, requested_version) = parse_package_spec(spec);
    let encoded_name = urlencoding::encode(&name);
    let url = format!("https://registry.npmjs.org/{encoded_name}");
    let metadata: Value = NPM_CLIENT
        .get(&url)
        .send()
        .with_context(|| format!("fetch npm metadata for {name}"))?
        .error_for_status()
        .with_context(|| format!("npm metadata request failed for {name}"))?
        .json()
        .with_context(|| format!("parse npm metadata for {name}"))?;

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
    let tarball = metadata
        .get("versions")
        .and_then(|versions| versions.get(&version))
        .and_then(|version| version.get("dist"))
        .and_then(|dist| dist.get("tarball"))
        .and_then(Value::as_str)
        .with_context(|| format!("resolve tarball for {name}@{version}"))?;

    Ok((format!("{name}@{version}"), tarball.to_string()))
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

fn add_factor(finding: &mut NpmFinding, score: i32, factor: &str) {
    finding.score += score;
    if !finding.factors.iter().any(|existing| existing == factor) {
        finding.factors.push(factor.to_string());
    }
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
    use super::{PackageFile, PackageSnapshot, analyze_package, parse_package_spec};
    use serde_json::json;

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
