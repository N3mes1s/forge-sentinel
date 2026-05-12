#!/usr/bin/env python3
"""ForgeSentinel GitHub workflow compromise detector.

Initial repo cut of the earlier /tmp prototype. Keep behavior stable first,
then split into smaller analyzers once regression coverage is in place.
"""
import argparse
import base64
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote


ARCHIVE_RE = re.compile(r"\.(tgz|tar\.gz|zip|whl|crate|nupkg|gem)$", re.I)
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$", re.I)
GENERATED_WORKFLOW_RE = re.compile(r"\.generated\.ya?ml$", re.I)
LOCKED_WORKFLOW_RE = re.compile(r"\.lock\.ya?ml$", re.I)
PROTECTIVE_WORKFLOW_FILE_RE = re.compile(
    r"(codeql|scorecard|security|secret|scan|sast|semgrep|trivy|osv|dependency[-_]?review|guarddog|lint|test|verify|validate|audit)",
    re.I,
)
LOCAL_PUBLISH_RE = re.compile(
    r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*"
    r"([./\w-]+/)?[^/\s]+\.(?:tgz|tar\.gz|whl|crate|nupkg|gem)",
    re.I,
)
DYNAMIC_PUBLISH_RE = re.compile(
    r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*"
    r"(\$\{\{\s*(inputs|github\.event\.inputs|env)\.|"
    r"\$(?:INPUT_[A-Z0-9_]*|TARBALL|ARTIFACT|ARTIFACT_PATH|PACKAGE_PATH|PUBLISH_PATH|NPM_PACKAGE))",
    re.I,
)
TEMP_OR_HOME_PUBLISH_RE = re.compile(
    r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b[^\n\r]*"
    r"(/tmp/|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)",
    re.I,
)
PUBLISH_RE = re.compile(
    r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b",
    re.I,
)
ARTIFACT_INPUT_RE = re.compile(
    r"^\+\s*(tarball|artifact|artifact_path|package_path|publish_path|dist|url):",
    re.I | re.M,
)
UNTRUSTED_ARTIFACT_FETCH_RE = re.compile(
    r"^\+.*\b(curl|wget|gh\s+release\s+download|actions/download-artifact)\b"
    r"[^\n\r]*(\.(?:tgz|tar\.gz|whl|crate|nupkg|gem)\b|artifact|tarball|package)",
    re.I | re.M,
)
OIDC_TOKEN_RE = re.compile(
    r"(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token|id-token:\s*write|trusted.?publish|provenance)",
    re.I,
)
PR_TARGET_RE = re.compile(r"^\+\s*pull_request_target:\s*$", re.I | re.M)
PR_HEAD_CHECKOUT_RE = re.compile(
    r"^\+.*(github\.event\.pull_request\.head\.(sha|ref)|"
    r"ref:\s*['\"]?\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\})",
    re.I | re.M,
)
WRITE_PERMISSIONS_RE = re.compile(
    r"^\+\s*permissions:\s*write-all\b"
    r"|^\+\s*(contents|pull-requests|actions|packages|id-token|checks|statuses):\s*write\b",
    re.I | re.M,
)
WORKFLOW_RUN_RE = re.compile(r"^\+\s*workflow_run:\s*$", re.I | re.M)
WORKFLOW_ARTIFACT_DOWNLOAD_RE = re.compile(
    r"^\+.*\b(actions/download-artifact|gh\s+run\s+download)\b",
    re.I | re.M,
)
CONTINUE_ON_ERROR_RE = re.compile(r"^\+\s*continue-on-error:\s*true\b", re.I | re.M)
AUTO_PUSH_OR_MERGE_RE = re.compile(
    r"^\+.*\b(git\s+push|gh\s+pr\s+merge|gh\s+api\b.*\bmerge\b|gh\s+api\b.*\bbranches/.*/protection\b)",
    re.I | re.M,
)
BRANCH_PROTECTION_RE = re.compile(
    r"^\+.*\b(gh\s+api|curl|gh\s+repo\s+edit)\b.*\b("
    r"branches/[^/\s]+/protection|rulesets|bypass_pull_request_allowances|"
    r"required_status_checks|enforce_admins|dismissal_restrictions"
    r")",
    re.I | re.M,
)
DISPATCH_TRIGGER_RE = re.compile(
    r"^\+\s*repository_dispatch:\s*$",
    re.I | re.M,
)
REUSABLE_WORKFLOW_MAIN_RE = re.compile(
    r"^\+\s*uses:\s*[\w.-]+/[\w.-]+/.github/workflows/[^@\s]+@(main|master|head)\b",
    re.I | re.M,
)
SECRETS_INHERIT_RE = re.compile(r"^\+\s*secrets:\s*inherit\b", re.I | re.M)
SELF_HOSTED_RE = re.compile(r"^\+.*self-hosted", re.I | re.M)
CHECK_BYPASS_RE = re.compile(
    r"^\+\s*(paths-ignore:|branches-ignore:)\s*$"
    r"|^\+\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$",
    re.I | re.M,
)
COMMENT_OR_REVIEW_TRIGGER_RE = re.compile(
    r"^\+\s*(issue_comment:|pull_request_review_comment:|discussion_comment:|issues:)",
    re.I | re.M,
)
UNTRUSTED_TEXT_SOURCE_RE = re.compile(
    r"github\.event\.(comment|issue|pull_request|review|discussion|discussion_comment)\.(body|title)"
    r"|github\.event\.head_commit\.message"
    r"|github\.event\.commits\[[0-9]+\]\.message",
    re.I,
)
AGENTIC_TOOL_RE = re.compile(
    r"(gh-aw-manifest|copilot|openai|anthropic|claude|codex|chatgpt|openrouter|aider|llm)",
    re.I,
)
AGENTIC_SECRET_RE = re.compile(
    r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|COPILOT_GITHUB_TOKEN|GH_AW_[A-Z0-9_]+|GEMINI_API_KEY|MISTRAL_API_KEY)",
    re.I,
)
FORK_PR_FETCH_RE = re.compile(
    r"git\s+fetch[^\n\r]*\bpull/\$?\{?[A-Z0-9_]+\}?/head"
    r"|git\s+fetch[^\n\r]*\bpull/\d+/head"
    r"|refs/pull/\$?\{?[A-Z0-9_]+\}?/head"
    r"|refs/pull/\d+/head",
    re.I,
)
PR_METADATA_FETCH_RE = re.compile(
    r"gh\s+pr\s+view[^\n\r]*--json[^\n\r]*(title|body|baseRefName)"
    r"|gh\s+api[^\n\r]*/pulls/[^\n\r]*(title|body|base)"
    r"|gh\s+pr\s+view[^\n\r]*\b(title|body|baseRefName)\b",
    re.I,
)
AGENTIC_TOOL_GRANT_RE = re.compile(
    r"allowedTools"
    r"|Bash\(git:\*\)"
    r"|Bash\(gh:\*\)"
    r"|claude_args:",
    re.I | re.M,
)
AGENTIC_GIT_TOKEN_RE = re.compile(
    r"github_token:\s*\$\{\{\s*secrets\."
    r"|GH_TOKEN:\s*\$\{\{\s*secrets\."
    r"|token:\s*\$\{\{\s*secrets\.(PAT|GITHUB_TOKEN|GH_TOKEN)"
    r"|use the .*service account"
    r"|secrets\.PAT",
    re.I,
)
UNPINNED_EXTERNAL_ACTION_RE = re.compile(
    r"^\+\s*uses:\s*(?!\./)(?!docker://)([\w.-]+/[\w.-]+(?:/[\w./-]+)?)@([^\s#]+)",
    re.I | re.M,
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
REPO_WRITE_TOKEN_RE = re.compile(
    r"(GH_TOKEN|GITHUB_TOKEN):\s*\$\{\{\s*secrets\."
    r"|github_token:\s*\$\{\{\s*secrets\."
    r"|token:\s*\$\{\{\s*secrets\.(PAT|GH_TOKEN|GITHUB_TOKEN|[A-Z0-9_]*PAT)\s*\}\}"
    r"|secrets\.(PAT|GH_TOKEN|GITHUB_TOKEN)",
    re.I,
)
ARTIFACT_STAGING_RE = re.compile(
    r"^\+.*\b(cp|mv)\b[^\n\r]*\.(tgz|tar\.gz|whl|crate|nupkg|gem)\b[^\n\r]*"
    r"(/tmp\b|/tmp/|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)"
    r"|^\+\s*cd\s+(/tmp\b|\$RUNNER_TEMP|\$\{\{\s*runner\.temp\s*\}\}|~/|/home/[^/\s]+/)",
    re.I | re.M,
)
PR_CREATE_RE = re.compile(r"^\+.*\bgh\s+pr\s+create\b", re.I | re.M)
SCRIPT_INJECTION_RE = re.compile(
    r"\$\{\{\s*github\.(?:event|head_commit|commits)[^}]*"
    r"(body|title|message)[^}]*\}\}",
    re.I,
)
SECRET_ENUMERATION_RE = re.compile(
    r"^\+\s*(printenv|env)(?:\s|$)"
    r"|^\+\s*set(?:\s+-[a-zA-Z]+|\s|$)"
    r"|^\+.*toJSON\(secrets\)"
    r"|^\+\s*compgen\s+-e\b"
    r"|^\+\s*Get-ChildItem\s+env:"
    r"|^\+\s*Get-Item\s+env:"
    r"|^\+\s*for\s+\w+\s+in\s+\$\(env\)",
    re.I | re.M,
)
EXTERNAL_SECRET_EXFIL_RE = re.compile(
    r"^\+.*\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|scp|sftp)\b",
    re.I | re.M,
)
COMMENTER_WRITE_GATE_RE = re.compile(
    r"collaborators/.+?/permission"
    r"|PERMISSION=.*gh api .*collaborators/.+?/permission"
    r"|permission[^\\n\\r]{0,80}(admin|write)"
    r"|You do not have write access to use",
    re.I,
)
MERGED_PR_ONLY_GATE_RE = re.compile(
    r"mergedAt|baseRefName"
    r"|only works on merged PRs"
    r"|only works on PRs targeting non-main branches"
    r"|This PR has not been merged yet"
    r"|This PR already targets [`']?main",
    re.I,
)
SKIP_GUARD_RE = re.compile(
    r"^\+.*\bif:\s*.*("
    r"contains\([^)]*label|"
    r"github\.actor\s*[!=]=|"
    r"\[(?:ci skip|skip ci)\]|skip[_ -]?ci|"
    r"github\.actor[^\n\r]{0,80}dependabot|dependabot[^\n\r]{0,80}github\.actor"
    r")",
    re.I | re.M,
)
MANUAL_OIDC_RE = re.compile(
    r"(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|oidc/token/exchange|npm/v1/oidc/token)",
    re.I,
)
REGISTRY_AUTH_RE = re.compile(
    r"(_authToken|NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|GITHUB_TOKEN|npm\s+config\s+set|npm/v1/oidc/token)",
    re.I,
)
TOKEN_EXPOSURE_RE = re.compile(
    r"(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)",
    re.I | re.M,
)
WEAK_TRIGGER_RE = re.compile(r"^\+\s*(push:|pull_request_target:|workflow_run:)", re.M)
TAG_TRIGGER_RE = re.compile(r"^\+\s*tags:\s*$", re.M)
REMOVED_GATES_RE = re.compile(
    r"^-\s*.*(branch check|can only publish|workflow_dispatch|publish_type|dry run|environment:|deployment:|needs:|download artifacts|npm ci|test|build|release_version|GITHUB_REF|refs/heads/rc|hotfix-rc|codeql|scan|verify|lint|sast|security)",
    re.I | re.M,
)
EVIDENCE_LINE_RE = re.compile(
    r"(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push|"
    r"ACTIONS_ID_TOKEN_REQUEST|oidc/token|npm/v1/oidc/token|_authToken|NODE_AUTH_TOKEN|"
    r"NPM_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|base64|printenv|set\s+-x|"
    r"id-token:\s*write|workflow_run:|pull_request_target:|tags:|workflow_dispatch|"
    r"continue-on-error:\s*true|permissions:\s*write-all|contents:\s*write|pull-requests:\s*write|"
    r"github\.event\.pull_request\.head\.(sha|ref)|actions/download-artifact|gh\s+run\s+download|"
    r"issue_comment:|pull_request_review_comment:|discussion_comment:|issues:|"
    r"github\.event\.(comment|issue|pull_request|review|discussion|discussion_comment)\.(body|title)|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|COPILOT_GITHUB_TOKEN|GH_AW_[A-Z0-9_]+|"
    r"GH_TOKEN|GITHUB_TOKEN|github_token:|"
    r"copilot|openai|anthropic|claude|codex|chatgpt|openrouter|aider|llm|"
    r"git\s+push|gh\s+pr\s+create|gh\s+pr\s+merge|paths-ignore|branches-ignore|repository_dispatch:|"
    r"rulesets|protection|secrets:\s*inherit|self-hosted|uses:\s*[\w.-]+/[\w.-]+/.github/workflows/|"
    r"tarball|artifact_path|package_path|publish_path|actions/download-artifact|"
    r"curl|wget|gh\s+release\s+download|npm ci|pnpm install|yarn install|test|build|environment:|needs:)",
    re.I,
)
NPM_OIDC_PACKAGE_RE = re.compile(r"npm/v1/oidc/token/exchange/package/([^\"'\s)]+)", re.I)
GITHUB_TOKEN_RE = re.compile(
    r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"
)
TEAMPCP_MARKER_RE = re.compile(r"LongLiveTheResistanceAgainstMachines:([A-Za-z0-9+/=_-]{20,})")

HUNT_PRESETS: dict[str, list[str]] = {
    "npm-local-archive": [
        '"npm publish" ".tgz" path:.github/workflows',
        '"npm publish" "tar.gz" path:.github/workflows',
        '"npm publish" "scripts/" path:.github/workflows',
        '"npm publish" "dist/" path:.github/workflows',
    ],
    "npm-manual-oidc": [
        '"npm/v1/oidc/token" path:.github/workflows',
        '"ACTIONS_ID_TOKEN_REQUEST_TOKEN" "npm" path:.github/workflows',
        '"ACTIONS_ID_TOKEN_REQUEST_URL" "npm" path:.github/workflows',
    ],
    "npm-token-exposure": [
        '"base64" "NPM_TOKEN" path:.github/workflows',
        '"printenv" "NPM_TOKEN" path:.github/workflows',
        '"echo" "NODE_AUTH_TOKEN" path:.github/workflows',
        '"_authToken" "base64" path:.github/workflows',
    ],
    "polyglot-local-archive": [
        '"twine upload" ".whl" path:.github/workflows',
        '"cargo publish" ".crate" path:.github/workflows',
        '"gem push" ".gem" path:.github/workflows',
        '"dotnet nuget push" ".nupkg" path:.github/workflows',
    ],
    "ci-bypass-pr-target": [
        '"pull_request_target" "github.event.pull_request.head.sha" path:.github/workflows',
        '"pull_request_target" "contents: write" path:.github/workflows',
        '"pull_request_target" "actions/checkout" "ref:" path:.github/workflows',
    ],
    "ci-bypass-workflow-run": [
        '"workflow_run" "actions/download-artifact" path:.github/workflows',
        '"workflow_run" "gh run download" path:.github/workflows',
        '"workflow_run" "contents: write" path:.github/workflows',
    ],
    "ci-bypass-auto-push": [
        '"git push" "GITHUB_TOKEN" path:.github/workflows',
        '"gh pr merge" path:.github/workflows',
        '"continue-on-error: true" path:.github/workflows',
    ],
    "ci-security-suppression": [
        '"paths-ignore" "codeql" path:.github/workflows',
        '"branches-ignore" "security" path:.github/workflows',
        '"if: false" path:.github/workflows',
    ],
    "ci-branch-protection": [
        '"branches/" "protection" "gh api" path:.github/workflows',
        '"rulesets" "gh api" path:.github/workflows',
        '"required_status_checks" "gh api" path:.github/workflows',
    ],
    "ci-dispatch-backdoor": [
        '"repository_dispatch" "contents: write" path:.github/workflows',
        '"workflow_dispatch" "git push" path:.github/workflows',
        '"workflow_dispatch" "npm publish" path:.github/workflows',
    ],
    "ci-reusable-workflow-trust": [
        '"uses:" ".github/workflows/" "@main" path:.github/workflows',
        '"uses:" ".github/workflows/" "@master" path:.github/workflows',
        '"secrets: inherit" ".github/workflows/" path:.github/workflows',
    ],
    "ci-self-hosted-privileged": [
        '"self-hosted" "pull_request_target" path:.github/workflows',
        '"self-hosted" "workflow_run" path:.github/workflows',
        '"self-hosted" "contents: write" path:.github/workflows',
    ],
    "ci-agentic-prompt-injection": [
        '"issue_comment" "github.event.comment.body" "contents: write" path:.github/workflows',
        '"issue_comment" "github.event.comment.body" "OPENAI_API_KEY" path:.github/workflows',
        '"pull_request_target" "github.event.pull_request.body" "ANTHROPIC_API_KEY" path:.github/workflows',
        '"gh-aw-manifest" "issue_comment" path:.github/workflows',
        '"issue_comment" "github.event.comment.body" "gh pr create" path:.github/workflows',
    ],
    "ci-script-injection": [
        '"github.event.pull_request.title" "run:" path:.github/workflows',
        '"github.event.comment.body" "run:" path:.github/workflows',
        '"github.event.head_commit.message" "run:" path:.github/workflows',
    ],
    "ci-secret-exfiltration": [
        '"printenv" "curl" path:.github/workflows',
        '"toJSON(secrets)" path:.github/workflows',
        '"Get-ChildItem env:" "Invoke-WebRequest" path:.github/workflows',
    ],
    "ci-unpinned-third-party-actions": [
        '"uses:" "@v1" "contents: write" path:.github/workflows',
        '"uses:" "@main" "contents: write" path:.github/workflows',
        '"uses:" "@master" "contents: write" path:.github/workflows',
    ],
}

MESSAGE_HUNT_PRESETS: dict[str, list[str]] = {
    "commit-message-secrets": [
        '"ghp_"',
        '"github_pat_"',
        '"LongLiveTheResistanceAgainstMachines"',
    ],
}

CORE_WORKFLOW_FACTORS = {
    "secret_material_printed_or_encoded",
    "dynamic_artifact_publish_with_registry_auth",
    "dynamic_artifact_publish_with_release_boundary_change",
    "runner_local_artifact_publish_with_boundary_change",
    "external_artifact_publish_with_boundary_change",
    "publishes_committed_archive_artifact",
    "local_archive_publish_with_release_gate_rewrite",
    "registry_publish_with_committed_archive",
    "pull_request_target_untrusted_checkout_with_write_capability",
    "workflow_run_artifact_with_write_or_publish_capability",
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
    "unpinned_third_party_action_in_privileged_workflow",
}


@dataclass
class Finding:
    repo: str
    sha: str
    url: str
    date: str
    author: str
    message: str
    score: int = 0
    factors: list[str] = field(default_factory=list)
    workflow_files: list[str] = field(default_factory=list)
    archive_files: list[str] = field(default_factory=list)
    actions_runs: list[str] = field(default_factory=list)
    pull_requests: list[str] = field(default_factory=list)
    evidence_added: list[str] = field(default_factory=list)
    evidence_removed: list[str] = field(default_factory=list)
    archive_blobs: list[str] = field(default_factory=list)
    npm_oidc_packages: list[str] = field(default_factory=list)
    message_evidence: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.score >= 10:
            return "critical"
        if self.score >= 7:
            return "high"
        if self.score >= 4:
            return "suspicious"
        return "low"


def gh_json(path: str, *, paginate: bool = False, jq: str | None = None) -> Any:
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    if jq:
        cmd.extend(["--jq", jq])
    cmd.append(path)
    for attempt in range(3):
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode == 0:
            text = proc.stdout.strip()
            if jq:
                return text
            if not text:
                return None
            return json.loads(text)
        if "rate limit" in proc.stderr.lower() or "secondary rate" in proc.stderr.lower():
            time.sleep(2 + attempt * 3)
            continue
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    raise RuntimeError(f"{' '.join(cmd)} failed after retries: {proc.stderr.strip()}")


def gh_search_code(query: str, limit: int) -> list[dict[str, Any]]:
    cmd = [
        "gh",
        "search",
        "code",
        query,
        "--limit",
        str(limit),
        "--json",
        "repository,path,url",
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout or "[]")


def gh_search_commits(query: str, limit: int) -> list[dict[str, Any]]:
    cmd = [
        "gh",
        "search",
        "commits",
        query,
        "--limit",
        str(limit),
        "--json",
        "repository,sha,url,commit",
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout or "[]")


def list_commits(repo: str, since: str | None, until: str | None, limit: int) -> list[dict[str, Any]]:
    per_page = max(1, min(limit, 100))
    params = [f"per_page={per_page}"]
    if since:
        params.append(f"since={since}")
    if until:
        params.append(f"until={until}")
    path = f"repos/{repo}/commits?{'&'.join(params)}"
    # Fast mode: only inspect the first page. Incident forensics should pass
    # explicit --sha values or use a tight --since/--until window.
    commits = gh_json(path, paginate=False)
    if not isinstance(commits, list):
        return []
    return commits[:limit]


def list_commits_for_path(
    repo: str,
    path_filter: str,
    since: str | None,
    until: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    per_page = max(1, min(limit, 100))
    params = [f"per_page={per_page}", f"path={path_filter}"]
    if since:
        params.append(f"since={since}")
    if until:
        params.append(f"until={until}")
    commits = gh_json(f"repos/{repo}/commits?{'&'.join(params)}", paginate=False)
    if not isinstance(commits, list):
        return []
    return commits[:limit]


def decode_content(repo: str, path: str, ref: str) -> str:
    try:
        encoded = gh_json(f"repos/{repo}/contents/{path}?ref={ref}", jq=".content") or ""
    except Exception:
        return ""
    encoded = "".join(str(encoded).split())
    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded).decode("utf-8", "replace")
    except Exception:
        return ""


def fetch_runs(repo: str, sha: str) -> list[str]:
    try:
        runs = gh_json(f"repos/{repo}/actions/runs?head_sha={sha}&per_page=20")
    except Exception:
        return []
    out = []
    for run in (runs or {}).get("workflow_runs", []):
        url = run.get("html_url")
        name = run.get("name") or run.get("display_title") or "workflow"
        event = run.get("event") or "event?"
        conclusion = run.get("conclusion") or run.get("status") or "unknown"
        if url:
            out.append(f"{name} [{event}/{conclusion}] {url}")
    return out


def fetch_prs(repo: str, sha: str) -> list[str]:
    try:
        prs = gh_json(f"repos/{repo}/commits/{sha}/pulls")
    except Exception:
        return []
    out = []
    if not isinstance(prs, list):
        return out
    for pr in prs:
        url = pr.get("html_url")
        number = pr.get("number")
        state = pr.get("state")
        if url:
            out.append(f"PR #{number} [{state}] {url}")
    return out


def patch_for_file(file: dict[str, Any], repo: str, sha: str, parent_sha: str | None) -> str:
    patch = file.get("patch") or ""
    if patch or not parent_sha:
        return patch
    filename = file.get("filename") or ""
    if not WORKFLOW_RE.match(filename):
        return patch
    before = decode_content(repo, filename, parent_sha)
    after = decode_content(repo, filename, sha)
    if not before and not after:
        return patch
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    removed = "\n".join(f"-{line}" for line in before_lines if line not in after_lines)
    added = "\n".join(f"+{line}" for line in after_lines if line not in before_lines)
    return f"{removed}\n{added}"


def add_factor(finding: Finding, score: int, factor: str) -> None:
    finding.score += score
    if factor not in finding.factors:
        finding.factors.append(factor)


def redact_secret(value: str) -> str:
    if value.startswith("ghp_") and len(value) > 12:
        return f"{value[:8]}...{value[-4:]}"
    if value.startswith("github_pat_") and len(value) > 20:
        return f"{value[:14]}...{value[-4:]}"
    return "<redacted>"


def redact_message(value: str) -> str:
    redacted = GITHUB_TOKEN_RE.sub(lambda m: redact_secret(m.group(0)), value)
    redacted = TEAMPCP_MARKER_RE.sub(
        lambda m: f"LongLiveTheResistanceAgainstMachines:<encoded-payload-redacted>",
        redacted,
    )
    return redacted


def decode_possible_base64(value: str, rounds: int = 3) -> list[str]:
    decoded: list[str] = []
    current = value
    for _ in range(rounds):
        padded = current + ("=" * ((4 - len(current) % 4) % 4))
        try:
            raw = base64.b64decode(padded, validate=False)
            text = raw.decode("utf-8", "replace").strip()
        except Exception:
            break
        if not text or text == current:
            break
        decoded.append(text)
        current = text
    return decoded


def message_secret_evidence(message: str) -> tuple[int, list[str], list[str]]:
    score = 0
    factors: list[str] = []
    evidence: list[str] = []

    direct_tokens = GITHUB_TOKEN_RE.findall(message)
    if direct_tokens:
        score += 10
        factors.append("commit_message_contains_github_token")
        redacted = ", ".join(redact_secret(token) for token in direct_tokens[:5])
        evidence.append(f"direct GitHub token-like value in commit message: {redacted}")

    for marker in TEAMPCP_MARKER_RE.finditer(message):
        encoded = marker.group(1)
        decoded_values = decode_possible_base64(encoded)
        decoded_tokens: list[str] = []
        for decoded in decoded_values:
            decoded_tokens.extend(GITHUB_TOKEN_RE.findall(decoded))
        if decoded_tokens:
            score += 12
            factors.append("prompt_injection_marker_decodes_to_github_token")
            redacted = ", ".join(redact_secret(token) for token in decoded_tokens[:5])
            evidence.append(
                "TeamPCP-style marker decodes to GitHub token-like value: "
                f"{redacted}"
            )
        else:
            score += 6
            factors.append("prompt_injection_marker_in_commit_message")
            evidence.append("TeamPCP-style marker found in commit message")

    return score, factors, evidence


def extract_evidence_lines(text: str, prefix: str, limit: int = 20) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if not EVIDENCE_LINE_RE.search(line):
            continue
        cleaned = line.strip()
        if not cleaned:
            continue
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip()
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned[:260])
        if len(out) >= limit:
            break
    return out


def extract_npm_oidc_packages(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in NPM_OIDC_PACKAGE_RE.finditer(text):
        raw = match.group(1).rstrip("\\)")
        package = unquote(raw)
        if package and package not in seen:
            seen.add(package)
            out.append(package)
    return out


def archive_blob_evidence(files: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for file in files:
        filename = file.get("filename") or ""
        if not ARCHIVE_RE.search(filename):
            continue
        status = file.get("status") or "unknown"
        sha = file.get("sha") or "sha?"
        additions = file.get("additions")
        deletions = file.get("deletions")
        change = ""
        if additions is not None or deletions is not None:
            change = f" +{additions or 0}/-{deletions or 0}"
        out.append(f"{status} {filename} blob={sha}{change}")
    return out


def token_exposure_lines(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("+"):
            continue
        if not TOKEN_EXPOSURE_RE.search(line):
            continue
        matched = False
        if re.search(
            r"^\+\s*(?:echo|printf)\s+['\"]?\$(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)\b",
            line,
            re.I,
        ):
            matched = True
        elif re.search(
            r"^\+\s*printenv\s+(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)\b",
            line,
            re.I,
        ):
            matched = True
        elif re.search(
            r"^\+\s*.*\b(?:echo|printf|printenv)\b.*(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*).*"
            r"\|\s*base64\b",
            line,
            re.I,
        ):
            matched = True
        elif re.search(
            r"^\+\s*.*\bbase64\b.*(?:[A-Z0-9_]*?(?:TOKEN|AUTH|PASSWORD)[A-Z0-9_]*)",
            line,
            re.I,
        ):
            matched = True
        if not matched:
            continue
        cleaned = line[1:].strip()
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned[:260])
    return out


def is_generated_workflow_regen(
    workflow_files: list[dict[str, Any]],
    message: str,
    added_lines: str,
    removed_lines: str,
) -> bool:
    generated_count = sum(
        1
        for workflow_file in workflow_files
        if GENERATED_WORKFLOW_RE.search(workflow_file.get("filename") or "")
    )
    if generated_count < 2:
        return False
    if "# GENERATED BY" in added_lines:
        return True
    lower_message = message.lower()
    if "generated" in lower_message or "gagen" in lower_message:
        return True
    if "# GENERATED BY" in removed_lines:
        return True
    return False


def is_locked_workflow_bundle(
    workflow_files: list[dict[str, Any]],
    added_lines: str,
    removed_lines: str,
) -> bool:
    locked_count = sum(
        1
        for workflow_file in workflow_files
        if LOCKED_WORKFLOW_RE.search(workflow_file.get("filename") or "")
    )
    if locked_count < 2:
        return False
    return (
        "gh-aw-manifest" in added_lines
        or "gh-aw-metadata" in added_lines
        or "gh-aw-manifest" in removed_lines
        or "gh-aw-metadata" in removed_lines
    )


def has_protective_workflow_context(workflow_files: list[dict[str, Any]]) -> bool:
    return any(
        PROTECTIVE_WORKFLOW_FILE_RE.search(workflow_file.get("filename") or "")
        for workflow_file in workflow_files
    )


def contains_unpinned_external_action(added_lines: str) -> bool:
    for match in UNPINNED_EXTERNAL_ACTION_RE.finditer(added_lines):
        ref = match.group(2)
        if FULL_SHA_RE.fullmatch(ref):
            continue
        return True
    return False


def has_untrusted_artifact_fetch(added_lines: str) -> bool:
    for line in added_lines.splitlines():
        lowered = line.lower()
        if "oidc/token" in lowered or "registry.npmjs.org" in lowered:
            continue
        if UNTRUSTED_ARTIFACT_FETCH_RE.search(line):
            return True
    return False


def has_external_artifact_fetch(added_lines: str) -> bool:
    for line in added_lines.splitlines():
        lowered = line.lower()
        if "oidc/token" in lowered or "registry.npmjs.org" in lowered:
            continue
        if "curl" not in lowered and "wget" not in lowered:
            continue
        if "github.com/" in lowered or "api.github.com/" in lowered:
            continue
        if re.search(r"https?://", line) and re.search(
            r"\.(tgz|tar\.gz|whl|crate|nupkg|gem)\b|artifact|tarball|package",
            line,
            re.I,
        ):
            return True
    return False


def analyze_commit(
    repo: str,
    summary: dict[str, Any] | str,
    enrich: bool,
    show_evidence: bool,
    include_weak_workflow_signals: bool,
) -> Finding | None:
    sha = summary if isinstance(summary, str) else summary.get("sha")
    if not sha:
        return None
    commit = gh_json(f"repos/{repo}/commits/{sha}")
    files = commit.get("files") or []
    workflow_files = [f for f in files if WORKFLOW_RE.match(f.get("filename") or "")]
    archive_files = [f for f in files if ARCHIVE_RE.search(f.get("filename") or "")]

    c = commit.get("commit") or {}
    author = c.get("author") or {}
    parent_sha = (commit.get("parents") or [{}])[0].get("sha")
    message = c.get("message") or ""
    finding = Finding(
        repo=repo,
        sha=sha,
        url=commit.get("html_url") or "",
        date=author.get("date") or "",
        author=f"{author.get('name') or ''} <{author.get('email') or ''}>".strip(),
        message=redact_message(message.splitlines()[0]),
        workflow_files=[f.get("filename") or "" for f in workflow_files],
        archive_files=[f.get("filename") or "" for f in archive_files],
    )

    message_score, message_factors, message_evidence = message_secret_evidence(message)
    for factor in message_factors:
        add_factor(finding, 0, factor)
    finding.score += message_score
    finding.message_evidence = message_evidence

    if not workflow_files:
        return finding if finding.score > 0 else None

    combined_patch = "\n".join(patch_for_file(f, repo, sha, parent_sha) for f in workflow_files)
    added_lines = "\n".join(line for line in combined_patch.splitlines() if line.startswith("+"))
    removed_lines = "\n".join(line for line in combined_patch.splitlines() if line.startswith("-"))
    if show_evidence:
        finding.evidence_added = extract_evidence_lines(added_lines, "+")
        finding.evidence_removed = extract_evidence_lines(removed_lines, "-")
        finding.archive_blobs = archive_blob_evidence(archive_files)
        finding.npm_oidc_packages = extract_npm_oidc_packages(added_lines)

    strong_workflow_signal = False
    explicit_token_exposure = token_exposure_lines(added_lines)
    generated_workflow_regen = is_generated_workflow_regen(
        workflow_files,
        message,
        added_lines,
        removed_lines,
    )
    locked_workflow_bundle = is_locked_workflow_bundle(
        workflow_files,
        added_lines,
        removed_lines,
    )
    protective_workflow_context = has_protective_workflow_context(workflow_files)
    publishes_local_archive = bool(LOCAL_PUBLISH_RE.search(added_lines))
    publishes_dynamic_artifact = bool(DYNAMIC_PUBLISH_RE.search(added_lines))
    publishes_temp_or_home_artifact = bool(TEMP_OR_HOME_PUBLISH_RE.search(added_lines))
    publishes_registry = bool(PUBLISH_RE.search(added_lines))
    adds_artifact_input = bool(ARTIFACT_INPUT_RE.search(added_lines))
    fetches_untrusted_artifact = has_untrusted_artifact_fetch(added_lines)
    fetches_external_artifact = has_external_artifact_fetch(added_lines)
    manual_oidc = bool(MANUAL_OIDC_RE.search(added_lines))
    oidc_or_provenance = bool(OIDC_TOKEN_RE.search(added_lines))
    registry_auth = bool(REGISTRY_AUTH_RE.search(added_lines))
    token_exposure = bool(explicit_token_exposure)
    adds_pull_request_target = bool(PR_TARGET_RE.search(added_lines))
    checks_out_pr_head = bool(PR_HEAD_CHECKOUT_RE.search(added_lines))
    adds_write_permissions = bool(WRITE_PERMISSIONS_RE.search(added_lines))
    adds_workflow_run = bool(WORKFLOW_RUN_RE.search(added_lines))
    downloads_workflow_artifact = bool(WORKFLOW_ARTIFACT_DOWNLOAD_RE.search(added_lines))
    adds_continue_on_error = bool(CONTINUE_ON_ERROR_RE.search(added_lines))
    adds_auto_push_or_merge = bool(AUTO_PUSH_OR_MERGE_RE.search(added_lines))
    creates_pr_from_ci = bool(PR_CREATE_RE.search(added_lines))
    modifies_branch_protection = bool(BRANCH_PROTECTION_RE.search(added_lines))
    adds_dispatch_trigger = bool(DISPATCH_TRIGGER_RE.search(added_lines))
    uses_unpinned_reusable_workflow = bool(REUSABLE_WORKFLOW_MAIN_RE.search(added_lines))
    inherits_secrets = bool(SECRETS_INHERIT_RE.search(added_lines))
    uses_self_hosted_runner = bool(SELF_HOSTED_RE.search(added_lines))
    adds_check_bypass = bool(CHECK_BYPASS_RE.search(added_lines))
    adds_comment_or_review_trigger = bool(COMMENT_OR_REVIEW_TRIGGER_RE.search(added_lines))
    reads_untrusted_text = bool(UNTRUSTED_TEXT_SOURCE_RE.search(added_lines))
    adds_agentic_tooling = bool(AGENTIC_TOOL_RE.search(added_lines))
    adds_agentic_secret = bool(AGENTIC_SECRET_RE.search(added_lines))
    fetches_fork_pr_head = bool(FORK_PR_FETCH_RE.search(added_lines))
    reads_pr_metadata = bool(PR_METADATA_FETCH_RE.search(added_lines))
    grants_agentic_tools = bool(AGENTIC_TOOL_GRANT_RE.search(added_lines))
    hands_agent_write_token = bool(AGENTIC_GIT_TOKEN_RE.search(added_lines))
    hands_repo_write_token = bool(REPO_WRITE_TOKEN_RE.search(added_lines))
    stages_artifact_in_temp_or_home = bool(ARTIFACT_STAGING_RE.search(added_lines))
    has_direct_script_injection = bool(SCRIPT_INJECTION_RE.search(added_lines))
    enumerates_secrets = bool(SECRET_ENUMERATION_RE.search(added_lines))
    exfiltrates_externally = bool(EXTERNAL_SECRET_EXFIL_RE.search(added_lines))
    has_unpinned_external_action = contains_unpinned_external_action(added_lines)
    commenter_write_gate = bool(COMMENTER_WRITE_GATE_RE.search(added_lines))
    merged_pr_only_gate = bool(MERGED_PR_ONLY_GATE_RE.search(added_lines))
    agentic_context = adds_agentic_tooling or adds_agentic_secret
    adds_skip_guard = bool(SKIP_GUARD_RE.search(added_lines))
    broad_trigger = bool(WEAK_TRIGGER_RE.search(added_lines) or TAG_TRIGGER_RE.search(added_lines))
    removed_gates = bool(REMOVED_GATES_RE.search(removed_lines))
    committed_archive = bool(archive_files)
    bulk_workflow = len(workflow_files) >= 3

    # Precision model:
    # - Normal publish, OIDC, provenance, and token setup are common release hygiene.
    # - Emit workflow findings only when at least one high-signal behavior is present.
    if token_exposure:
        strong_workflow_signal = True
        add_factor(finding, 8, "secret_material_printed_or_encoded")
        if show_evidence:
            for line in explicit_token_exposure[:5]:
                evidence = f"token exposure line: {line}"
                if evidence not in finding.message_evidence:
                    finding.message_evidence.append(evidence)

    if adds_pull_request_target:
        add_factor(finding, 1, "adds_pull_request_target")
        if checks_out_pr_head:
            add_factor(finding, 3, "checks_out_pr_head_in_privileged_context")
            if adds_write_permissions or registry_auth or adds_auto_push_or_merge:
                strong_workflow_signal = True
                add_factor(finding, 6, "pull_request_target_untrusted_checkout_with_write_capability")

    if adds_workflow_run:
        add_factor(finding, 1, "adds_workflow_run_trigger")
        if downloads_workflow_artifact:
            add_factor(finding, 2, "downloads_artifact_in_workflow_run")
            if adds_write_permissions or publishes_registry or adds_auto_push_or_merge:
                strong_workflow_signal = True
                add_factor(finding, 5, "workflow_run_artifact_with_write_or_publish_capability")

    if adds_continue_on_error:
        add_factor(finding, 2, "adds_continue_on_error")
        if removed_gates or publishes_registry or adds_auto_push_or_merge:
            strong_workflow_signal = True
            add_factor(finding, 4, "check_suppression_with_sensitive_follow_on_change")

    if adds_auto_push_or_merge:
        add_factor(finding, 2, "adds_ci_push_or_merge")
        if adds_write_permissions or registry_auth or broad_trigger:
            strong_workflow_signal = True
            add_factor(finding, 5, "ci_push_or_merge_with_write_permissions")
    if creates_pr_from_ci:
        add_factor(finding, 1, "creates_pull_request_from_ci")
    if hands_repo_write_token:
        add_factor(finding, 1, "hands_repo_write_token")
    if stages_artifact_in_temp_or_home:
        add_factor(finding, 1, "stages_artifact_in_temp_or_home")
    if has_unpinned_external_action:
        add_factor(finding, 1, "introduces_unpinned_external_action")
        if (
            adds_write_permissions
            or hands_repo_write_token
            or publishes_registry
            or registry_auth
            or inherits_secrets
        ):
            strong_workflow_signal = True
            add_factor(finding, 4, "unpinned_third_party_action_in_privileged_workflow")
    if has_direct_script_injection:
        add_factor(finding, 2, "direct_untrusted_context_interpolation")
        if (
            adds_write_permissions
            or hands_repo_write_token
            or publishes_registry
            or registry_auth
            or uses_self_hosted_runner
        ):
            strong_workflow_signal = True
            add_factor(finding, 5, "direct_script_injection_in_privileged_workflow")
    if enumerates_secrets:
        add_factor(finding, 2, "enumerates_environment_or_secrets")
    if exfiltrates_externally:
        add_factor(finding, 2, "external_network_or_exfil_path")
    if (enumerates_secrets or token_exposure) and exfiltrates_externally:
        strong_workflow_signal = True
        add_factor(finding, 6, "workflow_secret_enumeration_and_external_exfiltration")

    if adds_skip_guard:
        add_factor(finding, 2, "adds_actor_or_label_based_skip_guard")
        if removed_gates or publishes_registry or adds_auto_push_or_merge:
            strong_workflow_signal = True
            add_factor(finding, 3, "skip_guard_with_sensitive_workflow_change")

    if agentic_context:
        add_factor(finding, 1, "adds_agentic_or_llm_tooling")
    if reads_untrusted_text:
        add_factor(finding, 1, "reads_untrusted_issue_pr_or_comment_text")
    if adds_comment_or_review_trigger:
        add_factor(finding, 1, "adds_comment_or_review_trigger")
    if fetches_fork_pr_head:
        add_factor(finding, 2, "fetches_pr_head_from_fork_or_pull_ref")
    if reads_pr_metadata:
        add_factor(finding, 1, "reads_pr_metadata_for_agent")
    if grants_agentic_tools:
        add_factor(finding, 2, "grants_agent_shell_or_edit_tools")
    if hands_agent_write_token:
        add_factor(finding, 2, "hands_agent_repo_write_token")
    if commenter_write_gate:
        add_factor(finding, 0, "commenter_must_have_write_or_admin")
    if merged_pr_only_gate:
        add_factor(finding, 0, "requires_merged_non_main_pr")
    if agentic_context and reads_untrusted_text and (
        adds_comment_or_review_trigger or adds_pull_request_target
    ):
        add_factor(finding, 3, "agentic_workflow_reads_untrusted_user_text")
        if (
            adds_write_permissions
            or adds_auto_push_or_merge
            or publishes_registry
            or registry_auth
            or inherits_secrets
        ):
            strong_workflow_signal = True
            add_factor(finding, 6, "agentic_prompt_injection_with_write_or_secret_capability")
        if uses_self_hosted_runner:
            strong_workflow_signal = True
            add_factor(finding, 4, "agentic_prompt_injection_on_self_hosted_runner")
        if (
            fetches_fork_pr_head
            and reads_pr_metadata
            and grants_agentic_tools
            and (hands_agent_write_token or adds_write_permissions or adds_auto_push_or_merge)
        ):
            strong_workflow_signal = True
            add_factor(finding, 5, "agentic_prompt_injection_over_fork_pr_material")
        if commenter_write_gate:
            add_factor(finding, -2, "maintainer_gated_trigger")
        if merged_pr_only_gate:
            add_factor(finding, -1, "merged_pr_only_scope_reduction")

    if modifies_branch_protection:
        add_factor(finding, 3, "modifies_branch_protection_or_rulesets")
        if adds_write_permissions or adds_auto_push_or_merge or registry_auth or hands_repo_write_token:
            strong_workflow_signal = True
            add_factor(finding, 5, "workflow_modifies_branch_protection_with_write_capability")

    if adds_dispatch_trigger:
        add_factor(finding, 1, "adds_dispatch_trigger")
        if adds_write_permissions or publishes_registry or adds_auto_push_or_merge or creates_pr_from_ci:
            if removed_gates or adds_artifact_input or manual_oidc:
                strong_workflow_signal = True
                add_factor(finding, 5, "dispatch_backdoor_with_write_or_publish_capability")
            if hands_repo_write_token:
                strong_workflow_signal = True
                add_factor(finding, 4, "dispatch_backdoor_with_repo_token")

    if uses_unpinned_reusable_workflow:
        add_factor(finding, 2, "uses_unpinned_reusable_workflow_ref")
        if inherits_secrets or adds_write_permissions or hands_repo_write_token:
            strong_workflow_signal = True
            add_factor(finding, 5, "unpinned_reusable_workflow_with_secret_inheritance")

    if uses_self_hosted_runner:
        add_factor(finding, 2, "uses_self_hosted_runner")
        if (adds_pull_request_target and checks_out_pr_head) or (
            adds_workflow_run and downloads_workflow_artifact
        ):
            strong_workflow_signal = True
            add_factor(finding, 6, "untrusted_code_on_self_hosted_runner")
        if hands_repo_write_token and (
            fetches_external_artifact or fetches_fork_pr_head or adds_agentic_tooling
        ):
            strong_workflow_signal = True
            add_factor(finding, 4, "self_hosted_runner_with_repo_token_and_untrusted_input")

    if protective_workflow_context and adds_check_bypass:
        add_factor(finding, 3, "adds_protective_workflow_bypass_filter")
        if (
            removed_gates
            or adds_skip_guard
            or adds_continue_on_error
            or adds_write_permissions
            or hands_repo_write_token
        ):
            strong_workflow_signal = True
            add_factor(finding, 5, "protective_workflow_bypass_with_sensitive_follow_on_change")

    if publishes_dynamic_artifact:
        add_factor(finding, 3, "publishes_dynamic_artifact_path")
        if manual_oidc or registry_auth:
            strong_workflow_signal = True
            add_factor(finding, 5, "dynamic_artifact_publish_with_registry_auth")
        if removed_gates or broad_trigger or adds_artifact_input:
            strong_workflow_signal = True
            add_factor(finding, 4, "dynamic_artifact_publish_with_release_boundary_change")

    if publishes_temp_or_home_artifact:
        add_factor(finding, 2, "publishes_runner_temp_or_home_artifact")
        if manual_oidc or removed_gates or broad_trigger:
            strong_workflow_signal = True
            add_factor(finding, 4, "runner_local_artifact_publish_with_boundary_change")
        if stages_artifact_in_temp_or_home and (publishes_registry or registry_auth):
            strong_workflow_signal = True
            add_factor(finding, 4, "staged_local_artifact_publish_with_registry_capability")

    if fetches_untrusted_artifact and publishes_registry and (
        strong_workflow_signal or include_weak_workflow_signals
    ):
        add_factor(finding, 1, "fetches_artifact_before_publish")

    if fetches_external_artifact and publishes_registry:
        add_factor(finding, 2, "fetches_external_artifact_before_publish")
        if manual_oidc or registry_auth or removed_gates or broad_trigger:
            strong_workflow_signal = True
            add_factor(finding, 5, "external_artifact_publish_with_boundary_change")

    if publishes_local_archive and committed_archive:
        strong_workflow_signal = True
        add_factor(finding, 9, "publishes_committed_archive_artifact")
    elif publishes_local_archive:
        add_factor(finding, 2, "publishes_local_archive_path")
        if broad_trigger and removed_gates:
            strong_workflow_signal = True
            add_factor(finding, 4, "local_archive_publish_with_release_gate_rewrite")
        if stages_artifact_in_temp_or_home and (publishes_registry or registry_auth):
            strong_workflow_signal = True
            add_factor(finding, 4, "staged_local_artifact_publish_with_registry_capability")
    elif committed_archive:
        add_factor(finding, 2, "adds_archive_blob_in_same_commit")
        if publishes_registry and broad_trigger:
            strong_workflow_signal = True
            add_factor(finding, 4, "registry_publish_with_committed_archive")

    if publishes_registry and (strong_workflow_signal or include_weak_workflow_signals):
        add_factor(finding, 1, "adds_registry_publish")
    if manual_oidc:
        add_factor(finding, 1, "adds_manual_oidc_token_exchange")
    elif oidc_or_provenance:
        add_factor(finding, 0, "adds_oidc_or_provenance_token_path")
    if registry_auth:
        add_factor(finding, 0, "adds_registry_auth_token_handling")
    if broad_trigger and (strong_workflow_signal or include_weak_workflow_signals):
        add_factor(finding, 1, "adds_broader_or_tag_trigger")
    if removed_gates and (strong_workflow_signal or include_weak_workflow_signals):
        add_factor(finding, 1, "removes_release_gates_or_build_steps")
    if bulk_workflow:
        add_factor(finding, 0, "bulk_workflow_mutation")
    if generated_workflow_regen:
        add_factor(finding, 0, "generated_workflow_regeneration")
    if locked_workflow_bundle:
        add_factor(finding, 0, "locked_workflow_bundle_regeneration")

    has_core_workflow_factor = any(
        factor in CORE_WORKFLOW_FACTORS for factor in finding.factors
    )

    if enrich and finding.score > 0:
        finding.actions_runs = fetch_runs(repo, sha)
        finding.pull_requests = fetch_prs(repo, sha)
        if strong_workflow_signal or finding.message_evidence or include_weak_workflow_signals:
            if not finding.pull_requests:
                add_factor(finding, 1, "no_public_pr_association")
            if finding.actions_runs:
                add_factor(finding, 1, "actions_run_for_suspicious_sha")

    if (
        not strong_workflow_signal
        and not finding.message_evidence
        and not include_weak_workflow_signals
    ):
        return None

    if (
        generated_workflow_regen
        and not has_core_workflow_factor
        and not finding.message_evidence
    ):
        return None

    if (
        locked_workflow_bundle
        and not has_core_workflow_factor
        and not finding.message_evidence
    ):
        return None

    return finding if finding.score > 0 else None


def print_finding(f: Finding) -> None:
    print(f"{f.severity.upper()} score={f.score} {f.repo}@{f.sha[:12]} {f.date}")
    print(f"  {f.url}")
    print(f"  author: {f.author}")
    print(f"  message: {f.message}")
    print(f"  factors: {', '.join(f.factors)}")
    print(f"  workflows: {', '.join(f.workflow_files)}")
    if f.archive_files:
        print(f"  archives: {', '.join(f.archive_files)}")
    if f.message_evidence:
        print("  message evidence:")
        for line in f.message_evidence:
            print(f"    - {line}")
    if f.archive_blobs:
        print(f"  archive_blobs: {'; '.join(f.archive_blobs)}")
    if f.npm_oidc_packages:
        print(f"  npm_oidc_packages: {', '.join(f.npm_oidc_packages)}")
    if f.evidence_added:
        print("  added evidence:")
        for line in f.evidence_added:
            print(f"    + {line}")
    if f.evidence_removed:
        print("  removed evidence:")
        for line in f.evidence_removed:
            print(f"    - {line}")
    if f.pull_requests:
        print(f"  prs: {'; '.join(f.pull_requests)}")
    if f.actions_runs:
        print(f"  runs: {'; '.join(f.actions_runs)}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect suspicious GitHub workflow mutations and CI compromise patterns."
    )
    parser.add_argument("repos", nargs="*", help="OWNER/REPO values")
    parser.add_argument("--since", help="ISO timestamp, e.g. 2026-04-22T00:00:00Z")
    parser.add_argument("--until", help="ISO timestamp")
    parser.add_argument(
        "--sha",
        action="append",
        default=[],
        help="explicit commit SHA to inspect; repeatable and needed for deleted/orphaned refs",
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--search-limit",
        type=int,
        help="GitHub code-search hits per seed query; defaults to --limit",
    )
    parser.add_argument(
        "--commits-per-path",
        type=int,
        default=3,
        help="recent commits to inspect for each seeded workflow path",
    )
    parser.add_argument("--min-score", type=int, default=4)
    parser.add_argument("--json", action="store_true", help="emit JSON lines")
    parser.add_argument("--enrich", action="store_true", help="fetch runs and PR association")
    parser.add_argument("--verbose", action="store_true", help="print discovery progress to stderr")
    parser.add_argument(
        "--include-weak-workflow-signals",
        action="store_true",
        help="also emit publish/OIDC workflow changes that lack a core compromise signal",
    )
    parser.add_argument(
        "--show-evidence",
        action="store_true",
        help="print relevant added/removed workflow lines and archive blob metadata",
    )
    parser.add_argument(
        "--hunt-preset",
        action="append",
        choices=sorted(HUNT_PRESETS),
        default=[],
        help="add a built-in GitHub code-search seed set; repeatable",
    )
    parser.add_argument(
        "--message-hunt-preset",
        action="append",
        choices=sorted(MESSAGE_HUNT_PRESETS),
        default=[],
        help="add a built-in GitHub commit-search seed set; repeatable",
    )
    parser.add_argument(
        "--seed-code-search",
        action="append",
        help="seed candidate workflow paths from GitHub code search, then inspect commits touching those files",
    )
    parser.add_argument(
        "--seed-commit-search",
        action="append",
        help="seed explicit commits from GitHub commit search; repeatable",
    )
    parser.add_argument(
        "--seed-path",
        action="append",
        default=[],
        help="seed commits touching one workflow path as OWNER/REPO:.github/workflows/file.yml; repeatable",
    )
    args = parser.parse_args()

    findings: list[Finding] = []
    repo_commits: dict[str, list[dict[str, Any] | str]] = {repo: [] for repo in args.repos}
    seen_seed_paths: set[tuple[str, str]] = set()
    seed_queries: list[str] = []
    for preset in args.hunt_preset:
        seed_queries.extend(HUNT_PRESETS[preset])
    seed_queries.extend(args.seed_code_search or [])

    for query in seed_queries:
        if args.verbose:
            print(f"seed query: {query}", file=sys.stderr)
        for hit in gh_search_code(query, args.search_limit or args.limit):
            repo = (hit.get("repository") or {}).get("nameWithOwner")
            path_filter = hit.get("path")
            if not repo or not path_filter:
                continue
            seed_key = (repo, path_filter)
            if seed_key in seen_seed_paths:
                continue
            seen_seed_paths.add(seed_key)
            repo_commits.setdefault(repo, [])
            repo_commits[repo].extend(
                list_commits_for_path(
                    repo,
                    path_filter,
                    args.since,
                    args.until,
                    max(1, args.commits_per_path),
                )
            )

    commit_seed_queries: list[str] = []
    for preset in args.message_hunt_preset:
        commit_seed_queries.extend(MESSAGE_HUNT_PRESETS[preset])
    commit_seed_queries.extend(args.seed_commit_search or [])
    for query in commit_seed_queries:
        query_with_date = query
        if args.since and "author-date:" not in query:
            query_with_date = f"{query} author-date:>{args.since[:10]}"
        if args.verbose:
            print(f"commit seed query: {query_with_date}", file=sys.stderr)
        for hit in gh_search_commits(query_with_date, args.search_limit or args.limit):
            repo = (hit.get("repository") or {}).get("fullName")
            sha = hit.get("sha")
            if not repo or not sha:
                continue
            repo_commits.setdefault(repo, [])
            repo_commits[repo].append(sha)
    for item in args.seed_path:
        if ":" not in item:
            print(f"ERROR invalid --seed-path {item!r}; expected OWNER/REPO:path", file=sys.stderr)
            continue
        repo, path_filter = item.split(":", 1)
        if not repo or not path_filter:
            print(f"ERROR invalid --seed-path {item!r}; expected OWNER/REPO:path", file=sys.stderr)
            continue
        repo_commits.setdefault(repo, [])
        repo_commits[repo].extend(
            list_commits_for_path(
                repo,
                path_filter,
                args.since,
                args.until,
                max(1, args.commits_per_path),
            )
        )

    for repo in args.repos:
        repo_commits.setdefault(repo, [])

    for repo, seeded_commits in repo_commits.items():
        try:
            commits: list[dict[str, Any] | str]
            if args.sha:
                commits = args.sha
            elif seeded_commits:
                seen = set()
                commits = []
                for commit in seeded_commits:
                    sha = commit.get("sha") if isinstance(commit, dict) else commit
                    if sha and sha not in seen:
                        seen.add(sha)
                        commits.append(commit)
            else:
                commits = list_commits(repo, args.since, args.until, args.limit)
            for commit in commits:
                if args.verbose:
                    commit_sha = commit.get("sha") if isinstance(commit, dict) else commit
                    print(f"inspect {repo}@{str(commit_sha)[:12]}", file=sys.stderr)
                finding = analyze_commit(
                    repo,
                    commit,
                    args.enrich,
                    args.show_evidence,
                    args.include_weak_workflow_signals,
                )
                if finding and finding.score >= args.min_score:
                    findings.append(finding)
        except Exception as error:
            print(f"ERROR {repo}: {error}", file=sys.stderr)

    findings.sort(key=lambda f: (f.score, f.date), reverse=True)
    for finding in findings:
        if args.json:
            print(json.dumps(finding.__dict__, sort_keys=True))
        else:
            print_finding(finding)
    return 1 if any(f.score >= 10 for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
