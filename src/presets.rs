use clap::ValueEnum;

pub trait PresetMeta {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn queries(&self) -> &'static [&'static str];
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum WorkflowPreset {
    NpmLocalArchive,
    NpmManualOidc,
    NpmTokenExposure,
    PolyglotLocalArchive,
    CiBypassPrTarget,
    CiBypassWorkflowRun,
    CiBypassAutoPush,
    CiSecuritySuppression,
    CiBranchProtection,
    CiDispatchBackdoor,
    CiReusableWorkflowTrust,
    CiSelfHostedPrivileged,
    CiAgenticPromptInjection,
    CiScriptInjection,
    CiSecretExfiltration,
    CiUnpinnedThirdPartyActions,
    CiCachePoisoning,
    CiCredentialPersistence,
    CiSensitiveArtifactLeakage,
    CiEncodedRemotePayloads,
    DeveloperEnvironmentAutorun,
}

impl WorkflowPreset {
    pub const ALL: [Self; 21] = [
        Self::NpmLocalArchive,
        Self::NpmManualOidc,
        Self::NpmTokenExposure,
        Self::PolyglotLocalArchive,
        Self::CiBypassPrTarget,
        Self::CiBypassWorkflowRun,
        Self::CiBypassAutoPush,
        Self::CiSecuritySuppression,
        Self::CiBranchProtection,
        Self::CiDispatchBackdoor,
        Self::CiReusableWorkflowTrust,
        Self::CiSelfHostedPrivileged,
        Self::CiAgenticPromptInjection,
        Self::CiScriptInjection,
        Self::CiSecretExfiltration,
        Self::CiUnpinnedThirdPartyActions,
        Self::CiCachePoisoning,
        Self::CiCredentialPersistence,
        Self::CiSensitiveArtifactLeakage,
        Self::CiEncodedRemotePayloads,
        Self::DeveloperEnvironmentAutorun,
    ];
}

impl PresetMeta for WorkflowPreset {
    fn name(&self) -> &'static str {
        match self {
            Self::NpmLocalArchive => "npm-local-archive",
            Self::NpmManualOidc => "npm-manual-oidc",
            Self::NpmTokenExposure => "npm-token-exposure",
            Self::PolyglotLocalArchive => "polyglot-local-archive",
            Self::CiBypassPrTarget => "ci-bypass-pr-target",
            Self::CiBypassWorkflowRun => "ci-bypass-workflow-run",
            Self::CiBypassAutoPush => "ci-bypass-auto-push",
            Self::CiSecuritySuppression => "ci-security-suppression",
            Self::CiBranchProtection => "ci-branch-protection",
            Self::CiDispatchBackdoor => "ci-dispatch-backdoor",
            Self::CiReusableWorkflowTrust => "ci-reusable-workflow-trust",
            Self::CiSelfHostedPrivileged => "ci-self-hosted-privileged",
            Self::CiAgenticPromptInjection => "ci-agentic-prompt-injection",
            Self::CiScriptInjection => "ci-script-injection",
            Self::CiSecretExfiltration => "ci-secret-exfiltration",
            Self::CiUnpinnedThirdPartyActions => "ci-unpinned-third-party-actions",
            Self::CiCachePoisoning => "ci-cache-poisoning",
            Self::CiCredentialPersistence => "ci-credential-persistence",
            Self::CiSensitiveArtifactLeakage => "ci-sensitive-artifact-leakage",
            Self::CiEncodedRemotePayloads => "ci-encoded-remote-payloads",
            Self::DeveloperEnvironmentAutorun => "developer-environment-autorun",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::NpmLocalArchive => {
                "Seed npm publish workflows that handle local archives or staged package files."
            }
            Self::NpmManualOidc => {
                "Seed workflows that perform manual npm OIDC token exchange or trusted publish setup."
            }
            Self::NpmTokenExposure => {
                "Seed workflows that expose registry auth material in logs or transforms."
            }
            Self::PolyglotLocalArchive => {
                "Seed local archive publishing across PyPI, crates.io, RubyGems, and NuGet."
            }
            Self::CiBypassPrTarget => {
                "Seed pull_request_target workflows that combine untrusted checkout with write capability."
            }
            Self::CiBypassWorkflowRun => {
                "Seed workflow_run patterns that download artifacts and regain privilege."
            }
            Self::CiBypassAutoPush => {
                "Seed workflows that push, merge, or soften failures from CI."
            }
            Self::CiSecuritySuppression => {
                "Seed workflows that suppress security checks or bypass protective paths."
            }
            Self::CiBranchProtection => {
                "Seed branch protection or ruleset tampering from workflow code."
            }
            Self::CiDispatchBackdoor => {
                "Seed workflow_dispatch or repository_dispatch backdoor-style publish paths."
            }
            Self::CiReusableWorkflowTrust => {
                "Seed risky reusable workflow references and secret inheritance."
            }
            Self::CiSelfHostedPrivileged => {
                "Seed self-hosted runner workflows that mix untrusted input with privilege."
            }
            Self::CiAgenticPromptInjection => {
                "Seed agentic CI flows that read user-controlled text with secrets or write access."
            }
            Self::CiScriptInjection => {
                "Seed direct script interpolation of untrusted GitHub event fields."
            }
            Self::CiSecretExfiltration => {
                "Seed workflows that enumerate secrets or environment and send it outward."
            }
            Self::CiUnpinnedThirdPartyActions => {
                "Seed privileged workflows that rely on mutable third-party action refs."
            }
            Self::CiCachePoisoning => {
                "Seed pull_request_target workflows that can poison dependency caches across trust boundaries."
            }
            Self::CiCredentialPersistence => {
                "Seed workflows that persist Git or checkout credentials in privileged contexts."
            }
            Self::CiSensitiveArtifactLeakage => {
                "Seed workflows that upload or cache credential-bearing files."
            }
            Self::CiEncodedRemotePayloads => {
                "Seed workflows that execute remote, encoded, or dynamic payloads."
            }
            Self::DeveloperEnvironmentAutorun => {
                "Seed Claude and editor startup hooks that auto-run repository code."
            }
        }
    }

    fn queries(&self) -> &'static [&'static str] {
        match self {
            Self::NpmLocalArchive => &[
                "\"npm publish\" \".tgz\" path:.github/workflows",
                "\"npm publish\" \"tar.gz\" path:.github/workflows",
                "\"npm publish\" \"scripts/\" path:.github/workflows",
                "\"npm publish\" \"dist/\" path:.github/workflows",
            ],
            Self::NpmManualOidc => &[
                "\"npm/v1/oidc/token\" path:.github/workflows",
                "\"ACTIONS_ID_TOKEN_REQUEST_TOKEN\" \"npm\" path:.github/workflows",
                "\"ACTIONS_ID_TOKEN_REQUEST_URL\" \"npm\" path:.github/workflows",
            ],
            Self::NpmTokenExposure => &[
                "\"base64\" \"NPM_TOKEN\" path:.github/workflows",
                "\"printenv\" \"NPM_TOKEN\" path:.github/workflows",
                "\"echo\" \"NODE_AUTH_TOKEN\" path:.github/workflows",
                "\"_authToken\" \"base64\" path:.github/workflows",
            ],
            Self::PolyglotLocalArchive => &[
                "\"twine upload\" \".whl\" path:.github/workflows",
                "\"cargo publish\" \".crate\" path:.github/workflows",
                "\"gem push\" \".gem\" path:.github/workflows",
                "\"dotnet nuget push\" \".nupkg\" path:.github/workflows",
            ],
            Self::CiBypassPrTarget => &[
                "\"pull_request_target\" \"github.event.pull_request.head.sha\" path:.github/workflows",
                "\"pull_request_target\" \"contents: write\" path:.github/workflows",
                "\"pull_request_target\" \"actions/checkout\" \"ref:\" path:.github/workflows",
            ],
            Self::CiBypassWorkflowRun => &[
                "\"workflow_run\" \"actions/download-artifact\" path:.github/workflows",
                "\"workflow_run\" \"gh run download\" path:.github/workflows",
                "\"workflow_run\" \"contents: write\" path:.github/workflows",
            ],
            Self::CiBypassAutoPush => &[
                "\"git push\" \"GITHUB_TOKEN\" path:.github/workflows",
                "\"gh pr merge\" path:.github/workflows",
                "\"continue-on-error: true\" path:.github/workflows",
            ],
            Self::CiSecuritySuppression => &[
                "\"paths-ignore\" \"codeql\" path:.github/workflows",
                "\"branches-ignore\" \"security\" path:.github/workflows",
                "\"if: false\" path:.github/workflows",
            ],
            Self::CiBranchProtection => &[
                "\"branches/\" \"protection\" \"gh api\" path:.github/workflows",
                "\"rulesets\" \"gh api\" path:.github/workflows",
                "\"required_status_checks\" \"gh api\" path:.github/workflows",
            ],
            Self::CiDispatchBackdoor => &[
                "\"repository_dispatch\" \"contents: write\" path:.github/workflows",
                "\"workflow_dispatch\" \"git push\" path:.github/workflows",
                "\"workflow_dispatch\" \"npm publish\" path:.github/workflows",
            ],
            Self::CiReusableWorkflowTrust => &[
                "\"uses:\" \".github/workflows/\" \"@main\" path:.github/workflows",
                "\"uses:\" \".github/workflows/\" \"@master\" path:.github/workflows",
                "\"secrets: inherit\" \".github/workflows/\" path:.github/workflows",
            ],
            Self::CiSelfHostedPrivileged => &[
                "\"self-hosted\" \"pull_request_target\" path:.github/workflows",
                "\"self-hosted\" \"workflow_run\" path:.github/workflows",
                "\"self-hosted\" \"contents: write\" path:.github/workflows",
            ],
            Self::CiAgenticPromptInjection => &[
                "\"issue_comment\" \"github.event.comment.body\" \"contents: write\" path:.github/workflows",
                "\"issue_comment\" \"github.event.comment.body\" \"OPENAI_API_KEY\" path:.github/workflows",
                "\"pull_request_target\" \"github.event.pull_request.body\" \"ANTHROPIC_API_KEY\" path:.github/workflows",
                "\"gh-aw-manifest\" \"issue_comment\" path:.github/workflows",
                "\"issue_comment\" \"github.event.comment.body\" \"gh pr create\" path:.github/workflows",
            ],
            Self::CiScriptInjection => &[
                "\"github.event.pull_request.title\" \"run:\" path:.github/workflows",
                "\"github.event.comment.body\" \"run:\" path:.github/workflows",
                "\"github.event.head_commit.message\" \"run:\" path:.github/workflows",
            ],
            Self::CiSecretExfiltration => &[
                "\"printenv\" \"curl\" path:.github/workflows",
                "\"toJSON(secrets)\" path:.github/workflows",
                "\"Get-ChildItem env:\" \"Invoke-WebRequest\" path:.github/workflows",
                "\"Github Actions Security\" \"secrets.\" path:.github/workflows",
                "\"shai-hulud\" path:.github/workflows",
            ],
            Self::CiUnpinnedThirdPartyActions => &[
                "\"uses:\" \"@v1\" \"contents: write\" path:.github/workflows",
                "\"uses:\" \"@main\" \"contents: write\" path:.github/workflows",
                "\"uses:\" \"@master\" \"contents: write\" path:.github/workflows",
                "\"tj-actions/changed-files\" path:.github/workflows",
                "\"reviewdog/action-setup\" path:.github/workflows",
                "\"aquasecurity/trivy-action\" path:.github/workflows",
                "\"aquasecurity/setup-trivy\" path:.github/workflows",
            ],
            Self::CiCachePoisoning => &[
                "\"pull_request_target\" \"refs/pull\" \"pnpm\" path:.github/workflows",
                "\"pull_request_target\" \"refs/pull\" \"actions/cache\" path:.github/workflows",
                "\"pull_request_target\" \".github/setup@main\" path:.github/workflows",
                "\"pull_request_target\" \"skipRemoteCache\" path:.github/workflows",
            ],
            Self::CiCredentialPersistence => &[
                "\"persist-credentials: true\" \"pull_request_target\" path:.github/workflows",
                "\"git config\" \"insteadOf\" \"GITHUB_TOKEN\" path:.github/workflows",
                "\"gh auth setup-git\" path:.github/workflows",
                "\"git credential approve\" path:.github/workflows",
            ],
            Self::CiSensitiveArtifactLeakage => &[
                "\"actions/upload-artifact\" \".npmrc\" path:.github/workflows",
                "\"actions/upload-artifact\" \".env\" path:.github/workflows",
                "\"actions/cache\" \".docker/config.json\" path:.github/workflows",
                "\"actions/cache\" \".aws/credentials\" path:.github/workflows",
            ],
            Self::CiEncodedRemotePayloads => &[
                "\"curl\" \"| bash\" path:.github/workflows",
                "\"base64 -d\" \"| bash\" path:.github/workflows",
                "\"EncodedCommand\" path:.github/workflows",
                "\"actions/github-script\" \"child_process\" path:.github/workflows",
            ],
            Self::DeveloperEnvironmentAutorun => &[
                "\"SessionStart\" \"node .vscode/setup.mjs\" path:.claude/settings.json",
                "\"runOn\" \"folderOpen\" \"node .claude/setup.mjs\" path:.vscode/tasks.json",
                "\"ENTRY_SCRIPT\" \"execution.js\" \"downloadToFile\" path:.claude",
                "\"BUN_VERSION\" \"execFileSync(binPath\" path:.vscode",
            ],
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum MessagePreset {
    CommitMessageSecrets,
}

impl MessagePreset {
    pub const ALL: [Self; 1] = [Self::CommitMessageSecrets];
}

impl PresetMeta for MessagePreset {
    fn name(&self) -> &'static str {
        match self {
            Self::CommitMessageSecrets => "commit-message-secrets",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::CommitMessageSecrets => {
                "Seed commit searches for leaked GitHub tokens and TeamPCP campaign markers."
            }
        }
    }

    fn queries(&self) -> &'static [&'static str] {
        match self {
            Self::CommitMessageSecrets => &[
                "\"ghp_\"",
                "\"github_pat_\"",
                "\"LongLiveTheResistanceAgainstMachines\"",
            ],
        }
    }
}

pub fn iter_workflow_presets() -> impl Iterator<Item = WorkflowPreset> {
    WorkflowPreset::ALL.into_iter()
}

pub fn iter_message_presets() -> impl Iterator<Item = MessagePreset> {
    MessagePreset::ALL.into_iter()
}
