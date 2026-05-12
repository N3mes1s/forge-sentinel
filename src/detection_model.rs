#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FactorKind {
    Core,
    Context,
    Mitigation,
}

impl FactorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Context => "context",
            Self::Mitigation => "mitigation",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FactorMeta {
    pub(crate) name: &'static str,
    pub(crate) family: &'static str,
    pub(crate) kind: FactorKind,
    pub(crate) description: &'static str,
}

pub(crate) const DETECTION_FAMILIES: &[(&str, &str)] = &[
    (
        "publish-compromise",
        "Publish, registry, artifact, OIDC, and release-boundary compromise.",
    ),
    (
        "package-content-compromise",
        "Malicious npm package manifests, lifecycle hooks, hidden payloads, and credential-harvesting tarball contents.",
    ),
    (
        "ci-privilege-bypass",
        "GitHub Actions privilege regain through trigger, token, gate, or workflow topology changes.",
    ),
    (
        "action-supply-chain",
        "Mutable, downgraded, or publicly compromised third-party action and reusable workflow dependencies.",
    ),
    (
        "action-implementation-compromise",
        "Malicious changes to action manifests or privileged automation instruction files.",
    ),
    (
        "secret-exfiltration",
        "Secret printing, enumeration, runner-memory harvesting, and external exfiltration.",
    ),
    (
        "agentic-prompt-injection",
        "Agent/LLM workflows that consume untrusted text with privileged tools, secrets, or write tokens.",
    ),
    (
        "developer-environment-compromise",
        "Agent/editor startup hooks and bootstrap scripts that execute repository code in privileged human or agent sessions.",
    ),
    (
        "suppression",
        "Benign or risk-reducing context that lowers confidence or suppresses weak findings.",
    ),
];

pub(crate) const FACTOR_MODEL: &[FactorMeta] = &[
    FactorMeta {
        name: "secret_material_printed_or_encoded",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A token, password, or auth-looking value is printed or base64 encoded in workflow output.",
    },
    FactorMeta {
        name: "workflow_secret_enumeration_and_external_exfiltration",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "The workflow enumerates secrets/environment and sends data to an external endpoint.",
    },
    FactorMeta {
        name: "explicit_secret_exfiltration_to_external_endpoint",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "Multiple explicit GitHub secrets are posted or sent to a non-GitHub URL.",
    },
    FactorMeta {
        name: "ghostaction_style_secret_exfiltration_workflow",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A security-named workflow matches the GhostAction/Shai-Hulud style secret POST pattern.",
    },
    FactorMeta {
        name: "runner_memory_secret_harvesting_with_external_exfiltration",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "Runner memory/process secret harvesting is paired with external network exfiltration.",
    },
    FactorMeta {
        name: "npm_package_github_optional_dependency_payload",
        family: "package-content-compromise",
        kind: FactorKind::Core,
        description: "An npm package optionalDependency resolves directly to a GitHub commit payload.",
    },
    FactorMeta {
        name: "npm_package_optional_dependency_install_chain",
        family: "package-content-compromise",
        kind: FactorKind::Core,
        description: "A GitHub optionalDependency is paired with local package payload indicators.",
    },
    FactorMeta {
        name: "npm_package_credential_harvesting_payload",
        family: "package-content-compromise",
        kind: FactorKind::Core,
        description: "Package contents reference multiple credential sources such as cloud metadata, kube tokens, npmrc, git credentials, or SSH keys.",
    },
    FactorMeta {
        name: "npm_package_runner_memory_oidc_harvesting",
        family: "package-content-compromise",
        kind: FactorKind::Core,
        description: "Package contents reference runner process memory or npm OIDC token extraction.",
    },
    FactorMeta {
        name: "npm_package_session_network_exfiltration",
        family: "package-content-compromise",
        kind: FactorKind::Core,
        description: "Package contents reference Session/Oxen file-upload infrastructure used for exfiltration.",
    },
    FactorMeta {
        name: "publishes_committed_archive_artifact",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A committed archive artifact is published by workflow code.",
    },
    FactorMeta {
        name: "registry_publish_with_committed_archive",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A registry publish path is changed in the same commit as a committed package archive.",
    },
    FactorMeta {
        name: "dynamic_artifact_publish_with_registry_auth",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A publish command uses a dynamic artifact path while registry authentication is present.",
    },
    FactorMeta {
        name: "dynamic_artifact_publish_with_release_boundary_change",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A dynamic publish artifact is introduced with release trigger or gate changes.",
    },
    FactorMeta {
        name: "runner_local_artifact_publish_with_boundary_change",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "The workflow publishes runner-local temp/home artifacts with release-boundary changes.",
    },
    FactorMeta {
        name: "external_artifact_publish_with_boundary_change",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A workflow fetches an external artifact before publishing under changed trust boundaries.",
    },
    FactorMeta {
        name: "local_archive_publish_with_release_gate_rewrite",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A local archive publish path is paired with release-gate rewrites.",
    },
    FactorMeta {
        name: "staged_local_artifact_publish_with_registry_capability",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A package artifact is staged in temp/home storage before a privileged registry publish.",
    },
    FactorMeta {
        name: "pull_request_target_untrusted_checkout_with_write_capability",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A pull_request_target workflow checks out untrusted PR code while write/publish capability is present.",
    },
    FactorMeta {
        name: "pull_request_target_executes_untrusted_code",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A pull_request_target workflow checks out PR head code and runs build/test/install commands.",
    },
    FactorMeta {
        name: "pull_request_target_cache_poisoning_surface",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A pull_request_target job checks out fork PR merge code, restores/saves dependency cache state, and runs package build code.",
    },
    FactorMeta {
        name: "removes_pull_request_target_cache_poisoning_surface",
        family: "suppression",
        kind: FactorKind::Core,
        description: "A later workflow change removes a pull_request_target cache-poisoning surface; useful as remediation evidence.",
    },
    FactorMeta {
        name: "workflow_run_artifact_with_write_or_publish_capability",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A workflow_run job downloads artifacts and then has write or publish capability.",
    },
    FactorMeta {
        name: "ci_push_or_merge_with_write_permissions",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "CI can push or merge while write credentials or broad triggers are present.",
    },
    FactorMeta {
        name: "workflow_modifies_branch_protection_with_write_capability",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Workflow code modifies branch protection or rulesets with write capability.",
    },
    FactorMeta {
        name: "dispatch_backdoor_with_write_or_publish_capability",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A dispatch-triggered workflow path can write, publish, or create privileged follow-on actions.",
    },
    FactorMeta {
        name: "dispatch_backdoor_with_repo_token",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A dispatch-triggered workflow receives a repo write token.",
    },
    FactorMeta {
        name: "untrusted_code_on_self_hosted_runner",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Untrusted PR/artifact code can run on a self-hosted runner.",
    },
    FactorMeta {
        name: "self_hosted_runner_with_repo_token_and_untrusted_input",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A self-hosted runner combines repo tokens with untrusted artifacts, PR heads, or agents.",
    },
    FactorMeta {
        name: "protective_workflow_bypass_with_sensitive_follow_on_change",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Security/protective workflow filters are weakened near sensitive workflow changes.",
    },
    FactorMeta {
        name: "check_suppression_with_sensitive_follow_on_change",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "continue-on-error or check suppression is paired with publish, push, or gate changes.",
    },
    FactorMeta {
        name: "skip_guard_with_sensitive_workflow_change",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Actor, label, or skip-ci guards are added near sensitive workflow changes.",
    },
    FactorMeta {
        name: "unpinned_third_party_action_in_privileged_workflow",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "A privileged workflow uses a mutable third-party action reference.",
    },
    FactorMeta {
        name: "unpinned_reusable_workflow_with_secret_inheritance",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "A reusable workflow reference is mutable while secrets are inherited.",
    },
    FactorMeta {
        name: "known_compromised_mutable_action_ref",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "A workflow uses a known publicly compromised action repository via a mutable ref.",
    },
    FactorMeta {
        name: "known_compromised_action_in_privileged_workflow",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "A known publicly compromised action repository appears in a privileged workflow.",
    },
    FactorMeta {
        name: "action_dependency_ref_downgrade_to_mutable",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "An action dependency changed from SHA-pinned to tag, branch, or symbolic mutable ref.",
    },
    FactorMeta {
        name: "privileged_action_dependency_ref_downgrade_to_mutable",
        family: "action-supply-chain",
        kind: FactorKind::Core,
        description: "A privileged workflow downgraded an action dependency from SHA-pinned to mutable.",
    },
    FactorMeta {
        name: "action_manifest_remote_script_execution",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "An action manifest runs a remote script through curl/wget piped to a shell.",
    },
    FactorMeta {
        name: "security_workflow_removed_with_action_manifest_change",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "A protective workflow is removed or weakened alongside an action manifest change.",
    },
    FactorMeta {
        name: "agent_instruction_file_with_action_manifest_change",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "Agent instruction files are introduced near action-manifest or protective-workflow changes.",
    },
    FactorMeta {
        name: "agent_or_editor_startup_hook_executes_repo_code",
        family: "developer-environment-compromise",
        kind: FactorKind::Core,
        description: "Claude or editor startup hooks are added that automatically execute code from the repository.",
    },
    FactorMeta {
        name: "agent_runtime_bootstrap_executes_local_payload",
        family: "developer-environment-compromise",
        kind: FactorKind::Core,
        description: "A repo-local bootstrap downloads or locates a runtime and executes a local payload script.",
    },
    FactorMeta {
        name: "agent_autorun_bootstrap_chain",
        family: "developer-environment-compromise",
        kind: FactorKind::Core,
        description: "An auto-run hook is paired with a runtime bootstrap or payload script, forming a developer/agent execution chain.",
    },
    FactorMeta {
        name: "removed_oidc_registry_token_exposure_forensics",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A later commit removes OIDC or registry token printing, preserving forensic evidence of prior exposure.",
    },
    FactorMeta {
        name: "direct_script_injection_in_privileged_workflow",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Untrusted GitHub event text is interpolated into script execution in a privileged workflow.",
    },
    FactorMeta {
        name: "pull_request_target_with_oidc_write",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A pull_request_target workflow gains id-token write capability while handling PR-controlled code or registry auth.",
    },
    FactorMeta {
        name: "pull_request_target_with_explicit_secret_use",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A pull_request_target workflow uses explicit secrets while checking out PR-controlled code.",
    },
    FactorMeta {
        name: "privileged_checkout_persists_credentials",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A privileged workflow checks out untrusted refs while keeping checkout credentials persisted.",
    },
    FactorMeta {
        name: "workflow_run_untrusted_checkout_with_write_or_publish",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A workflow_run job checks out the triggering run's head ref while write or publish capability is present.",
    },
    FactorMeta {
        name: "sensitive_files_uploaded_as_artifact",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A workflow uploads credential-bearing paths such as .env, .npmrc, cloud config, Docker config, or SSH material as artifacts.",
    },
    FactorMeta {
        name: "sensitive_paths_cached_in_workflow",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A workflow caches credential-bearing paths in a privileged or untrusted execution context.",
    },
    FactorMeta {
        name: "git_credential_persistence_with_repo_token",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Workflow code configures persistent Git credentials while repo write, registry, or broad token capability is present.",
    },
    FactorMeta {
        name: "remote_script_pipe_to_shell",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "A privileged workflow or action downloads a remote script and pipes it to a shell.",
    },
    FactorMeta {
        name: "base64_decoded_payload_execution",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "Workflow code decodes base64 content and executes it as shell, PowerShell, Python, or Node code.",
    },
    FactorMeta {
        name: "powershell_encoded_command_execution",
        family: "action-implementation-compromise",
        kind: FactorKind::Core,
        description: "Workflow code invokes PowerShell with an encoded command payload.",
    },
    FactorMeta {
        name: "untrusted_input_written_to_github_env",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "Untrusted GitHub context data is written to GITHUB_ENV in a privileged or PR-target workflow.",
    },
    FactorMeta {
        name: "github_script_executes_untrusted_dynamic_code",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "actions/github-script reads untrusted event data and reaches dynamic code or process execution under privilege.",
    },
    FactorMeta {
        name: "package_script_safety_guard_removed",
        family: "publish-compromise",
        kind: FactorKind::Core,
        description: "A workflow removes package-manager lifecycle-script safety guards in a privileged, publish, or PR-target context.",
    },
    FactorMeta {
        name: "privileged_shell_uses_untrusted_ref_name",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A privileged workflow interpolates attacker-controllable branch/ref names into shell commands.",
    },
    FactorMeta {
        name: "docker_socket_exposed_to_untrusted_workflow",
        family: "ci-privilege-bypass",
        kind: FactorKind::Core,
        description: "A workflow exposes the host Docker socket while untrusted PR, workflow_run, or self-hosted runner context is present.",
    },
    FactorMeta {
        name: "cloud_secret_with_external_network_path",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "Cloud, registry, or package-manager secrets are introduced near external network transfer code.",
    },
    FactorMeta {
        name: "agentic_prompt_injection_with_write_or_secret_capability",
        family: "agentic-prompt-injection",
        kind: FactorKind::Core,
        description: "An agentic workflow reads untrusted text while holding write, secret, publish, or registry capability.",
    },
    FactorMeta {
        name: "agentic_prompt_injection_on_self_hosted_runner",
        family: "agentic-prompt-injection",
        kind: FactorKind::Core,
        description: "An agentic workflow reads untrusted text on a self-hosted runner.",
    },
    FactorMeta {
        name: "agentic_prompt_injection_over_fork_pr_material",
        family: "agentic-prompt-injection",
        kind: FactorKind::Core,
        description: "An agentic workflow reads fork PR material and has shell/edit/write capability.",
    },
    FactorMeta {
        name: "commit_message_contains_github_token",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A commit message contains a GitHub token-shaped secret.",
    },
    FactorMeta {
        name: "prompt_injection_marker_decodes_to_github_token",
        family: "secret-exfiltration",
        kind: FactorKind::Core,
        description: "A known prompt-injection marker decodes to GitHub token-shaped material.",
    },
    FactorMeta {
        name: "prompt_injection_marker_in_commit_message",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "A known prompt-injection campaign marker appears in the commit message.",
    },
    FactorMeta {
        name: "pull_request_target_untrusted_code_mitigated",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The pull_request_target workflow appears isolated by empty permissions, approval gates, or artifact sanitization.",
    },
    FactorMeta {
        name: "maintainer_gated_trigger",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The trigger checks commenter/write/admin permission before privileged behavior.",
    },
    FactorMeta {
        name: "merged_pr_only_scope_reduction",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The workflow limits scope to merged/non-main PR paths.",
    },
    FactorMeta {
        name: "generated_workflow_regeneration",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The change appears to regenerate generated workflow files.",
    },
    FactorMeta {
        name: "locked_workflow_bundle_regeneration",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The change appears to regenerate locked workflow bundle files.",
    },
    FactorMeta {
        name: "adds_write_all_permissions",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds permissions: write-all.",
    },
    FactorMeta {
        name: "adds_id_token_write_permission",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds id-token: write capability.",
    },
    FactorMeta {
        name: "adds_actions_write_permission",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds actions: write capability.",
    },
    FactorMeta {
        name: "adds_packages_write_permission",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds packages: write capability.",
    },
    FactorMeta {
        name: "persists_checkout_credentials",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "actions/checkout is configured with persisted credentials.",
    },
    FactorMeta {
        name: "persists_git_credentials",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Workflow code configures Git credential persistence or authenticated URL rewriting.",
    },
    FactorMeta {
        name: "caches_sensitive_credential_path",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The workflow configures actions/cache for credential-bearing paths.",
    },
    FactorMeta {
        name: "downloads_and_executes_remote_script",
        family: "action-implementation-compromise",
        kind: FactorKind::Context,
        description: "The workflow downloads a remote script and executes it.",
    },
    FactorMeta {
        name: "writes_untrusted_context_to_github_env",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Attacker-controllable GitHub context data is written to GITHUB_ENV.",
    },
    FactorMeta {
        name: "writes_untrusted_context_to_github_output",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Attacker-controllable GitHub context data is written to GITHUB_OUTPUT.",
    },
    FactorMeta {
        name: "github_script_dynamic_code_execution",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "actions/github-script reaches eval, Function, child_process, or synchronous process execution.",
    },
    FactorMeta {
        name: "github_script_reads_untrusted_context",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "actions/github-script reads user-controlled GitHub event fields.",
    },
    FactorMeta {
        name: "removes_package_script_safety_guard",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The patch removes or disables package-manager ignore-scripts protections.",
    },
    FactorMeta {
        name: "shell_uses_untrusted_ref_name",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "A shell command interpolates attacker-controllable branch or ref names.",
    },
    FactorMeta {
        name: "exposes_docker_socket",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow references the host Docker socket.",
    },
    FactorMeta {
        name: "checks_out_workflow_run_head_ref",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "A workflow_run job checks out the triggering run's head branch or SHA.",
    },
    FactorMeta {
        name: "adds_pull_request_target",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds a pull_request_target trigger.",
    },
    FactorMeta {
        name: "checks_out_pr_head_in_privileged_context",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow checks out PR head code from a privileged trigger context.",
    },
    FactorMeta {
        name: "checks_out_pr_merge_ref_in_privileged_context",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow checks out refs/pull/<number>/merge or head from a pull_request_target context.",
    },
    FactorMeta {
        name: "uses_cache_or_setup_action_in_untrusted_pr_job",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The untrusted PR job uses actions/cache or a setup action likely to restore/save dependency caches.",
    },
    FactorMeta {
        name: "executes_package_build_in_untrusted_pr_context",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The untrusted PR job runs package install/build/test commands that can execute fork-controlled code.",
    },
    FactorMeta {
        name: "removes_pull_request_target",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The workflow removes a pull_request_target trigger.",
    },
    FactorMeta {
        name: "adds_workflow_run_trigger",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds a workflow_run trigger.",
    },
    FactorMeta {
        name: "downloads_artifact_in_workflow_run",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "A workflow_run path downloads artifacts from another run.",
    },
    FactorMeta {
        name: "adds_continue_on_error",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow makes failures non-blocking with continue-on-error.",
    },
    FactorMeta {
        name: "adds_ci_push_or_merge",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "CI gains a path to push, merge, or call merge APIs.",
    },
    FactorMeta {
        name: "creates_pull_request_from_ci",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "CI can create pull requests.",
    },
    FactorMeta {
        name: "hands_repo_write_token",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Workflow code passes a repository write token or PAT-shaped secret.",
    },
    FactorMeta {
        name: "modifies_branch_protection_or_rulesets",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Workflow code calls APIs related to branch protection or rulesets.",
    },
    FactorMeta {
        name: "adds_dispatch_trigger",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds repository_dispatch or workflow_dispatch reachability.",
    },
    FactorMeta {
        name: "uses_self_hosted_runner",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow uses a self-hosted runner.",
    },
    FactorMeta {
        name: "adds_protective_workflow_bypass_filter",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds path, branch, or false-condition filters to protective checks.",
    },
    FactorMeta {
        name: "adds_actor_or_label_based_skip_guard",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds actor, label, or skip-ci based gating.",
    },
    FactorMeta {
        name: "direct_untrusted_context_interpolation",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "Untrusted GitHub event text is interpolated into a script context.",
    },
    FactorMeta {
        name: "changes_action_manifest",
        family: "action-implementation-compromise",
        kind: FactorKind::Context,
        description: "The commit changes an action.yml/action.yaml manifest.",
    },
    FactorMeta {
        name: "action_manifest_switches_docker_to_composite",
        family: "action-implementation-compromise",
        kind: FactorKind::Context,
        description: "An action manifest changes from a Docker action shape to a composite action shape.",
    },
    FactorMeta {
        name: "removes_protective_workflow",
        family: "action-implementation-compromise",
        kind: FactorKind::Context,
        description: "A protective workflow file is removed or materially weakened.",
    },
    FactorMeta {
        name: "adds_agent_instruction_file",
        family: "action-implementation-compromise",
        kind: FactorKind::Context,
        description: "An agent instruction file such as CLAUDE.md or AGENTS.md is added.",
    },
    FactorMeta {
        name: "adds_agent_or_editor_autorun_file",
        family: "developer-environment-compromise",
        kind: FactorKind::Context,
        description: "A Claude or VS Code auto-run/hook-capable file is added.",
    },
    FactorMeta {
        name: "adds_or_changes_agent_payload_script",
        family: "developer-environment-compromise",
        kind: FactorKind::Context,
        description: "A payload-shaped script used by agent/editor startup automation is added or changed.",
    },
    FactorMeta {
        name: "dependency_update_cover_message_for_sensitive_automation",
        family: "developer-environment-compromise",
        kind: FactorKind::Context,
        description: "The commit message claims dependency/security maintenance while changing sensitive automation instead of dependency manifests.",
    },
    FactorMeta {
        name: "removes_secret_material_printing_or_encoding",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The commit removes a line that printed or base64 encoded token-like material.",
    },
    FactorMeta {
        name: "uses_sha_pinned_action_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "An action dependency is pinned to a full commit SHA.",
    },
    FactorMeta {
        name: "uses_mutable_tag_action_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "An action dependency uses a mutable version tag.",
    },
    FactorMeta {
        name: "uses_branch_action_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "An action dependency uses a branch ref.",
    },
    FactorMeta {
        name: "uses_clearly_mutable_action_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "An action dependency uses a symbolic or otherwise clearly mutable ref.",
    },
    FactorMeta {
        name: "uses_sha_pinned_reusable_workflow_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "A reusable workflow dependency is pinned to a full commit SHA.",
    },
    FactorMeta {
        name: "uses_mutable_tag_reusable_workflow_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "A reusable workflow dependency uses a mutable version tag.",
    },
    FactorMeta {
        name: "uses_branch_reusable_workflow_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "A reusable workflow dependency uses a branch ref.",
    },
    FactorMeta {
        name: "uses_clearly_mutable_reusable_workflow_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "A reusable workflow dependency uses a symbolic or otherwise clearly mutable ref.",
    },
    FactorMeta {
        name: "resolved_action_ref_type_via_github",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "The detector resolved an ambiguous action ref against GitHub tags or branches.",
    },
    FactorMeta {
        name: "changes_action_dependency_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "An action or reusable workflow dependency ref changed.",
    },
    FactorMeta {
        name: "uses_known_compromised_action_repo",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "A dependency references a publicly reported compromised action repository.",
    },
    FactorMeta {
        name: "introduces_unpinned_external_action",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "The change introduces a mutable third-party action dependency.",
    },
    FactorMeta {
        name: "uses_unpinned_reusable_workflow_ref",
        family: "action-supply-chain",
        kind: FactorKind::Context,
        description: "The change introduces a mutable reusable workflow dependency.",
    },
    FactorMeta {
        name: "suspicious_workflow_name_or_path",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The workflow name or path matches suspicious security/exfiltration campaign naming.",
    },
    FactorMeta {
        name: "references_multiple_explicit_secrets",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The workflow references multiple explicit GitHub secrets.",
    },
    FactorMeta {
        name: "enumerates_environment_or_secrets",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The workflow enumerates environment variables or secrets.",
    },
    FactorMeta {
        name: "external_network_or_exfil_path",
        family: "secret-exfiltration",
        kind: FactorKind::Context,
        description: "The workflow invokes an external network transfer command.",
    },
    FactorMeta {
        name: "adds_agentic_or_llm_tooling",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow adds agentic or LLM tooling.",
    },
    FactorMeta {
        name: "reads_untrusted_issue_pr_or_comment_text",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow reads user-controlled issue, PR, comment, review, discussion, or commit-message text.",
    },
    FactorMeta {
        name: "adds_comment_or_review_trigger",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow adds issue/comment/review/discussion trigger reachability.",
    },
    FactorMeta {
        name: "fetches_pr_head_from_fork_or_pull_ref",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow fetches fork PR head material or refs/pull content.",
    },
    FactorMeta {
        name: "reads_pr_metadata_for_agent",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow reads PR metadata such as title, body, or base branch for an agent.",
    },
    FactorMeta {
        name: "grants_agent_shell_or_edit_tools",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow grants shell, git, gh, or edit tools to an agent.",
    },
    FactorMeta {
        name: "hands_agent_repo_write_token",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "The workflow hands a repository write token to an agent.",
    },
    FactorMeta {
        name: "agentic_workflow_reads_untrusted_user_text",
        family: "agentic-prompt-injection",
        kind: FactorKind::Context,
        description: "An agentic workflow reads untrusted user-controlled text.",
    },
    FactorMeta {
        name: "commenter_must_have_write_or_admin",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The workflow gates comment-triggered behavior on write/admin permission.",
    },
    FactorMeta {
        name: "requires_merged_non_main_pr",
        family: "suppression",
        kind: FactorKind::Mitigation,
        description: "The workflow narrows operation to merged non-main PRs.",
    },
    FactorMeta {
        name: "stages_artifact_in_temp_or_home",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow stages an artifact in runner temp or home storage.",
    },
    FactorMeta {
        name: "publishes_dynamic_artifact_path",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow publishes an artifact path controlled by inputs, event data, or env.",
    },
    FactorMeta {
        name: "publishes_runner_temp_or_home_artifact",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow publishes an artifact from runner temp or home storage.",
    },
    FactorMeta {
        name: "fetches_artifact_before_publish",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow fetches an artifact before a publish step.",
    },
    FactorMeta {
        name: "fetches_external_artifact_before_publish",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow fetches an external artifact before a publish step.",
    },
    FactorMeta {
        name: "publishes_local_archive_path",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow publishes a local archive file path.",
    },
    FactorMeta {
        name: "adds_archive_blob_in_same_commit",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The commit adds a package/archive blob alongside workflow changes.",
    },
    FactorMeta {
        name: "adds_registry_publish",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds a registry publish command.",
    },
    FactorMeta {
        name: "adds_manual_oidc_token_exchange",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds manual OIDC token exchange logic.",
    },
    FactorMeta {
        name: "adds_oidc_or_provenance_token_path",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds OIDC, id-token, trusted publish, or provenance token behavior.",
    },
    FactorMeta {
        name: "npm_package_lifecycle_script_executes_payload",
        family: "package-content-compromise",
        kind: FactorKind::Context,
        description: "The package manifest has an install/prepare lifecycle script that executes local JavaScript or shell payload code.",
    },
    FactorMeta {
        name: "npm_package_large_root_javascript_payload",
        family: "package-content-compromise",
        kind: FactorKind::Context,
        description: "The tarball contains an unusually large JavaScript payload at package root.",
    },
    FactorMeta {
        name: "npm_package_unlisted_root_payload",
        family: "package-content-compromise",
        kind: FactorKind::Context,
        description: "A root JavaScript payload is present even though package files metadata does not explicitly include it.",
    },
    FactorMeta {
        name: "adds_registry_auth_token_handling",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The workflow adds registry authentication token handling.",
    },
    FactorMeta {
        name: "adds_broader_or_tag_trigger",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The workflow adds push, pull_request_target, workflow_run, or tag trigger reachability.",
    },
    FactorMeta {
        name: "removes_release_gates_or_build_steps",
        family: "publish-compromise",
        kind: FactorKind::Context,
        description: "The patch removes release gates, checks, build/test steps, or protective conditions.",
    },
    FactorMeta {
        name: "bulk_workflow_mutation",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "The commit changes many workflow files at once.",
    },
    FactorMeta {
        name: "no_public_pr_association",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "No public PR association was found for the suspicious commit during enrichment.",
    },
    FactorMeta {
        name: "actions_run_for_suspicious_sha",
        family: "ci-privilege-bypass",
        kind: FactorKind::Context,
        description: "GitHub Actions run metadata exists for the suspicious commit during enrichment.",
    },
];

pub(crate) fn factor_meta(name: &str) -> Option<&'static FactorMeta> {
    FACTOR_MODEL.iter().find(|meta| meta.name == name)
}

pub(crate) fn humanize_factor(name: &str) -> String {
    let mut out = String::new();
    let mut capitalize_next = true;
    for ch in name.chars() {
        if ch == '_' {
            out.push(' ');
            capitalize_next = false;
        } else if capitalize_next {
            out.extend(ch.to_uppercase());
            capitalize_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}
