# ForgeSentinel Roadmap

## Phase 1

Stabilize the existing workflow-compromise detector:

- keep the current scoring model and regression cases
- reduce noisy workflow-generation false positives
- preserve high-signal detections such as Bitwarden-style publish compromise
- keep pwn-request detection job-context aware enough to suppress approval-gated split-job workflows
- lock in native Rust regression coverage before broader rule expansion

## Phase 2

Add action dependency resolution:

- resolve `uses:` references to owner/repo, optional subpath, reusable workflow path, and ref
- distinguish full SHA pinning from mutable tags, branch refs, and clearly mutable symbolic refs
- score privileged workflows that rely on mutable third-party actions or reusable workflows
- resolve ambiguous refs against GitHub when possible
- correlate known compromised actions and per-commit ref drift
- persist ref-drift history across scans

## Phase 2.5

Detect action implementation compromise:

- inspect `action.yml` and nested `action.yaml` mutations alongside workflows
- flag container-to-composite rewrites that execute remote scripts
- correlate protective workflow removal with agent instruction files such as `CLAUDE.md`
- detect agent/editor startup persistence through `.claude` hooks and VS Code folder-open tasks

## Phase 2.6

Track documented attack patterns:

- maintain a conservative catalog of publicly compromised GitHub Action repositories
- flag GhostAction/Shai-Hulud style workflows that exfiltrate explicit secrets to external endpoints
- strengthen pwn-request coverage for `pull_request_target` workflows that checkout and execute fork PR code
- detect TanStack-style cache poisoning where fork PR code in `pull_request_target` mutates dependency caches restored by later release workflows
- detect credential persistence, sensitive artifact/cache leakage, remote/encoded payload execution, dynamic GitHub Script execution, Docker socket exposure, and untrusted ref-name shell interpolation as attacker primitives
- preserve cleanup/root-cause evidence when later commits remove OIDC or registry token printing

## Phase 2.7

Make GitHub-scale scanning usable:

- provide a first-class `github-workflows scan` command that runs all built-in workflow seed presets
- pace seed queries so GitHub code-search rate limits do not make broad scans fail immediately
- expose detection families and factor explanations through `github-workflows detections`
- add per-finding explanations that separate core signals, context, mitigations, and score contribution
- seed developer-environment persistence searches, not only `.github/workflows` searches

## Phase 3

Add transient capture:

- ingest public push and workflow metadata continuously
- snapshot suspicious workflow files, diffs, and release artifacts before deletion or privatization
- persist enough evidence to survive GitHub search de-indexing

## Phase 3.5

Add package-content forensics:

- inspect npm tarballs directly from Rust, without adding Python to the detector path
- flag TanStack-style optionalDependency GitHub payload commits and hidden root JavaScript payloads
- detect package contents that harvest runner memory, npm OIDC tokens, cloud credentials, kube tokens, npmrc, git credentials, or SSH keys
- keep package-level evidence tied back to workflow root-cause findings when both are available

## Phase 4

Add broader forge intelligence:

- correlate workflow mutations with release, package, and attestation data
- map actor patterns across repositories
- score campaigns instead of isolated commits
