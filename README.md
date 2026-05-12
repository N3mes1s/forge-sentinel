# ForgeSentinel

ForgeSentinel is a repository forensics and supply-chain detection project focused on malicious GitHub workflow changes, publish-path compromise, CI bypass, and prompt-injection abuse in privileged automation.

The GitHub workflow detector now runs natively in Rust.

## Current scope

- Detect suspicious workflow mutations that introduce publish-path compromise
- Hunt for CI bypass patterns such as `pull_request_target`, `workflow_run`, branch-protection tampering, and security-check suppression
- Flag TanStack-style cache poisoning where `pull_request_target` runs fork PR code through dependency cache/setup paths later reused by privileged release workflows
- Flag prompt-injection surfaces where agents operate on untrusted PR or comment material with write-capable credentials
- Resolve GitHub workflow `uses:` dependencies and score mutable third-party action or reusable workflow refs in privileged workflows
- Detect GitHub Action definition compromise, including `action.yml` changes that replace container actions with composite actions running remote installer scripts
- Detect developer-environment persistence such as Claude/VS Code startup hooks that auto-run repository bootstrap scripts
- Preserve forensic cleanup evidence, including commits that remove OIDC/registry token printing from privileged workflows
- Flag documented campaign shapes such as mutable references to compromised actions, pwn-request workflows, and secret-exfiltration workflows that post explicit secrets to external endpoints
- Suppress known maintenance patterns such as generated workflow dependency pinning and approval-gated split-job `pull_request_target` workflows with empty build permissions and sanitized artifacts
- Seed investigations from GitHub code search and commit search

## Repo layout

- `src/`
  Rust product entrypoint and CLI surface.
- `detectors/github_workflow_hunt.py`
  Legacy Python reference copy of the original prototype, kept for parity checks while the Rust engine settles.
- `docs/roadmap.md`
  Short-term plan for growing ForgeSentinel beyond workflow diffs.

## Quick start

List the built-in hunt presets through the Rust CLI:

```bash
cargo run -- github-workflows presets --show-queries
```

Run the detector through the Rust CLI:

```bash
cargo run -- github-workflows hunt OWNER/REPO \
  --since 2026-04-20T00:00:00Z
```

ForgeSentinel talks to the GitHub REST API directly from Rust. Set `GITHUB_TOKEN` or `GH_TOKEN` for authenticated rate limits; the detector no longer requires the GitHub CLI for remote hunts.

Run a built-in hunt preset:

```bash
cargo run -- github-workflows hunt \
  --hunt-preset ci-agentic-prompt-injection \
  --since 2026-01-01T00:00:00Z
```

Hunt developer/agent auto-run persistence:

```bash
cargo run -- github-workflows hunt \
  --hunt-preset developer-environment-autorun \
  --since 2026-04-01T00:00:00Z \
  --explain
```

Scan GitHub with all built-in workflow seed presets:

```bash
cargo run -- github-workflows scan \
  --since 2026-04-01T00:00:00Z \
  --search-limit 20 \
  --commits-per-path 2 \
  --explain
```

The scan command is a rate-limit-aware wrapper around the same Rust detector. It uses all workflow presets by default, sleeps between seed queries, and can print the planned query set without scanning:

```bash
cargo run -- github-workflows scan --show-queries
```

Explain the detection model:

```bash
cargo run -- github-workflows detections --show-factors
```

Inspect a known commit directly:

```bash
cargo run -- github-workflows hunt \
  bitwarden/clients \
  --sha 47c6f59083d3851fa1f15970dc51cf4a15e55840 \
  --min-score 0 \
  --show-evidence
```

## Immediate next work

- Expand the known-compromised-action catalog and add persisted ref-drift history across scans
- Add continuous capture for transient public workflow changes and short-lived malicious repos
- Add regression fixtures so future rule changes can be checked against known Bitwarden, Deno, prompt-injection, and developer-environment persistence cases
