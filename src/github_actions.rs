use once_cell::sync::Lazy;
use regex::Regex;

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex")
}

static USES_LINE_RE: Lazy<Regex> =
    Lazy::new(|| re(r#"(?i)^[+-]?\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)"#));
static FULL_SHA_RE: Lazy<Regex> = Lazy::new(|| re(r"(?i)^[0-9a-f]{40}$"));
static TAG_RE: Lazy<Regex> =
    Lazy::new(|| re(r"(?i)^(?:refs/tags/)?v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?$"));
static BRANCH_RE: Lazy<Regex> = Lazy::new(|| {
    re(
        r"(?i)^(?:refs/heads/)?(main|master|develop|development|dev|trunk|head|stable|release|releases?/.*|release[-_/].*|prod|production)$",
    )
});

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ActionRefType {
    FullSha,
    Tag,
    Branch,
    ClearlyMutable,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ActionTrust {
    FirstParty,
    ThirdParty,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ActionUse {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) subpath: Option<String>,
    pub(crate) reference: String,
    pub(crate) ref_type: ActionRefType,
    pub(crate) trust: ActionTrust,
    pub(crate) reusable_workflow: bool,
}

impl ActionUse {
    pub(crate) fn is_pinned(&self) -> bool {
        self.ref_type == ActionRefType::FullSha
    }

    pub(crate) fn is_mutable(&self) -> bool {
        !self.is_pinned()
    }

    pub(crate) fn is_third_party(&self) -> bool {
        self.trust == ActionTrust::ThirdParty
    }
}

pub(crate) fn extract_action_uses(text: &str, current_repo: &str) -> Vec<ActionUse> {
    text.lines()
        .filter_map(|line| {
            let value = USES_LINE_RE
                .captures(line)?
                .get(1)
                .map(|mat| mat.as_str().trim_end_matches(','))?;
            parse_action_use(value, current_repo)
        })
        .collect()
}

pub(crate) fn parse_action_use(value: &str, current_repo: &str) -> Option<ActionUse> {
    let value = value.trim().trim_matches(|ch| ch == '\'' || ch == '"');
    if value.is_empty()
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("docker://")
    {
        return None;
    }

    let (path, reference) = value.rsplit_once('@')?;
    let mut parts = path.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    let rest = parts.collect::<Vec<_>>();
    let subpath = if rest.is_empty() {
        None
    } else {
        Some(rest.join("/"))
    };
    let reference = reference
        .trim()
        .trim_matches(|ch| ch == '\'' || ch == '"')
        .trim_end_matches(',')
        .to_string();
    if reference.is_empty() {
        return None;
    }

    let normalized_repo = format!("{owner}/{repo}");
    let trust = if normalized_repo.eq_ignore_ascii_case(current_repo) {
        ActionTrust::FirstParty
    } else {
        ActionTrust::ThirdParty
    };
    let reusable_workflow = subpath
        .as_deref()
        .map(|path| path.to_ascii_lowercase())
        .is_some_and(|path| path.starts_with(".github/workflows/"));

    Some(ActionUse {
        owner: owner.to_string(),
        repo: repo.to_string(),
        subpath,
        ref_type: classify_ref(&reference),
        reference,
        trust,
        reusable_workflow,
    })
}

pub(crate) fn classify_ref(reference: &str) -> ActionRefType {
    let reference = reference.trim();
    if FULL_SHA_RE.is_match(reference) {
        ActionRefType::FullSha
    } else if reference.contains("${{")
        || reference.eq_ignore_ascii_case("latest")
        || reference.eq_ignore_ascii_case("head")
        || reference == "*"
    {
        ActionRefType::ClearlyMutable
    } else if BRANCH_RE.is_match(reference) {
        ActionRefType::Branch
    } else if TAG_RE.is_match(reference) {
        ActionRefType::Tag
    } else {
        ActionRefType::ClearlyMutable
    }
}

pub(crate) fn mutable_third_party_actions(action_uses: &[ActionUse]) -> Vec<&ActionUse> {
    action_uses
        .iter()
        .filter(|action_use| {
            action_use.is_third_party() && action_use.is_mutable() && !action_use.reusable_workflow
        })
        .collect()
}

pub(crate) fn mutable_reusable_workflows(action_uses: &[ActionUse]) -> Vec<&ActionUse> {
    action_uses
        .iter()
        .filter(|action_use| action_use.reusable_workflow && action_use.is_mutable())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ActionRefType, ActionTrust, extract_action_uses, parse_action_use};

    #[test]
    fn parses_full_sha_pinned_action() {
        let parsed = parse_action_use(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "owner/repo",
        )
        .expect("parse action");
        assert_eq!(parsed.owner, "actions");
        assert_eq!(parsed.repo, "checkout");
        assert_eq!(parsed.subpath, None);
        assert_eq!(parsed.reference, "11bd71901bbe5b1630ceea73d27597364c9af683");
        assert_eq!(parsed.ref_type, ActionRefType::FullSha);
        assert!(parsed.is_pinned());
        assert_eq!(parsed.trust, ActionTrust::ThirdParty);
    }

    #[test]
    fn parses_mutable_tag() {
        let parsed = parse_action_use("actions/setup-node@v1", "owner/repo").expect("parse action");
        assert_eq!(parsed.ref_type, ActionRefType::Tag);
        assert!(parsed.is_mutable());
    }

    #[test]
    fn parses_branch_ref() {
        let parsed =
            parse_action_use("third-party/deploy@main", "owner/repo").expect("parse action");
        assert_eq!(parsed.ref_type, ActionRefType::Branch);
        assert!(parsed.is_mutable());
    }

    #[test]
    fn parses_reusable_workflow_ref() {
        let parsed = parse_action_use(
            "owner/repo/.github/workflows/release.yml@main",
            "different/repo",
        )
        .expect("parse action");
        assert_eq!(
            parsed.subpath.as_deref(),
            Some(".github/workflows/release.yml")
        );
        assert_eq!(parsed.ref_type, ActionRefType::Branch);
        assert!(parsed.reusable_workflow);
    }

    #[test]
    fn extracts_uses_from_diff_lines() {
        let parsed = extract_action_uses(
            "+      uses: third-party/deploy/sub/action@v2\n+      run: cargo test",
            "owner/repo",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].subpath.as_deref(), Some("sub/action"));
        assert_eq!(parsed[0].ref_type, ActionRefType::Tag);
    }
}
