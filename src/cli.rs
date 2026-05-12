use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::detection_model::{DETECTION_FAMILIES, FACTOR_MODEL};
use crate::github_workflows;
use crate::npm_packages;
use crate::presets::{
    MessagePreset, PresetMeta, WorkflowPreset, iter_message_presets, iter_workflow_presets,
};

#[derive(Parser)]
#[command(
    name = "forge-sentinel",
    version,
    about = "Repository forensics and supply-chain detection for GitHub workflow compromise"
)]
pub struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

impl Cli {
    pub fn run(self) -> Result<i32> {
        match self.command {
            TopLevelCommand::GithubWorkflows(command) => command.run(),
            TopLevelCommand::NpmPackages(command) => command.run(),
        }
    }
}

#[derive(Subcommand)]
enum TopLevelCommand {
    /// Hunt suspicious GitHub workflow mutations and CI compromise paths.
    GithubWorkflows(GithubWorkflowCommand),
    /// Inspect npm package tarballs for supply-chain compromise indicators.
    NpmPackages(NpmPackageCommand),
}

#[derive(Subcommand)]
enum GithubWorkflowAction {
    /// Run the current GitHub workflow detector.
    Hunt(GithubWorkflowHuntArgs),
    /// Scan GitHub using built-in seed presets.
    Scan(GithubWorkflowScanArgs),
    /// List the built-in hunt presets.
    Presets(ListPresetsArgs),
    /// Explain detection families and factors.
    Detections(ListDetectionsArgs),
}

#[derive(Args)]
struct GithubWorkflowCommand {
    #[command(subcommand)]
    action: GithubWorkflowAction,
}

impl GithubWorkflowCommand {
    fn run(self) -> Result<i32> {
        match self.action {
            GithubWorkflowAction::Hunt(args) => args.run(),
            GithubWorkflowAction::Scan(args) => args.run(),
            GithubWorkflowAction::Presets(args) => args.run(),
            GithubWorkflowAction::Detections(args) => args.run(),
        }
    }
}

#[derive(Subcommand)]
enum NpmPackageAction {
    /// Inspect npm package specs, tarball URLs, or local .tgz files.
    Inspect(NpmPackageInspectArgs),
}

#[derive(Args)]
struct NpmPackageCommand {
    #[command(subcommand)]
    action: NpmPackageAction,
}

impl NpmPackageCommand {
    fn run(self) -> Result<i32> {
        match self.action {
            NpmPackageAction::Inspect(args) => args.run(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum PresetFamily {
    Workflow,
    Message,
    All,
}

#[derive(Args)]
struct ListPresetsArgs {
    /// Which preset family to list.
    #[arg(long, value_enum, default_value_t = PresetFamily::All)]
    family: PresetFamily,
    /// Print the underlying seed queries too.
    #[arg(long)]
    show_queries: bool,
}

impl ListPresetsArgs {
    fn run(self) -> Result<i32> {
        match self.family {
            PresetFamily::Workflow => {
                print_workflow_presets(self.show_queries);
            }
            PresetFamily::Message => {
                print_message_presets(self.show_queries);
            }
            PresetFamily::All => {
                print_workflow_presets(self.show_queries);
                println!();
                print_message_presets(self.show_queries);
            }
        }
        Ok(0)
    }
}

#[derive(Args)]
struct ListDetectionsArgs {
    /// Print individual detection factors too.
    #[arg(long)]
    show_factors: bool,
    /// Only show one detection family.
    #[arg(long)]
    family: Option<String>,
}

impl ListDetectionsArgs {
    fn run(self) -> Result<i32> {
        let family_filter = self.family.as_deref();
        println!("Detection families:");
        for (family, description) in DETECTION_FAMILIES {
            if family_filter.is_some_and(|filter| filter != *family) {
                continue;
            }
            println!("  {family}: {description}");
            if self.show_factors {
                for factor in FACTOR_MODEL
                    .iter()
                    .filter(|factor| factor.family == *family)
                {
                    println!(
                        "    - {} [{}]: {}",
                        factor.name,
                        factor.kind.as_str(),
                        factor.description
                    );
                }
            }
        }

        if let Some(family) = family_filter {
            let known_family = DETECTION_FAMILIES
                .iter()
                .any(|(known_family, _)| *known_family == family);
            if !known_family {
                bail!("unknown detection family {family:?}");
            }
        }
        Ok(0)
    }
}

fn print_workflow_presets(show_queries: bool) {
    println!("Workflow presets:");
    for preset in iter_workflow_presets() {
        println!("  {}: {}", preset.name(), preset.description());
        if show_queries {
            for query in preset.queries() {
                println!("    - {}", query);
            }
        }
    }
}

fn print_message_presets(show_queries: bool) {
    println!("Message presets:");
    for preset in iter_message_presets() {
        println!("  {}: {}", preset.name(), preset.description());
        if show_queries {
            for query in preset.queries() {
                println!("    - {}", query);
            }
        }
    }
}

#[derive(Args)]
pub(crate) struct GithubWorkflowHuntArgs {
    /// OWNER/REPO values.
    pub(crate) repos: Vec<String>,
    /// ISO timestamp, e.g. 2026-04-22T00:00:00Z.
    #[arg(long)]
    pub(crate) since: Option<String>,
    /// ISO timestamp upper bound.
    #[arg(long)]
    pub(crate) until: Option<String>,
    /// Explicit commit SHA to inspect; repeatable.
    #[arg(long)]
    pub(crate) sha: Vec<String>,
    #[arg(long, default_value_t = 100)]
    pub(crate) limit: usize,
    #[arg(long)]
    pub(crate) search_limit: Option<usize>,
    #[arg(long, default_value_t = 3)]
    pub(crate) commits_per_path: usize,
    #[arg(long, default_value_t = 4)]
    pub(crate) min_score: usize,
    /// Emit JSON lines.
    #[arg(long)]
    pub(crate) json: bool,
    /// Fetch runs and PR association.
    #[arg(long)]
    pub(crate) enrich: bool,
    /// Print discovery progress to stderr.
    #[arg(long)]
    pub(crate) verbose: bool,
    /// Also emit weak publish/OIDC workflow changes.
    #[arg(long)]
    pub(crate) include_weak_workflow_signals: bool,
    /// Print relevant added/removed workflow lines and archive blob metadata.
    #[arg(long)]
    pub(crate) show_evidence: bool,
    /// Explain why each finding was emitted.
    #[arg(long)]
    pub(crate) explain: bool,
    /// Delay between GitHub search seed queries; useful for broad scans.
    #[arg(long, default_value_t = 0)]
    pub(crate) seed_delay_ms: u64,
    /// Add a built-in GitHub code-search seed set.
    #[arg(long = "hunt-preset", value_enum)]
    pub(crate) hunt_presets: Vec<WorkflowPreset>,
    /// Add a built-in GitHub commit-search seed set.
    #[arg(long = "message-hunt-preset", value_enum)]
    pub(crate) message_hunt_presets: Vec<MessagePreset>,
    /// Seed candidate workflow paths from GitHub code search.
    #[arg(long = "seed-code-search")]
    pub(crate) seed_code_search: Vec<String>,
    /// Seed explicit commits from GitHub commit search.
    #[arg(long = "seed-commit-search")]
    pub(crate) seed_commit_search: Vec<String>,
    /// Seed commits touching one workflow path as OWNER/REPO:path.
    #[arg(long = "seed-path")]
    pub(crate) seed_path: Vec<String>,
}

impl GithubWorkflowHuntArgs {
    fn run(self) -> Result<i32> {
        let has_seed_source = !self.repos.is_empty()
            || !self.seed_path.is_empty()
            || !self.hunt_presets.is_empty()
            || !self.message_hunt_presets.is_empty()
            || !self.seed_code_search.is_empty()
            || !self.seed_commit_search.is_empty();
        if !has_seed_source {
            bail!("provide at least one repo, --seed-path, or seed search input");
        }
        github_workflows::run_hunt(self)
    }
}

#[derive(Args)]
pub(crate) struct GithubWorkflowScanArgs {
    /// ISO timestamp, e.g. 2026-04-22T00:00:00Z.
    #[arg(long)]
    pub(crate) since: Option<String>,
    /// ISO timestamp upper bound.
    #[arg(long)]
    pub(crate) until: Option<String>,
    /// Limit per repository or search result page.
    #[arg(long, default_value_t = 100)]
    pub(crate) limit: usize,
    /// Limit code-search hits per seed query.
    #[arg(long, default_value_t = 20)]
    pub(crate) search_limit: usize,
    /// Commits to inspect per matched workflow path.
    #[arg(long, default_value_t = 2)]
    pub(crate) commits_per_path: usize,
    /// Minimum score to emit.
    #[arg(long, default_value_t = 4)]
    pub(crate) min_score: usize,
    /// Emit JSON lines.
    #[arg(long)]
    pub(crate) json: bool,
    /// Fetch runs and PR association.
    #[arg(long)]
    pub(crate) enrich: bool,
    /// Print discovery progress to stderr.
    #[arg(long)]
    pub(crate) verbose: bool,
    /// Also emit weak publish/OIDC workflow changes.
    #[arg(long)]
    pub(crate) include_weak_workflow_signals: bool,
    /// Print relevant added/removed workflow lines and archive blob metadata.
    #[arg(long)]
    pub(crate) show_evidence: bool,
    /// Explain why each finding was emitted.
    #[arg(long)]
    pub(crate) explain: bool,
    /// Use one or more specific workflow presets instead of all workflow presets.
    #[arg(long = "hunt-preset", value_enum)]
    pub(crate) hunt_presets: Vec<WorkflowPreset>,
    /// Include commit-message search presets in addition to workflow code-search presets.
    #[arg(long)]
    pub(crate) include_message_presets: bool,
    /// Delay between GitHub search seed queries to respect code-search rate limits.
    #[arg(long, default_value_t = 7000)]
    pub(crate) seed_delay_ms: u64,
    /// Print planned seed queries and exit.
    #[arg(long)]
    pub(crate) show_queries: bool,
}

impl GithubWorkflowScanArgs {
    fn run(self) -> Result<i32> {
        let hunt_presets = if self.hunt_presets.is_empty() {
            WorkflowPreset::ALL.to_vec()
        } else {
            self.hunt_presets
        };
        let message_hunt_presets = if self.include_message_presets {
            MessagePreset::ALL.to_vec()
        } else {
            Vec::new()
        };

        if self.show_queries {
            println!("GitHub scan seed queries:");
            for preset in &hunt_presets {
                println!("  {}: {}", preset.name(), preset.description());
                for query in preset.queries() {
                    println!("    - {query}");
                }
            }
            if self.include_message_presets {
                println!("  message presets:");
                for preset in &message_hunt_presets {
                    println!("    {}: {}", preset.name(), preset.description());
                    for query in preset.queries() {
                        println!("      - {query}");
                    }
                }
            }
            return Ok(0);
        }

        github_workflows::run_hunt(GithubWorkflowHuntArgs {
            repos: Vec::new(),
            since: self.since,
            until: self.until,
            sha: Vec::new(),
            limit: self.limit,
            search_limit: Some(self.search_limit),
            commits_per_path: self.commits_per_path,
            min_score: self.min_score,
            json: self.json,
            enrich: self.enrich,
            verbose: self.verbose,
            include_weak_workflow_signals: self.include_weak_workflow_signals,
            show_evidence: self.show_evidence,
            explain: self.explain,
            seed_delay_ms: self.seed_delay_ms,
            hunt_presets,
            message_hunt_presets,
            seed_code_search: Vec::new(),
            seed_commit_search: Vec::new(),
            seed_path: Vec::new(),
        })
    }
}

#[derive(Args)]
pub(crate) struct NpmPackageInspectArgs {
    /// Tarball URL or local .tgz path to inspect; repeatable.
    #[arg(long = "tarball")]
    pub(crate) tarballs: Vec<String>,
    /// npm registry metadata JSON captured earlier; pairs with package specs for offline forensics.
    #[arg(long = "metadata-file")]
    pub(crate) metadata_files: Vec<PathBuf>,
    /// Minimum score to emit.
    #[arg(long, default_value_t = 4)]
    pub(crate) min_score: i32,
    /// Emit JSON lines.
    #[arg(long)]
    pub(crate) json: bool,
    /// Print relevant manifest and tarball evidence.
    #[arg(long)]
    pub(crate) show_evidence: bool,
    /// Explain why each finding was emitted.
    #[arg(long)]
    pub(crate) explain: bool,
    /// Directory where package metadata, tarballs, and findings are snapshotted for forensics.
    #[arg(long)]
    pub(crate) evidence_dir: Option<PathBuf>,
    /// npm package spec such as @scope/name@1.2.3. Version defaults to latest.
    pub(crate) package_specs: Vec<String>,
}

impl NpmPackageInspectArgs {
    fn run(self) -> Result<i32> {
        if self.package_specs.is_empty() && self.tarballs.is_empty() {
            bail!("provide at least one package spec or --tarball");
        }
        npm_packages::run_inspect(self)
    }
}
