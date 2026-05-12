mod cli;
mod detection_model;
mod github_actions;
mod github_workflows;
mod npm_packages;
mod presets;

use anyhow::Result;
use clap::Parser;

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ERROR: {error:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let cli = cli::Cli::parse();
    cli.run()
}
