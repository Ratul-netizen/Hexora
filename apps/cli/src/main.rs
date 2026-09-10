//! The `hexora` command-line interface.
//!
//! The CLI and the desktop application share one engine. There is no second scanner,
//! no second proxy and no CLI-only code path that behaves differently from the GUI —
//! a result reproduced in CI must be the same result a tester sees on their machine.
//!
//! At M0 the CLI can create and inspect projects. Commands for the proxy, scanner and
//! fuzzer are not registered at all, rather than registered as stubs that fail at
//! runtime: `hexora --help` lists what genuinely works today.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hexora_storage::{migrations, Project};

mod project;

/// Hexora — the modern offensive security workbench.
#[derive(Debug, Parser)]
#[command(
    name = "hexora",
    version,
    about = "Hexora — the modern offensive security workbench",
    long_about = "Hexora is a web and API security testing platform for AUTHORIZED \
                  penetration testing and security research.\n\n\
                  Development status: M0 (architecture foundation). Project creation \
                  and inspection work. The proxy, scanner and fuzzer are not \
                  implemented yet and are therefore not offered as commands."
)]
struct Cli {
    /// Increase log verbosity. Repeat for more detail.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create, inspect and manage projects.
    #[command(subcommand)]
    Project(ProjectCommand),

    /// Print version and build information.
    Version,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create a new project.
    Init {
        /// Directory for the new project.
        path: PathBuf,
        /// Project name. Defaults to the directory name.
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Show information about an existing project.
    Info {
        /// Project directory.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if cli.json {
                let payload = serde_json::json!({ "error": e.to_string(), "code": e.code() });
                println!("{payload}");
            } else {
                eprintln!("error: {e}");
                let mut source = std::error::Error::source(&e);
                while let Some(cause) = source {
                    eprintln!("  caused by: {cause}");
                    source = cause.source();
                }
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> hexora_types::Result<()> {
    match &cli.command {
        Command::Version => {
            print_version(cli.json);
            Ok(())
        }
        Command::Project(ProjectCommand::Init { path, name }) => {
            project::init(path, name.as_deref(), cli.json)
        }
        Command::Project(ProjectCommand::Info { path }) => project::info(path, cli.json),
    }
}

fn print_version(json: bool) {
    let version = env!("CARGO_PKG_VERSION");
    let schema = migrations::target_version();
    let rpc = hexora_types::RPC_CONTRACT_VERSION;
    if json {
        let payload = serde_json::json!({
            "version": version,
            "schema_version": schema,
            "rpc_contract_version": rpc,
            "milestone": "M0",
        });
        println!("{payload}");
    } else {
        println!("hexora {version}");
        println!("  project schema revision: {schema}");
        println!("  rpc contract version:    {rpc}");
        println!("  milestone:               M0 (architecture foundation)");
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("hexora={level}")));
    // Secrets never reach a log because credentials are wrapped in
    // `hexora_types::redact::Secret`, whose Debug output is a placeholder. See
    // docs/security-invariants.md, invariant 2.
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

/// Confirms that a project directory really is one before acting on it.
fn open_project(path: &std::path::Path) -> hexora_types::Result<Project> {
    if path.exists() && !path.join("project.db").exists() {
        return Err(hexora_types::HexoraError::invalid_input(
            "path",
            format!("{} exists but is not a Hexora project", path.display()),
        ));
    }
    Ok(Project::open(path)?)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_cli_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_does_not_advertise_unimplemented_features() {
        let help = Cli::command().render_long_help().to_string().to_lowercase();
        for absent in ["proxy", "scan", "fuzz", "intruder", "repeater"] {
            assert!(
                !help.contains(&format!("  {absent}")),
                "help offers a {absent} command that does not exist"
            );
        }
    }

    #[test]
    fn help_states_the_development_status() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("M0"), "users must not mistake this for a finished tool");
    }

    #[test]
    fn opening_a_directory_that_is_not_a_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), "hello").unwrap();
        let err = open_project(dir.path()).unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }
}
