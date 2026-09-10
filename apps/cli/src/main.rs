//! The `hexora` command-line interface.
//!
//! The CLI and the desktop application share one engine. There is no second scanner,
//! no second proxy and no CLI-only code path that behaves differently from the GUI —
//! a result reproduced in CI must be the same result a tester sees on their machine.
//!
//! Commands that are not implemented are not registered at all, rather than
//! registered as stubs that fail at runtime: `hexora --help` lists what genuinely
//! works today and nothing else.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hexora_storage::{migrations, Project};

mod history;
mod project;
mod proxy;
mod repeat;
mod send;

/// Hexora — the modern offensive security workbench.
#[derive(Debug, Parser)]
#[command(
    name = "hexora",
    version,
    about = "Hexora — the modern offensive security workbench",
    long_about = "Hexora is a web and API security testing platform for AUTHORIZED \
                  penetration testing and security research.\n\n\
                  Development status: M4. The intercepting proxy, HTTP/1.x engine \
                  with TLS, project management, traffic capture and the repeater \
                  all work. The scanner and fuzzer are not implemented yet."
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

    /// Send a single HTTP request and print the response.
    ///
    /// Like `curl`, except nothing you wrote is rewritten on the way out: header
    /// order, casing and duplicates are all sent exactly as given.
    Send {
        /// Absolute URL, e.g. http://example.com/path
        url: String,

        /// HTTP method.
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,

        /// Extra header, in 'Name: Value' form. Repeatable, and duplicates are kept.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request body. A Content-Length is added only if you did not frame it.
        #[arg(short = 'd', long)]
        data: Option<String>,

        /// Print Authorization, Cookie and other sensitive headers in full.
        #[arg(long)]
        show_secrets: bool,

        /// Accept any TLS certificate.
        ///
        /// Needed for staging systems with self-signed or expired certificates. The
        /// connection stays encrypted but the peer is NOT authenticated, so it offers
        /// no protection against interception. Every use is reported.
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Client certificate chain (PEM) for mTLS. Requires --client-key.
        #[arg(long, value_name = "FILE")]
        client_cert: Option<PathBuf>,

        /// Client private key (PEM) for mTLS. Requires --client-cert.
        #[arg(long, value_name = "FILE")]
        client_key: Option<PathBuf>,
    },

    /// Run the intercepting proxy.
    ///
    /// Point a browser at it, install the CA, and Hexora sees the traffic. Every
    /// exchange is printed as it happens.
    Proxy {
        /// Record every exchange into this project.
        ///
        /// Without it the proxy prints traffic and keeps nothing, which is fine for a
        /// quick look and useless for an engagement.
        #[arg(short, long, value_name = "DIR")]
        project: Option<PathBuf>,

        /// Record only in-scope traffic.
        ///
        /// Off by default: the proxy has to see a host before you can decide it is in
        /// scope, so discarding out-of-scope exchanges would make scoping impossible.
        #[arg(long, requires = "project")]
        in_scope_only: bool,

        /// Address to listen on.
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: String,

        /// Directory holding the interception CA.
        #[arg(long, value_name = "DIR")]
        ca_dir: Option<PathBuf>,

        /// Host never to decrypt. Repeatable; accepts a leading `*.` wildcard.
        ///
        /// Use this for certificate-pinned applications, and for anything that
        /// should not be decrypted at all.
        #[arg(long, value_name = "HOST")]
        exempt: Vec<String>,

        /// Decrypt only this host, tunnelling everything else untouched.
        ///
        /// The safer posture: your own browsing stays encrypted while you work.
        #[arg(long, value_name = "HOST")]
        only: Vec<String>,

        /// Do not verify upstream certificates.
        ///
        /// Needed for staging targets with self-signed certificates. Applies to the
        /// connection between Hexora and the target, not the one your browser sees.
        #[arg(short = 'k', long)]
        insecure_upstream: bool,
    },

    /// Manage the interception certificate authority.
    Ca {
        /// Directory holding the CA.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,

        /// Write the CA certificate here and print trust instructions.
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,

        /// Delete the CA. Does not untrust it — remove it from trust stores too.
        #[arg(long)]
        delete: bool,
    },

    /// Browse traffic captured into a project.
    History {
        /// Project directory.
        path: PathBuf,

        /// Maximum exchanges to list.
        #[arg(short, long, default_value_t = 50)]
        limit: u32,

        /// Continue from the cursor printed by a previous page.
        #[arg(long, value_name = "CURSOR", conflicts_with = "body")]
        after: Option<String>,

        /// Write one exchange's response body to stdout, by request id.
        #[arg(long, value_name = "ID")]
        body: Option<String>,

        /// With --body, print the body as it arrived, before content decoding.
        #[arg(long, requires = "body")]
        wire: bool,
    },

    /// Resend a request from history, optionally editing it first.
    ///
    /// The request opens in $EDITOR when --edit is given, and is sent exactly as
    /// saved: a wrong Content-Length is reported, never corrected.
    Repeat {
        /// Project directory.
        path: PathBuf,

        /// The request to resend, from `hexora history`.
        id: String,

        /// Open the request in $EDITOR before sending.
        #[arg(short, long)]
        edit: bool,

        /// Print the request that would be sent, and stop.
        #[arg(long)]
        dry_run: bool,

        /// Print the response body as well as the head.
        #[arg(long)]
        show_body: bool,

        /// Do not verify the target's TLS certificate.
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Compare this request against another instead of sending anything.
        #[arg(long, value_name = "OTHER_ID", conflicts_with_all = ["edit", "dry_run"])]
        diff: Option<String>,

        /// Show every variant derived from this request.
        #[arg(long, conflicts_with_all = ["edit", "dry_run", "diff"])]
        tree: bool,
    },

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
        Command::History {
            path,
            limit,
            after,
            body,
            wire,
        } => match body {
            Some(id) => history::body(history::BodyArgs {
                project: path,
                id,
                wire: *wire,
            }),
            None => history::list(history::HistoryArgs {
                project: path,
                limit: *limit,
                after: after.as_deref(),
                json: cli.json,
            }),
        },
        Command::Repeat {
            path,
            id,
            edit,
            dry_run,
            show_body,
            insecure,
            diff,
            tree,
        } => {
            if *tree {
                repeat::tree(repeat::TreeArgs {
                    project: path,
                    id,
                    json: cli.json,
                })
            } else if let Some(other) = diff {
                repeat::diff(repeat::DiffArgs {
                    project: path,
                    before: id,
                    after: other,
                    json: cli.json,
                })
            } else {
                repeat::run(repeat::RepeatArgs {
                    project: path,
                    id,
                    edit: *edit,
                    dry_run: *dry_run,
                    show_body: *show_body,
                    insecure: *insecure,
                    json: cli.json,
                })
            }
        }
        Command::Proxy {
            project,
            in_scope_only,
            listen,
            ca_dir,
            exempt,
            only,
            insecure_upstream,
        } => proxy::run(proxy::ProxyArgs {
            project: project.as_deref(),
            in_scope_only: *in_scope_only,
            listen,
            ca_dir: ca_dir.as_deref(),
            exempt,
            only,
            insecure_upstream: *insecure_upstream,
        }),
        Command::Ca {
            dir,
            export,
            delete,
        } => proxy::ca(proxy::CaArgs {
            dir: dir.as_deref(),
            export: export.as_deref(),
            delete: *delete,
        }),
        Command::Send {
            url,
            method,
            headers,
            data,
            show_secrets,
            insecure,
            client_cert,
            client_key,
        } => send::run(send::SendArgs {
            url,
            method,
            headers,
            body: data.as_deref(),
            json: cli.json,
            show_secrets: *show_secrets,
            insecure: *insecure,
            client_cert: client_cert.as_deref(),
            client_key: client_key.as_deref(),
        }),
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
            "milestone": "M4",
        });
        println!("{payload}");
    } else {
        println!("hexora {version}");
        println!("  project schema revision: {schema}");
        println!("  rpc contract version:    {rpc}");
        println!("  milestone:               M4 (repeater)");
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
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
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
        for absent in ["scan", "fuzz", "intruder"] {
            assert!(
                !help.contains(&format!("  {absent}")),
                "help offers a {absent} command that does not exist"
            );
        }
    }

    #[test]
    fn help_states_the_development_status() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("M4"),
            "users must not mistake this for a finished tool"
        );
    }

    #[test]
    fn opening_a_directory_that_is_not_a_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), "hello").unwrap();
        let err = open_project(dir.path()).unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }
}
