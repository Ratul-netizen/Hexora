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

mod authz;
mod findings;
mod history;
mod identifiers;
mod identity;
mod object;
mod project;
mod proxy;
mod repeat;
mod report;
mod scope;
mod send;
mod setup;

/// Hexora — the modern offensive security workbench.
#[derive(Debug, Parser)]
#[command(
    name = "hexora",
    version,
    about = "Hexora — the modern offensive security workbench",
    long_about = "Hexora is a web and API security testing platform for AUTHORIZED \
                  penetration testing and security research.\n\n\
                  Development status: M12.7. The proxy, HTTP/1.x engine \
                  with TLS, projects, traffic capture, the repeater, authorization \
                  testing with constructed attempts, findings and reports all work. The \n                  scanner and fuzzer do not."
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
    ///
    /// With no flags, prints the CA, its fingerprint and whether the platform
    /// currently trusts it.
    Ca {
        /// Directory holding the CA.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,

        /// Install the CA into this user's trust store.
        ///
        /// Asks first. This is the most consequential thing Hexora will ask you to
        /// do, and it never happens as a side effect of anything else.
        #[arg(long, conflicts_with_all = ["delete", "untrust", "status"])]
        install: bool,

        /// Remove the CA from the trust store, leaving the files in place.
        #[arg(long, conflicts_with_all = ["delete", "status"])]
        untrust: bool,

        /// Report whether this machine currently trusts the CA.
        #[arg(long, conflicts_with = "delete")]
        status: bool,

        /// Do not ask before installing. For scripts and disposable machines.
        #[arg(short = 'y', long, requires = "install")]
        yes: bool,

        /// Write the CA certificate here and print trust instructions.
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,

        /// Untrust and delete the CA.
        #[arg(long)]
        delete: bool,
    },

    /// Set up a machine for testing: a project, the CA, and trust.
    ///
    /// The first-run path. Everything it does can also be done a command at a time.
    Setup {
        /// Directory for the project to create.
        #[arg(default_value = "./engagement")]
        path: PathBuf,

        /// Directory holding the CA.
        #[arg(long, value_name = "DIR")]
        ca_dir: Option<PathBuf>,

        /// Do not ask before installing the CA.
        #[arg(short = 'y', long)]
        yes: bool,

        /// Set everything up but do not touch the trust store.
        #[arg(long, conflicts_with = "yes")]
        no_trust: bool,
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

        /// Edit and send the request as raw bytes.
        ///
        /// Structured editing serializes a message model, which means CRLF line
        /// endings and framing headers added where they were missing. Raw mode sends
        /// exactly what you typed: a bare LF stays a bare LF, a wrong Content-Length
        /// stays wrong, duplicate headers stay in the order you wrote them. A request
        /// that was captured raw comes back raw without the flag.
        #[arg(long, conflicts_with_all = ["diff", "tree"])]
        raw: bool,

        /// Compare this request against another instead of sending anything.
        #[arg(long, value_name = "OTHER_ID", conflicts_with_all = ["edit", "dry_run"])]
        diff: Option<String>,

        /// Show every variant derived from this request.
        #[arg(long, conflicts_with_all = ["edit", "dry_run", "diff"])]
        tree: bool,
    },

    /// Manage the identities a project tests as.
    #[command(subcommand)]
    Identity(IdentityCommand),

    /// Review values that might be object identifiers.
    ///
    /// Analysis reads captured traffic and offers the values that *vary* where an
    /// identifier would. It sends nothing and declares nothing: accepting a
    /// suggestion says it is an identifier, never whose it is.
    Identifiers {
        /// Project directory.
        path: PathBuf,

        /// Read the project's traffic and offer what it finds.
        #[arg(long)]
        analyze: bool,

        /// Only suggestions in this state.
        #[arg(long, value_name = "STATE")]
        status: Option<String>,

        /// Show one suggestion in full, with the reasons it was offered.
        #[arg(long, value_name = "ID")]
        show: Option<String>,

        /// Record that this value is an identifier.
        ///
        /// Says nothing about who owns it. Declaring that is `hexora object add`.
        #[arg(long, value_name = "ID", conflicts_with_all = ["show", "reject"])]
        accept: Option<String>,

        /// Record that this value is not an identifier, so it is not offered again.
        #[arg(long, value_name = "ID", conflicts_with = "show")]
        reject: Option<String>,
    },

    /// Declare which identifiers are objects, and who owns them.
    ///
    /// Data entry, not a test: declaring sends nothing. It is what lets
    /// `hexora authz --construct` build the request nobody captured — one identity
    /// asking for another's object.
    #[command(subcommand)]
    Object(ObjectCommand),

    /// Show and change what this engagement is authorized to touch.
    ///
    /// Scope is not cosmetic: automated components refuse to send traffic to hosts
    /// nobody has declared here.
    #[command(subcommand)]
    Scope(ScopeCommand),

    /// Replay a captured request as several identities and compare what came back.
    ///
    /// The highest-value manual work in most engagements: does the application
    /// actually check who is asking, or only that somebody is?
    Authz {
        /// Project directory.
        path: PathBuf,

        /// The request to replay, from `hexora history`.
        id: String,

        /// The identity the captured request belongs to, by label or id.
        #[arg(long, value_name = "IDENTITY")]
        as_identity: String,

        /// Replay as this identity. Repeatable. Defaults to every other identity.
        #[arg(long = "identity", value_name = "IDENTITY")]
        identities: Vec<String>,

        /// Do not add an unauthenticated control request.
        ///
        /// The control is what separates "User B can read User A's data" from "that
        /// URL is public". Leaving it out makes every other row weaker.
        #[arg(long)]
        no_anonymous: bool,

        /// Replay each violation a second time before reporting it.
        ///
        /// Reproduction is the difference between a Tentative finding and a
        /// Confirmed one.
        #[arg(long)]
        verify: bool,

        /// Replay a request whose method may change data on the target.
        #[arg(short = 'y', long)]
        yes: bool,

        /// Do not verify the target's TLS certificate.
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Report the findings without writing them into the project.
        ///
        /// The default is to write them: a conclusion that lives only in a terminal
        /// cannot be cited, and the traffic behind it is already saved.
        #[arg(long)]
        no_save: bool,

        /// Also build cross-identity requests from the objects declared in the
        /// project.
        ///
        /// A replay asks "can this identity reach this URL?". Substituting an
        /// identifier somebody else owns asks "can it reach *their* object?", which
        /// is the question a captured request usually cannot answer. Declare who owns
        /// what with `hexora object add` first.
        #[arg(long)]
        construct: bool,

        /// The most constructed requests one run may send.
        #[arg(long, value_name = "N", default_value_t = 12, requires = "construct")]
        max_attempts: usize,
    },

    /// Read and triage the findings recorded in a project.
    ///
    /// Ordered worst first, and within a severity the established ones before the
    /// leads — the order they get worked through, not the order they were found.
    Findings {
        /// Project directory.
        path: PathBuf,

        /// Show one finding in full, evidence included.
        #[arg(long, value_name = "ID")]
        show: Option<String>,

        /// Set a finding's triage state. Use with --status.
        #[arg(long, value_name = "ID", conflicts_with = "show")]
        triage: Option<String>,

        /// With --triage, the state to set. Otherwise, only show this state.
        #[arg(long, value_name = "STATE")]
        status: Option<String>,

        /// Only findings at or above this severity.
        #[arg(long, value_name = "LEVEL", conflicts_with_all = ["show", "triage"])]
        severity: Option<String>,

        /// Hide anything still only a lead, leaving what can be reported.
        #[arg(long, conflicts_with_all = ["show", "triage"])]
        actionable: bool,

        /// Maximum findings to list.
        #[arg(short, long, default_value_t = 50)]
        limit: u32,

        /// Continue from the cursor printed by a previous page.
        #[arg(long, value_name = "CURSOR")]
        after: Option<String>,
    },

    /// Turn a project's findings into a document somebody can be handed.
    ///
    /// A render, not a run: it sends no traffic and changes nothing. Every claim
    /// carries the exact exchange behind it, credentials redacted, and unverified
    /// leads are kept in their own section rather than dressed up as findings.
    Report {
        /// Project directory.
        path: PathBuf,

        /// Output format: markdown, html or json.
        #[arg(short, long, value_name = "FORMAT")]
        format: Option<String>,

        /// Write the report here instead of to stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Document title. Defaults to the project name.
        #[arg(long, value_name = "TITLE")]
        title: Option<String>,

        /// Omit findings below this severity.
        #[arg(long, value_name = "LEVEL")]
        severity: Option<String>,

        /// Leave the unverified leads out, keeping only established issues.
        ///
        /// They are still counted, under "what this report leaves out": a document
        /// that silently dropped them would hide the size of the unfinished work.
        #[arg(long)]
        actionable: bool,

        /// Include real credentials in the quoted traffic.
        ///
        /// The resulting file is a secret, not a deliverable. Only use it for a
        /// report that stays on your own machine.
        #[arg(long)]
        show_secrets: bool,

        /// How much of each body to quote, in bytes.
        #[arg(long, value_name = "BYTES", default_value_t = 2048)]
        excerpt_bytes: usize,
    },

    /// Print version and build information.
    Version,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Add an identity.
    ///
    /// The credential is read from an environment variable or a file, never from an
    /// argument: `ps` and shell history would both capture it.
    Add {
        /// Project directory.
        path: PathBuf,

        /// Display name, e.g. "User B".
        label: String,

        /// How much authority this identity is expected to have.
        #[arg(long, default_value = "user")]
        privilege: String,

        /// Credential kind: bearer, cookie, basic, none, or a header name.
        #[arg(long, default_value = "bearer")]
        kind: String,

        /// Environment variable holding the credential.
        #[arg(long, value_name = "VAR", conflicts_with = "from_file")]
        from_env: Option<String>,

        /// File holding the credential.
        #[arg(long, value_name = "FILE")]
        from_file: Option<PathBuf>,

        /// An object identifier known to belong to this identity. Repeatable.
        ///
        /// This is what turns a similarity score into evidence: an id declared here,
        /// found in somebody else's response, is a disclosure rather than a guess.
        #[arg(long, value_name = "ID")]
        owns: Vec<String>,

        /// Extra header to send for this identity, in 'Name: Value' form.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
    },
    /// List the identities in a project. Never prints credentials.
    List {
        /// Project directory.
        path: PathBuf,
    },
    /// Remove an identity by label or id.
    Remove {
        /// Project directory.
        path: PathBuf,
        /// Label or id.
        who: String,
    },
}

#[derive(Debug, Subcommand)]
enum ObjectCommand {
    /// Declare an object identifier and who owns it.
    Add {
        /// Project directory.
        path: PathBuf,

        /// The identifier, exactly as it appears in a request.
        value: String,

        /// The identity that owns it, by label or id.
        #[arg(long, value_name = "IDENTITY")]
        owner: String,

        /// What kind of object it is, e.g. `invoice`.
        #[arg(long, default_value = "object")]
        name: String,

        /// A captured request the value appears in.
        ///
        /// Given one, Hexora finds the value and records where it actually sat, so
        /// nobody has to count path segments. Without one the declaration records the
        /// value alone, and a run substitutes it wherever the sender's own object is.
        #[arg(long, value_name = "ID")]
        in_request: Option<String>,
    },
    /// List the objects declared in a project.
    List {
        /// Project directory.
        path: PathBuf,
    },
    /// Remove a declaration by id.
    Remove {
        /// Project directory.
        path: PathBuf,
        /// The declaration's id.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ScopeCommand {
    /// Print the project's scope.
    List {
        /// Project directory.
        path: PathBuf,
    },
    /// Declare a host as authorized.
    Add {
        /// Project directory.
        path: PathBuf,
        /// Hostname, or a `*.example.com` wildcard.
        host: String,
        /// Limit the rule to paths starting with this prefix.
        #[arg(long, value_name = "PREFIX")]
        path_prefix: Option<String>,
        /// Add to the exclusion list instead. Exclusions win over inclusions.
        #[arg(long)]
        exclude: bool,
    },
    /// Remove every rule for a host.
    Remove {
        /// Project directory.
        path: PathBuf,
        /// Hostname.
        host: String,
    },
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
        Command::Identity(IdentityCommand::Add {
            path,
            label,
            privilege,
            kind,
            from_env,
            from_file,
            owns,
            headers,
        }) => identity::add(identity::AddArgs {
            project: path,
            label,
            privilege,
            kind,
            from_env: from_env.as_deref(),
            from_file: from_file.as_deref(),
            owns,
            headers,
            json: cli.json,
        }),
        Command::Identity(IdentityCommand::List { path }) => identity::list(path, cli.json),
        Command::Identity(IdentityCommand::Remove { path, who }) => {
            identity::remove(path, who, cli.json)
        }
        Command::Identifiers {
            path,
            analyze,
            status,
            show,
            accept,
            reject,
        } => match (show, accept, reject) {
            (Some(id), _, _) => identifiers::show(path, id, cli.json),
            (_, Some(id), _) => identifiers::decide(
                path,
                id,
                hexora_types::candidate::CandidateStatus::Accepted,
                cli.json,
            ),
            (_, _, Some(id)) => identifiers::decide(
                path,
                id,
                hexora_types::candidate::CandidateStatus::Rejected,
                cli.json,
            ),
            (None, None, None) => identifiers::list(identifiers::ListArgs {
                project: path,
                status: status.as_deref(),
                analyze: *analyze,
                json: cli.json,
            }),
        },
        Command::Object(ObjectCommand::Add {
            path,
            value,
            owner,
            name,
            in_request,
        }) => object::add(object::AddArgs {
            project: path,
            value,
            owner,
            name,
            in_request: in_request.as_deref(),
            json: cli.json,
        }),
        Command::Object(ObjectCommand::List { path }) => object::list(path, cli.json),
        Command::Object(ObjectCommand::Remove { path, id }) => object::remove(path, id, cli.json),
        Command::Scope(ScopeCommand::List { path }) => scope::list(path, cli.json),
        Command::Scope(ScopeCommand::Add {
            path,
            host,
            path_prefix,
            exclude,
        }) => scope::add(path, host, path_prefix.as_deref(), *exclude, cli.json),
        Command::Scope(ScopeCommand::Remove { path, host }) => scope::remove(path, host, cli.json),
        Command::Authz {
            path,
            id,
            as_identity,
            identities,
            no_anonymous,
            verify,
            yes,
            insecure,
            no_save,
            construct,
            max_attempts,
        } => authz::run(authz::AuthzArgs {
            project: path,
            id,
            owner: as_identity,
            identities,
            no_anonymous: *no_anonymous,
            verify: *verify,
            yes: *yes,
            insecure: *insecure,
            no_save: *no_save,
            construct: *construct,
            max_attempts: *max_attempts,
            json: cli.json,
        }),
        Command::Findings {
            path,
            show,
            triage,
            status,
            severity,
            actionable,
            limit,
            after,
        } => match (show, triage) {
            (Some(id), _) => findings::show(path, id, cli.json),
            (_, Some(id)) => {
                let status = status.as_deref().ok_or_else(|| {
                    hexora_types::HexoraError::invalid_input(
                        "--status",
                        "--triage needs the state to set, e.g. --status false-positive",
                    )
                })?;
                findings::triage(path, id, status, cli.json)
            }
            (None, None) => findings::list(findings::ListArgs {
                project: path,
                severity: severity.as_deref(),
                status: status.as_deref(),
                actionable: *actionable,
                limit: *limit,
                after: after.as_deref(),
                json: cli.json,
            }),
        },
        Command::Report {
            path,
            format,
            output,
            title,
            severity,
            actionable,
            show_secrets,
            excerpt_bytes,
        } => report::run(report::ReportArgs {
            project: path,
            format: format.as_deref(),
            output: output.as_deref(),
            title: title.as_deref(),
            severity: severity.as_deref(),
            actionable: *actionable,
            show_secrets: *show_secrets,
            excerpt_bytes: *excerpt_bytes,
            json: cli.json,
        }),
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
            raw,
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
                    raw: *raw,
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
            install,
            untrust,
            status,
            yes,
            export,
            delete,
        } => proxy::ca(proxy::CaArgs {
            dir: dir.as_deref(),
            export: export.as_deref(),
            delete: *delete,
            install: *install,
            untrust: *untrust,
            status: *status,
            yes: *yes,
            json: cli.json,
        }),
        Command::Setup {
            path,
            ca_dir,
            yes,
            no_trust,
        } => setup::run(setup::SetupArgs {
            project: path,
            ca_dir: ca_dir.as_deref(),
            yes: *yes,
            trust: !*no_trust,
            json: cli.json,
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
            "milestone": "M12.7",
        });
        println!("{payload}");
    } else {
        println!("hexora {version}");
        println!("  project schema revision: {schema}");
        println!("  rpc contract version:    {rpc}");
        println!("  milestone:               M12.7 (identifier suggestions)");
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
        // The command list, not the prose. Grepping the rendered help for "  scan"
        // also matched the development-status paragraph the moment a line wrapped
        // before the word "scanner" — a guard that fails on its own description is
        // one somebody eventually deletes.
        let commands: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_lowercase())
            .collect();

        for absent in ["scan", "fuzz", "intruder"] {
            assert!(
                !commands.iter().any(|name| name.starts_with(absent)),
                "help offers a {absent} command that does not exist: {commands:?}"
            );
        }
        assert!(
            commands.iter().any(|name| name == "authz"),
            "and it must still list the ones that do: {commands:?}"
        );
    }

    #[test]
    fn help_states_the_development_status() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("M12.7"),
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
