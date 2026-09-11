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

mod active;
mod authz;
mod detectors;
mod findings;
mod fuzz;
mod header;
mod history;
mod identifiers;
mod identity;
mod object;
mod poc;
mod programme;
mod project;
mod proxy;
mod repeat;
mod report;
mod scan;
mod scope;
mod send;
mod setup;
mod snapshot;

/// Hexora — the modern offensive security workbench.
#[derive(Debug, Parser)]
#[command(
    name = "hexora",
    version,
    about = "Hexora — the modern offensive security workbench",
    long_about = "Hexora is a web and API security testing platform for AUTHORIZED \
                  penetration testing and security research.\n\n\
                  Development status: M15.1. The proxy, HTTP/1.x engine with TLS, \
                  projects, traffic capture, the repeater, authorization testing, the \
                  passive scanner, the active scheduler, the intruder, findings and \
                  reports all work. There is no crawler: Hexora tests the traffic it \
                  was shown, so what it was never shown it never tested."
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

        /// Put this project's attached headers on in-scope requests your browser makes.
        ///
        /// A bug bounty programme that requires `X-HackerOne-Research` requires it on
        /// your traffic, not only on your scanner's — and while hunting, your browser
        /// is most of your traffic.
        ///
        /// Applies to declared hosts only. Everything else you browse is untouched,
        /// because broadcasting your researcher identity to your own mail provider is
        /// not what you turned this on for. Needs --project, a header, and a scope.
        #[arg(long, requires = "project")]
        attach_headers: bool,
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

    /// Run checks over traffic this project has already captured.
    ///
    /// The passive pass sends nothing: it reads stored exchanges and says what it
    /// sees. Every result it produces is a lead — it says what was observed, not
    /// that the application is exploitable.
    #[command(subcommand)]
    Scan(ScanCommand),

    /// List the checks this build has, and which of them send traffic.
    ///
    /// A scanner that will not say what it looks for is one whose silence means
    /// nothing. Every check raises a hypothesis; only a verification turns one into a
    /// finding.
    Detectors,

    /// Record what the engagement looks like now, and compare two moments.
    ///
    /// A consultant tests, the client fixes, the consultant comes back — and the only
    /// question on the second visit is what changed. Every other store in a project is
    /// live, so without a snapshot there is nothing to compare against.
    #[command(subcommand)]
    Snapshot(SnapshotCommand),

    /// Headers put on every request, for a programme that requires identification.
    #[command(subcommand)]
    Header(HeaderCommand),

    /// The terms this engagement is conducted under, and what they will not accept.
    #[command(subcommand)]
    Programme(ProgrammeCommand),

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

    /// Send one request many times, once per payload, and compare what came back.
    ///
    /// The tool between the repeater and the scanner: take a request that already
    /// works, vary one thing in it, and read the row that does not match the others.
    ///
    /// It concludes nothing. A response that differs is a response that differs, and
    /// what that means is a judgement about the application — so nothing is written
    /// into the findings store.
    ///
    /// Unlike `scan active`, this will replay a POST if you ask it to: a queue
    /// deciding that on its own is not a test anybody consented to, and a person
    /// typing the command has decided. It says what it is about to do first.
    Fuzz {
        /// Project directory.
        path: PathBuf,

        /// The request to vary, from `hexora history`.
        id: String,

        /// Where the payload goes: a query parameter or header name.
        #[arg(long, value_name = "NAME")]
        at: Option<String>,

        /// Or: the value in the request to replace, wherever it appears.
        #[arg(long, value_name = "VALUE", conflicts_with = "at")]
        replacing: Option<String>,

        /// A file of payloads, one per line.
        #[arg(long, value_name = "FILE")]
        payloads: Option<PathBuf>,

        /// Milliseconds to wait between requests.
        #[arg(long, value_name = "MS")]
        delay: Option<u64>,

        /// The most requests this run may send. Defaults to the whole list.
        #[arg(long, value_name = "N")]
        max_requests: Option<usize>,

        /// Work out what would be sent, print it, and send nothing.
        #[arg(long)]
        dry_run: bool,

        /// Send without asking first.
        #[arg(long)]
        yes: bool,

        /// Do not verify the target's TLS certificate.
        #[arg(long)]
        insecure: bool,
    },

    /// Compile a finding into steps somebody can run.
    ///
    /// Built from the exchanges the finding already cites, with every credential
    /// replaced by a named placeholder — a proof of concept is the most-forwarded
    /// thing an engagement produces.
    Poc {
        /// Project directory.
        path: PathBuf,

        /// The finding, from `hexora findings`.
        id: String,

        /// raw, curl, or markdown.
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Write it to this file instead of printing it.
        #[arg(long, value_name = "FILE")]
        save: Option<PathBuf>,
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

        /// Leave out the runnable reproduction blocks.
        ///
        /// They are included for established findings only, never for leads: a
        /// runnable block attached to an unverified claim is the thing most likely
        /// to be forwarded without the sentence that qualified it.
        #[arg(long)]
        no_poc: bool,
    },

    /// Print version and build information.
    Version,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Adopt a newer session for an identity, from traffic you generated.
    ///
    /// A captured credential decays. Once it does, every authorization result reads
    /// "the credential may no longer be valid" and establishes nothing — which is most
    /// of what this tool is for.
    ///
    /// The fix is not to record your login and replay it: that means storing a
    /// password, and it fails against captcha, MFA and SSO, which is most real targets.
    /// Log in the way you already do, through the proxy, and run this.
    ///
    /// Only **proxy** traffic is eligible — your browser. Never the repeater, whose
    /// requests you may have edited, and never the scanner or the authorization engine,
    /// which send credentials they broke deliberately.
    Refresh {
        /// Project directory.
        path: PathBuf,

        /// The identity, by label or id.
        who: String,

        /// Show what would be adopted without storing it.
        #[arg(long)]
        dry_run: bool,

        /// How many recent exchanges to look through.
        #[arg(long, default_value_t = 500)]
        limit: usize,

        /// Only adopt a session seen on this host.
        ///
        /// Cookies are per host and an engagement's scope covers many: against a real
        /// target the newest in-scope cookie came from the image CDN, which is not the
        /// session the API accepts. Without this, the host it came from is printed so
        /// you can judge.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,
    },

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
enum ScanCommand {
    /// Read captured traffic and report what the checks saw.
    ///
    /// Makes no network requests at all, which is why it is safe on any engagement
    /// at any time — including one whose client has gone home.
    Passive {
        /// Project directory.
        path: PathBuf,

        /// Run only this check, by id. `hexora detectors` lists them.
        #[arg(long, value_name = "ID")]
        detector: Option<String>,

        /// Only traffic to this host.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,

        /// Only traffic captured at or after this RFC 3339 instant.
        #[arg(long, value_name = "TIME")]
        since: Option<String>,

        /// Stop after this many exchanges.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,

        /// Read out-of-scope traffic too.
        ///
        /// Off by default. A project holds whatever the proxy saw, including your own
        /// browsing, and producing observations about systems nobody declared in
        /// scope is not a service to anybody.
        #[arg(long)]
        everything: bool,

        /// Print the results without writing them into the project.
        #[arg(long)]
        no_save: bool,
    },

    /// Settle the suspicions a passive pass could not, by running experiments.
    ///
    /// This sends requests. It is the only `scan` pass that does, which is why it is
    /// spelled out rather than a flag: a pass that reads a project and a pass that
    /// puts traffic on somebody's system are different acts and should not be one
    /// typo apart.
    ///
    /// Nothing is invented. An active run only tests hypotheses a passive pass
    /// raised, so `hexora scan passive` comes first. Use --dry-run to see exactly
    /// what would be sent, to which hosts, and how much.
    Active {
        /// Project directory.
        path: PathBuf,

        /// Only hypotheses about this host.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,

        /// Only hypotheses raised by this check, by id.
        #[arg(long, value_name = "ID")]
        detector: Option<String>,

        /// Work out what would be sent, print it, and send nothing.
        #[arg(long)]
        dry_run: bool,

        /// How many hosts to work at once. One host is never sent two requests at
        /// once whatever this is set to.
        #[arg(long, value_name = "N")]
        hosts_at_once: Option<usize>,

        /// Milliseconds to wait between requests to one host.
        #[arg(long, value_name = "MS")]
        delay: Option<u64>,

        /// The most requests this run may send in total.
        #[arg(long, value_name = "N")]
        max_requests: Option<usize>,

        /// Send without asking first.
        #[arg(long)]
        yes: bool,

        /// Do not verify the target's TLS certificate.
        #[arg(long)]
        insecure: bool,

        /// Print the results without writing them into the project.
        #[arg(long)]
        no_save: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Record the project as it stands.
    ///
    /// Reads the project and writes one row: scope, identities, declared objects and
    /// every claim as it stands. The traffic itself is not copied — a snapshot is a
    /// record to compare against, not a backup.
    Take {
        /// Project directory.
        path: PathBuf,

        /// What to call it, e.g. "before the fix".
        #[arg(long, value_name = "NAME")]
        label: Option<String>,

        /// Anything worth saying that the label could not hold.
        #[arg(long, value_name = "TEXT")]
        note: Option<String>,
    },
    /// List the snapshots a project holds, newest first.
    List {
        /// Project directory.
        path: PathBuf,
    },
    /// Print one snapshot in full.
    Show {
        /// Project directory.
        path: PathBuf,
        /// The snapshot's id.
        id: String,
    },
    /// Say what changed between two moments.
    ///
    /// With one id, compares that snapshot with the project as it stands, which is
    /// what a retest actually asks. A claim missing from the later side is reported
    /// with the reason it is missing, and only one of those reasons is about the
    /// application at all.
    Diff {
        /// Project directory.
        path: PathBuf,
        /// The earlier snapshot.
        from: String,
        /// The later snapshot. Defaults to the project as it stands.
        #[arg(long, value_name = "ID")]
        against: Option<String>,
    },
    /// Delete a snapshot, for one that was mislabelled.
    Remove {
        /// Project directory.
        path: PathBuf,
        /// The snapshot's id.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProgrammeCommand {
    /// Show the terms this engagement is conducted under.
    Show {
        /// Project directory.
        path: PathBuf,
    },
    /// Record what the programme is called and where its terms are published.
    Set {
        /// Project directory.
        path: PathBuf,
        /// What it is called, for the report header.
        #[arg(long)]
        name: Option<String>,
        /// Where the terms are published.
        #[arg(long)]
        policy_url: Option<String>,
    },
    /// Stop reporting a finding class this programme will not accept.
    ///
    /// The check still runs and its observations are still listed — a passive pass
    /// costs the target nothing, and the run record and the report both say what was
    /// excluded and why. What it no longer does is file a finding. An excluded *active*
    /// check is not run at all: sending somebody traffic to produce a finding they have
    /// said they will not take is a cost with no possible return.
    ///
    /// Excluding a lead does not exclude the experiment that would prove it. "CORS
    /// misconfiguration without proven impact" excludes `cors.configuration` and keeps
    /// `cors.reflection`, which is the check that proves impact.
    Exclude {
        /// Project directory.
        path: PathBuf,
        /// The detector id, as `hexora detectors` lists it.
        detector: String,
        /// Why, in the programme's own words where possible.
        #[arg(long)]
        reason: String,
    },
    /// Report a finding class again.
    Allow {
        /// Project directory.
        path: PathBuf,
        /// The detector id.
        detector: String,
    },
}

#[derive(Debug, Subcommand)]
enum HeaderCommand {
    /// Show the headers put on every request.
    List {
        /// Project directory.
        path: PathBuf,
    },
    /// Put a header on every request Hexora sends.
    ///
    /// For a programme that requires researchers to identify their traffic — the usual
    /// shape is `X-HackerOne-Research: <username>`, and a programme that cannot tell a
    /// researcher's requests from an attacker's is entitled to treat them the same way.
    ///
    /// Applies to everything structured: the repeater, the scanner's probes, the
    /// intruder's payloads, every authorization replay and every anonymous control. It
    /// does **not** apply to a raw send, which is byte-exact by definition — put it in
    /// the bytes there.
    Add {
        /// Project directory.
        path: PathBuf,
        /// The header, as `Name: value`.
        header: String,
    },
    /// Stop sending a header.
    Remove {
        /// Project directory.
        path: PathBuf,
        /// The header name.
        name: String,
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
        Command::Identity(IdentityCommand::Refresh {
            path,
            who,
            dry_run,
            limit,
            host,
        }) => identity::refresh(identity::RefreshArgs {
            project: path,
            who,
            dry_run: *dry_run,
            limit: *limit,
            host: host.as_deref(),
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
        Command::Programme(ProgrammeCommand::Show { path }) => programme::show(path, cli.json),
        Command::Programme(ProgrammeCommand::Set {
            path,
            name,
            policy_url,
        }) => programme::set(path, name.as_deref(), policy_url.as_deref(), cli.json),
        Command::Programme(ProgrammeCommand::Exclude {
            path,
            detector,
            reason,
        }) => programme::exclude(path, detector, reason, cli.json),
        Command::Programme(ProgrammeCommand::Allow { path, detector }) => {
            programme::allow(path, detector, cli.json)
        }
        Command::Header(HeaderCommand::List { path }) => header::list(path, cli.json),
        Command::Header(HeaderCommand::Add { path, header }) => header::add(path, header, cli.json),
        Command::Header(HeaderCommand::Remove { path, name }) => {
            header::remove(path, name, cli.json)
        }
        Command::Object(ObjectCommand::List { path }) => object::list(path, cli.json),
        Command::Object(ObjectCommand::Remove { path, id }) => object::remove(path, id, cli.json),
        Command::Scan(ScanCommand::Passive {
            path,
            detector,
            host,
            since,
            limit,
            everything,
            no_save,
        }) => scan::passive(scan::Args {
            project: path,
            detector: detector.as_deref(),
            host: host.as_deref(),
            since: since.as_deref(),
            limit: *limit,
            everything: *everything,
            no_save: *no_save,
            json: cli.json,
        }),
        Command::Scan(ScanCommand::Active {
            path,
            host,
            detector,
            dry_run,
            hosts_at_once,
            delay,
            max_requests,
            yes,
            insecure,
            no_save,
        }) => active::active(active::Args {
            project: path,
            host: host.as_deref(),
            detector: detector.as_deref(),
            hosts_at_once: *hosts_at_once,
            delay_ms: *delay,
            max_requests: *max_requests,
            dry_run: *dry_run,
            yes: *yes,
            insecure: *insecure,
            no_save: *no_save,
            json: cli.json,
        }),
        Command::Fuzz {
            path,
            id,
            at,
            replacing,
            payloads,
            delay,
            max_requests,
            dry_run,
            yes,
            insecure,
        } => fuzz::fuzz(fuzz::Args {
            project: path,
            id,
            at: at.as_deref(),
            replacing: replacing.as_deref(),
            payloads: payloads.as_deref(),
            delay_ms: *delay,
            max_requests: *max_requests,
            dry_run: *dry_run,
            yes: *yes,
            insecure: *insecure,
            json: cli.json,
        }),
        Command::Poc {
            path,
            id,
            format,
            save,
        } => poc::run(poc::Args {
            project: path,
            id,
            format,
            save_to: save.as_deref(),
            json: cli.json,
        }),
        Command::Detectors => detectors::list(cli.json),
        Command::Snapshot(SnapshotCommand::Take { path, label, note }) => {
            snapshot::take(path, label.as_deref(), note.as_deref(), cli.json)
        }
        Command::Snapshot(SnapshotCommand::List { path }) => snapshot::list(path, cli.json),
        Command::Snapshot(SnapshotCommand::Show { path, id }) => snapshot::show(path, id, cli.json),
        Command::Snapshot(SnapshotCommand::Diff {
            path,
            from,
            against,
        }) => snapshot::diff(path, from, against.as_deref(), cli.json),
        Command::Snapshot(SnapshotCommand::Remove { path, id }) => {
            snapshot::remove(path, id, cli.json)
        }
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
            no_poc,
        } => report::run(report::ReportArgs {
            project: path,
            format: format.as_deref(),
            output: output.as_deref(),
            title: title.as_deref(),
            severity: severity.as_deref(),
            actionable: *actionable,
            show_secrets: *show_secrets,
            excerpt_bytes: *excerpt_bytes,
            no_poc: *no_poc,
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
            attach_headers,
        } => proxy::run(proxy::ProxyArgs {
            project: project.as_deref(),
            in_scope_only: *in_scope_only,
            listen,
            ca_dir: ca_dir.as_deref(),
            exempt,
            only,
            insecure_upstream: *insecure_upstream,
            attach_headers: *attach_headers,
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
            "milestone": "M15.1",
        });
        println!("{payload}");
    } else {
        println!("hexora {version}");
        println!("  project schema revision: {schema}");
        println!("  rpc contract version:    {rpc}");
        println!("  milestone:               M15.1 (keeping a session alive)");
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

/// Refuses a project that was never created, before a setting is written into it.
///
/// `open_project` opens or creates the database; the `project` row is written by
/// `hexora project init`. A setting is stored on that row, so writing one into a
/// directory nobody initialised used to succeed and store nothing — `hexora header add`
/// printed "Attached" over a header that would never be sent. Storage refuses that now,
/// and this turns the refusal into an instruction.
fn require_initialised(project: &Project, path: &std::path::Path) -> hexora_types::Result<()> {
    let exists: bool = project
        .metadata()
        .connection()
        .map_err(hexora_types::HexoraError::from)?
        .query_row("SELECT count(*) FROM project", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|count| count > 0)
        .unwrap_or(false);

    if exists {
        return Ok(());
    }
    Err(hexora_types::HexoraError::invalid_input(
        "path",
        format!(
            "{} is not a Hexora project yet, so there is nowhere to keep this. \
             Create it with `hexora project init {}`",
            path.display(),
            path.display()
        ),
    ))
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

        for absent in ["intruder", "workflow", "collaborate"] {
            assert!(
                !commands.iter().any(|name| name.starts_with(absent)),
                "help offers a {absent} command that does not exist: {commands:?}"
            );
        }
        for present in ["authz", "scan", "detectors", "fuzz", "header", "programme"] {
            assert!(
                commands.iter().any(|name| name == present),
                "and it must still list the ones that do: {commands:?}"
            );
        }
    }

    #[test]
    fn the_scan_command_names_each_pass_rather_than_hiding_one_behind_a_flag() {
        // `scan` is a subcommand rather than a flag precisely so that the pass which
        // sends traffic is a word somebody had to type. A `--active` flag one
        // character away from a safe default is how a tool ends up scanning a
        // production system by accident.
        let scan = Cli::command()
            .get_subcommands()
            .find(|command| command.get_name() == "scan")
            .expect("the scan command")
            .clone();
        let passes: Vec<String> = scan
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect();

        assert_eq!(
            passes,
            vec!["passive".to_string(), "active".to_string()],
            "{passes:?}"
        );

        let active = scan
            .get_subcommands()
            .find(|command| command.get_name() == "active")
            .expect("the active pass");
        let flags: Vec<String> = active
            .get_arguments()
            .map(|arg| arg.get_id().to_string())
            .collect();
        for required in ["dry_run", "yes", "max_requests"] {
            assert!(
                flags.iter().any(|flag| flag == required),
                "an active pass must offer --{required}: {flags:?}"
            );
        }
    }

    #[test]
    fn help_states_the_development_status() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("M15.1"),
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
