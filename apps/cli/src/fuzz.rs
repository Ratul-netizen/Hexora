//! `nullhawk fuzz` — one request, many values, and what came back.
//!
//! The tool a tester reaches for between the repeater and the scanner: take a request
//! that already works, vary one thing in it, and read the column that does not match.
//!
//! ```text
//! STATUS   BYTES  COUNT  PAYLOADS
//! 401        312    199  user0, user1, user2, user3, user4  ← baseline behaved this way
//! 401        489      1  operator
//! ```
//!
//! # It concludes nothing
//!
//! There are no findings here and nothing is written into the project's findings store.
//! A response that differs is a response that differs; whether `operator` being a valid
//! username matters is a judgement about the application, and the person who chose the
//! payload list is the one making it.
//!
//! # It will replay a POST, and it will tell you first
//!
//! The scheduler refuses anything that might change data, because a *queue* deciding
//! that on its own is not a test anybody consented to. A tester who types this command
//! has decided. So the method and the request count are printed and confirmed before
//! anything goes out, which is the same bargain `nullhawk authz` makes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nullhawk_active::{Budget, Cancel};
use nullhawk_engine::guard::ScopeGuard;
use nullhawk_fuzz::{describe, Attack, AttackMode, Run};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_repeater::Repeater;
use nullhawk_types::ids::RequestId;
use nullhawk_types::inject::{inputs, locate};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::{NullhawkError, Result};
use nullhawk_verify::RepeaterLab;

/// Options for `nullhawk fuzz`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// The request to vary.
    pub id: &'a str,
    /// Where each payload goes: query parameter or header names. Repeatable for the
    /// multi-position modes.
    pub at: &'a [String],
    /// Or, for a single position: the value in the request to replace, wherever it appears.
    pub replacing: Option<&'a str>,
    /// Payload files, one per line. One for Sniper/Battering ram; one per position for
    /// Pitchfork/Cluster bomb.
    pub payloads: &'a [PathBuf],
    /// The attack shape: `sniper`, `battering-ram`, `pitchfork` or `cluster-bomb`.
    pub mode: &'a str,
    /// Milliseconds between requests.
    pub delay_ms: Option<u64>,
    /// The run's request ceiling.
    pub max_requests: Option<usize>,
    /// Work out the plan and stop.
    pub dry_run: bool,
    /// Send without asking.
    pub yes: bool,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    pub json: bool,
}

/// Sends one request once per payload placement, in the chosen attack shape.
pub fn fuzz(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = Arc::new(project.traffic());
    let id: RequestId = args.id.parse().map_err(|e| {
        NullhawkError::invalid_input("id", format!("{} is not a request id: {e}", args.id))
    })?;

    let mode = AttackMode::parse(args.mode).ok_or_else(|| {
        NullhawkError::invalid_input(
            "--mode",
            format!(
                "{:?} is not an attack mode. Use sniper, battering-ram, pitchfork or cluster-bomb",
                args.mode
            ),
        )
    })?;

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any()).http2(true)
    } else {
        TcpTransport::new().http2(true)
    };
    // The project's own scope. A payload list is automated traffic by volume whatever
    // it is by intent, and the guard refuses automated traffic to undeclared hosts.
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone())
        // Whatever the programme requires on every request. A researcher whose
        // traffic cannot be told from an attacker's is entitled to be treated
        // like one.
        .attaching(project.settings().attached_headers()?);
    let draft = repeater.draft_from(id)?;

    let positions = positions(&draft.request, &args)?;
    let lists = payload_lists(&args)?;
    let list_refs: Vec<&[String]> = lists.iter().map(Vec::as_slice).collect();

    // The ceiling defaults to the whole attack plus the baseline.
    let mut budget = Budget {
        max_requests: args.max_requests.unwrap_or(usize::MAX),
        // One host, always: every request in a fuzz run goes to the same place, so the
        // concurrency knob would only be a way to hit it harder.
        hosts_at_once: 1,
        ..Budget::default()
    };
    if let Some(delay) = args.delay_ms {
        budget.pause = std::time::Duration::from_millis(delay);
    }

    let attack = Attack {
        draft: &draft,
        positions,
        payload_lists: list_refs,
        mode,
        budget: budget.clone(),
    };
    // Say what is wrong with the shape before defaulting the ceiling to its size.
    attack.validate()?;
    if args.max_requests.is_none() {
        budget.max_requests = attack.requests();
    }
    let attack = Attack {
        budget: budget.clone(),
        ..attack
    };
    budget
        .check()
        .map_err(|why| NullhawkError::invalid_input("budget", why))?;

    let method = draft.request.method.clone();
    let url = draft.request.url();
    if !args.json {
        println!("{}", attack.describe(&method, &url));
    }
    if args.dry_run {
        if !args.json {
            println!();
            println!("Nothing was sent. Re-run without --dry-run to send these.");
        }
        return Ok(());
    }

    if !args.yes {
        if args.json {
            return Err(NullhawkError::invalid_input(
                "--yes",
                "this sends traffic and --json cannot ask. Pass --yes, or use --dry-run",
            ));
        }
        // Named explicitly for a method that may change something. The scheduler
        // refuses these outright; a person may decide otherwise, having been told.
        if nullhawk_active::is_state_changing(&method) {
            println!();
            println!(
                "{method} may change data on the target, and this will send it up to {} times.",
                attack.requests()
            );
        }
        println!();
        if !crate::proxy::confirm("Send these requests?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;

    let lab = RepeaterLab::scanner(&repeater);
    let cancel = Cancel::new();
    let run = runtime.block_on(stoppable(&attack, &lab, &cancel))?;

    if args.json {
        print_json(&run);
    } else {
        print_human(&run);
    }
    Ok(())
}

/// Runs the attack, with Ctrl-C wired to the run's own stop signal.
async fn stoppable(
    attack: &Attack<'_>,
    lab: &dyn nullhawk_verify::Lab,
    cancel: &Cancel,
) -> Result<Run> {
    let run = nullhawk_fuzz::run_attack(attack, lab, cancel);
    tokio::pin!(run);

    tokio::select! {
        outcome = &mut run => outcome,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_ok() {
                eprintln!();
                eprintln!("Stopping. No further payload will be sent — one already on the");
                eprintln!("wire will finish, because nothing can recall it.");
                cancel.stop();
            }
            (&mut run).await
        }
    }
}

/// Where the payloads go — one or several positions.
///
/// `--replacing` names a single position by value; `--at` names positions by parameter or
/// header name and may be repeated. A tester who mistypes a name is told what the request
/// actually has rather than left to guess.
fn positions(
    request: &nullhawk_types::http::HttpRequest,
    args: &Args<'_>,
) -> Result<Vec<ObjectLocation>> {
    if let Some(value) = args.replacing {
        let at = locate(request, value).into_iter().next().ok_or_else(|| {
            NullhawkError::invalid_input(
                "--replacing",
                format!("`{value}` does not appear in this request"),
            )
        })?;
        return Ok(vec![at]);
    }

    if args.at.is_empty() {
        return Err(NullhawkError::invalid_input(
            "--at",
            format!(
                "say where the payloads go: --at <name> (repeatable) or --replacing <value>. \
                 This request offers {}",
                list(&inputs(request))
            ),
        ));
    }

    let available = inputs(request);
    let mut out = Vec::with_capacity(args.at.len());
    for name in args.at {
        let found = available
            .iter()
            .find(|slot| match slot {
                ObjectLocation::Query { name: n, .. } | ObjectLocation::Header { name: n, .. } => {
                    n.eq_ignore_ascii_case(name)
                }
                _ => false,
            })
            .cloned()
            .ok_or_else(|| {
                NullhawkError::invalid_input(
                    "--at",
                    format!(
                        "this request has no `{name}` to vary. It offers {}",
                        list(&available)
                    ),
                )
            })?;
        out.push(found);
    }
    Ok(out)
}

fn list(available: &[ObjectLocation]) -> String {
    if available.is_empty() {
        return "nothing this command can address — try --replacing <value>".into();
    }
    available
        .iter()
        .map(describe)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The payload lists, one per `--payloads` file.
fn payload_lists(args: &Args<'_>) -> Result<Vec<Vec<String>>> {
    if args.payloads.is_empty() {
        return Err(NullhawkError::invalid_input(
            "--payloads",
            "give a file of payloads, one per line (one file per position for pitchfork and \
             cluster-bomb)",
        ));
    }
    args.payloads.iter().map(|path| read_list(path)).collect()
}

/// Reads one payload file into a list, dropping blank lines and Windows carriage returns.
fn read_list(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        NullhawkError::invalid_input(
            "--payloads",
            format!("{} could not be read: {e}", path.display()),
        )
    })?;
    let list: Vec<String> = text
        .lines()
        .map(str::trim_end_matches_carriage)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if list.is_empty() {
        return Err(NullhawkError::invalid_input(
            "--payloads",
            format!("{} has no payloads in it", path.display()),
        ));
    }
    Ok(list)
}

/// A newline-split line without its carriage return, for a list written on Windows.
trait TrimCr {
    fn trim_end_matches_carriage(&self) -> &str;
}

impl TrimCr for str {
    fn trim_end_matches_carriage(&self) -> &str {
        self.strip_suffix('\r').unwrap_or(self)
    }
}

fn print_human(run: &Run) {
    println!();
    println!("{}", run.summary());

    // First, because a list that was not finished must not read as one where nothing
    // stood out.
    if let Some(stopped) = run.stopped {
        println!();
        println!("This run is unfinished: {}", stopped.as_str());
    }

    if let Some(baseline) = &run.baseline {
        println!();
        match &baseline.error {
            Some(why) => println!("The unchanged request did not complete: {why}"),
            None => println!(
                "The unchanged request answered {} in {} bytes.",
                baseline.status, baseline.bytes
            ),
        }
    }

    let grouped = run.grouped();
    if !grouped.is_empty() {
        println!();
        println!("{:<8} {:>8} {:>6}  PAYLOADS", "STATUS", "BYTES", "COUNT");
        for group in &grouped {
            println!(
                "{:<8} {:>8} {:>6}  {}{}",
                group.status,
                group.bytes,
                group.count,
                group.examples.join(", "),
                if group.is_baseline {
                    "   ← as the unchanged request"
                } else {
                    ""
                },
            );
        }
    }

    let outliers = run.outliers();
    println!();
    if outliers.is_empty() {
        println!("Nothing stood out. Every payload that answered behaved like the others,");
        println!("which is a result about this list against this request and not about");
        println!("the application.");
    } else {
        println!(
            "{} payload(s) did not behave like the rest:",
            outliers.len()
        );
        for attempt in outliers.iter().take(20) {
            println!(
                "  {:<28} {} · {} bytes{}",
                attempt.payload,
                attempt.status,
                attempt.bytes,
                attempt
                    .request
                    .map(|id| format!(" · {id}"))
                    .unwrap_or_default(),
            );
        }
        if outliers.len() > 20 {
            println!("  … and {} more", outliers.len() - 20);
        }
        println!();
        println!("Open one with `nullhawk history <project> --id <request>`, or compare two");
        println!("with `nullhawk repeat <project> <a> --diff <b>`. Nothing here is a finding:");
        println!("what a difference means is a judgement about this application.");
    }

    let failed: Vec<_> = run.attempts.iter().filter(|a| !a.answered()).collect();
    if !failed.is_empty() {
        println!();
        println!("{} payload(s) did not complete:", failed.len());
        for attempt in failed.iter().take(5) {
            println!(
                "  {:<28} {}",
                attempt.payload,
                attempt.error.as_deref().unwrap_or("no reason recorded")
            );
        }
        if failed.len() > 5 {
            println!("  … and {} more", failed.len() - 5);
        }
    }
}

fn print_json(run: &Run) {
    let groups: Vec<_> = run
        .grouped()
        .into_iter()
        .map(|group| {
            serde_json::json!({
                "status": group.status,
                "bytes": group.bytes,
                "count": group.count,
                "examples": group.examples,
                "request": group.request.map(|id| id.to_string()),
                "as_unchanged": group.is_baseline,
            })
        })
        .collect();

    let outliers: Vec<_> = run
        .outliers()
        .into_iter()
        .map(|attempt| {
            serde_json::json!({
                "payload": attempt.payload,
                "status": attempt.status,
                "bytes": attempt.bytes,
                "request": attempt.request.map(|id| id.to_string()),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::json!({
            "summary": run.summary(),
            "complete": run.complete(),
            "stopped_because": run.stopped.map(|why| why.as_column()),
            "unfinished_note": run.stopped.map(|why| why.as_str()),
            "requests_sent": run.requests_sent,
            "baseline": run.baseline.as_ref().map(|a| serde_json::json!({
                "status": a.status,
                "bytes": a.bytes,
                "request": a.request.map(|id| id.to_string()),
                "error": a.error,
            })),
            "groups": groups,
            "outliers": outliers,
        })
    );
}
