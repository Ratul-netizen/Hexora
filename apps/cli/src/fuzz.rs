//! `hexora fuzz` — one request, many values, and what came back.
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
//! anything goes out, which is the same bargain `hexora authz` makes.

use std::path::Path;
use std::sync::Arc;

use hexora_active::{Budget, Cancel};
use hexora_engine::guard::ScopeGuard;
use hexora_fuzz::{describe, Plan, Run};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_repeater::Repeater;
use hexora_types::ids::RequestId;
use hexora_types::inject::{inputs, locate};
use hexora_types::object::ObjectLocation;
use hexora_types::{HexoraError, Result};
use hexora_verify::RepeaterLab;

/// Options for `hexora fuzz`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// The request to vary.
    pub id: &'a str,
    /// Where the payload goes: a query parameter or header name.
    pub at: Option<&'a str>,
    /// Or: the value in the request to replace, wherever it appears.
    pub replacing: Option<&'a str>,
    /// A file of payloads, one per line.
    pub payloads: Option<&'a Path>,
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

/// Sends one request once per payload.
pub fn fuzz(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = Arc::new(project.traffic());
    let id: RequestId = args.id.parse().map_err(|e| {
        HexoraError::invalid_input("id", format!("{} is not a request id: {e}", args.id))
    })?;

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The project's own scope. A payload list is automated traffic by volume whatever
    // it is by intent, and the guard refuses automated traffic to undeclared hosts.
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone());
    let draft = repeater.draft_from(id)?;

    let at = slot(&draft.request, &args)?;
    let payloads = payloads(&args)?;
    if payloads.is_empty() {
        return Err(HexoraError::invalid_input(
            "--payloads",
            "the payload list is empty, so there is nothing to send",
        ));
    }

    let mut budget = Budget {
        max_requests: args.max_requests.unwrap_or(payloads.len() + 1),
        // One host, always: every request in a fuzz run goes to the same place, so the
        // concurrency knob would only be a way to hit it harder.
        hosts_at_once: 1,
        ..Budget::default()
    };
    if let Some(delay) = args.delay_ms {
        budget.pause = std::time::Duration::from_millis(delay);
    }
    budget
        .check()
        .map_err(|why| HexoraError::invalid_input("budget", why))?;

    let plan = Plan {
        draft: &draft,
        at,
        payloads: &payloads,
        budget,
    };

    let method = draft.request.method.clone();
    let url = draft.request.url();
    if !args.json {
        println!("{}", plan.describe(&method, &url));
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
            return Err(HexoraError::invalid_input(
                "--yes",
                "this sends traffic and --json cannot ask. Pass --yes, or use --dry-run",
            ));
        }
        // Named explicitly for a method that may change something. The scheduler
        // refuses these outright; a person may decide otherwise, having been told.
        if hexora_active::is_state_changing(&method) {
            println!();
            println!(
                "{method} may change data on the target, and this will send it {} times.",
                plan.requests()
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
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    let lab = RepeaterLab::scanner(&repeater);
    let cancel = Cancel::new();
    let run = runtime.block_on(stoppable(&plan, &lab, &cancel))?;

    if args.json {
        print_json(&run);
    } else {
        print_human(&run);
    }
    Ok(())
}

/// Runs the list, with Ctrl-C wired to the run's own stop signal.
async fn stoppable(plan: &Plan<'_>, lab: &dyn hexora_verify::Lab, cancel: &Cancel) -> Result<Run> {
    let run = hexora_fuzz::run(plan, lab, cancel);
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

/// Where the payload goes.
///
/// Two ways to say it, and a list of what is available when neither works: a tester who
/// mistypes a parameter name should be told what the request actually has rather than
/// left to guess.
fn slot(request: &hexora_types::http::HttpRequest, args: &Args<'_>) -> Result<ObjectLocation> {
    if let Some(value) = args.replacing {
        return locate(request, value).into_iter().next().ok_or_else(|| {
            HexoraError::invalid_input(
                "--replacing",
                format!("`{value}` does not appear in this request"),
            )
        });
    }

    let available = inputs(request);
    let Some(name) = args.at else {
        return Err(HexoraError::invalid_input(
            "--at",
            format!(
                "say where the payload goes: --at <name> or --replacing <value>. This \
                 request offers {}",
                list(&available)
            ),
        ));
    };

    available
        .into_iter()
        .find(|slot| match slot {
            ObjectLocation::Query { name: n, .. } | ObjectLocation::Header { name: n, .. } => {
                n.eq_ignore_ascii_case(name)
            }
            _ => false,
        })
        .ok_or_else(|| {
            HexoraError::invalid_input(
                "--at",
                format!(
                    "this request has no `{name}` to vary. It offers {}",
                    list(&inputs(request))
                ),
            )
        })
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

/// The payload list.
fn payloads(args: &Args<'_>) -> Result<Vec<String>> {
    let Some(path) = args.payloads else {
        return Err(HexoraError::invalid_input(
            "--payloads",
            "give a file of payloads, one per line",
        ));
    };
    let text = std::fs::read_to_string(path).map_err(|e| {
        HexoraError::invalid_input(
            "--payloads",
            format!("{} could not be read: {e}", path.display()),
        )
    })?;
    Ok(text
        .lines()
        .map(str::trim_end_matches_carriage)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
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
        println!("Open one with `hexora history <project> --id <request>`, or compare two");
        println!("with `hexora repeat <project> <a> --diff <b>`. Nothing here is a finding:");
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
