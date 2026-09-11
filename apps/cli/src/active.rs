//! `hexora scan active` — the experiments a passive pass could not run.
//!
//! The first command in Hexora that sends traffic nobody typed, so it is the first one
//! that asks before doing it.
//!
//! ```text
//! hexora scan passive  reads a project                    → hypotheses, filed as nothing
//! hexora scan active   settles them, one request at a time → findings, or refutations
//! ```
//!
//! # The order of operations, and why it is this order
//!
//! 1. Read the hypotheses the last passive pass raised. If there are none, stop and
//!    say so — there is nothing an active run can invent for itself.
//! 2. Build a [`Plan`], which sends nothing.
//! 3. Print it: which hosts, how many requests at most, what was skipped and why.
//! 4. Ask, unless `--yes`. A non-interactive stdin answers *no*.
//! 5. Run.
//!
//! `--dry-run` stops after step 3. It is not a flag the sending path honours — the
//! sending path is simply not called, which is the same discipline as
//! [`hexora_scan::passive::scan`] having no transport in its signature.
//!
//! # A refutation is a result
//!
//! The output leads with what was settled, in both directions. "This host does not
//! reflect arbitrary origins" is the sentence that stops a passive suspicion from
//! following a tester around for the rest of an engagement, and it is printed as
//! prominently as a finding.

use std::path::Path;
use std::sync::Arc;

use hexora_active::{Budget, Cancel, Outcome, Plan};
use hexora_engine::guard::ScopeGuard;
use hexora_http::{TcpTransport, TlsConfig};
use hexora_repeater::Repeater;
use hexora_storage::Recorded;
use hexora_types::verify::Verification;
use hexora_types::{HexoraError, Result};
use hexora_verify::RepeaterLab;

/// Adopts the freshest credential the proxy has seen, for every identity that has one.
///
/// Quiet about what it did not change: an identity whose session is already the newest
/// one recorded is not news, and a run that printed a paragraph per identity before
/// every experiment would bury the plan.
fn refresh_sessions(project: &hexora_storage::Project) -> Result<()> {
    let identities = project.identities();
    let traffic = project.traffic();
    let scope = project.settings().scope()?;

    for identity in identities.list()? {
        let found =
            hexora_authz::session::find_renewal(&traffic, &scope, &identity, REFRESH_SAMPLE, None)?;
        let Some(renewal) = found else {
            continue;
        };
        // The value never appears. A host, a time and a size are what a person needs to
        // recognise the session they just created.
        println!(
            "Adopted a newer {} for {} from {} ({} bytes)",
            renewal.slot, identity.label, renewal.host, renewal.length
        );
        let mut updated = identity.clone();
        updated.credential = renewal.credential(&identity.credential);
        identities.put(&updated)?;
    }
    Ok(())
}

/// How many recent exchanges `--refresh` reads looking for a newer session.
const REFRESH_SAMPLE: usize = 500;

/// Options for `hexora scan active`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// Only hypotheses about this host.
    pub host: Option<&'a str>,
    /// Only hypotheses raised by this check.
    pub detector: Option<&'a str>,
    /// How many hosts to work at once.
    pub hosts_at_once: Option<usize>,
    /// Milliseconds between requests to one host.
    pub delay_ms: Option<u64>,
    /// The whole run's request ceiling.
    pub max_requests: Option<usize>,
    /// Work out the plan and stop.
    pub dry_run: bool,
    /// Do not ask before sending.
    pub yes: bool,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Do not write the findings into the project.
    pub no_save: bool,
    /// Adopt the freshest session from proxy traffic before planning.
    pub refresh: bool,
    pub json: bool,
}

/// Settles the hypotheses a passive pass left standing.
pub fn active(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = Arc::new(project.traffic());

    let budget = budget_from(&args)?;
    // One function, shared with the window: two surfaces of one tool that each worked
    // out for themselves what was testable would eventually disagree.
    let standing = hexora_active::standing(&project, &selection(&args))?;

    if standing.hypotheses.is_empty() {
        // `Standing` already asked whether "nothing to do" is true. A project can hold
        // traffic that raised a suspicion yesterday and is out of scope today, and
        // reporting that as "no suspicions" would be silence standing in for a reason.
        return nothing_to_do(standing.out_of_scope, args.json);
    }
    let hypotheses = standing.hypotheses;

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The project's own scope. An active run is automated traffic by definition, and
    // the guard refuses automated traffic to hosts nobody declared.
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone())
        // Whatever the programme requires on every request. A researcher whose
        // traffic cannot be told from an attacker's is entitled to be treated
        // like one.
        .attaching(project.settings().attached_headers()?);
    // `scanner`, not `new`: an experiment with no identity must be recorded as
    // automated traffic, so the scope guard refuses an out-of-scope target rather
    // than flagging it the way it would a request a person typed.
    let lab = RepeaterLab::scanner(&repeater);

    // The freshest session this project has seen, before anything is planned.
    //
    // Sessions are short and runs are not: a token issued for half an hour and adopted
    // by hand ten minutes ago leaves twenty, and a queue of two hundred experiments
    // does not fit in twenty. Starting from the newest credential the proxy has
    // recorded is the cheapest minute of the run — it sends nothing.
    if args.refresh {
        refresh_sessions(&project)?;
    }

    let checks = hexora_active::active_checks();
    let plan = Plan::prepare(&project, &lab, &checks, &hypotheses, &budget)?;

    if args.json {
        print_plan_json(&plan);
    } else {
        print_plan(&plan);
    }

    if plan.work.is_empty() {
        return Ok(());
    }
    if args.dry_run {
        if !args.json {
            println!();
            println!("Nothing was sent. Re-run without --dry-run to perform these experiments.");
        }
        return Ok(());
    }

    // Asked before anything goes out, and only ever here: there is no path into the
    // scheduler that skips this without the operator having said so.
    if !args.yes && !args.json {
        println!();
        if !crate::proxy::confirm("Send these requests?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if !args.yes && args.json {
        return Err(HexoraError::invalid_input(
            "--yes",
            "an active run sends traffic, and --json cannot ask. Pass --yes to say \
             that is intended, or use --dry-run to see the plan",
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    let cancel = Cancel::new();
    let outcome = runtime.block_on(stoppable(&plan, &lab, &checks, &cancel, &project))?;

    let saved = if args.no_save {
        Vec::new()
    } else {
        let findings = project.findings();
        let mut saved = Vec::new();
        for verified in outcome.findings() {
            saved.push(findings.record(verified)?);
        }
        saved
    };

    if args.json {
        print_json(&outcome, &saved);
    } else {
        print_human(&outcome, &saved, args.no_save);
    }
    Ok(())
}

/// Runs the plan, with Ctrl-C wired to the run's own stop signal.
///
/// Without this, Ctrl-C kills the process: the requests already sent are in the
/// project and nothing says what was done or how far it got. With it, the first
/// Ctrl-C stops the run before its next request and the normal report is printed,
/// including the sentence saying the run is unfinished.
///
/// A second Ctrl-C is not intercepted — the signal handler is dropped as soon as the
/// select resolves — so somebody who wants the process gone still gets it. A tool that
/// swallowed the second one would be worse than one that never handled the first.
async fn stoppable(
    plan: &Plan,
    lab: &dyn hexora_verify::Lab,
    checks: &[Box<dyn hexora_active::ActiveCheck>],
    cancel: &Cancel,
    project: &hexora_storage::Project,
) -> Result<hexora_active::Outcome> {
    let run = hexora_active::run_into(plan, lab, checks, cancel, project);
    tokio::pin!(run);

    // One `select!` and no loop: whichever arm wins, the run is then awaited to
    // completion. Pulling the signal does not abandon the run — it stops the *next*
    // request and lets the current one finish, which is the only promise `Cancel` can
    // keep and therefore the only one worth writing here.
    tokio::select! {
        outcome = &mut run => outcome,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_err() {
                // No handler available on this platform or terminal. The run is still
                // going and still bounded by its budget; saying so is better than
                // pretending Ctrl-C will work.
                eprintln!(
                    "Ctrl-C could not be handled here; the run will finish within its budget."
                );
            } else {
                eprintln!();
                eprintln!("Stopping. No further request will be sent — one already on the");
                eprintln!("wire will finish, because nothing can recall it.");
                cancel.stop();
            }
            (&mut run).await
        }
    }
}

/// The budget, from the flags, refusing rather than clamping.
fn budget_from(args: &Args<'_>) -> Result<Budget> {
    let mut budget = Budget::default();
    if let Some(hosts) = args.hosts_at_once {
        budget.hosts_at_once = hosts;
    }
    if let Some(delay) = args.delay_ms {
        budget.pause = std::time::Duration::from_millis(delay);
    }
    if let Some(max) = args.max_requests {
        budget.max_requests = max;
    }
    budget
        .check()
        .map_err(|why| HexoraError::invalid_input("budget", why))?;
    Ok(budget)
}

/// What the run was asked to look at.
fn selection(args: &Args<'_>) -> hexora_scan::Selection {
    hexora_scan::Selection {
        host: args.host.map(|host| host.to_string()),
        detector: args.detector.map(|detector| detector.to_string()),
        ..Default::default()
    }
}

/// Says nothing was tested, and — when it can — why that is not the same as nothing
/// being there.
fn nothing_to_do(out_of_scope: usize, json: bool) -> Result<()> {
    let note = if out_of_scope > 0 {
        format!(
            "no in-scope hypothesis to settle, though {out_of_scope} stand(s) on              traffic that is now out of scope"
        )
    } else {
        "no standing hypothesis to settle".to_string()
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "experiments": 0,
                "requests_sent": 0,
                "out_of_scope_hypotheses": out_of_scope,
                "note": note,
            })
        );
        return Ok(());
    }

    if out_of_scope > 0 {
        println!("No in-scope hypothesis to settle.");
        println!();
        println!("{out_of_scope} suspicion(s) stand on traffic that is no longer in this");
        println!("project's scope, so nothing was sent to it. That is the scope working,");
        println!("not the application being clean — widen the scope if those hosts are");
        println!("in bounds, with `hexora scope add`.");
    } else {
        println!("No standing hypothesis to settle.");
        println!();
        println!("An active run tests suspicions a passive pass raised; it does not");
        println!("invent work of its own. Run `hexora scan passive <project>` first,");
        println!("and capture more traffic if that produces nothing.");
    }
    Ok(())
}

fn print_plan(plan: &Plan) {
    println!("{}", plan.describe());

    if !plan.skipped.is_empty() {
        println!();
        println!("Not tested ({}):", plan.skipped.len());
        print_skipped(&plan.skipped);
    }
}

/// How many share a reason before it is worth saying once instead of each time.
///
/// Below this, which hypothesis was skipped is the useful part. Above it, the reason
/// is — a session that expired said so four hundred and forty-four times in one plan,
/// and a wall of identical paragraphs is how a reader learns to skip the section that
/// explains what was not tested.
const GROUP_ABOVE: usize = 3;

fn print_skipped(skipped: &[hexora_active::Skipped]) {
    let mut by_reason: std::collections::BTreeMap<&str, Vec<&hexora_active::Skipped>> =
        Default::default();
    for item in skipped {
        by_reason.entry(item.why.as_str()).or_default().push(item);
    }

    for (why, items) in by_reason {
        if items.len() > GROUP_ABOVE {
            println!("  {} — {why}", items.len());
            continue;
        }
        for item in items {
            println!("  {} — {}", item.detector, item.claim);
            println!("    {why}");
        }
    }
}

fn print_plan_json(plan: &Plan) {
    let hosts: Vec<_> = plan
        .by_host()
        .into_iter()
        .map(|(host, queue)| {
            serde_json::json!({
                "host": host,
                "experiments": queue.len(),
                "requests_at_most": queue.len() * plan.budget.per_hypothesis,
            })
        })
        .collect();
    let skipped: Vec<_> = plan
        .skipped
        .iter()
        .map(|skipped| {
            serde_json::json!({
                "detector": skipped.detector,
                "claim": skipped.claim,
                "why": skipped.why,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "plan": {
                "experiments": plan.work.len(),
                "requests_at_most": plan.requests_at_most(),
                "hosts": hosts,
                "budget": plan.budget.describe(),
                "skipped": skipped,
            }
        })
    );
}

fn print_human(outcome: &Outcome, saved: &[Recorded], no_save: bool) {
    println!();
    println!(
        "{} request(s) sent across {} experiment(s).",
        outcome.requests_sent,
        outcome.judged.len()
    );

    // First, because it is the sentence that must never be mistaken for a clean
    // result.
    if let Some(stopped) = outcome.stopped {
        println!();
        println!("This run is unfinished: {}", stopped.as_str());
    }

    let settled: Vec<_> = outcome
        .judged
        .iter()
        .filter(|judged| judged.finding.is_some())
        .collect();
    let refuted: Vec<_> = outcome.refuted().collect();
    let unclear: Vec<_> = outcome
        .judged
        .iter()
        .filter(|judged| matches!(judged.verification, Verification::Inconclusive { .. }))
        .collect();

    if !settled.is_empty() {
        println!();
        println!("Established ({}):", settled.len());
        for judged in &settled {
            let finding = judged.finding.as_ref().unwrap().clone().into_finding();
            println!(
                "  [{}/{}] {}",
                crate::findings::severity_word(finding.severity),
                crate::findings::confidence_word(finding.confidence),
                finding.title
            );
            println!("  {}", judged.verification.note());
        }
    }

    if !refuted.is_empty() {
        println!();
        println!("Ruled out ({}):", refuted.len());

        // The overwhelmingly common refutation, and the least interesting: the input
        // was tested and nothing came back. Counted rather than listed, because a
        // hundred identical lines bury the handful that say something.
        let (silent, echoed): (Vec<&&hexora_verify::Judged>, Vec<&&hexora_verify::Judged>) =
            refuted
                .iter()
                .partition(|judged| judged.verification.note().contains("did not come back"));

        if !silent.is_empty() {
            println!(
                "  {} input(s) were tested and did not come back in the response.",
                silent.len()
            );
        }
        for judged in &echoed {
            println!("  {}", judged.hypothesis.claim);
            println!("    {}", judged.verification.note());
        }
        println!();
        println!("  A refutation is a result: these were tested, and what came back");
        println!("  does not support the suspicion. Nothing was filed for them.");
    }

    if !unclear.is_empty() {
        println!();
        println!("Could not be established either way ({}):", unclear.len());
        for judged in &unclear {
            println!("  {}", judged.hypothesis.claim);
            println!("    {}", judged.verification.note());
        }
    }

    if !outcome.skipped.is_empty() {
        println!();
        println!("Not tested ({}):", outcome.skipped.len());
        // Grouped by reason: "no check can settle this" said four hundred times is one
        // fact about the tool, not four hundred.
        let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
        for skipped in &outcome.skipped {
            *by_reason.entry(skipped.why.as_str()).or_default() += 1;
        }
        for (why, count) in by_reason {
            println!("  {count} — {why}");
        }
    }

    println!();
    if outcome.detectors.is_empty() {
        println!("No active check ran.");
    } else {
        println!(
            "{:<24} {:<12} {:>10} {:>10}",
            "CHECK", "VERSION", "TESTED", "FILED"
        );
        for detector in &outcome.detectors {
            println!(
                "{:<24} {:<12} {:>10} {:>10} {}",
                detector.detector,
                detector.version,
                detector.hypotheses,
                detector.reportable,
                if detector.hypotheses == 0 {
                    "nothing to settle"
                } else {
                    ""
                }
            );
        }
    }

    println!();
    if no_save {
        println!("Nothing was written into the project (--no-save).");
    } else if saved.is_empty() {
        println!("No finding was recorded. A refutation is a result, not a claim.");
    } else {
        let new = saved.iter().filter(|r| r.is_new()).count();
        println!(
            "Recorded {} finding(s): {new} new, {} refreshed.",
            saved.len(),
            saved.len() - new
        );
    }
}

fn print_json(outcome: &Outcome, saved: &[Recorded]) {
    let judged: Vec<_> = outcome
        .judged
        .iter()
        .map(|judged| {
            serde_json::json!({
                "detector": judged.hypothesis.detector,
                "claim": judged.hypothesis.claim,
                "verification": judged.verification.as_str(),
                "note": judged.verification.note(),
                "finding": judged
                    .finding
                    .as_ref()
                    .map(|f| f.clone().into_finding().id.to_string()),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::json!({
            "requests_sent": outcome.requests_sent,
            "experiments": outcome.judged.len(),
            "complete": outcome.complete(),
            "stopped_because": outcome.stopped.map(|why| why.as_column()),
            "unfinished_note": outcome.stopped.map(|why| why.as_str()),
            "judged": judged,
            "skipped": outcome
                .skipped
                .iter()
                .map(|s| serde_json::json!({
                    "detector": s.detector,
                    "claim": s.claim,
                    "why": s.why,
                }))
                .collect::<Vec<_>>(),
            "detectors": outcome
                .detectors
                .iter()
                .map(|d| serde_json::json!({
                    "detector": d.detector,
                    "version": d.version,
                    "tested": d.hypotheses,
                    "filed": d.reportable,
                }))
                .collect::<Vec<_>>(),
            "recorded": saved.len(),
            "run": outcome.run.as_ref().map(|run| run.id.to_string()),
        })
    );
}
