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
use hexora_types::finding::Hypothesis;
use hexora_types::verify::Verification;
use hexora_types::{HexoraError, Result};
use hexora_verify::RepeaterLab;

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
    pub json: bool,
}

/// Settles the hypotheses a passive pass left standing.
pub fn active(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = Arc::new(project.traffic());

    let budget = budget_from(&args)?;
    let hypotheses = standing(&project, &args, false)?;

    if hypotheses.is_empty() {
        // Before saying "nothing to do", find out whether that is true. A project can
        // hold traffic that raised a suspicion yesterday and is out of scope today,
        // and reporting that as "no suspicions" would be silence standing in for a
        // reason — the failure this whole codebase is built around.
        let out_of_scope = standing(&project, &args, true)?.len();
        return nothing_to_do(out_of_scope, args.json);
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The project's own scope. An active run is automated traffic by definition, and
    // the guard refuses automated traffic to hosts nobody declared.
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone());
    // `scanner`, not `new`: an experiment with no identity must be recorded as
    // automated traffic, so the scope guard refuses an out-of-scope target rather
    // than flagging it the way it would a request a person typed.
    let lab = RepeaterLab::scanner(&repeater);

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
    let outcome = runtime.block_on(hexora_active::run_into(
        &plan, &lab, &checks, &cancel, &project,
    ))?;

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

/// The hypotheses a passive pass raised and nothing has settled.
///
/// Re-derived by running the passive checks again rather than read from a table:
/// a hypothesis is cheap to recompute, and computing it means the active run is
/// testing what the traffic says *now* rather than what a stale row remembers.
fn standing(
    project: &hexora_storage::Project,
    args: &Args<'_>,
    everything: bool,
) -> Result<Vec<Hypothesis>> {
    let selection = hexora_scan::Selection {
        host: args.host.map(|host| host.to_string()),
        detector: args.detector.map(|detector| detector.to_string()),
        everything,
        ..Default::default()
    };
    Ok(hexora_scan::passive::scan(project, &selection)?.hypotheses)
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
        for skipped in &plan.skipped {
            println!("  {} — {}", skipped.detector, skipped.claim);
            println!("    {}", skipped.why);
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
        for judged in &refuted {
            println!("  {}", judged.hypothesis.claim);
            println!("    {}", judged.verification.note());
        }
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
        for skipped in &outcome.skipped {
            println!("  {} — {}", skipped.detector, skipped.why);
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
