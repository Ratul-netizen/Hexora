//! `hexora authz` — replay one captured request as everybody, and say what it proves.
//!
//! The output is a table, because the question is a table: identities down the side,
//! what each of them got across it. Everything else the command prints exists to keep
//! the table honest — the scope refusal before anything is sent, the warning about
//! replaying a state-changing request, and the demotion note when an anonymous control
//! shows the resource was public all along.

use std::path::Path;
use std::sync::Arc;

use hexora_authz::construct::{Construction, ConstructionPlan};
use hexora_authz::{analysis, AuthzTester, Cell, Matrix, Plan, Verdict};
use hexora_engine::guard::ScopeGuard;
use hexora_http::{TcpTransport, TlsConfig};
use hexora_repeater::Repeater;
use hexora_storage::{FindingStore, Recorded};
use hexora_types::identity::Identity;
use hexora_types::ids::RequestId;
use hexora_types::structure::Comparable;
use hexora_types::verify::Verified;
use hexora_types::{HexoraError, Result};

/// Options for `hexora authz`.
pub struct AuthzArgs<'a> {
    pub project: &'a Path,
    /// The captured request to replay, from `hexora history`.
    pub id: &'a str,
    /// The identity the request belongs to.
    pub owner: &'a str,
    /// Identities to replay it as. Empty means every other identity in the project.
    pub identities: &'a [String],
    /// Do not add an unauthenticated control.
    pub no_anonymous: bool,
    /// Replay each violation once more before reporting it.
    pub verify: bool,
    /// Replay a state-changing request without asking.
    pub yes: bool,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Report the findings without writing them into the project.
    pub no_save: bool,
    /// Also build cross-identity requests from the declared objects.
    pub construct: bool,
    /// The most constructed requests this run may send.
    pub max_attempts: usize,
    pub json: bool,
}

/// Runs an authorization matrix and prints it.
pub fn run(args: AuthzArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let base: RequestId = args.id.parse()?;
    let identities_store = project.identities();
    let store = Arc::new(project.traffic());

    let owner = crate::identity::resolve(&identities_store, args.owner)?;
    let others = choose(&identities_store, args.identities, &owner)?;
    if others.is_empty() {
        return Err(HexoraError::invalid_input(
            "identities",
            "there is nobody to compare against: add a second identity with \
             `hexora identity add`",
        ));
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The project's own scope, not an empty one. An authorization matrix is automated
    // traffic, and the guard refuses automated traffic to undeclared hosts.
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone());
    let tester = AuthzTester::new(repeater, store.clone(), identities_store);

    let method = tester.method_of(base)?;
    if Plan::is_state_changing(&method) && !args.yes {
        return Err(HexoraError::invalid_input(
            "method",
            format!(
                "{method} may change data on the target, and this run would send it \
                 {} times. Re-run with --yes if that is what you want.",
                others.len() + 1
            ),
        ));
    }

    let mut plan = Plan::new(base, owner, others);
    plan.anonymous_control = !args.no_anonymous;
    plan.verify = args.verify;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;
    // The target the base request was actually sent to. A finding that named a
    // freshly minted id would cite a target the project has never heard of, and the
    // foreign key would refuse it — correctly.
    let target = store.target_of(base)?;

    // Run, detect, verify. Nothing between here and the store produces a `Finding`
    // directly — it cannot, because only a verification makes one.
    let assessment = runtime.block_on(tester.assess(&plan, target))?;
    let matrix = assessment.matrix.clone();
    let mut findings = assessment.findings();

    // Constructed attempts run after the matrix and against the same base request, so
    // the replay results are on screen before anything new is sent — and so a tester
    // who only wanted the matrix has already got it if construction fails.
    let construction = if args.construct {
        let declarations = project.objects().list()?;
        if declarations.is_empty() {
            return Err(HexoraError::invalid_input(
                "--construct",
                "no objects are declared in this project, so there is nothing to \
                 construct a request for. Declare one with `hexora object add`",
            ));
        }
        let senders = std::iter::once(plan.owner.clone())
            .chain(plan.others.iter().cloned())
            .collect();
        let construction = runtime.block_on(
            tester.construct(
                &ConstructionPlan::new(base, senders, declarations)
                    .with_limit(args.max_attempts)
                    .verifying(args.verify),
            ),
        )?;
        findings.extend(analysis::construction_findings(&construction, target));
        Some(construction)
    } else {
        None
    };

    let saved = if args.no_save || findings.is_empty() {
        Vec::new()
    } else {
        save(&project.findings(), &findings)?
    };

    if args.json {
        print_json(&matrix, construction.as_ref(), &findings, &saved);
    } else {
        print_human(
            &matrix,
            construction.as_ref(),
            &findings,
            &saved,
            args.no_save,
        );
    }
    Ok(())
}

/// Prints what was built, and what each attempt showed.
fn print_construction(construction: &Construction) {
    println!();
    println!(
        "Constructed {} cross-identity attempt(s) from {}:",
        construction.attempts.len(),
        construction.url
    );
    for attempt in &construction.attempts {
        println!();
        println!(
            "  {} → {} ({}, owned by {})",
            attempt.sender_label, attempt.object_value, attempt.object_name, attempt.owner_label
        );
        println!("    substituted {}", attempt.describe_substitution());
        match attempt.status {
            // The similarity is only meaningful next to a response that carried
            // something: "401 denied, 100% alike its own object" reads as nonsense
            // when the identity's own request was refused as well.
            Some(status) if attempt.outcome == hexora_authz::Outcome::Denied => {
                println!("    → {status} {}", attempt.outcome.as_str())
            }
            Some(status) => println!(
                "    → {status} {} · {:.0}% alike its own object",
                attempt.outcome.as_str(),
                attempt.similarity * 100.0
            ),
            None => println!(
                "    → not sent: {}",
                attempt.error.as_deref().unwrap_or("unknown reason")
            ),
        }
        if !attempt.disclosed_object_ids.is_empty() {
            println!(
                "    → response carried {}, which {} never sent",
                attempt.disclosed_object_ids.join(", "),
                attempt.sender_label
            );
        }
        println!(
            "    → {}{}",
            attempt.verdict.as_str(),
            if attempt.reproduced {
                ", reproduced"
            } else {
                ""
            }
        );
        if let Some(note) = &attempt.note {
            println!("    {note}");
        }
    }

    for skipped in &construction.skipped {
        println!();
        println!("  not constructed — {skipped}");
    }
}

/// Writes the run's findings into the project.
///
/// Uses `record` rather than `save`, so running the same matrix again after a fix
/// updates the claim instead of adding a second copy of it — and leaves whatever
/// triage decision a human already made about it alone.
fn save(store: &FindingStore, findings: &[Verified]) -> Result<Vec<Recorded>> {
    findings.iter().map(|f| Ok(store.record(f)?)).collect()
}

/// The identities to replay as: those named, or everybody except the owner.
fn choose(
    store: &hexora_storage::IdentityStore,
    named: &[String],
    owner: &Identity,
) -> Result<Vec<Identity>> {
    if named.is_empty() {
        return Ok(store
            .list()?
            .into_iter()
            .filter(|identity| identity.id != owner.id)
            .collect());
    }

    named
        .iter()
        .map(|who| crate::identity::resolve(store, who))
        .collect()
}

/// What differed, for the rows where a percentage is not an answer.
///
/// A similarity column tells a tester that two responses were 97% alike and leaves
/// them to open both and find out why. This says which field, which is the part they
/// were going to go and look for.
fn print_structure(matrix: &Matrix) {
    let interesting: Vec<&Cell> = matrix
        .cells
        .iter()
        .filter(|cell| cell.structure.is_some())
        .collect();
    if interesting.is_empty() {
        return;
    }

    let mut printed_heading = false;
    for cell in interesting {
        let Some(structure) = &cell.structure else {
            continue;
        };
        if structure.comparable != Comparable::Structurally {
            continue;
        }
        if !printed_heading {
            println!();
            println!(
                "Compared with {}'s response, field by field:",
                matrix.owner.label
            );
            printed_heading = true;
        }
        println!();
        if structure.same_document() {
            println!(
                "  {}: the same document at every one of its {} field(s)",
                cell.label, structure.shared_paths
            );
        } else {
            let ranked = structure.ranked();
            println!(
                "  {}: {} of {} field(s) differ",
                cell.label,
                ranked.len(),
                structure.total_paths
            );
            if structure.every_value_differs() {
                // An observation, not a claim: Hexora does not know whose record is
                // whose without a declaration. It is the shape a correctly-scoped
                // endpoint has, and a reader can check it against the list below.
                println!(
                    "    every one of {} shared value(s) differs — consistent with \
                     each caller being served their own record",
                    structure.shared_paths
                );
            }
            for difference in ranked.iter().take(MAX_DIFFERENCES) {
                println!(
                    "    {}",
                    difference.describe(&matrix.owner.label, &cell.label)
                );
            }
            if ranked.len() > MAX_DIFFERENCES {
                println!("    … and {} more", ranked.len() - MAX_DIFFERENCES);
            }
        }

        let aside = structure.set_aside();
        if aside > 0 {
            // Named rather than omitted. A comparison that decided some fields did not
            // count and did not say so would be altering the evidence it reports on.
            println!(
                "    {aside} field(s) set aside: {}",
                structure.policy.describe()
            );
            for difference in structure.differences.iter().filter(|d| !d.counts()) {
                println!(
                    "      {}",
                    difference.describe(&matrix.owner.label, &cell.label)
                );
            }
        }
        for quirk in &structure.quirks {
            println!("    note: {}", quirk.as_str());
        }
    }
}

/// How many differing fields a matrix row prints before it stops.
const MAX_DIFFERENCES: usize = 6;

fn print_human(
    matrix: &Matrix,
    construction: Option<&Construction>,
    findings: &[Verified],
    saved: &[Recorded],
    no_save: bool,
) {
    println!("{} {}", matrix.method, matrix.url);
    println!(
        "Baseline: {} → {}",
        matrix.owner.label,
        status(&matrix.owner)
    );
    println!();

    println!(
        "{:<22} {:<14} {:<7} {:<13} {:<6} VERDICT",
        "IDENTITY", "PRIVILEGE", "STATUS", "OUTCOME", "SIM"
    );
    for cell in &matrix.cells {
        println!(
            "{:<22} {:<14} {:<7} {:<13} {:<6} {}",
            truncate(&cell.label, 22),
            crate::identity::privilege_name(cell.privilege),
            status(cell),
            cell.outcome.as_str(),
            format!("{:.2}", cell.similarity),
            verdict(cell),
        );
    }

    if matrix.appears_public {
        println!();
        println!("An unauthenticated request received the same resource, so this endpoint");
        println!("appears to be public. Per-identity results are inconclusive as a result —");
        println!("the finding, if there is one, is that it needs no session at all.");
    }

    print_structure(matrix);

    for cell in &matrix.cells {
        if let Some(note) = &cell.note {
            println!();
            println!("{}: {note}", cell.label);
        }
        if let Some(error) = &cell.error {
            println!();
            println!("{}: could not be sent — {error}", cell.label);
        }
    }

    if let Some(construction) = construction {
        print_construction(construction);
    }

    println!();
    if findings.is_empty() {
        println!("No authorization violations found in this matrix.");
        return;
    }

    println!("{} candidate finding(s):", findings.len());
    for verified in findings {
        let finding = verified.finding();
        println!();
        // Rendered by the same helper the findings list uses: a finding that reads
        // one way when it is produced and another when it is read back is a finding
        // somebody has to translate.
        println!("  {}", crate::findings::one_line(finding));
        println!("  {}", finding.description);
        if !finding.confidence.is_actionable() {
            println!(
                "  Not yet actionable at {} confidence — re-run with --verify to \
                 attempt reproduction.",
                crate::findings::confidence_word(finding.confidence)
            );
        }
        for line in finding.reproduction.lines() {
            println!("  {line}");
        }
    }

    println!();
    if no_save {
        println!("Nothing was written to the project (--no-save).");
        return;
    }
    let new = saved.iter().filter(|r| r.is_new()).count();
    let updated = saved.len() - new;
    match (new, updated) {
        (0, 0) => {}
        (n, 0) => println!("Recorded {n} finding(s) in the project."),
        (0, u) => println!("Refreshed {u} finding(s) already recorded; triage decisions kept."),
        (n, u) => println!("Recorded {n} new finding(s) and refreshed {u} already recorded."),
    }
    println!("Read them back with `hexora findings <project>`.");
}

fn print_json(
    matrix: &Matrix,
    construction: Option<&Construction>,
    findings: &[Verified],
    saved: &[Recorded],
) {
    let cells: Vec<_> = matrix
        .cells
        .iter()
        .map(|cell| {
            serde_json::json!({
                "identity": cell.identity.to_string(),
                "label": cell.label,
                "privilege": crate::identity::privilege_name(cell.privilege),
                "request": cell.request.map(|r| r.to_string()),
                "status": cell.status,
                "similarity": cell.similarity,
                "structure": cell.structure.as_ref(),
                "outcome": cell.outcome.as_str(),
                "verdict": cell.verdict.as_str(),
                "leaked_object_ids": cell.leaked_object_ids,
                "own_object_ids": cell.own_object_ids,
                "verification": cell.verification.as_ref().map(|v| v.as_str()),
                "verification_note": cell.verification.as_ref().map(|v| v.note()),
                "note": cell.note,
                "error": cell.error,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "base": matrix.base.to_string(),
        "method": matrix.method,
        "url": matrix.url,
        "baseline": {
            "label": matrix.owner.label,
            "request": matrix.owner.request.map(|r| r.to_string()),
            "status": matrix.owner.status,
        },
        "appears_public": matrix.appears_public,
        "cells": cells,
        "constructed": construction.map(|construction| {
            serde_json::json!({
                "limit": construction.limit,
                "skipped": construction.skipped,
                "attempts": construction
                    .attempts
                    .iter()
                    .map(|attempt| serde_json::json!({
                        "sender": attempt.sender_label,
                        "object": attempt.object_value,
                        "object_name": attempt.object_name,
                        "owner": attempt.owner_label,
                        "location": attempt.location.describe(),
                        "original_value": attempt.original_value,
                        "request": attempt.request.map(|r| r.to_string()),
                        "control": attempt.control.map(|r| r.to_string()),
                        "status": attempt.status,
                        "similarity": attempt.similarity,
                        "outcome": attempt.outcome.as_str(),
                        "verdict": attempt.verdict.as_str(),
                        "disclosed_object_ids": attempt.disclosed_object_ids,
                        "echoed": attempt.echoed,
                        "own_object_ids": attempt.own_object_ids,
                        "reproduced": attempt.reproduced,
                        "note": attempt.note,
                        "error": attempt.error,
                    }))
                    .collect::<Vec<_>>(),
            })
        }),
        "findings": findings.iter().map(|v| v.finding()).collect::<Vec<_>>(),
        "recorded": saved
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id().to_string(),
                    "new": r.is_new(),
                })
            })
            .collect::<Vec<_>>(),
    });
    println!("{payload}");
}

fn status(cell: &Cell) -> String {
    cell.status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn verdict(cell: &Cell) -> &'static str {
    match cell.verdict {
        Verdict::Violation => "VIOLATION",
        Verdict::Expected => "ok",
        Verdict::Inconclusive => "inconclusive",
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_string()
    } else {
        let kept: String = value.chars().take(width.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

#[cfg(test)]
mod tests {
    use hexora_authz::Outcome;
    use hexora_types::identity::PrivilegeLevel;
    use hexora_types::ids::IdentityId;

    use super::*;

    fn cell(verdict: Verdict) -> Cell {
        Cell {
            identity: IdentityId::new(),
            label: "User B".into(),
            privilege: PrivilegeLevel::User,
            request: Some(RequestId::new()),
            status: Some(200),
            similarity: 0.97,
            structure: None,
            outcome: Outcome::Allowed,
            verdict,
            leaked_object_ids: Vec::new(),
            own_object_ids: Vec::new(),
            verification: None,
            error: None,
            note: None,
        }
    }

    #[test]
    fn a_violation_is_rendered_so_it_cannot_be_skimmed_past() {
        assert_eq!(verdict(&cell(Verdict::Violation)), "VIOLATION");
        assert_eq!(verdict(&cell(Verdict::Expected)), "ok");
    }

    #[test]
    fn a_cell_that_never_got_a_response_shows_a_dash_rather_than_a_zero() {
        let mut cell = cell(Verdict::Inconclusive);
        cell.status = None;
        assert_eq!(status(&cell), "—");
    }

    #[test]
    fn long_labels_are_truncated_rather_than_breaking_the_table() {
        assert_eq!(truncate("short", 22), "short");
        assert_eq!(truncate(&"x".repeat(30), 22).chars().count(), 22);
    }
}
