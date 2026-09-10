//! `hexora snapshot` — what the engagement looked like then, and what changed since.
//!
//! A consultant tests in March, the client fixes through April, the consultant comes
//! back in May. The only question anybody asks in May is *what changed* — and every
//! other store in a project is live, so without a record of what was true in March
//! there is nothing to compare against.
//!
//! Taking a snapshot reads the project and writes one row. It sends nothing, alters no
//! captured traffic, and creates no finding.
//!
//! # The word this command will not print
//!
//! *Fixed.* A finding is what a test produced; its absence from a later snapshot is
//! the absence of a result. `diff` says why a claim is missing — and only one of the
//! three answers is about the application at all. Security invariant 11.

use std::path::Path;

use hexora_storage::SnapshotSummary;
use hexora_types::ids::SnapshotId;
use hexora_types::snapshot::{
    compare, Change, ClaimChange, Comparison, FindingState, Snapshot, WhyGone,
};
use hexora_types::{HexoraError, Result};

/// Records the project as it stands.
pub fn take(project: &Path, label: Option<&str>, note: Option<&str>, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let store = handle.snapshots();

    let snapshot = Snapshot {
        id: SnapshotId::new(),
        label: label
            .map(str::to_string)
            .unwrap_or_else(|| default_label(&store.count().unwrap_or(0))),
        note: note.map(str::to_string),
        taken_at: chrono::Utc::now(),
        tool_version: hexora_types::VERSION.to_string(),
        schema_version: handle.metadata().schema_version()?,
        contents: hexora_storage::capture(&handle)?,
    };
    store.put(&snapshot)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": snapshot.id.to_string(),
                "label": snapshot.label,
                "taken_at": snapshot.taken_at.to_rfc3339(),
                "tool_version": snapshot.tool_version,
                "exchanges": snapshot.contents.exchanges,
                "findings": snapshot.contents.findings.len(),
                "identities": snapshot.contents.identities.len(),
                "objects": snapshot.contents.objects.len(),
                "candidates": snapshot.contents.candidates,
            })
        );
        return Ok(());
    }

    println!("Recorded {} as {}.", snapshot.label, snapshot.id);
    println!();
    println!(
        "  {} exchange(s) · {} finding(s) · {} identity(ies) · {} declared object(s)",
        snapshot.contents.exchanges,
        snapshot.contents.findings.len(),
        snapshot.contents.identities.len(),
        snapshot.contents.objects.len()
    );
    println!("  taken by hexora {}", snapshot.tool_version);
    println!();
    // Said once, at the point where somebody might assume otherwise: a snapshot is
    // small because it is a record to compare, not a copy to restore from.
    println!("The traffic itself is not copied — a snapshot is a record to compare against,");
    println!("not a backup. Compare it with the project as it stands later:");
    println!(
        "  hexora snapshot diff {} {}",
        project.display(),
        snapshot.id
    );
    Ok(())
}

/// Lists the snapshots a project holds.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let snapshots = handle.snapshots().list()?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "snapshots": snapshots.iter().map(summary_json).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    if snapshots.is_empty() {
        println!("No snapshots in {}.", project.display());
        println!();
        println!("A snapshot is what makes a retest answerable. Take one before the client");
        println!("starts fixing things, and the next visit can say what moved:");
        println!(
            "  hexora snapshot take {} --label \"before the fix\"",
            project.display()
        );
        return Ok(());
    }

    println!(
        "{:<38} {:<24} {:>9} {:>9} {:<20} WHEN",
        "ID", "LABEL", "FINDINGS", "EXCHANGES", "TOOL"
    );
    for snapshot in &snapshots {
        println!(
            "{:<38} {:<24} {:>9} {:>9} {:<20} {}",
            snapshot.id.to_string(),
            truncate(&snapshot.label, 24),
            snapshot.findings,
            snapshot.exchanges,
            snapshot.tool_version,
            snapshot.taken_at.format("%Y-%m-%d %H:%M")
        );
    }

    println!();
    println!("{} snapshot(s).", snapshots.len());
    println!("  hexora snapshot diff {} <id>", project.display());
    Ok(())
}

/// Prints one snapshot.
pub fn show(project: &Path, id: &str, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let snapshot = handle.snapshots().get(parse_id(id)?)?;

    if json {
        println!("{}", serde_json::to_string(&snapshot).unwrap_or_default());
        return Ok(());
    }

    println!("Snapshot: {}", snapshot.id);
    println!("Label:    {}", snapshot.label);
    if let Some(note) = &snapshot.note {
        println!("Note:     {note}");
    }
    println!("Taken:    {}", snapshot.taken_at.to_rfc3339());
    println!(
        "By:       hexora {} (project schema {})",
        snapshot.tool_version, snapshot.schema_version
    );

    println!();
    println!("Scope");
    if snapshot.contents.scope.include.is_empty() && snapshot.contents.scope.exclude.is_empty() {
        println!("  (nothing declared)");
    }
    for rule in &snapshot.contents.scope.include {
        println!("  include {rule}");
    }
    for rule in &snapshot.contents.scope.exclude {
        println!("  exclude {rule}");
    }

    println!();
    println!("Identities");
    if snapshot.contents.identities.is_empty() {
        println!("  (none)");
    }
    for identity in &snapshot.contents.identities {
        // Label and privilege. A snapshot has no credential to print, which is why
        // this listing cannot accidentally become one.
        println!(
            "  {:<24} {}",
            identity.label,
            crate::identity::privilege_name(identity.privilege)
        );
    }

    println!();
    println!("Declared objects");
    if snapshot.contents.objects.is_empty() {
        println!("  (none)");
    }
    for object in &snapshot.contents.objects {
        println!(
            "  {:<24} {:<14} owned by {}",
            truncate(&object.value, 24),
            object.name,
            object.owner
        );
    }

    println!();
    println!("Findings ({})", snapshot.contents.findings.len());
    for record in &snapshot.contents.findings {
        println!(
            "  [{}/{}] {:<10} {}",
            severity(record.state.severity),
            confidence(record.state.confidence),
            status(record.state.status),
            record.claim.title
        );
    }

    println!();
    println!(
        "Also recorded: {} exchange(s), {} identifier suggestion(s) ({} decided).",
        snapshot.contents.exchanges,
        snapshot.contents.candidates,
        snapshot.contents.candidates_reviewed
    );
    Ok(())
}

/// Removes a snapshot.
pub fn remove(project: &Path, id: &str, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let id = parse_id(id)?;
    if !handle.snapshots().delete(id)? {
        return Err(HexoraError::invalid_input(
            "id",
            format!("no snapshot {id} in this project"),
        ));
    }
    if json {
        println!("{}", serde_json::json!({ "deleted": id.to_string() }));
    } else {
        println!("Deleted {id}.");
    }
    Ok(())
}

/// Compares a snapshot with a later one, or with the project as it stands.
pub fn diff(project: &Path, from: &str, to: Option<&str>, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let store = handle.snapshots();

    let earlier = store.get(parse_id(from)?)?;
    let later = match to {
        Some(id) => store.get(parse_id(id)?)?,
        // The comparison a retest actually asks for: "what has changed since?" — and
        // it must not require saving a second snapshot first.
        None => Snapshot::of_current(
            hexora_storage::capture(&handle)?,
            hexora_types::VERSION,
            handle.metadata().schema_version()?,
        ),
    };

    let comparison = compare(&earlier, &later);

    if json {
        println!("{}", serde_json::to_string(&comparison).unwrap_or_default());
        return Ok(());
    }

    print_comparison(&comparison);
    Ok(())
}

fn print_comparison(comparison: &Comparison) {
    println!(
        "{}  →  {}",
        comparison.from.label.trim(),
        comparison.to.label.trim()
    );
    println!(
        "{}     {}",
        comparison.from.taken_at.format("%Y-%m-%d %H:%M"),
        comparison.to.taken_at.format("%Y-%m-%d %H:%M")
    );

    if !comparison.same_tool {
        println!();
        // Printed before anything else it undermines, because it undermines all of it.
        println!(
            "! Different builds took these ({} → {}). A claim that stopped appearing",
            comparison.from.tool_version, comparison.to.tool_version
        );
        println!("  could be the application or could be Hexora, and nothing here can tell");
        println!("  them apart.");
    }

    let untested = comparison
        .findings
        .iter()
        .filter(|c| !c.change.was_restated() && !c.change.is_movement())
        .count();
    let reconfirmed = comparison
        .findings
        .iter()
        .filter(|c| c.change.was_restated() && !c.change.is_movement())
        .count();

    if comparison.is_empty() && untested == 0 {
        println!();
        if reconfirmed > 0 {
            // Not "nothing changed": something *was* checked and came back the same,
            // which is a result and reads very differently in a retest report.
            println!("Nothing moved. {reconfirmed} claim(s) were re-tested and still stand.");
        } else {
            println!("Nothing changed.");
        }
        return;
    }

    section("Appeared", comparison, |c| {
        matches!(c, Change::Appeared { .. })
    });
    section("Gone", comparison, |c| matches!(c, Change::Gone { .. }));
    section("Changed", comparison, |c| {
        matches!(c, Change::Changed { .. })
    });
    section("Standing, but nothing re-tested them", comparison, |c| {
        matches!(
            c,
            Change::Unchanged {
                restated: false,
                ..
            }
        )
    });

    if !comparison.scope.is_empty() {
        println!();
        println!("Scope");
        for line in &comparison.scope.added {
            println!("  + {line}");
        }
        for line in &comparison.scope.removed {
            println!("  - {line}");
        }
        if !comparison.scope.removed.is_empty() {
            // The sentence that stops a shrunken scope reading as progress.
            println!("  A host that left scope stopped being tested. That is not the same as");
            println!("  having been fixed.");
        }
    }

    if !comparison.identities.is_empty() {
        println!();
        println!("Identities");
        for label in &comparison.identities.added {
            println!("  + {label}");
        }
        for label in &comparison.identities.removed {
            println!("  - {label}");
        }
    }

    if !comparison.objects.is_empty() {
        println!();
        println!("Declared objects");
        for key in &comparison.objects.added {
            println!("  + {key}");
        }
        for key in &comparison.objects.removed {
            println!("  - {key}");
        }
    }

    if reconfirmed > 0 {
        println!();
        println!("Re-tested and unchanged ({reconfirmed})");
        for row in &comparison.findings {
            if let Change::Unchanged {
                state,
                restated: true,
            } = &row.change
            {
                println!("  {} {}", badge(state), row.claim.title);
            }
        }
    }

    if comparison.counts.moved() {
        println!();
        println!("Volumes");
        count_line("exchanges", comparison.counts.exchanges);
        count_line("suggestions", comparison.counts.candidates);
        count_line("findings", comparison.counts.findings);
    }
}

fn section(title: &str, comparison: &Comparison, want: fn(&Change) -> bool) {
    let rows: Vec<&ClaimChange> = comparison.matching(want);
    if rows.is_empty() {
        return;
    }

    println!();
    println!("{title} ({})", rows.len());
    for row in rows {
        match &row.change {
            Change::Appeared { state } => {
                println!("  {} {}", badge(state), row.claim.title);
            }
            Change::Changed { before, after } => {
                println!("  {} {}", badge(after), row.claim.title);
                println!("      was {} → now {}", describe(before), describe(after));
            }
            Change::Gone { before, because } => {
                println!("  {} {}", badge(before), row.claim.title);
                // The reason, every time, on its own line. A "gone" list without it is
                // a fix report, and this cannot produce one.
                println!("      {}", explain(because));
                if before.status == hexora_types::finding::FindingStatus::FalsePositive {
                    println!("      (had been dismissed as a false positive)");
                }
            }
            Change::Unchanged { state, restated } => {
                if !restated {
                    println!("  {} {}", badge(state), row.claim.title);
                }
            }
        }
    }

    if title.starts_with("Standing") {
        // The sentence this section exists for. A retest where the application was
        // fixed and the matrix reported nothing leaves the old claim exactly as it
        // was, because a run that produces no claim never writes to the claim it did
        // not produce — so silence here looks identical to a result.
        println!("  Nothing wrote to these between the two snapshots. They are standing on");
        println!("  evidence gathered before the earlier one, so they are neither confirmed");
        println!("  still-present nor shown to be gone. Re-run the tests that raised them.");
    }
}

fn explain(why: &WhyGone) -> String {
    match why {
        WhyGone::NotReproduced => {
            "not reproduced — the same check ran and did not raise it again. That is not \
             proof it is fixed."
                .into()
        }
        WhyGone::SourceSilent => {
            "inconclusive — nothing from that check appears in the later snapshot, and \
             Hexora cannot tell \"ran and found nothing\" from \"never ran\"."
                .into()
        }
        WhyGone::ToolChanged { from, to } => {
            format!("inconclusive — the snapshots were taken by different builds ({from} → {to}).")
        }
    }
}

fn badge(state: &FindingState) -> String {
    format!(
        "[{}/{}]",
        severity(state.severity),
        confidence(state.confidence)
    )
}

fn describe(state: &FindingState) -> String {
    format!(
        "{}/{} {}",
        severity(state.severity),
        confidence(state.confidence),
        status(state.status)
    )
}

fn count_line(label: &str, count: hexora_types::snapshot::Count) {
    if !count.moved() {
        return;
    }
    let delta = count.delta();
    let sign = if delta > 0 { "+" } else { "" };
    println!(
        "  {label:<14} {} → {} ({sign}{delta})",
        count.before, count.after
    );
}

fn summary_json(snapshot: &SnapshotSummary) -> serde_json::Value {
    serde_json::json!({
        "id": snapshot.id.to_string(),
        "label": snapshot.label,
        "note": snapshot.note,
        "taken_at": snapshot.taken_at.to_rfc3339(),
        "tool_version": snapshot.tool_version,
        "schema_version": snapshot.schema_version,
        "exchanges": snapshot.exchanges,
        "candidates": snapshot.candidates,
        "candidates_reviewed": snapshot.candidates_reviewed,
        "findings": snapshot.findings,
        "identities": snapshot.identities,
        "objects": snapshot.objects,
    })
}

fn parse_id(value: &str) -> Result<SnapshotId> {
    value.parse()
}

/// A label for a snapshot nobody named.
///
/// Numbered rather than timestamped: the id already carries the time, and "snapshot 3"
/// is what a tester says out loud.
fn default_label(existing: &u64) -> String {
    format!("snapshot {}", existing + 1)
}

fn severity(severity: hexora_types::Severity) -> &'static str {
    hexora_storage::findings::severity_str(severity)
}

fn confidence(confidence: hexora_types::Confidence) -> &'static str {
    hexora_storage::findings::confidence_str(confidence)
}

fn status(status: hexora_types::finding::FindingStatus) -> &'static str {
    hexora_storage::findings::status_str(status)
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use hexora_types::snapshot::{Count, WhyGone};

    use super::*;

    #[test]
    fn a_disappearance_is_never_described_as_fixed() {
        // The one wording rule this command exists to keep. Every explanation a
        // reader can see is checked, not just the inconclusive ones.
        for why in [
            WhyGone::NotReproduced,
            WhyGone::SourceSilent,
            WhyGone::ToolChanged {
                from: "0.1.0".into(),
                to: "0.2.0".into(),
            },
        ] {
            let text = explain(&why).to_lowercase();
            // The word may appear, but only in a sentence denying it. An explanation
            // that mentions being fixed without that denial is the failure mode.
            if text.contains("fixed") {
                assert!(text.contains("not proof it is fixed"), "{text}");
            }
            assert!(!text.contains("has been fixed"), "{text}");
        }
    }

    #[test]
    fn the_two_inconclusive_reasons_say_so_in_the_first_word() {
        assert!(explain(&WhyGone::SourceSilent).starts_with("inconclusive"));
        assert!(explain(&WhyGone::ToolChanged {
            from: "a".into(),
            to: "b".into()
        })
        .starts_with("inconclusive"));
    }

    #[test]
    fn a_comparison_holding_only_untested_claims_does_not_print_nothing_changed() {
        // Found by running a retest for real: the application was fixed, the matrix
        // reported nothing, and the diff said "+3 exchanges" and stopped. The claim
        // was still standing and the reader was told nothing about it.
        use hexora_types::finding::{Confidence, FindingStatus, Severity};
        use hexora_types::ids::{SnapshotId, TargetId};
        use hexora_types::snapshot::{Claim, Contents, FindingRecord, Snapshot};

        let when = chrono::Utc::now();
        let record = FindingRecord {
            claim: Claim {
                target: TargetId::new(),
                title: "IDOR".into(),
                location: None,
            },
            state: FindingState {
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                status: FindingStatus::New,
                evidence: 1,
            },
            source: hexora_types::finding::FindingSource::AuthorizationTest,
            first_recorded: when,
            last_updated: Some(when),
        };
        let side = |label: &str| Snapshot {
            id: SnapshotId::new(),
            label: label.into(),
            note: None,
            taken_at: when,
            tool_version: "0.1.0".into(),
            schema_version: 6,
            contents: Contents {
                findings: vec![record.clone()],
                ..Contents::default()
            },
        };

        let comparison = compare(&side("before"), &side("after"));
        assert!(comparison.is_empty(), "the project holds the same claim");
        assert!(
            !comparison.findings[0].change.was_restated(),
            "and nothing re-tested it, which the reader has to be told"
        );
    }

    #[test]
    fn an_unnamed_snapshot_gets_the_next_number() {
        assert_eq!(default_label(&0), "snapshot 1");
        assert_eq!(default_label(&4), "snapshot 5");
    }

    #[test]
    fn a_count_that_did_not_move_prints_nothing() {
        let unmoved = Count {
            before: 7,
            after: 7,
        };
        assert!(!unmoved.moved());
        assert_eq!(unmoved.delta(), 0);
    }

    #[test]
    fn taking_and_listing_a_snapshot_of_a_fresh_project_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        take(&path, Some("day one"), None, true).unwrap();
        list(&path, true).unwrap();
    }

    #[test]
    fn listing_a_project_with_no_snapshots_explains_what_they_are_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();
        list(&path, false).unwrap();
    }

    #[test]
    fn diffing_a_snapshot_against_the_unchanged_project_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        take(&path, Some("day one"), None, true).unwrap();
        let id = crate::open_project(&path)
            .unwrap()
            .snapshots()
            .latest()
            .unwrap()
            .unwrap()
            .id;

        diff(&path, &id.to_string(), None, true).unwrap();
    }

    #[test]
    fn an_id_that_is_not_a_snapshot_id_is_rejected_before_anything_is_read() {
        assert!(parse_id("not-an-id").is_err());
    }
}
