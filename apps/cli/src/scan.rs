//! `hexora scan passive` — what the checks saw in traffic already captured.
//!
//! Sends nothing. The subcommand is spelled out rather than implied because the
//! difference between a pass that reads a project and a pass that puts traffic on
//! somebody's system is the most important thing about a scanner, and burying it in a
//! flag would make it easy to get wrong.
//!
//! # What the output says, and does not
//!
//! Three counts, kept apart on purpose:
//!
//! ```text
//! Observations   facts about the traffic
//! Hypotheses     suspicions that need an experiment, which this did not run
//! Findings       observations worth reporting — every one a lead, never more
//! ```
//!
//! A detector that produced nothing is printed saying so. **Silence must never mean
//! "the scanner did not run"**, which is the whole reason the run is recorded.

use std::path::Path;

use hexora_scan::passive::{scan, Selection, Summary};
use hexora_storage::Recorded;
use hexora_types::Result;

/// Options for `hexora scan passive`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// Only this detector, by id.
    pub detector: Option<&'a str>,
    /// Only this host.
    pub host: Option<&'a str>,
    /// Only traffic captured at or after this RFC 3339 instant.
    pub since: Option<&'a str>,
    /// Stop after this many exchanges.
    pub limit: Option<u32>,
    /// Read out-of-scope traffic too.
    pub everything: bool,
    /// Do not write the findings into the project.
    pub no_save: bool,
    pub json: bool,
}

/// Runs every passive check over the project's traffic.
pub fn passive(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;

    if let Some(detector) = args.detector {
        let registry = crate::detectors::registry();
        if registry.find(detector).is_none() {
            return Err(hexora_types::HexoraError::invalid_input(
                "--detector",
                format!(
                    "no check called {detector:?}. `hexora detectors` lists the ones \
                     this build has"
                ),
            ));
        }
    }

    let selection = Selection {
        host: args.host.map(str::to_string),
        detector: args.detector.map(str::to_string),
        since: args.since.map(str::to_string),
        limit: args.limit,
        everything: args.everything,
    };

    let summary = scan(&project, &selection)?;

    let saved = if args.no_save {
        Vec::new()
    } else {
        let store = project.findings();
        summary
            .findings()
            .into_iter()
            .map(|finding| Ok(store.record(finding)?))
            .collect::<Result<Vec<Recorded>>>()?
    };

    if args.json {
        print_json(&summary, &saved);
    } else {
        print_human(&summary, &saved, args.no_save);
    }
    Ok(())
}

fn print_human(summary: &Summary, saved: &[Recorded], no_save: bool) {
    println!("Exchanges analyzed: {}", summary.exchanges_read);
    if summary.exchanges_skipped > 0 {
        println!(
            "Exchanges skipped:  {} (out of scope, past the limit, or with no stored \
             response)",
            summary.exchanges_skipped
        );
    }
    println!("Detectors executed: {}", summary.detectors.len());
    println!("Observations:       {}", summary.observations.len());
    println!("Hypotheses:         {}", summary.hypotheses.len());
    println!("Findings produced:  {}", summary.findings().len());

    println!();
    println!(
        "{:<24} {:<9} {:>6} {:>6} WHAT IT SAW",
        "DETECTOR", "VERSION", "OBS", "HYP"
    );
    for detector in &summary.detectors {
        // A detector with nothing to say still gets a row. Silence has to be a fact
        // rather than an absence, or a retest cannot tell it from "never ran".
        println!(
            "{:<24} {:<9} {:>6} {:>6} {}",
            detector.detector,
            detector.version,
            detector.observations,
            detector.hypotheses,
            if detector.observations == 0 && detector.hypotheses == 0 {
                "nothing"
            } else {
                ""
            }
        );
    }

    if !summary.observations.is_empty() {
        println!();
        println!("Observations");
        for group in &summary.observations {
            let seen = if group.occurrences > 1 {
                format!(" ×{}", group.occurrences)
            } else {
                String::new()
            };
            println!(
                "  [{}]{} {}{}",
                severity_word(group.observation.severity),
                if group.observation.is_reportable() {
                    ""
                } else {
                    " context"
                },
                group.observation.about,
                seen
            );
        }
    }

    if !summary.hypotheses.is_empty() {
        println!();
        println!("Hypotheses ({})", summary.hypotheses.len());
        for hypothesis in &summary.hypotheses {
            println!("  {} — {}", hypothesis.detector, hypothesis.claim);
        }
        // The sentence that keeps a suspicion from being read as a result.
        println!();
        println!("  These are suspicions, not results. Settling one needs a request");
        println!("  this pass did not make, so none of them is a finding and none of");
        println!("  them is in the project.");
    }

    println!();
    if summary.findings().is_empty() {
        println!("No findings. Every observation above was context rather than an issue.");
    } else if no_save {
        println!(
            "{} finding(s), not written to the project (--no-save).",
            summary.findings().len()
        );
    } else {
        let new = saved.iter().filter(|r| r.is_new()).count();
        println!(
            "Recorded {} finding(s): {new} new, {} refreshed.",
            saved.len(),
            saved.len() - new
        );
    }

    println!();
    // Said once, at the end, because it is the thing most likely to be misread.
    println!("Every passive finding is a lead: it says what was seen, not that the");
    println!("application is exploitable. Read them with `hexora findings <project>`.");
}

fn print_json(summary: &Summary, saved: &[Recorded]) {
    let payload = serde_json::json!({
        "exchanges_analyzed": summary.exchanges_read,
        "exchanges_skipped": summary.exchanges_skipped,
        "run": summary.run.as_ref().map(|run| serde_json::json!({
            "id": run.id.to_string(),
            "selection": run.selection,
            "started_at": run.started_at.to_rfc3339(),
            "completed_at": run.completed_at.map(|at| at.to_rfc3339()),
            "status": run.status.as_str(),
        })),
        "detectors": summary.detectors.iter().map(|detector| serde_json::json!({
            "id": detector.detector,
            "version": detector.version,
            "mode": detector.mode.as_str(),
            "observations": detector.observations,
            "hypotheses": detector.hypotheses,
            "reportable": detector.reportable,
        })).collect::<Vec<_>>(),
        "observations": summary.observations.iter().map(|group| serde_json::json!({
            "detector": group.observation.detector,
            "version": group.observation.version,
            "about": group.observation.about,
            "expected": group.observation.expected,
            "observed": group.observation.observed,
            "rationale": group.observation.rationale,
            "severity": severity_word(group.observation.severity),
            "reportable": group.observation.is_reportable(),
            "host": group.host,
            "occurrences": group.occurrences,
            "exchanges": group.exchanges.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "hypotheses": summary.hypotheses.iter().map(|hypothesis| serde_json::json!({
            "detector": hypothesis.detector,
            "claim": hypothesis.claim,
            "source_request": hypothesis.source_request.to_string(),
            "provisional_severity": severity_word(hypothesis.provisional_severity),
        })).collect::<Vec<_>>(),
        "findings": summary.findings().iter().map(|f| f.finding()).collect::<Vec<_>>(),
        "recorded": saved.iter().map(|r| serde_json::json!({
            "id": r.id().to_string(),
            "new": r.is_new(),
        })).collect::<Vec<_>>(),
    });
    println!("{payload}");
}

fn severity_word(severity: hexora_types::Severity) -> &'static str {
    hexora_storage::findings::severity_str(severity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();
        (dir, path)
    }

    fn args(path: &Path) -> Args<'_> {
        Args {
            project: path,
            detector: None,
            host: None,
            since: None,
            limit: None,
            everything: false,
            no_save: false,
            json: false,
        }
    }

    #[test]
    fn scanning_an_empty_project_is_a_run_that_found_nothing() {
        let (_dir, path) = project();
        passive(args(&path)).unwrap();

        // And it is recorded as having happened, which is the distinction that makes
        // "nothing" mean something later.
        let project = crate::open_project(&path).unwrap();
        assert_eq!(project.scans().count().unwrap(), 1);
    }

    #[test]
    fn a_detector_that_does_not_exist_is_refused_before_anything_runs() {
        let (_dir, path) = project();
        let error = passive(Args {
            detector: Some("nothing.here"),
            ..args(&path)
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("hexora detectors"), "{error}");
        // Nothing ran, so nothing was recorded.
        let project = crate::open_project(&path).unwrap();
        assert_eq!(project.scans().count().unwrap(), 0);
    }

    #[test]
    fn both_output_forms_work() {
        let (_dir, path) = project();
        passive(args(&path)).unwrap();
        passive(Args {
            json: true,
            ..args(&path)
        })
        .unwrap();
    }
}
