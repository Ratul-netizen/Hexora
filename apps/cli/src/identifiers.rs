//! `hexora identifiers` — values that might be object identifiers.
//!
//! The command exists because declaring every identifier by hand is what keeps
//! constructed testing narrower than it should be. It does not exist to do the
//! declaring: everything it prints is a *suggestion*, and the wording never says
//! otherwise. A suggestion is not an object, and an object is not an ownership claim.
//!
//! Analysis reads captured traffic and writes suggestions. It sends nothing, touches
//! no stored request, and creates no finding — so it is safe to run at any point in an
//! engagement, including on a project belonging to a client who has gone home.

use std::path::Path;

use hexora_storage::{CandidateFilter, CandidateStore};
use hexora_types::candidate::CandidateStatus;
use hexora_types::ids::CandidateId;
use hexora_types::{HexoraError, Result};

/// Options for `hexora identifiers`.
pub struct ListArgs<'a> {
    pub project: &'a Path,
    /// Only suggestions in this state.
    pub status: Option<&'a str>,
    /// Re-read the project's traffic and offer what it finds.
    pub analyze: bool,
    pub json: bool,
}

/// Lists suggestions, strongest first.
pub fn list(args: ListArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = project.candidates();

    let analysis = if args.analyze {
        Some(hexora_authz::suggest::analyze(
            &project.traffic(),
            &project.objects(),
            &store,
        )?)
    } else {
        None
    };

    let filter = CandidateFilter {
        status: args.status.map(parse_status).transpose()?,
        min_score: None,
    };
    let candidates = store.list(&filter)?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "analyzed": analysis.as_ref().map(|a| serde_json::json!({
                    "exchanges": a.exchanges,
                    "created": a.created,
                    "refreshed": a.refreshed,
                    "reviewed": a.reviewed,
                    "not_offered": a.not_offered,
                })),
                "candidates": candidates,
            })
        );
        return Ok(());
    }

    if let Some(analysis) = &analysis {
        println!(
            "Read {} exchange(s): {} new suggestion(s), {} refreshed, {} left as you \
             decided them.",
            analysis.exchanges, analysis.created, analysis.refreshed, analysis.reviewed
        );
        if analysis.not_offered > 0 {
            println!(
                "{} more scored but were not offered; the strongest are listed.",
                analysis.not_offered
            );
        }
        println!();
    }

    if candidates.is_empty() {
        if analysis.is_some() {
            println!("Nothing to suggest.");
            println!();
            println!("A value is only offered when it *varies* where an identifier would:");
            println!("two requests that differ in one path segment, or one parameter.");
            println!("A single request cannot show that, so capture a little more traffic.");
        } else {
            println!("No suggestions recorded in {}.", args.project.display());
            println!();
            println!("Read the project's traffic and offer what it finds:");
            println!("  hexora identifiers {} --analyze", args.project.display());
        }
        return Ok(());
    }

    println!(
        "{:<38} {:<8} {:>6} {:<24} {:<12} WHERE",
        "ID", "STATUS", "SCORE", "VALUE", "STRENGTH"
    );
    for candidate in &candidates {
        println!(
            "{:<38} {:<8} {:>6} {:<24} {:<12} {}",
            candidate.id.to_string(),
            candidate.status.as_str(),
            candidate.score,
            truncate(&candidate.value, 24),
            candidate.strength().as_str(),
            candidate.descriptor,
        );
    }

    println!();
    println!("{} suggestion(s).", candidates.len());
    // Said once, at the bottom. It is the whole point of the command and repeating it
    // per row would make it something people scroll past.
    println!(
        "These are suggestions, not objects. Accepting one says it is an identifier; \
         it says nothing about whose."
    );
    println!(
        "  hexora identifiers {} --show <id>",
        args.project.display()
    );
    Ok(())
}

/// Prints one suggestion, with the reasons it was offered.
pub fn show(project: &Path, id: &str, json: bool) -> Result<()> {
    let handle = crate::open_project(project)?;
    let store = handle.candidates();
    let candidate_id: CandidateId = id.parse()?;
    let candidate = store.get(candidate_id)?;
    let observations = store.observations(candidate_id)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "candidate": candidate,
                "observed_in": observations.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!("Candidate: {}", candidate.id);
    println!("Value:     {}", candidate.value);
    println!("Where:     {}", candidate.descriptor);
    println!(
        "Status:    {} · {} (score {})",
        candidate.status.as_str(),
        candidate.strength().as_str(),
        candidate.score
    );

    println!();
    println!("Why it was suggested");
    for signal in &candidate.signals {
        // The sign is printed because a reason that argues *against* is as useful as
        // one that argues for, and a reader who cannot see which is which cannot
        // disagree with the total.
        println!(
            "  {:>+4}  {:<26} {}",
            signal.weight,
            signal.kind.as_str(),
            signal.detail
        );
    }
    println!("  {:>+4}  total", candidate.score);

    println!();
    let shown = observations.len().min(8);
    println!(
        "Observed in {} request(s){}",
        candidate.occurrences,
        if candidate.has_missing_traffic() {
            format!("; {} still in the project", candidate.live_observations)
        } else {
            String::new()
        }
    );
    for request in observations.iter().take(shown) {
        println!("  {request}");
    }
    if observations.len() > shown {
        println!("  … and {} more", observations.len() - shown);
    }

    println!();
    println!("This is a suggestion, not an ownership assertion.");
    if candidate.status == CandidateStatus::Proposed {
        println!("  hexora identifiers <project> --accept {}", candidate.id);
        println!("  hexora identifiers <project> --reject {}", candidate.id);
    }
    println!();
    println!("Declaring it as somebody's object is a separate, explicit step:");
    println!(
        "  hexora object add <project> {} --owner <identity> --name <what it is>",
        candidate.value
    );
    Ok(())
}

/// Records a human's decision about a suggestion.
pub fn decide(project: &Path, id: &str, status: CandidateStatus, json: bool) -> Result<()> {
    let store: CandidateStore = crate::open_project(project)?.candidates();
    let candidate_id: CandidateId = id.parse()?;
    let candidate = store.get(candidate_id)?;
    store.set_status(candidate_id, status)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": candidate_id.to_string(),
                "value": candidate.value,
                "status": status.as_str(),
            })
        );
        return Ok(());
    }

    match status {
        CandidateStatus::Accepted => {
            println!("{} is accepted as an identifier.", candidate.value);
            println!();
            // The sentence this whole milestone turns on.
            println!("That says it *is* an identifier. It says nothing about whose it is,");
            println!("and nothing has been declared. To say who owns it:");
            println!(
                "  hexora object add {} {} --owner <identity> --name <what it is>",
                project.display(),
                candidate.value
            );
        }
        CandidateStatus::Rejected => {
            println!("{} is rejected.", candidate.value);
            println!("Re-analysing the project will not offer it again.");
        }
        other => println!("{} is now {}.", candidate.value, other.as_str()),
    }
    Ok(())
}

fn parse_status(value: &str) -> Result<CandidateStatus> {
    CandidateStatus::parse(value).ok_or_else(|| {
        HexoraError::invalid_input(
            "--status",
            format!("{value:?} is not one of proposed, accepted, rejected, superseded"),
        )
    })
}

/// A short label for a table, cut at a width.
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
    use super::*;

    #[test]
    fn statuses_are_accepted_in_the_words_the_table_prints() {
        assert_eq!(parse_status("proposed").unwrap(), CandidateStatus::Proposed);
        assert_eq!(parse_status("rejected").unwrap(), CandidateStatus::Rejected);
        assert!(parse_status("maybe").is_err());
    }

    #[test]
    fn an_unknown_status_lists_the_ones_that_exist() {
        let error = parse_status("maybe").unwrap_err().to_string();
        assert!(error.contains("proposed"), "{error}");
    }

    #[test]
    fn a_long_value_is_cut_rather_than_wrapping_the_table() {
        assert_eq!(truncate("1000", 24), "1000");
        assert_eq!(truncate("aaaaaaaaaa", 5), "aaaa…");
    }

    #[test]
    fn listing_an_empty_project_explains_what_analysis_is_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        list(ListArgs {
            project: &path,
            status: None,
            analyze: false,
            json: true,
        })
        .unwrap();
    }

    #[test]
    fn analysing_a_project_with_no_traffic_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        list(ListArgs {
            project: &path,
            status: None,
            analyze: true,
            json: true,
        })
        .unwrap();
    }
}
