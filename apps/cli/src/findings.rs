//! `hexora findings` — what the project claims, and how firmly.
//!
//! The list is ordered the way a tester triages: worst first, and within a severity,
//! the ones that are actually established before the ones that are still leads. A
//! findings list that orders by discovery time makes somebody re-sort it by hand
//! before they can use it.
//!
//! Confidence is printed next to every row rather than folded into severity. They
//! answer different questions — "how bad if true" and "how sure are we" — and a tool
//! that merges them is the reason people stop believing tool output.

use std::path::Path;

use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::FindingFilter;
use hexora_types::finding::{Confidence, Evidence, Finding, FindingStatus, Severity};
use hexora_types::ids::FindingId;
use hexora_types::{HexoraError, Result};

/// Options for `hexora findings`.
pub struct ListArgs<'a> {
    pub project: &'a Path,
    /// Only findings at or above this severity.
    pub severity: Option<&'a str>,
    /// Only findings in this triage state.
    pub status: Option<&'a str>,
    /// Hide anything that is still only a lead.
    pub actionable: bool,
    pub limit: u32,
    pub after: Option<&'a str>,
    pub json: bool,
}

/// Lists findings, worst first.
pub fn list(args: ListArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let store = project.findings();

    let filter = FindingFilter {
        min_severity: args.severity.map(parse_severity).transpose()?,
        status: args.status.map(parse_status).transpose()?,
        target: None,
        actionable_only: args.actionable,
    };
    let page = store.list(
        &filter,
        args.after.map(|c| Cursor(c.to_owned())).as_ref(),
        Limit::new(args.limit),
    )?;
    let total = store.count()?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "total": total,
                "findings": page.items,
                "next": page.next.as_ref().map(|c| c.0.clone()),
            })
        );
        return Ok(());
    }

    if page.items.is_empty() {
        if total == 0 {
            println!("No findings recorded in {}.", args.project.display());
            println!();
            println!("Run an authorization matrix to produce some:");
            println!(
                "  hexora authz {} <request-id> --as-identity <who>",
                args.project.display()
            );
        } else {
            println!("No findings match that filter ({total} recorded).");
        }
        return Ok(());
    }

    println!(
        "{:<38} {:<9} {:<10} {:<15} TITLE",
        "ID", "SEVERITY", "CONFIDENCE", "STATUS"
    );
    for finding in &page.items {
        println!(
            "{:<38} {:<9} {:<10} {:<15} {}",
            finding.id.to_string(),
            severity_word(finding.severity),
            confidence_word(finding.confidence),
            status_word(finding.status),
            finding.title,
        );
    }

    println!();
    println!("{} of {total} shown", page.items.len());

    // Said once, at the bottom, rather than marked on every row: the distinction
    // matters and a repeated warning is one people learn to skip.
    let leads = page
        .items
        .iter()
        .filter(|f| !f.confidence.is_actionable())
        .count();
    if leads > 0 {
        println!(
            "{leads} of these are leads, not established issues — they need verifying \
             before they go in a report."
        );
    }
    if let Some(next) = &page.next {
        println!(
            "Next page: hexora findings {} --after {}",
            args.project.display(),
            next.0
        );
    }
    Ok(())
}

/// Prints one finding in full, evidence included.
pub fn show(project: &Path, id: &str, json: bool) -> Result<()> {
    let finding = crate::open_project(project)?.findings().get(id.parse()?)?;

    if json {
        println!("{}", serde_json::to_string(&finding).unwrap_or_default());
        return Ok(());
    }

    println!("{}", finding.title);
    println!(
        "  {} · {} · {}",
        severity_word(finding.severity),
        confidence_word(finding.confidence),
        status_word(finding.status)
    );
    if let Some(location) = &finding.location {
        println!("  location:    {:?} {}", location.part, location.name);
    }
    for (label, value) in [
        ("CWE", finding.cwe.as_deref()),
        ("OWASP", finding.owasp.as_deref()),
        ("CVSS", finding.cvss.as_deref()),
    ] {
        if let Some(value) = value {
            println!("  {label:<12} {value}");
        }
    }
    println!("  first seen:  {}", finding.created_at.to_rfc3339());
    println!("  last seen:   {}", finding.updated_at.to_rfc3339());

    println!();
    println!("{}", finding.description);
    println!();
    println!("Impact");
    println!("  {}", finding.impact);
    println!();
    println!("Remediation");
    println!("  {}", finding.remediation);
    println!();
    println!("Reproduction");
    for line in finding.reproduction.lines() {
        println!("  {line}");
    }

    println!();
    println!("Evidence ({})", finding.evidence.len());
    for evidence in &finding.evidence {
        println!("  {}", describe(evidence));
    }
    if !finding.confidence.is_actionable() {
        println!();
        println!(
            "This is a lead at {} confidence. Re-run the test with --verify to attempt \
             reproduction before reporting it.",
            confidence_word(finding.confidence)
        );
    }
    Ok(())
}

/// Changes a finding's triage state.
pub fn triage(project: &Path, id: &str, status: &str, json: bool) -> Result<()> {
    let store = crate::open_project(project)?.findings();
    let id: FindingId = id.parse()?;
    let status = parse_status(status)?;
    store.set_status(id, status)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "id": id.to_string(), "status": status_word(status) })
        );
    } else {
        println!("{id} is now {}.", status_word(status));
        if status == FindingStatus::FalsePositive {
            println!("Re-running the test that produced it will not resurrect it.");
        }
    }
    Ok(())
}

/// One line describing a piece of evidence, with the ids to go and look at.
fn describe(evidence: &Evidence) -> String {
    match evidence {
        Evidence::Exchange {
            request,
            response,
            note,
        } => match response {
            Some(response) => format!("exchange {request} → {response}: {note}"),
            None => format!("exchange {request}: {note}"),
        },
        Evidence::Comparison {
            baseline,
            variant,
            difference,
        } => format!("comparison {baseline} vs {variant}: {difference}"),
        Evidence::ResponseExcerpt {
            response,
            offset,
            excerpt,
        } => format!("excerpt from {response} at byte {offset}: {excerpt}"),
        Evidence::OutOfBand {
            request,
            interaction,
            protocol,
        } => format!("{protocol} interaction {interaction} caused by {request}"),
        Evidence::Timing {
            request,
            baseline_ms,
            variant_ms,
        } => format!("timing on {request}: baseline {baseline_ms:?}ms vs variant {variant_ms:?}ms"),
    }
}

pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

pub fn confidence_word(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Reported => "reported",
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Confirmed => "confirmed",
    }
}

pub fn status_word(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::Triaged => "triaged",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false-positive",
        FindingStatus::Duplicate => "duplicate",
        FindingStatus::Reported => "reported",
        FindingStatus::Fixed => "fixed",
        FindingStatus::Accepted => "accepted",
    }
}

/// Shared with `hexora report`, so both commands accept the same words for a level.
pub fn parse_severity(value: &str) -> Result<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        other => Err(HexoraError::invalid_input(
            "--severity",
            format!("{other:?} is not one of info, low, medium, high, critical"),
        )),
    }
}

/// Accepts the hyphenated form the CLI prints, as well as the stored form.
fn parse_status(value: &str) -> Result<FindingStatus> {
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "new" => Ok(FindingStatus::New),
        "triaged" => Ok(FindingStatus::Triaged),
        "confirmed" => Ok(FindingStatus::Confirmed),
        "false_positive" => Ok(FindingStatus::FalsePositive),
        "duplicate" => Ok(FindingStatus::Duplicate),
        "reported" => Ok(FindingStatus::Reported),
        "fixed" => Ok(FindingStatus::Fixed),
        "accepted" => Ok(FindingStatus::Accepted),
        other => Err(HexoraError::invalid_input(
            "--status",
            format!(
                "{other:?} is not one of new, triaged, confirmed, false-positive, \
                 duplicate, reported, fixed, accepted"
            ),
        )),
    }
}

/// A short summary line, for commands that mention findings in passing.
pub fn one_line(finding: &Finding) -> String {
    format!(
        "[{}/{}] {}",
        severity_word(finding.severity),
        confidence_word(finding.confidence),
        finding.title
    )
}

#[cfg(test)]
mod tests {
    use hexora_types::ids::{RequestId, ResponseId};

    use super::*;

    #[test]
    fn triage_states_are_accepted_in_the_form_the_cli_prints_them() {
        // The list prints "false-positive"; typing that back must work, or the
        // command teaches a form it then refuses.
        assert_eq!(
            parse_status("false-positive").unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(
            parse_status("false_positive").unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(parse_status("FIXED").unwrap(), FindingStatus::Fixed);
    }

    #[test]
    fn an_unknown_status_lists_the_ones_that_exist() {
        let error = parse_status("wontfix").unwrap_err().to_string();
        assert!(error.contains("false-positive"), "{error}");
    }

    #[test]
    fn severity_names_are_accepted_in_the_forms_people_type() {
        assert_eq!(parse_severity("HIGH").unwrap(), Severity::High);
        assert_eq!(parse_severity("crit").unwrap(), Severity::Critical);
        assert!(parse_severity("severe").is_err());
    }

    #[test]
    fn a_comparison_names_both_requests_so_they_can_be_opened() {
        let baseline = RequestId::new();
        let variant = RequestId::new();
        let line = describe(&Evidence::Comparison {
            baseline,
            variant,
            difference: "User B received acct-1000".into(),
        });
        assert!(line.contains(&baseline.to_string()));
        assert!(line.contains(&variant.to_string()));
        assert!(line.contains("acct-1000"));
    }

    #[test]
    fn an_exchange_without_a_response_does_not_print_a_dangling_arrow() {
        let line = describe(&Evidence::Exchange {
            request: RequestId::new(),
            response: None,
            note: "no response was received".into(),
        });
        assert!(!line.contains('→'), "{line}");
    }

    #[test]
    fn an_excerpt_says_where_in_the_body_it_came_from() {
        let line = describe(&Evidence::ResponseExcerpt {
            response: ResponseId::new(),
            offset: 412,
            excerpt: "acct-1000".into(),
        });
        assert!(line.contains("412"), "{line}");
    }
}
