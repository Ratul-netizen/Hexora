//! Turning a matrix into findings somebody can defend.
//!
//! A run produces outcomes. This module decides which of them are worth putting in a
//! report, how firmly each may be stated, and what evidence goes with it — and the
//! rules are deliberately conservative, because the failure mode that destroys trust
//! in a security tool is not a missed bug, it is a confident wrong one.
//!
//! # The confidence ladder, applied
//!
//! | What the run saw | Confidence |
//! | ---------------- | ---------- |
//! | Another identity got a response of the same shape | [`Confidence::Tentative`] |
//! | The owner's own object identifier appeared in that response | [`Confidence::Firm`] |
//! | Either of the above, reproduced by a second replay | [`Confidence::Confirmed`] |
//!
//! Nothing here can produce [`Confidence::Confirmed`] without `--verify` having
//! actually re-sent the request, and nothing produces [`Confidence::Firm`] from a
//! similarity score alone. A score says "the same kind of document came back"; only a
//! declared object identifier says "this is the other person's data".
//!
//! # Severity
//!
//! Severity answers "how bad is this for this application", which a tool cannot fully
//! know. What it can do is not flatten the distinction between an anonymous stranger
//! reading a record and a logged-in peer reading it, so:
//!
//! * unauthenticated access to a resource that needs a session — **High**
//! * a peer or lower-privileged identity reading another's object — **High** when an
//!   identifier confirms it, **Medium** on shape alone
//!
//! Nothing is emitted at Critical. Critical is a judgement about blast radius —
//! how many records, whose, and how easily enumerated — and that is the tester's call
//! after looking at the endpoint, not a matrix's call after looking at one object.

use chrono::Utc;
use hexora_types::finding::{
    Confidence, Evidence, Finding, FindingSource, FindingStatus, Location, MessagePart, Severity,
};
use hexora_types::identity::PrivilegeLevel;
use hexora_types::ids::{FindingId, TargetId};
use hexora_types::object::ObjectLocation;

use crate::construct::{Attempt, Construction};
use crate::{Cell, Matrix, Outcome, Verdict};

/// The longest excerpt quoted as evidence from a response body.
///
/// Long enough to show the leaked value in context, short enough that a report does
/// not carry a copy of somebody's personal data around with it.
const EXCERPT_LEN: usize = 160;

/// Builds the findings a matrix supports, most severe first.
///
/// Returns an empty vector for a clean run — which is the common and welcome case, and
/// is reported as such rather than padded with informational noise.
pub fn findings(matrix: &Matrix, target: TargetId) -> Vec<Finding> {
    let mut findings: Vec<Finding> = matrix
        .cells
        .iter()
        .filter(|cell| cell.verdict == Verdict::Violation)
        .filter_map(|cell| finding_for(matrix, cell, target))
        .collect();

    findings.sort_by_key(|finding| {
        (
            finding.severity.rank(),
            std::cmp::Reverse(finding.confidence),
        )
    });
    findings
}

fn finding_for(matrix: &Matrix, cell: &Cell, target: TargetId) -> Option<Finding> {
    // A violation with no stored request cannot be cited, and an uncitable finding is
    // exactly what this crate exists not to produce.
    let variant = cell.request?;
    let baseline = matrix.owner.request?;

    let unauthenticated = cell.privilege == PrivilegeLevel::Anonymous;
    let leaked = !cell.leaked_object_ids.is_empty();

    let confidence = match (cell.reproduced, leaked) {
        (true, _) => Confidence::Confirmed,
        (false, true) => Confidence::Firm,
        (false, false) => Confidence::Tentative,
    };

    let severity = if unauthenticated || leaked {
        Severity::High
    } else {
        Severity::Medium
    };

    let difference = if leaked {
        format!(
            "{} received the same resource as {}, including {} that belongs to {}",
            cell.label,
            matrix.owner.label,
            cell.leaked_object_ids.join(", "),
            matrix.owner.label,
        )
    } else {
        format!(
            "{} received a response {:.0}% alike the one served to {} (status {})",
            cell.label,
            cell.similarity * 100.0,
            matrix.owner.label,
            cell.status.unwrap_or(0),
        )
    };

    let mut evidence = vec![Evidence::Comparison {
        baseline,
        variant,
        difference: difference.clone(),
    }];
    if leaked {
        // Cited as the exchange rather than as a `ResponseExcerpt`: the excerpt
        // variant wants a `ResponseId`, and the only honest way to supply one is to
        // read it back from the project. Minting an id that resembles the request's
        // would put a reference in a report that resolves to nothing.
        evidence.push(Evidence::Exchange {
            request: variant,
            response: None,
            note: format!(
                "the response body contains {}, declared as belonging to {}",
                excerpt(&cell.leaked_object_ids),
                matrix.owner.label
            ),
        });
    }

    let title = if unauthenticated {
        format!(
            "Unauthenticated access to {} {}",
            matrix.method,
            path_of(&matrix.url)
        )
    } else {
        format!(
            "Broken object-level authorization in {} {}",
            matrix.method,
            path_of(&matrix.url)
        )
    };

    let description = if unauthenticated {
        format!(
            "{} was replayed with no credentials at all and returned the same resource \
             that {} receives. The endpoint does not require the session it appears to.",
            matrix.url, matrix.owner.label,
        )
    } else {
        format!(
            "{} was replayed as {} ({}), an identity that should not be able to reach \
             {}'s object, and the application served it anyway.",
            matrix.url,
            cell.label,
            privilege_name(cell.privilege),
            matrix.owner.label,
        )
    };

    let now = Utc::now();
    let finding = Finding {
        id: FindingId::new(),
        target,
        title,
        severity,
        confidence,
        location: Some(Location {
            part: MessagePart::Path,
            name: path_of(&matrix.url),
        }),
        description,
        impact: impact(unauthenticated, leaked),
        remediation: REMEDIATION.into(),
        reproduction: reproduction(matrix, cell),
        evidence,
        cwe: Some(
            if unauthenticated {
                "CWE-306"
            } else {
                "CWE-639"
            }
            .into(),
        ),
        owasp: Some(
            if unauthenticated {
                "API5:2023 Broken Function Level Authorization"
            } else {
                "API1:2023 Broken Object Level Authorization"
            }
            .into(),
        ),
        // Left unset on purpose. A CVSS vector implies somebody weighed scope, blast
        // radius and the data involved; inventing one here would put a number in a
        // report that nobody had actually thought about.
        cvss: None,
        source: FindingSource::AuthorizationTest,
        created_at: now,
        updated_at: now,
        status: FindingStatus::New,
    };

    // The model's own rule, enforced rather than trusted: nothing above Reported
    // without evidence, nothing actionable without reproduction steps.
    debug_assert!(finding.validate().is_ok(), "{:?}", finding.validate());
    Some(finding)
}

/// Builds the findings a construction run supports, most severe first.
///
/// Two kinds come out of it, and keeping them apart is the point:
///
/// * A **violation** — an identity received an object it does not own. Firm when the
///   response carried identifiers the caller never sent, Confirmed when a second
///   attempt reproduced it, Tentative when the only evidence is that the response
///   quotes the identifier and looks like the caller's own document.
/// * A **lead** — the response looked exactly like the object document and contained
///   nothing that says whose object it is. That is worth a tester's time and is not a
///   claim, so it comes out at [`Confidence::Tentative`] with a title that says so.
///
/// Anything the application refused, redirected, or answered with the caller's own
/// data produces nothing at all. A run against a correctly built endpoint should be
/// silent, and a tool that fills that silence with informational rows is a tool people
/// stop reading.
pub fn construction_findings(construction: &Construction, target: TargetId) -> Vec<Finding> {
    let mut findings: Vec<Finding> = construction
        .attempts
        .iter()
        .filter_map(|attempt| finding_for_attempt(construction, attempt, target))
        .collect();

    findings.sort_by_key(|finding| {
        (
            finding.severity.rank(),
            std::cmp::Reverse(finding.confidence),
        )
    });
    findings
}

fn finding_for_attempt(
    construction: &Construction,
    attempt: &Attempt,
    target: TargetId,
) -> Option<Finding> {
    // An attempt with no stored request cannot be cited, and an uncitable finding is
    // exactly what this crate exists not to produce.
    let variant = attempt.request?;
    let baseline = attempt.control?;

    let disclosed = !attempt.disclosed_object_ids.is_empty();
    let unidentified = attempt.verdict == Verdict::Inconclusive;
    if !attempt.is_violation() && !(unidentified && attempt.outcome == Outcome::Allowed) {
        return None;
    }

    // The verdict has already done the hard part. A violation means the response
    // either carried identifiers the caller never sent, or quoted the one it asked
    // for inside a document shaped like the caller's own — both are facts about the
    // bytes, so both are Firm. A second attempt that reproduces it makes it Confirmed.
    // Everything else that gets this far is the shape-only case, which is a lead.
    let confidence = match (attempt.reproduced, attempt.is_violation()) {
        (true, true) => Confidence::Confirmed,
        (_, true) => Confidence::Firm,
        (_, false) => Confidence::Tentative,
    };

    let severity = if attempt.is_violation() {
        Severity::High
    } else {
        Severity::Medium
    };

    let title = if attempt.is_violation() {
        format!(
            "{} can reach {}'s {} {} in {} {}",
            attempt.sender_label,
            attempt.owner_label,
            attempt.object_name,
            attempt.object_value,
            construction.method,
            path_of(&construction.url),
        )
    } else {
        format!(
            "Unproven cross-identity access to {} {} in {} {}",
            attempt.object_name,
            attempt.object_value,
            construction.method,
            path_of(&construction.url),
        )
    };

    let difference = if disclosed {
        format!(
            "{} asked for {}, declared as {}'s, and received a response containing {}",
            attempt.sender_label,
            attempt.object_value,
            attempt.owner_label,
            attempt.disclosed_object_ids.join(", "),
        )
    } else if attempt.echoed {
        format!(
            "{} asked for {}, declared as {}'s, and received a response {:.0}% alike \
             the document it receives for its own object, quoting that identifier",
            attempt.sender_label,
            attempt.object_value,
            attempt.owner_label,
            attempt.similarity * 100.0,
        )
    } else {
        format!(
            "{} asked for {}, declared as {}'s, and received a response {:.0}% alike \
             the document it receives for its own object — but nothing in it \
             establishes whose object it is",
            attempt.sender_label,
            attempt.object_value,
            attempt.owner_label,
            attempt.similarity * 100.0,
        )
    };

    let mut evidence = vec![Evidence::Comparison {
        baseline,
        variant,
        difference: difference.clone(),
    }];
    if disclosed {
        evidence.push(Evidence::Exchange {
            request: variant,
            response: None,
            note: format!(
                "the response body contains {}, declared as belonging to {} and never \
                 sent by {}",
                excerpt(&attempt.disclosed_object_ids),
                attempt.owner_label,
                attempt.sender_label,
            ),
        });
    }

    let description = format!(
        "This request was not captured; it was constructed. {} was taken from the \
         captured request and replaced with {}, which the tester declared as {}'s, and \
         the result was sent as {}. {}",
        attempt.original_value,
        attempt.object_value,
        attempt.owner_label,
        attempt.sender_label,
        if attempt.is_violation() {
            "The application served it."
        } else {
            "What the application served cannot be attributed to either principal."
        },
    );

    let now = Utc::now();
    let finding = Finding {
        id: FindingId::new(),
        target,
        title,
        severity,
        confidence,
        location: Some(Location {
            part: message_part(&attempt.location),
            name: attempt.location.describe(),
        }),
        description,
        impact: construction_impact(attempt, disclosed),
        remediation: REMEDIATION.into(),
        reproduction: construction_reproduction(construction, attempt),
        evidence,
        cwe: Some("CWE-639".into()),
        owasp: Some("API1:2023 Broken Object Level Authorization".into()),
        // Left unset deliberately; see the note on the replay path.
        cvss: None,
        source: FindingSource::AuthorizationTest,
        created_at: now,
        updated_at: now,
        status: FindingStatus::New,
    };

    debug_assert!(finding.validate().is_ok(), "{:?}", finding.validate());
    Some(finding)
}

fn construction_impact(attempt: &Attempt, disclosed: bool) -> String {
    if !attempt.is_violation() {
        return format!(
            "Unknown, and that is the finding: {} received a document of exactly the \
             shape it receives for its own {}, in answer to a request for somebody \
             else's. Declaring more of {}'s objects would settle whether this is a \
             disclosure or an empty template.",
            attempt.sender_label, attempt.object_name, attempt.owner_label,
        );
    }

    let mut impact = format!(
        "Any principal that can reach this endpoint can read another principal's {} by \
         putting its identifier in the request.",
        attempt.object_name
    );
    if disclosed {
        impact.push_str(
            " The response carried identifiers the caller never sent and that the \
             tester had declared as the other principal's, so this is a disclosure of \
             that principal's data rather than only a difference in behaviour.",
        );
    }
    impact
}

fn construction_reproduction(construction: &Construction, attempt: &Attempt) -> String {
    format!(
        "1. Send {} as {} — the unmodified request, recorded as {}.\n\
         2. Replace {} with {} ({}), and send that as {} — recorded as {}.\n\
         3. Compare the two responses: `hexora repeat <project> {} --diff {}`.\n\
         The second response answers a request for an object {} does not own.",
        construction.url,
        attempt.sender_label,
        attempt.control.map(|r| r.to_string()).unwrap_or_default(),
        attempt.original_value,
        attempt.object_value,
        attempt.location.describe(),
        attempt.sender_label,
        attempt.request.map(|r| r.to_string()).unwrap_or_default(),
        attempt.control.map(|r| r.to_string()).unwrap_or_default(),
        attempt.request.map(|r| r.to_string()).unwrap_or_default(),
        attempt.sender_label,
    )
}

/// Which part of the message a substitution touched.
fn message_part(location: &ObjectLocation) -> MessagePart {
    match location {
        ObjectLocation::PathSegment { .. } => MessagePart::Path,
        ObjectLocation::Query { .. } => MessagePart::Query,
        ObjectLocation::Header { .. } => MessagePart::Header,
        ObjectLocation::Body { .. } => MessagePart::Body,
        // Never reached from an attempt — a run resolves `Anywhere` to a concrete
        // place before it sends anything — but a finding with no location at all
        // would be worse than one that says "the path".
        ObjectLocation::Anywhere => MessagePart::Path,
    }
}

const REMEDIATION: &str = "Enforce the authorization check on the server for every \
    request, deriving the acting principal from the session rather than from a \
    parameter the client controls. Object lookups should be scoped to the authenticated \
    principal in the query itself, so an object belonging to somebody else is never \
    loaded to be checked afterwards.";

fn impact(unauthenticated: bool, leaked: bool) -> String {
    let mut impact = if unauthenticated {
        "Anyone who can reach the application can read this resource without \
         authenticating."
            .to_string()
    } else {
        "An ordinary user of the application can read another user's object by \
         addressing it directly."
            .to_string()
    };
    if leaked {
        impact.push_str(
            " The response carried an identifier the tester had declared as belonging \
             to the other principal, so this is a disclosure of that principal's data \
             rather than only a difference in behaviour.",
        );
    }
    impact
}

fn reproduction(matrix: &Matrix, cell: &Cell) -> String {
    format!(
        "1. Send {} as {} — recorded as {}.\n\
         2. Send the same request as {} — recorded as {}.\n\
         3. Compare the two responses: `hexora repeat <project> {} --diff {}`.\n\
         The second identity's response is the first identity's resource.",
        matrix.url,
        matrix.owner.label,
        matrix
            .owner
            .request
            .map(|r| r.to_string())
            .unwrap_or_default(),
        cell.label,
        cell.request.map(|r| r.to_string()).unwrap_or_default(),
        matrix
            .owner
            .request
            .map(|r| r.to_string())
            .unwrap_or_default(),
        cell.request.map(|r| r.to_string()).unwrap_or_default(),
    )
}

fn excerpt(leaked: &[String]) -> String {
    let joined = leaked.join(", ");
    if joined.len() <= EXCERPT_LEN {
        joined
    } else {
        format!("{}…", &joined[..EXCERPT_LEN])
    }
}

fn privilege_name(privilege: PrivilegeLevel) -> &'static str {
    match privilege {
        PrivilegeLevel::Anonymous => "unauthenticated",
        PrivilegeLevel::User => "ordinary user",
        PrivilegeLevel::Elevated => "elevated role",
        PrivilegeLevel::Administrator => "administrator",
    }
}

/// The path part of an absolute URL, for a title that fits on one line.
fn path_of(url: &str) -> String {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
        .unwrap_or_else(|| "/".to_string())
}

#[cfg(test)]
mod tests {
    use hexora_types::ids::{IdentityId, RequestId};

    use super::*;
    use crate::Outcome;

    fn cell(label: &str, privilege: PrivilegeLevel, verdict: Verdict) -> Cell {
        Cell {
            identity: IdentityId::new(),
            label: label.into(),
            privilege,
            request: Some(RequestId::new()),
            status: Some(200),
            similarity: 0.98,
            outcome: Outcome::Allowed,
            verdict,
            leaked_object_ids: Vec::new(),
            own_object_ids: Vec::new(),
            reproduced: false,
            error: None,
            note: None,
        }
    }

    fn matrix(cells: Vec<Cell>) -> Matrix {
        Matrix {
            base: RequestId::new(),
            method: "GET".into(),
            url: "https://api.example.com/accounts/acct-1000".into(),
            owner: cell("User A", PrivilegeLevel::User, Verdict::Expected),
            cells,
            appears_public: false,
        }
    }

    #[test]
    fn a_clean_run_produces_nothing() {
        let matrix = matrix(vec![cell(
            "User B",
            PrivilegeLevel::User,
            Verdict::Expected,
        )]);
        assert!(findings(&matrix, TargetId::new()).is_empty());
    }

    #[test]
    fn a_similarity_only_violation_is_never_stated_above_tentative() {
        let matrix = matrix(vec![cell(
            "User B",
            PrivilegeLevel::User,
            Verdict::Violation,
        )]);
        let findings = findings(&matrix, TargetId::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Tentative);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(!findings[0].confidence.is_actionable());
    }

    #[test]
    fn a_leaked_identifier_raises_confidence_and_severity() {
        let mut violating = cell("User B", PrivilegeLevel::User, Verdict::Violation);
        violating.leaked_object_ids = vec!["acct-1000".into()];
        let findings = findings(&matrix(vec![violating]), TargetId::new());

        assert_eq!(findings[0].confidence, Confidence::Firm);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Exchange { .. })));
    }

    #[test]
    fn only_a_reproduced_violation_reaches_confirmed() {
        let mut violating = cell("User B", PrivilegeLevel::User, Verdict::Violation);
        violating.reproduced = true;
        let findings = findings(&matrix(vec![violating]), TargetId::new());
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn an_unauthenticated_violation_is_reported_as_missing_authentication() {
        let violating = cell("Anonymous", PrivilegeLevel::Anonymous, Verdict::Violation);
        let findings = findings(&matrix(vec![violating]), TargetId::new());

        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-306"));
        assert!(findings[0].title.starts_with("Unauthenticated access"));
    }

    #[test]
    fn every_finding_carries_evidence_that_points_at_stored_traffic() {
        let violating = cell("User B", PrivilegeLevel::User, Verdict::Violation);
        let matrix = matrix(vec![violating]);
        let findings = findings(&matrix, TargetId::new());

        match &findings[0].evidence[0] {
            Evidence::Comparison {
                baseline, variant, ..
            } => {
                assert_eq!(*baseline, matrix.owner.request.unwrap());
                assert_eq!(*variant, matrix.cells[0].request.unwrap());
            }
            other => panic!("the first evidence must be the comparison: {other:?}"),
        }
    }

    #[test]
    fn every_finding_passes_the_models_own_validation() {
        let mut leaked = cell("User B", PrivilegeLevel::User, Verdict::Violation);
        leaked.leaked_object_ids = vec!["acct-1000".into()];
        let mut reproduced = cell("User C", PrivilegeLevel::User, Verdict::Violation);
        reproduced.reproduced = true;

        for finding in findings(
            &matrix(vec![
                cell("User B", PrivilegeLevel::User, Verdict::Violation),
                leaked,
                reproduced,
                cell("Anonymous", PrivilegeLevel::Anonymous, Verdict::Violation),
            ]),
            TargetId::new(),
        ) {
            assert!(finding.validate().is_ok(), "{:?}", finding.validate());
        }
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let mut leaked = cell("User C", PrivilegeLevel::User, Verdict::Violation);
        leaked.leaked_object_ids = vec!["acct-1000".into()];

        let findings = findings(
            &matrix(vec![
                cell("User B", PrivilegeLevel::User, Verdict::Violation),
                leaked,
            ]),
            TargetId::new(),
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn a_violation_that_was_never_recorded_is_dropped_rather_than_cited() {
        let mut violating = cell("User B", PrivilegeLevel::User, Verdict::Violation);
        violating.request = None;
        assert!(findings(&matrix(vec![violating]), TargetId::new()).is_empty());
    }

    #[test]
    fn nothing_is_emitted_at_critical() {
        let mut leaked = cell("Anonymous", PrivilegeLevel::Anonymous, Verdict::Violation);
        leaked.leaked_object_ids = vec!["acct-1000".into()];
        leaked.reproduced = true;
        let findings = findings(&matrix(vec![leaked]), TargetId::new());
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn a_url_without_a_path_still_produces_a_location() {
        assert_eq!(path_of("https://api.example.com"), "/");
        assert_eq!(path_of("https://api.example.com/a/b?c=1"), "/a/b?c=1");
    }
}
