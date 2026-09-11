//! The authorization checks, as a detector and a verifier.
//!
//! A run produces outcomes. Deciding which of them are worth putting in a report, and
//! how firmly each may be stated, used to happen here in one function that built a
//! `Finding` directly. It now happens in the shape every check in Hexora has:
//!
//! ```text
//! Matrix ──▶ MatrixDetector ──▶ Hypothesis ──▶ ReplayVerifier ──▶ Verification
//!                                                                     │
//!                                                          Verified ◀─┘
//! ```
//!
//! The rules are unchanged and still deliberately conservative, because the failure
//! mode that destroys trust in a security tool is not a missed bug, it is a confident
//! wrong one. What changed is where they live: the confidence ladder is no longer
//! prose applied by hand here, it is [`Verification::confidence`] in
//! [`hexora_types::verify`], which every future check climbs too.
//!
//! # The ladder, as this check uses it
//!
//! | What the run saw | Verification | Confidence |
//! | ---------------- | ------------ | ---------- |
//! | Another identity got a response of the same shape | `Supported(Consistent)` | `Tentative` |
//! | The owner's own object identifier appeared in it | `Supported(Distinctive)` | `Firm` |
//! | It was the *same document*, and anonymous was refused it | `Supported(Distinctive)` | `Firm` |
//! | A second experiment produced the same result | `Reproduced` | `Confirmed` |
//! | A second experiment did not | `Supported(Consistent)` | `Tentative` |
//!
//! The second row needs a declaration; the third does not, which is the point of it —
//! M12.10's field-by-field comparison can establish that two identities were served
//! not a document of the same *shape* but the same *document*, and that is a fact
//! about the bytes rather than a score. It is gated on the unauthenticated control
//! because two identities reading an identical *public* page looks exactly the same
//! from inside a comparison, and [`AnonymousControl::NotTried`] does not clear the
//! gate: a run that did not look has not shown anything.
//!
//! The last row is a deliberate change of behaviour. A violation that did not happen
//! again used to keep whatever confidence the first result had earned, with a note
//! attached. Two experiments that disagree cannot be "hard to explain any other way",
//! so the claim is now capped at a lead — the information is kept, the certainty is
//! not.
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

use async_trait::async_trait;
use hexora_types::finding::{Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity};
use hexora_types::identity::{Identity, PrivilegeLevel};
use hexora_types::ids::TargetId;
use hexora_types::object::ObjectLocation;
use hexora_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Verified, Writeup,
};
use hexora_types::Result;
use hexora_verify::{Detector, Lab, Verifier};

use crate::compare::Baseline;
use crate::construct::{Attempt, Construction};
use crate::{AnonymousControl, Cell, Matrix, Outcome, Verdict};

/// The check that replays one captured request as everybody.
pub const CROSS_IDENTITY: DetectorInfo = DetectorInfo {
    id: DetectorId("authz.cross_identity"),
    name: "Cross-identity access",
    version: "1.0.0",
    about: "one identity reaching a resource that belongs to another",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: true,
    // Raises its own and settles them, in one subsystem: the matrix is the first
    // experiment and `--verify` is the second. Recorded so the registry does not list
    // it among the suspicions nothing in this build can answer.
    settles: Some("authz.cross_identity"),
};

/// The check that builds the request nobody captured.
pub const CONSTRUCTED_OBJECT: DetectorInfo = DetectorInfo {
    id: DetectorId("authz.constructed_object"),
    name: "Constructed object access",
    version: "1.0.0",
    about: "a request built to ask for somebody else's declared object",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: true,
    settles: Some("authz.constructed_object"),
};

/// The longest excerpt quoted as evidence from a response body.
///
/// Long enough to show the leaked value in context, short enough that a report does
/// not carry a copy of somebody's personal data around with it.
const EXCERPT_LEN: usize = 160;

/// Raises a hypothesis for every cell the matrix judged a violation.
///
/// Cheap, and allowed to be wrong: a cell is a violation because one response looked
/// like another, which is a reason to run an experiment and not yet a reason to tell
/// anybody anything.
pub struct MatrixDetector;

impl Detector for MatrixDetector {
    type Subject = Matrix;

    fn about(&self) -> DetectorInfo {
        CROSS_IDENTITY
    }

    fn examine(&self, matrix: &Matrix) -> Vec<Hypothesis> {
        matrix
            .cells
            .iter()
            .filter(|cell| cell.verdict == Verdict::Violation)
            .filter_map(|cell| {
                // A violation with no stored request cannot be cited, and an
                // uncitable claim is exactly what this crate exists not to produce.
                let request = cell.request?;
                Some(Hypothesis {
                    detector: CROSS_IDENTITY.id.to_string(),
                    claim: format!(
                        "{} reached a resource that belongs to {}",
                        cell.label, matrix.owner.label
                    ),
                    source_request: request,
                    location: Some(Location {
                        part: MessagePart::Path,
                        name: path_of(&matrix.url),
                    }),
                    provisional_severity: severity_for(matrix, cell),
                })
            })
            .collect()
    }
}

/// What the verifier needs in order to run the cell again.
#[derive(Debug, Clone)]
pub struct CellCase {
    /// The cell the hypothesis was raised from.
    pub cell: Cell,
    /// The identity it was sent as, when the project still has it.
    pub identity: Option<Identity>,
}

/// Sends the request a second time and says whether the same thing happened.
///
/// Reproduction is what separates a lead from a claim: a one-off that does not repeat
/// was a cache, a race, or a session that had not expired yet, and a report that
/// cannot tell those apart from a real bug wastes a developer's afternoon.
///
/// With `repeat` off there is no second experiment, and the verdict rests on what the
/// first one showed — which is still an experiment, just not a repeated one.
pub struct ReplayVerifier<'a> {
    /// The request under test.
    pub draft: &'a hexora_repeater::Draft,
    /// The identity the captured request belonged to.
    pub owner: &'a Identity,
    /// The owner's response, to compare a second reply against.
    pub baseline: &'a Baseline,
    /// What an unauthenticated request established, if one was sent.
    pub control: AnonymousControl,
    /// The owner's own request, so a comparison cites both sides.
    pub owner_request: Option<hexora_types::ids::RequestId>,
    /// Whether to perform the second experiment.
    pub repeat: bool,
}

#[async_trait]
impl Verifier for ReplayVerifier<'_> {
    type Case = CellCase;

    fn about(&self) -> DetectorInfo {
        CROSS_IDENTITY
    }

    async fn verify(
        &self,
        _hypothesis: &Hypothesis,
        case: &CellCase,
        lab: &dyn Lab,
    ) -> Result<Verification> {
        let cell = &case.cell;
        let evidence = evidence_for(cell, self.owner_request, &self.owner.label);

        if !self.repeat {
            let _ = evidence;
            return Ok(judge(
                cell,
                &self.owner.label,
                self.owner_request,
                self.control,
            ));
        }

        let Some(identity) = &case.identity else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} is no longer in the project, so the result could not be re-run",
                    cell.label
                ),
            });
        };

        // Asked before sending: an out-of-scope second experiment is not a failed
        // experiment, it is one that never happened, and the two must not read alike.
        if lab.would_leave_scope(self.draft, Some(identity)) {
            return Ok(Verification::Inconclusive {
                why: "the target left the project's scope before it could be re-run".into(),
            });
        }

        let again = crate::replay_once(lab, self.draft, identity, self.owner, self.baseline).await;

        if again.outcome == cell.outcome && again.verdict == Verdict::Violation {
            Ok(Verification::Reproduced {
                note: format!(
                    "{} received {}'s resource again on a second request",
                    cell.label, self.owner.label
                ),
                evidence,
            })
        } else {
            // Not `Refuted`: the first experiment did show it. Two experiments that
            // disagree cannot support a firm claim, so this is capped at a lead
            // whatever the first one saw — including when an identifier leaked.
            Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "seen once and not again ({} the second time), so this is a lead \
                     rather than a reproduced result",
                    again.outcome.as_str()
                ),
                evidence,
            })
        }
    }
}

/// The verdict when no second experiment was run.
///
/// Separated from [`ReplayVerifier`] because it is the half that needs no network:
/// what the first experiment showed, judged. The verifier adds the second experiment
/// on top of it.
pub(crate) fn judge(
    cell: &Cell,
    owner_label: &str,
    owner_request: Option<hexora_types::ids::RequestId>,
    control: AnonymousControl,
) -> Verification {
    supported(
        cell,
        owner_label,
        control,
        evidence_for(cell, owner_request, owner_label),
    )
}

fn supported(
    cell: &Cell,
    owner_label: &str,
    control: AnonymousControl,
    evidence: Vec<Evidence>,
) -> Verification {
    if !cell.leaked_object_ids.is_empty() {
        // Not a similarity score: a declared identifier belonging to somebody else,
        // in a response served to this caller. That is a fact about the bytes.
        return Verification::Supported {
            support: Support::Distinctive,
            note: format!(
                "the response served to {} contained {}, declared as {}'s",
                cell.label,
                cell.leaked_object_ids.join(", "),
                owner_label
            ),
            evidence,
        };
    }

    // The same strength of fact, reached without a declaration. Two identities served
    // *the same document* — not a document of the same shape, the same one — is a
    // claim a reader can check field by field, which a percentage never is.
    //
    // Gated on the unauthenticated control, because the one thing that reading
    // identical is also consistent with is a public page. `NotTried` does not clear
    // that gate: a run that did not look has not shown anything.
    if control == AnonymousControl::Refused {
        if let Some(structure) = &cell.structure {
            if structure.same_document() {
                return Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "{} and {} were served the same document at every one of its \
                         {} field(s), and an unauthenticated request was refused it, \
                         so it is not a public page ({})",
                        cell.label,
                        owner_label,
                        structure.shared_paths,
                        structure.policy.describe(),
                    ),
                    evidence,
                };
            }
        }
    }

    Verification::Supported {
        support: Support::Consistent,
        note: match cell
            .structure
            .as_ref()
            .filter(|d| d.counted().next().is_some())
        {
            Some(structure) => format!(
                "{} received a response {:.0}% alike the one served to {}, differing \
                 at {}",
                cell.label,
                cell.similarity * 100.0,
                owner_label,
                structure.summary(owner_label, &cell.label),
            ),
            None => format!(
                "{} received a response {:.0}% alike the one served to {}",
                cell.label,
                cell.similarity * 100.0,
                owner_label
            ),
        },
        evidence,
    }
}

/// The traffic behind a cell.
fn evidence_for(
    cell: &Cell,
    baseline: Option<hexora_types::ids::RequestId>,
    owner_label: &str,
) -> Vec<Evidence> {
    let Some(variant) = cell.request else {
        return Vec::new();
    };

    let difference = if cell.leaked_object_ids.is_empty() {
        // A percentage is where this used to stop. The structural comparison says
        // which fields it is a percentage *of*, which is the difference between a
        // number a developer can argue with and a line they can go and look at.
        let structure = match cell.structure.as_ref() {
            Some(structure) if structure.same_document() => format!(
                " — the same document at every one of its {} field(s) ({})",
                structure.shared_paths,
                structure.policy.describe(),
            ),
            Some(structure) if structure.counted().next().is_some() => {
                format!(" — {}", structure.summary(owner_label, &cell.label))
            }
            _ => String::new(),
        };
        format!(
            "{} received a response {:.0}% alike the one served to {} (status {}){}",
            cell.label,
            cell.similarity * 100.0,
            owner_label,
            cell.status.unwrap_or(0),
            structure,
        )
    } else {
        format!(
            "{} received the same resource as {}, including {} that belongs to {}",
            cell.label,
            owner_label,
            cell.leaked_object_ids.join(", "),
            owner_label,
        )
    };

    let mut evidence = Vec::new();
    if let Some(baseline) = baseline {
        evidence.push(Evidence::Comparison {
            baseline,
            variant,
            difference,
        });
    } else {
        evidence.push(Evidence::Exchange {
            request: variant,
            response: None,
            note: difference,
        });
    }

    if !cell.leaked_object_ids.is_empty() {
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
                owner_label
            ),
        });
    }
    evidence
}

/// How bad this cell would be if the experiment supports it.
fn severity_for(matrix: &Matrix, cell: &Cell) -> Severity {
    let _ = matrix;
    if cell.privilege == PrivilegeLevel::Anonymous || !cell.leaked_object_ids.is_empty() {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// The prose a verified cell becomes.
pub fn matrix_writeup(matrix: &Matrix, cell: &Cell, target: TargetId) -> Writeup {
    let unauthenticated = cell.privilege == PrivilegeLevel::Anonymous;
    let leaked = !cell.leaked_object_ids.is_empty();

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

    Writeup {
        target,
        title,
        description,
        impact: impact(unauthenticated, leaked),
        remediation: REMEDIATION.into(),
        reproduction: reproduction(matrix, cell),
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
        source: FindingSource::AuthorizationTest,
        severity: severity_for(matrix, cell),
        location: Some(Location {
            part: MessagePart::Path,
            name: path_of(&matrix.url),
        }),
    }
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
pub fn construction_findings(construction: &Construction, target: TargetId) -> Vec<Verified> {
    let detector = ConstructionDetector;
    let mut findings: Vec<Verified> = detector
        .examine(construction)
        .into_iter()
        .filter_map(|hypothesis| {
            let attempt = construction
                .attempts
                .iter()
                .find(|attempt| attempt.request == Some(hypothesis.source_request))?;
            let verification = judge_attempt(construction, attempt);
            Verified::conclude(
                &hypothesis,
                &verification,
                attempt_writeup(construction, attempt, target)?,
            )
        })
        .collect();

    findings.sort_by_key(|verified| {
        (
            verified.finding().severity.rank(),
            std::cmp::Reverse(verified.finding().confidence),
        )
    });
    findings
}

/// Raises a hypothesis for every constructed attempt worth an opinion.
pub struct ConstructionDetector;

impl Detector for ConstructionDetector {
    type Subject = Construction;

    fn about(&self) -> DetectorInfo {
        CONSTRUCTED_OBJECT
    }

    fn examine(&self, construction: &Construction) -> Vec<Hypothesis> {
        construction
            .attempts
            .iter()
            .filter(|attempt| worth_judging(attempt))
            .filter_map(|attempt| {
                // An attempt with no stored request cannot be cited, and an uncitable
                // claim is exactly what this crate exists not to produce.
                let request = attempt.request?;
                attempt.control?;
                Some(Hypothesis {
                    detector: CONSTRUCTED_OBJECT.id.to_string(),
                    claim: format!(
                        "{} reached {}'s {}",
                        attempt.sender_label, attempt.owner_label, attempt.object_name
                    ),
                    source_request: request,
                    location: Some(Location {
                        part: message_part(&attempt.location),
                        name: attempt.location.describe(),
                    }),
                    provisional_severity: if attempt.is_violation() {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                })
            })
            .collect()
    }
}

/// Whether an attempt is worth an opinion at all.
///
/// Anything the application refused, redirected, or answered with the caller's own
/// data produces nothing. A run against a correctly built endpoint should be silent.
fn worth_judging(attempt: &Attempt) -> bool {
    let unidentified = attempt.verdict == Verdict::Inconclusive;
    attempt.is_violation() || (unidentified && attempt.outcome == Outcome::Allowed)
}

/// What the construction run's experiments established about one attempt.
///
/// The construction runner performs both experiments itself — it has to, because
/// building the request is the experiment — so this judges what they showed rather
/// than running a third. The ladder is the shared one either way.
pub(crate) fn judge_attempt(construction: &Construction, attempt: &Attempt) -> Verification {
    let Some(evidence) = attempt_evidence(construction, attempt) else {
        return Verification::Inconclusive {
            why: "the attempt was not recorded, so nothing can be cited".into(),
        };
    };

    if !attempt.is_violation() {
        // The shape-only case: the document looks right and nothing in it says whose
        // object it is. Worth a tester's time, and not a claim.
        return Verification::Supported {
            support: Support::Consistent,
            note: "the response looks like the object document and contains nothing \
                   that establishes whose object it is"
                .into(),
            evidence,
        };
    }

    if attempt.reproduced {
        return Verification::Reproduced {
            note: format!(
                "a second constructed attempt was served {}'s {} again",
                attempt.owner_label, attempt.object_name
            ),
            evidence,
        };
    }

    // A violation means the response either carried identifiers the caller never
    // sent, or quoted the one it asked for inside a document shaped like the
    // caller's own. Both are facts about the bytes rather than a similarity score.
    Verification::Supported {
        support: Support::Distinctive,
        note: format!(
            "{} asked for {}, declared as {}'s, and the application served it",
            attempt.sender_label, attempt.object_value, attempt.owner_label
        ),
        evidence,
    }
}

fn attempt_writeup(
    construction: &Construction,
    attempt: &Attempt,
    target: TargetId,
) -> Option<Writeup> {
    let disclosed = !attempt.disclosed_object_ids.is_empty();

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

    let _ = difference;

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

    Some(Writeup {
        target,
        title,
        description,
        impact: construction_impact(attempt, disclosed),
        remediation: REMEDIATION.into(),
        reproduction: construction_reproduction(construction, attempt),
        cwe: Some("CWE-639".into()),
        owasp: Some("API1:2023 Broken Object Level Authorization".into()),
        source: FindingSource::AuthorizationTest,
        severity,
        location: Some(Location {
            part: message_part(&attempt.location),
            name: attempt.location.describe(),
        }),
    })
}

/// The traffic behind one constructed attempt.
fn attempt_evidence(construction: &Construction, attempt: &Attempt) -> Option<Vec<Evidence>> {
    let _ = construction;
    let variant = attempt.request?;
    let baseline = attempt.control?;
    let disclosed = !attempt.disclosed_object_ids.is_empty();

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
        difference,
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
    Some(evidence)
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
    use hexora_types::finding::{Confidence, Finding};
    use hexora_types::ids::{IdentityId, RequestId};
    use hexora_types::verify::Verified;

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

    /// A cell carrying a real structural comparison of two bodies.
    fn compared(label: &str, verdict: Verdict, control: &str, variant: &str) -> Cell {
        let mut cell = cell(label, PrivilegeLevel::User, verdict);
        cell.structure = Some(hexora_types::structure::Diff::of(
            control.as_bytes(),
            variant.as_bytes(),
            &hexora_types::structure::Policy::default(),
        ));
        cell
    }

    /// An unauthenticated cell that was refused, which is what makes "the same
    /// document" mean something.
    fn refused_anonymous() -> Cell {
        let mut cell = cell("anonymous", PrivilegeLevel::Anonymous, Verdict::Expected);
        cell.status = Some(403);
        cell.outcome = Outcome::Denied;
        cell
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

    /// The whole check, minus the second experiment: detect, judge, conclude.
    ///
    /// The second experiment needs a transport, so it is tested in `lib.rs` against
    /// the fake one. Everything here is about what the *first* experiment supports.
    fn findings(matrix: &Matrix, target: TargetId) -> Vec<Finding> {
        let mut findings: Vec<Finding> = MatrixDetector
            .examine(matrix)
            .into_iter()
            .filter_map(|hypothesis| {
                let cell = matrix
                    .cells
                    .iter()
                    .find(|cell| cell.request == Some(hypothesis.source_request))?;
                let verification = judge(
                    cell,
                    &matrix.owner.label,
                    matrix.owner.request,
                    matrix.anonymous_control(),
                );
                Verified::conclude(
                    &hypothesis,
                    &verification,
                    matrix_writeup(matrix, cell, target),
                )
                .map(Verified::into_finding)
            })
            .collect();

        findings.sort_by_key(|finding| {
            (
                finding.severity.rank(),
                std::cmp::Reverse(finding.confidence),
            )
        });
        findings
    }

    /// The same, with a verification supplied rather than judged.
    fn finding_with(matrix: &Matrix, verification: &Verification) -> Option<Finding> {
        let hypothesis = MatrixDetector.examine(matrix).into_iter().next()?;
        let cell = matrix
            .cells
            .iter()
            .find(|cell| cell.request == Some(hypothesis.source_request))?;
        Verified::conclude(
            &hypothesis,
            verification,
            matrix_writeup(matrix, cell, TargetId::new()),
        )
        .map(Verified::into_finding)
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
    fn the_same_document_behind_a_refused_anonymous_request_is_stated_firmly() {
        // The claim a percentage cannot make. Two identities were served not a
        // document of the same shape but *the same document*, and an unauthenticated
        // request did not get it — so it is not a public page. That is checkable field
        // by field, which is what raises it above a lead.
        let body = r#"{"id":"acct-1000","owner":"User A","balance":4210}"#;
        let matrix = matrix(vec![
            compared("User B", Verdict::Violation, body, body),
            refused_anonymous(),
        ]);
        assert_eq!(matrix.anonymous_control(), AnonymousControl::Refused);

        let findings = findings(&matrix, TargetId::new());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].confidence, Confidence::Firm);
        assert!(findings[0].confidence.is_actionable());
    }

    #[test]
    fn the_same_document_without_an_anonymous_control_stays_a_lead() {
        // A run that did not try an unauthenticated request has not shown the resource
        // is non-public. Two identities reading an identical public page is exactly
        // what this looks like, so it does not get to be a firm claim.
        let body = r#"{"id":"acct-1000","owner":"User A","balance":4210}"#;
        let matrix = matrix(vec![compared("User B", Verdict::Violation, body, body)]);
        assert_eq!(matrix.anonymous_control(), AnonymousControl::NotTried);

        let findings = findings(&matrix, TargetId::new());
        assert_eq!(findings[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn two_different_documents_are_not_raised_however_alike_they_score() {
        // 98% alike and every value belonging to somebody else. The score says yes,
        // the fields say no, and the fields win.
        let matrix = matrix(vec![
            compared(
                "User B",
                Verdict::Violation,
                r#"{"id":"acct-1000","owner":"User A","balance":4210}"#,
                r#"{"id":"acct-2000","owner":"User B","balance":17}"#,
            ),
            refused_anonymous(),
        ]);
        let findings = findings(&matrix, TargetId::new());
        assert_eq!(findings[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn the_evidence_names_the_field_that_differed_rather_than_only_a_percentage() {
        let matrix = matrix(vec![compared(
            "User B",
            Verdict::Violation,
            r#"{"id":"acct-1000","email":"alice@example.com"}"#,
            r#"{"id":"acct-1000"}"#,
        )]);
        let findings = findings(&matrix, TargetId::new());
        let difference = findings[0]
            .evidence
            .iter()
            .find_map(|e| match e {
                Evidence::Comparison { difference, .. } => Some(difference.clone()),
                _ => None,
            })
            .expect("a comparison");
        assert!(difference.contains("$.email"), "{difference}");
        assert!(difference.contains("absent for User B"), "{difference}");
    }

    #[test]
    fn a_credential_in_a_body_does_not_reach_the_evidence() {
        // The comparison reads response bodies, so it is a path a session value could
        // travel down. It reports that the field differed and withholds what it was.
        let matrix = matrix(vec![compared(
            "User B",
            Verdict::Violation,
            r#"{"id":"acct-1000","session_token":"secret-value-for-a"}"#,
            r#"{"id":"acct-1000","session_token":"secret-value-for-b"}"#,
        )]);
        let findings = findings(&matrix, TargetId::new());
        let rendered = format!("{:#?}", findings[0]);
        assert!(!rendered.contains("secret-value-for-a"), "{rendered}");
        assert!(!rendered.contains("secret-value-for-b"), "{rendered}");
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
    fn a_detector_raises_a_hypothesis_and_cannot_produce_anything_more() {
        // The rule this milestone is about. The detector's whole output is a
        // hypothesis; there is no method on it that yields a finding, and this test
        // exists so that a future refactor that adds one has to delete a test saying
        // it must not.
        let matrix = matrix(vec![cell(
            "User B",
            PrivilegeLevel::User,
            Verdict::Violation,
        )]);
        let raised = MatrixDetector.examine(&matrix);

        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].detector, "authz.cross_identity");
        assert_eq!(raised[0].provisional_severity, Severity::Medium);
    }

    #[test]
    fn an_experiment_that_refutes_the_hypothesis_produces_nothing() {
        let matrix = matrix(vec![cell(
            "User B",
            PrivilegeLevel::User,
            Verdict::Violation,
        )]);
        let refuted = Verification::Refuted {
            note: "denied on the second request".into(),
        };
        assert!(finding_with(&matrix, &refuted).is_none());
    }

    #[test]
    fn only_a_reproduced_violation_reaches_confirmed() {
        let matrix = matrix(vec![cell(
            "User B",
            PrivilegeLevel::User,
            Verdict::Violation,
        )]);
        let reproduced = Verification::Reproduced {
            note: "it happened again".into(),
            evidence: judge(
                &matrix.cells[0],
                &matrix.owner.label,
                matrix.owner.request,
                matrix.anonymous_control(),
            )
            .evidence()
            .to_vec(),
        };
        let findings = finding_with(&matrix, &reproduced)
            .into_iter()
            .collect::<Vec<_>>();
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
        let reproduced = cell("User C", PrivilegeLevel::User, Verdict::Violation);

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
        let findings = findings(&matrix(vec![leaked]), TargetId::new());
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn a_url_without_a_path_still_produces_a_location() {
        assert_eq!(path_of("https://api.example.com"), "/");
        assert_eq!(path_of("https://api.example.com/a/b?c=1"), "/a/b?c=1");
    }
}
