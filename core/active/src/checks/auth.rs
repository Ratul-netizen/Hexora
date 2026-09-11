//! `auth.enforcement` — is a session required here, and is it checked?
//!
//! Two different failures, and a cross-identity matrix sees neither. Every identity in
//! a matrix holds a *valid* credential, so an endpoint that accepts any token at all
//! looks exactly like one that verifies properly:
//!
//! ```text
//! replayed as captured       →  200   the baseline: this session still works
//! sent with no credential    →  200   the endpoint needs no session
//! sent with a broken one     →  200   the endpoint has a session and does not check it
//! ```
//!
//! The third is the sharper finding. An application that accepts a JWT whose signature
//! has been changed — header and payload byte-identical — is not verifying signatures,
//! and that is a different sentence from "authentication is missing".
//!
//! # The baseline is replayed, never assumed
//!
//! The first request is the captured one, sent again as it was. Without it, an expired
//! session makes every probe come back 401 and the run would report *authentication is
//! enforced* having established nothing — the same mistake M12.8 exists to prevent for
//! a whole engagement, made one endpoint at a time. A baseline that does not succeed
//! ends the experiment as [`Verification::Inconclusive`].
//!
//! # Nothing that changes data is replayed
//!
//! `GET`, `HEAD` and `OPTIONS` only. A scheduler working through an engagement's
//! traffic will meet `POST /transfers` and `DELETE /accounts/42`, and sending those
//! again — three times each — is not a test anybody consented to. They are reported as
//! skipped, with the reason, so the gap is visible rather than silent.
//!
//! # The probe credential never reaches a report
//!
//! A credential with one character changed is, for disclosure purposes, the
//! credential. [`Tampered`](hexora_types::credential::Tampered) has no `Display`, a
//! redacting `Debug`, and an evidence note that says *what was done* rather than what
//! was sent. See invariant 17.

use async_trait::async_trait;
use hexora_types::credential::Credential;
use hexora_types::finding::{Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity};
use hexora_types::structure::{Comparable, Diff, Policy};
use hexora_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use hexora_types::Result;
use hexora_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct AuthEnforcement;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "auth.unverified";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("auth.enforcement"),
    name: "Authentication enforcement",
    version: "1.0.0",
    about: "whether an endpoint requires a session, and whether it checks the one it is given",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

#[async_trait]
impl ActiveCheck for AuthEnforcement {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn handles(&self, hypothesis: &Hypothesis) -> bool {
        hypothesis.detector == SETTLES
    }

    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        budget: &Budget,
    ) -> Result<Verification> {
        // 1. The baseline. Replayed rather than read back from the project: a
        //    comparison against a stored response produces differences that belong to
        //    time, and a session that has since expired would make every probe below
        //    look refused.
        let baseline = match send(subject, lab, Probe::AsCaptured).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        if !(200..300).contains(&baseline.status) {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "replaying {} {} as it was captured answered {}, so the session it \
                     was captured with no longer works and nothing below would have \
                     meant anything",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    baseline.status,
                ),
            });
        }

        // 2. No credential at all.
        let none = match send(subject, lab, Probe::WithoutCredential).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        let without = compare(&baseline, &none);
        let how = answered(&baseline, &none, &without);
        if how != Answered::Refused {
            return Ok(open(subject, &baseline, &none, without, how));
        }

        // 3. A credential the server issued, with one character changed. Only reached
        //    when the endpoint *does* refuse an anonymous request — an endpoint that
        //    needs no session has nothing to verify.
        if budget.per_hypothesis < 3 {
            return Ok(Verification::Refuted {
                note: format!(
                    "{} {} answered {} without a credential, so a session is required. \
                     The budget allowed two requests, so whether the session is \
                     verified was not tested",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    none.status,
                ),
            });
        }

        let broken = match send(subject, lab, Probe::WithBrokenCredential).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => {
                return Ok(Verification::Inconclusive {
                    why: format!(
                        "a session is required — {} {} answered {} without one — but the \
                         request that would have shown whether it is verified did not \
                         complete ({why})",
                        subject.exchange.method,
                        path_of(&subject.exchange.url),
                        none.status,
                    ),
                })
            }
        };

        if broken.skipped {
            return Ok(Verification::Refuted {
                note: format!(
                    "{} {} answered {} without a credential, so a session is required. \
                     Whether it is verified was not tested: the captured request either \
                     carried no credential this check knows how to break, or breaking it \
                     produced another credential this project declares — which would \
                     have been answered legitimately and read as a session nobody \
                     checked",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    none.status,
                ),
            });
        }

        let tampered = compare(&baseline, &broken);
        let how = answered(&baseline, &broken, &tampered);
        if how != Answered::Refused {
            return Ok(unverified(subject, &baseline, &broken, tampered, how));
        }

        Ok(Verification::Refuted {
            note: format!(
                "{} {} answered {} with no credential and {} with a broken one, and {} \
                 with the real one. A session is required and the one supplied is \
                 checked",
                subject.exchange.method,
                path_of(&subject.exchange.url),
                none.status,
                broken.status,
                baseline.status,
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let note = verification.note();
        let unverified = note.contains("does not check") || note.contains("could have refused");
        // Three outcomes, three titles. "No session required" is a claim, and the
        // ambiguous case — same status, different content — has not established it:
        // that is what a sign-in page answered 200 looks like. A title is the part
        // that gets forwarded without the sentence that qualified it.
        let where_ = format!(
            "{} {}",
            subject.exchange.method,
            path_of(&subject.exchange.url)
        );
        Writeup {
            target: subject.target,
            title: if unverified {
                format!("Session accepted without being verified in {where_}")
            } else if note.contains("serving the same document both times") {
                format!("No session required for {where_}")
            } else {
                format!("{where_} answered without a session, with different content")
            },
            description: format!(
                "{} {} was captured being sent with a credential. Replaying it \
                 established that the session still works; the requests below \
                 established what the endpoint does without one. {}",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: if unverified {
                "The endpoint reads a session and does not check that it is genuine. \
                 Anything that can be reached with a session can be reached by anybody \
                 who can construct something session-shaped, which — where the token is \
                 a JWT whose signature is not verified — means anybody at all, as \
                 whichever principal they care to name."
                    .into()
            } else {
                "The endpoint serves the same content to a caller with no session. What \
                 that is worth is whatever the content is: a public page is correct and \
                 a customer record is not, and the evidence below says which this is."
                    .into()
            },
            remediation: if unverified {
                "Verify the credential on every request rather than reading it. For a \
                 JWT that means checking the signature against the expected key and \
                 refusing `alg: none`; for an opaque token it means looking it up in \
                 the store that issued it. A check that decodes a token and trusts its \
                 claims is not authentication."
                    .into()
            } else {
                "If this endpoint is meant to be public, nothing here needs changing and \
                 the finding can be closed as such. If it is not, enforce the session \
                 check on the server for this route rather than relying on the caller \
                 to send one."
                    .into()
            },
            reproduction: format!(
                "Send {} {} three times: as captured, with the credential header \
                 removed, and with the credential's last character changed. Compare the \
                 three responses. `hexora poc <project> <finding>` compiles the \
                 requests, with credentials as placeholders.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some(if unverified { "CWE-287" } else { "CWE-306" }.into()),
            owasp: Some("A07:2021 Identification and Authentication Failures".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: Some(Location {
                part: MessagePart::Path,
                name: path_of(&subject.exchange.url).to_string(),
            }),
        }
    }
}

/// A declared object identifier appearing in a response served to nobody.
///
/// The one signal available here that separates "this endpoint is public" from "this
/// endpoint leaked somebody's data": an identifier a person declared as belonging to an
/// identity, found in a document handed to an unauthenticated caller.
///
/// Deliberately narrow. It looks only at identifiers somebody declared, never at
/// anything that merely *looks* like one — the same rule the constructed-attempt engine
/// follows, and for the same reason: Hexora does not decide what belongs to whom.
fn owned_id_in(subject: &Subject, answer: &Answer) -> Option<String> {
    let body = std::str::from_utf8(&answer.body).ok()?;
    subject
        .identities
        .iter()
        .flat_map(|identity| identity.owned_object_ids.iter())
        // A short id matches everywhere by accident. The constructed-attempt engine
        // draws this line in the same place.
        .filter(|id| id.len() >= 8)
        .find(|id| body.contains(id.as_str()))
        .cloned()
}

/// The verification for an endpoint that answered without a credential.
fn open(
    subject: &Subject,
    baseline: &Answer,
    none: &Answer,
    diff: Diff,
    how: Answered,
) -> Verification {
    let evidence = evidence(subject, &[baseline, none], &diff);
    let where_ = format!(
        "{} {}",
        subject.exchange.method,
        path_of(&subject.exchange.url)
    );

    match how {
        // Byte-identical content served to nobody.
        //
        // This used to be `Distinctive`, which made it High and Firm, and against a
        // real application it was wrong **every single time**: seven filings, seven
        // false positives, all of them public reference endpoints — a list of cities,
        // the districts in a city, address form fields, consent configuration.
        //
        // The classification was the error, not the threshold. `Distinctive` means the
        // evidence tells this hypothesis apart from the alternatives, and "the same
        // document came back without a session" does not: it is at least as consistent
        // with an endpoint that is *meant* to be public, which is much the commoner
        // thing. The premise underneath — captured with a credential, therefore meant
        // to be protected — is simply false for browser traffic, where the cookie goes
        // on every same-origin request including the ones to static config.
        //
        // So the question is not "was a session required" but "was anything of the
        // caller's disclosed". One thing in this project answers that without guessing:
        // an object identifier somebody declared as owned. Found in a document served
        // to nobody, that is a disclosure. Absent, there is nothing to distinguish a
        // missing control from a public page, and an honest check says so instead of
        // picking the exciting reading.
        Answered::SameDocument => match owned_id_in(subject, none) {
            Some(id) => Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{where_} answered {} with the captured credential and {} with no \
                     credential at all, serving the same document both times — and that \
                     document contains {id}, which this project declares as belonging to \
                     an identity. A caller with no session received it",
                    baseline.status, none.status,
                ),
                evidence,
            },
            None => Verification::Inconclusive {
                why: format!(
                    "{where_} answered {} with the captured credential and {} with no \
                     credential at all, serving the same document both times. That is \
                     what a missing session check looks like, and it is also exactly \
                     what a public endpoint looks like — nothing in the response \
                     belongs to a declared identity, so there is no way to tell them \
                     apart from here. Declare what an identity owns with `hexora \
                     identity add --owns` and run again",
                    baseline.status, none.status,
                ),
            },
        },
        // Different content to a caller with no session.
        //
        // This used to be a lead, and against a real application every one of them was
        // wrong. Read what it actually says: the server produced a *different* response
        // for an unauthenticated caller, which means it noticed. That is the control
        // working, not evidence it is missing. Measured on two of the endpoints filed:
        //
        //   /loyalty-program/v1/wallet -> {"wallet_enabled":false,"loyalty_programs":[]}
        //   /v1/pages/ftuPromoCounter  -> {"sections":[], ...}
        //
        // An empty wallet and a promo page with nothing in it. The application declined
        // to hand a stranger anything of the user's, and got filed for it.
        //
        // The residual worry is real but narrow: a *partially* populated view, where an
        // anonymous caller receives some of the owner's data and not all of it. That is
        // a disclosure question, and this project answers those with declared object
        // identifiers rather than with a hunch — found in the credential-less response,
        // one of those is the finding. Absent, the experiment ran and does not support
        // the suspicion, which is a result and is reported as one.
        Answered::DifferentContent => match owned_id_in(subject, none) {
            Some(id) => Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{where_} answered {} with no credential, serving content that \
                     differs from the real session's at {} — and that response contains \
                     {id}, which this project declares as belonging to an identity. A \
                     partial view is still a view, and part of this one belongs to \
                     somebody",
                    none.status,
                    diff.summary("with a session", "without"),
                ),
                evidence,
            },
            None => Verification::Refuted {
                note: format!(
                    "{where_} answered {} with no credential but served different \
                     content from the real session's, so the application distinguished \
                     the caller — which is what an enforced check looks like. Nothing in \
                     the unauthenticated response belongs to a declared identity. If you \
                     suspect it still leaks part of one, declare what an identity owns \
                     with `hexora identity add --owns` and run again",
                    none.status,
                ),
            },
        },
        Answered::Refused => Verification::Refuted {
            note: format!("{where_} refused a request with no credential"),
        },
    }
}

/// The verification for an endpoint that reads a session and does not check it.
fn unverified(
    subject: &Subject,
    baseline: &Answer,
    broken: &Answer,
    diff: Diff,
    how: Answered,
) -> Verification {
    let evidence = evidence(subject, &[baseline, broken], &diff);
    let where_ = format!(
        "{} {}",
        subject.exchange.method,
        path_of(&subject.exchange.url)
    );
    let what = broken.what.as_deref().unwrap_or("a broken credential");

    match how {
        // The application refuses an anonymous request and accepts a credential it
        // could have rejected. Not a score: a fact about what it did with bytes.
        Answered::SameDocument => Verification::Supported {
            support: Support::Distinctive,
            note: format!(
                "{where_} refuses a request with no credential, and answered {} to \
                 {what}, serving the same document as it served the real session — it \
                 reads a session and does not check it",
                broken.status,
            ),
            evidence,
        },
        Answered::DifferentContent => Verification::Supported {
            support: Support::Consistent,
            note: format!(
                "{where_} refuses a request with no credential and answered {} to \
                 {what}, with content that differs from the real session's at {}. It \
                 did not refuse a credential it could have refused, and what it served \
                 instead needs a reader",
                broken.status,
                diff.summary("the real session", "the broken one"),
            ),
            evidence,
        },
        Answered::Refused => Verification::Refuted {
            note: format!("{where_} refused {what}"),
        },
    }
}

/// What a probe was answered with, relative to the real session's answer.
///
/// Three outcomes rather than a boolean, because the middle one is real and common and
/// collapsing it either way is a mistake. A `200` carrying a sign-in page is a refusal
/// wearing a success status; a `200` carrying the same document is acceptance; a `200`
/// carrying *something else* is a question for a person, and saying so beats guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answered {
    /// A different status, or one that says no.
    Refused,
    /// The same status, and the same document everywhere the policy counts.
    SameDocument,
    /// The same status, and content that is not the same.
    DifferentContent,
}

fn answered(baseline: &Answer, probe: &Answer, diff: &Diff) -> Answered {
    if probe.status != baseline.status {
        return Answered::Refused;
    }
    if matches!(probe.status, 401 | 403 | 407) {
        return Answered::Refused;
    }
    // `same_document` is false when the bodies were not both JSON — because nothing
    // was compared, not because anything differed. Reading that as "different content"
    // reported two empty `204` bodies as a difference, which is how a real API's
    // perfectly ordinary no-content response became a finding.
    //
    // So when there was nothing to compare structurally, compare the bytes. Identical
    // bytes are the same document by any definition, and two genuinely different
    // non-JSON bodies are still different content.
    if diff.comparable != Comparable::Structurally {
        return match baseline.body == probe.body {
            true => Answered::SameDocument,
            false => Answered::DifferentContent,
        };
    }
    match diff.same_document() {
        true => Answered::SameDocument,
        false => Answered::DifferentContent,
    }
}

fn compare(baseline: &Answer, probe: &Answer) -> Diff {
    Diff::of(&baseline.body, &probe.body, &Policy::default())
}

/// Severity, from what the experiment established.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        Verification::Supported { .. } => Severity::Medium,
        _ => Severity::Low,
    }
}

/// What a probe changes about the request.
enum Probe {
    /// Exactly as captured.
    AsCaptured,
    /// Every credential header removed.
    WithoutCredential,
    /// The credential kept, with one character changed.
    WithBrokenCredential,
}

/// One request and what came back.
struct Answer {
    request: hexora_types::ids::RequestId,
    status: u16,
    body: bytes::Bytes,
    sent: String,
    /// How the credential was broken, for a probe that broke one.
    what: Option<String>,
    /// Whether there was nothing to do, so no request was made.
    skipped: bool,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

async fn send(subject: &Subject, lab: &dyn Lab, probe: Probe) -> Attempt {
    let mut draft = subject.draft.clone();
    let mut what = None;

    let sent = match probe {
        Probe::AsCaptured => "the request exactly as it was captured".to_string(),
        Probe::WithoutCredential => {
            let mut removed = Vec::new();
            for name in hexora_types::credential::CREDENTIAL_HEADERS {
                if draft.request.headers.remove(name) > 0 {
                    removed.push(*name);
                }
            }
            if removed.is_empty() {
                // Nothing to remove: the captured request carried no credential, so
                // this endpoint was never authenticated and there is no question here.
                return Attempt::Answered(skipped());
            }
            format!("the same request with {} removed", removed.join(", "))
        }
        Probe::WithBrokenCredential => {
            let Some(credential) = draft.request.headers.iter().find_map(Credential::read) else {
                return Attempt::Answered(skipped());
            };
            let tampered = credential.tamper();

            // Changing one character can land on another *valid* credential. It is
            // vanishingly unlikely against real tokens and certain against a test
            // fixture whose users differ by their last character — and the result is a
            // 200 that reads exactly like a session nobody verified, which is the
            // worst false positive this check could produce.
            //
            // The project knows every credential it declared, so this is checkable
            // rather than a risk to be accepted.
            if collides(&draft.request.headers, &tampered, &subject.identities) {
                return Attempt::Answered(skipped());
            }
            what = Some(tampered.describe());
            // The one place the probe bytes are used. They go onto the wire and
            // nowhere else: `what` carries the description, never the value.
            draft
                .request
                .headers
                .set(tampered.header(), tampered.expose_value());
            tampered.describe()
        }
    };

    match lab.experiment(&draft, None).await {
        Ok(result) => Attempt::Answered(Answer {
            request: result.id,
            status: result.exchange.response.status,
            body: result.exchange.response.body.clone(),
            sent,
            what,
            skipped: false,
        }),
        Err(e) => Attempt::Failed(e.to_string()),
    }
}

/// Whether a broken credential happens to be another declared identity's.
///
/// Compared by applying each declared credential to a copy of the headers the probe
/// would send, which is the same technique `Subject::whose` uses and for the same
/// reason: an exact answer, and no credential written down anywhere.
fn collides(
    headers: &hexora_types::http::Headers,
    tampered: &hexora_types::credential::Tampered,
    identities: &[hexora_types::identity::Identity],
) -> bool {
    let mut probe = headers.clone();
    probe.set(tampered.header(), tampered.expose_value());

    identities.iter().any(|identity| {
        let mut theirs = probe.clone();
        identity.credential.apply(&mut theirs);
        identity.credential.header_names().iter().all(|name| {
            match (probe.get(name), theirs.get(name)) {
                (Some(a), Some(b)) => a.value == b.value,
                _ => false,
            }
        })
    })
}

fn skipped() -> Answer {
    Answer {
        request: hexora_types::ids::RequestId::new(),
        status: 0,
        body: bytes::Bytes::new(),
        sent: String::new(),
        what: None,
        skipped: true,
    }
}

fn evidence(subject: &Subject, answers: &[&Answer], diff: &Diff) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {} answered {}",
            subject.exchange.method, subject.exchange.url, subject.exchange.status
        ),
    }];

    for answer in answers {
        if answer.skipped {
            continue;
        }
        evidence.push(Evidence::Exchange {
            request: answer.request,
            response: None,
            // `sent` describes the change. It never carries a credential — see
            // `Tampered::describe`.
            note: format!("{} — answered {}", answer.sent, answer.status),
        });
    }

    if let Some(first) = answers.first() {
        if let Some(second) = answers.get(1) {
            if !first.skipped && !second.skipped {
                evidence.push(Evidence::Comparison {
                    baseline: first.request,
                    variant: second.request,
                    difference: diff.summary("with a session", "without a valid one"),
                });
            }
        }
    }
    evidence
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

/// Raises one suspicion per authenticated endpoint that is safe to replay.
///
/// Two filters, and both are about not doing damage rather than about coverage:
///
/// * the captured request carried a credential — an endpoint nobody authenticated to
///   has no session to test;
/// * the method is one RFC 9110 calls safe. A scheduler working through an
///   engagement's traffic will meet `POST /transfers`, and sending it again three
///   times is not a test anybody consented to.
pub fn suspect(exchange: &hexora_scan::Exchange) -> Vec<Hypothesis> {
    if !exchange.authenticated {
        return Vec::new();
    }
    // The scheduler refuses these too, for every check. Refusing here as well keeps
    // the plan honest: a work item nobody could ever run would otherwise be listed as
    // skipped on every dry run for the rest of the engagement.
    if crate::schedule::is_state_changing(&exchange.method) {
        return Vec::new();
    }
    // An endpoint that already refuses everybody has nothing to establish.
    if !(200..400).contains(&exchange.status) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} was sent with a session — whether it needs one, and whether it \
             checks it, needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: Some(Location {
            part: MessagePart::Path,
            name: path_of(&exchange.url).to_string(),
        }),
        // A work item. Anything above `Info` would be claiming the result of an
        // experiment nobody has run.
        provisional_severity: Severity::Info,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(method: &str, status: u16, authenticated: bool) -> hexora_scan::Exchange {
        hexora_scan::Exchange {
            id: hexora_types::ids::RequestId::new(),
            target: hexora_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://api.example.com/account".into(),
            path: "/account".into(),
            status,
            request_headers: hexora_types::http::Headers::new(),
            response_headers: hexora_types::http::Headers::new(),
            response_bytes: 0,
            authenticated,
            tls: None,
            sent_at: "2026-09-11T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        let raised = |detector: &str| Hypothesis {
            detector: detector.into(),
            claim: String::new(),
            source_request: hexora_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        };
        assert!(AuthEnforcement.handles(&raised(SETTLES)));
        assert!(!AuthEnforcement.handles(&raised("input.reflected")));
        assert!(!AuthEnforcement.handles(&raised("redirect.controllable")));
    }

    #[test]
    fn nothing_that_changes_data_is_ever_queued() {
        // A scheduler working through an engagement's traffic meets `POST /transfers`,
        // and sending it three more times is not a test anybody consented to.
        for method in ["POST", "PUT", "PATCH", "DELETE", "post", "delete"] {
            assert!(
                suspect(&exchange(method, 200, true)).is_empty(),
                "{method} was queued for replay"
            );
        }
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert_eq!(suspect(&exchange(method, 200, true)).len(), 1, "{method}");
        }
    }

    #[test]
    fn an_endpoint_nobody_authenticated_to_has_no_session_to_test() {
        assert!(suspect(&exchange("GET", 200, false)).is_empty());
    }

    #[test]
    fn an_endpoint_that_already_refuses_everybody_establishes_nothing() {
        for status in [401, 403, 404, 500] {
            assert!(
                suspect(&exchange("GET", status, true)).is_empty(),
                "{status} was queued"
            );
        }
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        let raised = suspect(&exchange("GET", 200, true));
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        assert!(
            raised[0].claim.contains("needs a request"),
            "{}",
            raised[0].claim
        );
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = AuthEnforcement.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
        assert!(info.produces_something());
    }

    /// An identity that has declared what it owns.
    fn owner(id: &str) -> hexora_types::identity::Identity {
        hexora_types::identity::Identity {
            owned_object_ids: vec![id.to_string()],
            ..hexora_types::identity::Identity::anonymous()
        }
    }

    fn subject_owning(ids: Vec<hexora_types::identity::Identity>) -> Subject {
        // Only `identities` is read by `owned_id_in`; the rest is scaffolding.
        Subject {
            hypothesis: suspect(&exchange("GET", 200, true)).remove(0),
            exchange: exchange("GET", 200, true),
            draft: hexora_repeater::Draft::new(hexora_types::http::HttpRequest::get(
                hexora_types::http::HttpService::new("api.example.com", 443, true),
                "/me",
            )),
            target: hexora_types::ids::TargetId::new(),
            identities: std::sync::Arc::new(ids),
        }
    }

    #[test]
    fn a_public_document_served_to_nobody_establishes_nothing() {
        // Seven filings against a real application, seven false positives: a list of
        // cities, the districts in a city, address form fields, consent configuration.
        // Every one served the same document with and without a session, because every
        // one is meant to be public.
        //
        // "The same document came back without a session" does not tell a missing
        // control apart from a public page — it is at least as consistent with the
        // second, which is much the commoner thing. Saying so is the whole fix.
        let body = r#"{"cities":["Helsinki","Tampere"]}"#;
        let baseline = answer(200, body);
        let none = answer(200, body);
        let verification = open(
            &subject_owning(vec![owner("acct-1000-belongs-to-alice")]),
            &baseline,
            &none,
            compare(&baseline, &none),
            Answered::SameDocument,
        );

        assert!(
            matches!(verification, Verification::Inconclusive { .. }),
            "a public endpoint was filed as a finding: {verification:?}"
        );
        assert!(
            verification.confidence().is_none(),
            "and nothing was claimed"
        );
    }

    #[test]
    fn a_declared_owners_data_served_to_nobody_is_the_real_thing() {
        // The true positive this check exists for, and the one the fix must not cost:
        // a document handed to an unauthenticated caller containing an identifier
        // somebody declared as belonging to an identity.
        let body = r#"{"account":"acct-1000-belongs-to-alice","balance":4210}"#;
        let baseline = answer(200, body);
        let none = answer(200, body);
        let verification = open(
            &subject_owning(vec![owner("acct-1000-belongs-to-alice")]),
            &baseline,
            &none,
            compare(&baseline, &none),
            Answered::SameDocument,
        );

        match &verification {
            Verification::Supported { support, note, .. } => {
                assert_eq!(*support, Support::Distinctive);
                assert!(note.contains("acct-1000-belongs-to-alice"), "{note}");
            }
            other => panic!("the real thing was not established: {other:?}"),
        }
        assert_eq!(severity_for(&verification), Severity::High);
    }

    #[test]
    fn different_content_without_a_session_is_the_control_working() {
        // Every one of these was wrong against a real application. The server produced
        // a different response for an unauthenticated caller, which means it noticed —
        // an empty wallet, a promo page with no sections. It declined to hand a stranger
        // anything of the user's, and got filed for it.
        let baseline = answer(200, r#"{"wallet_enabled":true,"programs":["gold"]}"#);
        let none = answer(200, r#"{"wallet_enabled":false,"programs":[]}"#);
        let verification = open(
            &subject_owning(vec![owner("acct-1000-belongs-to-alice")]),
            &baseline,
            &none,
            compare(&baseline, &none),
            Answered::DifferentContent,
        );

        assert!(
            matches!(verification, Verification::Refuted { .. }),
            "an enforced check was reported as a lead: {verification:?}"
        );
        assert!(verification.confidence().is_none());
    }

    #[test]
    fn a_partial_view_containing_a_declared_owners_data_is_still_the_real_thing() {
        // The narrow case the refutation must not swallow: the anonymous caller gets
        // less than the owner does, but some of what it gets is the owner's.
        let baseline = answer(
            200,
            r#"{"account":"acct-1000-belongs-to-alice","balance":4210,"tier":"gold"}"#,
        );
        let none = answer(200, r#"{"account":"acct-1000-belongs-to-alice"}"#);
        let verification = open(
            &subject_owning(vec![owner("acct-1000-belongs-to-alice")]),
            &baseline,
            &none,
            compare(&baseline, &none),
            Answered::DifferentContent,
        );

        match &verification {
            Verification::Supported { support, note, .. } => {
                assert_eq!(*support, Support::Distinctive);
                assert!(note.contains("acct-1000-belongs-to-alice"), "{note}");
            }
            other => panic!("a partial disclosure was ruled out: {other:?}"),
        }
        assert_eq!(severity_for(&verification), Severity::High);
    }

    #[test]
    fn a_short_identifier_is_not_matched_by_accident() {
        // `id` or `42` appears in every document ever served. The constructed-attempt
        // engine draws this line in the same place.
        let body = r#"{"cities":["Helsinki"],"page":42}"#;
        let baseline = answer(200, body);
        let none = answer(200, body);
        let verification = open(
            &subject_owning(vec![owner("42")]),
            &baseline,
            &none,
            compare(&baseline, &none),
            Answered::SameDocument,
        );
        assert!(matches!(verification, Verification::Inconclusive { .. }));
    }

    fn how(baseline: &Answer, probe: &Answer) -> Answered {
        answered(baseline, probe, &compare(baseline, probe))
    }

    #[test]
    fn the_same_document_without_a_session_is_acceptance() {
        let body = r#"{"user":"alice","balance":4210}"#;
        assert_eq!(
            how(&answer(200, body), &answer(200, body)),
            Answered::SameDocument
        );
    }

    #[test]
    fn different_content_at_the_same_status_is_its_own_answer() {
        // A sign-in page answered 200 looks exactly like this — and so does a partly
        // populated view of the real resource. Collapsing it either way is a mistake,
        // so it is a third outcome and reaches a report as a lead.
        let with = answer(
            200,
            r#"{"user":"alice","balance":4210,"email":"a@x.example"}"#,
        );
        let without = answer(200, r#"{"user":null,"balance":0,"email":""}"#);
        assert_eq!(how(&with, &without), Answered::DifferentContent);
    }

    #[test]
    fn two_empty_bodies_are_the_same_document_not_a_difference() {
        // A real API's `204 No Content`, served identically with and without a session,
        // was reported as "answered without a session, with different content". Nothing
        // was compared — there was nothing to compare — and `same_document` says so by
        // returning false, which the caller was reading as "they differ".
        assert_eq!(
            how(&answer(204, ""), &answer(204, "")),
            Answered::SameDocument
        );
    }

    #[test]
    fn two_different_non_json_bodies_are_still_different_content() {
        // The other half: falling back to bytes must not make everything look equal.
        assert_eq!(
            how(
                &answer(200, "welcome back, alice"),
                &answer(200, "please sign in")
            ),
            Answered::DifferentContent
        );
    }

    #[test]
    fn identical_non_json_bodies_are_the_same_document() {
        let body = "<html><body>Shop</body></html>";
        assert_eq!(
            how(&answer(200, body), &answer(200, body)),
            Answered::SameDocument
        );
    }

    #[test]
    fn a_different_status_is_never_acceptance() {
        let body = r#"{"a":1}"#;
        assert_eq!(
            how(&answer(200, body), &answer(401, body)),
            Answered::Refused
        );
        assert_eq!(
            how(&answer(200, body), &answer(302, body)),
            Answered::Refused
        );
    }

    #[test]
    fn a_status_that_says_no_is_a_refusal_whatever_it_carries() {
        // An application that answers 401 to both the real session and the probe has
        // not accepted anything, however alike the two bodies are.
        let body = r#"{"error":"unauthorized"}"#;
        assert_eq!(
            how(&answer(401, body), &answer(401, body)),
            Answered::Refused
        );
    }

    #[test]
    fn a_timestamp_does_not_turn_acceptance_into_a_lead() {
        // The normalization policy earns its place here: without it, every real
        // application would land in `DifferentContent` and the strongest finding this
        // check can make would never be reached.
        let with = answer(
            200,
            r#"{"user":"alice","served_at":"2026-09-11T11:00:01Z"}"#,
        );
        let without = answer(
            200,
            r#"{"user":"alice","served_at":"2026-09-11T11:00:09Z"}"#,
        );
        assert_eq!(how(&with, &without), Answered::SameDocument);
    }

    #[test]
    fn severity_follows_what_the_experiment_showed() {
        assert_eq!(
            severity_for(&Verification::Supported {
                support: Support::Distinctive,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::High
        );
        assert_eq!(
            severity_for(&Verification::Supported {
                support: Support::Consistent,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::Medium
        );
        assert_eq!(
            severity_for(&Verification::Refuted {
                note: String::new()
            }),
            Severity::Low
        );
    }

    fn answer(status: u16, body: &str) -> Answer {
        Answer {
            request: hexora_types::ids::RequestId::new(),
            status,
            body: bytes::Bytes::from(body.to_string()),
            sent: String::new(),
            what: None,
            skipped: false,
        }
    }
}
