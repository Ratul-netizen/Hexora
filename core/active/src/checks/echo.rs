//! `input.reflection` — where an input comes back, and what survived the trip.
//!
//! The check a scanner is most often wrong about. "My string appeared in the response"
//! is true of every search box ever built, and a tool that reports it has taught its
//! reader to skip its output. So this asks the two questions that actually separate
//! the cases:
//!
//! ```text
//! sent:  ?q=hxa9f3<>"'`;()hxb2k7
//!
//! back:  {"q": "hxa9f3<>\\"'`;()hxb2k7"}   application/json   → data. Nothing.
//!        <div>hxa9f3&lt;&gt;...hxb2k7</div>                   → escaped. Nothing.
//!        <div>hxa9f3<>"'`;()hxb2k7</div>                      → `<` in HTML text.
//! ```
//!
//! # It never says "cross-site scripting"
//!
//! The finding says which characters came back unencoded and where they landed. Whether
//! that is exploitable depends on a Content-Security-Policy, a template engine that may
//! re-encode on render, and a page somebody has to look at — none of which is visible
//! from one response. A tester reading "`<` came back unencoded in HTML text at
//! `$.results[0]`" can check it in thirty seconds; a tester reading "possible XSS" has
//! to start from nothing. See [`hexora_types::echo`].
//!
//! # What it costs the target
//!
//! One request per input, plus one more to confirm. An endpoint with four query
//! parameters is four experiments, which the scheduler paces and bounds like any
//! other — and the plan says so before anything is sent.
//!
//! # Which inputs
//!
//! Whatever [`hexora_types::inject::inputs`] offers: query parameters and ordinary
//! headers. Not path segments, because a segment is as often a route as a value and a
//! marker in the wrong one produces a 404 and a wasted request. Not credential
//! headers, ever. Not bodies yet — that wants a body model rather than a byte offset,
//! and the gap is stated rather than papered over.

use async_trait::async_trait;
use hexora_types::echo::{Probe, Serving, Survived};
use hexora_types::finding::{Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity};
use hexora_types::inject::{inputs, substitute};
use hexora_types::object::ObjectLocation;
use hexora_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use hexora_types::Result;
use hexora_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct InputReflection;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "input.reflected";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.reflection"),
    name: "Input reflection",
    version: "1.0.0",
    about: "which characters of an input come back unencoded, and what they land inside",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

#[async_trait]
impl ActiveCheck for InputReflection {
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
        let Some(slot) = slot_named(subject) else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "the input this was raised about is no longer in {} {}, so there \
                     was nothing to place a marker in",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };

        let first = match probe(subject, lab, &slot, seed_for(subject, 0)).await {
            Attempt::Answered(found) => found,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        if !first.found.reflected() {
            return Ok(Verification::Refuted {
                note: format!(
                    "a marker placed in {} did not come back in the response at all, so \
                     this input is not reflected",
                    describe(&slot)
                ),
            });
        }

        let Some(notable) = first.found.notable().next().cloned() else {
            // It came back, and nothing that would matter survived. The common and
            // welcome answer, and worth stating rather than discarding: a tester who
            // sees it knows the input was actually tested.
            let where_it_landed = first
                .found
                .echoes
                .first()
                .map(|echo| echo.context.as_str())
                .unwrap_or("the response");
            return Ok(Verification::Refuted {
                note: format!(
                    "a marker placed in {} came back inside {where_it_landed}, with \
                     every character that would have mattered there encoded or removed",
                    describe(&slot),
                ),
            });
        };

        let characters = quoted(&notable.dangerous());
        let evidence = evidence(subject, &slot, &first, None);

        if budget.per_hypothesis < 2 {
            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{characters} came back unencoded from {} inside {}. The budget \
                     allowed one request, so it was not sent a second time",
                    describe(&slot),
                    notable.context.as_str(),
                ),
                evidence,
            });
        }

        // A second marker, generated independently. Not the same request twice: a page
        // that cached the first answer, or that echoes a fixed string that happened to
        // contain the marker, does not survive a different one.
        let second = match probe(subject, lab, &slot, seed_for(subject, 1)).await {
            Attempt::Answered(found) => found,
            Attempt::Failed(why) => {
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "{characters} came back unencoded from {} inside {}. The \
                         confirming request did not complete ({why}), so this rests on \
                         one experiment",
                        describe(&slot),
                        notable.context.as_str(),
                    ),
                    evidence,
                })
            }
        };

        let agreed = second
            .found
            .notable()
            .any(|echo| echo.context == notable.context && !echo.dangerous().is_empty());

        let evidence = evidence_both(subject, &slot, &first, &second);
        if agreed {
            return Ok(Verification::Reproduced {
                note: format!(
                    "two independently generated markers placed in {} both came back \
                     inside {} with {characters} unencoded",
                    describe(&slot),
                    notable.context.as_str(),
                ),
                evidence,
            });
        }

        Ok(Verification::Supported {
            support: Support::Consistent,
            note: format!(
                "a marker placed in {} came back inside {} with {characters} \
                 unencoded, and a second marker did not do the same. Two experiments \
                 that disagree cannot support a firm claim",
                describe(&slot),
                notable.context.as_str(),
            ),
            evidence,
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let slot = slot_named(subject);
        let where_ = slot
            .as_ref()
            .map(describe)
            .unwrap_or_else(|| "an input".into());

        Writeup {
            target: subject.target,
            title: format!(
                "Input reflected without encoding in {} {}",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A marker was placed in {where_} of {} {} and came back in the \
                 response with characters that the surrounding context gives meaning \
                 to. {}\n\nThis states what the bytes did. Whether it can be exploited \
                 depends on a Content-Security-Policy, on whether the page is rendered \
                 by a template that re-encodes, and on what an attacker could get a \
                 user to visit — all of which need a person to look at the page.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A value a caller controls is placed into a response without being \
                     encoded for where it lands. Where that is markup or script, it is \
                     the precondition for cross-site scripting; whether the precondition \
                     is enough here is what the next half hour of a tester's time is for."
                .into(),
            remediation: "Encode on output, for the context the value lands in rather \
                          than once for all of them: HTML-escape for text and \
                          attributes, JavaScript-escape inside script, URL-encode inside \
                          a URL. A template engine that does this by default is the \
                          reliable fix; a filter that strips `<script>` is not."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} set to a value containing `<`, `>`, `\"` and \
                 `'`, and read the response body at the offset the evidence names. \
                 `hexora poc <project> <finding>` compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-79".into()),
            owasp: Some("A03:2021 Injection".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: slot
                .as_ref()
                .map(|slot| Location {
                    part: part_of(slot),
                    name: name_of(slot),
                })
                .or(subject.hypothesis.location.clone()),
        }
    }
}

/// Severity, from what the experiment actually established.
///
/// Never Critical: blast radius is a judgement about who can be reached and what the
/// page does, which is the tester's call after looking at it.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::Medium,
        _ => Severity::Low,
    }
}

/// One probe and what came back.
struct Answer {
    request: hexora_types::ids::RequestId,
    status: u16,
    found: Survived,
    sent: String,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

/// Places a marker in one input and reads the response.
async fn probe(subject: &Subject, lab: &dyn Lab, slot: &ObjectLocation, seed: u64) -> Attempt {
    let probe = Probe::seeded(seed);
    let mut draft = subject.draft.clone();

    draft.request = match substitute(&draft.request, slot, &probe.value()) {
        Ok(request) => request,
        Err(e) => return Attempt::Failed(format!("the marker could not be placed: {e}")),
    };

    let sent = match lab.experiment(&draft, None).await {
        Ok(sent) => sent,
        Err(e) => return Attempt::Failed(e.to_string()),
    };

    let response = &sent.exchange.response;
    // The response's own declared type, not a guess from the bytes. The same body is
    // data as `application/json` and markup as `text/html`.
    let serving = Serving::of(
        response
            .headers
            .get("content-type")
            .map(|header| header.value_lossy().to_string())
            .as_deref(),
    );

    Attempt::Answered(Answer {
        request: sent.id,
        status: response.status,
        found: probe.found_in(&response.body, serving),
        sent: probe.value(),
    })
}

/// The input the hypothesis was raised about, if the request still has it.
fn slot_named(subject: &Subject) -> Option<ObjectLocation> {
    let wanted = subject.hypothesis.location.as_ref()?;
    inputs(&subject.draft.request).into_iter().find(|slot| {
        name_of(slot).eq_ignore_ascii_case(&wanted.name) && part_of(slot) == wanted.part
    })
}

fn describe(slot: &ObjectLocation) -> String {
    match slot {
        ObjectLocation::Query { name, .. } => format!("the `{name}` query parameter"),
        ObjectLocation::Header { name, .. } => format!("the `{name}` header"),
        other => format!("{other:?}"),
    }
}

fn name_of(slot: &ObjectLocation) -> String {
    match slot {
        ObjectLocation::Query { name, .. } | ObjectLocation::Header { name, .. } => name.clone(),
        other => format!("{other:?}"),
    }
}

fn part_of(slot: &ObjectLocation) -> MessagePart {
    match slot {
        ObjectLocation::Query { .. } => MessagePart::Query,
        ObjectLocation::Header { .. } => MessagePart::Header,
        _ => MessagePart::Body,
    }
}

/// A seed that differs per subject and per attempt.
///
/// Per subject so two endpoints do not share a marker, and per attempt so the
/// confirming request is genuinely a different value rather than the same one sent
/// twice — which is what makes agreement between them mean something.
fn seed_for(subject: &Subject, attempt: u64) -> u64 {
    let id = subject.hypothesis.source_request.to_string();
    let mut seed = 0xcbf2_9ce4_8422_2325u64;
    for byte in id.bytes().chain(std::iter::once(attempt as u8)) {
        seed ^= byte as u64;
        seed = seed.wrapping_mul(0x1000_0000_01b3);
    }
    seed
}

/// A note, capitalised so it reads as a sentence where one is expected.
fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn quoted(characters: &[char]) -> String {
    characters
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

fn evidence(
    subject: &Subject,
    slot: &ObjectLocation,
    first: &Answer,
    second: Option<&Answer>,
) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {}",
            subject.exchange.method, subject.exchange.url
        ),
    }];

    for answer in [Some(first), second].into_iter().flatten() {
        let landed = answer
            .found
            .notable()
            .next()
            .or_else(|| answer.found.echoes.first());
        evidence.push(Evidence::Exchange {
            request: answer.request,
            response: None,
            note: match landed {
                Some(echo) => format!(
                    "{} set to `{}` — answered {}, and it came back at byte {} inside \
                     {}, as `{}`",
                    describe(slot),
                    answer.sent,
                    answer.status,
                    echo.offset,
                    echo.context.as_str(),
                    echo.between,
                ),
                None => format!(
                    "{} set to `{}` — answered {}, and it did not come back",
                    describe(slot),
                    answer.sent,
                    answer.status,
                ),
            },
        });
    }
    evidence
}

fn evidence_both(
    subject: &Subject,
    slot: &ObjectLocation,
    first: &Answer,
    second: &Answer,
) -> Vec<Evidence> {
    evidence(subject, slot, first, Some(second))
}

/// Raises one suspicion per input of a captured request.
///
/// Not a [`PassiveCheck`](hexora_scan::PassiveCheck): a passive check observes a
/// response, and *"this request takes a `q` parameter"* is an observation about a
/// **request** that says nothing at all until somebody sends one. So the suspicion is
/// manufactured here, next to the check that settles it, and it is honest about being
/// a work item rather than a finding — see [`Hypothesis::provisional_severity`], which
/// is `Info` until an experiment says otherwise.
///
/// [`Hypothesis::provisional_severity`]: hexora_types::finding::Hypothesis::provisional_severity
pub fn suspect(exchange: &hexora_scan::Exchange) -> Vec<Hypothesis> {
    hexora_types::inject::inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        .map(|slot| Hypothesis {
            detector: SETTLES.to_string(),
            // Short, because it is printed once per input and a real application has
            // hundreds. The long form said "whether it comes back, and in what state,
            // needs a request" on every line, which is true of all of them and
            // therefore worth saying once in the section heading instead.
            claim: format!(
                "{} {} — {}",
                exchange.method,
                path_of(&exchange.url),
                describe(&slot),
            ),
            source_request: exchange.id,
            location: Some(Location {
                part: part_of(&slot),
                name: name_of(&slot),
            }),
            // A work item, not a suspicion of a bug. Everything above `Info` here would
            // be claiming something about an experiment nobody has run.
            provisional_severity: Severity::Info,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use hexora_types::echo::Context;
    use hexora_types::http::{HttpRequest, HttpService};

    /// A captured exchange at `target`, as the scheduler would hand one over.
    fn exchange(target: &str) -> hexora_scan::Exchange {
        hexora_scan::Exchange {
            id: hexora_types::ids::RequestId::new(),
            target: hexora_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: format!("https://api.example.com{target}"),
            path: target.into(),
            status: 200,
            request_headers: hexora_types::http::Headers::new(),
            response_headers: hexora_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-09-11T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    /// A subject over that exchange, with a draft of the same request.
    fn subject_at(target: &str) -> Subject {
        let exchange = exchange(target);
        Subject {
            hypothesis: Hypothesis {
                source_request: exchange.id,
                ..raised(SETTLES)
            },
            draft: hexora_repeater::Draft::new(HttpRequest::get(
                HttpService::new("api.example.com", 443, true),
                target,
            )),
            target: exchange.target,
            exchange,
        }
    }

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: hexora_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(InputReflection.handles(&raised(SETTLES)));
        assert!(!InputReflection.handles(&raised("cors.configuration")));
        assert!(!InputReflection.handles(&raised("authz.cross_identity")));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = InputReflection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
        assert!(info.produces_something());
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        // It is a work item. A scanner that filed "input reflection" at Medium before
        // sending anything would be claiming the result of a test nobody ran.
        let raised = suspect(&exchange("/search?q=shoes&page=2"));
        assert_eq!(raised.len(), 2, "{raised:#?}");
        for hypothesis in &raised {
            assert_eq!(hypothesis.provisional_severity, Severity::Info);
            assert_eq!(hypothesis.detector, SETTLES);
        }
        assert!(raised[0].claim.contains("`q`"), "{}", raised[0].claim);
    }

    #[test]
    fn two_attempts_on_one_subject_use_different_markers() {
        // The confirming request has to be a *different* value, or agreement between
        // the two would only prove the page is deterministic.
        let one = subject_at("/search?q=shoes");

        assert_ne!(seed_for(&one, 0), seed_for(&one, 1));
        assert_ne!(
            Probe::seeded(seed_for(&one, 0)).value(),
            Probe::seeded(seed_for(&one, 1)).value()
        );

        // And two different endpoints do not share one.
        let other = subject_at("/other?q=shoes");
        assert_ne!(seed_for(&one, 0), seed_for(&other, 0));
    }

    #[test]
    fn the_writeup_states_facts_and_leaves_the_verdict_to_a_person() {
        let verification = Verification::Reproduced {
            note: "two markers came back".into(),
            evidence: Vec::new(),
        };
        let subject = subject_at("/search?q=shoes");
        let writeup = InputReflection.writeup(&subject, &verification);
        let title = writeup.title.to_lowercase();
        assert!(
            !title.contains("xss") && !title.contains("cross-site"),
            "the title claims a verdict this check did not establish: {}",
            writeup.title
        );
        assert!(
            writeup
                .description
                .contains("need a person to look at the page"),
            "the description must say what it does not know: {}",
            writeup.description
        );
        assert_eq!(writeup.severity, Severity::High);
    }

    #[test]
    fn severity_follows_what_the_experiment_showed() {
        assert_eq!(
            severity_for(&Verification::Reproduced {
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::High
        );
        assert_eq!(
            severity_for(&Verification::Supported {
                support: Support::Distinctive,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::Medium
        );
        assert_eq!(
            severity_for(&Verification::Supported {
                support: Support::Consistent,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::Low
        );
    }

    #[test]
    fn nothing_here_is_reported_at_critical() {
        // Blast radius is a judgement about who can be reached and what the page does.
        for verification in [
            Verification::Reproduced {
                note: String::new(),
                evidence: Vec::new(),
            },
            Verification::Supported {
                support: Support::Distinctive,
                note: String::new(),
                evidence: Vec::new(),
            },
        ] {
            assert_ne!(severity_for(&verification), Severity::Critical);
        }
    }

    #[test]
    fn a_context_that_would_not_matter_is_never_the_one_reported() {
        // `notable()` is what keeps a JSON API echoing a parameter out of the report,
        // and it is the single most important line in this check.
        assert!(!Context::JsonString.worth_looking_at());
        assert!(!Context::Unknown.worth_looking_at());
        assert!(Context::HtmlText.worth_looking_at());
    }
}
