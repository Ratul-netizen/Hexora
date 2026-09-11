//! `redirect.destination` — can a caller choose where a redirect sends somebody?
//!
//! ```text
//! captured:  GET /login?next=/dashboard   →  302  Location: /dashboard
//! probed:    GET /login?next=https://hexora-probe.invalid/
//!                                         →  302  Location: https://hexora-probe.invalid/
//! ```
//!
//! # The header is read, never followed
//!
//! Following it would mean sending a request to a host **the target chose**, which is
//! the one way an automated tool can be talked into generating traffic to a machine
//! nobody authorized. The scope guard would refuse it, and relying on that would be
//! relying on a backstop instead of not doing the thing. So the destination is resolved
//! from the header and the request's own host, by [`hexora_types::redirect`], and no
//! request is ever made to it.
//!
//! # The destination is a host, not a substring
//!
//! `location.contains(probe)` is true of all of these and only three of them send a
//! browser anywhere:
//!
//! ```text
//! https://hexora-probe.invalid/                    taken
//! //hexora-probe.invalid/                          taken — and invisible to a filter
//!                                                          that only looks for `http`
//! https://app.example.com@hexora-probe.invalid/    taken — the host is after the `@`
//! /redirect?to=https://hexora-probe.invalid        carried, not obeyed
//! ```
//!
//! A carried value is **refuted, with the reason**, because a tester who has been told
//! three times that a search parameter is an open redirect stops reading.
//!
//! # Two forms, because a filter that stops one often misses the other
//!
//! The absolute form first. If it is refused, the protocol-relative form — and an
//! application that refuses `https://elsewhere` while accepting `//elsewhere` is a
//! *more* interesting finding than one that accepts both, because it says somebody
//! wrote a filter and the filter does not work.
//!
//! # Which endpoints, and which inputs
//!
//! Only endpoints whose captured response actually redirected, and only their **query
//! parameters**.
//!
//! A destination comes from a parameter. Placing one in `Accept` or `User-Agent` is
//! two requests per header against somebody's system for a behaviour that does not
//! exist, and this check would have spent two thirds of its queue that way.
//!
//! Header-driven redirects are real — `X-Forwarded-Host` poisoning is the usual one —
//! and they are **not covered here**. They have a different shape: the interesting
//! response is often a 200 whose absolute links have moved, not a `Location` at all.
//! Claiming to cover them by trying `Accept` would be worse than saying they are not
//! covered.
//!
//! A redirect that happens only for certain input values is also missed. Both are
//! stated limitations rather than quiet ones.

use async_trait::async_trait;
use hexora_types::finding::{Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity};
use hexora_types::inject::{inputs_in, substitute};
use hexora_types::object::ObjectLocation;
use hexora_types::redirect::{resolve, Destination};
use hexora_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use hexora_types::Result;
use hexora_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct RedirectDestination;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "redirect.controllable";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("redirect.destination"),
    name: "Redirect destination",
    version: "1.0.0",
    about: "whether a caller can choose the host a redirect sends somebody to",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Destinations that cannot exist.
///
/// `.invalid` is reserved by RFC 2606: it never resolves, so a mistake anywhere —
/// a browser opened by hand, a library that follows automatically — reaches nothing.
/// Nobody can register it either, so a redirect reported last year cannot be turned
/// into a live one by somebody buying the domain.
const PROBE_HOST: &str = "hexora-probe.invalid";
const SECOND_PROBE_HOST: &str = "hexora-second-probe.invalid";

#[async_trait]
impl ActiveCheck for RedirectDestination {
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
                     was nothing to place a destination in",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };

        let absolute = format!("https://{PROBE_HOST}/");
        let first = match probe(subject, lab, &slot, &absolute).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        if !first.redirected {
            return Ok(Verification::Refuted {
                note: format!(
                    "with a destination in {}, {} {} answered {} and sent no Location \
                     header, so nothing about where it redirects is controllable here",
                    describe(&slot),
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    first.status,
                ),
            });
        }

        if let Some(taken) = took(&first) {
            // It went somewhere else on the first try. Confirm with a *different*
            // host: a page that happened to redirect off-site for its own reasons
            // does not send a browser to two hosts of our choosing.
            return Ok(self
                .confirm(subject, lab, &slot, first, taken, budget)
                .await);
        }

        // The absolute form did not work. A filter that refuses `https://elsewhere`
        // and accepts `//elsewhere` is the common shape, and finding it is most of
        // what this check is worth.
        if budget.per_hypothesis < 2 {
            return Ok(Verification::Refuted {
                note: carried(&first, &slot, subject),
            });
        }

        let relative = format!("//{PROBE_HOST}/");
        let second = match probe(subject, lab, &slot, &relative).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(_) => {
                return Ok(Verification::Refuted {
                    note: carried(&first, &slot, subject),
                })
            }
        };

        match took(&second) {
            Some(taken) => Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{} {} refused `{absolute}` and accepted `{relative}`: the redirect \
                     went to {taken} as {}. A filter is present and does not cover the \
                     form a browser treats identically",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    second.destination.reach.as_str(),
                ),
                evidence: evidence(subject, &slot, &[&first, &second]),
            }),
            None => Ok(Verification::Refuted {
                note: format!(
                    "{}. Neither the absolute form nor the protocol-relative one moved \
                     it off {}",
                    carried(&first, &slot, subject),
                    subject.exchange.host,
                ),
            }),
        }
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
                "Redirect destination is caller-controlled in {} {}",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "{} {} was sent a destination in {where_} naming a host that cannot \
                 exist, and answered with a Location header pointing at it. {}\n\nThe \
                 header was read, never followed: Hexora does not send a request to a \
                 destination a target chose.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A link to this application can send whoever clicks it to a site \
                     the link's author picked, with this application's name in the \
                     visible part of the URL. That is worth most as a way to make a \
                     phishing page look like it came from here, and worth more if any \
                     token or referrer travels to the destination — which depends on \
                     what this endpoint does before it redirects."
                .into(),
            remediation: "Do not build the destination from a caller-supplied value. \
                          Where a return path is genuinely needed, accept a path only \
                          — rejecting anything with a scheme, a `//` or a `\\` — or \
                          look the destination up from a fixed table by key. A filter \
                          that blocks `http` and lets `//host` through is the usual \
                          failure, because a browser treats them the same."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} set to `https://{PROBE_HOST}/` and read the \
                 Location header on the response without following it. `hexora poc \
                 <project> <finding>` compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-601".into()),
            owasp: Some("A01:2021 Broken Access Control".into()),
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

impl RedirectDestination {
    /// Sends a second, different destination.
    ///
    /// Not the same request twice: two *different* hosts of our choosing is what
    /// separates a controllable redirect from a page that redirects off-site anyway.
    async fn confirm(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        slot: &ObjectLocation,
        first: Answer,
        taken: String,
        budget: &Budget,
    ) -> Verification {
        if budget.per_hypothesis < 2 {
            return Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "the redirect went to {taken}, chosen in {}. The budget allowed one \
                     request, so a second destination was not tried",
                    describe(slot),
                ),
                evidence: evidence(subject, slot, &[&first]),
            };
        }

        let second_url = format!("https://{SECOND_PROBE_HOST}/");
        let second = match probe(subject, lab, slot, &second_url).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => {
                return Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "the redirect went to {taken}, chosen in {}. The confirming \
                         request did not complete ({why}), so this rests on one \
                         experiment",
                        describe(slot),
                    ),
                    evidence: evidence(subject, slot, &[&first]),
                }
            }
        };

        match took(&second) {
            Some(other) if other != taken => Verification::Reproduced {
                note: format!(
                    "two different hosts named in {} were each answered with a Location \
                     pointing at them — {taken} and {other}. The destination is chosen \
                     by the caller",
                    describe(slot),
                ),
                evidence: evidence(subject, slot, &[&first, &second]),
            },
            _ => Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "the redirect went to {taken} when the first destination was \
                     supplied, and a second, different destination did not produce the \
                     same behaviour. Two experiments that disagree cannot support a \
                     firm claim",
                ),
                evidence: evidence(subject, slot, &[&first, &second]),
            },
        }
    }
}

/// Where the response would actually send somebody, if that is off the host.
fn took(answer: &Answer) -> Option<String> {
    if !answer.destination.reach.leaves_the_host() {
        return None;
    }
    answer.destination.host.clone().filter(|host| {
        // Only a destination *we* named counts. A page that redirects to its own login
        // provider on every request is not a caller-controlled redirect.
        host == PROBE_HOST || host == SECOND_PROBE_HOST
    })
}

/// The sentence for a destination that travelled without being obeyed.
fn carried(answer: &Answer, slot: &ObjectLocation, subject: &Subject) -> String {
    let mentioned = answer.destination.location.contains(PROBE_HOST);
    if mentioned {
        format!(
            "a destination placed in {} appeared in the Location header but is not \
             where it points: `{}` resolves to {}, which is {}",
            describe(slot),
            answer.destination.location,
            answer
                .destination
                .host
                .clone()
                .unwrap_or_else(|| subject.exchange.host.clone()),
            answer.destination.reach.as_str(),
        )
    } else {
        format!(
            "a destination placed in {} did not reach the Location header, which \
             pointed at `{}`",
            describe(slot),
            answer.destination.location,
        )
    }
}

/// Severity, from what the experiment established.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::Medium,
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
    redirected: bool,
    destination: Destination,
    sent: String,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

/// Places a destination in one input and reads the `Location` it comes back with.
async fn probe(subject: &Subject, lab: &dyn Lab, slot: &ObjectLocation, to: &str) -> Attempt {
    let mut draft = subject.draft.clone();
    draft.request = match substitute(&draft.request, slot, to) {
        Ok(request) => request,
        Err(e) => return Attempt::Failed(format!("the destination could not be placed: {e}")),
    };

    let sent = match lab.experiment(&draft, None).await {
        Ok(sent) => sent,
        Err(e) => return Attempt::Failed(e.to_string()),
    };

    let response = &sent.exchange.response;
    let location = response
        .headers
        .get("location")
        .map(|header| header.value_lossy().to_string());

    Attempt::Answered(Answer {
        request: sent.id,
        status: response.status,
        redirected: location.is_some(),
        // Resolved against the host the request went to, exactly as a browser would.
        // Nothing is fetched.
        destination: resolve(&subject.exchange.host, location.as_deref().unwrap_or("")),
        sent: to.to_string(),
    })
}

/// The input the hypothesis was raised about, if the request still has it.
fn slot_named(subject: &Subject) -> Option<ObjectLocation> {
    let wanted = subject.hypothesis.location.as_ref()?;
    inputs_in(&subject.draft.request.path, &subject.draft.request.headers)
        .into_iter()
        .find(|slot| {
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

fn evidence(subject: &Subject, slot: &ObjectLocation, answers: &[&Answer]) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {} answered {}",
            subject.exchange.method, subject.exchange.url, subject.exchange.status
        ),
    }];

    for answer in answers {
        evidence.push(Evidence::Exchange {
            request: answer.request,
            response: None,
            note: format!(
                "{} set to `{}` — answered {} with Location: `{}`, which resolves to {}",
                describe(slot),
                answer.sent,
                answer.status,
                answer.destination.location,
                answer
                    .destination
                    .host
                    .clone()
                    .unwrap_or_else(|| "no host".into()),
            ),
        });
    }
    evidence
}

/// Raises one suspicion per input of an endpoint that actually redirected.
///
/// The narrowing is deliberate. Probing every input of every endpoint for a behaviour
/// most of them do not have would double a queue for nothing; a captured 3xx with a
/// `Location` is evidence that this endpoint redirects. The cost is that a redirect
/// which happens only for certain values is missed, and that is written down rather
/// than hidden.
pub fn suspect(exchange: &hexora_scan::Exchange) -> Vec<Hypothesis> {
    if !(300..400).contains(&exchange.status) || exchange.response_headers.get("location").is_none()
    {
        return Vec::new();
    }

    inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        // Query parameters only. See the module documentation: a destination comes
        // from a parameter, and probing every header would spend two thirds of this
        // check's queue on a behaviour that does not exist.
        .filter(|slot| matches!(slot, ObjectLocation::Query { .. }))
        .map(|slot| Hypothesis {
            detector: SETTLES.to_string(),
            claim: format!(
                "{} {} redirects — whether {} chooses where, needs a request",
                exchange.method,
                path_of(&exchange.url),
                describe(&slot),
            ),
            source_request: exchange.id,
            location: Some(Location {
                part: part_of(&slot),
                name: name_of(&slot),
            }),
            // A work item. Anything above `Info` would be claiming the result of an
            // experiment nobody has run.
            provisional_severity: Severity::Info,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: hexora_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange(status: u16, location: Option<&str>) -> hexora_scan::Exchange {
        let mut response_headers = hexora_types::http::Headers::new();
        if let Some(location) = location {
            response_headers.set("Location", location);
        }
        hexora_scan::Exchange {
            id: hexora_types::ids::RequestId::new(),
            target: hexora_types::ids::TargetId::new(),
            host: "app.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: "https://app.example.com/login?next=/dashboard".into(),
            path: "/login?next=/dashboard".into(),
            status,
            request_headers: hexora_types::http::Headers::new(),
            response_headers,
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-09-11T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(RedirectDestination.handles(&raised(SETTLES)));
        assert!(!RedirectDestination.handles(&raised("input.reflected")));
        assert!(!RedirectDestination.handles(&raised("cors.configuration")));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = RedirectDestination.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
        assert!(info.produces_something());
    }

    #[test]
    fn a_header_is_never_probed_for_a_redirect_destination() {
        // Two requests per header against somebody's system, for a behaviour that does
        // not exist. Header-driven redirects are real and are a different check.
        let mut exchange = exchange(302, Some("/dashboard"));
        exchange.request_headers.set("User-Agent", "curl/8");
        exchange
            .request_headers
            .set("Referer", "https://x.example/");

        let raised = suspect(&exchange);
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(
            raised[0].location.as_ref().map(|l| l.part),
            Some(MessagePart::Query)
        );
    }

    #[test]
    fn only_an_endpoint_that_actually_redirected_is_worth_probing() {
        assert_eq!(suspect(&exchange(302, Some("/dashboard"))).len(), 1);
        assert_eq!(suspect(&exchange(301, Some("/x"))).len(), 1);

        // Redirect status with no Location, and a 200 with one. Neither redirects.
        assert!(suspect(&exchange(302, None)).is_empty());
        assert!(suspect(&exchange(200, Some("/x"))).is_empty());
        assert!(suspect(&exchange(404, None)).is_empty());
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        let raised = suspect(&exchange(302, Some("/dashboard")));
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        assert!(raised[0].claim.contains("`next`"), "{}", raised[0].claim);
        assert!(
            raised[0].claim.contains("needs a request"),
            "{}",
            raised[0].claim
        );
    }

    #[test]
    fn the_probe_destinations_can_never_exist() {
        // RFC 2606 reserves `.invalid`. A destination somebody could register would
        // eventually turn an old report into a live redirect to a real attacker.
        for host in [PROBE_HOST, SECOND_PROBE_HOST] {
            assert!(host.ends_with(".invalid"), "{host}");
        }
        assert_ne!(PROBE_HOST, SECOND_PROBE_HOST);
    }

    #[test]
    fn a_subject_carries_the_endpoint_the_suspicion_was_raised_from() {
        let subject = subject();
        assert_eq!(subject.exchange.status, 302);
        assert!(subject.draft.request.path.contains("next="));
    }

    #[test]
    fn only_a_destination_this_check_named_counts_as_taken() {
        // A page that redirects to its own identity provider on every request is not a
        // caller-controlled redirect, however far off-host it goes.
        let elsewhere = answer("https://login.microsoftonline.com/");
        assert_eq!(took(&elsewhere), None);

        let ours = answer(&format!("https://{PROBE_HOST}/"));
        assert_eq!(took(&ours), Some(PROBE_HOST.to_string()));
    }

    #[test]
    fn a_destination_merely_carried_in_the_header_is_not_taken() {
        let carried = answer(&format!(
            "https://app.example.com/login?next=https://{PROBE_HOST}/"
        ));
        assert_eq!(took(&carried), None);
    }

    #[test]
    fn severity_never_reaches_high_for_a_redirect() {
        // What an open redirect is worth depends on what the endpoint does before it
        // redirects and on what travels with the user. That is a tester's judgement.
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
            let severity = severity_for(&verification);
            assert!(
                severity <= Severity::Medium,
                "{severity:?} overstates a redirect"
            );
        }
    }

    fn subject() -> Subject {
        let exchange = exchange(302, Some("/dashboard"));
        Subject {
            hypothesis: Hypothesis {
                source_request: exchange.id,
                ..raised(SETTLES)
            },
            draft: hexora_repeater::Draft::new(hexora_types::http::HttpRequest::get(
                hexora_types::http::HttpService::new("app.example.com", 443, true),
                "/login?next=/dashboard",
            )),
            target: exchange.target,
            exchange,
            identities: std::sync::Arc::new(Vec::new()),
        }
    }

    fn answer(location: &str) -> Answer {
        Answer {
            request: hexora_types::ids::RequestId::new(),
            status: 302,
            redirected: true,
            destination: resolve("app.example.com", location),
            sent: String::new(),
        }
    }
}
