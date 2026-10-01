//! `input.crlf` — whether an input can inject a header by carrying a line break.
//!
//! A value reflected into a *response header* — a `Location` built from a `?url=`, a
//! `Set-Cookie` echoing a preference — that is placed there without stripping control
//! characters lets the input add headers of its own:
//!
//! ```text
//! ?next=/home%0d%0aX-Nullhawk-Crlf: <token>
//!   → HTTP/1.1 302
//!     Location: /home
//!     X-Nullhawk-Crlf: <token>      ← a header the input wrote
//! ```
//!
//! The tell is unambiguous and needs no guessing: the payload names a header with a fresh
//! random token, and either that exact header comes back on the response or it does not.
//! A random token can appear for no other reason than the injection, so a match is the
//! finding, confirmed by a second token in a second request.
//!
//! # Only a line break, never a smuggled request
//!
//! The break is carried percent-encoded (`%0d%0a`), which [`substitute`] passes through
//! untouched — it refuses only a *raw* CR or LF, the kind that would split the request
//! this check itself sends. The decoded break lands in the *response*, where the server
//! put the value, and the only header the payload adds is an inert marker: nothing here
//! sets a cookie, redirects a victim or poisoned a cache. Proving the break is honoured
//! is the whole experiment; weaponising it is the tester's call.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::inject::{inputs, inputs_in, substitute, value_at};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct CrlfInjection;

const SETTLES: &str = "input.crlf";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.crlf"),
    name: "HTTP header injection (CRLF)",
    version: "1.0.0",
    about: "whether an input reflected into a response header can add a header of its own \
            by carrying an encoded line break",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

/// The header the payload tells the server to emit. If it comes back, the break was
/// honoured — the name is distinctive so it cannot be one the application already sends.
const MARKER: &str = "X-Nullhawk-Crlf";

/// Ways to carry the break, tried in turn. The first is the plain encoding; the second is
/// LF alone, which some servers accept where they reject CRLF; the third is the
/// overlong-UTF-8 pair (`ꘊ꘍`) that a few parsers fold down to CR and LF.
const BREAKS: &[(&str, &str)] = &[
    ("CRLF", "%0d%0a"),
    ("LF", "%0a"),
    ("unicode", "%E5%98%8A%E5%98%8D"),
];

#[async_trait]
impl ActiveCheck for CrlfInjection {
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
                    "the input this was raised about is no longer in {} {}, so there was \
                     nothing to inject into",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();

        let mut spent = 0usize;
        for (kind, br) in BREAKS {
            if spent + 1 > budget.per_hypothesis.max(1) {
                break;
            }
            let token = fresh_token();
            let payload = format!("{base}{br}{MARKER}:%20{token}");
            let Some(first) = probe(subject, lab, &slot, &payload).await else {
                continue;
            };
            spent += 1;
            if first.marker.as_deref() != Some(token.as_str()) {
                continue; // the break was not honoured through this encoding
            }

            // Confirm with a second, different token. A header carrying a value the
            // application never saw, twice, is the input writing the header — not a fixed
            // one it happens to send.
            if spent < budget.per_hypothesis.max(1) {
                let token2 = fresh_token();
                let payload2 = format!("{base}{br}{MARKER}:%20{token2}");
                if let Some(second) = probe(subject, lab, &slot, &payload2).await {
                    if second.marker.as_deref() == Some(token2.as_str()) {
                        return Ok(Verification::Reproduced {
                            note: format!(
                                "{} injected a response header: a {kind} line break in the \
                                 input added `{MARKER}` carrying a value only this request \
                                 supplied, and a second request with a different value did \
                                 the same — the input writes response headers",
                                describe(&slot),
                            ),
                            evidence: vec![
                                from_exchange(subject),
                                Evidence::Comparison {
                                    baseline: first.request,
                                    variant: second.request,
                                    difference: format!(
                                        "each request's `{MARKER}` header carried back the \
                                         exact token its payload placed after a {kind} break"
                                    ),
                                },
                            ],
                        });
                    }
                }
            }

            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{} added a `{MARKER}` response header through a {kind} line break, \
                     carrying a value only this request supplied; the confirming second \
                     request was not sent",
                    describe(&slot),
                ),
                evidence: vec![from_exchange(subject), answered(&first, &payload)],
            });
        }

        Ok(Verification::Refuted {
            note: format!(
                "no encoded line break in {} added a header to the response — the input is \
                 not reflected into a response header, or the break is stripped before it \
                 is",
                describe(&slot),
            ),
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
                "HTTP header injection in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is reflected into a response header \
                 with its line breaks intact, so the input can end the current header and \
                 start one of its own. {}\n\nThe evidence records the injected marker \
                 header and the token each request placed in it.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "Whoever controls a response header controls more than one line of it. \
                     Depending on where the value lands, that is a `Set-Cookie` fixing a \
                     victim's session, a redirect to an attacker's host, cache poisoning \
                     from an injected caching directive, or — where a blank line can be \
                     reached — a second response body spliced in front of the real one."
                .into(),
            remediation: "Strip or reject CR and LF in any value placed into a response \
                          header, at the point the header is built. Prefer a framework API \
                          that sets headers structurally over string concatenation, and \
                          never build a `Location` or `Set-Cookie` from unvalidated input."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} carrying `…%0d%0a{MARKER}: <token>` and read the \
                 response headers for `{MARKER}` echoing the token. `nullhawk poc \
                 <project> <finding>` compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-113".into()),
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

/// One probe and the marker header it did or did not carry back.
struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    /// The value of the injected marker header, if the response carried one.
    marker: Option<String>,
}

/// Places a payload and reads the response for the injected marker header.
async fn probe(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    value: &str,
) -> Option<Answer> {
    let mut draft = subject.draft.clone();
    draft.request = substitute(&draft.request, slot, value).ok()?;
    let sent = lab.experiment(&draft, None).await.ok()?;
    let response = &sent.exchange.response;
    let marker = response
        .headers
        .get(MARKER)
        .map(|header| header.value_lossy().trim().to_string());
    Some(Answer {
        request: sent.id,
        status: response.status,
        marker,
    })
}

fn fresh_token() -> String {
    // The whole UUID, not a prefix: a v7's leading hex is a millisecond timestamp, so two
    // minted in the same millisecond would share it — and a marker token has to be unique
    // per request or the confirming probe cannot tell its callback from the first.
    uuid::Uuid::now_v7().simple().to_string()
}

fn answered(answer: &Answer, payload: &str) -> Evidence {
    Evidence::Exchange {
        request: answer.request,
        response: None,
        note: format!(
            "payload `{payload}` — answered {} with `{MARKER}: {}`",
            answer.status,
            answer.marker.as_deref().unwrap_or("(absent)"),
        ),
    }
}

fn from_exchange(subject: &Subject) -> Evidence {
    Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {}",
            subject.exchange.method, subject.exchange.url
        ),
    }
}

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

/// Raises one suspicion per input — a work item at `Info`, settled by an experiment.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        .map(|slot| Hypothesis {
            detector: SETTLES.to_string(),
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
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    #[test]
    fn it_settles_only_crlf_suspicions() {
        assert!(CrlfInjection.handles(&raised(SETTLES)));
        assert!(!CrlfInjection.handles(&raised("input.sqli")));
        assert!(!CrlfInjection.handles(&raised("input.cmdi")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = CrlfInjection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn a_returned_marker_matching_the_token_is_the_tell() {
        // The whole detection: the marker header comes back carrying exactly the token
        // this request placed. A random token cannot appear for another reason.
        let hit = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 302,
            marker: Some("abc123def456".into()),
        };
        assert_eq!(hit.marker.as_deref(), Some("abc123def456"));
        let miss = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            marker: None,
        };
        assert_eq!(miss.marker, None);
    }

    #[test]
    fn the_breaks_include_crlf_lf_and_the_unicode_bypass() {
        let kinds: Vec<&str> = BREAKS.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&"CRLF"));
        assert!(kinds.contains(&"LF"));
        assert!(kinds.contains(&"unicode"));
        // The plain CRLF is the standard percent-encoded pair.
        assert_eq!(BREAKS[0].1, "%0d%0a");
    }

    #[test]
    fn tokens_are_fresh_and_hex() {
        let a = fresh_token();
        let b = fresh_token();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
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
            severity_for(&Verification::Refuted {
                note: String::new()
            }),
            Severity::Low
        );
    }
}
