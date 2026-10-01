//! `host.injection` — does the application build absolute URLs from a spoofable host?
//!
//! A server behind a proxy often trusts `X-Forwarded-Host` (or the `Host` header itself)
//! to know what it is called, and builds absolute URLs from it — a canonical link, a
//! redirect, and most dangerously a password-reset link mailed to a user:
//!
//! ```text
//! X-Forwarded-Host: nhHOST.nullhawk-probe.invalid
//!   → <a href="https://nhHOST.nullhawk-probe.invalid/reset?token=…">reset</a>
//!         or  Location: https://nhHOST.nullhawk-probe.invalid/…
//! ```
//!
//! Where that URL is a reset link, an attacker who sets the header on a victim's
//! reset request receives the victim's token when they click — account takeover from one
//! spoofed header. This proves the precondition: the host the caller supplied reaches an
//! absolute URL in the response. The marker is a fresh `.invalid` host (RFC 2606, never
//! resolves), and a match inside a URL — not merely reflected as text — is the tell,
//! confirmed by a second marker.
//!
//! # Distinct from cache poisoning
//!
//! `cache.poisoning` asks whether an unkeyed header's effect is *stored and served to
//! others*; this asks whether the host reaches a *generated URL* at all, which is the
//! reset-poisoning question and does not need a cache. They share the vector and answer
//! different questions.
//!
//! # Only where a URL could be built
//!
//! Raised for an HTML response or a redirect — the places an absolute URL surfaces —
//! never for a plain data endpoint that has no links to build.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct HostHeaderInjection;

const SETTLES: &str = "host.injection";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("host.injection"),
    name: "Host header injection",
    version: "1.0.0",
    about: "whether the application builds an absolute URL from a spoofable host header, \
            the precondition for password-reset poisoning",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

/// Headers a proxy-fronted application commonly trusts for its own host. `Forwarded`
/// carries a `host=` value; the rest carry a bare host.
const HOST_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "Forwarded",
];

#[async_trait]
impl ActiveCheck for HostHeaderInjection {
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
        let where_ = where_(subject);
        let mut reflected_as_text: Option<&str> = None;

        let mut spent = 0usize;
        for header in HOST_HEADERS {
            if spent + 1 > budget.per_hypothesis.max(1) {
                break;
            }
            let marker = format!("nh{}.nullhawk-probe.invalid", fresh_token());
            let value = if *header == "Forwarded" {
                format!("host={marker}")
            } else {
                marker.clone()
            };

            let Some(first) = probe(subject, lab, header, &value).await else {
                continue;
            };
            spent += 1;
            match first.landed(&marker) {
                Landing::InUrl => {}
                Landing::AsText => {
                    reflected_as_text.get_or_insert(header);
                    continue;
                }
                Landing::Absent => continue,
            }

            // Confirm with a second marker: a fixed URL the app always emits would not
            // carry a value this request invented, twice.
            let marker2 = format!("nh{}.nullhawk-probe.invalid", fresh_token());
            let value2 = if *header == "Forwarded" {
                format!("host={marker2}")
            } else {
                marker2.clone()
            };
            if spent < budget.per_hypothesis.max(1) {
                if let Some(second) = probe(subject, lab, header, &value2).await {
                    if let Landing::InUrl = second.landed(&marker2) {
                        return Ok(Verification::Reproduced {
                            note: format!(
                                "{where_} builds an absolute URL from the `{header}` header: \
                                 a host supplied there came back inside a URL in the \
                                 response ({}), and a second, different host did the same. \
                                 A reset link built this way is sent to wherever the header \
                                 says",
                                first.where_found,
                            ),
                            evidence: vec![
                                from_exchange(subject),
                                Evidence::Comparison {
                                    baseline: first.request,
                                    variant: second.request,
                                    difference: format!(
                                        "each request's `{header}` host appeared in an \
                                         absolute URL in the response"
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
                    "{where_} placed a host supplied in `{header}` into an absolute URL in \
                     the response ({}); the confirming second request was not sent",
                    first.where_found,
                ),
                evidence: vec![from_exchange(subject), answered(&first, header)],
            });
        }

        if let Some(header) = reflected_as_text {
            return Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "{where_} reflects the `{header}` host into the response, but as text \
                     rather than inside a URL. It is worth a look by hand for where that \
                     value is used; a reset-link built from it is not confirmed here",
                ),
                evidence: vec![from_exchange(subject)],
            });
        }

        Ok(Verification::Refuted {
            note: format!(
                "no spoofed host header reached an absolute URL in {where_}'s response — \
                 the application does not build its URLs from a header the caller controls",
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let confirmed = matches!(verification, Verification::Reproduced { .. });
        Writeup {
            target: subject.target,
            title: if confirmed {
                format!("Host header injection in {}", where_(subject))
            } else {
                format!("Spoofable host reflected by {}", where_(subject))
            },
            description: format!(
                "{} builds an absolute URL in its response from a host header the caller \
                 supplies. {}\n\nThe marker host was a `.invalid` name that can never \
                 resolve, placed only to prove the value reaches a URL.",
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "An attacker who sets the host header on another user's request steers \
                     the absolute URLs the application builds for it. Where one is a \
                     password-reset link, the reset token is mailed to the attacker's host \
                     and the account is taken over; elsewhere it is a redirect or an \
                     imported resource pointed at a host of the attacker's choosing."
                .into(),
            remediation: "Do not build absolute URLs from the `Host` or `X-Forwarded-Host` \
                          header. Configure the application's canonical host explicitly and \
                          build URLs from that. If a proxy must pass the original host, \
                          validate it against an allowlist before any URL is built from it."
                .into(),
            reproduction: format!(
                "Send {} {} with `X-Forwarded-Host: <marker>` and read the response for the \
                 marker appearing inside an absolute URL (a link or a Location header). \
                 `nullhawk poc <project> <finding>` compiles the exact requests.",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            cwe: Some("CWE-644".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: Some(Location {
                part: MessagePart::Header,
                name: "X-Forwarded-Host".into(),
            }),
        }
    }
}

fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        Verification::Supported { .. } => Severity::Low,
        _ => Severity::Low,
    }
}

/// Where a marker host turned up, if at all.
#[derive(Debug, PartialEq, Eq)]
enum Landing {
    /// Inside an absolute URL — the finding.
    InUrl,
    /// In the response, but only as plain text.
    AsText,
    /// Not present.
    Absent,
}

struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    body: String,
    location: Option<String>,
    where_found: String,
}

impl Answer {
    fn landed(&self, marker: &str) -> Landing {
        // In a URL: after `//` (covers `https://`, `http://` and protocol-relative), or
        // as the whole of a `Location` the response redirects to.
        if self.body.contains(&format!("//{marker}")) {
            return Landing::InUrl;
        }
        if let Some(location) = &self.location {
            if location.contains(marker) {
                return Landing::InUrl;
            }
        }
        if self.body.contains(marker) {
            return Landing::AsText;
        }
        Landing::Absent
    }
}

/// Sends the captured request with one host header added, and reads the response.
async fn probe(subject: &Subject, lab: &dyn Lab, header: &str, value: &str) -> Option<Answer> {
    let mut draft = subject.draft.clone();
    draft.request.headers.set(header, value);
    let sent = lab.experiment(&draft, None).await.ok()?;
    let response = &sent.exchange.response;
    let body = String::from_utf8_lossy(&response.body).into_owned();
    let location = response
        .headers
        .get("location")
        .map(|h| h.value_lossy().into_owned());
    // For the evidence note: name where the marker was seen without quoting a whole page.
    let where_found = if location.is_some() {
        "a Location header".to_string()
    } else {
        "a link in the body".to_string()
    };
    Some(Answer {
        request: sent.id,
        status: response.status,
        body,
        location,
        where_found,
    })
}

fn answered(answer: &Answer, header: &str) -> Evidence {
    Evidence::Exchange {
        request: answer.request,
        response: None,
        note: format!(
            "`{header}` set to a marker host — answered {}, marker in {}",
            answer.status, answer.where_found
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

fn where_(subject: &Subject) -> String {
    format!(
        "{} {}",
        subject.exchange.method,
        path_of(&subject.exchange.url)
    )
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

fn fresh_token() -> String {
    uuid::Uuid::now_v7().simple().to_string()[..12].to_string()
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Whether a response is one where an absolute URL might be built — HTML, or a redirect.
fn builds_urls(exchange: &nullhawk_scan::Exchange) -> bool {
    if (300..400).contains(&exchange.status) || exchange.response_headers.get("location").is_some()
    {
        return true;
    }
    exchange
        .response_headers
        .get("content-type")
        .map(|h| h.value_lossy().to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// Raises one suspicion per endpoint that could build an absolute URL. Per endpoint, not
/// per input: the input it tries is the host header, not one the request already carries.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if crate::schedule::is_state_changing(&exchange.method) {
        return Vec::new();
    }
    if !(200..400).contains(&exchange.status) {
        return Vec::new();
    }
    if !builds_urls(exchange) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} returns URLs or a redirect — whether it builds them from a spoofable \
             host needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: Some(Location {
            part: MessagePart::Header,
            name: "X-Forwarded-Host".into(),
        }),
        provisional_severity: Severity::Info,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullhawk_types::http::Headers;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange_with(
        headers: &[(&str, &str)],
        status: u16,
        method: &str,
    ) -> nullhawk_scan::Exchange {
        let mut response_headers = Headers::new();
        for &(n, v) in headers {
            response_headers.set(n, v);
        }
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "shop.example".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://shop.example/account".into(),
            path: "/account".into(),
            status,
            request_headers: Headers::new(),
            response_headers,
            response_bytes: 100,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_only_its_own_suspicion() {
        assert!(HostHeaderInjection.handles(&raised(SETTLES)));
        assert!(!HostHeaderInjection.handles(&raised("cache.poisoning")));
        assert!(!HostHeaderInjection.handles(&raised("input.xss")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = HostHeaderInjection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn html_responses_and_redirects_are_worth_probing() {
        assert_eq!(
            suspect(&exchange_with(&[("Content-Type", "text/html")], 200, "GET")).len(),
            1
        );
        assert_eq!(
            suspect(&exchange_with(&[("Location", "/login")], 302, "GET")).len(),
            1
        );
    }

    #[test]
    fn data_responses_and_unsafe_methods_are_left_alone() {
        assert!(suspect(&exchange_with(
            &[("Content-Type", "application/json")],
            200,
            "GET"
        ))
        .is_empty());
        assert!(suspect(&exchange_with(
            &[("Content-Type", "text/html")],
            200,
            "POST"
        ))
        .is_empty());
        assert!(suspect(&exchange_with(&[("Content-Type", "text/html")], 500, "GET")).is_empty());
    }

    fn answer(body: &str, location: Option<&str>) -> Answer {
        Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            body: body.to_string(),
            location: location.map(|s| s.to_string()),
            where_found: String::new(),
        }
    }

    #[test]
    fn a_marker_inside_a_url_is_the_finding_and_plain_text_is_only_a_lead() {
        let m = "nhABC.nullhawk-probe.invalid";
        assert_eq!(
            answer(&format!("<a href=\"https://{m}/reset\">go</a>"), None).landed(m),
            Landing::InUrl
        );
        assert_eq!(
            answer("body", Some(&format!("https://{m}/x"))).landed(m),
            Landing::InUrl
        );
        assert_eq!(
            answer(&format!("<p>Your host is {m}</p>"), None).landed(m),
            Landing::AsText
        );
        assert_eq!(answer("nothing here", None).landed(m), Landing::Absent);
    }

    #[test]
    fn confirmed_injection_is_high_and_a_text_reflection_is_low() {
        assert_eq!(
            severity_for(&Verification::Reproduced {
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
            Severity::Low
        );
    }
}
