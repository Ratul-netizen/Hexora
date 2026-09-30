//! `cache.poisoning` — can an unkeyed header change what a cache stores and serves?
//!
//! A cache in front of an application keeps one stored copy per *cache key* — usually
//! the method and URL, sometimes a few headers. Anything the response depends on that is
//! **not** in the key is a way to poison the store: change it, and the altered response
//! is cached and handed to everyone whose request produces the same key.
//!
//! ```text
//! request  GET /?cb=x   X-Forwarded-Host: nhABC.nullhawk-probe.invalid
//!   response reflects nhABC… in a generated URL, and is cached under (GET, /?cb=x)
//!
//! request  GET /?cb=x   (no such header — a "victim")
//!   response STILL contains nhABC…  → it came from the cache, poisoned
//! ```
//!
//! The proof needs no cache-status header: the victim request never carried the header
//! that produces the marker, so a marker in its response can only have come from a store.
//! The marker is a fresh random token, so its presence can never be a coincidence.
//!
//! # It never poisons a real user's cache entry
//!
//! Every probe carries a unique `nhcb=<token>` query parameter, so the cache key it
//! writes is one only this run uses. A real visitor's request produces a different key
//! and is never served the poisoned copy. This is the one rule that makes cache-poisoning
//! testing safe to run against a live cache, and it is not optional here — the buster is
//! on every request the check sends.
//!
//! # Only where a cache is plausibly in front
//!
//! Raised only for a response that showed a cache is involved — an `Age` or cache-status
//! header, or `Cache-Control: public`/a positive `max-age`. Probing an endpoint nothing
//! caches would send traffic to answer a question whose answer is already "there is no
//! cache to poison".

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
pub struct CachePoisoning;

const SETTLES: &str = "cache.poisoning";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cache.poisoning"),
    name: "Web cache poisoning",
    version: "1.0.0",
    about: "whether an unkeyed request header changes a cached response, so the altered \
            copy is served to other callers",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Headers a cache commonly leaves out of its key, and which an application commonly
/// reflects into a generated absolute URL, canonical link or redirect.
///
/// `Forwarded` takes a `host=` value; the rest take a bare host. All point at a
/// `.nullhawk-probe.invalid` marker (RFC 2606: never resolves, cannot name a real site).
const HOST_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
];

#[async_trait]
impl ActiveCheck for CachePoisoning {
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
        let mut reflected_but_uncached: Option<&str> = None;

        let mut sent = 0usize;
        for header in HOST_HEADERS {
            // Two requests per header — the poison and the victim. Stop before a header
            // that the budget cannot pay for both halves of.
            if sent + 2 > budget.per_hypothesis.max(2) {
                break;
            }

            // A fresh cache key and a fresh marker for each header, so a poison stored
            // for one candidate cannot be read back while testing the next.
            let buster = fresh_token();
            let marker = format!("nh{}.nullhawk-probe.invalid", fresh_token());
            let value = if *header == "Forwarded" {
                format!("host={marker}")
            } else {
                marker.clone()
            };

            // The poison: the same URL (cache-busted), with the unkeyed header set.
            let Some(poison) = probe(subject, lab, &buster, Some((header, &value))).await else {
                continue;
            };
            sent += 1;
            if !poison.has(&marker) {
                // The header changed nothing that reached the response — not a vector.
                continue;
            }

            // The victim: the same cache key, with no such header. A marker here was not
            // produced by this request, so it was served from the store.
            let Some(victim) = probe(subject, lab, &buster, None).await else {
                // The poison reflected but the confirming fetch did not complete: a lead,
                // not a proven cache hit.
                return Ok(Verification::Supported {
                    support: Support::Consistent,
                    note: format!(
                        "{where_} reflected an unkeyed `{header}` into its response, but \
                         the request that would show whether a cache stored it did not \
                         complete",
                    ),
                    evidence: vec![from_exchange(subject), answered(&poison, header, "set")],
                });
            };
            sent += 1;

            if victim.has(&marker) {
                return Ok(Verification::Reproduced {
                    note: format!(
                        "{where_} reflects the unkeyed `{header}` header, and a request \
                         carrying no such header was served the reflected value from the \
                         cache — the response is poisoned for everyone whose request keys \
                         the same way",
                    ),
                    evidence: vec![
                        from_exchange(subject),
                        answered(&poison, header, "set to a marker"),
                        Evidence::Comparison {
                            baseline: poison.request,
                            variant: victim.request,
                            difference: format!(
                                "the marker injected through `{header}` came back on a \
                                 request that did not send it — served from the cache"
                            ),
                        },
                    ],
                });
            }

            // Reflected, but the victim did not get it: the response is not cached on this
            // key, or the header is in the key after all. Remembered in case nothing
            // stronger turns up, so the report can still say the header is reflected.
            reflected_but_uncached.get_or_insert(header);
        }

        if let Some(header) = reflected_but_uncached {
            return Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "{where_} reflects the unkeyed `{header}` header into its response, but \
                     a following request with no such header did not receive the reflected \
                     value — so it is not being cached across callers on the key tested. \
                     The reflection is real and worth a look by hand; the poisoning is not \
                     confirmed",
                ),
                evidence: vec![from_exchange(subject)],
            });
        }

        Ok(Verification::Refuted {
            note: format!(
                "no unkeyed header this check tried changed a cached response for \
                 {where_}: each was either ignored or already part of the cache key",
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let confirmed = matches!(verification, Verification::Reproduced { .. });
        Writeup {
            target: subject.target,
            title: if confirmed {
                format!("Web cache poisoning in {}", where_(subject))
            } else {
                format!("Unkeyed header reflected by {}", where_(subject))
            },
            description: format!(
                "{} is served through a cache, and a request header the cache does not \
                 include in its key changes the response. {}\n\nEvery probe carried a \
                 unique cache-busting parameter, so the test poisoned only a key nobody \
                 else uses.",
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: if confirmed {
                "An attacker who sends one request can store a response of their making in \
                 the shared cache, and everyone whose request keys the same way is served \
                 it until the entry expires. Depending on what the header reaches, that is \
                 a redirect to an attacker's host, an imported script from one, or a \
                 defaced page — delivered by the site's own cache to ordinary visitors who \
                 did nothing."
                    .into()
            } else {
                "A request header the cache ignores changes the response. On its own that \
                 is a reflection, not a stored one; it becomes cache poisoning only if the \
                 altered response is cached and served to others, which was not shown \
                 here. It is worth confirming by hand with the real cache's behaviour in \
                 view."
                    .into()
            },
            remediation: "Include every header the response depends on in the cache key, \
                          or stop the response depending on headers the cache ignores. Do \
                          not reflect `X-Forwarded-Host` and its kin into absolute URLs, \
                          links or redirects; derive those from a configured canonical \
                          host instead."
                .into(),
            reproduction: format!(
                "Send {} {} with a unique cache-buster and an unkeyed host header (e.g. \
                 `X-Forwarded-Host`) carrying a marker, then send the same URL with no \
                 such header and see the marker come back from the cache. `nullhawk poc \
                 <project> <finding>` compiles the exact requests.",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            cwe: Some("CWE-524".into()),
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

struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    haystack: String,
}

impl Answer {
    /// Whether the marker appears anywhere a reflected host tends to land — the body or a
    /// response header value (a `Location`, a `Link`, a `Content-Location`).
    fn has(&self, needle: &str) -> bool {
        self.haystack.contains(needle)
    }
}

/// Sends the captured request with a cache-buster and, optionally, one added header.
async fn probe(
    subject: &Subject,
    lab: &dyn Lab,
    buster: &str,
    header: Option<(&str, &str)>,
) -> Option<Answer> {
    let mut draft = subject.draft.clone();
    draft.request.path = with_cache_buster(&draft.request.path, buster);
    if let Some((name, value)) = header {
        draft.request.headers.set(name, value);
    }
    let sent = lab.experiment(&draft, None).await.ok()?;

    // The marker can surface in the body or in a response header, so both are searched.
    let response = &sent.exchange.response;
    let mut haystack = String::from_utf8_lossy(&response.body).into_owned();
    for header in response.headers.iter() {
        haystack.push('\n');
        haystack.push_str(&header.value_lossy());
    }

    Some(Answer {
        request: sent.id,
        status: response.status,
        haystack,
    })
}

/// Appends a unique query parameter, so the cache key this request writes is one only
/// this run uses.
fn with_cache_buster(path: &str, token: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}nhcb={token}")
}

/// A fresh, unguessable, URL-safe token — for a cache-buster nobody else uses and a
/// marker that cannot occur by coincidence. Hex, so it is safe in a query value and a
/// hostname label alike.
fn fresh_token() -> String {
    uuid::Uuid::now_v7().simple().to_string()[..24].to_string()
}

fn answered(answer: &Answer, header: &str, how: &str) -> Evidence {
    Evidence::Exchange {
        request: answer.request,
        response: None,
        note: format!("`{header}` {how} — answered {}", answer.status),
    }
}

fn from_exchange(subject: &Subject) -> Evidence {
    Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {}, served through a cache",
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

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Whether a captured response shows a cache is plausibly in front of it.
///
/// The precondition for the whole question: an `Age` or cache-status header, which a
/// cache adds, or a `Cache-Control` that invites storage. Absent all of these there is
/// nothing to poison, and raising the work item would send traffic to learn that.
fn looks_cacheable(exchange: &nullhawk_scan::Exchange) -> bool {
    let headers = &exchange.response_headers;
    if headers.get("age").is_some() {
        return true;
    }
    for name in [
        "x-cache",
        "cf-cache-status",
        "cache-status",
        "x-varnish-cache",
    ] {
        if headers
            .get(name)
            .map(|h| h.value_lossy().to_ascii_lowercase().contains("hit"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    let control = headers
        .get_all("cache-control")
        .map(|h| h.value_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(", ");
    if control.contains("no-store") || control.contains("private") {
        return false;
    }
    control.contains("public") || positive_max_age(&control)
}

fn positive_max_age(control: &str) -> bool {
    control.split(',').any(|part| {
        part.trim()
            .strip_prefix("max-age=")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_some_and(|s| s > 0)
    })
}

/// Raises one suspicion per cacheable endpoint — a work item at `Info`, settled by an
/// experiment. Per endpoint, not per input: the inputs it tries are headers it adds, not
/// ones the request already carries.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    // Only safe methods reach here from the scheduler, but a cache stores `GET`, so the
    // question is only meaningful for one.
    if !exchange.method.eq_ignore_ascii_case("GET") {
        return Vec::new();
    }
    if !(200..400).contains(&exchange.status) {
        return Vec::new();
    }
    if !looks_cacheable(exchange) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} is served through a cache — whether an unkeyed header can poison it \
             needs a request",
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
        cache_control: &[(&str, &str)],
        status: u16,
        method: &str,
    ) -> nullhawk_scan::Exchange {
        let mut headers = Headers::new();
        for &(n, v) in cache_control {
            headers.set(n, v);
        }
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "shop.example".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://shop.example/home".into(),
            path: "/home".into(),
            status,
            request_headers: Headers::new(),
            response_headers: headers,
            response_bytes: 100,
            authenticated: false,
            tls: None,
            sent_at: "2026-09-30T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_only_its_own_suspicion() {
        assert!(CachePoisoning.handles(&raised(SETTLES)));
        assert!(!CachePoisoning.handles(&raised("cache.exposure")));
        assert!(!CachePoisoning.handles(&raised("input.cmdi")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = CachePoisoning.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn a_cacheable_get_is_worth_probing() {
        for cc in [
            vec![("Cache-Control", "public, max-age=600")],
            vec![("Cache-Control", "max-age=30")],
            vec![("Age", "12")],
            vec![("X-Cache", "HIT")],
            vec![("CF-Cache-Status", "HIT")],
        ] {
            assert_eq!(
                suspect(&exchange_with(&cc, 200, "GET")).len(),
                1,
                "{cc:?} was not seen as cacheable"
            );
        }
    }

    #[test]
    fn an_uncacheable_or_private_response_is_left_alone() {
        for cc in [
            vec![],
            vec![("Cache-Control", "no-store")],
            vec![("Cache-Control", "private, max-age=60")],
            vec![("Cache-Control", "max-age=0")],
            vec![("X-Cache", "MISS")],
        ] {
            assert!(
                suspect(&exchange_with(&cc, 200, "GET")).is_empty(),
                "{cc:?} was probed though nothing said a cache stores it"
            );
        }
    }

    #[test]
    fn a_non_get_or_error_response_is_never_probed() {
        let cc = vec![("Cache-Control", "public")];
        assert!(suspect(&exchange_with(&cc, 200, "POST")).is_empty());
        assert!(suspect(&exchange_with(&cc, 500, "GET")).is_empty());
    }

    #[test]
    fn the_cache_buster_is_added_as_a_fresh_parameter() {
        assert_eq!(with_cache_buster("/home", "abc"), "/home?nhcb=abc");
        assert_eq!(with_cache_buster("/home?q=1", "abc"), "/home?q=1&nhcb=abc");
    }

    #[test]
    fn confirmed_poisoning_is_high_and_a_bare_reflection_is_low() {
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

    #[test]
    fn the_marker_is_searched_in_body_and_headers() {
        let a = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            haystack: "body text\nhttps://nhABC.nullhawk-probe.invalid/login".into(),
        };
        assert!(a.has("nhABC.nullhawk-probe.invalid"));
        assert!(!a.has("nhZZZ.nullhawk-probe.invalid"));
    }
}
