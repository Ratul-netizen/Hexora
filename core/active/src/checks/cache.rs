//! `cache.exposure` — is an authenticated response actually served to somebody else?
//!
//! `nullhawk_scan`'s `cache.sensitive` sees a response that was authenticated,
//! successful, had a body, and *asked to be stored* — `Cache-Control: public` or a
//! positive `max-age`. That is an invitation, not a finding: whether it matters depends
//! on something a captured exchange cannot show — whether a shared cache is in front of
//! this application, and whether it will hand one user's stored copy to another.
//!
//! ```text
//! captured   GET /me   (Alice's cookie)   →  200, Cache-Control: public, {"id":"acct-…alice"}
//! probe      GET /me   (no cookie)         →  200, X-Cache: HIT,          {"id":"acct-…alice"}
//!                                                   ▲ a cache                ▲ Alice's data
//! ```
//!
//! The second request is where the question is answered. It is the same URL with the
//! credential removed, and two independent things have to be true before this is a
//! finding, because either alone is something innocent:
//!
//! * **the response came from a cache** — an `Age` header (RFC 9111 says only a cache
//!   adds one) or a cache-status header reporting a `HIT`. Without this, a body that
//!   matches is a missing-session problem, which is [`auth.unverified`]'s to report,
//!   not evidence a *cache* is doing anything;
//! * **the body carries somebody's declared data** — an object identifier a person
//!   declared as owned, found in a document handed to a caller with no session. Without
//!   this, a cached copy served to nobody is indistinguishable from a public page that
//!   is *meant* to be cached, which is the far commoner thing.
//!
//! The ownership test, and the reason it is drawn exactly here, are the same as
//! [`auth::owned_id_in`](super::auth): Nullhawk does not decide what belongs to whom, so
//! it looks only at identifiers somebody declared and never at anything that merely
//! looks like one.
//!
//! # The credential is removed, never assumed absent
//!
//! Like the authentication check, the baseline is the captured request replayed as it
//! was. If replaying it no longer succeeds, the session has expired and the probe below
//! would look refused for a reason that has nothing to do with caching — that is
//! [`Verification::Inconclusive`], kept apart from [`Verification::Refuted`] so "my
//! token ran out" is never reported as "the cache is safe".
//!
//! # Nothing that changes data is replayed
//!
//! The scheduler only queues `GET`, `HEAD` and `OPTIONS`, which is exactly where
//! caching lives — a cache does not store the response to a `POST /transfers`. The
//! constraint and this check want the same methods.

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
pub struct CacheExposure;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "cache.sensitive";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cache.exposure"),
    name: "Cached authenticated response",
    version: "1.0.0",
    about: "whether a shared cache serves one identity's authenticated response to a caller with no session",
    mode: DetectorMode::Active,
    observes: false,
    // It settles a passive check's suspicion and raises none of its own.
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Headers a cache in front of the origin uses to report a hit.
///
/// Deliberately excludes `X-Cache-Hits`, whose value is a count that is `0` on a miss —
/// a substring match for `hit` on the header *name* would read every one of those as a
/// hit.
const CACHE_STATUS_HEADERS: [&str; 7] = [
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "cache-status",
    "x-drupal-cache",
    "x-varnish-cache",
    "x-proxy-cache",
];

#[async_trait]
impl ActiveCheck for CacheExposure {
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
        // 1. The baseline: the captured, authenticated request, replayed as it was. A
        //    response that no longer succeeds means the session has expired, and every
        //    conclusion below would rest on a probe that was refused for the wrong
        //    reason.
        let baseline = match send(subject, lab, Probe::AsCaptured).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if !(200..300).contains(&baseline.status) || baseline.body.is_empty() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "replaying {} as it was captured answered {} with {} byte(s) of body, \
                     so the session it was captured with no longer serves the response \
                     that would be cached — nothing below would have meant anything",
                    where_(subject),
                    baseline.status,
                    baseline.body.len(),
                ),
            });
        }

        // 2. The same URL with every credential removed. This is the request a stranger
        //    — or the next visitor to a shared machine — would make.
        let anon = match send(subject, lab, Probe::WithoutCredential).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if anon.skipped {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} carried no credential this check knows how to remove, so a \
                     request with no session could not be formed and whether a cache \
                     would serve one was not tested",
                    where_(subject),
                ),
            });
        }

        match decide(subject, &baseline, &anon) {
            // The finding: a cache handed a caller with no session a document carrying
            // one identity's declared data. Confirmed with a second anonymous request
            // when the budget allows — the same experiment repeated, which is what
            // separates reproduced from a single lucky read.
            Decision::Exposed { id, signal } => {
                if budget.per_hypothesis >= 3 {
                    if let Attempt::Answered(again) =
                        send(subject, lab, Probe::WithoutCredential).await
                    {
                        if !again.skipped
                            && cache_signal(&again).is_some()
                            && owned_id_in(subject, &again.body).as_deref() == Some(id.as_str())
                        {
                            return Ok(Verification::Reproduced {
                                note: exposed_note(subject, &anon, &id, &signal, true),
                                evidence: evidence(subject, &baseline, &anon, Some(&again)),
                            });
                        }
                    }
                }
                Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: exposed_note(subject, &anon, &id, &signal, false),
                    evidence: evidence(subject, &baseline, &anon, None),
                })
            }
            // The declared data reached a caller with no session, but no header
            // attributes the response to a cache. It is still served to somebody else —
            // the suspicion is answered yes — yet whether a cache or the application
            // itself did it is not shown here. Reported as a lead, and pointed at the
            // check whose finding it may really be.
            Decision::Leaked { id } => Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "{} answered {} to a request with no credential, and the response \
                     contains {id}, which this project declares as belonging to an \
                     identity — so the authenticated response reached a caller with no \
                     session. No cache-status header was present, so whether a shared \
                     cache or the application served it is not established from here; if \
                     it is the application, auth.unverified is where that is settled",
                    where_(subject),
                    anon.status,
                ),
                evidence: evidence(subject, &baseline, &anon, None),
            }),
            // Served from a cache to a caller with no session, the same document as the
            // real session's — but nothing in it is declared as owned. A public page
            // that is cached normally looks exactly like this, and there is no way to
            // tell them apart from here.
            Decision::CachedButUnowned { signal } => Ok(Verification::Inconclusive {
                why: format!(
                    "{} was served to a request with no credential from a cache ({signal}), \
                     the same document as the real session received. That is what a cached \
                     private response looks like, and it is also exactly what a public page \
                     that is meant to be cached looks like — nothing in it belongs to a \
                     declared identity, so there is no way to tell them apart. Declare what \
                     an identity owns with `nullhawk identity add --owns` and run again",
                    where_(subject),
                ),
            }),
            Decision::Refuted { note } => Ok(Verification::Refuted { note }),
        }
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let note = verification.note();
        let served_from_cache = note.contains("a shared cache served");
        Writeup {
            target: subject.target,
            title: if served_from_cache {
                format!(
                    "A shared cache serves {} to a caller with no session",
                    where_(subject)
                )
            } else {
                format!(
                    "An authenticated response for {} reached a caller with no session",
                    where_(subject)
                )
            },
            description: format!(
                "{} was captured being served to an authenticated request, with cache \
                 directives that invited it to be stored. Replaying it established the \
                 session still works; replaying the same URL with no credential \
                 established what a stranger receives. {}",
                subject.exchange.url,
                sentence(note),
            ),
            impact: if served_from_cache {
                "One identity's authenticated response is sitting in a shared cache and \
                 is handed to callers who present no session at all. Anybody who reaches \
                 that cache — the next person on a shared machine, anyone behind the same \
                 proxy or CDN edge — reads it. What that is worth is whatever the \
                 response contains, and the evidence below shows it contains data this \
                 project declares as belonging to an identity."
                    .into()
            } else {
                "The response served to an authenticated request is reaching a caller \
                 with no session, and it contains data this project declares as \
                 belonging to an identity. Whether a shared cache or the application \
                 itself is responsible changes the remediation but not the exposure."
                    .into()
            },
            remediation: "Send `Cache-Control: no-store` (or `private` where only a \
                          browser cache is acceptable) on every response that contains \
                          one identity's data, so a shared cache never stores it. Where a \
                          cache is intended, make the credential part of the cache key so \
                          an unauthenticated request can never be answered from an \
                          authenticated entry, and send `Vary` accordingly."
                .into(),
            reproduction: format!(
                "Send {} with its session, then send the same request with the \
                 credential header removed, and read the cache-status headers (`Age`, \
                 `X-Cache`, `CF-Cache-Status`) and the body of the second response. \
                 `nullhawk poc <project> <finding>` compiles both requests, credentials \
                 replaced by placeholders.",
                subject.exchange.url,
            ),
            cwe: Some("CWE-525".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: Some(Location {
                part: MessagePart::Header,
                name: "Cache-Control".into(),
            }),
        }
    }
}

/// What the anonymous probe established, once compared with the baseline.
#[derive(Debug)]
enum Decision {
    /// A cache served declared-owned data to a caller with no session.
    Exposed { id: String, signal: String },
    /// Declared-owned data reached a caller with no session, but no cache said so.
    Leaked { id: String },
    /// A cache served the same document to a caller with no session, but nothing in it
    /// is declared as owned — indistinguishable from a normally-cached public page.
    CachedButUnowned { signal: String },
    /// Nothing here shows a cache serving one identity's response to another.
    Refuted { note: String },
}

/// The whole decision, factored out so the matrix can be tested without a [`Lab`].
fn decide(subject: &Subject, baseline: &Answer, anon: &Answer) -> Decision {
    // A caller turned away cannot be handed a cached copy. A different status — a 401, a
    // redirect to a login page — is the control working.
    if !(200..300).contains(&anon.status) {
        return Decision::Refuted {
            note: format!(
                "{} answered {} to a request with no credential, so a cache is not \
                 serving this response to an unauthenticated caller",
                where_(subject),
                anon.status,
            ),
        };
    }

    let owned = owned_id_in(subject, &anon.body);
    let signal = cache_signal(anon);

    match (signal, owned) {
        (Some(signal), Some(id)) => Decision::Exposed { id, signal },
        (None, Some(id)) => Decision::Leaked { id },
        (Some(signal), None) if baseline.body == anon.body => Decision::CachedButUnowned { signal },
        // A cache that served the anonymous caller a *different* document has its own,
        // correctly-separated entry for unauthenticated requests — the key includes the
        // session, which is what it should do.
        (Some(_), None) => Decision::Refuted {
            note: format!(
                "{} was served from a cache to a request with no credential, but a \
                 different document from the real session's — the cache keeps a separate \
                 entry for unauthenticated callers, which is the key working",
                where_(subject),
            ),
        },
        (None, None) => Decision::Refuted {
            note: format!(
                "{} answered a request with no credential without any cache-status \
                 header, so a shared cache serving this response could not be shown. If \
                 the concern is that the endpoint needs no session at all, that is \
                 auth.unverified's to settle",
                where_(subject),
            ),
        },
    }
}

/// The evidence a cache — rather than the origin — produced this response.
///
/// Two independent signals, either sufficient:
///
/// * a cache-status header reporting a `HIT`, which is a cache naming itself;
/// * an `Age` header. RFC 9111 §5.1 has only a cache generate one, so its presence means
///   the response was served from a store rather than freshly from the origin.
fn cache_signal(answer: &Answer) -> Option<String> {
    for (name, value) in &answer.headers {
        let lname = name.to_ascii_lowercase();
        if CACHE_STATUS_HEADERS.contains(&lname.as_str())
            && value.to_ascii_lowercase().contains("hit")
        {
            return Some(format!("{name}: {}", value.trim()));
        }
    }
    for (name, value) in &answer.headers {
        if name.eq_ignore_ascii_case("age") && value.trim().parse::<u64>().is_ok() {
            return Some(format!("Age: {}", value.trim()));
        }
    }
    None
}

/// An object identifier a person declared as owned, if one appears in the body.
///
/// Narrow on purpose, and drawn exactly where [`auth::owned_id_in`](super::auth) draws
/// it: only identifiers somebody declared, never anything that merely looks like one,
/// and never one short enough to match by accident.
fn owned_id_in(subject: &Subject, body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    subject
        .identities
        .iter()
        .flat_map(|identity| identity.owned_object_ids.iter())
        .filter(|id| id.len() >= 8)
        .find(|id| text.contains(id.as_str()))
        .cloned()
}

fn exposed_note(
    subject: &Subject,
    anon: &Answer,
    id: &str,
    signal: &str,
    reproduced: bool,
) -> String {
    format!(
        "a shared cache served {} to a request with no credential ({signal}), answered \
         {}, and the document it returned contains {id}, which this project declares as \
         belonging to an identity{}",
        where_(subject),
        anon.status,
        if reproduced {
            " — and a second anonymous request was answered the same way"
        } else {
            ""
        },
    )
}

/// `METHOD /path`, for a claim that names an endpoint rather than a host.
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

/// Severity, from what the experiment established.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        Verification::Supported { .. } => Severity::Medium,
        _ => Severity::Low,
    }
}

/// One request and what came back, with its headers flattened to owned strings so the
/// decision logic can be exercised without a live response.
struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    body: bytes::Bytes,
    headers: Vec<(String, String)>,
    /// Whether there was nothing to do, so no request was made.
    skipped: bool,
}

/// What a probe changes about the captured request.
enum Probe {
    /// Exactly as captured — the authenticated baseline.
    AsCaptured,
    /// Every credential header removed — what a stranger sends.
    WithoutCredential,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

async fn send(subject: &Subject, lab: &dyn Lab, probe: Probe) -> Attempt {
    let mut draft = subject.draft.clone();

    if let Probe::WithoutCredential = probe {
        let mut removed = 0;
        for name in nullhawk_types::credential::CREDENTIAL_HEADERS {
            removed += draft.request.headers.remove(name);
        }
        if removed == 0 {
            return Attempt::Answered(Answer {
                request: nullhawk_types::ids::RequestId::new(),
                status: 0,
                body: bytes::Bytes::new(),
                headers: Vec::new(),
                skipped: true,
            });
        }
    }

    match lab.experiment(&draft, None).await {
        Ok(result) => {
            let response = &result.exchange.response;
            let headers = response
                .headers
                .iter()
                .map(|header| (header.name.to_string(), header.value_lossy().to_string()))
                .collect();
            Attempt::Answered(Answer {
                request: result.id,
                status: response.status,
                body: response.body.clone(),
                headers,
                skipped: false,
            })
        }
        Err(e) => Attempt::Failed(e.to_string()),
    }
}

/// The capture, the baseline replay, and each anonymous probe.
fn evidence(
    subject: &Subject,
    baseline: &Answer,
    anon: &Answer,
    again: Option<&Answer>,
) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence::Exchange {
            request: subject.exchange.id,
            response: None,
            note: format!(
                "the captured exchange this was raised from: {} answered {}, with cache \
                 directives that invited storage",
                where_(subject),
                subject.exchange.status,
            ),
        },
        Evidence::Exchange {
            request: baseline.request,
            response: None,
            note: format!(
                "replayed with its session — answered {}, {} byte(s)",
                baseline.status,
                baseline.body.len()
            ),
        },
    ];

    for probe in [Some(anon), again].into_iter().flatten() {
        evidence.push(Evidence::Exchange {
            request: probe.request,
            response: None,
            note: format!(
                "replayed with no credential — answered {}{}",
                probe.status,
                match cache_signal(probe) {
                    Some(signal) => format!(", served from a cache ({signal})"),
                    None => String::new(),
                },
            ),
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn owner(id: &str) -> nullhawk_types::identity::Identity {
        nullhawk_types::identity::Identity {
            owned_object_ids: vec![id.to_string()],
            ..nullhawk_types::identity::Identity::anonymous()
        }
    }

    fn subject_owning(ids: Vec<nullhawk_types::identity::Identity>) -> Subject {
        Subject {
            hypothesis: Hypothesis {
                detector: SETTLES.into(),
                claim: String::new(),
                source_request: nullhawk_types::ids::RequestId::new(),
                location: None,
                provisional_severity: Severity::Medium,
            },
            exchange: exchange(),
            draft: nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
                nullhawk_types::http::HttpService::new("api.example.com", 443, true),
                "/me",
            )),
            target: nullhawk_types::ids::TargetId::new(),
            identities: Arc::new(ids),
        }
    }

    fn exchange() -> nullhawk_scan::Exchange {
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: "https://api.example.com/me".into(),
            path: "/me".into(),
            status: 200,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: true,
            tls: None,
            sent_at: "2026-09-30T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    fn answer(status: u16, body: &str, headers: &[(&str, &str)]) -> Answer {
        Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status,
            body: bytes::Bytes::from(body.to_string()),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            skipped: false,
        }
    }

    const ALICE: &str = "acct-1000-belongs-to-alice";

    #[test]
    fn it_settles_the_passive_checks_hypothesis_and_no_others() {
        let raised = |detector: &str| Hypothesis {
            detector: detector.into(),
            claim: String::new(),
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Medium,
        };
        assert!(CacheExposure.handles(&raised(SETTLES)));
        assert!(!CacheExposure.handles(&raised("cors.configuration")));
        assert!(!CacheExposure.handles(&raised("auth.unverified")));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = CacheExposure.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert!(
            !info.hypothesizes,
            "it settles suspicions, it does not raise them"
        );
        assert_eq!(info.settles, Some(SETTLES));
        assert!(info.produces_something());
    }

    #[test]
    fn a_cache_hit_carrying_a_declared_owners_data_is_the_finding() {
        // The true positive this check exists for: a cache served the owner's data to a
        // caller with no session.
        let subject = subject_owning(vec![owner(ALICE)]);
        let baseline = answer(200, &format!(r#"{{"id":"{ALICE}","balance":10}}"#), &[]);
        let anon = answer(
            200,
            &format!(r#"{{"id":"{ALICE}","balance":10}}"#),
            &[("X-Cache", "HIT")],
        );
        match decide(&subject, &baseline, &anon) {
            Decision::Exposed { id, signal } => {
                assert_eq!(id, ALICE);
                assert!(signal.contains("HIT"), "{signal}");
            }
            other => panic!("the real thing was not established: {other:?}"),
        }
    }

    #[test]
    fn an_age_header_counts_as_a_cache_serving_it() {
        // RFC 9111: only a cache adds Age, so its presence is a cache naming itself even
        // when no vendor header does.
        let subject = subject_owning(vec![owner(ALICE)]);
        let body = format!(r#"{{"id":"{ALICE}"}}"#);
        let baseline = answer(200, &body, &[]);
        let anon = answer(200, &body, &[("Age", "42")]);
        assert!(matches!(
            decide(&subject, &baseline, &anon),
            Decision::Exposed { .. }
        ));
    }

    #[test]
    fn a_cache_hit_with_no_declared_owner_is_ambiguous_not_a_finding() {
        // A public page that is meant to be cached looks exactly like this. Without a
        // declared owner in the body there is no way to tell them apart, and guessing is
        // the seven-false-positives mistake auth.rs already paid for.
        let subject = subject_owning(vec![owner(ALICE)]);
        let body = r#"{"cities":["Helsinki","Tampere"]}"#;
        let baseline = answer(200, body, &[]);
        let anon = answer(200, body, &[("X-Cache", "HIT")]);
        assert!(matches!(
            decide(&subject, &baseline, &anon),
            Decision::CachedButUnowned { .. }
        ));
    }

    #[test]
    fn owned_data_with_no_cache_header_is_a_lead_pointed_at_the_auth_check() {
        // Served to a stranger, but nothing says a cache did it. Real, but its home may
        // be auth.unverified.
        let subject = subject_owning(vec![owner(ALICE)]);
        let body = format!(r#"{{"id":"{ALICE}"}}"#);
        let baseline = answer(200, &body, &[]);
        let anon = answer(200, &body, &[]);
        assert!(matches!(
            decide(&subject, &baseline, &anon),
            Decision::Leaked { .. }
        ));
    }

    #[test]
    fn a_refused_anonymous_request_is_the_control_working() {
        let subject = subject_owning(vec![owner(ALICE)]);
        let baseline = answer(200, &format!(r#"{{"id":"{ALICE}"}}"#), &[]);
        for status in [401, 403, 302] {
            let anon = answer(status, "", &[("X-Cache", "HIT")]);
            assert!(
                matches!(decide(&subject, &baseline, &anon), Decision::Refuted { .. }),
                "{status} was not read as a refusal"
            );
        }
    }

    #[test]
    fn a_cache_serving_a_separate_anonymous_document_is_the_key_working() {
        // The cache answered the stranger from its *own* entry, not the owner's — the
        // session is part of the key, which is correct.
        let subject = subject_owning(vec![owner(ALICE)]);
        let baseline = answer(200, &format!(r#"{{"id":"{ALICE}"}}"#), &[]);
        let anon = answer(200, r#"{"id":null}"#, &[("CF-Cache-Status", "HIT")]);
        assert!(matches!(
            decide(&subject, &baseline, &anon),
            Decision::Refuted { .. }
        ));
    }

    #[test]
    fn x_cache_hits_zero_is_not_read_as_a_hit() {
        // The header name contains "hit"; its value is a miss. A substring match on the
        // name would invert the result.
        let a = answer(200, "body", &[("X-Cache-Hits", "0")]);
        assert!(cache_signal(&a).is_none());
    }

    #[test]
    fn a_miss_is_not_a_hit() {
        let a = answer(200, "body", &[("CF-Cache-Status", "MISS")]);
        assert!(cache_signal(&a).is_none());
        let b = answer(200, "body", &[("X-Cache", "MISS from edge-1")]);
        assert!(cache_signal(&b).is_none());
    }

    #[test]
    fn a_short_identifier_is_not_matched_by_accident() {
        let subject = subject_owning(vec![owner("42")]);
        let body = r#"{"page":42,"id":"acct-9999-somebody-else"}"#;
        assert!(owned_id_in(&subject, body.as_bytes()).is_none());
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
}
