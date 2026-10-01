//! `cache.deception` — does a static-looking suffix trick a shared cache into storing a
//! private page?
//!
//! `cache.exposure` settles the case where an authenticated response *asked* to be cached
//! (`Cache-Control: public`) and a shared cache then served it to a stranger. Web cache
//! deception is the nastier cousin: the page never asked to be cached, but a cache that
//! stores by file extension will store it anyway if the URL is dressed up as a static
//! asset — and the origin, through a path-normalisation quirk, serves the private page for
//! that dressed-up URL.
//!
//! ```text
//! captured   GET /account              (Alice's cookie) → 200  {"id":"acct-…alice"}
//! probe 1    GET /account/nhXX.css      (Alice's cookie) → 200  {"id":"acct-…alice"}   ← origin ignores the suffix
//! probe 2    GET /account/nhXX.css      (no cookie)      → 200  X-Cache: HIT  {"id":"acct-…alice"}
//!                                                                 ▲ a cache      ▲ Alice's data, to nobody
//! ```
//!
//! Three things have to hold, and each is checked rather than assumed:
//!
//! 1. **The page is private** — its body carries an identifier a person declared as owned
//!    ([`super::auth::owned_id_in`]'s rule). Without a known-private marker, a cached copy
//!    cannot be told from a public page that is meant to be cached.
//! 2. **The origin confuses the path** — the `.css`-suffixed URL, sent with the session,
//!    still returns the private page. If the origin serves the suffix as its own resource
//!    (a 404, a real stylesheet), there is nothing for a cache to store wrongly.
//! 3. **A cache serves it to no one** — the same suffixed URL, with the credential removed,
//!    returns the private page *and* a cache-status header says a cache produced it. The
//!    cache signal is what separates this from the origin simply serving the page without a
//!    session, which is [`auth.unverified`]'s to report, not this check's.
//!
//! A random token in the suffix (`nh…`) makes the cache entry this run's own, so a hit on
//! probe 2 is the copy probe 1 planted, not a pre-existing one.
//!
//! Needs declared ownership (`nullhawk identity add --owns`): without it, step 1 cannot be
//! established and the result is [`Verification::Inconclusive`], never a guess.

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
pub struct CacheDeception;

/// The hypothesis this check raises and settles itself: no passive check sees it, because
/// a web-cache-deception target is a page that did *not* ask to be cached.
const SETTLES: &str = "cache.deceivable";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cache.deception"),
    name: "Web cache deception",
    version: "1.0.0",
    about: "whether a static-looking suffix tricks a shared cache into storing a private page for anonymous callers",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: true,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

/// Headers a cache in front of the origin uses to report a hit. Same list, and the same
/// reason for excluding `X-Cache-Hits`, as [`super::cache`].
const CACHE_STATUS_HEADERS: [&str; 7] = [
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "cache-status",
    "x-drupal-cache",
    "x-varnish-cache",
    "x-proxy-cache",
];

/// Extensions a path that already ends in one is not a deception target — it is already a
/// static asset, so there is nothing to disguise.
const STATIC_EXTENSIONS: [&str; 13] = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map",
    ".pdf", ".webp",
];

#[async_trait]
impl ActiveCheck for CacheDeception {
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
        // 1. The baseline: the captured, authenticated request as it was. It must still
        //    succeed, and must carry a declared-owned identifier — the marker that says the
        //    page is private, without which a cached copy cannot be told from a public one.
        let baseline = match send(subject, lab, None, false).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if !(200..300).contains(&baseline.status) || baseline.body.is_empty() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "replaying {} as captured answered {} with {} byte(s), so the session \
                     no longer serves the page a cache would store",
                    where_(subject),
                    baseline.status,
                    baseline.body.len(),
                ),
            });
        }
        let Some(owned) = owned_id_in(subject, &baseline.body) else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "the authenticated response for {} carries no identifier this project \
                     declares as owned, so whether the page is private — and therefore \
                     whether a cached copy would matter — cannot be established. Declare \
                     ownership with `nullhawk identity add --owns` and run again",
                    where_(subject),
                ),
            });
        };

        // 2. Path confusion: the same resource under a `.css` suffix, with the session. If
        //    the origin still hands back the private page, it is ignoring the suffix — the
        //    precondition for a cache keyed on extension to store the wrong thing.
        let token = deception_token();
        let suffixed = deceive(&subject.draft.request.path, &token);
        let planted = match send(subject, lab, Some(&suffixed), false).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if !(200..300).contains(&planted.status)
            || owned_id_in(subject, &planted.body).as_deref() != Some(owned.as_str())
        {
            return Ok(Verification::Refuted {
                note: format!(
                    "with a `.css` suffix, {} answered {} and did not return the private \
                     page, so the origin treats the suffixed path as its own resource — \
                     there is nothing for a cache to confuse",
                    path_of_str(&suffixed),
                    planted.status,
                ),
            });
        }

        // 3. The same suffixed URL with the credential removed — what a stranger, or the
        //    next person behind the same CDN edge, receives.
        let anon = match send(subject, lab, Some(&suffixed), true).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if anon.skipped {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} carried no credential this check knows how to remove, so a request \
                     with no session could not be formed",
                    where_(subject),
                ),
            });
        }

        match decide(subject, &owned, &anon, &suffixed) {
            Decision::Deceived { signal } => {
                // Confirm with a second anonymous request when the budget allows: the same
                // experiment repeated is what separates reproduced from one lucky read.
                if budget.per_hypothesis >= 4 {
                    if let Attempt::Answered(again) =
                        send(subject, lab, Some(&suffixed), true).await
                    {
                        if !again.skipped
                            && cache_signal(&again).is_some()
                            && owned_id_in(subject, &again.body).as_deref() == Some(owned.as_str())
                        {
                            return Ok(Verification::Reproduced {
                                note: deceived_note(&suffixed, &owned, &signal, true),
                                evidence: evidence(subject, &planted, &anon, Some(&again)),
                            });
                        }
                    }
                }
                Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: deceived_note(&suffixed, &owned, &signal, false),
                    evidence: evidence(subject, &planted, &anon, None),
                })
            }
            Decision::Leaked => Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "{} returned the private page to a request with no credential, but no \
                     cache-status header was present — so the page reaches a stranger, yet \
                     whether a cache or the origin serves it is not established from here. \
                     If the origin serves it without a session, auth.unverified is where \
                     that is settled",
                    path_of_str(&suffixed),
                ),
                evidence: evidence(subject, &planted, &anon, None),
            }),
            Decision::Refuted { note } => Ok(Verification::Refuted { note }),
        }
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: format!(
                "A static-suffix trick caches the private page at {}",
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "{} was captured returning a private page to an authenticated request. The \
                 same resource requested under a `.css` suffix still returned the private \
                 page — the origin ignores the suffix — and the suffixed URL, with no \
                 credential, returned it too. {}\n\nThe suffix carried a random token, so \
                 the copy served to the anonymous request is the one the authenticated \
                 request planted.",
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A cache keyed on file extension is storing a private page under a \
                     URL anyone can request without a session. An attacker who gets a \
                     victim to open the crafted link plants the victim's own page in the \
                     shared cache, then reads it back with no credentials at all. What it \
                     is worth is whatever the page contains — the evidence shows it \
                     contains data this project declares as belonging to an identity."
                .into(),
            remediation: "Make the cache key depend on the response being cacheable, not on \
                          the URL's extension: configure the CDN or cache to store only \
                          responses that set `Cache-Control: public`, and send `no-store` \
                          (or `private`) on every page carrying one identity's data. On the \
                          origin, do not serve application pages for paths with trailing \
                          static-looking segments — return 404 instead of normalising them \
                          back to the page."
                .into(),
            reproduction: format!(
                "Send {} with its session and note the private content, then append \
                 `/<token>.css` to the path and send it twice — once with the session, \
                 once with the credential removed — and read the cache-status headers and \
                 body of the second. `nullhawk poc <project> <finding>` compiles the \
                 requests, credentials replaced by placeholders.",
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
                part: MessagePart::Path,
                name: path_of(&subject.exchange.url).to_string(),
            }),
        }
    }
}

/// What the anonymous probe established.
#[derive(Debug)]
enum Decision {
    /// A cache served the private page to a caller with no session, at the deceptive URL.
    Deceived { signal: String },
    /// The private page reached a caller with no session, but no cache said it did.
    Leaked,
    /// Nothing here shows a cache serving the private page to a stranger.
    Refuted { note: String },
}

/// The decision over the anonymous probe, factored out so it can be tested without a lab.
fn decide(subject: &Subject, owned: &str, anon: &Answer, suffixed: &str) -> Decision {
    if !(200..300).contains(&anon.status) {
        return Decision::Refuted {
            note: format!(
                "{} answered {} to a request with no credential, so a cache is not serving \
                 the private page to an unauthenticated caller",
                path_of_str(suffixed),
                anon.status,
            ),
        };
    }
    if owned_id_in(subject, &anon.body).as_deref() != Some(owned) {
        return Decision::Refuted {
            note: format!(
                "{} answered a request with no credential without the private page's owned \
                 identifier, so the suffixed URL is not serving one identity's page to a \
                 stranger",
                path_of_str(suffixed),
            ),
        };
    }
    match cache_signal(anon) {
        Some(signal) => Decision::Deceived { signal },
        None => Decision::Leaked,
    }
}

/// `/account?tab=x` → `/account/nh….css?tab=x`. The suffix becomes a new path segment, so
/// a cache keyed on extension treats it as static; the query is preserved so the same
/// resource is addressed.
fn deceive(full_path: &str, token: &str) -> String {
    let (path, query) = match full_path.find('?') {
        Some(at) => (&full_path[..at], &full_path[at..]),
        None => (full_path, ""),
    };
    let base = path.trim_end_matches('/');
    format!("{base}/{token}.css{query}")
}

/// A per-run token for the suffix, so a hit is this run's planted copy and not a stale one.
fn deception_token() -> String {
    // The *tail* of the id, not the head: a time-ordered UUID shares its leading digits
    // between two requests in the same millisecond, and a token that collided would point
    // the second probe at the first's cache entry. The random end does not collide.
    let digits: Vec<char> = nullhawk_types::ids::RequestId::new()
        .to_string()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let tail: String = digits.iter().rev().take(12).rev().collect();
    format!("nh{tail}")
}

/// The evidence a cache produced this response. Identical rule to [`super::cache`]: a
/// cache-status header reporting a hit, or an `Age` header (RFC 9111: only a cache adds one).
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

/// An object identifier a person declared as owned, if one appears in the body. Narrow on
/// purpose, drawn exactly where [`super::auth::owned_id_in`] draws it.
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

fn deceived_note(suffixed: &str, owned: &str, signal: &str, reproduced: bool) -> String {
    format!(
        "a shared cache ({signal}) served {} to a request with no credential, and the page \
         it returned contains {owned}, which this project declares as belonging to an \
         identity{}",
        path_of_str(suffixed),
        if reproduced {
            " — and a second anonymous request was answered the same way"
        } else {
            ""
        },
    )
}

/// One request and what came back.
struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    body: bytes::Bytes,
    headers: Vec<(String, String)>,
    skipped: bool,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

/// Sends the captured request, optionally under a replaced path and/or with every
/// credential header removed.
async fn send(
    subject: &Subject,
    lab: &dyn Lab,
    path: Option<&str>,
    strip_credential: bool,
) -> Attempt {
    let mut draft = subject.draft.clone();
    if let Some(path) = path {
        draft.request.path = path.to_string();
    }
    if strip_credential {
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

fn evidence(
    subject: &Subject,
    planted: &Answer,
    anon: &Answer,
    again: Option<&Answer>,
) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence::Exchange {
            request: subject.exchange.id,
            response: None,
            note: format!(
                "the captured exchange this was raised from: {} answered {}",
                where_(subject),
                subject.exchange.status,
            ),
        },
        Evidence::Exchange {
            request: planted.request,
            response: None,
            note: format!(
                "the `.css`-suffixed URL with the session — answered {}, returned the \
                 private page, so the origin ignores the suffix",
                planted.status,
            ),
        },
    ];
    for probe in [Some(anon), again].into_iter().flatten() {
        evidence.push(Evidence::Exchange {
            request: probe.request,
            response: None,
            note: format!(
                "the same URL with no credential — answered {}{}",
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

/// Raises one suspicion per authenticated page worth trying to deceive a cache with.
///
/// A captured `GET` that was authenticated, succeeded, and had a body — and whose path is
/// not already a static asset. One per endpoint; the deception is a property of the URL.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if !exchange.authenticated
        || !exchange.method.eq_ignore_ascii_case("GET")
        || !(200..300).contains(&exchange.status)
        || exchange.response_bytes == 0
        || is_static_asset(&exchange.path)
    {
        return Vec::new();
    }
    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} returns a private page — whether a `.css` suffix gets it cached for \
             anonymous callers needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: None,
        provisional_severity: Severity::Info,
    }]
}

/// Whether a path already ends in a static-asset extension.
fn is_static_asset(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
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

/// The path of something that is already a path (not a full URL), query trimmed off.
fn path_of_str(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
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

    const ALICE: &str = "acct-1000-belongs-to-alice";

    fn owner(id: &str) -> nullhawk_types::identity::Identity {
        nullhawk_types::identity::Identity {
            owned_object_ids: vec![id.to_string()],
            ..nullhawk_types::identity::Identity::anonymous()
        }
    }

    fn subject() -> Subject {
        Subject {
            hypothesis: Hypothesis {
                detector: SETTLES.into(),
                claim: String::new(),
                source_request: nullhawk_types::ids::RequestId::new(),
                location: None,
                provisional_severity: Severity::Info,
            },
            exchange: exchange(200, "GET", "https://api.example.com/account", true),
            draft: nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
                nullhawk_types::http::HttpService::new("api.example.com", 443, true),
                "/account",
            )),
            target: nullhawk_types::ids::TargetId::new(),
            identities: Arc::new(vec![owner(ALICE)]),
        }
    }

    fn exchange(status: u16, method: &str, url: &str, authed: bool) -> nullhawk_scan::Exchange {
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .unwrap_or_else(|| "/".into());
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: url.into(),
            path,
            status,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 128,
            authenticated: authed,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
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

    #[test]
    fn it_raises_and_settles_its_own_suspicion() {
        let info = CacheDeception.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert!(info.hypothesizes);
        assert_eq!(info.settles, Some(SETTLES));
        assert!(CacheDeception.handles(&subject().hypothesis));
    }

    #[test]
    fn only_an_authenticated_non_static_get_is_a_target() {
        assert_eq!(
            suspect(&exchange(
                200,
                "GET",
                "https://api.example.com/account",
                true
            ))
            .len(),
            1
        );
        // Unauthenticated, wrong method, error status, and already-static: none qualify.
        assert!(suspect(&exchange(
            200,
            "GET",
            "https://api.example.com/account",
            false
        ))
        .is_empty());
        assert!(suspect(&exchange(
            200,
            "POST",
            "https://api.example.com/account",
            true
        ))
        .is_empty());
        assert!(suspect(&exchange(
            404,
            "GET",
            "https://api.example.com/account",
            true
        ))
        .is_empty());
        assert!(suspect(&exchange(
            200,
            "GET",
            "https://api.example.com/app.css",
            true
        ))
        .is_empty());
    }

    #[test]
    fn the_suffix_is_a_new_segment_and_keeps_the_query() {
        let deceived = deceive("/account?tab=settings", "nhABC");
        assert_eq!(deceived, "/account/nhABC.css?tab=settings");
        assert_eq!(deceive("/account/", "nhABC"), "/account/nhABC.css");
    }

    #[test]
    fn a_cache_hit_returning_the_owners_page_to_a_stranger_is_the_finding() {
        let subject = subject();
        let anon = answer(
            200,
            &format!(r#"{{"id":"{ALICE}"}}"#),
            &[("X-Cache", "HIT")],
        );
        match decide(&subject, ALICE, &anon, "/account/nhX.css") {
            Decision::Deceived { signal } => assert!(signal.contains("HIT"), "{signal}"),
            other => panic!("the real thing was not established: {other:?}"),
        }
    }

    #[test]
    fn the_owners_page_to_a_stranger_without_a_cache_header_is_a_lead_for_auth() {
        // Served to no session, but nothing says a cache did it — its home may be
        // auth.unverified, so it is a lead, not a cache-deception finding.
        let subject = subject();
        let anon = answer(200, &format!(r#"{{"id":"{ALICE}"}}"#), &[]);
        assert!(matches!(
            decide(&subject, ALICE, &anon, "/account/nhX.css"),
            Decision::Leaked
        ));
    }

    #[test]
    fn a_stranger_turned_away_is_the_control_working() {
        let subject = subject();
        for status in [401, 403, 302] {
            let anon = answer(status, "", &[("X-Cache", "HIT")]);
            assert!(
                matches!(
                    decide(&subject, ALICE, &anon, "/account/nhX.css"),
                    Decision::Refuted { .. }
                ),
                "{status} was not read as a refusal"
            );
        }
    }

    #[test]
    fn a_cached_page_without_the_owners_data_is_not_this_finding() {
        // A cache hit on the suffixed URL, but it is some other, non-private document — a
        // real stylesheet, a public page. Not web cache deception.
        let subject = subject();
        let anon = answer(200, "body{color:red}", &[("X-Cache", "HIT")]);
        assert!(matches!(
            decide(&subject, ALICE, &anon, "/account/nhX.css"),
            Decision::Refuted { .. }
        ));
    }

    #[test]
    fn the_token_is_alphanumeric_and_unique() {
        let a = deception_token();
        let b = deception_token();
        assert!(a.starts_with("nh"));
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b, "a reused token would hit a stale cache entry");
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
    }
}
