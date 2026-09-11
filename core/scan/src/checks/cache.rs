//! `cache.sensitive` — authenticated responses that said they could be stored.
//!
//! Narrow on purpose. "No `Cache-Control`" on a public page is not worth saying, so
//! this check only looks at responses that were **authenticated**, **successful** and
//! **had content** — the ones where a stored copy is somebody's data sitting in a
//! shared cache or on disk in a browser profile.
//!
//! Even then it is careful about which product it produces:
//!
//! | What the response said | What this is |
//! | ---------------------- | ------------ |
//! | Explicitly `no-store` or `private` | nothing at all |
//! | No cache directives whatever | an **observation** — the defaults decide, and they vary |
//! | Explicitly `public` or a positive `max-age` | a **hypothesis** — it asked to be stored |
//!
//! The last row is a hypothesis rather than a finding because whether it matters
//! depends on something a captured exchange does not show: whether a shared cache is
//! actually in front of this application, and what it is configured to do. That is a
//! question for an experiment, not a header.
//!
//! No cache-poisoning tests are performed, and none could be: nothing here sends.

use hexora_types::finding::Hypothesis;

use super::prelude::*;

/// The check.
pub struct CacheBehaviour;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cache.sensitive"),
    name: "Cache directives on authenticated responses",
    version: "1.0.0",
    about: "whether responses to authenticated requests asked not to be stored",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: true,
};

/// What a response's cache headers amount to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    /// Said not to store it.
    Refused,
    /// Said nothing, so the defaults decide.
    Silent,
    /// Asked to be stored.
    Invited,
}

fn directive(exchange: &Exchange) -> Directive {
    let control = exchange
        .response_headers
        .get_all("cache-control")
        .map(|header| crate::text(header).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(", ");

    if control.contains("no-store") || control.contains("private") {
        return Directive::Refused;
    }

    // `Pragma: no-cache` is the HTTP/1.0 spelling and still worth honouring: an
    // application that sent it meant the same thing.
    if exchange
        .response_headers
        .get("pragma")
        .map(|header| {
            crate::text(header)
                .to_ascii_lowercase()
                .contains("no-cache")
        })
        .unwrap_or(false)
    {
        return Directive::Refused;
    }

    if control.contains("public") || positive_max_age(&control) {
        return Directive::Invited;
    }

    if control.is_empty() {
        Directive::Silent
    } else {
        // Something was said — `no-cache`, `must-revalidate` — that neither refuses
        // storage outright nor invites it. Treated as silent rather than as an
        // invitation, because guessing the stricter reading of an ambiguous header
        // would produce noise.
        Directive::Silent
    }
}

/// Whether a `Cache-Control` asks to be kept for a non-zero time.
fn positive_max_age(control: &str) -> bool {
    control.split(',').any(|part| {
        part.trim()
            .strip_prefix("max-age=")
            .and_then(|seconds| seconds.trim().parse::<u64>().ok())
            .is_some_and(|seconds| seconds > 0)
    })
}

/// Whether this response is one where a stored copy would be somebody's data.
fn worth_asking_about(exchange: &Exchange) -> bool {
    exchange.is_authenticated() && (200..300).contains(&exchange.status) && exchange.has_body()
}

impl PassiveCheck for CacheBehaviour {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        if !worth_asking_about(exchange) || directive(exchange) != Directive::Silent {
            return Vec::new();
        }

        vec![observation(
            &INFO,
            exchange,
            format!(
                "Authenticated response with no cache directives on {}",
                exchange.host
            ),
            "a response to an authenticated request says no-store or private",
            "it says nothing, so the defaults decide",
            "What happens to a copy of this response is then up to whatever is \
             between the application and the user: a browser cache on a shared \
             machine, a corporate proxy, a CDN. The response was served to a request \
             carrying a credential, so a stored copy is somebody's data.",
            Severity::Low,
            Significance::Reportable,
            header_at("Cache-Control"),
        )]
    }

    fn suspect(&self, exchange: &Exchange) -> Vec<Hypothesis> {
        if !worth_asking_about(exchange) || directive(exchange) != Directive::Invited {
            return Vec::new();
        }

        // It asked to be stored. Whether anything took it up on that — and whether
        // what is stored is one user's data served to another — needs a shared cache
        // to exist and be probed, which is an experiment.
        vec![Hypothesis {
            detector: INFO.id.to_string(),
            claim: format!(
                "an authenticated response on {} asked to be cached, and may be \
                 served to somebody else",
                exchange.host
            ),
            source_request: exchange.id,
            location: Some(Location {
                part: MessagePart::Header,
                name: "Cache-Control".into(),
            }),
            provisional_severity: Severity::Medium,
        }]
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: observation.about.clone(),
            description: format!(
                "{} Expected: {}. Observed: {}.",
                observation.rationale, observation.expected, observation.observed
            ),
            impact: "A cached copy of an authenticated response can outlive the \
                     session and can be read by whoever reaches the cache. Whether \
                     anything is caching this is not something a captured exchange \
                     shows."
                .into(),
            remediation: "Send Cache-Control: no-store on responses that contain one \
                          user's data, or private where a browser cache is acceptable \
                          and a shared one is not."
                .into(),
            reproduction: format!(
                "Request {} {} with a session and read the Cache-Control header.",
                exchange.method, exchange.url
            ),
            cwe: Some("CWE-525".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: source(&INFO),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    fn authenticated() -> crate::checks::test_support::Build {
        https().authenticated().response(200, &[]).bytes(512)
    }

    #[test]
    fn an_unauthenticated_response_is_not_asked_about_at_all() {
        // The rule that keeps this check from firing on every public page.
        let exchange = exchange(https().response(200, &[]).bytes(512));
        assert!(CacheBehaviour.observe(&exchange).is_empty());
        assert!(CacheBehaviour.suspect(&exchange).is_empty());
    }

    #[test]
    fn an_authenticated_response_that_refused_storage_says_nothing() {
        for value in [
            "no-store",
            "private, max-age=0",
            "no-store, must-revalidate",
        ] {
            let exchange = exchange(authenticated().header("Cache-Control", value));
            assert!(
                CacheBehaviour.observe(&exchange).is_empty(),
                "{value} produced something"
            );
            assert!(CacheBehaviour.suspect(&exchange).is_empty(), "{value}");
        }
    }

    #[test]
    fn a_silent_authenticated_response_is_an_observation() {
        let exchange = exchange(authenticated());
        let found = CacheBehaviour.observe(&exchange);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].is_reportable());
        assert!(CacheBehaviour.suspect(&exchange).is_empty());
    }

    #[test]
    fn a_response_that_asked_to_be_cached_is_a_hypothesis_and_stops_there() {
        for value in ["public, max-age=600", "max-age=3600"] {
            let exchange = exchange(authenticated().header("Cache-Control", value));
            let suspected = CacheBehaviour.suspect(&exchange);
            assert_eq!(suspected.len(), 1, "{value}: {suspected:#?}");
            assert_eq!(suspected[0].provisional_severity, Severity::Medium);
            // And it produced no finding, because whether a cache is in front of
            // this is not something the headers say.
            assert!(CacheBehaviour.observe(&exchange).is_empty(), "{value}");
        }
    }

    #[test]
    fn max_age_zero_is_not_an_invitation() {
        let exchange = exchange(authenticated().header("Cache-Control", "max-age=0"));
        assert!(CacheBehaviour.suspect(&exchange).is_empty());
    }

    #[test]
    fn the_http_1_0_spelling_is_honoured() {
        let exchange = exchange(authenticated().header("Pragma", "no-cache"));
        assert!(CacheBehaviour.observe(&exchange).is_empty());
    }

    #[test]
    fn an_empty_response_is_not_a_disclosure() {
        // A 204 or an empty 200 has nothing to leak into a cache.
        let exchange = exchange(https().authenticated().response(204, &[]).bytes(0));
        assert!(CacheBehaviour.observe(&exchange).is_empty());
    }

    #[test]
    fn malformed_cache_control_does_not_panic_or_over_claim() {
        for value in [
            "",
            "max-age=",
            "max-age=abc",
            ",,,",
            "max-age=99999999999999999999",
        ] {
            let exchange = exchange(authenticated().header("Cache-Control", value));
            let _ = CacheBehaviour.observe(&exchange);
            assert!(
                CacheBehaviour.suspect(&exchange).is_empty(),
                "{value:?} was read as an invitation to cache"
            );
        }
    }

    #[test]
    fn duplicate_cache_control_headers_are_read_together() {
        // A server that sent the directives across two headers meant both.
        let exchange = exchange(
            authenticated()
                .header("Cache-Control", "max-age=600")
                .header("Cache-Control", "no-store"),
        );
        assert!(CacheBehaviour.observe(&exchange).is_empty());
        assert!(CacheBehaviour.suspect(&exchange).is_empty());
    }
}
