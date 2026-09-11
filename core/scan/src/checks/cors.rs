//! `cors.configuration` — who the application says may read its responses.
//!
//! The one check in this milestone that produces **both** products, and the clearest
//! example of why they are separate:
//!
//! | What one exchange shows | What it is |
//! | ----------------------- | ---------- |
//! | `Access-Control-Allow-Origin: *` with credentials allowed | an **observation** — the pair is contradictory whatever else is true |
//! | `Access-Control-Allow-Origin` equal to the request's `Origin`, with credentials | a **hypothesis** — and it stops here |
//!
//! The second one is the interesting case and the one a passive scanner cannot
//! settle. A response that echoes the origin it was asked about is consistent with a
//! server that reflects *any* origin — the real finding — and equally consistent with
//! a server that has that one origin on an allowlist, which is correct behaviour. The
//! difference is a second request carrying a different `Origin`, and sending one is
//! exactly what this crate does not do.
//!
//! So it becomes a [`Hypothesis`](hexora_types::finding::Hypothesis), which is
//! recorded, counted, shown to the tester — and turns into nothing at all until an
//! active verifier runs the experiment. Filing it as a finding here would be claiming
//! the result of a test nobody ran.

use hexora_types::finding::Hypothesis;

use super::prelude::*;

/// The check.
pub struct CorsConfiguration;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cors.configuration"),
    name: "CORS configuration analysis",
    version: "1.0.0",
    about: "who the application allows to read its responses, and with whose credentials",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: true,
    settles: None,
};

/// Whether the response says credentialed cross-origin reads are allowed.
fn allows_credentials(exchange: &Exchange) -> bool {
    exchange
        .response_headers
        .get("access-control-allow-credentials")
        .map(|header| crate::text(header).trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

impl PassiveCheck for CorsConfiguration {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let Some(allow_origin) = exchange.response_headers.get("access-control-allow-origin")
        else {
            return Vec::new();
        };
        let allow_origin = crate::text(allow_origin).trim().to_string();
        let credentialed = allows_credentials(exchange);
        let mut found = Vec::new();

        if allow_origin == "*" && credentialed {
            found.push(observation(
                &INFO,
                exchange,
                format!("Wildcard CORS origin with credentials on {}", exchange.host),
                "Access-Control-Allow-Origin: * is not combined with \
                 Access-Control-Allow-Credentials: true",
                "both are present",
                "The pair is contradictory: browsers refuse the combination, so the \
                 credentialed requests this appears to allow will not work — which \
                 usually means the configuration was written to be permissive and \
                 nobody has read the error. A server that later replaces the wildcard \
                 with the caller's own origin to make it work is the actual problem.",
                Severity::Medium,
                Significance::Reportable,
                header_at("Access-Control-Allow-Origin"),
            ));
        } else if allow_origin == "*" {
            found.push(observation(
                &INFO,
                exchange,
                format!("Responses on {} are readable by any origin", exchange.host),
                "a response that any site may read carries nothing that needs a session",
                "Access-Control-Allow-Origin: *",
                "Correct and normal for a public API. Recorded as context so a tester \
                 can say whether this endpoint is one, rather than having to check.",
                Severity::Info,
                Significance::Informational,
                header_at("Access-Control-Allow-Origin"),
            ));
        }

        // `Vary: Origin` is how a server that varies its answer tells caches so.
        // Its absence on a response that *did* vary is a cache-poisoning shape, and
        // is worth recording as context rather than as an accusation.
        let varies_by_origin = exchange
            .response_headers
            .get_all("vary")
            .any(|header| crate::text(header).to_ascii_lowercase().contains("origin"));
        let echoes_origin = echoes_request_origin(exchange);

        if echoes_origin && !varies_by_origin {
            found.push(observation(
                &INFO,
                exchange,
                format!(
                    "Origin-dependent response without Vary: Origin on {}",
                    exchange.host
                ),
                "a response whose Access-Control-Allow-Origin depends on the request \
                 carries Vary: Origin",
                "it does not",
                "A shared cache may serve one origin's permission header to another. \
                 Whether a shared cache is in front of this is not something a \
                 captured exchange shows.",
                Severity::Low,
                Significance::Reportable,
                header_at("Vary"),
            ));
        }

        found
    }

    fn suspect(&self, exchange: &Exchange) -> Vec<Hypothesis> {
        // Echoing the caller's own origin, with credentials. Either the server
        // reflects anything it is sent — which would be serious — or this origin is
        // on an allowlist, which is correct. One exchange cannot tell them apart.
        if !echoes_request_origin(exchange) || !allows_credentials(exchange) {
            return Vec::new();
        }

        vec![Hypothesis {
            detector: INFO.id.to_string(),
            // Names the endpoint, not just the host. Two endpoints on one host
            // routinely differ — one reflecting, one correctly allowlisted — and two
            // suspicions that read identically are two a tester cannot tell apart in
            // a list or in a plan.
            claim: format!(
                "{} {} may reflect any Origin it is sent, with credentials allowed",
                exchange.method, exchange.url
            ),
            source_request: exchange.id,
            location: Some(Location {
                part: MessagePart::Header,
                name: "Access-Control-Allow-Origin".into(),
            }),
            provisional_severity: Severity::High,
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
            impact: "A cross-origin policy decides which other sites may read this \
                     application's responses using a visitor's session. What that is \
                     worth depends on what the responses contain."
                .into(),
            remediation: "Allow specific origins rather than reflecting whatever is \
                          asked for, allow credentials only for origins that need \
                          them, and send Vary: Origin whenever the answer depends on \
                          the request."
                .into(),
            reproduction: format!(
                "Request {} {} with an Origin header and read the \
                 Access-Control-* headers on the response.",
                exchange.method, exchange.url
            ),
            cwe: Some("CWE-942".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: source(&INFO),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

/// Whether the response's allowed origin is byte-for-byte the one the request sent.
///
/// Compared as bytes rather than as text. The values are somebody else's — one is
/// attacker-supplied by definition — and two different byte strings can decode to the
/// same replacement characters, which would turn a decoding artefact into a claim
/// that the server reflects whatever it is sent.
///
/// `Origin: null` is excluded: it is what a sandboxed frame sends, and a response
/// allowing the literal `null` is not evidence of reflection.
fn echoes_request_origin(exchange: &Exchange) -> bool {
    let Some(origin) = exchange.request_headers.get("origin") else {
        return false;
    };
    let Some(allowed) = exchange.response_headers.get("access-control-allow-origin") else {
        return false;
    };
    let sent = crate::text(origin);
    let sent = sent.trim();
    if sent.is_empty() || sent == "null" {
        return false;
    }
    crate::bytes_equal(origin, allowed)
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    #[test]
    fn a_wildcard_with_credentials_is_a_fact_about_one_response() {
        let exchange = exchange(
            https()
                .response(200, &[])
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true"),
        );
        let found = CorsConfiguration.observe(&exchange);

        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].is_reportable());
        // And it needs no experiment: both headers are right there.
        assert!(CorsConfiguration.suspect(&exchange).is_empty());
    }

    #[test]
    fn a_reflected_origin_with_credentials_is_a_hypothesis_and_stops_there() {
        // The case this check exists to get right. One exchange cannot distinguish
        // "reflects anything" from "this origin is allowed", so it does not try.
        let exchange = exchange(
            https()
                .response(200, &[])
                .request_header("Origin", "https://evil.example")
                .header("Access-Control-Allow-Origin", "https://evil.example")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Vary", "Origin"),
        );

        let suspected = CorsConfiguration.suspect(&exchange);
        assert_eq!(suspected.len(), 1, "{suspected:#?}");
        assert_eq!(suspected[0].detector, "cors.configuration");
        assert_eq!(suspected[0].provisional_severity, Severity::High);

        // Nothing reportable came out of it. The severity above is what it *would*
        // be worth if an experiment established it — which nothing here does.
        let reportable: Vec<_> = CorsConfiguration
            .observe(&exchange)
            .into_iter()
            .filter(|o| o.is_reportable())
            .collect();
        assert!(reportable.is_empty(), "{reportable:#?}");
    }

    #[test]
    fn an_echoed_origin_without_credentials_raises_nothing() {
        // Readable by that origin, but not with the visitor's session. Much less
        // interesting, and not worth a tester's afternoon.
        let exchange = exchange(
            https()
                .response(200, &[])
                .request_header("Origin", "https://app.example")
                .header("Access-Control-Allow-Origin", "https://app.example")
                .header("Vary", "Origin"),
        );
        assert!(CorsConfiguration.suspect(&exchange).is_empty());
    }

    #[test]
    fn a_public_wildcard_is_context_rather_than_a_problem() {
        let exchange = exchange(
            https()
                .response(200, &[])
                .header("Access-Control-Allow-Origin", "*"),
        );
        let found = CorsConfiguration.observe(&exchange);
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_reportable(), "{:#?}", found[0]);
        assert_eq!(found[0].severity, Severity::Info);
    }

    #[test]
    fn a_response_with_no_cors_headers_is_not_about_cors() {
        let exchange = exchange(https().response(200, &[("Content-Type", "text/html")]));
        assert!(CorsConfiguration.observe(&exchange).is_empty());
        assert!(CorsConfiguration.suspect(&exchange).is_empty());
    }

    #[test]
    fn an_origin_dependent_response_without_vary_is_noted() {
        let exchange = exchange(
            https()
                .response(200, &[])
                .request_header("Origin", "https://app.example")
                .header("Access-Control-Allow-Origin", "https://app.example"),
        );
        let found = CorsConfiguration.observe(&exchange);
        assert!(found.iter().any(|o| o.about.contains("Vary")), "{found:#?}");
    }

    #[test]
    fn a_null_origin_is_not_treated_as_an_echo() {
        // `Origin: null` is what a sandboxed frame sends. Treating a literal "null"
        // match as a reflection would raise a hypothesis about nothing.
        let exchange = exchange(
            https()
                .response(200, &[])
                .request_header("Origin", "null")
                .header("Access-Control-Allow-Origin", "null")
                .header("Access-Control-Allow-Credentials", "true"),
        );
        assert!(CorsConfiguration.suspect(&exchange).is_empty());
    }

    #[test]
    fn duplicate_and_oddly_cased_cors_headers_do_not_confuse_it() {
        let exchange = exchange(
            https()
                .response(200, &[])
                .request_header("ORIGIN", "https://app.example")
                .header("access-control-allow-origin", "https://app.example")
                .header("Access-Control-Allow-Origin", "*")
                .header("ACCESS-CONTROL-ALLOW-CREDENTIALS", "TRUE")
                .header("vary", "Accept-Encoding, Origin"),
        );
        // The first header wins, as it does on the wire.
        let suspected = CorsConfiguration.suspect(&exchange);
        assert_eq!(suspected.len(), 1, "{suspected:#?}");
        // And `Vary` is satisfied by a list that mentions Origin among others.
        let found = CorsConfiguration.observe(&exchange);
        assert!(
            !found.iter().any(|o| o.about.contains("Vary")),
            "{found:#?}"
        );
    }
}
