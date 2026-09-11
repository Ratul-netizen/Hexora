//! `headers.security` — response headers that were expected and were not there.
//!
//! The check most likely to become noise, so applicability is decided per header
//! rather than by listing six names and reporting whichever are absent:
//!
//! | Header | Asked about |
//! | ------ | ----------- |
//! | `Strict-Transport-Security` | HTTPS responses only. On plaintext it does nothing. |
//! | `Content-Security-Policy` | HTML documents only. A JSON body has no scripts. |
//! | `X-Frame-Options` / CSP `frame-ancestors` | HTML documents only. |
//! | `X-Content-Type-Options` | HTML documents only, where sniffing changes meaning. |
//! | `Referrer-Policy` | HTML documents only. |
//! | `Permissions-Policy` | HTML documents only, and informational. |
//!
//! A missing header is an **observation**, not a vulnerability: it is a fact about
//! one response, and whether it matters depends on the application. It reaches a
//! report as a lead, which is the strongest thing a passive check can say.
//!
//! Only responses that were actually served are examined — a 404 with no security
//! headers is a 404, and a redirect is not the document.

use super::prelude::*;

/// The check.
pub struct SecurityHeaders;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("headers.security"),
    name: "Security header analysis",
    version: "1.0.0",
    about: "response headers that were applicable and absent",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: false,
    settles: None,
};

impl PassiveCheck for SecurityHeaders {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        // A response that was not served is not a response whose headers mean
        // anything. Redirects and errors carry their own, usually deliberately.
        if !(200..300).contains(&exchange.status) {
            return Vec::new();
        }

        let mut found = Vec::new();
        let headers = &exchange.response_headers;

        if exchange.secure && headers.get("strict-transport-security").is_none() {
            found.push(observation(
                &INFO,
                exchange,
                format!("No Strict-Transport-Security on {}", exchange.host),
                "an HTTPS response carries Strict-Transport-Security",
                "the header is absent",
                "Without it a browser that has only ever seen this host over HTTPS \
                 will still try plaintext first if a link, a typed address or an \
                 attacker sends it there.",
                Severity::Low,
                Significance::Reportable,
                header_at("Strict-Transport-Security"),
            ));
        }

        // Everything below is about how a browser treats a document. A JSON API
        // response is not framed, not sniffed into a document and has no scripts, so
        // reporting these against one is noise with a severity attached.
        if !exchange.is_document() {
            return found;
        }

        let csp = headers.get("content-security-policy");
        if csp.is_none() {
            found.push(observation(
                &INFO,
                exchange,
                format!("No Content-Security-Policy on {}", exchange.host),
                "an HTML document carries a Content-Security-Policy",
                "the header is absent",
                "A policy is the difference between an injected script running and \
                 being refused. Its absence is not itself an injection — Hexora has \
                 not looked for one — but it removes the layer that would contain it.",
                Severity::Low,
                Significance::Reportable,
                header_at("Content-Security-Policy"),
            ));
        }

        let framed = headers.get("x-frame-options").is_some()
            || csp
                .map(|policy| {
                    crate::text(policy)
                        .to_ascii_lowercase()
                        .contains("frame-ancestors")
                })
                .unwrap_or(false);
        if !framed {
            found.push(observation(
                &INFO,
                exchange,
                format!("No framing policy on {}", exchange.host),
                "an HTML document declares who may frame it, via X-Frame-Options or \
                 a CSP frame-ancestors directive",
                "neither is present",
                "A document any site may frame can be overlaid and clicked through. \
                 Whether that matters depends on what the page does.",
                Severity::Low,
                Significance::Reportable,
                header_at("X-Frame-Options"),
            ));
        }

        if headers.get("x-content-type-options").is_none() {
            found.push(observation(
                &INFO,
                exchange,
                format!("No X-Content-Type-Options on {}", exchange.host),
                "an HTML document sets X-Content-Type-Options: nosniff",
                "the header is absent",
                "Without it a browser may decide a response is a different type than \
                 the one it was served as, which turns an upload into a script.",
                Severity::Low,
                Significance::Reportable,
                header_at("X-Content-Type-Options"),
            ));
        }

        if headers.get("referrer-policy").is_none() {
            found.push(observation(
                &INFO,
                exchange,
                format!("No Referrer-Policy on {}", exchange.host),
                "an HTML document declares a Referrer-Policy",
                "the header is absent",
                "The default sends the full URL to other origins on navigation, which \
                 matters when a URL carries an identifier or a token.",
                Severity::Info,
                Significance::Reportable,
                header_at("Referrer-Policy"),
            ));
        }

        if headers.get("permissions-policy").is_none() {
            found.push(observation(
                &INFO,
                exchange,
                format!("No Permissions-Policy on {}", exchange.host),
                "an HTML document declares a Permissions-Policy",
                "the header is absent",
                "Context rather than an issue: the defaults are reasonable for most \
                 applications, and this is here so the absence is visible rather than \
                 assumed.",
                Severity::Info,
                // Informational on purpose. Filing this as something to fix is how a
                // findings list becomes something people stop reading.
                Significance::Informational,
                header_at("Permissions-Policy"),
            ));
        }

        found
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: observation.about.clone(),
            description: format!(
                "{} Expected: {}. Observed: {}.",
                observation.rationale, observation.expected, observation.observed
            ),
            impact: "A missing response header is not an exploited weakness. It is a \
                     layer that is not present, and what that costs depends on what \
                     else the application does."
                .into(),
            remediation: remediation_for(observation),
            reproduction: format!(
                "Request {} {} and read the response headers.",
                exchange.method, exchange.url
            ),
            cwe: Some("CWE-693".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: source(&INFO),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

fn remediation_for(observation: &Observation) -> String {
    let header = observation
        .location
        .as_ref()
        .map(|location| location.name.as_str())
        .unwrap_or("the header");
    match header {
        "Strict-Transport-Security" => {
            "Send Strict-Transport-Security on HTTPS responses, with a max-age long \
             enough to outlast a visit. Add includeSubDomains once every subdomain is \
             ready for it, and preload only when the answer is permanent."
                .into()
        }
        "Content-Security-Policy" => {
            "Send a Content-Security-Policy. Start in report-only mode against real \
             traffic so the policy is written from what the application does rather \
             than from what it was assumed to do."
                .into()
        }
        "X-Frame-Options" => {
            "Declare who may frame the document: a CSP frame-ancestors directive, or \
             X-Frame-Options for older clients."
                .into()
        }
        "X-Content-Type-Options" => {
            "Send X-Content-Type-Options: nosniff, and serve every response with the \
             content type it actually is."
                .into()
        }
        _ => format!("Send {header} on this response."),
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    #[test]
    fn an_https_response_without_hsts_is_observed() {
        let exchange = exchange(https().response(200, &[("Content-Type", "application/json")]));
        let found = SecurityHeaders.observe(&exchange);

        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].about.contains("Strict-Transport-Security"));
        assert!(found[0].is_reportable());
        // A lead, not a vulnerability. The severity is the ceiling of what it would
        // be worth, not a claim that it is worth that.
        assert_eq!(found[0].severity, Severity::Low);
    }

    #[test]
    fn a_plaintext_response_is_not_asked_about_hsts() {
        // The header does nothing on a plaintext response, so reporting its absence
        // would be reporting a fact with no consequence.
        let exchange = exchange(plaintext().response(200, &[("Content-Type", "text/plain")]));
        let found = SecurityHeaders.observe(&exchange);
        assert!(
            !found.iter().any(|o| o.about.contains("Strict-Transport")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_json_api_response_is_not_asked_about_document_headers() {
        // The check that keeps this detector from producing five rows per endpoint
        // on an API, where four of them are meaningless.
        let exchange = exchange(
            https()
                .response(200, &[("Content-Type", "application/json")])
                .header("Strict-Transport-Security", "max-age=31536000"),
        );
        assert!(SecurityHeaders.observe(&exchange).is_empty());
    }

    #[test]
    fn an_html_document_is_asked_about_all_of_them() {
        let exchange =
            exchange(https().response(200, &[("Content-Type", "text/html; charset=utf-8")]));
        let found = SecurityHeaders.observe(&exchange);

        let about: Vec<&str> = found.iter().map(|o| o.about.as_str()).collect();
        assert!(
            about.iter().any(|a| a.contains("Content-Security-Policy")),
            "{about:?}"
        );
        assert!(
            about.iter().any(|a| a.contains("framing policy")),
            "{about:?}"
        );
        assert!(
            about.iter().any(|a| a.contains("X-Content-Type-Options")),
            "{about:?}"
        );
        assert!(
            about.iter().any(|a| a.contains("Referrer-Policy")),
            "{about:?}"
        );
    }

    #[test]
    fn a_csp_with_frame_ancestors_satisfies_the_framing_question() {
        // Two ways to say the same thing, and a check that only knew one of them
        // would file a finding against an application that had done it properly.
        let exchange = exchange(
            https()
                .response(200, &[("Content-Type", "text/html")])
                .header(
                    "Content-Security-Policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
        );
        let found = SecurityHeaders.observe(&exchange);
        assert!(
            !found.iter().any(|o| o.about.contains("framing")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_correctly_configured_document_produces_nothing_reportable() {
        // The negative control. A clean run has to be silent, or the list is noise.
        let exchange = exchange(
            https()
                .response(200, &[("Content-Type", "text/html")])
                .header("Strict-Transport-Security", "max-age=63072000")
                .header(
                    "Content-Security-Policy",
                    "default-src 'self'; frame-ancestors 'none'",
                )
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "strict-origin-when-cross-origin"),
        );
        let reportable: Vec<_> = SecurityHeaders
            .observe(&exchange)
            .into_iter()
            .filter(|o| o.is_reportable())
            .collect();
        assert!(reportable.is_empty(), "{reportable:#?}");
    }

    #[test]
    fn a_permissions_policy_is_context_rather_than_something_to_fix() {
        let exchange = exchange(
            https()
                .response(200, &[("Content-Type", "text/html")])
                .header("Strict-Transport-Security", "max-age=1")
                .header("Content-Security-Policy", "frame-ancestors 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer"),
        );
        let found = SecurityHeaders.observe(&exchange);
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_reportable(), "{:#?}", found[0]);
    }

    #[test]
    fn a_response_that_was_not_served_is_left_alone() {
        for status in [301, 304, 404, 500] {
            let exchange = exchange(https().response(status, &[]));
            assert!(
                SecurityHeaders.observe(&exchange).is_empty(),
                "status {status} produced something"
            );
        }
    }

    #[test]
    fn header_casing_and_duplicates_do_not_confuse_it() {
        let exchange = exchange(
            https()
                .response(200, &[("CONTENT-TYPE", "TEXT/HTML")])
                .header("strict-transport-security", "max-age=1")
                .header("Strict-Transport-Security", "max-age=2"),
        );
        let found = SecurityHeaders.observe(&exchange);
        assert!(!found.iter().any(|o| o.about.contains("Strict-Transport")));
        // And the shouted content type still reads as a document.
        assert!(found
            .iter()
            .any(|o| o.about.contains("Content-Security-Policy")));
    }
}
