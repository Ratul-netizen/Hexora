//! `disclosure.headers` — what the response said about what is running.
//!
//! **Every observation this check makes is informational, and none of them becomes a
//! finding.** That is not a limitation, it is the whole design:
//!
//! > `Server: nginx/1.24.0` is a fact about the response. Whether it matters depends
//! > on the engagement.
//!
//! Turning it into a finding would require knowing the patch level, the
//! distribution's backporting policy, and whether the version is even truthful — and
//! a tool that files "nginx 1.24.0" as something to fix teaches people to skim past
//! the findings list, which is the only thing a findings list must never become.
//!
//! So these are recorded as context. A tester reading "this host runs nginx and
//! Express, and advertises PHP 8.1.2" is being given a map, not an accusation.

use super::prelude::*;

/// The check.
pub struct DisclosureHeaders;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("disclosure.headers"),
    name: "Technology disclosure",
    version: "1.0.0",
    about: "product and version headers the application volunteers",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: false,
};

/// The headers that name a product, and what to call each of them.
const DISCLOSING: &[(&str, &str)] = &[
    ("server", "server software"),
    ("x-powered-by", "application framework"),
    ("via", "intermediary"),
    ("x-aspnet-version", "ASP.NET runtime"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-generator", "generator"),
    ("x-drupal-cache", "Drupal"),
    ("x-runtime", "application runtime"),
];

impl PassiveCheck for DisclosureHeaders {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let mut found = Vec::new();

        for (name, what) in DISCLOSING {
            let Some(header) = exchange.response_headers.get(name) else {
                continue;
            };
            let value = crate::text(header);
            let value = value.trim();
            if value.is_empty() {
                continue;
            }

            found.push(observation(
                &INFO,
                exchange,
                // The value is in the title on purpose: the whole point is to say
                // what was disclosed, and it is the server's own words about itself.
                format!(
                    "Technology disclosure on {}: {} {}",
                    exchange.host, what, value
                ),
                "a response says no more about its stack than it has to",
                format!("{}: {}", header.name, value),
                "A fact, recorded as one. Whether a named version matters depends on \
                 the version, the distribution's patching, and whether the banner is \
                 even truthful — none of which a captured response settles.",
                Severity::Info,
                // Never reportable. See the module documentation.
                Significance::Informational,
                header_at(&header.name),
            ));
        }

        found
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        // Unreachable in practice: nothing this check produces is reportable, so the
        // scanner never asks for a writeup. Implemented honestly rather than with a
        // panic, because a trait method that would be wrong if it were ever called is
        // a trap for whoever changes the significance later.
        Writeup {
            target,
            title: observation.about.clone(),
            description: observation.rationale.clone(),
            impact: "Context for a tester, not an issue in itself.".into(),
            remediation: "Remove or generalise the header if the application has no \
                          reason to advertise its stack."
                .into(),
            reproduction: format!(
                "Request {} {} and read the response headers.",
                exchange.method, exchange.url
            ),
            cwe: Some("CWE-200".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: source(&INFO),
            severity: Severity::Info,
            location: observation.location.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    #[test]
    fn a_server_banner_is_an_observation_and_never_a_finding() {
        // The example from the roadmap, as a test.
        let exchange = exchange(https().response(200, &[("Server", "nginx/1.24.0")]));
        let found = DisclosureHeaders.observe(&exchange);

        assert_eq!(found.len(), 1);
        assert!(found[0].about.contains("nginx/1.24.0"));
        assert!(
            !found[0].is_reportable(),
            "a technology banner must not reach the findings list"
        );
        assert_eq!(found[0].severity, Severity::Info);
    }

    #[test]
    fn nothing_this_check_produces_is_ever_reportable() {
        // Checked across every header it knows about, so adding one cannot quietly
        // make this detector start filing findings.
        let mut build = https().response(200, &[]);
        for (name, _) in DISCLOSING {
            build = build.header(name, "something/1.0");
        }
        let found = DisclosureHeaders.observe(&exchange(build));

        assert_eq!(found.len(), DISCLOSING.len());
        assert!(found.iter().all(|o| !o.is_reportable()), "{found:#?}");
        assert!(found.iter().all(|o| o.severity == Severity::Info));
    }

    #[test]
    fn a_quiet_response_says_nothing() {
        let exchange = exchange(https().response(200, &[("Content-Type", "application/json")]));
        assert!(DisclosureHeaders.observe(&exchange).is_empty());
    }

    #[test]
    fn an_empty_banner_is_not_a_disclosure() {
        let exchange = exchange(https().response(200, &[("Server", "   ")]));
        assert!(DisclosureHeaders.observe(&exchange).is_empty());
    }
}
