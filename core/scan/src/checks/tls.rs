//! `tls.observations` — what the handshake already recorded.
//!
//! No new connection is made, and none could be: this reads the
//! [`TlsInfo`](hexora_types::tls::TlsInfo) the HTTP engine wrote down when the
//! exchange happened. A TLS check that reconnects to enumerate cipher suites is a
//! different, active thing.
//!
//! It also invents nothing from data it does not have. `TlsInfo` records the
//! negotiated protocol, the cipher suite, the ALPN selection, how the peer was
//! verified and a summary of the leaf certificate — so those are what it can talk
//! about. It cannot say whether the server *would* have accepted TLS 1.0, because
//! nobody asked it to.
//!
//! # One thing deliberately not reported
//!
//! `Verification::AcceptAny` means the tester told Hexora not to check the
//! certificate, usually with `--insecure` against a staging box. Reporting "the peer
//! certificate was not verified" as an issue would be reporting the tester's own
//! flag back at them, so it is recorded as context — the fact that a run was done
//! that way is worth knowing when reading the rest of it.

use hexora_types::tls::Verification as TlsVerification;

use super::prelude::*;

/// The check.
pub struct TlsObservations;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("tls.observations"),
    name: "TLS observations",
    version: "1.0.0",
    about: "what the recorded handshake showed, without making a new one",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: false,
    settles: None,
};

impl PassiveCheck for TlsObservations {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let Some(tls) = &exchange.tls else {
            return Vec::new();
        };
        let mut found = Vec::new();

        if matches!(tls.protocol.as_str(), "TLSv1.0" | "TLSv1.1") {
            found.push(observation(
                &INFO,
                exchange,
                format!("{} negotiated {}", exchange.host, tls.protocol),
                "a connection negotiates TLS 1.2 or better",
                format!("it negotiated {}", tls.protocol),
                "RFC 8996 deprecated both. This is what *this* connection agreed on, \
                 which is a lower bound on what the server accepts rather than a \
                 statement about its whole configuration — nothing here asked it for \
                 anything else.",
                Severity::Medium,
                Significance::Reportable,
                None,
            ));
        }

        if let Some(leaf) = tls.peer_certificates.first() {
            if leaf.expired {
                found.push(observation(
                    &INFO,
                    exchange,
                    format!("{} served an expired certificate", exchange.host),
                    "the leaf certificate is inside its validity window",
                    format!("it expired on {}", leaf.not_after),
                    "A browser refuses this, so either users are being taught to click \
                     through warnings or this host is not reached by browsers.",
                    Severity::Medium,
                    Significance::Reportable,
                    None,
                ));
            }
            if leaf.self_signed {
                found.push(observation(
                    &INFO,
                    exchange,
                    format!("{} served a self-signed certificate", exchange.host),
                    "the leaf certificate is issued by a party the client trusts",
                    "subject and issuer are the same",
                    "Normal on a staging system and not on a production one. Which \
                     this is, is the tester's call.",
                    Severity::Low,
                    Significance::Reportable,
                    None,
                ));
            }
        }

        // Context, every time there was a handshake: what was actually agreed.
        found.push(observation(
            &INFO,
            exchange,
            format!(
                "{} negotiated {} with {}",
                exchange.host, tls.protocol, tls.cipher_suite
            ),
            "recorded for context",
            format!(
                "{}, {}{}",
                tls.protocol,
                tls.cipher_suite,
                tls.alpn
                    .as_deref()
                    .map(|alpn| format!(", ALPN {alpn}"))
                    .unwrap_or_default()
            ),
            "What this connection agreed on. A lower bound on the server's \
             configuration, not a survey of it.",
            Severity::Info,
            Significance::Informational,
            None,
        ));

        if !matches!(tls.verification, TlsVerification::Platform) {
            found.push(observation(
                &INFO,
                exchange,
                format!(
                    "{} was contacted without verifying its certificate",
                    exchange.host
                ),
                "recorded for context",
                "certificate verification was relaxed for this connection",
                "The tester asked for this, so it is not an issue with the \
                 application. It is worth knowing while reading everything else that \
                 came from this connection.",
                Severity::Info,
                Significance::Informational,
                None,
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
            impact: "Recorded from the handshake this exchange actually made. What \
                     the server would accept from a different client is not something \
                     a captured connection shows."
                .into(),
            remediation: "Check the host's TLS configuration directly. Hexora has \
                          reported one negotiated connection, not a survey."
                .into(),
            reproduction: format!(
                "Open {} and read the negotiated protocol and certificate.",
                exchange.url
            ),
            cwe: Some("CWE-326".into()),
            owasp: Some("A02:2021 Cryptographic Failures".into()),
            source: source(&INFO),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::tls::{CertificateSummary, TlsInfo};

    use crate::checks::test_support::*;

    use super::*;

    fn certificate(expired: bool, self_signed: bool) -> CertificateSummary {
        CertificateSummary {
            subject: "CN=api.example.com".into(),
            issuer: if self_signed {
                "CN=api.example.com".into()
            } else {
                "CN=Example CA".into()
            },
            not_before: "2025-01-01T00:00:00Z".into(),
            not_after: "2026-01-01T00:00:00Z".into(),
            expired,
            self_signed,
            subject_alt_names: vec!["api.example.com".into()],
        }
    }

    fn tls(protocol: &str) -> TlsInfo {
        TlsInfo {
            protocol: protocol.into(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".into(),
            alpn: Some("h2".into()),
            verification: TlsVerification::Platform,
            peer_certificates: vec![certificate(false, false)],
        }
    }

    #[test]
    fn an_exchange_with_no_handshake_says_nothing() {
        let exchange = exchange(plaintext().response(200, &[]));
        assert!(TlsObservations.observe(&exchange).is_empty());
    }

    #[test]
    fn a_modern_connection_produces_only_context() {
        let exchange = exchange(https().response(200, &[]).tls(tls("TLSv1.3")));
        let found = TlsObservations.observe(&exchange);

        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(!found[0].is_reportable());
        assert!(found[0].observed.contains("ALPN h2"));
    }

    #[test]
    fn a_deprecated_protocol_is_reported_as_what_this_connection_agreed() {
        let exchange = exchange(https().response(200, &[]).tls(tls("TLSv1.0")));
        let found = TlsObservations.observe(&exchange);

        let deprecated = found.iter().find(|o| o.about.contains("TLSv1.0")).unwrap();
        assert!(deprecated.is_reportable());
        // The wording has to stay honest about what was and was not established.
        assert!(
            deprecated.rationale.contains("lower bound"),
            "{deprecated:#?}"
        );
    }

    #[test]
    fn an_expired_or_self_signed_leaf_is_reported() {
        let mut info = tls("TLSv1.3");
        info.peer_certificates = vec![certificate(true, true)];
        let exchange = exchange(https().response(200, &[]).tls(info));
        let found = TlsObservations.observe(&exchange);

        assert!(
            found.iter().any(|o| o.about.contains("expired")),
            "{found:#?}"
        );
        assert!(
            found.iter().any(|o| o.about.contains("self-signed")),
            "{found:#?}"
        );
    }

    #[test]
    fn the_testers_own_insecure_flag_is_context_rather_than_an_issue() {
        // Reporting this as a problem would be reporting `--insecure` back at the
        // person who typed it.
        let mut info = tls("TLSv1.3");
        info.verification = TlsVerification::AcceptAny;
        let exchange = exchange(https().response(200, &[]).tls(info));
        let found = TlsObservations.observe(&exchange);

        let relaxed = found
            .iter()
            .find(|o| o.about.contains("without verifying"))
            .unwrap();
        assert!(!relaxed.is_reportable(), "{relaxed:#?}");
    }

    #[test]
    fn a_handshake_with_no_certificates_does_not_panic() {
        let mut info = tls("TLSv1.3");
        info.peer_certificates.clear();
        let exchange = exchange(https().response(200, &[]).tls(info));
        assert_eq!(TlsObservations.observe(&exchange).len(), 1);
    }
}
