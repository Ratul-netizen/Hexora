//! TLS observations.
//!
//! What a handshake produced, in a form the whole product can use: the engine fills it
//! in, storage persists it, the UI renders it and the scanner reads it. It deliberately
//! contains no `rustls` types, so this crate stays free of a TLS implementation and the
//! same record survives if the implementation is ever swapped.
//!
//! These are **observations, not findings**. A deprecated protocol version is something
//! a tester should be told; turning it into a finding requires the verification engine.
//! See `docs/security-invariants.md`, invariant 6.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How strictly the server certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Verify against the platform root store. The default, and the only mode that
    /// authenticates the peer.
    #[default]
    Platform,
    /// Accept any certificate.
    ///
    /// Required for testing systems with self-signed, expired or internally-issued
    /// certificates — which is most staging estates. The connection is still
    /// encrypted, but the peer is **not authenticated**, so it offers no protection
    /// against interception. Every use is logged and recorded on the exchange.
    AcceptAny,
}

impl Verification {
    /// Whether this mode actually authenticates the peer.
    pub fn authenticates_peer(&self) -> bool {
        matches!(self, Self::Platform)
    }
}

impl fmt::Display for Verification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform => f.write_str("platform root store"),
            Self::AcceptAny => f.write_str("unverified (any certificate accepted)"),
        }
    }
}

/// What the handshake produced. Recorded on the exchange as observable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Negotiated protocol, e.g. `TLSv1.3`.
    pub protocol: String,
    /// Negotiated cipher suite.
    pub cipher_suite: String,
    /// ALPN protocol the server selected, if any.
    pub alpn: Option<String>,
    /// How the peer certificate was checked.
    pub verification: Verification,
    /// The peer's certificate chain, leaf first.
    pub peer_certificates: Vec<CertificateSummary>,
}

impl TlsInfo {
    /// Whether the peer was actually authenticated.
    pub fn peer_authenticated(&self) -> bool {
        self.verification.authenticates_peer()
    }

    /// Observations a tester would want raised without having to look.
    ///
    /// Deliberately conservative: these are *observations*, not findings. Promotion to
    /// a finding requires the verification engine, per invariant 6.
    pub fn observations(&self) -> Vec<String> {
        let mut out = Vec::new();

        if matches!(self.protocol.as_str(), "TLSv1.0" | "TLSv1.1") {
            out.push(format!(
                "negotiated {}, which is deprecated (RFC 8996)",
                self.protocol
            ));
        }
        if !self.peer_authenticated() {
            out.push("peer certificate was not verified".to_string());
        }
        if let Some(leaf) = self.peer_certificates.first() {
            if leaf.expired {
                out.push(format!("leaf certificate expired on {}", leaf.not_after));
            }
            if leaf.self_signed {
                out.push("leaf certificate is self-signed".to_string());
            }
        }
        out
    }
}

/// The parts of an X.509 certificate a tester reads at a glance.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    /// Whether the certificate is outside its validity window right now.
    pub expired: bool,
    /// Whether subject and issuer are identical.
    pub self_signed: bool,
    /// Subject alternative names.
    pub subject_alt_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(protocol: &str, verification: Verification) -> TlsInfo {
        TlsInfo {
            protocol: protocol.to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
            alpn: Some("http/1.1".to_string()),
            verification,
            peer_certificates: Vec::new(),
        }
    }

    #[test]
    fn platform_verification_is_the_default() {
        assert_eq!(Verification::default(), Verification::Platform);
        assert!(Verification::default().authenticates_peer());
    }

    #[test]
    fn accept_any_does_not_authenticate_the_peer() {
        assert!(!Verification::AcceptAny.authenticates_peer());
        assert!(Verification::AcceptAny.to_string().contains("unverified"));
    }

    #[test]
    fn a_modern_verified_connection_raises_nothing() {
        assert!(info("TLSv1.3", Verification::Platform)
            .observations()
            .is_empty());
    }

    #[test]
    fn deprecated_protocol_versions_are_observed() {
        for protocol in ["TLSv1.0", "TLSv1.1"] {
            let observations = info(protocol, Verification::Platform).observations();
            assert!(
                observations.iter().any(|o| o.contains("deprecated")),
                "{protocol}: {observations:?}"
            );
        }
    }

    #[test]
    fn an_unverified_connection_says_so() {
        let observations = info("TLSv1.3", Verification::AcceptAny).observations();
        assert!(
            observations.iter().any(|o| o.contains("not verified")),
            "{observations:?}"
        );
    }

    #[test]
    fn an_expired_self_signed_leaf_is_observed() {
        let mut tls = info("TLSv1.3", Verification::Platform);
        tls.peer_certificates.push(CertificateSummary {
            subject: "CN=staging.internal".into(),
            issuer: "CN=staging.internal".into(),
            not_before: "Jan 1 00:00:00 2020 GMT".into(),
            not_after: "Jan 1 00:00:00 2021 GMT".into(),
            expired: true,
            self_signed: true,
            subject_alt_names: vec!["staging.internal".into()],
        });
        let observations = tls.observations();
        assert!(
            observations.iter().any(|o| o.contains("expired")),
            "{observations:?}"
        );
        assert!(
            observations.iter().any(|o| o.contains("self-signed")),
            "{observations:?}"
        );
    }

    #[test]
    fn tls_info_round_trips_through_serialization() {
        let original = info("TLSv1.3", Verification::AcceptAny);
        let json = serde_json::to_string(&original).unwrap();
        let back: TlsInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }
}
