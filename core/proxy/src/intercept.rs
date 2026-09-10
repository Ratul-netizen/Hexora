//! `CONNECT` tunnelling and TLS interception.
//!
//! # What actually happens
//!
//! A browser wanting `https://example.com` sends the proxy:
//!
//! ```text
//! CONNECT example.com:443 HTTP/1.1
//! ```
//!
//! and expects an opaque byte pipe. To *see* inside it, Hexora answers `200`, then
//! performs a TLS handshake with the client while pretending to be `example.com` —
//! using a certificate minted on the spot by [`crate::ca`] — and a second, real
//! handshake with the actual server. Two TLS sessions, plaintext in the middle:
//!
//! ```text
//! browser <--TLS(Hexora leaf)--> Hexora <--TLS(real cert)--> example.com
//! ```
//!
//! This is a man-in-the-middle attack performed with the user's consent. That framing
//! is worth keeping in mind, because every design decision here follows from it.
//!
//! # Two rules
//!
//! **Upstream verification is independent of the client's.** The browser is checking
//! Hexora's minted certificate, which tells it nothing about the real server. If
//! Hexora did not verify upstream, a tester intercepting their own traffic would lose
//! the protection they think they still have, silently. Verification upstream stays
//! on unless explicitly relaxed, exactly as for a direct request.
//!
//! **Hosts can be exempted from interception.** Certificate-pinned applications break
//! when intercepted, and some traffic — a tester's password manager, say — should
//! never be decrypted at all. An exempt host is tunnelled blind: bytes are copied,
//! nothing is decrypted, and nothing is recorded beyond the fact that a tunnel
//! happened.

use std::sync::Arc;

use hexora_types::error::{HexoraError, NetworkError, Result};
use hexora_types::http::HttpService;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ca::CertificateAuthority;

/// Which hosts get decrypted and which are passed through untouched.
#[derive(Debug, Clone, Default)]
pub struct InterceptionPolicy {
    /// Hosts never to intercept, matched like scope host rules (`*.` allowed).
    exempt: Vec<String>,
    /// When set, *only* these hosts are intercepted; everything else is tunnelled.
    only: Option<Vec<String>>,
}

impl InterceptionPolicy {
    /// Intercept everything.
    pub fn intercept_all() -> Self {
        Self::default()
    }

    /// Intercept everything except these hosts.
    pub fn exempting(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            exempt: hosts.into_iter().collect(),
            only: None,
        }
    }

    /// Intercept only these hosts, tunnelling everything else blind.
    ///
    /// The safer posture for a tester who does not want their own traffic decrypted
    /// while working.
    pub fn only(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            exempt: Vec::new(),
            only: Some(hosts.into_iter().collect()),
        }
    }

    /// Whether `host` should be decrypted.
    pub fn intercepts(&self, host: &str) -> bool {
        if self.exempt.iter().any(|p| matches_host(p, host)) {
            return false;
        }
        match &self.only {
            Some(allowed) => allowed.iter().any(|p| matches_host(p, host)),
            None => true,
        }
    }
}

/// Host matching with a single leading `*.` wildcard, as in scope rules.
///
/// A wildcard matches deeper labels but never the apex, for the same reason it does
/// not there: authority over a subdomain does not extend to the parent.
fn matches_host(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        }
        None => host == pattern,
    }
}

/// What happened to a `CONNECT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelOutcome {
    /// The tunnel was decrypted and its requests observed.
    Intercepted,
    /// Bytes were copied without being decrypted.
    Tunnelled,
}

/// Builds the TLS configuration used to impersonate `host` to the client.
pub fn server_config_for(
    ca: &CertificateAuthority,
    host: &str,
    alpn: &[Vec<u8>],
) -> Result<Arc<ServerConfig>> {
    let leaf = ca.leaf_for(host)?;

    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_error(host, format!("protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(leaf.chain.clone(), leaf.key.clone_key())
            .map_err(|e| tls_error(host, format!("installing the minted certificate: {e}")))?;

    // Only offer what Hexora can actually speak. Advertising h2 here would have the
    // browser send HTTP/2 frames the engine cannot parse yet, which looks to the user
    // like a broken site rather than an unimplemented feature.
    config.alpn_protocols = alpn.to_vec();
    Ok(Arc::new(config))
}

/// Answers a `CONNECT` with `200`, which is what tells the client to start its
/// handshake.
pub async fn accept_tunnel<S: AsyncWrite + Unpin>(client: &mut S) -> Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    client
        .flush()
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    Ok(())
}

/// Copies bytes both ways without decrypting anything.
///
/// Used for exempt hosts. Hexora learns that a tunnel to `service` happened and
/// nothing else — which is the point.
pub async fn tunnel_blind<C>(client: &mut C, service: &HttpService) -> Result<u64>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = TcpStream::connect((service.host.as_str(), service.port))
        .await
        .map_err(|e| {
            HexoraError::Network(NetworkError::Io(format!(
                "connecting to {}: {e}",
                service.authority()
            )))
        })?;

    let (copied, _) = tokio::io::copy_bidirectional(client, &mut upstream)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;

    tracing::debug!(
        host = %service.authority(),
        bytes = copied,
        "tunnelled without interception"
    );
    Ok(copied)
}

fn tls_error(host: &str, reason: String) -> HexoraError {
    HexoraError::Network(NetworkError::Tls {
        peer: host.to_string(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intercept_all_intercepts_everything() {
        let policy = InterceptionPolicy::intercept_all();
        assert!(policy.intercepts("example.com"));
        assert!(policy.intercepts("anything.at.all"));
    }

    #[test]
    fn exempt_hosts_are_not_intercepted() {
        let policy = InterceptionPolicy::exempting(["vault.example.com".to_string()]);
        assert!(!policy.intercepts("vault.example.com"));
        assert!(policy.intercepts("app.example.com"));
    }

    #[test]
    fn exemptions_accept_a_subdomain_wildcard() {
        let policy = InterceptionPolicy::exempting(["*.banking.test".to_string()]);
        assert!(!policy.intercepts("secure.banking.test"));
        assert!(!policy.intercepts("a.b.banking.test"));
        // The apex is not covered, exactly as in scope rules.
        assert!(policy.intercepts("banking.test"));
    }

    #[test]
    fn a_wildcard_does_not_match_a_lookalike_domain() {
        let policy = InterceptionPolicy::exempting(["*.example.com".to_string()]);
        assert!(policy.intercepts("notexample.com"));
        assert!(policy.intercepts("example.com.evil.net"));
    }

    #[test]
    fn only_mode_tunnels_everything_else() {
        // The safer posture: decrypt the target, leave the tester's own traffic alone.
        let policy = InterceptionPolicy::only(["target.test".to_string()]);
        assert!(policy.intercepts("target.test"));
        assert!(!policy.intercepts("mail.google.com"));
        assert!(!policy.intercepts("vault.example.com"));
    }

    #[test]
    fn an_exemption_beats_an_only_list() {
        let mut policy = InterceptionPolicy::only(["example.com".to_string()]);
        policy.exempt.push("example.com".to_string());
        assert!(
            !policy.intercepts("example.com"),
            "a host the user asked never to decrypt must never be decrypted"
        );
    }

    #[test]
    fn host_matching_ignores_case() {
        let policy = InterceptionPolicy::exempting(["Example.COM".to_string()]);
        assert!(!policy.intercepts("example.com"));
    }

    #[test]
    fn a_server_config_is_built_from_a_minted_leaf() {
        let ca = CertificateAuthority::generate().unwrap();
        let config = server_config_for(&ca, "example.com", &[b"http/1.1".to_vec()]).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn only_protocols_hexora_can_speak_are_advertised() {
        // Offering h2 would have the browser send frames the engine cannot parse,
        // which the user would experience as a broken site.
        let ca = CertificateAuthority::generate().unwrap();
        let config = server_config_for(&ca, "example.com", &[b"http/1.1".to_vec()]).unwrap();
        assert!(
            !config.alpn_protocols.iter().any(|p| p == b"h2"),
            "HTTP/2 is not implemented, so it must not be advertised"
        );
    }

    #[tokio::test]
    async fn accepting_a_tunnel_sends_the_established_response() {
        let mut out = Vec::new();
        accept_tunnel(&mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text:?}");
    }
}
