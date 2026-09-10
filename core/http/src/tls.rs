//! TLS for outbound connections.
//!
//! # The certificate-verification problem
//!
//! An ordinary HTTP client has an easy job here: verify the chain, refuse otherwise.
//! A security tool cannot do that, because the systems worth testing are exactly the
//! ones with broken certificates — staging environments with self-signed certs,
//! appliances with expired ones, internal CAs nobody exported. A tool that refuses to
//! connect to those is useless for the work.
//!
//! The wrong fix is a global "ignore TLS errors" switch, which is what most tools
//! ship. Flip it once and every subsequent connection is silently unauthenticated,
//! including the ones where a real interception attack would have been visible.
//!
//! So verification here is:
//!
//! * **per-connection**, not global — [`Verification`] is part of the request's
//!   options, so relaxing it for one host does not relax it for the next;
//! * **recorded** — [`TlsInfo::verification`] says how the peer was trusted, so a
//!   finding derived from an unverified connection can disclose that; and
//! * **loud** — every unverified handshake logs a warning naming the host.
//!
//! # Root store
//!
//! Roots come from the **platform** store rather than a bundled copy. A tester behind
//! a corporate TLS-inspecting proxy has that proxy's CA installed system-wide; a
//! bundled root set would reject every connection and look like a Hexora bug. It also
//! means an administrator's trust decisions apply to Hexora automatically.

use std::fmt;
use std::sync::Arc;

use hexora_types::error::{HexoraError, NetworkError, Result, TimeoutPhase};
use hexora_types::limits::Limits;
use hexora_types::tls::{CertificateSummary, TlsInfo, Verification};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// A client certificate and its private key, for mTLS.
#[derive(Clone)]
pub struct ClientIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the private key, not even its length.
        f.debug_struct("ClientIdentity")
            .field("certificates", &self.certs.len())
            .finish_non_exhaustive()
    }
}

impl ClientIdentity {
    /// Loads a PEM certificate chain and private key from disk.
    pub fn from_pem_files(cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<Self> {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            HexoraError::invalid_input(
                "client-cert",
                format!("cannot read {}: {e}", cert_path.display()),
            )
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            HexoraError::invalid_input(
                "client-key",
                format!("cannot read {}: {e}", key_path.display()),
            )
        })?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Parses a PEM certificate chain and private key from memory.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| HexoraError::invalid_input("client-cert", e.to_string()))?;
        if certs.is_empty() {
            return Err(HexoraError::invalid_input(
                "client-cert",
                "no CERTIFICATE block found in the PEM file",
            ));
        }

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| HexoraError::invalid_input("client-key", e.to_string()))?
            .ok_or_else(|| {
                HexoraError::invalid_input(
                    "client-key",
                    "no PRIVATE KEY block found in the PEM file",
                )
            })?;

        Ok(Self {
            certs,
            key: Arc::new(key),
        })
    }
}

/// Per-connection TLS settings.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// How to check the server certificate.
    pub verification: Verification,
    /// ALPN protocols to offer, in preference order.
    ///
    /// Empty means no ALPN extension is sent at all, which is itself a useful test
    /// case — some servers behave differently without it.
    pub alpn: Vec<Vec<u8>>,
    /// Client certificate for mTLS.
    pub client_identity: Option<ClientIdentity>,
    /// Override the SNI name sent in the handshake.
    ///
    /// Sending a name that disagrees with the `Host` header is a routing and
    /// virtual-host test, so it has to be expressible.
    pub sni_override: Option<String>,
}

impl TlsConfig {
    /// Settings for an ordinary verified connection offering HTTP/1.1.
    pub fn verified() -> Self {
        Self {
            verification: Verification::Platform,
            alpn: vec![b"http/1.1".to_vec()],
            client_identity: None,
            sni_override: None,
        }
    }

    /// Settings that accept any certificate. See [`Verification::AcceptAny`].
    pub fn accept_any() -> Self {
        Self {
            verification: Verification::AcceptAny,
            ..Self::verified()
        }
    }

    /// Builds the rustls client configuration.
    pub fn build(&self) -> Result<Arc<ClientConfig>> {
        // The provider is passed explicitly rather than installed process-wide, so
        // linking Hexora into another program cannot change that program's crypto.
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_setup_error(format!("protocol versions: {e}")))?;

        let builder = match self.verification {
            Verification::Platform => builder.with_root_certificates(platform_roots()?),
            Verification::AcceptAny => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate { provider })),
        };

        let mut config = match &self.client_identity {
            Some(identity) => builder
                .with_client_auth_cert(identity.certs.clone(), identity.key.clone_key())
                .map_err(|e| tls_setup_error(format!("client certificate: {e}")))?,
            None => builder.with_no_client_auth(),
        };

        config.alpn_protocols = self.alpn.clone();
        Ok(Arc::new(config))
    }
}

/// Loads the operating system's trusted roots.
fn platform_roots() -> Result<RootCertStore> {
    let loaded = rustls_native_certs::load_native_certs();

    let mut store = RootCertStore::empty();
    let mut rejected = 0usize;
    for cert in loaded.certs {
        if store.add(cert).is_err() {
            rejected += 1;
        }
    }

    if !loaded.errors.is_empty() {
        // Not fatal on its own: partial loads are normal on some systems. It becomes
        // fatal below only if nothing usable was found.
        tracing::warn!(
            errors = ?loaded.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "some platform root certificates could not be loaded"
        );
    }
    if rejected > 0 {
        tracing::debug!(rejected, "platform roots rejected as unparseable");
    }

    if store.is_empty() {
        return Err(tls_setup_error(
            "no usable certificates in the platform trust store".to_string(),
        ));
    }
    Ok(store)
}

/// Performs the TLS handshake over an established TCP connection.
///
/// Returns the encrypted stream together with what the handshake produced, so the
/// caller records the TLS facts on the exchange rather than having to ask for them.
pub async fn handshake(
    tcp: tokio::net::TcpStream,
    host: &str,
    settings: &TlsConfig,
    limits: &Limits,
) -> Result<(
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    TlsInfo,
)> {
    let config = settings.build()?;
    let connector = tokio_rustls::TlsConnector::from(config);

    // SNI is a DNS name. An IP literal legitimately has none, and an override exists
    // so a tester can deliberately disagree with the Host header.
    let sni_source = settings.sni_override.as_deref().unwrap_or(host);
    let sni =
        ServerName::try_from(sni_source.trim_matches(['[', ']']).to_string()).map_err(|e| {
            HexoraError::invalid_input(
                "sni",
                format!("{sni_source:?} is not a valid server name: {e}"),
            )
        })?;

    let stream = tokio::time::timeout(limits.tls_timeout, connector.connect(sni, tcp))
        .await
        .map_err(|_| {
            HexoraError::Network(NetworkError::Timeout {
                phase: TimeoutPhase::TlsHandshake,
                elapsed: limits.tls_timeout,
            })
        })?
        .map_err(|e| {
            HexoraError::Network(NetworkError::Tls {
                peer: host.to_string(),
                reason: e.to_string(),
            })
        })?;

    let info = describe(&stream, settings.verification);

    if !info.peer_authenticated() {
        // Warn every time, naming the host. An unverified connection offers no
        // protection against interception, and that must never become invisible
        // just because it was requested once.
        tracing::warn!(
            host,
            protocol = %info.protocol,
            "TLS peer was not verified; the connection is encrypted but unauthenticated"
        );
    }
    for observation in info.observations() {
        tracing::info!(host, "{observation}");
    }

    Ok((stream, info))
}

fn describe(
    stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    verification: Verification,
) -> TlsInfo {
    let (_, connection) = stream.get_ref();

    TlsInfo {
        protocol: connection
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "unknown".to_string()),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_else(|| "unknown".to_string()),
        alpn: connection
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        verification,
        peer_certificates: connection
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| summarise_certificate(c)).collect())
            .unwrap_or_default(),
    }
}

/// Summarises a DER-encoded certificate.
///
/// A certificate that cannot be parsed produces a placeholder rather than an error:
/// the connection already succeeded, and failing the whole exchange because a display
/// field could not be rendered would be the wrong trade.
pub fn summarise_certificate(der: &[u8]) -> CertificateSummary {
    use x509_parser::prelude::*;

    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let validity = cert.validity();
            let sans = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|ext| {
                    ext.value
                        .general_names
                        .iter()
                        .map(|name| name.to_string())
                        .collect()
                })
                .unwrap_or_default();

            CertificateSummary {
                self_signed: subject == issuer,
                expired: !validity.is_valid(),
                not_before: validity.not_before.to_string(),
                not_after: validity.not_after.to_string(),
                subject,
                issuer,
                subject_alt_names: sans,
            }
        }
        Err(e) => CertificateSummary {
            subject: format!("<unparseable certificate: {e}>"),
            issuer: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            expired: false,
            self_signed: false,
            subject_alt_names: Vec::new(),
        },
    }
}

/// A verifier that accepts any certificate.
///
/// Signature checking is still delegated to the crypto provider — the handshake must
/// remain cryptographically coherent, we are only declining to check *who* the peer
/// is. Skipping signature verification too would allow a garbage handshake to succeed
/// and produce results that mean nothing.
#[derive(Debug)]
struct AcceptAnyCertificate {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_setup_error(reason: String) -> HexoraError {
    HexoraError::Network(NetworkError::Tls {
        peer: "<local configuration>".to_string(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verified_config_builds_against_the_platform_store() {
        // Fails only on a machine with no usable trust store, which is itself
        // something a tester needs told rather than silently worked around.
        let config = TlsConfig::verified().build();
        assert!(config.is_ok(), "{:?}", config.err());
    }

    #[test]
    fn an_accept_any_config_builds_without_a_trust_store() {
        assert!(TlsConfig::accept_any().build().is_ok());
    }

    #[test]
    fn http_1_1_is_offered_by_default() {
        let config = TlsConfig::verified().build().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn alpn_can_be_omitted_entirely() {
        let mut settings = TlsConfig::verified();
        settings.alpn.clear();
        let config = settings.build().unwrap();
        assert!(
            config.alpn_protocols.is_empty(),
            "sending no ALPN extension must remain expressible"
        );
    }

    #[test]
    fn a_client_identity_never_renders_its_private_key() {
        // A structurally valid but obviously fake key pair would require real DER;
        // the property under test is the Debug impl, which does not need one.
        let identity = ClientIdentity {
            certs: vec![CertificateDer::from(vec![0x30, 0x00])],
            key: Arc::new(PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(vec![0xAB, 0xCD]),
            )),
        };
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("certificates"), "{rendered}");
        assert!(!rendered.contains("key"), "{rendered}");
        assert!(!rendered.contains("AB"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
    }

    #[test]
    fn malformed_client_certificates_are_rejected_with_a_useful_message() {
        let err = ClientIdentity::from_pem(b"not a pem file", b"nor is this").unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("CERTIFICATE"), "{err}");
    }

    #[test]
    fn a_missing_client_certificate_file_is_reported_by_path() {
        let err = ClientIdentity::from_pem_files(
            std::path::Path::new("/nonexistent/cert.pem"),
            std::path::Path::new("/nonexistent/key.pem"),
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("cert.pem"), "{err}");
    }

    #[test]
    fn an_unparseable_certificate_summarises_rather_than_failing() {
        let summary = summarise_certificate(&[0xff, 0xfe, 0x00]);
        assert!(summary.subject.contains("unparseable"), "{summary:?}");
    }
}
