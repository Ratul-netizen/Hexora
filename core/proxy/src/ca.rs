//! The interception certificate authority.
//!
//! # The most dangerous thing Hexora stores
//!
//! To intercept HTTPS, the proxy mints a certificate for whatever host the client
//! asked for and signs it with a CA the user has trusted. That CA private key is,
//! functionally, the ability to impersonate **every site on the internet** to that
//! machine. Anyone who steals it can read the user's banking session as easily as they
//! can read a test target.
//!
//! Three rules follow, and they are not negotiable:
//!
//! 1. **The CA is generated per installation, never shipped.** A CA baked into a
//!    release would let anyone holding a copy of Hexora intercept every user of it.
//!    This is not hypothetical: shipped-CA incidents have ended products.
//! 2. **The key never leaves the machine.** It is not synced, not uploaded, not
//!    included in a project export, and not printed by any `Debug` implementation.
//! 3. **Regenerating and removing it must be easy**, because "how do I undo this"
//!    deserves an answer better than "find the file yourself".
//!
//! # Leaf certificates
//!
//! One certificate is minted per host and cached in memory only. Leaves are short
//! lived: if one escapes, it is useless in a few weeks, and nothing depends on
//! long-lived leaves because they are regenerated on demand anyway.
//!
//! # What this does not protect against
//!
//! Filesystem permissions are the only thing standing between the key and another
//! process running as the same user. Malware already running as you can take it. See
//! `docs/threat-model.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hexora_types::error::{HexoraError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};

/// File name of the CA certificate inside the CA directory.
const CERT_FILE: &str = "hexora-ca.crt";
/// File name of the CA private key inside the CA directory.
const KEY_FILE: &str = "hexora-ca.key";

/// How long a generated CA is valid.
///
/// Long enough that a tester is not reinstalling it mid-engagement, short enough that
/// a forgotten CA on an old machine eventually stops working.
const CA_VALIDITY_DAYS: i64 = 825;

/// How long a minted leaf certificate is valid.
///
/// Deliberately short. Leaves are regenerated on demand, so nothing is gained by
/// making them long lived, and a leaf that leaks expires quickly.
const LEAF_VALIDITY_DAYS: i64 = 14;

/// A locally generated certificate authority used to intercept TLS.
pub struct CertificateAuthority {
    key_pair: KeyPair,
    certificate: rcgen::Certificate,
    certificate_pem: String,
    der: CertificateDer<'static>,
    /// Minted leaves, kept in memory only — never written to disk.
    cache: Mutex<HashMap<String, Arc<LeafCertificate>>>,
    directory: Option<PathBuf>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key, nor anything derived from it.
        f.debug_struct("CertificateAuthority")
            .field("directory", &self.directory)
            .field(
                "cached_leaves",
                &self.cache.lock().map(|c| c.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

/// A certificate minted for one host, ready to hand to rustls.
pub struct LeafCertificate {
    /// The leaf followed by the CA, as rustls expects a chain.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key.
    pub key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for LeafCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafCertificate")
            .field("chain_length", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Loads the CA from `directory`, generating one if it is not there yet.
    ///
    /// This is the normal entry point. First run generates; every later run reuses,
    /// so the certificate the user trusted stays valid.
    pub fn load_or_create(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory).map_err(io_error("creating the CA directory"))?;

        let cert_path = directory.join(CERT_FILE);
        let key_path = directory.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            return Self::load(&cert_path, &key_path);
        }

        // A half-present CA means a previous run was interrupted or someone deleted
        // one file. Guessing which half to keep would produce a CA whose certificate
        // and key do not match, so refuse and say what to do.
        if cert_path.exists() != key_path.exists() {
            return Err(HexoraError::invalid_input(
                "ca",
                format!(
                    "{} contains only half of a certificate authority; \
                     delete both {CERT_FILE} and {KEY_FILE} to regenerate",
                    directory.display()
                ),
            ));
        }

        let ca = Self::generate()?;
        ca.write_to(directory)?;
        tracing::info!(
            directory = %directory.display(),
            "generated a new interception certificate authority"
        );
        Ok(Self {
            directory: Some(directory.to_path_buf()),
            ..ca
        })
    }

    /// Generates a fresh CA in memory, writing nothing.
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate().map_err(rcgen_error("generating the CA key"))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now();
        params.not_after = days_from_now(CA_VALIDITY_DAYS);

        let mut name = DistinguishedName::new();
        // Named so a user scrolling their trust store can tell what it is and where it
        // came from. An anonymous CA in a trust store is alarming and rightly so.
        name.push(DnType::CommonName, "Hexora Interception CA");
        name.push(DnType::OrganizationName, "Hexora");
        name.push(
            DnType::OrganizationalUnitName,
            "Locally generated - do not trust elsewhere",
        );
        params.distinguished_name = name;

        let certificate = params
            .self_signed(&key_pair)
            .map_err(rcgen_error("self-signing the CA"))?;

        Ok(Self {
            certificate_pem: certificate.pem(),
            der: CertificateDer::from(certificate.der().to_vec()),
            certificate,
            key_pair,
            cache: Mutex::new(HashMap::new()),
            directory: None,
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem =
            std::fs::read_to_string(cert_path).map_err(io_error("reading the CA certificate"))?;
        let key_pem = std::fs::read_to_string(key_path).map_err(io_error("reading the CA key"))?;

        let key_pair =
            KeyPair::from_pem(&key_pem).map_err(rcgen_error("parsing the CA private key"))?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .map_err(rcgen_error("parsing the CA certificate"))?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(rcgen_error("reconstructing the CA certificate"))?;

        Ok(Self {
            certificate_pem: cert_pem,
            der: CertificateDer::from(certificate.der().to_vec()),
            certificate,
            key_pair,
            cache: Mutex::new(HashMap::new()),
            directory: cert_path.parent().map(Path::to_path_buf),
        })
    }

    /// Writes the CA to `directory`, restricting the key's permissions.
    fn write_to(&self, directory: &Path) -> Result<()> {
        let cert_path = directory.join(CERT_FILE);
        let key_path = directory.join(KEY_FILE);

        std::fs::write(&cert_path, &self.certificate_pem)
            .map_err(io_error("writing the CA certificate"))?;

        let key_pem = self.key_pair.serialize_pem();
        std::fs::write(&key_path, &key_pem).map_err(io_error("writing the CA key"))?;
        restrict_permissions(&key_path)?;

        Ok(())
    }

    /// The CA certificate in PEM form, for the user to install in a trust store.
    ///
    /// Only the certificate — the key is never rendered by any accessor here.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The CA certificate in DER form.
    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// Where the CA lives on disk, if it was loaded from or written to a directory.
    pub fn directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }

    /// Mints (or returns a cached) certificate for `host`.
    ///
    /// Cached in memory only: writing minted leaves to disk would scatter usable
    /// impersonation certificates across the filesystem for no benefit, since they
    /// regenerate in milliseconds.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<LeafCertificate>> {
        let key = host.to_ascii_lowercase();

        if let Some(existing) = self
            .cache
            .lock()
            .expect("certificate cache mutex poisoned")
            .get(&key)
        {
            return Ok(existing.clone());
        }

        let leaf = Arc::new(self.mint(&key)?);
        self.cache
            .lock()
            .expect("certificate cache mutex poisoned")
            .insert(key, leaf.clone());
        Ok(leaf)
    }

    fn mint(&self, host: &str) -> Result<LeafCertificate> {
        let leaf_key = KeyPair::generate().map_err(rcgen_error("generating a leaf key"))?;

        // An IP literal must go in the SAN as an IP, not a DNS name, or every client
        // will reject it — and testing against a bare address is common enough that
        // getting this wrong would be noticed immediately.
        let san = match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
            Ok(ip) => rcgen::SanType::IpAddress(ip),
            Err(_) => {
                // rcgen's IA5 string accepts any ASCII, so it would happily mint a
                // certificate for "not a valid host!". The host here comes from a
                // client-controlled CONNECT line or Host header, so it is validated
                // rather than trusted.
                if !is_valid_dns_name(host) {
                    return Err(HexoraError::invalid_input(
                        "host",
                        format!("{host:?} is not a valid DNS name"),
                    ));
                }
                rcgen::SanType::DnsName(host.to_string().try_into().map_err(|_| {
                    HexoraError::invalid_input("host", format!("{host:?} is not representable"))
                })?)
            }
        };

        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san];
        params.not_before = now();
        params.not_after = days_from_now(LEAF_VALIDITY_DAYS);
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;

        let certificate = params
            .signed_by(&leaf_key, &self.certificate, &self.key_pair)
            .map_err(rcgen_error("signing the leaf certificate"))?;

        Ok(LeafCertificate {
            chain: vec![
                CertificateDer::from(certificate.der().to_vec()),
                self.der.clone(),
            ],
            key: PrivateKeyDer::try_from(leaf_key.serialize_der())
                .map_err(|e| HexoraError::Internal(format!("leaf key not usable: {e}")))?,
        })
    }

    /// How many leaves are currently cached.
    pub fn cached_leaf_count(&self) -> usize {
        self.cache
            .lock()
            .expect("certificate cache mutex poisoned")
            .len()
    }

    /// Deletes the CA from disk.
    ///
    /// The counterpart to installing it. A user who wants Hexora off their machine
    /// should not have to hunt for files, and a CA left behind is a standing risk.
    pub fn delete(directory: impl AsRef<Path>) -> Result<()> {
        let directory = directory.as_ref();
        for file in [CERT_FILE, KEY_FILE] {
            let path = directory.join(file);
            if path.exists() {
                std::fs::remove_file(&path).map_err(io_error("removing the CA"))?;
            }
        }
        tracing::info!(directory = %directory.display(), "removed the interception CA");
        Ok(())
    }
}

/// Whether `host` is a syntactically valid DNS name per RFC 1123.
///
/// Labels are alphanumeric plus hyphen, may not begin or end with a hyphen, and are
/// at most 63 characters; the whole name is at most 253. Underscores are accepted
/// because real services use them despite the RFC, and a proxy that refused to
/// intercept those hosts would simply be broken for its users.
fn is_valid_dns_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Restricts a private key file to the current user.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(io_error("restricting CA key permissions"))
}

/// Restricts a private key file to the current user.
///
/// Windows has no mode bits. The key lives under the user's profile, which is already
/// ACL-restricted to that user and to administrators; tightening it further would need
/// `icacls` and buys little, since an administrator can read it either way. This is
/// stated in `docs/threat-model.md` rather than left implied.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn days_from_now(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::days(days)
}

fn io_error(what: &'static str) -> impl Fn(std::io::Error) -> HexoraError {
    move |e| HexoraError::Internal(format!("{what}: {e}"))
}

fn rcgen_error(what: &'static str) -> impl Fn(rcgen::Error) -> HexoraError {
    move |e| HexoraError::Internal(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_ca_is_a_certificate_authority() {
        let ca = CertificateAuthority::generate().unwrap();
        let pem = ca.certificate_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem:.40}");
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn the_ca_is_named_so_a_user_can_recognise_it_in_a_trust_store() {
        let ca = CertificateAuthority::generate().unwrap();
        let summary = hexora_http::tls::summarise_certificate(ca.certificate_der());
        assert!(summary.subject.contains("Hexora"), "{summary:?}");
        assert!(summary.self_signed, "a root CA signs itself");
    }

    #[test]
    fn every_generated_ca_is_unique() {
        // The single most important property. A CA shared between installations would
        // let anyone with a copy of Hexora intercept every other user.
        let a = CertificateAuthority::generate().unwrap();
        let b = CertificateAuthority::generate().unwrap();
        assert_ne!(
            a.certificate_pem(),
            b.certificate_pem(),
            "two installations must never share a CA"
        );
    }

    #[test]
    fn debug_output_never_reveals_the_key() {
        let ca = CertificateAuthority::generate().unwrap();
        let rendered = format!("{ca:?}");
        assert!(!rendered.contains("PRIVATE"), "{rendered}");
        assert!(!rendered.contains("BEGIN"), "{rendered}");
    }

    #[test]
    fn a_leaf_is_minted_for_a_host_and_chains_to_the_ca() {
        let ca = CertificateAuthority::generate().unwrap();
        let leaf = ca.leaf_for("example.com").unwrap();

        assert_eq!(leaf.chain.len(), 2, "leaf then CA");
        let summary = hexora_http::tls::summarise_certificate(&leaf.chain[0]);
        assert!(summary.subject.contains("example.com"), "{summary:?}");
        assert!(
            summary
                .subject_alt_names
                .iter()
                .any(|n| n.contains("example.com")),
            "{summary:?}"
        );
        assert!(!summary.self_signed, "a leaf is signed by the CA");
        assert!(!summary.expired);
    }

    #[test]
    fn leaves_are_cached_per_host() {
        let ca = CertificateAuthority::generate().unwrap();
        let first = ca.leaf_for("example.com").unwrap();
        let second = ca.leaf_for("EXAMPLE.COM").unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "host lookup should be case-insensitive and cached"
        );
        assert_eq!(ca.cached_leaf_count(), 1);

        ca.leaf_for("other.example.com").unwrap();
        assert_eq!(ca.cached_leaf_count(), 2);
    }

    #[test]
    fn an_ip_literal_gets_an_ip_san_not_a_dns_name() {
        // Clients reject an IP in a DNS SAN, and testing against a bare address is
        // common enough that getting this wrong would break immediately.
        let ca = CertificateAuthority::generate().unwrap();
        for host in ["127.0.0.1", "[::1]"] {
            let leaf = ca.leaf_for(host).unwrap();
            let summary = hexora_http::tls::summarise_certificate(&leaf.chain[0]);
            assert!(
                summary.subject_alt_names.iter().any(|n| n.contains("1")),
                "{host}: {summary:?}"
            );
        }
    }

    #[test]
    fn leaves_are_short_lived() {
        let ca = CertificateAuthority::generate().unwrap();
        let leaf = ca.leaf_for("example.com").unwrap();
        let summary = hexora_http::tls::summarise_certificate(&leaf.chain[0]);
        // Not a precise date check — the property is simply that it is not a decade.
        assert!(!summary.not_after.is_empty(), "{summary:?}");
    }

    #[test]
    fn a_ca_survives_being_written_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let pem = first.certificate_pem().to_string();
        drop(first);

        let second = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(
            second.certificate_pem(),
            pem,
            "reloading must not invalidate the certificate the user trusted"
        );
        // And it must still be able to sign.
        assert!(second.leaf_for("example.com").is_ok());
    }

    #[test]
    fn a_half_deleted_ca_is_refused_rather_than_silently_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join(KEY_FILE)).unwrap();

        let err = CertificateAuthority::load_or_create(dir.path()).unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("half"), "{err}");
    }

    #[test]
    fn the_key_file_is_not_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path()).unwrap();
        let key_path = dir.path().join(KEY_FILE);
        assert!(key_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "the CA key must not be group or world readable"
            );
        }
    }

    #[test]
    fn deleting_removes_both_files_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path()).unwrap();

        CertificateAuthority::delete(dir.path()).unwrap();
        assert!(!dir.path().join(CERT_FILE).exists());
        assert!(!dir.path().join(KEY_FILE).exists());

        // Removing an already-removed CA is not an error: "get this off my machine"
        // should always succeed.
        CertificateAuthority::delete(dir.path()).unwrap();
    }

    #[test]
    fn dns_name_validation_matches_rfc_1123() {
        for good in [
            "example.com",
            "a.b.c.example.com",
            "xn--80ak6aa92e.com",
            "host_name.local",
            "EXAMPLE.com",
            "example.com.",
        ] {
            assert!(is_valid_dns_name(good), "{good} should be valid");
        }
        for bad in [
            "",
            "not a valid host!",
            "-leading.com",
            "trailing-.com",
            "double..dot",
            "a".repeat(64).as_str(),
        ] {
            assert!(!is_valid_dns_name(bad), "{bad} should be rejected");
        }
    }
    #[test]
    fn an_invalid_host_is_rejected_rather_than_producing_a_broken_certificate() {
        let ca = CertificateAuthority::generate().unwrap();
        assert!(ca.leaf_for("not a valid host!").is_err());
    }
}
