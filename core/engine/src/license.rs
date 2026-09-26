//! Offline licence verification and the entitlement gate (LIC.a).
//!
//! Hexora is a paid tool with a free tier, and this is the mechanism that tells them apart.
//! It follows two rules that are not negotiable for software a penetration tester runs.
//!
//! **Offline-first.** Testers work in air-gapped and isolated networks; a launch that phones
//! home to check a licence is a launch that fails in exactly the environments the tool is
//! for. So a licence is a small **Ed25519-signed file** verified against a public key
//! **embedded in the binary** — no network, no licence server in the request path.
//!
//! **A bad licence never gets in the way of the work.** A missing, malformed, expired or
//! wrongly-signed licence is not an error that stops the tool: it falls back to the free
//! tier, loudly in the log and never by crashing. An expired licence in particular must not
//! lock a tester's evidence mid-engagement — that degradation is [`Tier::Free`], which still
//! reads and reports. (Grace periods and the activation UX are LIC.c; this is the gate.)
//!
//! ## The gate is the capability model, again
//!
//! [`crate::permission`] orders capabilities by implication and gates an extension at one
//! boundary; the scope guard gates automated traffic at one boundary. An entitlement is the
//! same shape: a [`Feature`] names a minimum [`Tier`], a caller asks [`EntitlementGate::require`]
//! once, and a denial is **explicit** — [`HexoraError::NotLicensed`] names the feature and the
//! tier it needs, so the UI says "the active scanner needs the Pro tier" rather than failing
//! mysteriously.
//!
//! ## What this does and does not defend
//!
//! Client-side licensing deters casual sharing of a licence file. It does not stop someone
//! who can patch the binary — no client-side scheme does, and the tool does not pretend
//! otherwise. Hard, unbypassable enforcement lives server-side, in the team/server tier
//! (M22). This gate's job is to make the honest path easy and the tiers clear.

use std::path::Path;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use hexora_types::error::{HexoraError, Result};

/// The Ed25519 public key licences are verified against, embedded in the binary.
///
/// This placeholder is all zeros, so it verifies nothing and every build using it runs at
/// the free tier — a safe default. A release build replaces it with Hexora's real public
/// key; the matching private key is the most sensitive secret this feature introduces after
/// the interception CA, and its storage and rotation are a runbook, not a line in a script.
pub const EMBEDDED_LICENSE_KEY: [u8; 32] = [0u8; 32];

/// A licence tier, ordered from least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The free tier: interception, the repeater and reporting. Never locked.
    Free,
    /// The paid individual tier.
    Pro,
    /// The organisation tier (team/server features live behind M22, gated the same way).
    Enterprise,
}

impl Tier {
    /// A rank for comparison; a higher tier includes everything a lower one does.
    fn rank(self) -> u8 {
        match self {
            Tier::Free => 0,
            Tier::Pro => 1,
            Tier::Enterprise => 2,
        }
    }

    /// The word shown to a user and written in a licence.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Pro => "Pro",
            Tier::Enterprise => "Enterprise",
        }
    }

    /// Parses the tier word from a licence claim, case-insensitively.
    fn parse(value: &str) -> Option<Tier> {
        match value.trim().to_ascii_lowercase().as_str() {
            "free" => Some(Tier::Free),
            "pro" => Some(Tier::Pro),
            "enterprise" => Some(Tier::Enterprise),
            _ => None,
        }
    }
}

/// A paid feature, and the minimum tier that includes it.
///
/// The mapping here is a proposal, not a commitment — the free/paid split is a product
/// decision, finalised when the gate is wired into features (LIC.b). What matters at LIC.a is
/// that every gateable feature has one place that says which tier it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Feature {
    /// The active scanner — traffic Hexora sends on its own.
    ActiveScanner,
    /// The intruder run without a throttle.
    Intruder,
    /// SARIF export, for putting findings into a CI pipeline.
    SarifExport,
    /// Engagement snapshots and retest comparison.
    RetestSnapshots,
    /// Shared, multi-user projects (the M22 team/server tier).
    TeamProjects,
    /// The tamper-evident audit log.
    AuditLog,
    /// Single sign-on.
    Sso,
}

impl Feature {
    /// The least tier that includes this feature.
    pub fn min_tier(self) -> Tier {
        match self {
            Feature::ActiveScanner
            | Feature::Intruder
            | Feature::SarifExport
            | Feature::RetestSnapshots => Tier::Pro,
            Feature::TeamProjects | Feature::AuditLog | Feature::Sso => Tier::Enterprise,
        }
    }

    /// A human name for the feature, for the "needs the Pro tier" message.
    pub fn label(self) -> &'static str {
        match self {
            Feature::ActiveScanner => "the active scanner",
            Feature::Intruder => "the intruder",
            Feature::SarifExport => "SARIF export",
            Feature::RetestSnapshots => "retest snapshots",
            Feature::TeamProjects => "shared projects",
            Feature::AuditLog => "the audit log",
            Feature::Sso => "single sign-on",
        }
    }
}

/// What a verified licence grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlements {
    /// The tier in force.
    pub tier: Tier,
    /// Who the licence was issued to, for display. Empty on the free tier.
    pub licensee: String,
    /// When the licence expires, if it does. `None` is a perpetual licence.
    pub expires: Option<DateTime<Utc>>,
}

impl Entitlements {
    /// The free tier — what an unlicensed, misconfigured or expired install runs as.
    pub fn free() -> Self {
        Self {
            tier: Tier::Free,
            licensee: String::new(),
            expires: None,
        }
    }

    /// Whether this entitlement includes `feature`.
    pub fn allows(&self, feature: Feature) -> bool {
        self.tier.rank() >= feature.min_tier().rank()
    }
}

/// The licence file on disk: a signed claims payload.
///
/// The payload is base64 of the exact claims JSON that was signed, kept as bytes rather than
/// re-serialised, so verification is over the same bytes the issuer signed and cannot drift
/// on a JSON field reordering.
#[derive(Debug, Deserialize)]
struct LicenceFile {
    /// base64 of the claims JSON.
    payload: String,
    /// base64 of the Ed25519 signature over the decoded payload bytes.
    signature: String,
}

/// The claims inside a licence.
#[derive(Debug, Deserialize)]
struct Claims {
    tier: String,
    #[serde(default)]
    licensee: String,
    /// RFC 3339, when present.
    #[serde(default)]
    expires: Option<String>,
}

/// Decides what the current install is entitled to.
#[derive(Debug, Clone)]
pub struct EntitlementGate {
    entitlements: Entitlements,
}

impl Default for EntitlementGate {
    fn default() -> Self {
        Self::free()
    }
}

impl EntitlementGate {
    /// A gate at the free tier.
    pub fn free() -> Self {
        Self {
            entitlements: Entitlements::free(),
        }
    }

    /// Builds a gate from a signed licence, verified against `verifying_key`.
    ///
    /// Falls back to the free tier — never an error — on any failure: a malformed file, a bad
    /// signature, an unknown tier or an expired licence. The reason is logged, because a
    /// tester who paid and is silently on the free tier deserves to find out why in the log
    /// rather than by a feature quietly missing.
    pub fn from_license(license: &[u8], verifying_key: &[u8], now: DateTime<Utc>) -> Self {
        match verify(license, verifying_key, now) {
            Ok(entitlements) => Self { entitlements },
            Err(reason) => {
                tracing::warn!(reason, "no valid licence; running at the free tier");
                Self::free()
            }
        }
    }

    /// Builds a gate from a licence file on disk, using the embedded public key.
    ///
    /// A path that cannot be read is treated the same as no licence: the free tier.
    pub fn from_license_file(path: &Path, now: DateTime<Utc>) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_license(&bytes, &EMBEDDED_LICENSE_KEY, now),
            Err(_) => Self::free(),
        }
    }

    /// The entitlements in force.
    pub fn entitlements(&self) -> &Entitlements {
        &self.entitlements
    }

    /// Whether `feature` may be used.
    pub fn allows(&self, feature: Feature) -> bool {
        self.entitlements.allows(feature)
    }

    /// Returns an explicit error naming the tier when `feature` is not licensed.
    ///
    /// This is the one call a feature makes at its boundary — the entitlement analogue of the
    /// scope guard's check before the socket.
    pub fn require(&self, feature: Feature) -> Result<()> {
        if self.allows(feature) {
            Ok(())
        } else {
            Err(HexoraError::NotLicensed {
                feature: feature.label(),
                tier: feature.min_tier().label(),
            })
        }
    }
}

/// Verifies a licence and returns its entitlements, or a short reason it was rejected.
fn verify(license: &[u8], verifying_key: &[u8], now: DateTime<Utc>) -> std::result::Result<Entitlements, &'static str> {
    let file: LicenceFile = serde_json::from_slice(license).map_err(|_| "the licence file is not valid JSON")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64.decode(file.payload.trim()).map_err(|_| "the licence payload is not valid base64")?;
    let signature = b64.decode(file.signature.trim()).map_err(|_| "the licence signature is not valid base64")?;

    // The signature is over the exact payload bytes, against the embedded key.
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, verifying_key)
        .verify(&payload, &signature)
        .map_err(|_| "the licence signature does not verify against Hexora's key")?;

    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| "the licence claims are not valid JSON")?;
    let tier = Tier::parse(&claims.tier).ok_or("the licence names an unknown tier")?;

    let expires = match &claims.expires {
        Some(text) => {
            let at = DateTime::parse_from_rfc3339(text.trim())
                .map_err(|_| "the licence expiry is not a valid RFC 3339 timestamp")?
                .with_timezone(&Utc);
            if now > at {
                // Honest fallback: an expired licence is the free tier, not a hard error and
                // never a locked project. Grace handling is LIC.c.
                return Err("the licence has expired");
            }
            Some(at)
        }
        None => None,
    };

    Ok(Entitlements {
        tier,
        licensee: claims.licensee,
        expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// A throwaway Ed25519 signer, standing in for Hexora's real issuing key.
    struct TestIssuer {
        key_pair: ring::signature::Ed25519KeyPair,
    }

    impl TestIssuer {
        fn new() -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            Self { key_pair }
        }

        fn public_key(&self) -> Vec<u8> {
            self.key_pair.public_key().as_ref().to_vec()
        }

        /// Issues a signed licence file for the given claims JSON.
        fn issue(&self, claims_json: &str) -> Vec<u8> {
            let b64 = base64::engine::general_purpose::STANDARD;
            let payload = b64.encode(claims_json.as_bytes());
            let signature = b64.encode(self.key_pair.sign(claims_json.as_bytes()).as_ref());
            format!("{{\"payload\":\"{payload}\",\"signature\":\"{signature}\"}}").into_bytes()
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn a_validly_signed_pro_licence_grants_pro() {
        let issuer = TestIssuer::new();
        let licence = issuer.issue(r#"{"tier":"pro","licensee":"Acme Pentest Ltd"}"#);

        let gate = EntitlementGate::from_license(&licence, &issuer.public_key(), now());
        assert_eq!(gate.entitlements().tier, Tier::Pro);
        assert_eq!(gate.entitlements().licensee, "Acme Pentest Ltd");
        assert!(gate.allows(Feature::ActiveScanner));
        assert!(gate.require(Feature::SarifExport).is_ok());
        // Pro does not reach the Enterprise features.
        assert!(!gate.allows(Feature::TeamProjects));
    }

    #[test]
    fn a_require_denial_names_the_tier() {
        let gate = EntitlementGate::free();
        let error = gate.require(Feature::ActiveScanner).unwrap_err();
        assert_eq!(error.code(), "not_licensed");
        let message = error.to_string();
        assert!(message.contains("active scanner") && message.contains("Pro"), "{message}");
    }

    #[test]
    fn a_tampered_licence_falls_back_to_free() {
        let issuer = TestIssuer::new();
        let mut licence = issuer.issue(r#"{"tier":"enterprise","licensee":"Mallory"}"#);
        // Flip a byte in the middle of the file — the signature no longer matches.
        let mid = licence.len() / 2;
        licence[mid] ^= 0x01;

        let gate = EntitlementGate::from_license(&licence, &issuer.public_key(), now());
        assert_eq!(gate.entitlements().tier, Tier::Free, "a tampered licence must not grant a tier");
    }

    #[test]
    fn a_licence_signed_by_the_wrong_key_falls_back_to_free() {
        let issuer = TestIssuer::new();
        let attacker = TestIssuer::new();
        let licence = issuer.issue(r#"{"tier":"enterprise"}"#);

        // Verified against a *different* key than signed it.
        let gate = EntitlementGate::from_license(&licence, &attacker.public_key(), now());
        assert_eq!(gate.entitlements().tier, Tier::Free);
    }

    #[test]
    fn an_expired_licence_falls_back_to_free_without_locking() {
        let issuer = TestIssuer::new();
        let licence = issuer.issue(r#"{"tier":"pro","expires":"2025-01-01T00:00:00Z"}"#);

        let gate = EntitlementGate::from_license(&licence, &issuer.public_key(), now());
        // Degrades to free — which still reads and reports — rather than erroring.
        assert_eq!(gate.entitlements().tier, Tier::Free);
    }

    #[test]
    fn a_not_yet_expired_licence_is_honoured() {
        let issuer = TestIssuer::new();
        let licence = issuer.issue(r#"{"tier":"pro","expires":"2027-01-01T00:00:00Z"}"#);

        let gate = EntitlementGate::from_license(&licence, &issuer.public_key(), now());
        assert_eq!(gate.entitlements().tier, Tier::Pro);
        assert!(gate.entitlements().expires.is_some());
    }

    #[test]
    fn the_embedded_placeholder_key_verifies_nothing() {
        // The shipped placeholder key is all zeros; until a release replaces it, no licence
        // validates and every build is free. A real, correctly-signed licence checked against
        // the placeholder must still come back free.
        let issuer = TestIssuer::new();
        let licence = issuer.issue(r#"{"tier":"enterprise"}"#);
        let gate = EntitlementGate::from_license(&licence, &EMBEDDED_LICENSE_KEY, now());
        assert_eq!(gate.entitlements().tier, Tier::Free);
    }

    #[test]
    fn garbage_is_free_not_a_crash() {
        for junk in [b"".as_slice(), b"not json", b"{}", br#"{"payload":"!!","signature":"!!"}"#] {
            let gate = EntitlementGate::from_license(junk, &[0u8; 32], now());
            assert_eq!(gate.entitlements().tier, Tier::Free);
        }
    }
}
