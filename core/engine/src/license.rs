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
    /// Whether this tier comes from a time-limited trial rather than a paid licence.
    pub trial: bool,
}

impl Entitlements {
    /// The free tier — what an unlicensed, misconfigured or expired install runs as.
    pub fn free() -> Self {
        Self {
            tier: Tier::Free,
            licensee: String::new(),
            expires: None,
            trial: false,
        }
    }

    /// Whether this entitlement includes `feature`.
    pub fn allows(&self, feature: Feature) -> bool {
        self.tier.rank() >= feature.min_tier().rank()
    }

    /// Whole days until the entitlement expires, or `None` for a perpetual one.
    ///
    /// Negative once expired, though the gate degrades to free before that shows. Used to
    /// warn a tester *before* a licence or trial lapses rather than only after.
    pub fn days_until_expiry(&self, now: DateTime<Utc>) -> Option<i64> {
        self.expires.map(|at| (at - now).num_days())
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

    /// Builds a gate from the licence at the default location, then an active trial, else
    /// the free tier. This is what an app calls at startup — one place resolves it all.
    ///
    /// A signed paid licence wins; if there is none, an unexpired trial grants Pro; otherwise
    /// free. An expired trial simply stops granting — the marker stays, which is what stops a
    /// second trial being started.
    pub fn from_default_location(now: DateTime<Utc>) -> Self {
        if let Some(path) = default_license_path() {
            if path.exists() {
                let gate = Self::from_license_file(&path, now);
                if gate.entitlements.tier != Tier::Free {
                    return gate;
                }
            }
        }

        if let Some(trial) = active_trial(now) {
            return Self {
                entitlements: trial,
            };
        }

        Self::free()
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

/// The default place a licence file lives, or `None` when it cannot be determined.
///
/// `HEXORA_LICENSE` overrides everything, so a tester can point at a licence explicitly and a
/// test can avoid touching the real one. Otherwise it is a `hexora/license.json` under the
/// platform's per-user config directory — `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or
/// `~/.config` elsewhere. A licence is per-user, not per-project, so it never lives in a
/// project directory a tester might share as evidence.
pub fn default_license_path() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    if let Some(explicit) = std::env::var_os("HEXORA_LICENSE") {
        return Some(PathBuf::from(explicit));
    }

    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
    };

    base.map(|dir| dir.join("hexora").join("license.json"))
}

/// How long a trial lasts.
pub const TRIAL_DAYS: i64 = 14;

/// Where the trial marker lives — beside the licence, so both are per-user.
pub fn default_trial_path() -> Option<std::path::PathBuf> {
    default_license_path().and_then(|p| p.parent().map(|dir| dir.join("trial.json")))
}

/// The trial marker: when it started and when it ends.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct TrialMarker {
    started: DateTime<Utc>,
    expires: DateTime<Utc>,
}

/// The Pro entitlement a trial grants, expiring at `expires`.
fn trial_entitlements(expires: DateTime<Utc>) -> Entitlements {
    Entitlements {
        tier: Tier::Pro,
        licensee: "Trial".to_string(),
        expires: Some(expires),
        trial: true,
    }
}

/// The active trial at the default location, if any.
///
/// A trial grants Pro. It is a local, unsigned marker — trivially removable, which is fine:
/// a trial deters, it does not enforce, and the honest anti-abuse is that starting a second
/// one is refused while the marker is there, not that the marker cannot be deleted.
fn active_trial(now: DateTime<Utc>) -> Option<Entitlements> {
    active_trial_at(&default_trial_path()?, now)
}

/// The active trial recorded at `path`, if the marker exists and has not expired.
fn active_trial_at(path: &Path, now: DateTime<Utc>) -> Option<Entitlements> {
    let bytes = std::fs::read(path).ok()?;
    let marker: TrialMarker = serde_json::from_slice(&bytes).ok()?;
    if now > marker.expires {
        return None;
    }
    Some(trial_entitlements(marker.expires))
}

/// Starts a [`TRIAL_DAYS`]-day Pro trial at the default location.
pub fn start_trial(now: DateTime<Utc>) -> Result<Entitlements> {
    let path = default_trial_path().ok_or_else(|| {
        HexoraError::Internal("could not determine where to store the trial".into())
    })?;
    start_trial_at(&path, now)
}

/// Writes a trial marker at `path`, refusing if one is already there.
///
/// The marker's presence is the record, so an expired trial cannot be restarted without
/// deleting the file — the deterrent a trial is entitled to, and no more.
fn start_trial_at(path: &Path, now: DateTime<Utc>) -> Result<Entitlements> {
    if path.exists() {
        return Err(HexoraError::invalid_input(
            "trial",
            "a trial has already been started on this machine",
        ));
    }

    let expires = now + chrono::Duration::days(TRIAL_DAYS);
    let marker = TrialMarker {
        started: now,
        expires,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            HexoraError::invalid_input("trial", format!("{}: {e}", parent.display()))
        })?;
    }
    let json = serde_json::to_vec_pretty(&marker)
        .map_err(|e| HexoraError::Internal(format!("serialising the trial marker: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| HexoraError::invalid_input("trial", format!("{}: {e}", path.display())))?;

    Ok(trial_entitlements(expires))
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
        trial: false,
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
    fn a_trial_grants_pro_until_it_expires() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("trial.json");

        let started = start_trial_at(&marker, now()).unwrap();
        assert_eq!(started.tier, Tier::Pro);
        assert!(started.trial);
        assert!(started.allows(Feature::ActiveScanner));

        // Active while inside the window, gone once past it.
        assert!(active_trial_at(&marker, now()).is_some());
        let after = now() + chrono::Duration::days(TRIAL_DAYS + 1);
        assert!(active_trial_at(&marker, after).is_none());
    }

    #[test]
    fn a_second_trial_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("trial.json");

        start_trial_at(&marker, now()).unwrap();
        // Even after it expires, the marker's presence refuses a fresh trial.
        let later = now() + chrono::Duration::days(TRIAL_DAYS + 30);
        let error = start_trial_at(&marker, later).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn days_until_expiry_counts_down() {
        let expires = now() + chrono::Duration::days(3);
        let ent = Entitlements {
            tier: Tier::Pro,
            licensee: String::new(),
            expires: Some(expires),
            trial: false,
        };
        assert_eq!(ent.days_until_expiry(now()), Some(3));
        // A perpetual entitlement has no countdown.
        assert_eq!(Entitlements::free().days_until_expiry(now()), None);
    }

    #[test]
    fn garbage_is_free_not_a_crash() {
        for junk in [b"".as_slice(), b"not json", b"{}", br#"{"payload":"!!","signature":"!!"}"#] {
            let gate = EntitlementGate::from_license(junk, &[0u8; 32], now());
            assert_eq!(gate.entitlements().tier, Tier::Free);
        }
    }
}
