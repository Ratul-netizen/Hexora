//! Offline licence verification and the entitlement gate (LIC.a).
//!
//! Nullhawk is a paid tool with a free tier, and this is the mechanism that tells them apart.
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
//! once, and a denial is **explicit** — [`NullhawkError::NotLicensed`] names the feature and the
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

use nullhawk_types::error::{NullhawkError, Result};

/// The Ed25519 public key licences are verified against, embedded in the binary.
///
/// Set at build time from `NULLHAWK_LICENSE_PUBKEY` (64 hex characters, the 32-byte key a
/// [`generate_keypair`] run printed). A release is built with it set:
///
/// ```console
/// $ NULLHAWK_LICENSE_PUBKEY=<64 hex> cargo build --release -p nullhawk-cli
/// ```
///
/// Unset — every ordinary `cargo build`, and every test — it is all zeros, which verifies
/// nothing, so those builds run at the free tier. That is the safe default and why the
/// signing tools live beside the gate without weakening it: a build with no real key
/// embedded cannot grant a tier no matter what licence it is handed. The matching private
/// key is the most sensitive secret this feature introduces after the interception CA; its
/// storage and rotation are a runbook, not a line in a script.
pub const EMBEDDED_LICENSE_KEY: [u8; 32] = embedded_key();

/// Resolves the embedded key from the build environment, or all zeros when unset.
const fn embedded_key() -> [u8; 32] {
    match option_env!("NULLHAWK_LICENSE_PUBKEY") {
        Some(hex) => decode_key_hex(hex),
        None => [0u8; 32],
    }
}

/// Decodes exactly 64 hex characters into a 32-byte key, at compile time. A wrong length or a
/// non-hex character fails the build rather than shipping a silently-wrong key.
const fn decode_key_hex(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(
        bytes.len() == 64,
        "NULLHAWK_LICENSE_PUBKEY must be 64 hex characters (a 32-byte Ed25519 public key)"
    );
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// One hex character to its nibble, at compile time.
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("NULLHAWK_LICENSE_PUBKEY contains a non-hex character"),
    }
}

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
    /// The active scanner — traffic Nullhawk sends on its own.
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
            Err(NullhawkError::NotLicensed {
                feature: feature.label(),
                tier: feature.min_tier().label(),
            })
        }
    }
}

/// The default place a licence file lives, or `None` when it cannot be determined.
///
/// `NULLHAWK_LICENSE` overrides everything, so a tester can point at a licence explicitly and a
/// test can avoid touching the real one. Otherwise it is a `nullhawk/license.json` under the
/// platform's per-user config directory — `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or
/// `~/.config` elsewhere. A licence is per-user, not per-project, so it never lives in a
/// project directory a tester might share as evidence.
pub fn default_license_path() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    if let Some(explicit) = std::env::var_os("NULLHAWK_LICENSE") {
        return Some(PathBuf::from(explicit));
    }

    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
    };

    base.map(|dir| dir.join("nullhawk").join("license.json"))
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
        NullhawkError::Internal("could not determine where to store the trial".into())
    })?;
    start_trial_at(&path, now)
}

/// Writes a trial marker at `path`, refusing if one is already there.
///
/// The marker's presence is the record, so an expired trial cannot be restarted without
/// deleting the file — the deterrent a trial is entitled to, and no more.
fn start_trial_at(path: &Path, now: DateTime<Utc>) -> Result<Entitlements> {
    if path.exists() {
        return Err(NullhawkError::invalid_input(
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
            NullhawkError::invalid_input("trial", format!("{}: {e}", parent.display()))
        })?;
    }
    let json = serde_json::to_vec_pretty(&marker)
        .map_err(|e| NullhawkError::Internal(format!("serialising the trial marker: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| NullhawkError::invalid_input("trial", format!("{}: {e}", path.display())))?;

    Ok(trial_entitlements(expires))
}

/// Verifies a licence and returns its entitlements, or a short reason it was rejected.
fn verify(
    license: &[u8],
    verifying_key: &[u8],
    now: DateTime<Utc>,
) -> std::result::Result<Entitlements, &'static str> {
    let file: LicenceFile =
        serde_json::from_slice(license).map_err(|_| "the licence file is not valid JSON")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64
        .decode(file.payload.trim())
        .map_err(|_| "the licence payload is not valid base64")?;
    let signature = b64
        .decode(file.signature.trim())
        .map_err(|_| "the licence signature is not valid base64")?;

    // The signature is over the exact payload bytes, against the embedded key.
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, verifying_key)
        .verify(&payload, &signature)
        .map_err(|_| "the licence signature does not verify against Nullhawk's key")?;

    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| "the licence claims are not valid JSON")?;
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

// ---- Issuer-side: generating a key and signing licences ----
//
// These are the vendor's tools, not a customer's. They are compiled into the binary
// unconditionally, and that is safe: signing needs the private key, which a customer does not
// have, and the *embedded* key a build verifies against is set separately at build time. A
// build with no real key embedded (the default) cannot be tricked into honouring a licence,
// whatever it was signed with.

/// The claims to put in a licence.
#[derive(Debug, Clone)]
pub struct LicenseClaims {
    /// The tier to grant.
    pub tier: Tier,
    /// Who it is issued to, for display. May be empty.
    pub licensee: String,
    /// When it expires. `None` is perpetual.
    pub expires: Option<DateTime<Utc>>,
}

/// Generates a fresh Ed25519 issuing keypair.
///
/// Returns `(pkcs8_private_key, public_key)`: the PKCS#8 DER private key to keep offline and
/// feed to [`sign_license`], and the 32-byte public key to embed via `NULLHAWK_LICENSE_PUBKEY`.
/// The private key never leaves the issuer; losing it means re-keying every licence.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| NullhawkError::Internal("could not generate an Ed25519 key".into()))?;
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| NullhawkError::Internal("generated an unusable Ed25519 key".into()))?;
    use ring::signature::KeyPair as _;
    Ok((
        pkcs8.as_ref().to_vec(),
        key_pair.public_key().as_ref().to_vec(),
    ))
}

/// Signs a licence file for `claims` with a PKCS#8 Ed25519 private key.
///
/// Produces the exact on-disk bytes [`EntitlementGate::from_license`] reads: a `{payload,
/// signature}` JSON where the signature is over the claims bytes, so verification checks the
/// same bytes that were signed.
pub fn sign_license(pkcs8_private_key: &[u8], claims: &LicenseClaims) -> Result<Vec<u8>> {
    let key_pair =
        ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_private_key).map_err(|_| {
            NullhawkError::invalid_input("key", "not a valid Ed25519 PKCS#8 private key")
        })?;

    // Build the claims JSON, omitting fields that carry nothing, so the payload is minimal and
    // matches what the verifier's `Claims` reads back.
    let mut object = serde_json::Map::new();
    object.insert(
        "tier".into(),
        serde_json::Value::String(claims.tier.label().to_ascii_lowercase()),
    );
    if !claims.licensee.is_empty() {
        object.insert(
            "licensee".into(),
            serde_json::Value::String(claims.licensee.clone()),
        );
    }
    if let Some(expires) = claims.expires {
        object.insert(
            "expires".into(),
            serde_json::Value::String(expires.to_rfc3339()),
        );
    }
    let claims_json = serde_json::to_vec(&serde_json::Value::Object(object))
        .map_err(|e| NullhawkError::Internal(format!("serialising licence claims: {e}")))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64.encode(&claims_json);
    let signature = b64.encode(key_pair.sign(&claims_json).as_ref());
    let file = serde_json::json!({ "payload": payload, "signature": signature });
    serde_json::to_vec_pretty(&file)
        .map_err(|e| NullhawkError::Internal(format!("serialising licence file: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// A throwaway Ed25519 signer, standing in for Nullhawk's real issuing key.
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
        assert!(
            message.contains("active scanner") && message.contains("Pro"),
            "{message}"
        );
    }

    #[test]
    fn a_tampered_licence_falls_back_to_free() {
        let issuer = TestIssuer::new();
        let mut licence = issuer.issue(r#"{"tier":"enterprise","licensee":"Mallory"}"#);
        // Flip a byte in the middle of the file — the signature no longer matches.
        let mid = licence.len() / 2;
        licence[mid] ^= 0x01;

        let gate = EntitlementGate::from_license(&licence, &issuer.public_key(), now());
        assert_eq!(
            gate.entitlements().tier,
            Tier::Free,
            "a tampered licence must not grant a tier"
        );
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
    fn keygen_sign_and_verify_is_a_round_trip() {
        // The real issuer path, end to end: generate a key, sign a licence with the private
        // half, verify it against the public half.
        let (private_key, public_key) = generate_keypair().unwrap();
        let licence = sign_license(
            &private_key,
            &LicenseClaims {
                tier: Tier::Pro,
                licensee: "Acme Pentest Ltd".into(),
                expires: None,
            },
        )
        .unwrap();

        let gate = EntitlementGate::from_license(&licence, &public_key, now());
        assert_eq!(gate.entitlements().tier, Tier::Pro);
        assert_eq!(gate.entitlements().licensee, "Acme Pentest Ltd");
        assert!(gate.allows(Feature::ActiveScanner));
    }

    #[test]
    fn a_signed_licence_is_rejected_by_a_different_embedded_key() {
        // The security property that makes shipping the signing tool safe: a licence signed
        // by one key does not verify against another (and the shipped placeholder is neither).
        let (private_key, _public_key) = generate_keypair().unwrap();
        let (_other_private, other_public) = generate_keypair().unwrap();
        let licence = sign_license(
            &private_key,
            &LicenseClaims {
                tier: Tier::Enterprise,
                licensee: String::new(),
                expires: None,
            },
        )
        .unwrap();

        assert_eq!(
            EntitlementGate::from_license(&licence, &other_public, now())
                .entitlements()
                .tier,
            Tier::Free
        );
        assert_eq!(
            EntitlementGate::from_license(&licence, &EMBEDDED_LICENSE_KEY, now())
                .entitlements()
                .tier,
            Tier::Free
        );
    }

    #[test]
    fn a_signed_expiry_is_honoured_then_lapses() {
        let (private_key, public_key) = generate_keypair().unwrap();
        let expires = now() + chrono::Duration::days(30);
        let licence = sign_license(
            &private_key,
            &LicenseClaims {
                tier: Tier::Pro,
                licensee: "Time-Boxed".into(),
                expires: Some(expires),
            },
        )
        .unwrap();

        assert_eq!(
            EntitlementGate::from_license(&licence, &public_key, now())
                .entitlements()
                .tier,
            Tier::Pro
        );
        // Past the expiry it degrades to free, never a lock.
        let later = expires + chrono::Duration::days(1);
        assert_eq!(
            EntitlementGate::from_license(&licence, &public_key, later)
                .entitlements()
                .tier,
            Tier::Free
        );
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
        for junk in [
            b"".as_slice(),
            b"not json",
            b"{}",
            br#"{"payload":"!!","signature":"!!"}"#,
        ] {
            let gate = EntitlementGate::from_license(junk, &[0u8; 32], now());
            assert_eq!(gate.entitlements().tier, Tier::Free);
        }
    }
}
