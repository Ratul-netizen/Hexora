//! `hexora license` — show the active licence, or activate one.
//!
//! The gate itself lives in `hexora_engine::license`; this is the CLI's window onto it and
//! the one place the CLI loads a licence. A feature that costs money asks [`gate`] for its
//! entitlement at the command boundary, the way automated traffic asks the scope guard.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use hexora_engine::license::{
    default_license_path, EntitlementGate, LicenseClaims, Tier, EMBEDDED_LICENSE_KEY,
};
use hexora_types::{HexoraError, Result};

/// Lowercase hex, for printing a public key to embed.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The entitlement gate for this run, loaded from the licence at the default location (or
/// the free tier when there is none). Cheap enough to call at each gated command.
pub fn gate() -> EntitlementGate {
    EntitlementGate::from_default_location(chrono::Utc::now())
}

/// `hexora license show` — what tier this install is running at, and why.
pub fn show(json: bool) -> Result<()> {
    let gate = gate();
    let entitlements = gate.entitlements();
    let path = default_license_path();
    let expires = entitlements
        .expires
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    if json {
        let payload = serde_json::json!({
            "tier": entitlements.tier.label(),
            "licensee": entitlements.licensee,
            "expires": expires,
            "licence_path": path.as_ref().map(|p| p.display().to_string()),
        });
        println!("{payload}");
        return Ok(());
    }

    println!(
        "Tier: {}{}",
        entitlements.tier.label(),
        if entitlements.trial { " (trial)" } else { "" }
    );
    if !entitlements.licensee.is_empty() {
        println!("Licensed to: {}", entitlements.licensee);
    }
    match (&expires, entitlements.days_until_expiry(chrono::Utc::now())) {
        (Some(at), Some(days)) => {
            println!("Expires: {at} ({days} days)");
            // Loud before it lapses, not only after — a tester mid-engagement should have
            // warning, and the fall to free afterwards never locks their evidence.
            if days <= 7 {
                let what = if entitlements.trial { "trial" } else { "licence" };
                println!("  warning: this {what} expires in {days} days; it will fall back to the free tier");
            }
        }
        (Some(at), None) => println!("Expires: {at}"),
        (None, _) if entitlements.tier == Tier::Free => {}
        (None, _) => println!("Expires: never"),
    }
    match path {
        Some(path) if path.exists() => println!("Licence file: {}", path.display()),
        // A trial grants a tier without a signed file; say so rather than claiming free.
        _ if entitlements.trial => println!("No signed licence — this tier is from a trial."),
        Some(path) => println!(
            "No licence file at {} — running at the free tier. Activate one with \
             `hexora license activate <file>`, or start a trial with `hexora license trial`.",
            path.display()
        ),
        None => println!("Running at the free tier."),
    }
    Ok(())
}

/// `hexora license activate <file>` — verify a licence and install it for later runs.
///
/// A file that does not verify against this build's embedded key is refused rather than
/// installed: a licence that would only ever read back as free is not worth storing, and
/// installing it silently would hide why a paid feature is still unavailable.
pub fn activate(file: &Path, json: bool) -> Result<()> {
    let bytes = std::fs::read(file)
        .map_err(|e| HexoraError::invalid_input("licence", format!("{}: {e}", file.display())))?;

    let gate = EntitlementGate::from_license(&bytes, &EMBEDDED_LICENSE_KEY, chrono::Utc::now());
    if gate.entitlements().tier == Tier::Free {
        return Err(HexoraError::invalid_input(
            "licence",
            "this file did not verify as a Hexora licence signed for this build; it was not \
             installed",
        ));
    }

    let path = default_license_path().ok_or_else(|| {
        HexoraError::Internal("could not determine where to store the licence".into())
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            HexoraError::invalid_input("licence", format!("{}: {e}", parent.display()))
        })?;
    }
    std::fs::write(&path, &bytes)
        .map_err(|e| HexoraError::invalid_input("licence", format!("{}: {e}", path.display())))?;

    let entitlements = gate.entitlements();
    if json {
        let payload = serde_json::json!({
            "activated": true,
            "tier": entitlements.tier.label(),
            "licensee": entitlements.licensee,
            "licence_path": path.display().to_string(),
        });
        println!("{payload}");
    } else {
        println!(
            "Activated the {} licence{} — stored at {}.",
            entitlements.tier.label(),
            if entitlements.licensee.is_empty() {
                String::new()
            } else {
                format!(" for {}", entitlements.licensee)
            },
            path.display()
        );
    }
    Ok(())
}

/// `hexora license trial` — start a time-limited Pro trial.
pub fn trial(json: bool) -> Result<()> {
    let entitlements = hexora_engine::license::start_trial(chrono::Utc::now())?;
    let expires = entitlements
        .expires
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    if json {
        let payload = serde_json::json!({
            "trial": true,
            "tier": entitlements.tier.label(),
            "expires": expires,
        });
        println!("{payload}");
    } else {
        println!(
            "Started a {}-day {} trial{}.",
            hexora_engine::license::TRIAL_DAYS,
            entitlements.tier.label(),
            expires.map(|at| format!(", through {at}")).unwrap_or_default()
        );
    }
    Ok(())
}

// ---- Issuer tools ----
//
// `keygen` and `sign` are the vendor's, not a customer's: signing needs the private key, and
// the key a build verifies against is embedded separately at build time (HEXORA_LICENSE_PUBKEY).
// A customer running these without the private key can produce nothing that any real build honours.

/// `hexora license keygen` — generate an Ed25519 issuing keypair.
///
/// Writes the private key (PKCS#8) to `out`, and prints the public key as hex for embedding.
/// Refuses to overwrite an existing key file: clobbering an issuing key invalidates every
/// licence ever signed with it.
pub fn keygen(out: &Path, json: bool) -> Result<()> {
    if out.exists() {
        return Err(HexoraError::invalid_input(
            "out",
            format!(
                "{} already exists; refusing to overwrite an issuing key",
                out.display()
            ),
        ));
    }

    let (private_key, public_key) = hexora_engine::license::generate_keypair()?;
    std::fs::write(out, &private_key)
        .map_err(|e| HexoraError::invalid_input("out", format!("{}: {e}", out.display())))?;
    let public_hex = to_hex(&public_key);

    if json {
        let payload = serde_json::json!({
            "private_key_path": out.display().to_string(),
            "public_key_hex": public_hex,
        });
        println!("{payload}");
        return Ok(());
    }

    println!(
        "Wrote the issuing private key to {} — keep it offline and never commit it.",
        out.display()
    );
    println!();
    println!("Public key (embed in a release build):");
    println!("  {public_hex}");
    println!();
    println!("  HEXORA_LICENSE_PUBKEY={public_hex} cargo build --release -p hexora-cli");
    Ok(())
}

/// Arguments for `hexora license sign`.
pub struct SignArgs<'a> {
    /// The issuing private key (PKCS#8) from `keygen`.
    pub key: &'a Path,
    /// The tier to grant: `pro` or `enterprise`.
    pub tier: &'a str,
    /// Who the licence is for.
    pub licensee: Option<&'a str>,
    /// An explicit RFC 3339 expiry.
    pub expires: Option<&'a str>,
    /// An expiry this many days from now, instead of `--expires`.
    pub days: Option<i64>,
    /// Where to write the licence file. Printed to stdout when absent.
    pub out: Option<&'a Path>,
    pub json: bool,
}

/// `hexora license sign` — mint a signed licence file.
pub fn sign(args: SignArgs<'_>) -> Result<()> {
    let private_key = std::fs::read(args.key).map_err(|e| {
        HexoraError::invalid_input("key", format!("{}: {e}", args.key.display()))
    })?;

    let tier = match args.tier.trim().to_ascii_lowercase().as_str() {
        "pro" => Tier::Pro,
        "enterprise" => Tier::Enterprise,
        other => {
            return Err(HexoraError::invalid_input(
                "tier",
                format!("unknown tier {other:?}; use `pro` or `enterprise`"),
            ))
        }
    };

    let expires = match (args.expires, args.days) {
        (Some(_), Some(_)) => {
            return Err(HexoraError::invalid_input(
                "expires",
                "pass --expires or --days, not both",
            ))
        }
        (Some(text), None) => Some(
            DateTime::parse_from_rfc3339(text.trim())
                .map_err(|_| {
                    HexoraError::invalid_input("expires", "not a valid RFC 3339 timestamp")
                })?
                .with_timezone(&Utc),
        ),
        (None, Some(days)) => Some(Utc::now() + Duration::days(days)),
        (None, None) => None,
    };

    let claims = LicenseClaims {
        tier,
        licensee: args.licensee.unwrap_or_default().to_string(),
        expires,
    };
    let licence = hexora_engine::license::sign_license(&private_key, &claims)?;

    match args.out {
        Some(path) => {
            std::fs::write(path, &licence).map_err(|e| {
                HexoraError::invalid_input("out", format!("{}: {e}", path.display()))
            })?;
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "signed": true,
                        "tier": tier.label(),
                        "out": path.display().to_string(),
                    })
                );
            } else {
                println!("Wrote a {} licence to {}.", tier.label(), path.display());
            }
        }
        None => {
            // No output path: the licence itself goes to stdout, so it can be piped.
            print!("{}", String::from_utf8_lossy(&licence));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_then_sign_produces_a_licence_that_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("issuer.key");
        let out = dir.path().join("acme.hexlic");

        // Generate a key straight from the engine so the test also holds the public half.
        let (private_key, public_key) = hexora_engine::license::generate_keypair().unwrap();
        std::fs::write(&key, &private_key).unwrap();

        sign(SignArgs {
            key: &key,
            tier: "pro",
            licensee: Some("Acme"),
            expires: None,
            days: Some(365),
            out: Some(&out),
            json: false,
        })
        .unwrap();

        let bytes = std::fs::read(&out).unwrap();
        let gate = EntitlementGate::from_license(&bytes, &public_key, Utc::now());
        assert_eq!(gate.entitlements().tier, Tier::Pro);
        assert_eq!(gate.entitlements().licensee, "Acme");
    }

    #[test]
    fn keygen_refuses_to_overwrite_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("issuer.key");
        std::fs::write(&key, b"existing").unwrap();
        let error = keygen(&key, false).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn signing_with_an_unknown_tier_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("issuer.key");
        let (private_key, _) = hexora_engine::license::generate_keypair().unwrap();
        std::fs::write(&key, &private_key).unwrap();

        let error = sign(SignArgs {
            key: &key,
            tier: "platinum",
            licensee: None,
            expires: None,
            days: None,
            out: None,
            json: false,
        })
        .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn activating_an_unverifiable_file_is_refused_and_installs_nothing() {
        // Refused before the licence location is even resolved, so it cannot write anything.
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, br#"{"payload":"eyJ0aWVyIjoicHJvIn0=","signature":"AAAA"}"#).unwrap();

        let error = activate(&bad, false).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn a_missing_file_is_a_clear_error() {
        let error = activate(Path::new("does-not-exist.json"), false).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }
}
