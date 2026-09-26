//! `hexora license` — show the active licence, or activate one.
//!
//! The gate itself lives in `hexora_engine::license`; this is the CLI's window onto it and
//! the one place the CLI loads a licence. A feature that costs money asks [`gate`] for its
//! entitlement at the command boundary, the way automated traffic asks the scope guard.

use std::path::Path;

use hexora_engine::license::{default_license_path, EntitlementGate, Tier, EMBEDDED_LICENSE_KEY};
use hexora_types::{HexoraError, Result};

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

#[cfg(test)]
mod tests {
    use super::*;

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
