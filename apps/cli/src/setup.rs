//! `hexora setup` — the first ten minutes.
//!
//! Everything here can be done a command at a time, and the output says which command
//! each step corresponds to. It exists because the alternative first-run experience is
//! reading three pages of documentation to discover that you needed a project, a CA,
//! a trust-store entry and a browser setting — and that Firefox ignores the third.
//!
//! # What it will not do
//!
//! Install the CA without asking. `--yes` is available and is a deliberate choice;
//! silence is not consent for a root certificate.

use std::path::Path;

use hexora_proxy::{trust, CertificateAuthority, TrustState};
use hexora_types::Result;

/// Options for `hexora setup`.
pub struct SetupArgs<'a> {
    pub project: &'a Path,
    pub ca_dir: Option<&'a Path>,
    /// Do not prompt before installing the CA.
    pub yes: bool,
    /// Whether to touch the trust store at all.
    pub trust: bool,
    pub json: bool,
}

/// Runs the first-run sequence.
pub fn run(args: SetupArgs<'_>) -> Result<()> {
    let mut steps: Vec<(&str, String)> = Vec::new();

    // 1. The project.
    let project_existed = args.project.join("project.db").exists();
    if project_existed {
        steps.push(("project", format!("already at {}", args.project.display())));
    } else {
        let name = crate::project::create(args.project, None)?;
        steps.push((
            "project",
            format!("created {name:?} at {}", args.project.display()),
        ));
    }

    // 2. The CA.
    let ca_dir = crate::proxy::resolve_ca_dir(args.ca_dir)?;
    let ca_existed = ca_dir.join("hexora-ca.crt").exists();
    let ca = CertificateAuthority::load_or_create(&ca_dir)?;
    let fingerprint = ca.fingerprints();
    steps.push((
        "ca",
        if ca_existed {
            format!("reusing the one in {}", ca_dir.display())
        } else {
            format!("generated in {}", ca_dir.display())
        },
    ));

    // 3. Trust.
    let state = trust::status(&fingerprint);
    let mut manual = Vec::new();
    let trust_result = if !args.trust {
        "skipped (--no-trust)".to_string()
    } else if state == TrustState::Trusted {
        "already trusted".to_string()
    } else {
        let (outcome, steps) = install_ca(&ca, &ca_dir, args.yes, args.json)?;
        manual = steps;
        outcome
    };
    steps.push(("trust", trust_result));

    if args.json {
        let payload = serde_json::json!({
            "project": args.project.display().to_string(),
            "ca_directory": ca_dir.display().to_string(),
            "fingerprint_sha256": fingerprint.sha256,
            "trusted": trust::status(&fingerprint) == TrustState::Trusted,
            "steps": steps.iter().map(|(name, detail)| serde_json::json!({
                "step": name,
                "detail": detail,
            })).collect::<Vec<_>>(),
        });
        println!("{payload}");
        return Ok(());
    }

    println!();
    for (name, detail) in &steps {
        println!("  {name:<8} {detail}");
    }

    // After the summary, not during it: a wall of Firefox instructions printed before
    // the tester has seen whether anything worked reads as a failure.
    for step in &manual {
        println!();
        println!("{} still needs doing by hand:", step.application);
        for line in step.instruction.lines() {
            println!("  {line}");
        }
    }

    println!();
    println!("Point your browser at 127.0.0.1:8080 as its HTTP and HTTPS proxy, then:");
    println!();
    println!("  hexora proxy --project {}", args.project.display());
    println!("  hexora history {}", args.project.display());
    println!();
    println!("When you are finished with this machine:");
    println!("  hexora ca --delete");
    Ok(())
}

/// Installs the CA, asking first unless told not to.
///
/// Returns what happened and anything left for the user to do by hand; the caller
/// prints the latter once the summary has been shown.
fn install_ca(
    ca: &CertificateAuthority,
    ca_dir: &Path,
    yes: bool,
    json: bool,
) -> Result<(String, Vec<hexora_proxy::ManualStep>)> {
    if !yes && !json {
        println!("Hexora needs a certificate authority in your trust store to read HTTPS.");
        println!();
        println!("  Fingerprint: {}", ca.fingerprint_display());
        println!("  Private key: {}", ca_dir.join("hexora-ca.key").display());
        println!();
        println!("Anyone who obtains that private key could impersonate any site to you.");
        println!("Install it only on a machine you control. Undo it with: hexora ca --delete");
        println!();
        if !crate::proxy::confirm("Install it now?")? {
            return Ok((
                "declined — install later with: hexora ca --install".to_string(),
                Vec::new(),
            ));
        }
    }

    let installed = trust::install(&ca_dir.join("hexora-ca.crt"), &ca.fingerprints())?;
    let manual = if json { Vec::new() } else { installed.manual };

    let outcome = match installed.verified {
        TrustState::Trusted => format!("installed into the {}", installed.store.name),
        // Never reported as success on the strength of an exit code alone.
        TrustState::NotTrusted => format!(
            "installed into the {} but the platform does not report it as trusted",
            installed.store.name
        ),
        TrustState::Unknown(why) => format!(
            "installed into the {} but could not be verified ({why})",
            installed.store.name
        ),
    };
    Ok((outcome, manual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_creates_a_project_and_a_ca_without_touching_the_trust_store() {
        // --no-trust is the path a CI machine or a curious first-time user takes, and
        // it must not need a password or change anything outside these directories.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("engagement");
        let ca_dir = dir.path().join("ca");

        run(SetupArgs {
            project: &project,
            ca_dir: Some(&ca_dir),
            yes: false,
            trust: false,
            json: true,
        })
        .unwrap();

        assert!(project.join("project.db").is_file());
        assert!(ca_dir.join("hexora-ca.crt").is_file());
        assert!(ca_dir.join("hexora-ca.key").is_file());
    }

    #[test]
    fn running_setup_twice_reuses_what_is_already_there() {
        // The CA in particular: regenerating it would silently invalidate the one the
        // user already trusted, and every HTTPS connection would start failing.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("engagement");
        let ca_dir = dir.path().join("ca");

        let args = || SetupArgs {
            project: &project,
            ca_dir: Some(&ca_dir),
            yes: false,
            trust: false,
            json: true,
        };

        run(args()).unwrap();
        let first = CertificateAuthority::load_or_create(&ca_dir)
            .unwrap()
            .fingerprints();

        run(args()).unwrap();
        let second = CertificateAuthority::load_or_create(&ca_dir)
            .unwrap()
            .fingerprints();

        assert_eq!(first, second, "setup must never invalidate a trusted CA");
    }

    #[test]
    fn setup_does_not_overwrite_an_existing_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("engagement");
        let ca_dir = dir.path().join("ca");

        crate::project::init(&project, Some("Existing engagement"), true).unwrap();
        run(SetupArgs {
            project: &project,
            ca_dir: Some(&ca_dir),
            yes: false,
            trust: false,
            json: true,
        })
        .unwrap();

        let opened = crate::open_project(&project).unwrap();
        let name: String = opened
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT name FROM project", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            name, "Existing engagement",
            "an engagement's evidence is never overwritten"
        );
    }
}
