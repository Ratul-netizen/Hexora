//! `hexora programme` — the terms this engagement is conducted under.
//!
//! [`hexora_types::scope`] answers *which systems*. This answers the other question a
//! bug bounty programme decides for you: **which kinds of finding it will accept**.
//!
//! Wolt's, for example, puts missing security headers, missing cookie flags, CORS
//! without proven impact, banner grabbing, username enumeration and absent rate limits
//! out of scope as *classes*. That is most of what a passive scanner produces, and a
//! run that files forty of them is a run whose output gets skipped — which is how a
//! real finding gets missed.
//!
//! Excluding a class does not hide anything. A passive check still runs, its
//! observations are still listed, and the run record and the report both say what was
//! excluded and why. What it stops is the observation becoming a claim in somebody's
//! project — and, for an active check, the traffic being sent at all.

use std::path::Path;

use hexora_types::programme::Exclusion;
use hexora_types::{HexoraError, Result};

/// Prints the engagement's terms.
pub fn show(path: &Path, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    let programme = project.settings().programme()?;

    if json {
        println!("{}", serde_json::json!(&programme));
        return Ok(());
    }

    if programme.is_empty() {
        println!("No programme is recorded for this project.");
        println!();
        println!("Everything Hexora finds will be reported. If you are testing under a");
        println!("bug bounty programme, record what it will not accept so a run does not");
        println!("bury a real finding under forty it would reject:");
        println!();
        println!("  hexora programme set <project> --name \"Wolt\" \\");
        println!("      --policy-url https://hackerone.com/wolt");
        println!("  hexora programme exclude <project> headers.security \\");
        println!("      --reason \"out of scope: missing security headers\"");
        return Ok(());
    }

    match &programme.name {
        Some(name) => println!("Programme: {name}"),
        None => println!("Programme: (unnamed)"),
    }
    if let Some(url) = &programme.policy_url {
        println!("Terms:     {url}");
    }

    println!();
    if programme.exclusions.is_empty() {
        println!("No finding classes are excluded: everything found will be reported.");
        return Ok(());
    }

    println!("Will not be reported for this engagement:");
    for exclusion in &programme.exclusions {
        println!("  {}", exclusion.detector);
        println!("      {}", exclusion.reason);
    }
    println!();
    println!("These checks still run and their observations are still listed — a passive");
    println!("pass costs the target nothing. What they no longer do is file a finding.");
    println!("An excluded *active* check is not run at all.");
    Ok(())
}

/// Records what the programme is called and where its terms are published.
pub fn set(path: &Path, name: Option<&str>, policy_url: Option<&str>, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    crate::require_initialised(&project, path)?;
    let mut programme = project.settings().programme()?;
    if let Some(name) = name {
        programme.name = Some(name.to_string());
    }
    if let Some(url) = policy_url {
        programme.policy_url = Some(url.to_string());
    }
    project.settings().set_programme(&programme)?;

    if json {
        println!("{}", serde_json::json!(&programme));
        return Ok(());
    }
    println!("Programme: {}", programme.describe());
    Ok(())
}

/// Stops a finding class being reported.
pub fn exclude(path: &Path, detector: &str, reason: &str, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    crate::require_initialised(&project, path)?;
    known(detector)?;

    let reason = reason.trim();
    if reason.is_empty() {
        return Err(HexoraError::invalid_input(
            "--reason",
            "say why this programme will not accept it. Six weeks later an exclusion \
             with no reason is indistinguishable from a mistake, and it is the sentence \
             a reader of the report sees where the findings would have been",
        ));
    }

    let mut programme = project.settings().programme()?;
    let replaced = programme.excluded(detector).is_some();
    programme.exclude(Exclusion::new(detector, reason));
    project.settings().set_programme(&programme)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "detector": detector,
                "reason": reason,
                "replaced": replaced,
                "excluded": programme.exclusions.len(),
            })
        );
        return Ok(());
    }

    println!(
        "{} {detector}: {reason}",
        if replaced { "Re-excluded" } else { "Excluded" }
    );
    println!();
    println!("It will still run and still be listed. It will not become a finding.");
    Ok(())
}

/// Reports a finding class again.
pub fn allow(path: &Path, detector: &str, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    crate::require_initialised(&project, path)?;
    let mut programme = project.settings().programme()?;
    let removed = programme.allow(detector);
    project.settings().set_programme(&programme)?;

    if json {
        println!("{}", serde_json::json!({ "removed": removed }));
        return Ok(());
    }
    if removed {
        println!("{detector} will be reported again.");
    } else {
        println!("{detector} was not excluded.");
    }
    Ok(())
}

/// Refuses a detector id this build does not have.
///
/// A typo in an exclusion is silent in the worst direction: the class goes on being
/// reported, the tester believes it does not, and they find out from the programme.
fn known(detector: &str) -> Result<()> {
    let ids: Vec<String> = crate::detectors::every_id();
    if ids.iter().any(|id| id == detector) {
        return Ok(());
    }
    Err(HexoraError::invalid_input(
        "detector",
        format!(
            "this build has no detector called `{detector}`. It has: {}",
            ids.join(", ")
        ),
    ))
}
