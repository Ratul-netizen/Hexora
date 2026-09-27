//! `hexora check` — user-defined scan checks (Hexora's answer to Burp's BChecks).
//!
//! A custom check is a saved query plus a finding template. When the query matches a captured
//! exchange, the passive scanner records a lead with the check's name, severity and message.
//! Checks run whenever `hexora scan passive` runs; they match on metadata and headers, never on
//! bodies, and can only ever produce a lead — never an actionable finding.

use std::path::Path;

use hexora_types::custom::CustomCheck;
use hexora_types::finding::Severity;
use hexora_types::{HexoraError, Result};

/// Prints the project's custom checks, in the order they run.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let checks = crate::open_project(project)?.settings().custom_checks()?;

    if json {
        println!("{}", serde_json::to_string(&checks).unwrap_or_default());
        return Ok(());
    }
    if checks.is_empty() {
        println!("No custom checks. Add one with `hexora check add`.");
        return Ok(());
    }
    println!("Custom checks (run during `hexora scan passive`):");
    for check in &checks {
        println!("  {}", check.summary());
    }
    Ok(())
}

/// Options for adding a check.
pub struct AddArgs<'a> {
    pub project: &'a Path,
    pub id: &'a str,
    pub name: &'a str,
    pub severity: &'a str,
    pub query: &'a str,
    pub message: &'a str,
    pub disabled: bool,
    pub json: bool,
}

/// Adds a custom check.
pub fn add(args: AddArgs<'_>) -> Result<()> {
    let id = args.id.trim();
    if id.is_empty() {
        return Err(HexoraError::invalid_input("id", "a check needs an id"));
    }
    let severity = Severity::parse(args.severity).ok_or_else(|| {
        HexoraError::invalid_input(
            "--severity",
            format!(
                "{:?} is not a severity (info, low, medium, high, critical)",
                args.severity
            ),
        )
    })?;

    let mut check = CustomCheck::new(id, args.name, severity, args.query, args.message);
    check.enabled = !args.disabled;

    // The query must compile and touch no body — refused here, not silently at scan time.
    hexora_scan::custom::validate(&check)
        .map_err(|why| HexoraError::invalid_input("--query", why))?;

    let settings = crate::open_project(args.project)?.settings();
    let mut checks = settings.custom_checks()?;
    if checks.iter().any(|c| c.id == id) {
        return Err(HexoraError::invalid_input(
            "id",
            format!("a check with id {id:?} already exists; remove it or pick another id"),
        ));
    }
    checks.push(check.clone());
    settings.set_custom_checks(&checks)?;

    if args.json {
        println!("{}", serde_json::to_string(&check).unwrap_or_default());
    } else {
        println!("Added check: {}", check.summary());
        println!("It runs during `hexora scan passive` and files a lead when it matches.");
    }
    Ok(())
}

/// Removes a check by id.
pub fn remove(project: &Path, id: &str, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut checks = settings.custom_checks()?;
    let before = checks.len();
    checks.retain(|c| c.id != id);
    if checks.len() == before {
        return Err(HexoraError::not_found("custom check", id.to_string()));
    }
    settings.set_custom_checks(&checks)?;

    if json {
        println!("{}", serde_json::json!({ "removed": id }));
    } else {
        println!("Removed check {id:?}.");
    }
    Ok(())
}

/// Enables or disables a check by id.
pub fn set_enabled(project: &Path, id: &str, enabled: bool, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut checks = settings.custom_checks()?;
    let check = checks
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| HexoraError::not_found("custom check", id.to_string()))?;
    check.enabled = enabled;
    let summary = check.summary();
    settings.set_custom_checks(&checks)?;

    if json {
        println!("{}", serde_json::json!({ "id": id, "enabled": enabled }));
    } else {
        println!(
            "{} check {id:?}: {summary}",
            if enabled { "Enabled" } else { "Disabled" }
        );
    }
    Ok(())
}
