//! `hexora ext` — install and manage extensions.
//!
//! An extension is a manifest plus a WASM module. Installing one runs someone else's code inside
//! a tool that holds a client's traffic and credentials, so the permission model is front and
//! centre: an extension receives exactly the capabilities approved here and nothing else, the
//! grant is recorded in the project, and one whose *required* capabilities are declined installs
//! switched off rather than half-working.
//!
//! This build manages extensions and their permissions. Executing the WASM module in a sandbox
//! is the runtime milestone; `install` validates and records the manifest, it does not run it.

use std::path::Path;

use hexora_ext::{InstalledExtension, Manifest};
use hexora_types::{HexoraError, Result};

/// Lists the project's installed extensions.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let extensions = crate::open_project(project)?.settings().extensions()?;

    if json {
        println!("{}", serde_json::to_string(&extensions).unwrap_or_default());
        return Ok(());
    }
    if extensions.is_empty() {
        println!("No extensions installed. Add one with `hexora ext install <manifest>`.");
        return Ok(());
    }
    println!("Installed extensions:");
    for ext in &extensions {
        let state = if ext.enabled { "enabled" } else { "disabled" };
        let caps: Vec<String> = ext.grants.capabilities().map(|c| c.to_string()).collect();
        println!(
            "  {} {} v{} [{}] ({}) — {}",
            ext.manifest.id,
            ext.manifest.name,
            ext.manifest.version,
            state,
            ext.manifest.kind.label(),
            if caps.is_empty() {
                "no capabilities".to_string()
            } else {
                caps.join(", ")
            }
        );
    }
    Ok(())
}

/// Installs an extension from a manifest file.
pub fn install(project: &Path, manifest_path: &Path, grant_all: bool, json: bool) -> Result<()> {
    let bytes = std::fs::read(manifest_path).map_err(|e| {
        HexoraError::invalid_input("manifest", format!("{}: {e}", manifest_path.display()))
    })?;
    let manifest =
        Manifest::parse(&bytes).map_err(|e| HexoraError::invalid_input("manifest", e.message))?;

    // Default: grant only what the extension marks required. `--grant-all` also grants the
    // optional capabilities. Never more than the manifest requested — enforced in the crate.
    let installed = if grant_all {
        let all: Vec<_> = manifest.requested().collect();
        InstalledExtension::install(manifest, all)
    } else {
        InstalledExtension::install_required_only(manifest)
    };

    let settings = crate::open_project(project)?.settings();
    let mut extensions = settings.extensions()?;
    if extensions
        .iter()
        .any(|e| e.manifest.id == installed.manifest.id)
    {
        return Err(HexoraError::invalid_input(
            "install",
            format!(
                "{} is already installed; remove it first",
                installed.manifest.id
            ),
        ));
    }
    extensions.push(installed.clone());
    settings.set_extensions(&extensions)?;

    if json {
        println!("{}", serde_json::to_string(&installed).unwrap_or_default());
        return Ok(());
    }

    println!(
        "Installed {} ({}).",
        installed.manifest.name, installed.manifest.id
    );
    let granted: Vec<String> = installed
        .grants
        .capabilities()
        .map(|c| c.to_string())
        .collect();
    if granted.is_empty() {
        println!("Granted: nothing.");
    } else {
        println!("Granted:");
        for cap in installed.grants.capabilities() {
            let mark = if cap.is_dangerous() { "  ⚠ " } else { "    " };
            println!("{mark}{cap} — {}", cap.explanation());
        }
    }
    if installed.grants.has_dangerous() {
        println!();
        println!("This extension holds dangerous capabilities. It can reach beyond the target.");
    }
    if !installed.enabled {
        println!();
        println!("Installed DISABLED: some required capabilities were not granted. Re-install");
        println!(
            "with --grant-all, or grant them, then `hexora ext enable {}`.",
            installed.manifest.id
        );
    }
    Ok(())
}

/// Removes an extension by id.
pub fn remove(project: &Path, id: &str, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut extensions = settings.extensions()?;
    let before = extensions.len();
    extensions.retain(|e| e.manifest.id != id);
    if extensions.len() == before {
        return Err(HexoraError::not_found("extension", id.to_string()));
    }
    settings.set_extensions(&extensions)?;
    if json {
        println!("{}", serde_json::json!({ "removed": id }));
    } else {
        println!("Removed {id}.");
    }
    Ok(())
}

/// Shows what an extension requested and what it was granted.
pub fn permissions(project: &Path, id: &str, json: bool) -> Result<()> {
    let extensions = crate::open_project(project)?.settings().extensions()?;
    let ext = extensions
        .iter()
        .find(|e| e.manifest.id == id)
        .ok_or_else(|| HexoraError::not_found("extension", id.to_string()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": ext.manifest.id,
                "required": ext.manifest.permissions.required.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "optional": ext.manifest.permissions.optional.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "granted": ext.grants.capabilities().map(|c| c.to_string()).collect::<Vec<_>>(),
                "enabled": ext.enabled,
            })
        );
        return Ok(());
    }

    println!("{} ({})", ext.manifest.name, ext.manifest.id);
    println!("Required:");
    for cap in &ext.manifest.permissions.required {
        let held = if ext.grants.allows(*cap) {
            "granted"
        } else {
            "DECLINED"
        };
        println!("  {cap} [{held}] — {}", cap.explanation());
    }
    if !ext.manifest.permissions.optional.is_empty() {
        println!("Optional:");
        for cap in &ext.manifest.permissions.optional {
            let held = if ext.grants.allows(*cap) {
                "granted"
            } else {
                "not granted"
            };
            println!("  {cap} [{held}] — {}", cap.explanation());
        }
    }
    Ok(())
}

/// Enables or disables an extension.
pub fn set_enabled(project: &Path, id: &str, enabled: bool, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut extensions = settings.extensions()?;
    let ext = extensions
        .iter_mut()
        .find(|e| e.manifest.id == id)
        .ok_or_else(|| HexoraError::not_found("extension", id.to_string()))?;

    // An extension cannot be enabled while its required capabilities are unmet — that is the
    // state that would fail unpredictably mid-run.
    if enabled && !ext.requirements_met() {
        return Err(HexoraError::invalid_input(
            "enable",
            format!("{id} is missing required capabilities; re-install with --grant-all"),
        ));
    }
    ext.enabled = enabled;
    settings.set_extensions(&extensions)?;

    if json {
        println!("{}", serde_json::json!({ "id": id, "enabled": enabled }));
    } else {
        println!("{} {id}.", if enabled { "Enabled" } else { "Disabled" });
    }
    Ok(())
}
