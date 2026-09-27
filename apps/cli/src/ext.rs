//! `nullhawk ext` — install and manage extensions.
//!
//! An extension is a manifest plus a WASM module. Installing one runs someone else's code inside
//! a tool that holds a client's traffic and credentials, so the permission model is front and
//! centre: an extension receives exactly the capabilities approved here and nothing else, the
//! grant is recorded in the project, and one whose *required* capabilities are declined installs
//! switched off rather than half-working.
//!
//! `install` validates the manifest, records the exact grant, and captures the WASM module bytes
//! so the record of what code was permitted travels with the project — it does not run the
//! module. Running it is the scanner's job: an enabled passive-check extension that holds
//! `http:read` is executed in the sandbox over each exchange during `nullhawk scan passive`.

use std::path::Path;

use nullhawk_ext::{ExtensionKind, InstalledExtension, Manifest};
use nullhawk_types::{NullhawkError, Result};

/// Lists the project's installed extensions.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let extensions = crate::open_project(project)?.settings().extensions()?;

    if json {
        println!("{}", serde_json::to_string(&extensions).unwrap_or_default());
        return Ok(());
    }
    if extensions.is_empty() {
        println!("No extensions installed. Add one with `nullhawk ext install <manifest>`.");
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
        NullhawkError::invalid_input("manifest", format!("{}: {e}", manifest_path.display()))
    })?;
    let manifest =
        Manifest::parse(&bytes).map_err(|e| NullhawkError::invalid_input("manifest", e.message))?;

    // Capture the module the manifest points at, so the runtime can execute it without the
    // original files and the record of what code was permitted travels with the project.
    let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let module_path = dir.join(&manifest.entry);
    let module = std::fs::read(&module_path).map_err(|e| {
        NullhawkError::invalid_input("entry", format!("{}: {e}", module_path.display()))
    })?;

    // Default: grant only what the extension marks required. `--grant-all` also grants the
    // optional capabilities. Never more than the manifest requested — enforced in the crate.
    let installed = if grant_all {
        let all: Vec<_> = manifest.requested().collect();
        InstalledExtension::install(manifest, all)
    } else {
        InstalledExtension::install_required_only(manifest)
    }
    .with_module(module);

    let settings = crate::open_project(project)?.settings();
    let mut extensions = settings.extensions()?;
    if extensions
        .iter()
        .any(|e| e.manifest.id == installed.manifest.id)
    {
        return Err(NullhawkError::invalid_input(
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
            "with --grant-all, or grant them, then `nullhawk ext enable {}`.",
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
        return Err(NullhawkError::not_found("extension", id.to_string()));
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
        .ok_or_else(|| NullhawkError::not_found("extension", id.to_string()))?;

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

/// Runs a passive-check extension's WASM module against one exchange, in the sandbox.
///
/// A test harness for extension authors: it loads the module the manifest points at and runs it
/// over an exchange you supply, printing the observations it emits. The module runs with no host
/// imports (no filesystem, network or clock), bounded by fuel and a memory cap, so a runaway or
/// hostile module fails the run rather than the tool.
pub fn run_extension(manifest_path: &Path, exchange_path: Option<&Path>, json: bool) -> Result<()> {
    let bytes = std::fs::read(manifest_path).map_err(|e| {
        NullhawkError::invalid_input("manifest", format!("{}: {e}", manifest_path.display()))
    })?;
    let manifest =
        Manifest::parse(&bytes).map_err(|e| NullhawkError::invalid_input("manifest", e.message))?;
    if manifest.kind != ExtensionKind::PassiveCheck {
        return Err(NullhawkError::invalid_input(
            "kind",
            format!(
                "only passive-check extensions can be run this way; this is a {}",
                manifest.kind.label()
            ),
        ));
    }

    let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let module_path = dir.join(&manifest.entry);
    let module = std::fs::read(&module_path).map_err(|e| {
        NullhawkError::invalid_input("entry", format!("{}: {e}", module_path.display()))
    })?;

    let exchange = match exchange_path {
        Some(path) => std::fs::read_to_string(path).map_err(|e| {
            NullhawkError::invalid_input("--exchange", format!("{}: {e}", path.display()))
        })?,
        None => "{}".to_string(),
    };

    let out = nullhawk_wasm::run_passive(&module, &exchange, &nullhawk_wasm::Limits::default())
        .map_err(|e| NullhawkError::invalid_input("extension", e.message))?;

    if json {
        println!("{out}");
    } else {
        println!("{} produced:", manifest.name);
        println!("{out}");
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
        .ok_or_else(|| NullhawkError::not_found("extension", id.to_string()))?;

    // An extension cannot be enabled while its required capabilities are unmet — that is the
    // state that would fail unpredictably mid-run.
    if enabled && !ext.requirements_met() {
        return Err(NullhawkError::invalid_input(
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
