//! # hexora-ext
//!
//! The extension SDK contract: what an extension **is** to the host, and the permission-gated
//! registry that installs one. An extension is a signed-off manifest plus a WASM module; this
//! crate defines the manifest, validates it, and pairs it with the capabilities the user
//! approved. Executing the module in a sandbox is the runtime's job (a separate milestone) — the
//! contract here is what the runtime, the store, and every extension author build against.
//!
//! # Nothing runs before it is granted
//!
//! Installing an extension means running someone else's code inside a tool that holds session
//! cookies and a client's traffic. The permission model
//! ([`hexora_engine::permission`]) enforces invariant 4 — nothing is granted implicitly — and
//! this crate carries it through: an [`InstalledExtension`] cannot be created enabled unless the
//! capabilities its manifest marks **required** were actually granted. An extension whose
//! requirements were declined installs disabled, not half-working.
//!
//! # The manifest is data, the module is code
//!
//! A manifest is parsed here (JSON or YAML) and fully validated — id shape, a supported API
//! version, a declared entry point and kind. None of that runs the module. The `entry` is a path
//! the runtime will load; this crate never opens it.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use serde::{Deserialize, Serialize};

pub use hexora_engine::permission::{Capability, GrantSet, PermissionRequest};

/// The extension API version this build speaks. An extension declaring a newer version is
/// refused rather than loaded against a contract it does not match.
pub const CURRENT_API_VERSION: u32 = 1;

/// What an extension plugs into — the host surface it registers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    /// A passive check: observes an exchange and may emit observations.
    PassiveCheck,
    /// An active check: sends requests and settles hypotheses.
    ActiveCheck,
    /// A report renderer: turns findings into a document format.
    Report,
    /// A UI contribution: tabs, panels, context-menu entries.
    Ui,
    /// A workflow: an automation the user can run.
    Workflow,
}

impl ExtensionKind {
    /// A short label.
    pub fn label(self) -> &'static str {
        match self {
            ExtensionKind::PassiveCheck => "passive check",
            ExtensionKind::ActiveCheck => "active check",
            ExtensionKind::Report => "report renderer",
            ExtensionKind::Ui => "UI contribution",
            ExtensionKind::Workflow => "workflow",
        }
    }
}

/// An extension's manifest — everything the host needs to decide whether and how to run it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// A stable, reverse-DNS-ish id, e.g. `com.example.jwt-tools`. Lowercase.
    pub id: String,
    /// A human name for the install dialog and lists.
    pub name: String,
    /// The extension's own version string.
    pub version: String,
    /// The Hexora extension API version it targets. Must be `<= CURRENT_API_VERSION`.
    pub api_version: u32,
    /// What it plugs into.
    pub kind: ExtensionKind,
    /// The WASM module to load, as a path relative to the manifest. Never opened here.
    pub entry: String,
    /// One line for the install dialog.
    #[serde(default)]
    pub description: Option<String>,
    /// Who wrote it.
    #[serde(default)]
    pub author: Option<String>,
    /// Where to read more.
    #[serde(default)]
    pub homepage: Option<String>,
    /// The capabilities it requests, split into required and optional.
    #[serde(default)]
    pub permissions: PermissionRequest,
}

/// Why a manifest was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    /// A human reason.
    pub message: String,
}

impl ManifestError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    /// Parses a manifest (JSON or YAML) and validates it.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        let manifest: Manifest = match serde_json::from_slice(bytes) {
            Ok(m) => m,
            Err(_) => serde_yaml_ng::from_slice(bytes)
                .map_err(|e| ManifestError::new(format!("not a valid manifest: {e}")))?,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Checks the manifest is well-formed and targets a supported API version.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let id = self.id.trim();
        if id.is_empty() {
            return Err(ManifestError::new("a manifest needs an id"));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
        {
            return Err(ManifestError::new(
                "an id may use only lowercase letters, digits, dot, hyphen and underscore",
            ));
        }
        if self.name.trim().is_empty() {
            return Err(ManifestError::new("a manifest needs a name"));
        }
        if self.version.trim().is_empty() {
            return Err(ManifestError::new("a manifest needs a version"));
        }
        if self.entry.trim().is_empty() {
            return Err(ManifestError::new(
                "a manifest needs an `entry` module path",
            ));
        }
        if self.api_version == 0 || self.api_version > CURRENT_API_VERSION {
            return Err(ManifestError::new(format!(
                "this build speaks extension API version {CURRENT_API_VERSION}; the manifest \
                 targets {}",
                self.api_version
            )));
        }
        Ok(())
    }

    /// Every capability the manifest asks for, required and optional.
    pub fn requested(&self) -> impl Iterator<Item = Capability> + '_ {
        self.permissions.all()
    }
}

/// An extension as the host holds it: its manifest, the capabilities actually granted, and
/// whether it is switched on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledExtension {
    /// The parsed, validated manifest.
    pub manifest: Manifest,
    /// The capabilities the user approved — never wider than requested.
    pub grants: GrantSet,
    /// Whether it runs. False when its required capabilities are not all granted.
    pub enabled: bool,
}

impl InstalledExtension {
    /// Installs an extension with the given grants.
    ///
    /// The grants are narrowed to what the manifest actually requested — a host cannot hand an
    /// extension a capability it never asked for. It is enabled only if every required capability
    /// survived that narrowing; otherwise it installs disabled, so a declined requirement is a
    /// switched-off extension rather than one that fails halfway through a run.
    pub fn install(manifest: Manifest, granted: impl IntoIterator<Item = Capability>) -> Self {
        // Never grant beyond what was requested.
        let requested = GrantSet::granted_by_user(manifest.requested());
        let grants = GrantSet::granted_by_user(granted).intersect(&requested);
        let enabled = manifest.permissions.satisfied_by(&grants);
        Self {
            manifest,
            grants,
            enabled,
        }
    }

    /// The default grant: exactly the required capabilities, nothing optional. The safe install
    /// when the user has not chosen which optional capabilities to allow.
    pub fn install_required_only(manifest: Manifest) -> Self {
        let required: Vec<Capability> = manifest.permissions.required.clone();
        Self::install(manifest, required)
    }

    /// Whether the grants cover the manifest's required capabilities.
    pub fn requirements_met(&self) -> bool {
        self.manifest.permissions.satisfied_by(&self.grants)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "id": "com.example.jwt-tools",
        "name": "JWT Tools",
        "version": "1.2.0",
        "api_version": 1,
        "kind": "passive_check",
        "entry": "jwt_tools.wasm",
        "description": "Flags weak JWTs",
        "permissions": { "required": ["http_read"], "optional": ["project_write"] }
    }"#;

    #[test]
    fn a_valid_manifest_parses_and_reports_its_requests() {
        let m = Manifest::parse(MANIFEST.as_bytes()).unwrap();
        assert_eq!(m.id, "com.example.jwt-tools");
        assert_eq!(m.kind, ExtensionKind::PassiveCheck);
        let requested: Vec<_> = m.requested().collect();
        assert!(requested.contains(&Capability::HttpRead));
        assert!(requested.contains(&Capability::ProjectWrite));
    }

    #[test]
    fn yaml_manifests_work_too() {
        let yaml = "id: com.example.y\nname: Y\nversion: 0.1.0\napi_version: 1\nkind: report\nentry: y.wasm\n";
        let m = Manifest::parse(yaml.as_bytes()).unwrap();
        assert_eq!(m.kind, ExtensionKind::Report);
    }

    #[test]
    fn a_future_api_version_is_refused() {
        let bad = MANIFEST.replace("\"api_version\": 1", "\"api_version\": 99");
        let err = Manifest::parse(bad.as_bytes()).unwrap_err();
        assert!(err.message.contains("API version"), "{}", err.message);
    }

    #[test]
    fn a_bad_id_is_refused() {
        let bad = MANIFEST.replace("com.example.jwt-tools", "Com Example!");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn installing_never_grants_beyond_what_was_requested() {
        let m = Manifest::parse(MANIFEST.as_bytes()).unwrap();
        // Try to hand it Filesystem, which it never asked for.
        let installed = InstalledExtension::install(
            m,
            [
                Capability::HttpRead,
                Capability::ProjectWrite,
                Capability::Filesystem,
            ],
        );
        assert!(installed.grants.allows(Capability::HttpRead));
        assert!(installed.grants.allows(Capability::ProjectWrite));
        assert!(
            !installed.grants.allows(Capability::Filesystem),
            "a capability never requested cannot be granted"
        );
        assert!(installed.enabled);
    }

    #[test]
    fn declining_a_required_capability_installs_disabled() {
        let m = Manifest::parse(MANIFEST.as_bytes()).unwrap();
        // Grant only the optional one; the required http_read is withheld.
        let installed = InstalledExtension::install(m, [Capability::ProjectWrite]);
        assert!(!installed.enabled, "requirements not met");
        assert!(!installed.requirements_met());
    }

    #[test]
    fn required_only_install_omits_optional_capabilities() {
        let m = Manifest::parse(MANIFEST.as_bytes()).unwrap();
        let installed = InstalledExtension::install_required_only(m);
        assert!(installed.enabled);
        assert!(installed.grants.allows(Capability::HttpRead));
        assert!(
            !installed.grants.allows(Capability::ProjectWrite),
            "optional capabilities are not granted by default"
        );
    }

    #[test]
    fn an_installed_extension_round_trips_through_json() {
        let m = Manifest::parse(MANIFEST.as_bytes()).unwrap();
        let installed = InstalledExtension::install_required_only(m);
        let json = serde_json::to_string(&installed).unwrap();
        let back: InstalledExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, installed);
    }
}
