//! The Hexora desktop shell.
//!
//! The shell is deliberately thin. All application state — projects, traffic, scan
//! jobs — lives in the Rust core, and the React frontend is a view over it. Putting
//! state in the frontend would mean the CLI and the desktop client could disagree
//! about what a project contains, and it would put security-relevant logic in the
//! most easily influenced part of the process.
//!
//! So the only thing crossing the IPC boundary is a versioned command surface:
//!
//! ```text
//! React ──invoke()──→ Tauri IPC ──→ command ──→ hexora-engine / hexora-storage
//! ```
//!
//! At M0 that surface is one command: [`engine_info`]. The window it opens shows the
//! build's status rather than a mock interface, because a dashboard full of
//! non-functional panels is worse than an honest empty one.

use serde::Serialize;

/// What the frontend needs in order to decide whether it can talk to this engine.
#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    /// The engine's package version.
    pub version: String,
    /// The IPC contract version. The UI refuses to proceed on a mismatch rather than
    /// misinterpreting messages from an engine it does not understand.
    pub rpc_contract_version: u32,
    /// The project schema revision this build writes.
    pub schema_version: u32,
    /// The current development milestone, surfaced in the UI.
    pub milestone: &'static str,
}

/// Returns engine version and contract information.
#[tauri::command]
pub fn engine_info() -> EngineInfo {
    EngineInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        rpc_contract_version: hexora_types::RPC_CONTRACT_VERSION,
        schema_version: hexora_storage::migrations::target_version(),
        milestone: "M0",
    }
}

/// Builds and runs the desktop application.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hexora=info")),
        )
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![engine_info])
        .run(tauri::generate_context!())
        .expect("failed to start the Hexora desktop shell");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_reports_the_same_contract_version_as_the_core() {
        let info = engine_info();
        assert_eq!(info.rpc_contract_version, hexora_types::RPC_CONTRACT_VERSION);
        assert_eq!(info.schema_version, hexora_storage::migrations::target_version());
    }

    #[test]
    fn engine_info_serializes_for_the_frontend() {
        let json = serde_json::to_value(engine_info()).unwrap();
        assert!(json.get("rpcContractVersion").is_some() || json.get("rpc_contract_version").is_some());
    }
}
