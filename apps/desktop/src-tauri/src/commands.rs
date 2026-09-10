//! The IPC command surface.
//!
//! Every command the frontend can invoke lives here, and nowhere else. Two reasons:
//!
//! * **Auditability.** The set of things the UI can ask the engine to do is the
//!   desktop client's whole attack surface. Keeping it in one module means reviewing
//!   it is reading one file.
//! * **Macro hygiene.** `#[tauri::command]` generates helper macros named after the
//!   function. In the crate root those collide with the re-export the macro also
//!   emits (`E0255`), so commands must live in a submodule.
//!
//! At M0 there is exactly one command. The proxy, repeater and scanner surfaces
//! arrive with the milestones that implement them — not before, so that the command
//! list never advertises capability that does not exist.

use serde::Serialize;

/// What the frontend needs in order to decide whether it can talk to this engine.
#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    /// The engine's package version.
    pub version: String,
    /// The IPC contract version.
    ///
    /// The UI refuses to proceed on a mismatch rather than misinterpreting messages
    /// from an engine it does not understand. A security tool that quietly displays
    /// the wrong request is worse than one that will not start.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_reports_the_same_contract_version_as_the_core() {
        let info = engine_info();
        assert_eq!(
            info.rpc_contract_version,
            hexora_types::RPC_CONTRACT_VERSION
        );
        assert_eq!(
            info.schema_version,
            hexora_storage::migrations::target_version()
        );
    }

    #[test]
    fn engine_info_serializes_for_the_frontend() {
        let json = serde_json::to_value(engine_info()).unwrap();
        // The frontend keys off this field to decide whether it can proceed.
        assert!(json.get("rpc_contract_version").is_some(), "{json}");
    }
}
