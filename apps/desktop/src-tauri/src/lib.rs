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
//! React ──invoke()──→ Tauri IPC ──→ commands ──→ hexora-engine / hexora-storage
//! ```
//!
//! Commands are added only as the milestone that implements them lands, so the
//! surface never advertises capability that does not exist. At M12.4 it covers
//! projects, the proxy, history, the repeater, the certificate authority, project
//! scope, identities, declared objects, the authorization matrix with
//! constructed attempts, findings and the report — everything
//! the CLI can do, calling exactly the same crates.
//!
//! # State lives in Rust
//!
//! [`state::AppState`] holds the open project and the running proxy. The frontend
//! holds only what it is currently rendering, and re-asks after anything that could
//! change the answer.

pub mod commands;
pub mod preview;
pub mod state;

pub use commands::EngineInfo;
pub use preview::{BodyPreview, Rendering};
pub use state::AppState;

/// Builds and runs the desktop application.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hexora=info")),
        )
        .init();

    tauri::Builder::default()
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::engine_info,
            commands::project_open,
            commands::project_current,
            commands::proxy_start,
            commands::proxy_stop,
            commands::proxy_status,
            commands::history_list,
            commands::history_detail,
            commands::repeater_draft,
            commands::repeater_send,
            commands::repeater_tree,
            commands::ca_status,
            commands::ca_install,
            commands::ca_untrust,
            commands::scope_list,
            commands::scope_add,
            commands::scope_remove,
            commands::identities_list,
            commands::identity_add,
            commands::identity_remove,
            commands::objects_list,
            commands::object_add,
            commands::object_remove,
            commands::candidates_list,
            commands::candidates_analyze,
            commands::candidate_decide,
            commands::finding_reproduction,
            commands::scan_passive,
            commands::scan_active_plan,
            commands::scan_active_run,
            commands::detectors_list,
            commands::snapshots_list,
            commands::snapshot_take,
            commands::snapshot_delete,
            commands::snapshot_compare,
            commands::authz_run,
            commands::findings_list,
            commands::findings_detail,
            commands::findings_triage,
            commands::report_render,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Hexora desktop shell");
}
