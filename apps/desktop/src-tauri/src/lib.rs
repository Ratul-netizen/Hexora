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
//! At M0 that surface is one command, [`commands::engine_info`]. The window it opens
//! reports the build's status rather than a mock interface, because a dashboard full
//! of non-functional panels is worse than an honest empty one.

pub mod commands;

pub use commands::EngineInfo;

/// Builds and runs the desktop application.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hexora=info")),
        )
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![commands::engine_info])
        .run(tauri::generate_context!())
        .expect("failed to start the Hexora desktop shell");
}
