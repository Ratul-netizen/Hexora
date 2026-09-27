//! WebSocket domain types shared across crates.
//!
//! The frame codec lives in `nullhawk-http`; this is the small vocabulary the storage and
//! capture layers need without depending on the HTTP engine.

use serde::{Deserialize, Serialize};

/// Which way a WebSocket message travelled.
///
/// The two values match the `direction` CHECK constraint on the `websocket_messages` table,
/// so a captured frame's direction is a fact the schema enforces rather than free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsDirection {
    /// From the browser (or client) to the server.
    ClientToServer,
    /// From the server back to the client.
    ServerToClient,
}

impl WsDirection {
    /// The stored string, matching the database CHECK constraint.
    pub fn as_str(self) -> &'static str {
        match self {
            WsDirection::ClientToServer => "client_to_server",
            WsDirection::ServerToClient => "server_to_client",
        }
    }
}
