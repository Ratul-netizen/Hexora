//! Structured error types shared across the Hexora engine.
//!
//! Every fallible boundary in the engine returns [`HexoraError`]. Errors carry enough
//! structure for the UI and CLI to render them without string matching, and never
//! embed credentials — see [`crate::redact`].

use std::time::Duration;

use thiserror::Error;

/// The result type used throughout the Hexora core.
pub type Result<T> = std::result::Result<T, HexoraError>;

/// A structured engine error.
///
/// Field-level docs are omitted deliberately: the `#[error(...)]` message on each
/// variant is what a user actually sees, and duplicating it above every field adds
/// noise without adding information.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HexoraError {
    /// A network-level failure while talking to a target.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// The peer sent something that could not be parsed as valid protocol data.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// A configured resource limit was exceeded. This is hostile-input defence,
    /// not a bug: see `docs/threat-model.md`.
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(#[from] LimitError),

    /// Persistence failure (project database, migrations, blob store).
    #[error("storage error: {0}")]
    Storage(String),

    /// The requested item does not exist.
    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },

    /// The caller supplied invalid input.
    #[error("invalid input for {field}: {reason}")]
    InvalidInput { field: String, reason: String },

    /// An extension attempted an action its manifest does not permit.
    #[error("permission denied: extension {extension} lacks capability {capability}")]
    PermissionDenied {
        extension: String,
        capability: String,
    },

    /// The operation was cancelled by the user or a supervising task.
    #[error("operation cancelled")]
    Cancelled,

    /// The target is outside the project scope. Hexora refuses to send traffic to
    /// out-of-scope hosts; this is a safety control, not a recoverable error.
    #[error("target {0} is out of scope")]
    OutOfScope(String),

    /// A surface that is declared in the architecture but not yet implemented.
    ///
    /// This variant exists so unfinished milestones fail loudly instead of silently
    /// returning empty or fabricated data. It must never be reachable from a feature
    /// documented as complete.
    #[error("not implemented: {0} (see docs/roadmap.md)")]
    NotImplemented(&'static str),

    /// An unexpected internal failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl HexoraError {
    /// Convenience constructor for [`HexoraError::InvalidInput`].
    pub fn invalid_input(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Convenience constructor for [`HexoraError::NotFound`].
    pub fn not_found(kind: &'static str, id: impl Into<String>) -> Self {
        Self::NotFound {
            kind,
            id: id.into(),
        }
    }

    /// Whether retrying the same operation could plausibly succeed.
    ///
    /// Used by the fuzzer and scanner to decide between retry and abort.
    /// [`HexoraError::Cancelled`] is deliberately *not* retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(e) => e.is_retryable(),
            Self::LimitExceeded(LimitError::RateLimited { .. }) => true,
            _ => false,
        }
    }

    /// A stable machine-readable code for RPC, CLI JSON output and log correlation.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::Protocol(_) => "protocol",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Storage(_) => "storage",
            Self::NotFound { .. } => "not_found",
            Self::InvalidInput { .. } => "invalid_input",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::Cancelled => "cancelled",
            Self::OutOfScope(_) => "out_of_scope",
            Self::NotImplemented(_) => "not_implemented",
            Self::Internal(_) => "internal",
        }
    }
}

/// Network-level failures.
///
/// Variants are named for the condition they describe; the `#[error]` message on
/// each is the documentation that actually reaches a user.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkError {
    #[error("failed to resolve host {host}")]
    Dns { host: String },

    #[error("connection to {peer} refused")]
    ConnectionRefused { peer: String },

    #[error("connection to {peer} reset")]
    ConnectionReset { peer: String },

    #[error("{phase} timed out after {}ms", .elapsed.as_millis())]
    Timeout {
        phase: TimeoutPhase,
        elapsed: Duration,
    },

    #[error("TLS handshake with {peer} failed: {reason}")]
    Tls { peer: String, reason: String },

    #[error("I/O error: {0}")]
    Io(String),
}

impl NetworkError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ConnectionReset { .. } | Self::Timeout { .. } | Self::Dns { .. } | Self::Io(_)
        )
    }
}

/// Which phase of a request exceeded its deadline.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPhase {
    Resolve,
    Connect,
    TlsHandshake,
    WriteRequest,
    ReadResponseHead,
    ReadResponseBody,
    Total,
}

impl std::fmt::Display for TimeoutPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Resolve => "DNS resolution",
            Self::Connect => "TCP connect",
            Self::TlsHandshake => "TLS handshake",
            Self::WriteRequest => "request write",
            Self::ReadResponseHead => "response head read",
            Self::ReadResponseBody => "response body read",
            Self::Total => "request",
        };
        f.write_str(s)
    }
}

/// Malformed protocol data received from a peer.
///
/// Hexora must stay stable when a hostile target returns deliberately broken data,
/// so these are ordinary errors rather than panics.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("malformed {protocol} message: {reason}")]
    Malformed {
        protocol: &'static str,
        reason: String,
    },

    #[error("invalid header name or value: {0}")]
    InvalidHeader(String),

    #[error("invalid status line: {0}")]
    InvalidStatusLine(String),

    #[error("invalid chunked encoding: {0}")]
    InvalidChunkedEncoding(String),

    #[error("ambiguous message framing: {0}")]
    AmbiguousFraming(String),

    #[error("unsupported content encoding {0}")]
    UnsupportedEncoding(String),

    #[error("failed to decode {encoding} body: {reason}")]
    DecodeFailed { encoding: String, reason: String },
}

/// A resource limit was hit. Each variant records the configured limit so the UI can
/// tell the user which setting to raise.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LimitError {
    #[error("response body exceeded {limit} bytes")]
    BodyTooLarge { limit: u64 },

    #[error("header section exceeded {limit} bytes")]
    HeadersTooLarge { limit: usize },

    #[error("decompressed body exceeded {limit} bytes (compression ratio {ratio:.1}x)")]
    DecompressionBomb { limit: u64, ratio: f64 },

    #[error("exceeded {limit} redirects")]
    TooManyRedirects { limit: u8 },

    #[error("rate limited: {reason}")]
    RateLimited { reason: String },

    #[error("too many concurrent operations (limit {limit})")]
    ConcurrencyExceeded { limit: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_never_retryable() {
        assert!(!HexoraError::Cancelled.is_retryable());
    }

    #[test]
    fn transient_network_failures_are_retryable() {
        let e = HexoraError::Network(NetworkError::ConnectionReset {
            peer: "1.2.3.4:443".into(),
        });
        assert!(e.is_retryable());
    }

    #[test]
    fn refused_connections_are_not_retryable() {
        let e = HexoraError::Network(NetworkError::ConnectionRefused {
            peer: "1.2.3.4:443".into(),
        });
        assert!(!e.is_retryable());
    }

    #[test]
    fn protocol_errors_are_not_retryable() {
        let e = HexoraError::Protocol(ProtocolError::InvalidStatusLine("HTTP/9".into()));
        assert!(!e.is_retryable());
        assert_eq!(e.code(), "protocol");
    }

    #[test]
    fn decompression_bomb_reports_the_limit_it_hit() {
        let e = LimitError::DecompressionBomb {
            limit: 100_000_000,
            ratio: 1042.0,
        };
        let msg = e.to_string();
        assert!(msg.contains("100000000"), "{msg}");
        assert!(msg.contains("1042"), "{msg}");
    }
}
