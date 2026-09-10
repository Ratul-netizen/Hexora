//! Storage error types.

use hexora_types::HexoraError;
use thiserror::Error;

/// The result type used by the storage layer.
pub type Result<T> = std::result::Result<T, StorageError>;

/// A persistence failure.
///
/// As with [`hexora_types::HexoraError`], the `#[error(...)]` message on each variant
/// is the documentation that reaches a user; field-level docs would only restate it.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The underlying SQLite call failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The connection pool could not hand out a connection.
    #[error("connection pool error: {0}")]
    Pool(String),

    /// A specific migration failed to apply.
    #[error("migration {version} ({name}) failed: {source}")]
    MigrationFailed {
        version: u32,
        name: &'static str,
        #[source]
        source: rusqlite::Error,
    },

    /// The project was written by a newer Hexora than this build understands.
    ///
    /// Opening it anyway would risk silently corrupting engagement evidence, so this
    /// is a hard stop rather than a warning.
    #[error(
        "project schema revision {found} is newer than this build supports ({supported}); \
         upgrade Hexora to open it"
    )]
    SchemaTooNew { found: u32, supported: u32 },

    /// The database is structurally invalid.
    #[error("corrupt project schema: {0}")]
    CorruptSchema(String),

    /// A stored row could not be turned back into a domain type.
    #[error("failed to decode stored {entity}: {reason}")]
    Decode {
        entity: &'static str,
        reason: String,
    },

    /// A stored blob's content does not match the hash it is filed under.
    ///
    /// Bodies are the evidence behind findings, so a mismatch is surfaced rather than
    /// repaired: returning corrupted bytes would put a false claim in a client report.
    #[error(
        "blob {hash} failed its integrity check; the stored body has been altered or corrupted"
    )]
    BlobIntegrity { hash: String },

    /// A message references a body that is not in the blob store.
    #[error("blob {hash} is referenced but not present in the blob store")]
    BlobMissing { hash: String },

    /// Filesystem failure opening or creating the project file.
    #[error("project file I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<r2d2::Error> for StorageError {
    fn from(e: r2d2::Error) -> Self {
        Self::Pool(e.to_string())
    }
}

impl From<StorageError> for HexoraError {
    fn from(e: StorageError) -> Self {
        HexoraError::Storage(e.to_string())
    }
}
