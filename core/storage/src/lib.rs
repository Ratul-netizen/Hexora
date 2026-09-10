//! # hexora-storage
//!
//! Project persistence for Hexora.
//!
//! ## The split
//!
//! A pentest project is not a normal CRUD workload. One engagement can capture
//! millions of exchanges and hundreds of gigabytes of response bodies, so storage is
//! split by access pattern rather than kept in a single store:
//!
//! ```text
//! metadata  →  MetadataDb    small, relational, queried constantly
//! bodies    →  BlobStore     enormous, immutable, written once and read rarely
//! ```
//!
//! Bodies are content-addressed, which deduplicates the vast repetition a crawl or a
//! fuzzing run produces, and keeps the relational database small enough to stay
//! portable and quick to back up.
//!
//! ## Backends
//!
//! The domain model is backend-agnostic. [`repository`] holds the interfaces; today
//! there is one implementation of each:
//!
//! | Role      | Now (desktop/CLI)      | Intended (team server) |
//! | --------- | ---------------------- | ---------------------- |
//! | Metadata  | SQLite ([`MetadataDb`])| PostgreSQL             |
//! | Bodies    | [`blob::FsBlobStore`]  | Object storage         |
//! | Search    | relational `LIKE`      | Tantivy                |
//! | Analytics | relational queries     | DuckDB                 |
//!
//! The right-hand column is **not implemented and not scheduled**. It is listed
//! because the interfaces were shaped to accommodate it, not to imply it exists.
//! Any of those choices should be re-decided against a benchmark, not this table.
//!
//! ## Blocking
//!
//! Everything here is synchronous, because SQLite is. The async engine calls it via
//! `tokio::task::spawn_blocking`.
//!
//! ## Status at M0
//!
//! Implemented and tested: connection management, pragmas, migrations, the blob
//! store. The repository traits in [`repository`] have no SQLite implementation yet —
//! that lands with M3 (traffic history). Nothing here pretends otherwise.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod blob;
pub mod error;
pub mod migrations;
pub mod repository;

use std::path::{Path, PathBuf};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

// Re-exported so downstream crates use exactly the SQLite version this crate links
// against, rather than declaring their own and risking two incompatible copies.
pub use rusqlite;

pub use crate::blob::{BlobRef, BlobStore, FsBlobStore, MemoryBlobStore};
pub use crate::error::{Result, StorageError};

/// A handle to a project's relational metadata database.
#[derive(Clone)]
pub struct MetadataDb {
    pool: Pool<SqliteConnectionManager>,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for MetadataDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataDb").field("path", &self.path).finish_non_exhaustive()
    }
}

impl MetadataDb {
    /// Opens (or creates) a metadata database and migrates it to the current schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let manager = SqliteConnectionManager::file(&path).with_init(Self::configure);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let db = Self { pool, path: Some(path) };
        db.migrate()?;
        Ok(db)
    }

    /// Opens an in-memory database, for tests and for commands that persist nothing.
    ///
    /// The pool is capped at one connection: every additional SQLite in-memory
    /// connection would otherwise get its *own* empty database.
    pub fn in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory().with_init(Self::configure);
        let pool = Pool::builder().max_size(1).build(manager)?;
        let db = Self { pool, path: None };
        db.migrate()?;
        Ok(db)
    }

    /// Per-connection pragmas.
    ///
    /// `foreign_keys` is off by default in SQLite and is per *connection*, not per
    /// database. The cascade rules in the schema are load bearing, so a connection
    /// that skipped this would silently orphan rows.
    ///
    /// `journal_mode = WAL` is what lets the proxy append captured traffic while the
    /// UI reads history; it is persistent, but is set on every connection because
    /// setting it is idempotent and cheaper than checking.
    fn configure(conn: &mut Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = MEMORY;",
        )
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = self.pool.get()?;
        migrations::migrate(&mut conn)?;
        Ok(())
    }

    /// Borrows a pooled connection.
    pub fn connection(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.pool.get()?)
    }

    /// The schema revision of the open database.
    pub fn schema_version(&self) -> Result<u32> {
        migrations::current_version(&self.connection()?)
    }

    /// The database file path, or `None` for an in-memory database.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// An open project: metadata plus the blob store holding its bodies.
///
/// On disk a project is a directory, not a single file:
///
/// ```text
/// engagement.hexora/
/// ├── project.db      metadata (SQLite)
/// └── blobs/          content-addressed bodies
///     └── ab/abcdef…
/// ```
///
/// A directory rather than one file is what makes the metadata small and portable
/// while the body store grows to whatever the engagement needs, and it lets the blob
/// directory be excluded from a quick backup or moved to a different volume.
pub struct Project {
    metadata: MetadataDb,
    blobs: Box<dyn BlobStore>,
    root: Option<PathBuf>,
}

impl std::fmt::Debug for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Project").field("root", &self.root).finish_non_exhaustive()
    }
}

impl Project {
    /// Bodies at or above this size are worth the round trip to the blob store.
    ///
    /// Below it the storage overhead of a separate file outweighs the benefit, so
    /// small bodies are still content-addressed but callers may batch them.
    pub const BLOB_THRESHOLD: usize = 4 * 1024;

    /// Opens (or creates) a project directory.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let metadata = MetadataDb::open(root.join("project.db"))?;
        let blobs = FsBlobStore::open(root.join("blobs"))?;
        Ok(Self { metadata, blobs: Box::new(blobs), root: Some(root) })
    }

    /// Opens a project that persists nothing. Used by tests and `hexora replay`.
    pub fn in_memory() -> Result<Self> {
        Ok(Self {
            metadata: MetadataDb::in_memory()?,
            blobs: Box::new(MemoryBlobStore::new()),
            root: None,
        })
    }

    /// The relational metadata database.
    pub fn metadata(&self) -> &MetadataDb {
        &self.metadata
    }

    /// The body store.
    pub fn blobs(&self) -> &dyn BlobStore {
        self.blobs.as_ref()
    }

    /// The project directory, or `None` for an in-memory project.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_memory_database_opens_at_the_current_schema() {
        let db = MetadataDb::in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), migrations::target_version());
        assert!(db.path().is_none());
    }

    #[test]
    fn foreign_keys_are_enforced_on_pooled_connections() {
        let db = MetadataDb::in_memory().unwrap();
        let conn = db.connection().unwrap();
        let enabled: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(enabled, 1, "the schema's cascade rules depend on this");
    }

    #[test]
    fn a_file_database_uses_wal_so_capture_and_browsing_can_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDb::open(dir.path().join("project.db")).unwrap();
        let mode: String =
            db.connection().unwrap().query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn a_project_survives_being_closed_and_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("engagement.hexora");

        let project = Project::open(&root).unwrap();
        project
            .metadata()
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO project (id, name, created_at, updated_at)
                 VALUES ('prj_1', 'Acme engagement', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        let body = project.blobs().put(b"a captured response body").unwrap();
        drop(project);

        let reopened = Project::open(&root).unwrap();
        let name: String = reopened
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT name FROM project WHERE id = 'prj_1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Acme engagement");
        assert_eq!(reopened.blobs().get(&body).unwrap(), b"a captured response body");
    }

    #[test]
    fn a_project_keeps_metadata_and_bodies_in_separate_places() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("p.hexora");
        let project = Project::open(&root).unwrap();
        project.blobs().put(b"body").unwrap();
        assert!(root.join("project.db").is_file());
        assert!(root.join("blobs").is_dir());
    }

    #[test]
    fn an_in_memory_project_persists_nothing() {
        let project = Project::in_memory().unwrap();
        assert!(project.root().is_none());
        let reference = project.blobs().put(b"scratch").unwrap();
        assert_eq!(project.blobs().get(&reference).unwrap(), b"scratch");
    }

    #[test]
    fn concurrent_pooled_connections_see_the_same_data() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDb::open(dir.path().join("project.db")).unwrap();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
                 VALUES ('tgt_1', 'example.com', 443, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        let reader = db.connection().unwrap();
        let count: i64 = reader.query_row("SELECT count(*) FROM targets", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn opening_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deeper").join("project.db");
        assert!(MetadataDb::open(&path).is_ok());
        assert!(path.exists());
    }
}
