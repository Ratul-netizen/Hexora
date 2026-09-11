//! Schema migrations.
//!
//! A Hexora project is a file a tester keeps for the length of an engagement and
//! often much longer — it is the evidence behind a report. Opening last year's
//! project in this year's build must work, so the rule is absolute: **migrations only
//! ever move forward, and a released migration is never edited.**
//!
//! Migrations are embedded in the binary with `include_str!` so a project can be
//! opened by a single-file CLI with no data directory alongside it.

use rusqlite::{Connection, Transaction};

use crate::error::{Result, StorageError};

/// One forward schema migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Monotonic revision number, starting at 1.
    pub version: u32,
    /// Human-readable name, matching the filename.
    pub name: &'static str,
    /// The SQL to apply.
    pub sql: &'static str,
}

/// Every migration, in application order.
///
/// Appending here is the only supported way to change the schema.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: include_str!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "wire_bodies",
        sql: include_str!("../migrations/0002_wire_bodies.sql"),
    },
    Migration {
        version: 3,
        name: "object_declarations",
        sql: include_str!("../migrations/0003_object_declarations.sql"),
    },
    Migration {
        version: 4,
        name: "request_mode",
        sql: include_str!("../migrations/0004_request_mode.sql"),
    },
    Migration {
        version: 5,
        name: "identifier_candidates",
        sql: include_str!("../migrations/0005_identifier_candidates.sql"),
    },
    Migration {
        version: 6,
        name: "snapshots",
        sql: include_str!("../migrations/0006_snapshots.sql"),
    },
    Migration {
        version: 7,
        name: "scan_runs",
        sql: include_str!("../migrations/0007_scan_runs.sql"),
    },
    Migration {
        version: 8,
        name: "active_runs",
        sql: include_str!("../migrations/0008_active_runs.sql"),
    },
    Migration {
        version: 9,
        name: "attached_headers",
        sql: include_str!("../migrations/0009_attached_headers.sql"),
    },
    Migration {
        version: 10,
        name: "programme",
        sql: include_str!("../migrations/0010_programme.sql"),
    },
    Migration {
        version: 11,
        name: "session_cookies",
        sql: include_str!("../migrations/0011_session_cookies.sql"),
    },
];

/// The schema version this build expects.
pub fn target_version() -> u32 {
    MIGRATIONS.last().map(|m| m.version).unwrap_or(0)
}

/// Reads the schema version recorded in a database.
///
/// Uses SQLite's built-in `user_version` pragma rather than a bespoke table, so the
/// version is readable even from a database whose tables failed to create.
pub fn current_version(conn: &Connection) -> Result<u32> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    u32::try_from(version)
        .map_err(|_| StorageError::CorruptSchema(format!("negative user_version {version}")))
}

/// Applies every migration newer than the database's recorded version.
///
/// Each migration runs inside its own transaction together with the version bump, so
/// an interrupted upgrade leaves the database at a consistent earlier revision rather
/// than half-migrated.
pub fn migrate(conn: &mut Connection) -> Result<u32> {
    let from = current_version(conn)?;
    let to = target_version();

    if from > to {
        // The project was written by a newer Hexora. Refusing is the only safe
        // option: applying old code to a newer schema silently corrupts evidence.
        return Err(StorageError::SchemaTooNew {
            found: from,
            supported: to,
        });
    }

    for migration in MIGRATIONS.iter().filter(|m| m.version > from) {
        tracing::info!(
            version = migration.version,
            name = migration.name,
            "applying schema migration"
        );
        let tx = conn.transaction()?;
        apply(&tx, migration)?;
        tx.commit()?;
    }

    Ok(to)
}

fn apply(tx: &Transaction<'_>, migration: &Migration) -> Result<()> {
    tx.execute_batch(migration.sql)
        .map_err(|e| StorageError::MigrationFailed {
            version: migration.version,
            name: migration.name,
            source: e,
        })?;
    // `pragma_update` cannot be used inside a transaction for user_version on all
    // SQLite builds, so the value is set with a literal. It is a `u32` from a
    // compile-time constant, so there is no injection surface here.
    tx.execute_batch(&format!("PRAGMA user_version = {}", migration.version))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn a_fresh_database_reports_version_zero() {
        assert_eq!(current_version(&memory_db()).unwrap(), 0);
    }

    #[test]
    fn migrating_brings_a_fresh_database_to_the_target_version() {
        let mut conn = memory_db();
        let version = migrate(&mut conn).unwrap();
        assert_eq!(version, target_version());
        assert_eq!(current_version(&conn).unwrap(), target_version());
    }

    #[test]
    fn migrating_is_idempotent() {
        let mut conn = memory_db();
        migrate(&mut conn).unwrap();
        let second = migrate(&mut conn).unwrap();
        assert_eq!(
            second,
            target_version(),
            "re-running migrations must be a no-op"
        );
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_downgraded() {
        let mut conn = memory_db();
        conn.execute_batch("PRAGMA user_version = 9999").unwrap();
        let err = migrate(&mut conn).unwrap_err();
        assert!(
            matches!(err, StorageError::SchemaTooNew { found: 9999, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_v1_database_upgrades_in_place_without_losing_data() {
        // The property that makes migrations safe: an existing project keeps its
        // contents. A tester's evidence must survive a Hexora upgrade.
        let mut conn = memory_db();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.execute_batch("PRAGMA user_version = 1").unwrap();
        conn.execute_batch(
            "INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
             VALUES ('tgt_1', 'example.com', 443, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO requests (id, target_id, origin, method, path, http_version, headers_raw, sent_at)
             VALUES ('req_1', 'tgt_1', 'proxy', 'GET', '/kept', 'HTTP/1.1', x'', '2026-01-01T00:00:00Z');",
        )
        .unwrap();

        assert_eq!(migrate(&mut conn).unwrap(), target_version());

        let path: String = conn
            .query_row("SELECT path FROM requests WHERE id = 'req_1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(path, "/kept", "an upgrade must not lose captured traffic");

        // And the new columns exist with their defaults.
        let quirks: String = conn
            .query_row("SELECT quirks FROM requests WHERE id = 'req_1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(quirks, "[]");
    }

    #[test]
    fn migration_versions_are_sequential_and_start_at_one() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                migration.version,
                index as u32 + 1,
                "migration versions must be dense and start at 1"
            );
        }
    }

    #[test]
    fn every_expected_table_exists_after_migration() {
        let mut conn = memory_db();
        migrate(&mut conn).unwrap();
        let expected = [
            "project",
            "targets",
            "endpoints",
            "requests",
            "responses",
            "websocket_messages",
            "notes",
            "identities",
            "findings",
            "finding_evidence",
            "scanner_jobs",
            "attacks",
            "oob_interactions",
            "workflows",
            "workflow_runs",
            "extensions",
            "audit_events",
        ];
        for table in expected {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} is missing after migration");
        }
    }

    #[test]
    fn deleting_a_request_cascades_to_its_response() {
        let mut conn = memory_db();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
                VALUES ('tgt_1', 'example.com', 443, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
            INSERT INTO requests (id, target_id, origin, method, path, http_version, headers_raw, sent_at)
                VALUES ('req_1', 'tgt_1', 'proxy', 'GET', '/', 'HTTP/1.1', x'', '2026-01-01T00:00:00Z');
            INSERT INTO responses (id, request_id, status, http_version, headers_raw, received_at)
                VALUES ('res_1', 'req_1', 200, 'HTTP/1.1', x'', '2026-01-01T00:00:00Z');
            DELETE FROM requests WHERE id = 'req_1';
            "#,
        )
        .unwrap();
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM responses", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            remaining, 0,
            "orphaned responses must not survive their request"
        );
    }

    #[test]
    fn a_body_reference_and_its_size_must_agree() {
        let mut conn = memory_db();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
             VALUES ('tgt_1', 'example.com', 443, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .unwrap();

        // A hash with a zero size, or a non-zero size with no hash, would leave the
        // blob store and the metadata disagreeing about whether a body exists.
        let dangling_hash = conn.execute_batch(
            "INSERT INTO requests (id, target_id, origin, method, path, http_version,
                                   headers_raw, body_hash, body_size, sent_at)
             VALUES ('req_1', 'tgt_1', 'proxy', 'GET', '/', 'HTTP/1.1', x'', 'abc', 0,
                     '2026-01-01T00:00:00Z');",
        );
        assert!(
            dangling_hash.is_err(),
            "a body reference with zero size is inconsistent"
        );

        let sizeless_body = conn.execute_batch(
            "INSERT INTO requests (id, target_id, origin, method, path, http_version,
                                   headers_raw, body_hash, body_size, sent_at)
             VALUES ('req_2', 'tgt_1', 'proxy', 'GET', '/', 'HTTP/1.1', x'', NULL, 42,
                     '2026-01-01T00:00:00Z');",
        );
        assert!(
            sizeless_body.is_err(),
            "a sized body with no reference is inconsistent"
        );

        // An empty body is the normal case and must be accepted.
        conn.execute_batch(
            "INSERT INTO requests (id, target_id, origin, method, path, http_version,
                                   headers_raw, body_hash, body_size, sent_at)
             VALUES ('req_3', 'tgt_1', 'proxy', 'GET', '/', 'HTTP/1.1', x'', NULL, 0,
                     '2026-01-01T00:00:00Z');",
        )
        .unwrap();
    }

    #[test]
    fn an_unknown_request_origin_is_rejected() {
        let mut conn = memory_db();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
             VALUES ('tgt_1', 'example.com', 443, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .unwrap();
        let result = conn.execute_batch(
            "INSERT INTO requests (id, target_id, origin, method, path, http_version, headers_raw, sent_at)
             VALUES ('req_1', 'tgt_1', 'telepathy', 'GET', '/', 'HTTP/1.1', x'', '2026-01-01T00:00:00Z');",
        );
        assert!(result.is_err());
    }
}
