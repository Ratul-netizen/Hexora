//! Persisting declared object identifiers, and the requests constructed from them.
//!
//! A declaration is the tester's assertion that a particular string is an object
//! belonging to a particular identity. It is stored because a constructed attempt
//! made six weeks ago has to remain explicable: "why did Hexora ask for
//! `invoice-1001` as User B?" is answered by a row here, not by a reader inferring it
//! from two paths that differ by one segment.
//!
//! # Declaring causes no traffic
//!
//! Nothing in this module sends anything. Writing a declaration is data entry;
//! running the test is a separate, explicit act. That separation is deliberate — a
//! project that emitted requests as a side effect of being edited would be a project
//! nobody could safely open on a client's network.

use hexora_types::ids::{IdentityId, ObjectId, RequestId};
use hexora_types::object::{ObjectDeclaration, ObjectLocation};
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StorageError};
use crate::MetadataDb;

/// One constructed request, and why it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructedAttempt {
    /// The generated request.
    pub request: RequestId,
    /// The request it was built from.
    pub source_request: RequestId,
    /// The declaration whose value was substituted in, when it is still there.
    pub declaration: Option<ObjectId>,
    /// The identity it was sent as.
    pub sender: Option<IdentityId>,
    /// Where the substitution happened.
    pub location: ObjectLocation,
    /// What was in that place before.
    pub original_value: String,
    /// What replaced it.
    pub replacement_value: String,
}

/// Reads and writes object declarations and constructed attempts.
#[derive(Debug, Clone)]
pub struct ObjectStore {
    db: MetadataDb,
}

impl ObjectStore {
    /// Opens the store over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// Writes a declaration, replacing one that says the same thing.
    ///
    /// "The same thing" is the same value, owned by the same identity, in the same
    /// place. Declaring it twice is something a tester does by accident; producing two
    /// rows would then produce two constructed attempts and, eventually, two findings
    /// about one substitution.
    pub fn put(&self, declaration: &ObjectDeclaration) -> Result<()> {
        let conn = self.db.connection()?;
        conn.execute(
            "INSERT INTO object_declarations
                 (id, name, value, owner_id, source_request_id, location_json,
                  location_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (owner_id, value, location_key) DO UPDATE SET
                 name = excluded.name,
                 source_request_id = excluded.source_request_id,
                 location_json = excluded.location_json",
            params![
                declaration.id.to_string(),
                declaration.name,
                declaration.value,
                declaration.owner.to_string(),
                declaration.source_request.map(|r| r.to_string()),
                serde_json::to_string(&declaration.location).map_err(|e| {
                    StorageError::Decode {
                        entity: "object location",
                        reason: e.to_string(),
                    }
                })?,
                declaration.location.key(),
                declaration.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Every declaration in the project, oldest first.
    pub fn list(&self) -> Result<Vec<ObjectDeclaration>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT id, name, value, owner_id, source_request_id, location_json, created_at
             FROM object_declarations ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], decode)?;
        let mut declarations = Vec::new();
        for row in rows {
            declarations.push(row??);
        }
        Ok(declarations)
    }

    /// One declaration by id.
    pub fn get(&self, id: ObjectId) -> Result<ObjectDeclaration> {
        let conn = self.db.connection()?;
        let row = conn
            .query_row(
                "SELECT id, name, value, owner_id, source_request_id, location_json, created_at
                 FROM object_declarations WHERE id = ?1",
                params![id.to_string()],
                decode,
            )
            .optional()?;
        row.ok_or_else(|| StorageError::NotFound {
            entity: "object declaration",
            id: id.to_string(),
        })?
    }

    /// Removes a declaration. Returns whether there was one.
    ///
    /// Traffic already constructed from it is kept, and still names the substitution:
    /// the attempt row holds the values rather than only pointing at the declaration,
    /// so deleting a declaration cannot orphan the evidence behind a finding.
    pub fn delete(&self, id: ObjectId) -> Result<bool> {
        let conn = self.db.connection()?;
        let removed = conn.execute(
            "DELETE FROM object_declarations WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(removed > 0)
    }

    /// Records why a constructed request exists.
    pub fn record_attempt(&self, attempt: &ConstructedAttempt) -> Result<()> {
        let conn = self.db.connection()?;
        conn.execute(
            "INSERT OR REPLACE INTO constructed_attempts
                 (request_id, source_request_id, declaration_id, sender_id,
                  location_json, original_value, replacement_value, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                attempt.request.to_string(),
                attempt.source_request.to_string(),
                attempt.declaration.map(|d| d.to_string()),
                attempt.sender.map(|s| s.to_string()),
                serde_json::to_string(&attempt.location).map_err(|e| StorageError::Decode {
                    entity: "object location",
                    reason: e.to_string(),
                })?,
                attempt.original_value,
                attempt.replacement_value,
                crate::traffic::now(),
            ],
        )?;
        Ok(())
    }

    /// Why one generated request exists, if it was constructed.
    pub fn attempt(&self, request: RequestId) -> Result<Option<ConstructedAttempt>> {
        let conn = self.db.connection()?;
        let row = conn
            .query_row(
                "SELECT request_id, source_request_id, declaration_id, sender_id,
                        location_json, original_value, replacement_value
                 FROM constructed_attempts WHERE request_id = ?1",
                params![request.to_string()],
                decode_attempt,
            )
            .optional()?;
        row.transpose()
    }

    /// Every attempt constructed from one source request, oldest first.
    pub fn attempts_from(&self, source: RequestId) -> Result<Vec<ConstructedAttempt>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT request_id, source_request_id, declaration_id, sender_id,
                    location_json, original_value, replacement_value
             FROM constructed_attempts WHERE source_request_id = ?1
             ORDER BY request_id ASC",
        )?;
        let rows = statement.query_map(params![source.to_string()], decode_attempt)?;
        let mut attempts = Vec::new();
        for row in rows {
            attempts.push(row??);
        }
        Ok(attempts)
    }

    /// How many declarations the project holds.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 =
            conn.query_row("SELECT count(*) FROM object_declarations", [], |r| r.get(0))?;
        Ok(count as u64)
    }
}

type Decoded<T> = rusqlite::Result<Result<T>>;

fn decode(row: &rusqlite::Row<'_>) -> Decoded<ObjectDeclaration> {
    let id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let value: String = row.get(2)?;
    let owner: String = row.get(3)?;
    let source: Option<String> = row.get(4)?;
    let location: String = row.get(5)?;
    let created: String = row.get(6)?;

    Ok((|| {
        Ok(ObjectDeclaration {
            id: id.parse()?,
            name,
            value,
            owner: owner.parse()?,
            source_request: source.map(|s| s.parse()).transpose()?,
            location: serde_json::from_str(&location).map_err(|e| StorageError::Decode {
                entity: "object location",
                reason: e.to_string(),
            })?,
            created_at: parse_time(&created)?,
        })
    })())
}

fn decode_attempt(row: &rusqlite::Row<'_>) -> Decoded<ConstructedAttempt> {
    let request: String = row.get(0)?;
    let source: String = row.get(1)?;
    let declaration: Option<String> = row.get(2)?;
    let sender: Option<String> = row.get(3)?;
    let location: String = row.get(4)?;
    let original_value: String = row.get(5)?;
    let replacement_value: String = row.get(6)?;

    Ok((|| {
        Ok(ConstructedAttempt {
            request: request.parse()?,
            source_request: source.parse()?,
            declaration: declaration.map(|d| d.parse()).transpose()?,
            sender: sender.map(|s| s.parse()).transpose()?,
            location: serde_json::from_str(&location).map_err(|e| StorageError::Decode {
                entity: "object location",
                reason: e.to_string(),
            })?,
            original_value,
            replacement_value,
        })
    })())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| StorageError::Decode {
            entity: "object declaration",
            reason: format!("{value:?} is not an RFC 3339 timestamp: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use hexora_types::identity::Identity;

    use super::*;
    use crate::{IdentityStore, Project};

    fn project() -> (Project, IdentityId) {
        let project = Project::in_memory().unwrap();
        let identity = Identity::bearer("User A", "token-a");
        IdentityStore::new(project.metadata().clone())
            .put(&identity)
            .unwrap();
        (project, identity.id)
    }

    fn declaration(owner: IdentityId, value: &str) -> ObjectDeclaration {
        ObjectDeclaration::new(
            "invoice",
            value,
            owner,
            ObjectLocation::PathSegment { index: 1 },
        )
        .unwrap()
    }

    #[test]
    fn a_declaration_survives_a_round_trip() {
        let (project, owner) = project();
        let store = ObjectStore::new(project.metadata().clone());
        let declared = declaration(owner, "invoice-1001");
        store.put(&declared).unwrap();

        let read = store.get(declared.id).unwrap();
        assert_eq!(read.value, "invoice-1001");
        assert_eq!(read.owner, owner);
        assert_eq!(read.location, ObjectLocation::PathSegment { index: 1 });
        assert_eq!(read.name, "invoice");
    }

    #[test]
    fn declaring_the_same_object_twice_leaves_one_row() {
        // Otherwise one accidental repeat becomes two constructed attempts and,
        // eventually, two findings about a single substitution.
        let (project, owner) = project();
        let store = ObjectStore::new(project.metadata().clone());
        store.put(&declaration(owner, "invoice-1001")).unwrap();
        store.put(&declaration(owner, "invoice-1001")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn the_same_value_in_a_different_place_is_a_different_declaration() {
        let (project, owner) = project();
        let store = ObjectStore::new(project.metadata().clone());
        store.put(&declaration(owner, "invoice-1001")).unwrap();

        let mut elsewhere = declaration(owner, "invoice-1001");
        elsewhere.location = ObjectLocation::Query {
            name: "id".into(),
            occurrence: 0,
        };
        store.put(&elsewhere).unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn removing_an_identity_removes_its_declarations() {
        // A declaration is a claim about who owns something. Left behind, it would be
        // a claim about nobody.
        let (project, owner) = project();
        let store = ObjectStore::new(project.metadata().clone());
        store.put(&declaration(owner, "invoice-1001")).unwrap();

        IdentityStore::new(project.metadata().clone())
            .delete(owner)
            .unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn a_missing_declaration_is_reported_as_not_found() {
        let (project, _) = project();
        let store = ObjectStore::new(project.metadata().clone());
        let error = store.get(ObjectId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error:?}");
    }

    #[test]
    fn deleting_reports_whether_there_was_anything_to_delete() {
        let (project, owner) = project();
        let store = ObjectStore::new(project.metadata().clone());
        let declared = declaration(owner, "invoice-1001");
        store.put(&declared).unwrap();

        assert!(store.delete(declared.id).unwrap());
        assert!(!store.delete(declared.id).unwrap());
    }
}
