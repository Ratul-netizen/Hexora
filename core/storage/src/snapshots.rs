//! Storing what an engagement looked like at a moment.
//!
//! Every other store in this crate is live: findings are refreshed in place when a
//! test is re-run, candidates re-scored, scope edited. That is what a working project
//! needs and exactly what a retest cannot use — the question on the second visit is
//! *what changed*, and answering it requires a record of what was true then that a
//! later run cannot rewrite.
//!
//! # Immutable, and structurally so
//!
//! There is no update method here, and there is no path that takes a
//! [`SnapshotId`](hexora_types::ids::SnapshotId) and writes to it. A snapshot is
//! created, read and deleted. That is what makes the summary columns on the row safe:
//! they are computed from the contents at insert time, and nothing exists that could
//! change one without the other.
//!
//! # What [`capture`] reads, and what it never touches
//!
//! `capture` is a read of a project against itself. It sends nothing, changes nothing,
//! and takes no transport — the same shape as the identifier analyzer, for the same
//! reason. It reads scope, identities (labels and privilege only, never credentials),
//! declared objects, findings, and two counts. It does **not** copy traffic: bodies
//! are the largest thing in a project by orders of magnitude, and a snapshot exists to
//! be diffed, not restored.

use hexora_types::ids::SnapshotId;
use hexora_types::snapshot::{
    Claim, Contents, FindingRecord, FindingState, IdentityRecord, ObjectRecord, Snapshot,
};
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StorageError};
use crate::repository::{Limit, Page};
use crate::{FindingFilter, Project};

/// A snapshot's header, without its contents.
///
/// What a list shows. The contents column is deliberately not selected: SQLite keeps a
/// large value in overflow pages and only faults them in when the column is read, so
/// listing twenty snapshots costs twenty small rows rather than twenty documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSummary {
    /// Stable identifier.
    pub id: SnapshotId,
    /// What the tester called it.
    pub label: String,
    /// Anything the label could not hold.
    pub note: Option<String>,
    /// When it was taken.
    pub taken_at: chrono::DateTime<chrono::Utc>,
    /// The build that took it.
    pub tool_version: String,
    /// The project schema revision at the time.
    pub schema_version: u32,
    /// Captured exchanges at the time.
    pub exchanges: u64,
    /// Identifier suggestions at the time.
    pub candidates: u64,
    /// How many of those a human had decided.
    pub candidates_reviewed: u64,
    /// Claims held at the time.
    pub findings: u64,
    /// Identities the project tested as.
    pub identities: u64,
    /// Object identifiers declared.
    pub objects: u64,
}

/// Reads and writes a project's snapshots.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    db: crate::MetadataDb,
}

impl SnapshotStore {
    /// Opens the snapshot store over a project's metadata database.
    pub fn new(db: crate::MetadataDb) -> Self {
        Self { db }
    }

    /// Writes a snapshot. There is no method that modifies one afterwards.
    pub fn put(&self, snapshot: &Snapshot) -> Result<()> {
        let contents =
            serde_json::to_string(&snapshot.contents).map_err(|e| StorageError::Decode {
                entity: "SnapshotContents",
                reason: format!("{e}"),
            })?;
        let reviewed = snapshot.contents.candidates_reviewed;

        let conn = self.db.connection()?;
        conn.execute(
            "INSERT INTO snapshots (
                 id, label, note, taken_at, tool_version, schema_version,
                 exchanges, candidates, candidates_reviewed,
                 finding_count, identity_count, object_count, contents_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                snapshot.id.to_string(),
                snapshot.label,
                snapshot.note,
                snapshot.taken_at.to_rfc3339(),
                snapshot.tool_version,
                snapshot.schema_version,
                snapshot.contents.exchanges as i64,
                snapshot.contents.candidates as i64,
                reviewed as i64,
                snapshot.contents.findings.len() as i64,
                snapshot.contents.identities.len() as i64,
                snapshot.contents.objects.len() as i64,
                contents,
            ],
        )?;
        Ok(())
    }

    /// Every snapshot, newest first.
    ///
    /// Not paginated: snapshots are taken by hand, a few per engagement. Anything that
    /// grows with traffic volume is paginated; this does not.
    pub fn list(&self) -> Result<Vec<SnapshotSummary>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT id, label, note, taken_at, tool_version, schema_version,
                    exchanges, candidates, candidates_reviewed,
                    finding_count, identity_count, object_count
             FROM snapshots ORDER BY taken_at DESC, id DESC",
        )?;
        let rows = statement.query_map([], decode_summary)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .collect()
    }

    /// The most recent snapshot's header, if the project has one.
    ///
    /// The default left-hand side of "what has changed?", which is the comparison
    /// almost every retest actually wants.
    pub fn latest(&self) -> Result<Option<SnapshotSummary>> {
        Ok(self.list()?.into_iter().next())
    }

    /// One snapshot, with its contents.
    pub fn get(&self, id: SnapshotId) -> Result<Snapshot> {
        let conn = self.db.connection()?;
        let row: Option<(String, Option<String>, String, String, u32, String)> = conn
            .query_row(
                "SELECT label, note, taken_at, tool_version, schema_version, contents_json
                 FROM snapshots WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;

        let (label, note, taken_at, tool_version, schema_version, contents) =
            row.ok_or_else(|| StorageError::NotFound {
                entity: "snapshot",
                id: id.to_string(),
            })?;

        let contents: Contents =
            serde_json::from_str(&contents).map_err(|e| StorageError::Decode {
                entity: "SnapshotContents",
                reason: format!("{e}"),
            })?;

        Ok(Snapshot {
            id,
            label,
            note,
            taken_at: parse_time(&taken_at)?,
            tool_version,
            schema_version,
            contents,
        })
    }

    /// Removes a snapshot. Used for a mislabelled one; nothing else deletes them.
    pub fn delete(&self, id: SnapshotId) -> Result<bool> {
        let conn = self.db.connection()?;
        let removed = conn.execute(
            "DELETE FROM snapshots WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(removed > 0)
    }

    /// How many snapshots the project holds.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 = conn.query_row("SELECT count(*) FROM snapshots", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

/// Reads a project into a snapshot's contents.
///
/// A read, and only a read: no transport, no writes, nothing sent. Safe to call at any
/// point in an engagement, including on somebody else's finished project.
pub fn capture(project: &Project) -> Result<Contents> {
    let identities = project.identities();

    let mut records = Vec::new();
    for identity in identities.list()? {
        // Three fields, chosen rather than derived. `Identity` also carries a
        // `Credential`; copying the struct wholesale is how that would end up in an
        // exported snapshot, so the fields are listed out one at a time.
        records.push(IdentityRecord {
            id: identity.id,
            label: identity.label,
            privilege: identity.privilege,
        });
    }

    let by_id: std::collections::BTreeMap<String, String> = records
        .iter()
        .map(|i| (i.id.to_string(), i.label.clone()))
        .collect();

    let objects = project
        .objects()
        .list()?
        .into_iter()
        .map(|declaration| ObjectRecord {
            name: declaration.name,
            value: declaration.value,
            // The label at the time. An identity renamed between snapshots would
            // otherwise make every declaration look like it moved.
            owner: by_id
                .get(&declaration.owner.to_string())
                .cloned()
                .unwrap_or_else(|| declaration.owner.to_string()),
            location: declaration.location,
        })
        .collect();

    let findings = all_findings(project)?;
    let candidates = project
        .candidates()
        .list(&crate::CandidateFilter::default())?;

    Ok(Contents {
        scope: project.settings().scope()?,
        identities: records,
        objects,
        findings,
        exchanges: project.traffic().count()?,
        candidates: candidates.len() as u64,
        candidates_reviewed: candidates
            .iter()
            .filter(|candidate| candidate.status.is_reviewed())
            .count() as u64,
    })
}

/// Every finding in the project, paged through to the end.
///
/// A snapshot that silently held the first page would report every claim beyond it as
/// having appeared or disappeared on the next comparison, so this pages rather than
/// taking a limit.
fn all_findings(project: &Project) -> Result<Vec<FindingRecord>> {
    let store = project.findings();
    let filter = FindingFilter::default();
    let mut cursor = None;
    let mut out = Vec::new();

    loop {
        let Page { items, next } = store.list(&filter, cursor.as_ref(), Limit::new(Limit::MAX))?;
        for finding in items {
            out.push(FindingRecord {
                claim: Claim {
                    target: finding.target,
                    title: finding.title,
                    location: finding.location,
                },
                state: FindingState {
                    severity: finding.severity,
                    confidence: finding.confidence,
                    status: finding.status,
                    evidence: finding.evidence.len() as u32,
                },
                source: finding.source,
                first_recorded: finding.created_at,
                last_updated: Some(finding.updated_at),
            });
        }
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(out)
}

fn decode_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<SnapshotSummary>> {
    let id: String = row.get(0)?;
    let taken_at: String = row.get(3)?;
    let label: String = row.get(1)?;
    let note: Option<String> = row.get(2)?;
    let tool_version: String = row.get(4)?;
    let schema_version: u32 = row.get(5)?;
    let counts: [i64; 6] = [
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ];

    Ok((|| {
        Ok(SnapshotSummary {
            id: id.parse().map_err(|e| StorageError::Decode {
                entity: "SnapshotId",
                reason: format!("{e}"),
            })?,
            label,
            note,
            taken_at: parse_time(&taken_at)?,
            tool_version,
            schema_version,
            exchanges: counts[0] as u64,
            candidates: counts[1] as u64,
            candidates_reviewed: counts[2] as u64,
            findings: counts[3] as u64,
            identities: counts[4] as u64,
            objects: counts[5] as u64,
        })
    })())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| StorageError::Decode {
            entity: "Snapshot.taken_at",
            reason: format!("{e}"),
        })
}

#[cfg(test)]
mod tests {
    use hexora_types::finding::{
        Confidence, Evidence, Finding, FindingSource, FindingStatus, Location, MessagePart,
        Severity,
    };
    use hexora_types::identity::{Identity, PrivilegeLevel};
    use hexora_types::ids::{FindingId, RequestId, TargetId};
    use hexora_types::object::{ObjectDeclaration, ObjectLocation};
    use hexora_types::scope::{Scope, ScopeRule};
    use hexora_types::snapshot::{compare, Change, WhyGone};

    use super::*;

    fn project() -> Project {
        let project = Project::in_memory().unwrap();
        // `set_scope` writes onto the project row, which `Project::in_memory` does not
        // create. Seeded here rather than worked around, so the test exercises the same
        // path a real project takes.
        project
            .metadata()
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO project (id, name, created_at, updated_at)
                 VALUES ('prj_default', 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        project
    }

    fn target(project: &Project) -> TargetId {
        project
            .traffic()
            .upsert_target("api.example.com", 443, true)
            .unwrap()
    }

    fn finding(target: TargetId, title: &str, severity: Severity) -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: FindingId::new(),
            target,
            title: title.into(),
            severity,
            confidence: Confidence::Confirmed,
            location: Some(Location {
                part: MessagePart::Path,
                name: title.into(),
            }),
            description: "One identity received another identity's account.".into(),
            impact: "One user can read another user's records.".into(),
            remediation: "Scope the lookup to the session.".into(),
            reproduction: "Send as A, send as B, compare.".into(),
            evidence: vec![Evidence::Comparison {
                baseline: RequestId::new(),
                variant: RequestId::new(),
                difference: "User B received acct-1000".into(),
            }],
            cwe: Some("CWE-639".into()),
            owasp: None,
            cvss: None,
            source: FindingSource::AuthorizationTest,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        }
    }

    fn take(project: &Project, label: &str, version: &str) -> Snapshot {
        let snapshot = Snapshot {
            id: SnapshotId::new(),
            label: label.into(),
            note: None,
            taken_at: chrono::Utc::now(),
            tool_version: version.into(),
            schema_version: project.metadata().schema_version().unwrap(),
            contents: capture(project).unwrap(),
        };
        project.snapshots().put(&snapshot).unwrap();
        snapshot
    }

    #[test]
    fn a_snapshot_survives_the_findings_it_copied_being_rewritten() {
        // The property the whole milestone rests on. The findings store updates a
        // claim in place on a re-run; if a snapshot referenced rows instead of copying
        // them, taking one would be pointless.
        let project = project();
        let target = target(&project);
        let mut original = finding(target, "IDOR in GET /accounts/{id}", Severity::High);
        project.findings().record(&original).unwrap();

        let before = take(&project, "before the fix", "0.1.0");

        original.severity = Severity::Low;
        original.confidence = Confidence::Tentative;
        project.findings().record(&original).unwrap();

        let reread = project.snapshots().get(before.id).unwrap();
        assert_eq!(reread.contents.findings[0].state.severity, Severity::High);
        assert_eq!(
            reread.contents.findings[0].state.confidence,
            Confidence::Confirmed
        );
    }

    #[test]
    fn capturing_records_labels_and_privilege_and_never_a_credential() {
        let project = project();
        let identity = Identity::bearer("User A", "super-secret-session-token");
        project.identities().put(&identity).unwrap();

        let contents = capture(&project).unwrap();
        assert_eq!(contents.identities[0].label, "User A");
        assert_eq!(contents.identities[0].privilege, PrivilegeLevel::User);

        let json = serde_json::to_string(&contents).unwrap();
        assert!(
            !json.contains("super-secret-session-token"),
            "a credential reached a snapshot: {json}"
        );
    }

    #[test]
    fn capturing_reads_scope_objects_and_counts() {
        let project = project();
        project
            .settings()
            .set_scope(&Scope::new().include(ScopeRule::host("api.example.com")))
            .unwrap();

        let identity = Identity::bearer("User A", "token");
        let owner = identity.id;
        project.identities().put(&identity).unwrap();
        project
            .objects()
            .put(
                &ObjectDeclaration::new(
                    "account",
                    "acct-1000",
                    owner,
                    ObjectLocation::PathSegment { index: 1 },
                )
                .unwrap(),
            )
            .unwrap();

        let contents = capture(&project).unwrap();
        assert_eq!(contents.scope.include.len(), 1);
        assert_eq!(contents.objects.len(), 1);
        // The owner is the label, not the id: an identity renamed between snapshots
        // should not make every declaration look like it moved.
        assert_eq!(contents.objects[0].owner, "User A");
        assert_eq!(contents.exchanges, 0);
    }

    #[test]
    fn snapshots_list_newest_first_with_their_counts() {
        let project = project();
        let target = target(&project);
        project
            .findings()
            .record(&finding(target, "One", Severity::Low))
            .unwrap();
        let first = take(&project, "day 1", "0.1.0");
        project
            .findings()
            .record(&finding(target, "Two", Severity::High))
            .unwrap();
        let second = take(&project, "day 2", "0.1.0");

        let listed = project.snapshots().list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, second.id);
        assert_eq!(listed[0].findings, 2);
        assert_eq!(listed[1].id, first.id);
        assert_eq!(listed[1].findings, 1);
        assert_eq!(project.snapshots().latest().unwrap().unwrap().id, second.id);
    }

    #[test]
    fn a_retest_that_no_longer_produces_a_claim_reads_as_not_reproduced() {
        let project = project();
        let target = target(&project);
        let gone = finding(target, "IDOR in GET /accounts/{id}", Severity::High);
        let stays = finding(target, "IDOR in GET /invoices/{id}", Severity::Medium);
        project.findings().record(&gone).unwrap();
        project.findings().record(&stays).unwrap();
        let before = take(&project, "before the fix", "0.1.0");

        // The client fixed one endpoint. The matrix still runs, and still reports the
        // other, which is what makes the disappearance mean anything at all.
        project.findings().delete(gone.id).unwrap();
        let after = take(&project, "retest", "0.1.0");

        let comparison = compare(&before, &after);
        let change = comparison
            .findings
            .iter()
            .find(|c| c.claim.title == "IDOR in GET /accounts/{id}")
            .unwrap();
        assert!(
            matches!(
                change.change,
                Change::Gone {
                    because: WhyGone::NotReproduced,
                    ..
                }
            ),
            "{:?}",
            change.change
        );
    }

    #[test]
    fn a_deleted_snapshot_is_gone_and_the_others_are_not() {
        let project = project();
        let first = take(&project, "day 1", "0.1.0");
        let second = take(&project, "day 2", "0.1.0");

        assert!(project.snapshots().delete(first.id).unwrap());
        assert!(!project.snapshots().delete(first.id).unwrap());
        assert_eq!(project.snapshots().count().unwrap(), 1);
        assert!(project.snapshots().get(second.id).is_ok());
    }

    #[test]
    fn asking_for_a_snapshot_that_is_not_there_says_so() {
        let project = project();
        let error = project.snapshots().get(SnapshotId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error:?}");
    }

    #[test]
    fn every_finding_is_captured_even_past_one_page() {
        // A snapshot holding only the first page would report everything beyond it as
        // having appeared or vanished on the next comparison.
        let project = project();
        let target = target(&project);
        for index in 0..(Limit::MAX + 5) {
            project
                .findings()
                .record(&finding(target, &format!("Claim {index}"), Severity::Low))
                .unwrap();
        }
        let contents = capture(&project).unwrap();
        assert_eq!(contents.findings.len() as u32, Limit::MAX + 5);
    }
}
