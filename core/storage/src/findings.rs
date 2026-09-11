//! Persisting findings.
//!
//! A finding that exists only in a terminal is not evidence. The point of a Hexora
//! project is that six months later somebody can open it, read a claim, and follow it
//! back to the exact exchanges that support it — which requires the claim to be in the
//! project alongside the traffic, not in a scrollback buffer.
//!
//! # The door is a type, not a check
//!
//! [`FindingStore::save`] and [`FindingStore::record`] take a
//! [`Verified`](hexora_types::verify::Verified), which is the only thing a
//! [`Verification`](hexora_types::verify::Verification) can produce. A detector emits
//! a [`Hypothesis`](hexora_types::finding::Hypothesis), and there is no path from one
//! to the other — so a check that is merely suspicious cannot reach a report by
//! taking the storage route around the verification engine. It is not that the store
//! refuses it; it is that the call does not compile.
//!
//! That is security invariant 6, moved from a runtime check into the type system.
//! `Finding::validate` still runs inside `Verified::conclude`, as the backstop for a
//! verifier that returned support with nothing behind it.
//!
//! # Re-running a test does not pile up duplicates
//!
//! Authorization matrices get run repeatedly — after a fix, after a deploy, on the
//! next engagement day. [`FindingStore::record`] therefore keys a finding on what it
//! *claims* (its target, title and location) rather than on its generated id, and a
//! second run updates the existing row instead of adding a near-identical one.
//!
//! Two consequences are deliberate:
//!
//! * **Triage survives.** A finding marked `false_positive` stays marked. Resurrecting
//!   it as `new` on every run would teach testers to ignore the list, which is the
//!   only thing a findings list must never become.
//! * **Confidence follows the evidence currently attached, in both directions.** A row
//!   updated by a run that did not reproduce the result comes back down to
//!   `Tentative`, because the evidence now stored is what that run produced. A
//!   `Confirmed` finding citing an unverified comparison would be exactly the
//!   dishonesty the model exists to prevent.

use hexora_types::finding::{
    Confidence, Evidence, Finding, FindingSource, FindingStatus, Location, Severity,
};
use hexora_types::ids::{FindingId, TargetId};
use hexora_types::verify::Verified;
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StorageError};
use crate::repository::{Cursor, Limit, Page};
use crate::MetadataDb;

/// What [`FindingStore::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// The claim was not in the project; a new finding was written.
    Created(FindingId),
    /// The same claim was already recorded; its evidence was refreshed and its triage
    /// status left alone.
    Updated(FindingId),
}

impl Recorded {
    /// The finding's id, however it got there.
    pub fn id(&self) -> FindingId {
        match self {
            Self::Created(id) | Self::Updated(id) => *id,
        }
    }

    /// Whether this run produced a claim the project had not seen before.
    pub fn is_new(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Which findings to return.
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    /// Only findings at or above this severity.
    pub min_severity: Option<Severity>,
    /// Only findings in this triage state.
    pub status: Option<FindingStatus>,
    /// Only findings about this target.
    pub target: Option<TargetId>,
    /// Only findings that may be presented as real issues rather than leads.
    pub actionable_only: bool,
}

/// Reads and writes a project's findings.
#[derive(Debug, Clone)]
pub struct FindingStore {
    db: MetadataDb,
}

impl FindingStore {
    /// Opens the finding store over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// Writes a verified finding.
    ///
    /// Always inserts. Callers that re-run a test want [`Self::record`].
    ///
    /// Takes a [`Verified`] rather than a [`Finding`]: see the module documentation.
    pub fn save(&self, verified: &Verified) -> Result<()> {
        let finding = verified.finding();
        self.write(finding, finding.id, false)
    }

    /// Writes a verified finding, or refreshes the one already recording the same
    /// claim.
    ///
    /// See the module documentation for what "the same claim" means and what survives
    /// an update.
    pub fn record(&self, verified: &Verified) -> Result<Recorded> {
        let finding = verified.finding();
        match self.find_matching(finding)? {
            None => {
                self.save(verified)?;
                Ok(Recorded::Created(finding.id))
            }
            Some(existing) => {
                self.write(finding, existing, true)?;
                Ok(Recorded::Updated(existing))
            }
        }
    }

    /// One finding by id.
    pub fn get(&self, id: FindingId) -> Result<Finding> {
        let conn = self.db.connection()?;
        let row = conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM findings WHERE id = ?1"),
                params![id.to_string()],
                decode_row,
            )
            .optional()?;

        let finding = row.ok_or_else(|| StorageError::NotFound {
            entity: "finding",
            id: id.to_string(),
        })??;
        with_evidence(&conn, finding)
    }

    /// Pages through findings, most severe first.
    ///
    /// Ordered by severity, then confidence, then id — the order a tester triages in,
    /// rather than the order the detectors happened to run in. Paging is on that same
    /// ordering, so a page boundary does not reshuffle rows underneath a reader.
    pub fn list(
        &self,
        filter: &FindingFilter,
        after: Option<&Cursor>,
        limit: Limit,
    ) -> Result<Page<Finding>> {
        let conn = self.db.connection()?;

        // Severity and confidence are stored as words, so ordering has to be by their
        // rank rather than alphabetically — "critical" sorts before "high" by luck and
        // "info" before "low" by accident, and neither is a property to rely on.
        let sql = format!(
            "SELECT {COLUMNS}, {SEVERITY_RANK} AS sev, {CONFIDENCE_RANK} AS conf
             FROM findings
             WHERE (?1 IS NULL OR {SEVERITY_RANK} <= ?1)
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR target_id = ?3)
               AND (?4 = 0 OR confidence IN ('firm', 'confirmed'))
               AND (?5 IS NULL OR (
                    printf('%d|%d|%s', {SEVERITY_RANK}, {CONFIDENCE_RANK}, id) > ?5))
             ORDER BY sev ASC, conf ASC, id ASC
             LIMIT ?6"
        );

        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                filter.min_severity.map(|s| s.rank() as i64),
                filter.status.map(status_str),
                filter.target.map(|t| t.to_string()),
                filter.actionable_only as i64,
                after.map(|c| c.0.clone()),
                limit.get() + 1,
            ],
            decode_row,
        )?;

        // Collected before any evidence is loaded. Reading it inside the loop would
        // hold this statement's connection while asking the pool for another, which
        // deadlocks the moment the pool has one connection — as it does for every
        // in-memory project.
        let mut items = Vec::new();
        for row in rows {
            items.push(row??);
        }
        drop(statement);

        for finding in &mut items {
            *finding = with_evidence(&conn, std::mem::replace(finding, placeholder()))?;
        }

        let next = if items.len() > limit.get() as usize {
            items.truncate(limit.get() as usize);
            items.last().map(cursor_for)
        } else {
            None
        };

        Ok(Page { items, next })
    }

    /// Changes a finding's triage state.
    ///
    /// Triage is a human judgement about a claim, so it is the one field a detector
    /// re-run never touches and the only one exposed for editing on its own.
    pub fn set_status(&self, id: FindingId, status: FindingStatus) -> Result<()> {
        let conn = self.db.connection()?;
        let updated = conn.execute(
            "UPDATE findings SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), status_str(status), crate::traffic::now()],
        )?;

        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "finding",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    /// How many findings the project holds.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 = conn.query_row("SELECT count(*) FROM findings", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Removes a finding and its evidence. Reports whether a row was removed.
    pub fn delete(&self, id: FindingId) -> Result<bool> {
        let conn = self.db.connection()?;
        // `finding_evidence` cascades on delete, so the evidence goes with it.
        let affected = conn.execute(
            "DELETE FROM findings WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(affected > 0)
    }

    /// The id of a finding already recording this claim, if there is one.
    fn find_matching(&self, finding: &Finding) -> Result<Option<FindingId>> {
        let conn = self.db.connection()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM findings
                 WHERE target_id = ?1 AND title = ?2
                   AND ifnull(location_json, '') = ifnull(?3, '')
                 ORDER BY id LIMIT 1",
                params![
                    finding.target.to_string(),
                    finding.title,
                    location_json(finding.location.as_ref())?,
                ],
                |row| row.get(0),
            )
            .optional()?;

        existing
            .map(|id| {
                id.parse().map_err(|e| StorageError::Decode {
                    entity: "FindingId",
                    reason: format!("{e}"),
                })
            })
            .transpose()
    }

    /// Writes a finding under `id`, replacing any row already there.
    ///
    /// `preserve_triage` keeps the stored status and creation time, which is what
    /// makes a re-run an update rather than a reset.
    fn write(&self, finding: &Finding, id: FindingId, preserve_triage: bool) -> Result<()> {
        finding
            .validate()
            .map_err(|problems| StorageError::Decode {
                entity: "Finding",
                reason: problems.join("; "),
            })?;

        let location = location_json(finding.location.as_ref())?;
        let source = serde_json::to_string(&finding.source).map_err(|e| StorageError::Decode {
            entity: "FindingSource",
            reason: e.to_string(),
        })?;

        let mut conn = self.db.connection()?;
        // One transaction: a finding whose evidence half-wrote would be a claim with
        // nothing behind it, which is the state this whole crate exists to prevent.
        let tx = conn.transaction()?;

        let now = crate::traffic::now();
        let (status, created_at) = if preserve_triage {
            tx.query_row(
                "SELECT status, created_at FROM findings WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
        } else {
            (
                status_str(finding.status).to_string(),
                finding.created_at.to_rfc3339(),
            )
        };

        tx.execute(
            "INSERT INTO findings
                (id, target_id, title, severity, confidence, status, location_json,
                 description, impact, remediation, reproduction, cwe, owasp, cvss,
                 source_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                severity = excluded.severity,
                confidence = excluded.confidence,
                location_json = excluded.location_json,
                description = excluded.description,
                impact = excluded.impact,
                remediation = excluded.remediation,
                reproduction = excluded.reproduction,
                cwe = excluded.cwe,
                owasp = excluded.owasp,
                cvss = excluded.cvss,
                source_json = excluded.source_json,
                updated_at = excluded.updated_at",
            params![
                id.to_string(),
                finding.target.to_string(),
                finding.title,
                severity_str(finding.severity),
                confidence_str(finding.confidence),
                status,
                location,
                finding.description,
                finding.impact,
                finding.remediation,
                finding.reproduction,
                finding.cwe,
                finding.owasp,
                finding.cvss,
                source,
                created_at,
                now,
            ],
        )?;

        // Evidence is replaced rather than appended: what is stored has to be the
        // evidence behind the confidence in the same row, and a decade of accumulated
        // comparisons from nightly re-runs is not that.
        tx.execute(
            "DELETE FROM finding_evidence WHERE finding_id = ?1",
            params![id.to_string()],
        )?;
        for (ordinal, evidence) in finding.evidence.iter().enumerate() {
            let json = serde_json::to_string(evidence).map_err(|e| StorageError::Decode {
                entity: "Evidence",
                reason: e.to_string(),
            })?;
            tx.execute(
                "INSERT INTO finding_evidence (finding_id, ordinal, evidence_json)
                 VALUES (?1, ?2, ?3)",
                params![id.to_string(), ordinal as i64, json],
            )?;
        }

        tx.commit()?;
        Ok(())
    }
}

/// Attaches a finding's evidence rows, in the order they were recorded.
///
/// Takes the caller's connection rather than borrowing another from the pool: a
/// project opened in memory has exactly one, and asking for a second while holding the
/// first is a deadlock rather than a slow query.
fn with_evidence(conn: &rusqlite::Connection, mut finding: Finding) -> Result<Finding> {
    let mut statement = conn.prepare(
        "SELECT evidence_json FROM finding_evidence
         WHERE finding_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map(params![finding.id.to_string()], |row| {
        row.get::<_, String>(0)
    })?;

    let mut evidence = Vec::new();
    for row in rows {
        let json = row?;
        evidence.push(serde_json::from_str::<Evidence>(&json).map_err(|e| {
            StorageError::Decode {
                entity: "Evidence",
                reason: e.to_string(),
            }
        })?);
    }
    finding.evidence = evidence;
    Ok(finding)
}

/// A stand-in used only while swapping a row out of the page to fill in its evidence.
///
/// Never observable: every placeholder is replaced in the same statement that made it.
fn placeholder() -> Finding {
    Finding {
        id: FindingId::new(),
        target: TargetId::new(),
        title: String::new(),
        severity: Severity::Info,
        confidence: Confidence::Reported,
        location: None,
        description: String::new(),
        impact: String::new(),
        remediation: String::new(),
        reproduction: String::new(),
        evidence: Vec::new(),
        cwe: None,
        owasp: None,
        cvss: None,
        source: FindingSource::Manual,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        status: FindingStatus::New,
    }
}

impl crate::repository::FindingStore for FindingStore {
    fn save(&self, verified: &Verified) -> Result<()> {
        Self::save(self, verified)
    }

    fn get(&self, id: FindingId) -> Result<Finding> {
        Self::get(self, id)
    }

    fn list(&self, target: TargetId) -> Result<Vec<Finding>> {
        let filter = FindingFilter {
            target: Some(target),
            ..Default::default()
        };
        Ok(Self::list(self, &filter, None, Limit::new(Limit::MAX))?.items)
    }
}

/// The columns [`decode_row`] expects, in order.
const COLUMNS: &str = "id, target_id, title, severity, confidence, status, location_json,
     description, impact, remediation, reproduction, cwe, owasp, cvss, source_json,
     created_at, updated_at";

/// Severity as a sortable rank, worst first. Mirrors [`Severity::rank`].
const SEVERITY_RANK: &str = "(CASE severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
        WHEN 'low' THEN 3 ELSE 4 END)";

/// Confidence as a sortable rank, firmest first.
const CONFIDENCE_RANK: &str = "(CASE confidence
        WHEN 'confirmed' THEN 0 WHEN 'firm' THEN 1 WHEN 'tentative' THEN 2
        ELSE 3 END)";

/// The keyset cursor for a row: its exact position in the list ordering.
fn cursor_for(finding: &Finding) -> Cursor {
    Cursor(format!(
        "{}|{}|{}",
        finding.severity.rank(),
        confidence_rank(finding.confidence),
        finding.id
    ))
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Confirmed => 0,
        Confidence::Firm => 1,
        Confidence::Tentative => 2,
        Confidence::Reported => 3,
    }
}

/// Builds a `Finding` from a row, less its evidence.
///
/// The `rusqlite` closure can only return `rusqlite::Error`, and the domain decoding
/// here fails in other ways, so the result is nested and unwrapped by the caller.
#[allow(clippy::type_complexity)]
fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Finding>> {
    let id: String = row.get(0)?;
    let target: String = row.get(1)?;
    let severity: String = row.get(3)?;
    let confidence: String = row.get(4)?;
    let status: String = row.get(5)?;
    let location: Option<String> = row.get(6)?;
    let source: String = row.get(14)?;
    let created_at: String = row.get(15)?;
    let updated_at: String = row.get(16)?;

    Ok(build(FindingRow {
        id,
        target,
        title: row.get(2)?,
        severity,
        confidence,
        status,
        location,
        description: row.get(7)?,
        impact: row.get(8)?,
        remediation: row.get(9)?,
        reproduction: row.get(10)?,
        cwe: row.get(11)?,
        owasp: row.get(12)?,
        cvss: row.get(13)?,
        source,
        created_at,
        updated_at,
    }))
}

/// A `findings` row, before it becomes a domain type.
struct FindingRow {
    id: String,
    target: String,
    title: String,
    severity: String,
    confidence: String,
    status: String,
    location: Option<String>,
    description: String,
    impact: String,
    remediation: String,
    reproduction: String,
    cwe: Option<String>,
    owasp: Option<String>,
    cvss: Option<String>,
    source: String,
    created_at: String,
    updated_at: String,
}

fn build(row: FindingRow) -> Result<Finding> {
    let location = match row.location {
        None => None,
        Some(json) => {
            Some(
                serde_json::from_str::<Location>(&json).map_err(|e| StorageError::Decode {
                    entity: "Location",
                    reason: e.to_string(),
                })?,
            )
        }
    };
    let source =
        serde_json::from_str::<FindingSource>(&row.source).map_err(|e| StorageError::Decode {
            entity: "FindingSource",
            reason: e.to_string(),
        })?;

    Ok(Finding {
        id: parse_id(&row.id)?,
        target: parse_target(&row.target)?,
        title: row.title,
        severity: parse_severity(&row.severity)?,
        confidence: parse_confidence(&row.confidence)?,
        status: parse_status(&row.status)?,
        location,
        description: row.description,
        impact: row.impact,
        remediation: row.remediation,
        reproduction: row.reproduction,
        // Filled in by `with_evidence`: it is a separate table, and a finding read
        // back without it would silently be a claim with nothing behind it.
        evidence: Vec::new(),
        cwe: row.cwe,
        owasp: row.owasp,
        cvss: row.cvss,
        source,
        created_at: parse_time(&row.created_at)?,
        updated_at: parse_time(&row.updated_at)?,
    })
}

fn location_json(location: Option<&Location>) -> Result<Option<String>> {
    location
        .map(|location| {
            serde_json::to_string(location).map_err(|e| StorageError::Decode {
                entity: "Location",
                reason: e.to_string(),
            })
        })
        .transpose()
}

fn parse_id(value: &str) -> Result<FindingId> {
    value.parse().map_err(|e| StorageError::Decode {
        entity: "FindingId",
        reason: format!("{e}"),
    })
}

fn parse_target(value: &str) -> Result<TargetId> {
    value.parse().map_err(|e| StorageError::Decode {
        entity: "TargetId",
        reason: format!("{e}"),
    })
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| StorageError::Decode {
            entity: "timestamp",
            reason: format!("{value:?}: {e}"),
        })
}

/// The stored word for a severity. Must match the `CHECK` constraint in migration 1.
pub fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// The stored word for a confidence level.
pub fn confidence_str(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Reported => "reported",
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Confirmed => "confirmed",
    }
}

/// The stored word for a triage status.
pub fn status_str(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::Triaged => "triaged",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false_positive",
        FindingStatus::Duplicate => "duplicate",
        FindingStatus::Reported => "reported",
        FindingStatus::Fixed => "fixed",
        FindingStatus::Accepted => "accepted",
    }
}

/// Parses a severity written by [`severity_str`].
pub fn parse_severity(value: &str) -> Result<Severity> {
    match value {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(StorageError::Decode {
            entity: "Severity",
            reason: format!("unknown severity {other:?}"),
        }),
    }
}

/// Parses a confidence level written by [`confidence_str`].
pub fn parse_confidence(value: &str) -> Result<Confidence> {
    match value {
        "reported" => Ok(Confidence::Reported),
        "tentative" => Ok(Confidence::Tentative),
        "firm" => Ok(Confidence::Firm),
        "confirmed" => Ok(Confidence::Confirmed),
        other => Err(StorageError::Decode {
            entity: "Confidence",
            reason: format!("unknown confidence {other:?}"),
        }),
    }
}

/// Parses a triage status written by [`status_str`].
pub fn parse_status(value: &str) -> Result<FindingStatus> {
    match value {
        "new" => Ok(FindingStatus::New),
        "triaged" => Ok(FindingStatus::Triaged),
        "confirmed" => Ok(FindingStatus::Confirmed),
        "false_positive" => Ok(FindingStatus::FalsePositive),
        "duplicate" => Ok(FindingStatus::Duplicate),
        "reported" => Ok(FindingStatus::Reported),
        "fixed" => Ok(FindingStatus::Fixed),
        "accepted" => Ok(FindingStatus::Accepted),
        other => Err(StorageError::Decode {
            entity: "FindingStatus",
            reason: format!("unknown status {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::finding::MessagePart;
    use hexora_types::ids::RequestId;

    use super::*;

    /// A store over a project that has one target, so the foreign key can be met.
    fn store() -> (FindingStore, TargetId) {
        let db = MetadataDb::in_memory().unwrap();
        let traffic = crate::TrafficStore::new(
            db.clone(),
            std::sync::Arc::new(crate::MemoryBlobStore::new()),
        );
        let target = traffic.upsert_target("example.com", 443, true).unwrap();
        (FindingStore::new(db), target)
    }

    /// Wraps a finding the way a verification would, without staging one.
    ///
    /// These tests are about the *store* — ordering, paging, triage, the claim key —
    /// not about the verification ladder, which is tested where it lives. The feature
    /// this uses is off in every shipped binary.
    fn verified(finding: Finding) -> hexora_types::verify::Verified {
        hexora_types::verify::Verified::from_trusted_finding(finding)
    }

    fn finding(target: TargetId, severity: Severity, confidence: Confidence) -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: FindingId::new(),
            target,
            title: "Broken object-level authorization in GET /accounts/{id}".into(),
            severity,
            confidence,
            location: Some(Location {
                part: MessagePart::Path,
                name: "/accounts/acct-1000".into(),
            }),
            description: "User B received User A's account.".into(),
            impact: "One user can read another's records.".into(),
            remediation: "Scope the lookup to the session.".into(),
            reproduction: "Send as A, send as B, compare.".into(),
            evidence: vec![Evidence::Comparison {
                baseline: RequestId::new(),
                variant: RequestId::new(),
                difference: "User B received acct-1000".into(),
            }],
            cwe: Some("CWE-639".into()),
            owasp: Some("API1:2023 Broken Object Level Authorization".into()),
            cvss: None,
            source: FindingSource::AuthorizationTest,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        }
    }

    fn all(store: &FindingStore) -> Vec<Finding> {
        store
            .list(&FindingFilter::default(), None, Limit::new(100))
            .unwrap()
            .items
    }

    #[test]
    fn a_finding_survives_a_round_trip_with_its_evidence() {
        let (store, target) = store();
        let finding = finding(target, Severity::High, Confidence::Firm);
        store.save(&verified(finding.clone())).unwrap();

        let read = store.get(finding.id).unwrap();
        assert_eq!(read.title, finding.title);
        assert_eq!(read.severity, Severity::High);
        assert_eq!(read.confidence, Confidence::Firm);
        assert_eq!(read.evidence, finding.evidence);
        assert_eq!(read.cwe.as_deref(), Some("CWE-639"));
        assert_eq!(read.location.unwrap().name, "/accounts/acct-1000");
        assert!(matches!(read.source, FindingSource::AuthorizationTest));
    }

    #[test]
    fn a_finding_with_no_evidence_has_no_way_to_reach_the_store() {
        // Invariant 6 used to be enforced here, at the last moment, by validate().
        // It is now enforced one step earlier and one level up: an evidence-free
        // claim cannot be turned into a `Verified` at all, and `Verified` is the only
        // thing `save` accepts. The runtime check below is the backstop, still wired
        // up, for a finding assembled some other way.
        let (store, target) = store();
        let mut invalid = finding(target, Severity::High, Confidence::Firm);
        invalid.evidence.clear();

        let hypothesis = hexora_types::finding::Hypothesis {
            detector: "test".into(),
            claim: "something".into(),
            source_request: RequestId::new(),
            location: None,
            provisional_severity: Severity::High,
        };
        let empty = hexora_types::verify::Verification::Supported {
            support: hexora_types::verify::Support::Distinctive,
            note: "nothing behind it".into(),
            evidence: Vec::new(),
        };
        assert!(
            hexora_types::verify::Verified::conclude(&hypothesis, &empty, writeup_for(&invalid))
                .is_none(),
            "a claim with no evidence must not become a Verified"
        );

        let error = store.save(&verified(invalid)).unwrap_err();
        assert!(error.to_string().contains("evidence"), "{error}");
        assert_eq!(store.count().unwrap(), 0);
    }

    fn writeup_for(finding: &Finding) -> hexora_types::verify::Writeup {
        hexora_types::verify::Writeup {
            target: finding.target,
            title: finding.title.clone(),
            description: finding.description.clone(),
            impact: finding.impact.clone(),
            remediation: finding.remediation.clone(),
            reproduction: finding.reproduction.clone(),
            cwe: finding.cwe.clone(),
            owasp: finding.owasp.clone(),
            source: finding.source.clone(),
            severity: finding.severity,
            location: finding.location.clone(),
        }
    }

    #[test]
    fn every_severity_and_confidence_word_round_trips() {
        let (store, target) = store();
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            for confidence in [
                Confidence::Tentative,
                Confidence::Firm,
                Confidence::Confirmed,
            ] {
                let mut f = finding(target, severity, confidence);
                f.title = format!("{severity:?}/{confidence:?}");
                store.save(&verified(f.clone())).unwrap();
                let read = store.get(f.id).unwrap();
                assert_eq!(read.severity, severity);
                assert_eq!(read.confidence, confidence);
            }
        }
    }

    #[test]
    fn every_triage_status_round_trips() {
        let (store, target) = store();
        let f = finding(target, Severity::Low, Confidence::Tentative);
        store.save(&verified(f.clone())).unwrap();

        for status in [
            FindingStatus::New,
            FindingStatus::Triaged,
            FindingStatus::Confirmed,
            FindingStatus::FalsePositive,
            FindingStatus::Duplicate,
            FindingStatus::Reported,
            FindingStatus::Fixed,
            FindingStatus::Accepted,
        ] {
            store.set_status(f.id, status).unwrap();
            assert_eq!(store.get(f.id).unwrap().status, status);
        }
    }

    #[test]
    fn re_running_a_test_updates_the_claim_instead_of_duplicating_it() {
        let (store, target) = store();
        let first = finding(target, Severity::Medium, Confidence::Tentative);
        assert!(store.record(&verified(first.clone())).unwrap().is_new());

        // A second run: new ids, same claim.
        let mut second = finding(target, Severity::High, Confidence::Confirmed);
        let outcome = store.record(&verified(second.clone())).unwrap();
        assert_eq!(outcome, Recorded::Updated(first.id));
        assert_eq!(store.count().unwrap(), 1);

        let read = store.get(first.id).unwrap();
        assert_eq!(read.confidence, Confidence::Confirmed);
        assert_eq!(read.severity, Severity::High);
        second.id = first.id;
        assert_eq!(
            read.evidence, second.evidence,
            "evidence is the newest run's"
        );
    }

    #[test]
    fn a_re_run_never_resurrects_a_triaged_finding() {
        let (store, target) = store();
        let first = finding(target, Severity::Medium, Confidence::Tentative);
        store.record(&verified(first.clone())).unwrap();
        store
            .set_status(first.id, FindingStatus::FalsePositive)
            .unwrap();

        store
            .record(&verified(finding(
                target,
                Severity::Medium,
                Confidence::Tentative,
            )))
            .unwrap();

        assert_eq!(
            store.get(first.id).unwrap().status,
            FindingStatus::FalsePositive,
            "a list that keeps un-dismissing dismissed findings is a list nobody reads"
        );
    }

    #[test]
    fn a_re_run_that_did_not_reproduce_lowers_the_confidence_it_can_no_longer_support() {
        let (store, target) = store();
        let confirmed = finding(target, Severity::High, Confidence::Confirmed);
        store.record(&verified(confirmed.clone())).unwrap();

        store
            .record(&verified(finding(
                target,
                Severity::High,
                Confidence::Tentative,
            )))
            .unwrap();

        assert_eq!(
            store.get(confirmed.id).unwrap().confidence,
            Confidence::Tentative,
            "the stored evidence is the last run's, and the confidence has to match it"
        );
    }

    #[test]
    fn a_different_claim_about_the_same_target_is_its_own_finding() {
        let (store, target) = store();
        let first = finding(target, Severity::Medium, Confidence::Tentative);
        let mut other = finding(target, Severity::Medium, Confidence::Tentative);
        other.location = Some(Location {
            part: MessagePart::Path,
            name: "/accounts/acct-2000".into(),
        });

        store.record(&verified(first.clone())).unwrap();
        assert!(store.record(&verified(other.clone())).unwrap().is_new());
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn findings_are_listed_worst_first() {
        let (store, target) = store();
        for (severity, confidence, title) in [
            (Severity::Low, Confidence::Firm, "low"),
            (Severity::Critical, Confidence::Tentative, "critical"),
            (Severity::High, Confidence::Tentative, "high tentative"),
            (Severity::High, Confidence::Confirmed, "high confirmed"),
        ] {
            let mut f = finding(target, severity, confidence);
            f.title = title.into();
            store.save(&verified(f.clone())).unwrap();
        }

        let titles: Vec<_> = all(&store).into_iter().map(|f| f.title).collect();
        assert_eq!(
            titles,
            ["critical", "high confirmed", "high tentative", "low"],
            "severity first, then how firmly it is established"
        );
    }

    #[test]
    fn listing_pages_without_repeating_or_skipping_a_row() {
        let (store, target) = store();
        for i in 0..7 {
            let mut f = finding(target, Severity::High, Confidence::Firm);
            f.title = format!("finding {i}");
            store.save(&verified(f.clone())).unwrap();
        }

        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = store
                .list(&FindingFilter::default(), cursor.as_ref(), Limit::new(3))
                .unwrap();
            seen.extend(page.items.iter().map(|f| f.id));
            match page.next {
                None => break,
                Some(next) => cursor = Some(next),
            }
        }

        assert_eq!(seen.len(), 7);
        let unique: std::collections::BTreeSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), 7, "a page boundary must not repeat a row");
    }

    #[test]
    fn filtering_by_severity_returns_everything_at_least_that_bad() {
        let (store, target) = store();
        for (severity, title) in [
            (Severity::Info, "info"),
            (Severity::Medium, "medium"),
            (Severity::Critical, "critical"),
        ] {
            let mut f = finding(target, severity, Confidence::Firm);
            f.title = title.into();
            store.save(&verified(f.clone())).unwrap();
        }

        let filter = FindingFilter {
            min_severity: Some(Severity::Medium),
            ..Default::default()
        };
        let titles: Vec<_> = store
            .list(&filter, None, Limit::new(10))
            .unwrap()
            .items
            .into_iter()
            .map(|f| f.title)
            .collect();
        assert_eq!(titles, ["critical", "medium"]);
    }

    #[test]
    fn filtering_to_actionable_hides_the_leads() {
        let (store, target) = store();
        let mut lead = finding(target, Severity::High, Confidence::Tentative);
        lead.title = "a lead".into();
        store.save(&verified(lead.clone())).unwrap();
        let mut real = finding(target, Severity::High, Confidence::Firm);
        real.title = "established".into();
        store.save(&verified(real.clone())).unwrap();

        let filter = FindingFilter {
            actionable_only: true,
            ..Default::default()
        };
        let items = store.list(&filter, None, Limit::new(10)).unwrap().items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "established");
    }

    #[test]
    fn filtering_by_status_finds_what_triage_left_behind() {
        let (store, target) = store();
        let f = finding(target, Severity::High, Confidence::Firm);
        store.save(&verified(f.clone())).unwrap();
        store
            .set_status(f.id, FindingStatus::FalsePositive)
            .unwrap();

        let filter = FindingFilter {
            status: Some(FindingStatus::FalsePositive),
            ..Default::default()
        };
        assert_eq!(
            store
                .list(&filter, None, Limit::new(10))
                .unwrap()
                .items
                .len(),
            1
        );

        let filter = FindingFilter {
            status: Some(FindingStatus::New),
            ..Default::default()
        };
        assert!(store
            .list(&filter, None, Limit::new(10))
            .unwrap()
            .items
            .is_empty());
    }

    #[test]
    fn a_missing_finding_is_not_found_rather_than_empty() {
        let (store, _) = store();
        let error = store.get(FindingId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");
        assert!(matches!(
            store.set_status(FindingId::new(), FindingStatus::Fixed),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn deleting_takes_the_evidence_with_it() {
        let (store, target) = store();
        let f = finding(target, Severity::High, Confidence::Firm);
        store.save(&verified(f.clone())).unwrap();

        assert!(store.delete(f.id).unwrap());
        assert!(!store.delete(f.id).unwrap());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn evidence_keeps_the_order_it_was_recorded_in() {
        let (store, target) = store();
        let mut f = finding(target, Severity::High, Confidence::Firm);
        f.evidence.push(Evidence::Exchange {
            request: RequestId::new(),
            response: None,
            note: "second".into(),
        });
        f.evidence.push(Evidence::ResponseExcerpt {
            response: hexora_types::ids::ResponseId::new(),
            offset: 12,
            excerpt: "third".into(),
        });
        store.save(&verified(f.clone())).unwrap();

        assert_eq!(store.get(f.id).unwrap().evidence, f.evidence);
    }

    #[test]
    fn a_finding_about_an_unknown_target_is_refused_by_the_database() {
        let (store, _) = store();
        let orphan = finding(TargetId::new(), Severity::High, Confidence::Firm);
        assert!(
            store.save(&verified(orphan.clone())).is_err(),
            "evidence has to point at a target the project knows about"
        );
    }
}
