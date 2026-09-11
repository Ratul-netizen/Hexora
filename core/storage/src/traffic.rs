//! The SQLite traffic store.
//!
//! Where captured exchanges finally land. Metadata goes to the relational database,
//! bodies to the content-addressed blob store, exactly as [`crate`] describes — an
//! engagement can capture millions of exchanges, and a database that is also the blob
//! repository degrades badly at that size.
//!
//! # Both forms of every body
//!
//! A response is stored twice over: as it arrived on the wire, and as it reads after
//! `Content-Encoding` was reversed. That sounds wasteful and is not, because both are
//! content-addressed — for an uncompressed response the two hashes are equal and the
//! blob is stored once.
//!
//! It matters because a finding about a compression side channel, a decompression
//! bomb, or a gzip parser differential is a finding about the *encoded* bytes. Keeping
//! only the decoded form would make that evidence unexaminable and the exchange
//! unreplayable.
//!
//! # Blocking
//!
//! Synchronous, because SQLite is. The proxy calls it from a blocking pool.

use std::sync::Arc;

use hexora_types::http::{HttpRequest, HttpResponse};
use hexora_types::ids::{RequestId, ResponseId, TargetId};
use hexora_types::tls::TlsInfo;
use rusqlite::{params, OptionalExtension};

use crate::blob::{BlobRef, BlobStore};
use crate::error::{Result, StorageError};
use crate::repository::{Cursor, Limit, Page};
use crate::MetadataDb;

/// One captured exchange, ready to store.
#[derive(Debug, Clone)]
pub struct CapturedExchange {
    /// The request as it was sent.
    ///
    /// For a raw send this is a best-effort reading of [`Self::raw_request`], kept so
    /// the history table has a method and a URL to show. It is never what goes back
    /// on the wire.
    pub request: HttpRequest,
    /// The exact bytes written, when the request was sent raw.
    ///
    /// `None` for a structured send, where re-serializing the model reproduces what
    /// went out. `Some` is what makes a raw request re-sendable byte for byte a month
    /// later — the whole reason raw mode exists.
    pub raw_request: Option<bytes::Bytes>,
    /// The response as it was received, already decoded.
    pub response: HttpResponse,
    /// The response body exactly as it arrived, before content decoding.
    ///
    /// `None` when no content coding was applied, in which case the decoded body
    /// already is the wire form.
    pub encoded_body: Option<bytes::Bytes>,
    /// The `Content-Encoding` that was reversed, if any.
    pub content_encoding: Option<String>,
    /// Which subsystem produced the request.
    pub origin: &'static str,
    /// The identity the request was sent as, when one was chosen deliberately.
    ///
    /// Set by the authorization subsystem, which cannot produce evidence without it:
    /// "this response reached User B" is only a claim if the row says which principal
    /// sent the request. `None` for proxy traffic, where the credential is whatever
    /// the browser already had.
    pub identity: Option<hexora_types::ids::IdentityId>,
    /// The request this one was derived from, for repeater branching.
    ///
    /// A variant that keeps its parent is what makes "which edit caused the change?"
    /// answerable weeks later, when the tab it was edited in is long gone.
    pub parent: Option<RequestId>,
    /// Framing anomalies observed, as quirk names.
    pub quirks: Vec<String>,
    /// What the TLS handshake produced, for `https` exchanges.
    pub tls: Option<TlsInfo>,
    /// Round-trip time in milliseconds.
    pub duration_ms: u32,
}

/// A stored exchange, as read back.
#[derive(Debug, Clone)]
pub struct StoredTraffic {
    /// The request's identifier, and the handle for fetching its bodies.
    pub id: RequestId,
    /// The host and port it was sent to.
    pub target: TargetId,
    /// The request method, exactly as sent.
    pub method: String,
    /// The absolute URL that was requested.
    pub url: String,
    /// The response status, or `None` if no response was received.
    pub status: Option<u16>,
    /// Decoded response body size in bytes.
    pub response_bytes: u64,
    /// Round-trip time in milliseconds, where it was measured.
    pub duration_ms: Option<u32>,
    /// When the request was sent, RFC 3339.
    pub sent_at: String,
    /// Framing anomalies recorded for this exchange.
    pub quirks: Vec<String>,
    /// Whether the connection was TLS.
    pub secure: bool,
    /// The label of the identity the request was sent as, when it was sent as one.
    ///
    /// The label rather than the id: history is read by people, and an authorization
    /// replay whose row says only `idn_01a08c…` cannot be checked at a glance against
    /// the claim a finding makes about it.
    pub identity: Option<String>,
    /// How the request reached the socket.
    ///
    /// In the index rather than only in the detail: a row that was sent byte for byte
    /// may not mean what its method and path suggest, and that is worth knowing while
    /// scrolling.
    pub mode: hexora_types::raw::RequestMode,
}

/// A stored request, read back in full.
///
/// The header block stays raw rather than being parsed here. Storage is a byte store:
/// it is `hexora-http` that knows how to read a header block, and re-parsing on the
/// way out is also what proves the bytes survived the round trip unaltered.
#[derive(Debug, Clone)]
pub struct StoredRequest {
    /// The request's identifier.
    pub id: RequestId,
    /// The request this one was derived from, if any.
    pub parent: Option<RequestId>,
    /// Which subsystem sent it.
    pub origin: String,
    /// The identity it was sent as, when one was chosen.
    pub identity: Option<hexora_types::ids::IdentityId>,
    /// The method, verbatim.
    pub method: String,
    /// The request target as sent.
    pub path: String,
    /// The protocol version token, e.g. `HTTP/1.1`.
    pub http_version: String,
    /// The header block exactly as sent, CRLF-separated, without the trailing blank
    /// line.
    pub headers_raw: Vec<u8>,
    /// The request body.
    ///
    /// For a raw request this is the bytes after the head terminator, as they were
    /// sent. It is a *view*: what gets re-sent is [`Self::raw`].
    pub body: Vec<u8>,
    /// How the request reached the socket.
    pub mode: hexora_types::raw::RequestMode,
    /// The exact bytes that were written, for a raw request.
    ///
    /// `None` for a structured one, and for a raw row whose blob has been pruned —
    /// which is reported rather than papered over, because re-sending a structured
    /// reconstruction of a raw request would send something else.
    pub raw: Option<Vec<u8>>,
    /// Host, port and scheme it was sent to.
    pub service: hexora_types::http::HttpService,
    /// When it was sent, RFC 3339.
    pub sent_at: String,
}

/// A `requests` row before its blob-backed body and parsed parent are filled in.
struct RequestRow {
    request: StoredRequest,
    parent: Option<String>,
    identity: Option<String>,
    body_hash: Option<String>,
    body_size: i64,
    raw_hash: Option<String>,
    raw_size: i64,
}

/// Reads and writes captured traffic.
pub struct TrafficStore {
    db: MetadataDb,
    blobs: Arc<dyn BlobStore>,
}

impl std::fmt::Debug for TrafficStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficStore").finish_non_exhaustive()
    }
}

impl CapturedExchange {
    /// How this exchange's request reached the socket.
    ///
    /// Derived from whether raw bytes are present rather than stored twice: two
    /// fields that could disagree about the same fact is one field too many.
    pub fn mode(&self) -> hexora_types::raw::RequestMode {
        match self.raw_request {
            Some(_) => hexora_types::raw::RequestMode::Raw,
            None => hexora_types::raw::RequestMode::Structured,
        }
    }
}

impl TrafficStore {
    /// Builds a store over a metadata database and a blob store.
    pub fn new(db: MetadataDb, blobs: Arc<dyn BlobStore>) -> Self {
        Self { db, blobs }
    }

    /// Registers a target, returning the existing row if it is already known.
    pub fn upsert_target(&self, host: &str, port: u16, secure: bool) -> Result<TargetId> {
        let conn = self.db.connection()?;
        let now = now();

        // A target is identified by host, port and scheme together: the same host on
        // 80 and 443 is two attack surfaces, not one.
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM targets WHERE host = ?1 AND port = ?2 AND secure = ?3",
                params![host, port, secure as i64],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            conn.execute(
                "UPDATE targets SET last_seen_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
            return Ok(id.parse()?);
        }

        let id = TargetId::new();
        conn.execute(
            "INSERT INTO targets (id, host, port, secure, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id.to_string(), host, port, secure as i64, now],
        )?;
        Ok(id)
    }

    /// Stores one exchange, returning its identifier.
    pub fn record(&self, exchange: &CapturedExchange) -> Result<RequestId> {
        let service = &exchange.request.service;
        let target = self.upsert_target(&service.host, service.port, service.secure)?;

        let request_body = self.put_body(&exchange.request.body)?;
        // Content-addressed like every other body: fuzzing one header of the same raw
        // request a thousand times stores the distinct variants, not a thousand copies
        // of the parts that did not change.
        let raw_request = match &exchange.raw_request {
            Some(bytes) => self.put_body(bytes)?,
            None => None,
        };
        let decoded_body = self.put_body(&exchange.response.body)?;
        let encoded_body = match &exchange.encoded_body {
            Some(bytes) => self.put_body(bytes)?,
            None => None,
        };

        let request_id = RequestId::new();
        let response_id = ResponseId::new();
        let now = now();

        let quirks = serde_json::to_string(&exchange.quirks).map_err(|e| StorageError::Decode {
            entity: "quirks",
            reason: e.to_string(),
        })?;
        let tls_json = match &exchange.tls {
            Some(tls) => Some(
                serde_json::to_string(tls).map_err(|e| StorageError::Decode {
                    entity: "TlsInfo",
                    reason: e.to_string(),
                })?,
            ),
            None => None,
        };

        let mut conn = self.db.connection()?;
        // One transaction: a request without its response would be a half-recorded
        // exchange, and evidence with a hole in it is worse than none.
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO requests
                (id, target_id, origin, parent_id, method, path, http_version,
                 headers_raw, body_hash, body_size, sent_at, quirks, tls_json,
                 identity_id, request_mode, raw_hash, raw_size)
             VALUES (?1, ?2, ?3, ?13, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?14,
                     ?15, ?16, ?17)",
            params![
                request_id.to_string(),
                target.to_string(),
                exchange.origin,
                exchange.request.method,
                exchange.request.path,
                exchange.request.version.as_str(),
                header_block(&exchange.request.headers),
                encoded_hash(&request_body),
                encoded_size(&request_body),
                now,
                quirks,
                tls_json,
                exchange.parent.map(|p| p.to_string()),
                exchange.identity.map(|i| i.to_string()),
                exchange.mode().as_str(),
                encoded_hash(&raw_request),
                encoded_size(&raw_request),
            ],
        )?;

        tx.execute(
            "INSERT INTO responses
                (id, request_id, status, reason, http_version, headers_raw,
                 body_hash, body_size, encoded_body_hash, encoded_body_size,
                 content_encoding, truncated, duration_ms, received_at, quirks)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                response_id.to_string(),
                request_id.to_string(),
                exchange.response.status,
                exchange.response.reason,
                exchange.response.version.as_str(),
                header_block(&exchange.response.headers),
                encoded_hash(&decoded_body),
                encoded_size(&decoded_body),
                encoded_hash(&encoded_body),
                encoded_size(&encoded_body),
                exchange.content_encoding,
                exchange.response.truncated as i64,
                exchange.duration_ms,
                now,
                "[]",
            ],
        )?;

        tx.commit()?;
        Ok(request_id)
    }

    /// Pages through captured traffic, newest first.
    pub fn history(&self, after: Option<&Cursor>, limit: Limit) -> Result<Page<StoredTraffic>> {
        let conn = self.db.connection()?;

        // Keyset pagination on the id. UUIDv7 sorts chronologically, so this is both
        // "newest first" and stable while the proxy keeps appending — an offset would
        // skip or repeat rows as traffic arrives underneath the reader.
        let sql = "
            SELECT r.id, r.target_id, r.method, r.path, r.sent_at, r.quirks,
                   t.host, t.port, t.secure,
                   res.status, res.body_size, res.duration_ms,
                   i.label, r.request_mode
            FROM requests r
            JOIN targets t ON t.id = r.target_id
            LEFT JOIN responses res ON res.request_id = r.id
            LEFT JOIN identities i ON i.id = r.identity_id
            WHERE (?1 IS NULL OR r.id < ?1)
            ORDER BY r.id DESC
            LIMIT ?2";

        let mut statement = conn.prepare(sql)?;
        let cursor = after.map(|c| c.0.clone());
        let rows = statement.query_map(params![cursor, limit.get() + 1], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
            ))
        })?;

        let mut items = Vec::new();
        for row in rows {
            let (
                id,
                target,
                method,
                path,
                sent_at,
                quirks,
                host,
                port,
                secure,
                status,
                size,
                ms,
                identity,
                mode,
            ) = row?;
            let secure = secure != 0;
            let service = hexora_types::http::HttpService::new(&host, port as u16, secure);
            items.push(StoredTraffic {
                id: id.parse()?,
                target: target.parse()?,
                method,
                url: format!("{}{}", service.origin(), path),
                status: status.map(|s| s as u16),
                response_bytes: size.unwrap_or(0) as u64,
                duration_ms: ms.map(|d| d as u32),
                sent_at,
                quirks: serde_json::from_str(&quirks).unwrap_or_default(),
                secure,
                identity,
                mode: hexora_types::raw::RequestMode::parse(&mode),
            });
        }

        // One extra row was requested purely to learn whether another page exists.
        let next = if items.len() > limit.get() as usize {
            items.truncate(limit.get() as usize);
            items.last().map(|last| Cursor(last.id.to_string()))
        } else {
            None
        };

        Ok(Page { items, next })
    }

    /// Reads back a stored response body.
    ///
    /// `wire` selects the bytes as they arrived rather than the decoded form. For an
    /// uncompressed response the two are the same blob.
    pub fn response_body(&self, request: RequestId, wire: bool) -> Result<Vec<u8>> {
        let conn = self.db.connection()?;
        let column = if wire {
            "COALESCE(encoded_body_hash, body_hash), COALESCE(encoded_body_size, body_size)"
        } else {
            "body_hash, body_size"
        };

        let row: Option<(Option<String>, i64)> = conn
            .query_row(
                &format!("SELECT {column} FROM responses WHERE request_id = ?1"),
                params![request.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match row {
            None => Err(StorageError::Decode {
                entity: "response",
                reason: format!("no response stored for {request}"),
            }),
            Some((None, _)) => Ok(Vec::new()),
            Some((Some(hash), size)) => {
                let reference = BlobRef::from_parts(hash, size as u64)?;
                self.blobs.get(&reference)
            }
        }
    }

    /// Reads back a stored request in full, ready to be resent.
    pub fn request(&self, id: RequestId) -> Result<StoredRequest> {
        let conn = self.db.connection()?;

        // The row is assembled into the result type inside the closure rather than
        // returned as a wide tuple: twelve positional columns is exactly the shape
        // that gets silently mis-ordered during a later edit.
        let row = conn
            .query_row(
                "SELECT r.parent_id, r.origin, r.method, r.path, r.http_version,
                        r.headers_raw, r.body_hash, r.body_size, r.sent_at,
                        t.host, t.port, t.secure, r.identity_id,
                        r.request_mode, r.raw_hash, r.raw_size
                 FROM requests r
                 JOIN targets t ON t.id = r.target_id
                 WHERE r.id = ?1",
                params![id.to_string()],
                |row| {
                    let host: String = row.get(9)?;
                    let port: i64 = row.get(10)?;
                    let secure: i64 = row.get(11)?;
                    let identity: Option<String> = row.get(12)?;
                    let mode: String = row.get(13)?;
                    Ok(RequestRow {
                        identity,
                        raw_hash: row.get(14)?,
                        raw_size: row.get(15)?,
                        // Parsed after the query: the id types return `HexoraError`,
                        // which is not a `rusqlite::Error` and cannot surface here.
                        parent: row.get(0)?,
                        body_hash: row.get(6)?,
                        body_size: row.get(7)?,
                        request: StoredRequest {
                            id,
                            parent: None,
                            identity: None,
                            origin: row.get(1)?,
                            method: row.get(2)?,
                            path: row.get(3)?,
                            http_version: row.get(4)?,
                            headers_raw: row.get(5)?,
                            body: Vec::new(),
                            service: hexora_types::http::HttpService::new(
                                &host,
                                port as u16,
                                secure != 0,
                            ),
                            sent_at: row.get(8)?,
                            mode: hexora_types::raw::RequestMode::parse(&mode),
                            raw: None,
                        },
                    })
                },
            )
            .optional()?;

        let row = row.ok_or_else(|| StorageError::Decode {
            entity: "request",
            reason: format!("no request stored with id {id}"),
        })?;

        let mut stored = row.request;
        stored.parent = row.parent.map(|p| p.parse()).transpose()?;
        stored.identity = row.identity.map(|i| i.parse()).transpose()?;
        stored.body = match row.body_hash {
            None => Vec::new(),
            Some(hash) => {
                let reference = BlobRef::from_parts(hash, row.body_size as u64)?;
                self.blobs.get(&reference)?
            }
        };
        stored.raw = match row.raw_hash {
            None => None,
            Some(hash) => {
                let reference = BlobRef::from_parts(hash, row.raw_size as u64)?;
                Some(self.blobs.get(&reference)?)
            }
        };
        Ok(stored)
    }

    /// Reads back a stored response's status line and headers.
    ///
    /// Returned as `(status, reason, version, headers_raw)`. The body comes from
    /// [`Self::response_body`], because it can be enormous and is often not wanted.
    pub fn response_head(
        &self,
        request: RequestId,
    ) -> Result<(u16, Option<String>, String, Vec<u8>)> {
        let conn = self.db.connection()?;
        let row: Option<(i64, Option<String>, String, Vec<u8>)> = conn
            .query_row(
                "SELECT status, reason, http_version, headers_raw
                 FROM responses WHERE request_id = ?1",
                params![request.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let (status, reason, version, headers) = row.ok_or_else(|| StorageError::Decode {
            entity: "response",
            reason: format!("no response stored for {request}"),
        })?;
        Ok((status as u16, reason, version, headers))
    }

    /// The TLS details recorded for an exchange, if it had any.
    ///
    /// Read back rather than carried on every history row: most callers never look at
    /// it, and a passive check that does should pay for it only for the exchanges it
    /// examines.
    pub fn tls_of(&self, request: RequestId) -> Result<Option<TlsInfo>> {
        let conn = self.db.connection()?;
        let stored: Option<Option<String>> = conn
            .query_row(
                "SELECT tls_json FROM requests WHERE id = ?1",
                params![request.to_string()],
                |row| row.get(0),
            )
            .optional()?;

        let Some(Some(json)) = stored else {
            return Ok(None);
        };
        serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| StorageError::Decode {
                entity: "TlsInfo",
                reason: format!("{e}"),
            })
    }

    /// Which target a stored request was sent to.
    ///
    /// A finding has to name the target it is about, and the honest source of that is
    /// the request it was derived from — not a fresh id minted at report time, which
    /// would point at a target the project has never heard of.
    pub fn target_of(&self, id: RequestId) -> Result<TargetId> {
        let conn = self.db.connection()?;
        let target: Option<String> = conn
            .query_row(
                "SELECT target_id FROM requests WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?;

        let target = target.ok_or_else(|| StorageError::NotFound {
            entity: "request",
            id: id.to_string(),
        })?;
        Ok(target.parse()?)
    }

    /// Every request derived from `parent`, oldest first.
    ///
    /// Oldest first because a branch is read as a sequence of edits: what was tried,
    /// in the order it was tried.
    pub fn children(&self, parent: RequestId) -> Result<Vec<RequestId>> {
        let conn = self.db.connection()?;
        let mut statement =
            conn.prepare("SELECT id FROM requests WHERE parent_id = ?1 ORDER BY id ASC")?;
        let rows =
            statement.query_map(params![parent.to_string()], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?.parse()?);
        }
        Ok(ids)
    }

    /// How many exchanges are stored.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 = conn.query_row("SELECT count(*) FROM requests", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Stores a body, returning `None` for an empty one.
    ///
    /// Empty bodies are extremely common, and a reference to zero bytes is pure
    /// overhead — the schema encodes "no body" as a NULL hash.
    fn put_body(&self, body: &[u8]) -> Result<Option<BlobRef>> {
        if body.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.blobs.put(body)?))
    }
}

fn encoded_hash(reference: &Option<BlobRef>) -> Option<String> {
    reference.as_ref().map(|r| r.hash().to_string())
}

fn encoded_size(reference: &Option<BlobRef>) -> i64 {
    reference.as_ref().map(|r| r.size() as i64).unwrap_or(0)
}

/// Serializes a header block back to its wire form.
///
/// Stored raw rather than as parsed JSON so the exact bytes survive — duplicate
/// fields, unusual casing and non-UTF-8 values all included.
fn header_block(headers: &hexora_types::http::Headers) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.wire_size());
    for header in headers.iter() {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }
    out
}

pub(crate) fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl From<hexora_types::HexoraError> for StorageError {
    fn from(e: hexora_types::HexoraError) -> Self {
        StorageError::Decode {
            entity: "identifier",
            reason: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use hexora_types::http::{Header, Headers, HttpService, HttpVersion};

    use super::*;
    use crate::{MemoryBlobStore, Project};

    fn store() -> (TrafficStore, Project) {
        let project = Project::in_memory().unwrap();
        let store = TrafficStore::new(project.metadata().clone(), Arc::new(MemoryBlobStore::new()));
        (store, project)
    }

    fn exchange(path: &str, status: u16, body: &[u8]) -> CapturedExchange {
        let mut request = HttpRequest::get(HttpService::new("example.com", 443, true), path);
        request.headers.append(Header::new("X-Test", "1"));

        CapturedExchange {
            request,
            response: HttpResponse {
                status,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: Bytes::copy_from_slice(body),
                truncated: false,
            },
            encoded_body: None,
            raw_request: None,
            content_encoding: None,
            origin: "proxy",
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 42,
        }
    }

    #[test]
    fn a_stored_request_can_be_read_back_in_full() {
        // The repeater's whole premise: an exchange from history can be reconstituted
        // and sent again. If any part of this is lossy, the resend is not a resend.
        let (store, _project) = store();
        let mut captured = exchange("/login?next=%2Fadmin", 200, b"ok");
        captured.request.method = "POST".into();
        captured.request.body = Bytes::from_static(b"user=admin&pass=hunter2");
        captured
            .request
            .headers
            .append(Header::new("content-length", "23"));
        let id = store.record(&captured).unwrap();

        let read = store.request(id).unwrap();
        assert_eq!(read.method, "POST");
        assert_eq!(read.path, "/login?next=%2Fadmin");
        assert_eq!(read.body, b"user=admin&pass=hunter2");
        assert_eq!(read.service.host, "example.com");
        assert_eq!(read.service.port, 443);
        assert!(read.service.secure);
        assert_eq!(read.origin, "proxy");
        assert!(read.parent.is_none());
        // Lower-case as written: a resend must not silently re-case a header.
        let headers = String::from_utf8(read.headers_raw).unwrap();
        assert!(headers.contains("content-length: 23"), "{headers}");
    }

    #[test]
    fn reading_an_unknown_request_is_an_error_not_an_empty_one() {
        let (store, _project) = store();
        assert!(store.request(RequestId::new()).is_err());
    }

    #[test]
    fn a_request_with_no_body_reads_back_empty() {
        let (store, _project) = store();
        let id = store.record(&exchange("/", 200, b"")).unwrap();
        assert!(store.request(id).unwrap().body.is_empty());
    }

    #[test]
    fn a_request_sent_as_an_identity_reads_back_naming_it() {
        let (store, project) = store();
        let identity = hexora_types::identity::Identity::bearer("User B", "TEST_TOKEN");
        project.identities().put(&identity).unwrap();

        let mut captured = exchange("/accounts/1", 200, b"{}");
        captured.origin = "authz";
        captured.identity = Some(identity.id);
        let id = store.record(&captured).unwrap();

        assert_eq!(store.request(id).unwrap().identity, Some(identity.id));
        let page = store
            .history(None, crate::repository::Limit::new(10))
            .unwrap();
        assert_eq!(
            page.items[0].identity.as_deref(),
            Some("User B"),
            "history shows the label, because history is read by people"
        );
    }

    #[test]
    fn a_request_names_the_target_it_was_sent_to() {
        let (store, _project) = store();
        let id = store.record(&exchange("/a", 200, b"x")).unwrap();
        let target = store.upsert_target("example.com", 443, true).unwrap();
        assert_eq!(store.target_of(id).unwrap(), target);
    }

    #[test]
    fn asking_for_the_target_of_an_unknown_request_is_an_error() {
        let (store, _project) = store();
        assert!(store.target_of(RequestId::new()).is_err());
    }

    #[test]
    fn a_variant_keeps_the_request_it_was_derived_from() {
        // Branching is the point: weeks later, "which edit caused the change?" has to
        // still be answerable, long after the tab it was edited in is gone.
        let (store, _project) = store();
        let original = store.record(&exchange("/item/1", 200, b"a")).unwrap();

        let mut variant = exchange("/item/2", 403, b"denied");
        variant.origin = "repeater";
        variant.parent = Some(original);
        let variant = store.record(&variant).unwrap();

        assert_eq!(store.request(variant).unwrap().parent, Some(original));
        assert_eq!(store.children(original).unwrap(), vec![variant]);
        assert!(store.children(variant).unwrap().is_empty());
    }

    #[test]
    fn siblings_are_returned_in_the_order_they_were_tried() {
        let (store, _project) = store();
        let original = store.record(&exchange("/", 200, b"a")).unwrap();

        let mut ids = Vec::new();
        for path in ["/a", "/b", "/c"] {
            let mut variant = exchange(path, 200, b"x");
            variant.origin = "repeater";
            variant.parent = Some(original);
            ids.push(store.record(&variant).unwrap());
        }
        assert_eq!(store.children(original).unwrap(), ids);
    }

    #[test]
    fn a_response_head_is_readable_without_fetching_the_body() {
        // Bodies can be enormous; a diff of status and headers must not require one.
        let (store, _project) = store();
        let mut captured = exchange("/", 301, b"redirecting");
        captured.response.reason = Some("Moved Permanently".into());
        captured
            .response
            .headers
            .append(Header::new("Location", "/elsewhere"));
        let id = store.record(&captured).unwrap();

        let (status, reason, version, headers) = store.response_head(id).unwrap();
        assert_eq!(status, 301);
        assert_eq!(reason.as_deref(), Some("Moved Permanently"));
        assert_eq!(version, "HTTP/1.1");
        assert!(String::from_utf8(headers).unwrap().contains("/elsewhere"));
    }

    #[test]
    fn an_exchange_round_trips() {
        let (store, _project) = store();
        let id = store.record(&exchange("/a", 200, b"hello")).unwrap();

        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.response_body(id, false).unwrap(), b"hello");

        let page = store.history(None, Limit::default()).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].url, "https://example.com/a");
        assert_eq!(page.items[0].status, Some(200));
        assert_eq!(page.items[0].response_bytes, 5);
        assert_eq!(page.items[0].duration_ms, Some(42));
        assert!(page.items[0].secure);
    }

    #[test]
    fn the_same_target_is_registered_once() {
        let (store, _project) = store();
        let first = store.upsert_target("example.com", 443, true).unwrap();
        let second = store.upsert_target("example.com", 443, true).unwrap();
        assert_eq!(first, second);

        // Same host, different port or scheme, is a different attack surface.
        let plain = store.upsert_target("example.com", 80, false).unwrap();
        assert_ne!(first, plain);
    }

    #[test]
    fn identical_bodies_are_stored_once() {
        // The reason bodies are content-addressed: a crawl repeats itself heavily.
        let project = Project::in_memory().unwrap();
        let blobs = Arc::new(MemoryBlobStore::new());
        let store = TrafficStore::new(project.metadata().clone(), blobs.clone());

        for i in 0..10 {
            store
                .record(&exchange(&format!("/page{i}"), 404, b"the same 404 page"))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 10);
        assert_eq!(blobs.len(), 1, "ten identical bodies must cost one blob");
    }

    #[test]
    fn an_empty_body_stores_no_blob() {
        let project = Project::in_memory().unwrap();
        let blobs = Arc::new(MemoryBlobStore::new());
        let store = TrafficStore::new(project.metadata().clone(), blobs.clone());

        let id = store.record(&exchange("/", 204, b"")).unwrap();
        assert!(
            blobs.is_empty(),
            "a reference to zero bytes is pure overhead"
        );
        assert!(store.response_body(id, false).unwrap().is_empty());
    }

    #[test]
    fn both_the_wire_and_decoded_bodies_are_kept() {
        // The M1.5 gap this migration closed. A finding about a compression side
        // channel is a finding about the encoded bytes.
        let (store, _project) = store();
        let mut captured = exchange("/compressed", 200, b"decoded content");
        captured.encoded_body = Some(Bytes::from_static(b"\x1f\x8b\x08fake-gzip"));
        captured.content_encoding = Some("gzip".to_string());

        let id = store.record(&captured).unwrap();
        assert_eq!(store.response_body(id, false).unwrap(), b"decoded content");
        assert_eq!(
            store.response_body(id, true).unwrap(),
            b"\x1f\x8b\x08fake-gzip",
            "the bytes as they arrived must be recoverable"
        );
    }

    #[test]
    fn an_uncompressed_body_costs_one_blob_not_two() {
        let project = Project::in_memory().unwrap();
        let blobs = Arc::new(MemoryBlobStore::new());
        let store = TrafficStore::new(project.metadata().clone(), blobs.clone());

        let id = store.record(&exchange("/", 200, b"plain")).unwrap();
        assert_eq!(blobs.len(), 1);
        // With no content coding, asking for the wire form yields the same bytes.
        assert_eq!(store.response_body(id, true).unwrap(), b"plain");
    }

    #[test]
    fn header_order_casing_and_duplicates_survive_storage() {
        let (store, project) = store();
        let mut captured = exchange("/", 200, b"");
        captured.request.headers.append(Header::new("X-Dup", "1"));
        captured.request.headers.append(Header::new("x-dup", "2"));

        store.record(&captured).unwrap();

        let raw: Vec<u8> = project
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT headers_raw FROM requests", [], |row| row.get(0))
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("X-Dup: 1"), "{text}");
        assert!(text.contains("x-dup: 2"), "casing must survive: {text}");
    }

    #[test]
    fn quirks_are_recorded_so_smuggling_signals_can_be_searched_for() {
        let (store, _project) = store();
        let mut captured = exchange("/", 200, b"");
        captured.quirks = vec!["BareLf".into(), "DataAfterFinalChunk".into()];

        store.record(&captured).unwrap();
        let page = store.history(None, Limit::default()).unwrap();
        assert_eq!(page.items[0].quirks, vec!["BareLf", "DataAfterFinalChunk"]);
    }

    #[test]
    fn tls_details_are_recorded_for_https_exchanges() {
        let (store, project) = store();
        let mut captured = exchange("/", 200, b"");
        captured.tls = Some(TlsInfo {
            protocol: "TLSv1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            alpn: Some("http/1.1".into()),
            verification: hexora_types::tls::Verification::AcceptAny,
            peer_certificates: Vec::new(),
        });

        store.record(&captured).unwrap();

        let json: Option<String> = project
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT tls_json FROM requests", [], |row| row.get(0))
            .unwrap();
        let stored: TlsInfo = serde_json::from_str(&json.unwrap()).unwrap();
        assert!(
            !stored.peer_authenticated(),
            "a finding built on an unverified connection must be able to say so"
        );
    }

    #[test]
    fn history_is_newest_first_and_pages_stably() {
        let (store, _project) = store();
        for i in 0..25 {
            store
                .record(&exchange(&format!("/{i}"), 200, b"x"))
                .unwrap();
        }

        let first = store.history(None, Limit::new(10)).unwrap();
        assert_eq!(first.items.len(), 10);
        assert!(first.items[0].url.ends_with("/24"), "newest first");
        let cursor = first.next.expect("more pages remain");

        let second = store.history(Some(&cursor), Limit::new(10)).unwrap();
        assert_eq!(second.items.len(), 10);
        assert!(second.items[0].url.ends_with("/14"));

        // No overlap between pages, which offset pagination would not guarantee while
        // the proxy keeps appending.
        let ids: Vec<_> = first.items.iter().map(|i| i.id).collect();
        assert!(second.items.iter().all(|i| !ids.contains(&i.id)));
    }

    #[test]
    fn the_last_page_reports_no_cursor() {
        let (store, _project) = store();
        for i in 0..3 {
            store.record(&exchange(&format!("/{i}"), 200, b"")).unwrap();
        }
        let page = store.history(None, Limit::new(10)).unwrap();
        assert_eq!(page.items.len(), 3);
        assert!(page.next.is_none());
    }

    #[test]
    fn an_empty_project_yields_an_empty_page() {
        let (store, _project) = store();
        let page = store.history(None, Limit::default()).unwrap();
        assert!(page.items.is_empty());
        assert!(page.next.is_none());
    }

    #[test]
    fn reading_a_body_for_an_unknown_request_is_an_error_not_an_empty_body() {
        let (store, _project) = store();
        assert!(store.response_body(RequestId::new(), false).is_err());
    }
}
