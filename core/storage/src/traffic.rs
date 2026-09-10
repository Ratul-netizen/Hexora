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
    pub request: HttpRequest,
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
                (id, target_id, origin, method, path, http_version, headers_raw,
                 body_hash, body_size, sent_at, quirks, tls_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                   res.status, res.body_size, res.duration_ms
            FROM requests r
            JOIN targets t ON t.id = r.target_id
            LEFT JOIN responses res ON res.request_id = r.id
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
            ))
        })?;

        let mut items = Vec::new();
        for row in rows {
            let (id, target, method, path, sent_at, quirks, host, port, secure, status, size, ms) =
                row?;
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

fn now() -> String {
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
            content_encoding: None,
            origin: "proxy",
            quirks: Vec::new(),
            tls: None,
            duration_ms: 42,
        }
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
