//! Backend-agnostic persistence interfaces.
//!
//! The domain model must not know whether it is being persisted into a local SQLite
//! file or a shared PostgreSQL instance, because Hexora ships in two shapes:
//!
//! ```text
//! Desktop / CLI   →  SQLite file + filesystem blob store   (offline, portable)
//! Team server     →  PostgreSQL + object storage           (concurrent, shared)
//! ```
//!
//! Only the SQLite backend exists today. These traits are the seam that lets the
//! second one arrive without touching the engine, and they are deliberately narrow —
//! each exists because the engine, the UI and at least one future backend all have to
//! agree on it.
//!
//! # Conventions
//!
//! * **Blocking.** SQLite is a blocking API; callers use `spawn_blocking`. See
//!   [`crate::blob`].
//! * **Bodies are references.** Every method here deals in
//!   [`BlobRef`](crate::blob::BlobRef); bytes come from the [`BlobStore`](crate::blob::BlobStore).
//! * **Pagination is mandatory** on anything that can grow with traffic volume. A
//!   project with five million exchanges must never be loaded into a `Vec`.

use hexora_types::finding::Finding;
use hexora_types::http::HttpService;
use hexora_types::ids::{FindingId, RequestId, TargetId};
use hexora_types::scope::Scope;
use hexora_types::verify::Verified;

use crate::blob::BlobRef;
use crate::error::Result;

/// A page of results plus the cursor needed to fetch the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows in this page.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, or `None` at the end of the result set.
    pub next: Option<Cursor>,
}

/// An opaque position in a result set.
///
/// Deliberately not an offset: traffic is being appended while the user scrolls, and
/// offset pagination would skip or repeat rows. Backends encode a key here instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(pub String);

/// How many rows to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u32);

impl Limit {
    /// The largest page any backend will return, whatever the caller asks for.
    pub const MAX: u32 = 1000;

    /// Clamps a requested page size into the permitted range.
    pub fn new(requested: u32) -> Self {
        Self(requested.clamp(1, Self::MAX))
    }

    /// The clamped value.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self(100)
    }
}

/// Project-level metadata: name, scope, settings.
pub trait ProjectStore: Send + Sync {
    /// Reads the project scope.
    fn scope(&self) -> Result<Scope>;

    /// Replaces the project scope.
    ///
    /// Backends record an audit event for this: widening scope mid-engagement is a
    /// decision a tester may need to justify later.
    fn set_scope(&self, scope: &Scope) -> Result<()>;
}

/// A captured or crafted exchange, as stored.
///
/// Header blocks stay raw so the exact bytes can be re-rendered; bodies are
/// references into the blob store.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExchange {
    pub id: RequestId,
    pub target: TargetId,
    pub method: String,
    pub path: String,
    pub request_headers_raw: Vec<u8>,
    pub request_body: Option<BlobRef>,
    pub status: Option<u16>,
    pub response_headers_raw: Option<Vec<u8>>,
    pub response_body: Option<BlobRef>,
    pub duration_ms: Option<u32>,
}

/// Reading and writing traffic.
pub trait TrafficStore: Send + Sync {
    /// Records one exchange, returning its assigned identifier.
    fn record(&self, exchange: &StoredExchange) -> Result<RequestId>;

    /// Fetches a single exchange.
    fn get(&self, id: RequestId) -> Result<StoredExchange>;

    /// Pages through a target's history, newest first.
    fn history(
        &self,
        target: TargetId,
        after: Option<&Cursor>,
        limit: Limit,
    ) -> Result<Page<StoredExchange>>;

    /// Registers a target, or returns the existing one for this service.
    fn upsert_target(&self, service: &HttpService) -> Result<TargetId>;
}

/// Reading and writing findings.
pub trait FindingStore: Send + Sync {
    /// Persists a verified finding.
    ///
    /// Takes a [`Verified`], which only a
    /// [`Verification`](hexora_types::verify::Verification) produces, so a detector's
    /// suspicion cannot reach a report by going around the verification engine — the
    /// call does not compile rather than being rejected at runtime. See
    /// `docs/security-invariants.md`, invariant 6.
    ///
    /// A future backend cannot weaken this: the signature is the invariant.
    fn save(&self, verified: &Verified) -> Result<()>;

    /// Fetches a finding.
    fn get(&self, id: FindingId) -> Result<Finding>;

    /// Lists findings for a target, most severe first.
    fn list(&self, target: TargetId) -> Result<Vec<Finding>>;
}

/// Full-text search over captured traffic.
///
/// Kept separate from [`TrafficStore`] because the two have genuinely different
/// implementations: the relational backend can answer this with `LIKE` at small
/// scale, but an engagement with millions of exchanges needs a real inverted index
/// (Tantivy is the intended second implementation). Splitting the trait now means
/// that swap does not touch the engine.
pub trait TrafficSearch: Send + Sync {
    /// Returns exchanges whose request or response matches `query`.
    fn search(&self, query: &str, after: Option<&Cursor>, limit: Limit) -> Result<Page<RequestId>>;

    /// Adds an exchange to the index.
    fn index(&self, exchange: &StoredExchange) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_clamped_to_a_sane_range() {
        assert_eq!(Limit::new(0).get(), 1);
        assert_eq!(Limit::new(50).get(), 50);
        assert_eq!(Limit::new(u32::MAX).get(), Limit::MAX);
    }

    #[test]
    fn the_default_page_size_is_within_the_permitted_range() {
        let default = Limit::default().get();
        assert!((1..=Limit::MAX).contains(&default));
    }
}
