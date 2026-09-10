//! Content-addressed storage for HTTP bodies.
//!
//! # Why bodies do not live in the relational database
//!
//! A single engagement can capture millions of exchanges. At an average 100 KB
//! response that is hundreds of gigabytes, and a relational database that is also the
//! primary blob repository degrades badly at that size: the page cache is displaced
//! by body bytes, `VACUUM` becomes impractical, and backing up the project means
//! copying every byte of every response.
//!
//! So the split is:
//!
//! ```text
//! metadata  →  MetadataStore   (SQLite now, PostgreSQL for team deployments)
//! bodies    →  BlobStore       (content-addressed files now)
//! ```
//!
//! The message row keeps a [`BlobRef`], not the bytes.
//!
//! # Why content-addressed
//!
//! Blobs are keyed by the SHA-256 of their content, which gives deduplication for
//! free. Fuzzing 50 000 payloads against an endpoint that returns the same 8 KB error
//! page stores that page once. Crawls repeat themselves heavily, so in practice this
//! is the difference between a project that stays portable and one that does not.
//!
//! It also means writes are idempotent and blobs are immutable, so no locking is
//! needed between the proxy writing traffic and the UI reading it.
//!
//! # Blocking, not async
//!
//! This trait is synchronous. SQLite is a blocking API, so the whole storage layer is
//! blocking and the engine calls it from a blocking pool
//! (`tokio::task::spawn_blocking`). Making only the blob half async would put an
//! `.await` in front of a call that still has a blocking sibling, which buys nothing
//! and hides the real constraint.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, StorageError};

/// A reference to stored body bytes: the SHA-256 hash and the original length.
///
/// The length is carried alongside the hash so the UI can render "2.4 MB response"
/// without touching the blob store at all.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobRef {
    hash: String,
    size: u64,
}

impl BlobRef {
    /// Computes the reference for a body without storing it.
    pub fn of(content: &[u8]) -> Self {
        Self { hash: hex_sha256(content), size: content.len() as u64 }
    }

    /// The lowercase hex SHA-256 of the content.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The content length in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this reference points at zero bytes.
    ///
    /// Empty bodies are extremely common, so callers skip the store entirely.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Rebuilds a reference from its stored parts.
    pub fn from_parts(hash: impl Into<String>, size: u64) -> Result<Self> {
        let hash = hash.into();
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::Decode {
                entity: "BlobRef",
                reason: format!("{hash:?} is not a SHA-256 hex digest"),
            });
        }
        Ok(Self { hash: hash.to_ascii_lowercase(), size })
    }
}

impl fmt::Display for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.hash, self.size)
    }
}

impl FromStr for BlobRef {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self> {
        let (hash, size) = s.split_once(':').ok_or_else(|| StorageError::Decode {
            entity: "BlobRef",
            reason: format!("{s:?} is not in hash:size form"),
        })?;
        let size = size.parse::<u64>().map_err(|e| StorageError::Decode {
            entity: "BlobRef",
            reason: e.to_string(),
        })?;
        Self::from_parts(hash, size)
    }
}

/// Storage for immutable body bytes.
///
/// Implementations are cheap to clone and safe to share across threads: the proxy
/// writes from many connection tasks while the UI reads.
pub trait BlobStore: Send + Sync + fmt::Debug {
    /// Stores content and returns its reference.
    ///
    /// Storing content that is already present is a successful no-op.
    fn put(&self, content: &[u8]) -> Result<BlobRef>;

    /// Retrieves content, verifying it still hashes to the reference it is filed
    /// under.
    ///
    /// The verification is not paranoia: these bytes are the evidence behind findings
    /// in a report, and silent bit-rot or a truncated write would corrupt a claim
    /// made to a client.
    fn get(&self, reference: &BlobRef) -> Result<Vec<u8>>;

    /// Whether the store holds this blob.
    fn contains(&self, reference: &BlobRef) -> Result<bool>;

    /// Permanently removes a blob.
    ///
    /// Blobs are shared by deduplication, so this must only be called by a garbage
    /// collector that has established nothing references the blob any more.
    fn delete(&self, reference: &BlobRef) -> Result<()>;
}

/// A content-addressed blob store backed by the filesystem.
///
/// Files are sharded two hex characters deep (`ab/abcdef…`) because a single
/// directory holding a million entries is slow to enumerate on every major
/// filesystem, and 256 buckets keeps directories to a manageable size for the project
/// scales this is built for.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Opens (creating if needed) a blob store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The directory this store writes to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[..2]).join(hash)
    }
}

impl BlobStore for FsBlobStore {
    fn put(&self, content: &[u8]) -> Result<BlobRef> {
        let reference = BlobRef::of(content);
        let path = self.path_for(&reference.hash);
        if path.exists() {
            // Content-addressed: identical hash means identical bytes, so there is
            // nothing to do and nothing to overwrite.
            return Ok(reference);
        }
        let dir = path.parent().expect("blob paths always have a parent");
        fs::create_dir_all(dir)?;

        // Write to a unique temporary name and rename into place, so a crash or a
        // concurrent writer can never leave a half-written blob visible under a hash
        // that promises complete content.
        let temp = dir.join(format!("{}.{}.tmp", reference.hash, uuid::Uuid::now_v7().simple()));
        {
            let mut file = fs::File::create(&temp)?;
            file.write_all(content)?;
            file.sync_all()?;
        }
        match fs::rename(&temp, &path) {
            Ok(()) => Ok(reference),
            Err(e) => {
                let _ = fs::remove_file(&temp);
                // A concurrent writer winning the race is a success, not a failure:
                // the bytes are identical by construction.
                if path.exists() {
                    Ok(reference)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    fn get(&self, reference: &BlobRef) -> Result<Vec<u8>> {
        let path = self.path_for(&reference.hash);
        let content = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StorageError::BlobMissing { hash: reference.hash.clone() },
            _ => StorageError::Io(e),
        })?;
        if hex_sha256(&content) != reference.hash {
            return Err(StorageError::BlobIntegrity { hash: reference.hash.clone() });
        }
        Ok(content)
    }

    fn contains(&self, reference: &BlobRef) -> Result<bool> {
        Ok(self.path_for(&reference.hash).exists())
    }

    fn delete(&self, reference: &BlobRef) -> Result<()> {
        match fs::remove_file(self.path_for(&reference.hash)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// An in-memory blob store, for tests and for `hexora replay`, which does not
/// persist anything.
#[derive(Debug, Clone, Default)]
pub struct MemoryBlobStore {
    blobs: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
}

impl MemoryBlobStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct blobs are held.
    pub fn len(&self) -> usize {
        self.blobs.lock().expect("blob mutex poisoned").len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BlobStore for MemoryBlobStore {
    fn put(&self, content: &[u8]) -> Result<BlobRef> {
        let reference = BlobRef::of(content);
        self.blobs
            .lock()
            .expect("blob mutex poisoned")
            .entry(reference.hash.clone())
            .or_insert_with(|| content.to_vec());
        Ok(reference)
    }

    fn get(&self, reference: &BlobRef) -> Result<Vec<u8>> {
        self.blobs
            .lock()
            .expect("blob mutex poisoned")
            .get(&reference.hash)
            .cloned()
            .ok_or_else(|| StorageError::BlobMissing { hash: reference.hash.clone() })
    }

    fn contains(&self, reference: &BlobRef) -> Result<bool> {
        Ok(self.blobs.lock().expect("blob mutex poisoned").contains_key(&reference.hash))
    }

    fn delete(&self, reference: &BlobRef) -> Result<()> {
        self.blobs.lock().expect("blob mutex poisoned").remove(&reference.hash);
        Ok(())
    }
}

fn hex_sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stores() -> Vec<(&'static str, Box<dyn BlobStore>, Option<tempfile::TempDir>)> {
        let dir = tempfile::tempdir().unwrap();
        vec![
            ("memory", Box::new(MemoryBlobStore::new()), None),
            ("filesystem", Box::new(FsBlobStore::open(dir.path()).unwrap()), Some(dir)),
        ]
    }

    #[test]
    fn known_digest_matches_the_reference_value() {
        // The canonical SHA-256 of the empty input and of "abc".
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn every_store_round_trips_content() {
        for (name, store, _dir) in stores() {
            let content = b"HTTP/1.1 200 OK\r\n\r\nhello";
            let reference = store.put(content).unwrap();
            assert_eq!(store.get(&reference).unwrap(), content, "{name}");
            assert!(store.contains(&reference).unwrap(), "{name}");
            assert_eq!(reference.size(), content.len() as u64, "{name}");
        }
    }

    #[test]
    fn identical_content_deduplicates() {
        let store = MemoryBlobStore::new();
        let a = store.put(b"the same 404 page").unwrap();
        let b = store.put(b"the same 404 page").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.len(), 1, "a repeated response must be stored once");
    }

    #[test]
    fn different_content_gets_different_references() {
        let store = MemoryBlobStore::new();
        let a = store.put(b"one").unwrap();
        let b = store.put(b"two").unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn binary_and_non_utf8_bodies_survive_intact() {
        for (name, store, _dir) in stores() {
            let content: Vec<u8> = (0u8..=255).chain([0xff, 0xfe, 0x00]).collect();
            let reference = store.put(&content).unwrap();
            assert_eq!(store.get(&reference).unwrap(), content, "{name}");
        }
    }

    #[test]
    fn a_missing_blob_reports_itself_as_missing() {
        for (name, store, _dir) in stores() {
            let reference = BlobRef::of(b"never stored");
            assert!(!store.contains(&reference).unwrap(), "{name}");
            let err = store.get(&reference).unwrap_err();
            assert!(matches!(err, StorageError::BlobMissing { .. }), "{name}: {err:?}");
        }
    }

    #[test]
    fn corrupted_blobs_are_detected_rather_than_returned() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(dir.path()).unwrap();
        let reference = store.put(b"evidence for a finding").unwrap();

        // Simulate bit-rot or tampering under the store's feet.
        let path = store.path_for(reference.hash());
        fs::write(&path, b"evidence for a FINDING").unwrap();

        let err = store.get(&reference).unwrap_err();
        assert!(
            matches!(err, StorageError::BlobIntegrity { .. }),
            "report evidence must never be served silently corrupted: {err:?}"
        );
    }

    #[test]
    fn writes_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(dir.path()).unwrap();
        let first = store.put(b"repeat").unwrap();
        let second = store.put(b"repeat").unwrap();
        assert_eq!(first, second);
        assert_eq!(store.get(&first).unwrap(), b"repeat");
    }

    #[test]
    fn deleting_is_idempotent_and_removes_the_blob() {
        for (name, store, _dir) in stores() {
            let reference = store.put(b"transient").unwrap();
            store.delete(&reference).unwrap();
            assert!(!store.contains(&reference).unwrap(), "{name}");
            store.delete(&reference).unwrap();
        }
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(dir.path()).unwrap();
        for i in 0..16 {
            store.put(format!("body {i}").as_bytes()).unwrap();
        }
        let leftovers: Vec<_> = walk(dir.path())
            .into_iter()
            .filter(|p| p.to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn blobs_are_sharded_so_no_directory_holds_everything() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(dir.path()).unwrap();
        for i in 0..64 {
            store.put(format!("body {i}").as_bytes()).unwrap();
        }
        let top_level: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(top_level.len() > 1, "expected sharding, got {top_level:?}");
        assert!(top_level.iter().all(|n| n.len() == 2), "shards are two hex chars: {top_level:?}");
    }

    #[test]
    fn a_blob_reference_round_trips_through_its_string_form() {
        let reference = BlobRef::of(b"content");
        let parsed: BlobRef = reference.to_string().parse().unwrap();
        assert_eq!(parsed, reference);
    }

    #[test]
    fn a_malformed_blob_reference_is_rejected() {
        assert!("not-a-hash:12".parse::<BlobRef>().is_err());
        assert!("abc".parse::<BlobRef>().is_err());
        assert!(BlobRef::from_parts("zz", 0).is_err());
    }

    #[test]
    fn the_empty_body_is_recognisable_without_a_store_lookup() {
        assert!(BlobRef::of(b"").is_empty());
        assert!(!BlobRef::of(b"x").is_empty());
    }

    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(root) else { return out };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }
}
