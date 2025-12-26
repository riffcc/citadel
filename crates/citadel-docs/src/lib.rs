//! # Citadel Docs: Bilateral CRDT Document Storage
//!
//! This crate provides persistent document storage with Bilateral CRDT semantics.
//! Documents are content-addressed, CRDT-merged, and synced via SPORE.
//!
//! ## Key Concepts
//!
//! ### Documents
//!
//! A Document is any structured data that implements:
//! - `TotalMerge` - Lossless, deterministic merge (from citadel-crdt)
//! - `Document` trait - Type prefix, ID, serialization
//!
//! ### Storage Model
//!
//! Documents are stored in RocksDB with:
//! - Key: `{type_prefix}:{content_id}`
//! - Value: bincode-serialized document
//!
//! ### SPORE Integration
//!
//! The DocumentStore maintains a SPORE HaveList of all stored documents.
//! This enables O(k) sync where k = documents differing between peers.
//!
//! ## Proven Properties
//!
//! From `proofs/CitadelProofs/CRDT/`:
//! - `merge_cannot_disagree` - Same inputs → same outputs
//! - `no_merge_failure` - Merge is total, cannot fail
//! - `full_sync_convergence` - Same operations → same state

use citadel_crdt::{ContentId, TotalMerge};
use citadel_spore::{Range256, Spore, U256};
use rocksdb::{DB, Options, WriteBatch};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, trace};

/// Convert a ContentId to a U256 for SPORE tracking
fn content_id_to_u256(id: &ContentId) -> U256 {
    U256::from_be_bytes(id.as_bytes())
}

/// Create a point range for a single content ID
fn point_range(id: &ContentId) -> Range256 {
    let u = content_id_to_u256(id);
    // Point range [u, u+1) - covers exactly one value
    // For U256::MAX we just use a tiny range
    if let Some(next) = u.checked_add(&U256::from_u64(1)) {
        Range256::new(u, next)
    } else {
        // Edge case: u is MAX, can't add 1
        // Just use [MAX-1, MAX] range
        Range256::new(u, U256::MAX)
    }
}

/// Errors that can occur in document operations.
#[derive(Error, Debug)]
pub enum DocError {
    #[error("Document not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] rocksdb::Error),

    #[error("Invalid document format")]
    InvalidFormat,
}

pub type Result<T> = std::result::Result<T, DocError>;

/// A document that can be stored and synced via Citadel Docs.
///
/// Documents must be:
/// - Serializable (serde)
/// - Mergeable (TotalMerge from citadel-crdt)
/// - Content-addressable (has a ContentId)
pub trait Document: Serialize + DeserializeOwned + TotalMerge + Clone {
    /// Type prefix for storage keys (e.g., "job", "release", "audit")
    const TYPE_PREFIX: &'static str;

    /// Get the document's content ID
    fn content_id(&self) -> ContentId;

    /// Compute content ID from serialized form
    fn compute_content_id(&self) -> ContentId {
        let bytes = bincode::serialize(self).expect("serialization cannot fail");
        ContentId::hash(&bytes)
    }
}

/// Persistent document store backed by RocksDB.
///
/// Stores documents with automatic SPORE tracking for sync.
pub struct DocumentStore {
    db: Arc<DB>,
    /// SPORE HaveList tracking all stored document IDs
    have_list: Spore,
}

impl DocumentStore {
    /// Open or create a document store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let db = DB::open(&opts, path)?;

        // Rebuild HaveList from existing documents
        let have_list = Self::rebuild_havelist(&db)?;

        debug!(
            docs = have_list.range_count(),
            "Opened document store"
        );

        Ok(Self {
            db: Arc::new(db),
            have_list,
        })
    }

    /// Rebuild SPORE HaveList by scanning all keys
    fn rebuild_havelist(db: &DB) -> Result<Spore> {
        let mut ranges = Vec::new();

        let iter = db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            // Extract content ID from key (after the type prefix)
            if let Some(id_hex) = std::str::from_utf8(&key)
                .ok()
                .and_then(|s| s.split(':').nth(1))
            {
                if let Ok(content_id) = ContentId::from_hex(id_hex) {
                    ranges.push(point_range(&content_id));
                }
            }
        }

        Ok(Spore::from_ranges(ranges))
    }

    /// Get the current SPORE HaveList
    pub fn have_list(&self) -> &Spore {
        &self.have_list
    }

    /// Store a document, merging with existing if present.
    ///
    /// This is the core operation - it:
    /// 1. Fetches any existing document
    /// 2. Merges (TotalMerge - cannot fail)
    /// 3. Stores the result
    /// 4. Updates SPORE HaveList
    pub fn put<D: Document>(&mut self, doc: &D) -> Result<ContentId> {
        let content_id = doc.content_id();
        let key = self.make_key::<D>(&content_id);

        // Check for existing document
        let merged = if let Some(existing_bytes) = self.db.get(&key)? {
            let existing: D = bincode::deserialize(&existing_bytes)?;
            // TotalMerge - this CANNOT fail (proven in Lean)
            existing.merge(doc)
        } else {
            doc.clone()
        };

        // Serialize and store
        let bytes = bincode::serialize(&merged)?;
        self.db.put(&key, &bytes)?;

        // Update SPORE HaveList
        let range = point_range(&content_id);
        self.have_list = self.have_list.union(&Spore::from_range(range));

        trace!(
            doc_type = D::TYPE_PREFIX,
            id = %content_id,
            "Stored document"
        );

        Ok(content_id)
    }

    /// Get a document by content ID.
    pub fn get<D: Document>(&self, content_id: &ContentId) -> Result<Option<D>> {
        let key = self.make_key::<D>(content_id);

        match self.db.get(&key)? {
            Some(bytes) => {
                let doc: D = bincode::deserialize(&bytes)?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Check if a document exists.
    pub fn contains<D: Document>(&self, content_id: &ContentId) -> Result<bool> {
        let key = self.make_key::<D>(content_id);
        Ok(self.db.get(&key)?.is_some())
    }

    /// List all documents of a given type.
    pub fn list<D: Document>(&self) -> Result<Vec<D>> {
        let prefix = format!("{}:", D::TYPE_PREFIX);
        let mut docs = Vec::new();

        let iter = db_prefix_iterator(&self.db, &prefix);
        for item in iter {
            let (_, value) = item?;
            let doc: D = bincode::deserialize(&value)?;
            docs.push(doc);
        }

        Ok(docs)
    }

    /// Delete a document by content ID.
    ///
    /// Note: In a CRDT context, deletion is usually modeled as a tombstone,
    /// not physical deletion. Use with caution.
    pub fn delete<D: Document>(&mut self, content_id: &ContentId) -> Result<()> {
        let key = self.make_key::<D>(content_id);
        self.db.delete(&key)?;

        // Update SPORE HaveList
        let range = point_range(content_id);
        self.have_list = self.have_list.subtract(&Spore::from_range(range));

        trace!(
            doc_type = D::TYPE_PREFIX,
            id = %content_id,
            "Deleted document"
        );

        Ok(())
    }

    /// Apply a batch of document operations atomically.
    pub fn batch<D: Document>(&mut self, ops: Vec<BatchOp<D>>) -> Result<()> {
        let mut batch = WriteBatch::default();

        for op in ops {
            match op {
                BatchOp::Put(doc) => {
                    let content_id = doc.content_id();
                    let key = self.make_key::<D>(&content_id);
                    let bytes = bincode::serialize(&doc)?;
                    batch.put(&key, &bytes);

                    let range = point_range(&content_id);
                    self.have_list = self.have_list.union(&Spore::from_range(range));
                }
                BatchOp::Delete(content_id) => {
                    let key = self.make_key::<D>(&content_id);
                    batch.delete(&key);

                    let range = point_range(&content_id);
                    self.have_list = self.have_list.subtract(&Spore::from_range(range));
                }
            }
        }

        self.db.write(batch)?;
        Ok(())
    }

    /// Compute what documents we have that a peer doesn't.
    ///
    /// This is the SPORE XOR diff - O(k) where k = differing ranges.
    pub fn diff(&self, peer_have: &Spore) -> Spore {
        self.have_list.xor(peer_have)
    }

    /// Get documents that exist in a SPORE range.
    pub fn get_in_range<D: Document>(&self, range: &Spore) -> Result<Vec<D>> {
        let mut docs = Vec::new();

        for doc in self.list::<D>()? {
            let u256 = content_id_to_u256(&doc.content_id());
            if range.covers(&u256) {
                docs.push(doc);
            }
        }

        Ok(docs)
    }

    fn make_key<D: Document>(&self, content_id: &ContentId) -> String {
        format!("{}:{}", D::TYPE_PREFIX, content_id.to_hex())
    }
}

/// Batch operation for atomic updates.
pub enum BatchOp<D: Document> {
    Put(D),
    Delete(ContentId),
}

/// Helper to iterate over keys with a prefix
fn db_prefix_iterator<'a>(
    db: &'a DB,
    prefix: &str,
) -> impl Iterator<Item = std::result::Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a {
    let prefix_bytes = prefix.as_bytes().to_vec();
    db.iterator(rocksdb::IteratorMode::From(
        &prefix_bytes,
        rocksdb::Direction::Forward,
    ))
    .take_while(move |item| {
        item.as_ref()
            .map(|(k, _)| k.starts_with(&prefix_bytes))
            .unwrap_or(false)
    })
}

/// A typed collection handle for working with a specific document type.
///
/// This provides a cleaner API when working with a single document type.
pub struct Collection<'a, D: Document> {
    store: &'a mut DocumentStore,
    _phantom: PhantomData<D>,
}

impl<'a, D: Document> Collection<'a, D> {
    pub fn new(store: &'a mut DocumentStore) -> Self {
        Self {
            store,
            _phantom: PhantomData,
        }
    }

    pub fn put(&mut self, doc: &D) -> Result<ContentId> {
        self.store.put(doc)
    }

    pub fn get(&self, content_id: &ContentId) -> Result<Option<D>> {
        self.store.get(content_id)
    }

    pub fn list(&self) -> Result<Vec<D>> {
        self.store.list()
    }

    pub fn delete(&mut self, content_id: &ContentId) -> Result<()> {
        self.store.delete::<D>(content_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_crdt::{CommutativeMerge, AssociativeMerge, IdempotentMerge};
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    /// Test document: a simple set of tags
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct TagDoc {
        id: ContentId,
        tags: BTreeSet<String>,
    }

    impl TagDoc {
        fn new(tags: &[&str]) -> Self {
            let tags: BTreeSet<String> = tags.iter().map(|s| s.to_string()).collect();
            let id = ContentId::hash(&bincode::serialize(&tags).unwrap());
            Self { id, tags }
        }
    }

    impl TotalMerge for TagDoc {
        fn merge(&self, other: &Self) -> Self {
            let tags: BTreeSet<String> = self.tags.union(&other.tags).cloned().collect();
            Self {
                id: self.id, // Keep original ID
                tags,
            }
        }
    }

    impl CommutativeMerge for TagDoc {}
    impl AssociativeMerge for TagDoc {}
    impl IdempotentMerge for TagDoc {}

    impl Document for TagDoc {
        const TYPE_PREFIX: &'static str = "tag";

        fn content_id(&self) -> ContentId {
            self.id
        }
    }

    #[test]
    fn test_put_and_get() {
        let dir = tempdir().unwrap();
        let mut store = DocumentStore::open(dir.path()).unwrap();

        let doc = TagDoc::new(&["rust", "crdt"]);
        let id = store.put(&doc).unwrap();

        let retrieved: Option<TagDoc> = store.get(&id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tags, doc.tags);
    }

    #[test]
    fn test_merge_on_put() {
        let dir = tempdir().unwrap();
        let mut store = DocumentStore::open(dir.path()).unwrap();

        // First put
        let doc1 = TagDoc::new(&["rust"]);
        let id = store.put(&doc1).unwrap();

        // Second put with same ID but different tags - should merge
        let mut doc2 = doc1.clone();
        doc2.tags.insert("crdt".to_string());
        store.put(&doc2).unwrap();

        // Should have both tags
        let retrieved: TagDoc = store.get(&id).unwrap().unwrap();
        assert!(retrieved.tags.contains("rust"));
        assert!(retrieved.tags.contains("crdt"));
    }

    #[test]
    fn test_list() {
        let dir = tempdir().unwrap();
        let mut store = DocumentStore::open(dir.path()).unwrap();

        let doc1 = TagDoc::new(&["a"]);
        let doc2 = TagDoc::new(&["b"]);
        let doc3 = TagDoc::new(&["c"]);

        store.put(&doc1).unwrap();
        store.put(&doc2).unwrap();
        store.put(&doc3).unwrap();

        let all: Vec<TagDoc> = store.list().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_spore_tracking() {
        let dir = tempdir().unwrap();
        let mut store = DocumentStore::open(dir.path()).unwrap();

        assert_eq!(store.have_list().range_count(), 0);

        let doc = TagDoc::new(&["test"]);
        store.put(&doc).unwrap();

        // HaveList should now contain one range
        assert!(store.have_list().range_count() > 0);

        // The document's ID should be covered
        let u256 = U256::from_be_bytes(doc.content_id().as_bytes());
        assert!(store.have_list().covers(&u256));
    }

    #[test]
    fn test_diff() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();

        let mut store1 = DocumentStore::open(dir1.path()).unwrap();
        let mut store2 = DocumentStore::open(dir2.path()).unwrap();

        // Both have doc_a
        let doc_a = TagDoc::new(&["a"]);
        store1.put(&doc_a).unwrap();
        store2.put(&doc_a).unwrap();

        // Only store1 has doc_b
        let doc_b = TagDoc::new(&["b"]);
        store1.put(&doc_b).unwrap();

        // Only store2 has doc_c
        let doc_c = TagDoc::new(&["c"]);
        store2.put(&doc_c).unwrap();

        // Diff should show differences
        let diff = store1.diff(store2.have_list());

        // doc_b should be in diff (store1 has, store2 doesn't)
        let b_u256 = U256::from_be_bytes(doc_b.content_id().as_bytes());
        assert!(diff.covers(&b_u256));

        // doc_a should NOT be in diff (both have it)
        let a_u256 = U256::from_be_bytes(doc_a.content_id().as_bytes());
        assert!(!diff.covers(&a_u256));
    }
}
