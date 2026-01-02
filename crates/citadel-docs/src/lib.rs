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
//! Documents are stored in ReDB with:
//! - Table: One table per document type (named by TYPE_PREFIX)
//! - Key: `[u8; 32]` ContentId bytes (CID-native)
//! - Value: JSON-serialized document
//!
//! ### SPORE Integration
//!
//! The DocumentStore maintains a SPORE HaveList of all stored documents.
//! This enables O(k) sync where k = documents differing between peers.
//!
//! From `proofs/CitadelProofs/Spore.lean`:
//! - **XOR Cancellation**: Matching documents cancel in XOR. If nodes have 99% overlap,
//!   only 1% shows up in the diff. At 100% convergence, sync cost is ZERO.
//! - **Optimality**: SPORE size ∝ boundary transitions, not data size. One range
//!   covering 2^255 values costs the same as one range covering 1 value: 512 bits.
//!
//! ### Rich Merge Semantics (NOT LWW)
//!
//! Documents use **rich semantic merges**, NOT Last-Writer-Wins. For a document
//! with multiple field types, the merge is field-by-field:
//!
//! | Field Type | Merge Strategy | Example |
//! |------------|----------------|---------|
//! | Counter    | `max(a, b)`    | views, clicks |
//! | Set        | `union(a, b)`  | tags, regions |
//! | Boolean    | `or(a, b)`     | promoted |
//! | Timestamp  | `min(a, b)`    | created_at |
//! | Time window| `(min(start), max(end))` | active period |
//!
//! **LWW loses concurrent edits. Rich merges preserve ALL data.**
//!
//! ## Proven Properties
//!
//! From `proofs/CitadelProofs/CRDT/`:
//! - `merge_cannot_disagree` - Same inputs → same outputs
//! - `no_merge_failure` - Merge is total, cannot fail
//! - `full_sync_convergence` - Same operations → same state
//! - `crdt_bilateral` - All CRDT merges have the bilateral property
//! - `convergence_dominates` - At 100% convergence, XOR is empty (zero sync cost)
//!
//! ## The Bilateral Property
//!
//! The "bilateral property" means: if YOU compute `merge(a, b) = result`, then
//! EVERYONE computing `merge(a, b)` gets the SAME result. This is trivially true
//! for pure functions, but profoundly useful:
//!
//! **No network needed. Offline-first. Instantly bilateral.**
//!
//! Traditional TGP (network): `C → D → T → Q` (4 phases, latency)
//! Bilateral CRDT (local):   `C=D=T=Q` (1 computation, instant)

use citadel_crdt::{ContentId, TotalMerge};
use citadel_spore::{Range256, Spore, U256};
use redb::{Database, ReadableTable, ReadableDatabase, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, trace};

/// Index table for SPORE tracking - stores all ContentIds
/// Key: ContentId bytes, Value: empty (just presence marker)
const CONTENT_INDEX: TableDefinition<&[u8; 32], ()> = TableDefinition::new("_content_index");

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
    Serialization(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid document format")]
    InvalidFormat,
}

impl From<redb::DatabaseError> for DocError {
    fn from(e: redb::DatabaseError) -> Self {
        DocError::Storage(e.to_string())
    }
}

impl From<redb::TransactionError> for DocError {
    fn from(e: redb::TransactionError) -> Self {
        DocError::Storage(e.to_string())
    }
}

impl From<redb::TableError> for DocError {
    fn from(e: redb::TableError) -> Self {
        DocError::Storage(e.to_string())
    }
}

impl From<redb::StorageError> for DocError {
    fn from(e: redb::StorageError) -> Self {
        DocError::Storage(e.to_string())
    }
}

impl From<redb::CommitError> for DocError {
    fn from(e: redb::CommitError) -> Self {
        DocError::Storage(e.to_string())
    }
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
        let bytes = serde_json::to_vec(self).expect("serialization cannot fail");
        ContentId::hash(&bytes)
    }
}

/// Persistent document store backed by ReDB.
///
/// Stores documents with automatic SPORE tracking for sync.
/// Uses CID-native keys: `[u8; 32]` ContentId bytes.
pub struct DocumentStore {
    db: Arc<Database>,
    /// SPORE HaveList tracking all stored document IDs
    have_list: Spore,
}

impl DocumentStore {
    /// Open or create a document store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path)?;

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

    /// Rebuild SPORE HaveList by scanning the content index table
    fn rebuild_havelist(db: &Database) -> Result<Spore> {
        let mut ranges = Vec::new();

        let read_txn = db.begin_read()?;

        // Scan the content index table (stores all ContentIds)
        let table = match read_txn.open_table(CONTENT_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Spore::from_ranges(vec![])),
            Err(e) => return Err(DocError::from(e)),
        };

        for item in table.iter()? {
            let (key, _): (redb::AccessGuard<&[u8; 32]>, redb::AccessGuard<()>) = item?;
            let key_bytes: [u8; 32] = *key.value();
            let content_id = ContentId::from_bytes(key_bytes);
            ranges.push(point_range(&content_id));
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
    ///
    /// Returns `(content_id, changed)` where `changed` is true if the stored
    /// document differs from what was previously stored (or is new).
    pub fn put<D: Document>(&mut self, doc: &D) -> Result<(ContentId, bool)> {
        let content_id = doc.content_id();
        let key_bytes: [u8; 32] = *content_id.as_bytes();

        let write_txn = self.db.begin_write()?;
        let changed = {
            // Open table by TYPE_PREFIX (one table per document type)
            let table_def: TableDefinition<&[u8; 32], &[u8]> =
                TableDefinition::new(D::TYPE_PREFIX);
            let mut table = write_txn.open_table(table_def)?;

            // Check for existing document
            let (merged, changed) = if let Some(existing_guard) = table.get(&key_bytes)? {
                let existing: D = serde_json::from_slice(existing_guard.value())?;
                // TotalMerge - this CANNOT fail (proven in Lean)
                let merged = existing.merge(doc);
                let merged_bytes = serde_json::to_vec(&merged)?;
                // Changed if merged differs from existing
                let changed = merged_bytes.as_slice() != existing_guard.value();
                (merged, changed)
            } else {
                // New document = always changed
                (doc.clone(), true)
            };

            // Serialize and store
            let bytes = serde_json::to_vec(&merged)?;
            table.insert(&key_bytes, bytes.as_slice())?;

            // Update content index for SPORE tracking
            let mut index_table = write_txn.open_table(CONTENT_INDEX)?;
            index_table.insert(&key_bytes, ())?;

            changed
        };
        write_txn.commit()?;

        // Update SPORE HaveList
        let range = point_range(&content_id);
        self.have_list = self.have_list.union(&Spore::from_range(range));

        trace!(
            doc_type = D::TYPE_PREFIX,
            id = %content_id,
            changed = changed,
            "Stored document"
        );

        Ok((content_id, changed))
    }

    /// Get a document by content ID.
    pub fn get<D: Document>(&self, content_id: &ContentId) -> Result<Option<D>> {
        let key_bytes: [u8; 32] = *content_id.as_bytes();
        let table_def: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new(D::TYPE_PREFIX);

        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DocError::from(e)),
        };

        match table.get(&key_bytes)? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                let doc: D = serde_json::from_slice(bytes)?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Check if a document exists.
    pub fn contains<D: Document>(&self, content_id: &ContentId) -> Result<bool> {
        let key_bytes: [u8; 32] = *content_id.as_bytes();
        let table_def: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new(D::TYPE_PREFIX);

        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(DocError::from(e)),
        };

        let result: Option<redb::AccessGuard<&[u8]>> = table.get(&key_bytes)?;
        Ok(result.is_some())
    }

    /// List all documents of a given type.
    pub fn list<D: Document>(&self) -> Result<Vec<D>> {
        let table_def: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new(D::TYPE_PREFIX);

        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DocError::from(e)),
        };

        let mut docs = Vec::new();
        for item in table.iter()? {
            let (_, value): (redb::AccessGuard<&[u8; 32]>, redb::AccessGuard<&[u8]>) = item?;
            let bytes: &[u8] = value.value();
            let doc: D = serde_json::from_slice(bytes)?;
            docs.push(doc);
        }

        Ok(docs)
    }

    /// Delete a document by content ID.
    ///
    /// Note: In a CRDT context, deletion is usually modeled as a tombstone,
    /// not physical deletion. Use with caution.
    pub fn delete<D: Document>(&mut self, content_id: &ContentId) -> Result<()> {
        let key_bytes: [u8; 32] = *content_id.as_bytes();
        let table_def: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new(D::TYPE_PREFIX);

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            table.remove(&key_bytes)?;

            // Remove from content index
            let mut index_table = write_txn.open_table(CONTENT_INDEX)?;
            index_table.remove(&key_bytes)?;
        }
        write_txn.commit()?;

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
        let table_def: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new(D::TYPE_PREFIX);

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            let mut index_table = write_txn.open_table(CONTENT_INDEX)?;

            for op in ops {
                match op {
                    BatchOp::Put(doc) => {
                        let content_id = doc.content_id();
                        let key_bytes: [u8; 32] = *content_id.as_bytes();
                        let bytes = serde_json::to_vec(&doc)?;
                        table.insert(&key_bytes, bytes.as_slice())?;
                        index_table.insert(&key_bytes, ())?;

                        let range = point_range(&content_id);
                        self.have_list = self.have_list.union(&Spore::from_range(range));
                    }
                    BatchOp::Delete(content_id) => {
                        let key_bytes: [u8; 32] = *content_id.as_bytes();
                        table.remove(&key_bytes)?;
                        index_table.remove(&key_bytes)?;

                        let range = point_range(&content_id);
                        self.have_list = self.have_list.subtract(&Spore::from_range(range));
                    }
                }
            }
        }

        write_txn.commit()?;
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
}

/// Batch operation for atomic updates.
pub enum BatchOp<D: Document> {
    Put(D),
    Delete(ContentId),
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

    pub fn put(&mut self, doc: &D) -> Result<(ContentId, bool)> {
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
    use citadel_crdt::{AssociativeMerge, CommutativeMerge, IdempotentMerge};
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
            let id = ContentId::hash(&serde_json::to_vec(&tags).unwrap());
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
        let mut store = DocumentStore::open(dir.path().join("docs.redb")).unwrap();

        let doc = TagDoc::new(&["rust", "crdt"]);
        let (id, _) = store.put(&doc).unwrap();

        let retrieved: Option<TagDoc> = store.get(&id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tags, doc.tags);
    }

    #[test]
    fn test_merge_on_put() {
        let dir = tempdir().unwrap();
        let mut store = DocumentStore::open(dir.path().join("docs.redb")).unwrap();

        // First put
        let doc1 = TagDoc::new(&["rust"]);
        let (id, _) = store.put(&doc1).unwrap();

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
        let mut store = DocumentStore::open(dir.path().join("docs.redb")).unwrap();

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
        let mut store = DocumentStore::open(dir.path().join("docs.redb")).unwrap();

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

        let mut store1 = DocumentStore::open(dir1.path().join("docs.redb")).unwrap();
        let mut store2 = DocumentStore::open(dir2.path().join("docs.redb")).unwrap();

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
