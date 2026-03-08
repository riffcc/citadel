//! DHT state management.

use crate::{DhtEntry, DhtKey, DhtValue};
use std::collections::HashMap;

/// Local DHT state.
///
/// Stores entries that this node is responsible for based on its
/// position in the hexagonal mesh.
#[derive(Debug, Default)]
pub struct DhtState {
    /// Entries stored locally.
    entries: HashMap<DhtKey, DhtEntry>,
}

impl DhtState {
    /// Create empty state.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get an entry by key.
    pub fn get(&self, key: &DhtKey) -> Option<&DhtEntry> {
        self.entries.get(key)
    }

    /// Put an entry (with current timestamp).
    pub fn put(&mut self, key: DhtKey, value: DhtValue) -> bool {
        let entry = DhtEntry::new(key, value);
        self.put_entry(entry)
    }

    /// Put an entry with explicit timestamp.
    pub fn put_with_timestamp(&mut self, key: DhtKey, value: DhtValue, timestamp: u64) -> bool {
        let entry = DhtEntry::with_timestamp(key, value, timestamp);
        self.put_entry(entry)
    }

    /// Put a pre-constructed entry.
    /// Returns true if the entry was newer and stored.
    pub fn put_entry(&mut self, entry: DhtEntry) -> bool {
        let key = entry.key;
        match self.entries.get_mut(&key) {
            Some(existing) => existing.merge(entry),
            None => {
                self.entries.insert(key, entry);
                true
            }
        }
    }

    /// Delete an entry.
    pub fn delete(&mut self, key: &DhtKey) -> Option<DhtEntry> {
        self.entries.remove(key)
    }

    /// Merge another state into this one.
    /// Uses last-write-wins semantics.
    /// Returns number of entries updated.
    pub fn merge(&mut self, other: DhtState) -> usize {
        let mut updated = 0;
        for (_key, entry) in other.entries {
            if self.put_entry(entry) {
                updated += 1;
            }
        }
        updated
    }

    /// Get all entries (for synchronization).
    pub fn entries(&self) -> impl Iterator<Item = &DhtEntry> {
        self.entries.values()
    }

    /// Get entries newer than a timestamp.
    pub fn entries_since(&self, timestamp: u64) -> impl Iterator<Item = &DhtEntry> {
        self.entries
            .values()
            .filter(move |e| e.timestamp > timestamp)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = &DhtKey> {
        self.entries.keys()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate with prefix filter.
    /// Note: This is O(n) - use sparingly.
    pub fn iter_prefix<'a>(&'a self, prefix_bytes: &'a [u8]) -> impl Iterator<Item = &'a DhtEntry> {
        self.entries
            .values()
            .filter(move |e| e.key.0.starts_with(prefix_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_key;

    #[test]
    fn put_and_get() {
        let mut state = DhtState::new();
        let key = hash_key(b"test");

        state.put(key, "value".into());

        let entry = state.get(&key).unwrap();
        assert_eq!(entry.value.as_str(), Some("value"));
    }

    #[test]
    fn put_overwrites_older() {
        let mut state = DhtState::new();
        let key = hash_key(b"test");

        state.put_with_timestamp(key, "old".into(), 100);
        state.put_with_timestamp(key, "new".into(), 200);

        let entry = state.get(&key).unwrap();
        assert_eq!(entry.value.as_str(), Some("new"));
    }

    #[test]
    fn put_keeps_newer() {
        let mut state = DhtState::new();
        let key = hash_key(b"test");

        state.put_with_timestamp(key, "new".into(), 200);
        let updated = state.put_with_timestamp(key, "old".into(), 100);

        assert!(!updated);
        let entry = state.get(&key).unwrap();
        assert_eq!(entry.value.as_str(), Some("new"));
    }

    #[test]
    fn merge_states() {
        let mut state1 = DhtState::new();
        let mut state2 = DhtState::new();

        let key1 = hash_key(b"key1");
        let key2 = hash_key(b"key2");
        let key3 = hash_key(b"key3");

        // state1 has key1 (newer) and key2
        state1.put_with_timestamp(key1, "state1-new".into(), 200);
        state1.put_with_timestamp(key2, "state1".into(), 100);

        // state2 has key1 (older) and key3
        state2.put_with_timestamp(key1, "state2-old".into(), 100);
        state2.put_with_timestamp(key3, "state2".into(), 100);

        // Merge state2 into state1
        let updated = state1.merge(state2);

        // key3 should be added (1 update)
        // key1 should keep state1's value (0 updates from key1)
        assert_eq!(updated, 1);
        assert_eq!(state1.len(), 3);
        assert_eq!(
            state1.get(&key1).unwrap().value.as_str(),
            Some("state1-new")
        );
        assert_eq!(state1.get(&key3).unwrap().value.as_str(), Some("state2"));
    }

    #[test]
    fn entries_since() {
        let mut state = DhtState::new();

        state.put_with_timestamp(hash_key(b"old"), "old".into(), 100);
        state.put_with_timestamp(hash_key(b"new"), "new".into(), 200);
        state.put_with_timestamp(hash_key(b"newer"), "newer".into(), 300);

        let recent: Vec<_> = state.entries_since(150).collect();
        assert_eq!(recent.len(), 2);
    }
}
