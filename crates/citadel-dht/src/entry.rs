//! DHT entry types.

use std::time::{SystemTime, UNIX_EPOCH};

/// A 32-byte DHT key (Blake3 hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhtKey(pub [u8; 32]);

impl DhtKey {
    /// Create a key from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Get the first 8 bytes as u64 (for slot mapping).
    pub fn prefix_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().unwrap())
    }
}

impl std::fmt::Display for DhtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 hex chars
        write!(f, "{}...", &self.to_hex()[..8])
    }
}

/// DHT value - arbitrary bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtValue(pub Vec<u8>);

impl DhtValue {
    /// Create from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Create from string.
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to get as UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl From<Vec<u8>> for DhtValue {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&str> for DhtValue {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for DhtValue {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

/// A DHT entry with value and timestamp.
#[derive(Debug, Clone)]
pub struct DhtEntry {
    /// The key.
    pub key: DhtKey,
    /// The value.
    pub value: DhtValue,
    /// Unix timestamp in milliseconds (for last-write-wins).
    pub timestamp: u64,
}

impl DhtEntry {
    /// Create a new entry with current timestamp.
    pub fn new(key: DhtKey, value: DhtValue) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Self {
            key,
            value,
            timestamp,
        }
    }

    /// Create an entry with explicit timestamp.
    pub fn with_timestamp(key: DhtKey, value: DhtValue, timestamp: u64) -> Self {
        Self {
            key,
            value,
            timestamp,
        }
    }

    /// Check if this entry is newer than another.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.timestamp > other.timestamp
    }

    /// Merge with another entry, keeping the newer one.
    /// Returns true if self was updated.
    pub fn merge(&mut self, other: Self) -> bool {
        if other.is_newer_than(self) {
            *self = other;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_roundtrip() {
        let key = DhtKey::from_bytes([1u8; 32]);
        let hex = key.to_hex();
        let parsed = DhtKey::from_hex(&hex).unwrap();
        assert_eq!(key, parsed);
    }

    #[test]
    fn entry_newer_check() {
        let key = DhtKey::from_bytes([0u8; 32]);
        let old = DhtEntry::with_timestamp(key, "old".into(), 100);
        let new = DhtEntry::with_timestamp(key, "new".into(), 200);

        assert!(new.is_newer_than(&old));
        assert!(!old.is_newer_than(&new));
    }

    #[test]
    fn entry_merge() {
        let key = DhtKey::from_bytes([0u8; 32]);
        let mut entry = DhtEntry::with_timestamp(key, "old".into(), 100);
        let newer = DhtEntry::with_timestamp(key, "new".into(), 200);

        assert!(entry.merge(newer));
        assert_eq!(entry.value.as_str(), Some("new"));
        assert_eq!(entry.timestamp, 200);
    }

    #[test]
    fn entry_merge_keeps_newer() {
        let key = DhtKey::from_bytes([0u8; 32]);
        let mut entry = DhtEntry::with_timestamp(key, "new".into(), 200);
        let older = DhtEntry::with_timestamp(key, "old".into(), 100);

        assert!(!entry.merge(older));
        assert_eq!(entry.value.as_str(), Some("new"));
        assert_eq!(entry.timestamp, 200);
    }
}
