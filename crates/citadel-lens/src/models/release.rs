//! Release model - albums, movies, TV series, etc.

use serde::{Deserialize, Serialize};

/// CRDT-ready version info for SPORE sync.
///
/// Designed for Last-Writer-Wins Register (LWWRegister) CRDT semantics:
/// - Lamport timestamp for causal ordering
/// - Node ID for deterministic tiebreaking
/// - Content hash for SPORE range positioning
/// - Replaces field for automatic garbage collection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    /// Lamport timestamp - logical clock for causal ordering
    /// Incremented on each update, max(local, received) + 1 on merge
    #[serde(default)]
    pub lamport: u64,

    /// Node ID that last modified this release (first 8 bytes of pubkey hash)
    /// Used for deterministic tiebreaking when lamport timestamps are equal
    #[serde(default, with = "hex_bytes")]
    pub node_id: [u8; 8],

    /// Blake3 hash of serialized content (excludes version_info itself)
    /// Determines position in SPORE range: hash(id || content_hash)
    #[serde(default, with = "hex_bytes_32")]
    pub content_hash: [u8; 32],

    /// Hash of the previous version this replaces (for automatic GC)
    /// When receiving, if replaces matches our version, replace it
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_hex_bytes_32")]
    pub replaces: Option<[u8; 32]>,
}

impl VersionInfo {
    /// Create new version info for initial release
    pub fn new(node_id: [u8; 8], content_hash: [u8; 32]) -> Self {
        Self {
            lamport: 1,
            node_id,
            content_hash,
            replaces: None,
        }
    }

    /// Create updated version info (increments lamport, sets replaces)
    pub fn update(&self, node_id: [u8; 8], new_content_hash: [u8; 32]) -> Self {
        Self {
            lamport: self.lamport + 1,
            node_id,
            content_hash: new_content_hash,
            replaces: Some(self.content_hash),
        }
    }

    /// CRDT merge: returns true if other wins (should replace self)
    pub fn should_replace_with(&self, other: &VersionInfo) -> bool {
        if other.lamport > self.lamport {
            return true;
        }
        if other.lamport == self.lamport {
            // Deterministic tiebreak: higher content_hash wins
            return other.content_hash > self.content_hash;
        }
        false
    }

    /// Compute SPORE position from release ID and content hash
    pub fn spore_position(&self, release_id: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(release_id.as_bytes());
        hasher.update(&self.content_hash);
        *hasher.finalize().as_bytes()
    }
}

// Hex serialization helpers for byte arrays
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 8 {
            return Err(serde::de::Error::custom("expected 8 bytes"));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod option_hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where D: Deserializer<'de> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// A release in the Lens ecosystem.
///
/// Represents any distributable content unit: music album, movie, TV series,
/// book, game, etc.
///
/// Field names match Flagship's expected format (camelCase with legacy naming)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    /// Unique identifier (Blake3 hash of content)
    pub id: String,

    /// Human-readable title (serialized as "name" for Flagship compatibility)
    #[serde(rename = "name", alias = "title")]
    pub title: String,

    /// Creator/artist/director (serialized as "postedBy" for Flagship compatibility)
    #[serde(rename = "postedBy", alias = "creator")]
    pub creator: Option<String>,

    /// Release year
    pub year: Option<u32>,

    /// Category ID (links to Category)
    #[serde(rename = "categoryId", alias = "category_id")]
    pub category_id: String,

    /// Category slug (URL-friendly identifier, defaults to category_id)
    #[serde(default)]
    pub category_slug: Option<String>,

    /// Content Identifier (CID) for thumbnail image
    #[serde(rename = "thumbnailCID", alias = "thumbnail_cid")]
    pub thumbnail_cid: Option<String>,

    /// Content Identifier (CID) for the actual content
    #[serde(rename = "contentCID", alias = "content_cid")]
    pub content_cid: Option<String>,

    /// Description/synopsis
    pub description: Option<String>,

    /// Tags for categorization and search
    #[serde(default)]
    pub tags: Vec<String>,

    /// Schema version for forward compatibility
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Site address (ZeroNet/IPNS address, optional)
    #[serde(default, alias = "site_address")]
    pub site_address: Option<String>,

    /// Creation timestamp (ISO 8601)
    #[serde(default, alias = "created_at")]
    pub created_at: Option<String>,

    /// Metadata (arbitrary key-value pairs)
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,

    /// CRDT version info for SPORE sync (managed by Citadel, not clients)
    /// Contains lamport timestamp, node ID, content hash, and replaces pointer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

impl Release {
    /// Create a new release with required fields.
    pub fn new(id: String, title: String, category_id: String) -> Self {
        let category_slug = Some(category_id.clone());
        Self {
            id,
            title,
            creator: None,
            year: None,
            category_slug,
            category_id,
            thumbnail_cid: None,
            content_cid: None,
            description: None,
            tags: Vec::new(),
            schema_version: default_schema_version(),
            site_address: None,
            created_at: None,
            metadata: None,
            version_info: None,
        }
    }

    /// Generate ID from content hash.
    pub fn generate_id(content: &[u8]) -> String {
        let hash = blake3::hash(content);
        hex::encode(hash.as_bytes())
    }

    /// DHT key prefix for releases.
    pub const DHT_PREFIX: &'static str = "release";

    /// Get the DHT key for this release.
    pub fn dht_key(&self) -> citadel_dht::DhtKey {
        citadel_dht::hash_prefixed_key(Self::DHT_PREFIX, &self.id)
    }

    /// Ensure all optional fields have sensible defaults for API responses.
    /// This fills in categorySlug from categoryId if not set.
    pub fn with_defaults(mut self) -> Self {
        if self.category_slug.is_none() {
            self.category_slug = Some(self.category_id.clone());
        }
        self
    }

    /// Compute content hash (excludes version_info to avoid circular dependency)
    pub fn compute_content_hash(&self) -> [u8; 32] {
        // Create a copy without version_info for hashing
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.title.as_bytes());
        if let Some(ref creator) = self.creator {
            hasher.update(creator.as_bytes());
        }
        if let Some(year) = self.year {
            hasher.update(&year.to_le_bytes());
        }
        hasher.update(self.category_id.as_bytes());
        if let Some(ref thumb) = self.thumbnail_cid {
            hasher.update(thumb.as_bytes());
        }
        if let Some(ref content) = self.content_cid {
            hasher.update(content.as_bytes());
        }
        if let Some(ref desc) = self.description {
            hasher.update(desc.as_bytes());
        }
        for tag in &self.tags {
            hasher.update(tag.as_bytes());
        }
        if let Some(ref meta) = self.metadata {
            hasher.update(meta.to_string().as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Get SPORE position for this release (uses version_info if available, else computes)
    pub fn spore_position(&self) -> [u8; 32] {
        if let Some(ref vi) = self.version_info {
            vi.spore_position(&self.id)
        } else {
            // Fallback: hash(id || content_hash)
            let content_hash = self.compute_content_hash();
            let mut hasher = blake3::Hasher::new();
            hasher.update(self.id.as_bytes());
            hasher.update(&content_hash);
            *hasher.finalize().as_bytes()
        }
    }

    /// Initialize version_info for a new release (call before first save)
    pub fn init_version(&mut self, node_id: [u8; 8]) {
        let content_hash = self.compute_content_hash();
        self.version_info = Some(VersionInfo::new(node_id, content_hash));
    }

    /// Update version_info for an edited release (call before save)
    pub fn update_version(&mut self, node_id: [u8; 8]) {
        let new_content_hash = self.compute_content_hash();
        if let Some(ref old_vi) = self.version_info {
            self.version_info = Some(old_vi.update(node_id, new_content_hash));
        } else {
            // No previous version, initialize
            self.version_info = Some(VersionInfo::new(node_id, new_content_hash));
        }
    }

    /// CRDT merge: returns true if incoming release should replace this one
    pub fn should_replace_with(&self, other: &Release) -> bool {
        match (&self.version_info, &other.version_info) {
            (Some(self_vi), Some(other_vi)) => self_vi.should_replace_with(other_vi),
            (None, Some(_)) => true,  // We have no version, incoming does - accept
            (Some(_), None) => false, // We have version, incoming doesn't - keep ours
            (None, None) => false,    // Neither has version - keep existing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_release() {
        let release = Release::new(
            "abc123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );
        assert_eq!(release.id, "abc123");
        assert_eq!(release.title, "Test Album");
        assert_eq!(release.category_id, "music");
        assert_eq!(release.schema_version, "1.0.0");
    }

    #[test]
    fn generate_id_deterministic() {
        let id1 = Release::generate_id(b"test content");
        let id2 = Release::generate_id(b"test content");
        assert_eq!(id1, id2);
    }

    #[test]
    fn serialize_deserialize() {
        let release = Release {
            id: "test".to_string(),
            title: "Test".to_string(),
            creator: Some("Artist".to_string()),
            year: Some(2024),
            category_id: "music".to_string(),
            category_slug: Some("music".to_string()),
            thumbnail_cid: None,
            content_cid: Some("QmContentCid".to_string()),
            description: Some("A test release".to_string()),
            tags: vec!["rock".to_string(), "indie".to_string()],
            schema_version: "1.0.0".to_string(),
            site_address: None,
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            metadata: None,
        };

        let json = serde_json::to_string(&release).unwrap();
        let parsed: Release = serde_json::from_str(&json).unwrap();
        assert_eq!(release, parsed);
    }
}
