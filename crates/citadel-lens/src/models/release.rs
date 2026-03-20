//! Release model - albums, movies, TV series, etc.
//!
//! ## CRDT Semantics
//!
//! Release uses **LWW (Last-Writer-Wins)** merge based on `modified_at`.
//!
//! This is appropriate because:
//! - Release content is typically edited by a single owner
//! - Concurrent edits are rare
//! - Later edit = correct state
//!
//! | Field Type | Merge Strategy | Fields |
//! |------------|----------------|--------|
//! | LWW        | later modified_at wins | all content and moderation fields |
//! | Timestamp  | min | created_at |
//!
//! **Future**: Can upgrade to rich merges (union for tags, etc.) by changing merge() impl.

use citadel_crdt::{AssociativeMerge, CommutativeMerge, ContentId, IdempotentMerge, TotalMerge};
use citadel_docs::Document;
use serde::{Deserialize, Serialize};

/// CRDT-friendly version metadata for release updates.
///
/// Kept optional to preserve compatibility with legacy release records and older peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    /// Lamport timestamp for update ordering.
    #[serde(default)]
    pub lamport: u64,

    /// Node ID that produced this version.
    /// Encoded as first 8 bytes of `blake3(public_key)` hex.
    #[serde(default, with = "hex_bytes")]
    pub node_id: [u8; 8],

    /// Hash of serialized content (excluding version_info).
    #[serde(default, with = "hex_bytes_32")]
    pub content_hash: [u8; 32],

    /// Optional pointer to content hash of prior version.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_hex_bytes_32"
    )]
    pub replaces: Option<[u8; 32]>,
}

impl VersionInfo {
    pub fn new(node_id: [u8; 8], content_hash: [u8; 32]) -> Self {
        Self {
            lamport: 1,
            node_id,
            content_hash,
            replaces: None,
        }
    }

    pub fn update(&self, node_id: [u8; 8], content_hash: [u8; 32]) -> Self {
        Self {
            lamport: self.lamport + 1,
            node_id,
            content_hash,
            replaces: Some(self.content_hash),
        }
    }

    pub fn should_replace_with(&self, other: &VersionInfo) -> bool {
        if other.lamport > self.lamport {
            return true;
        }
        if other.lamport == self.lamport {
            return other.node_id > self.node_id;
        }
        false
    }

    /// Deterministic SPORE seed based on release id + content hash.
    pub fn spore_position(&self, release_id: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(release_id.as_bytes());
        hasher.update(&self.content_hash);
        *hasher.finalize().as_bytes()
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
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
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
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
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
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

/// Moderation status for a release.
///
/// Controls visibility in the public catalog:
/// - `Pending`: Awaiting moderator review, only visible to admins
/// - `Approved`: Visible in public catalog (default for backward compatibility)
/// - `Rejected`: Hidden from catalog, with optional rejection reason
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseStatus {
    /// Awaiting moderator review
    Pending,
    /// Approved and visible in public catalog
    #[default]
    Approved,
    /// Rejected by moderator
    Rejected,
    /// Deleted by owner/admin (still exists in mesh, just hidden)
    Deleted,
}

impl std::fmt::Display for ReleaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseStatus::Pending => write!(f, "pending"),
            ReleaseStatus::Approved => write!(f, "approved"),
            ReleaseStatus::Rejected => write!(f, "rejected"),
            ReleaseStatus::Deleted => write!(f, "deleted"),
        }
    }
}

/// A named content variant for a release.
///
/// This lets a single release expose a quality ladder or alternate delivery
/// formats while keeping one primary compatibility CID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseQuality {
    /// Stable tier key, e.g. "master", "lossless", "opus_192", "1080p".
    pub key: String,
    /// CID for this quality variant.
    pub cid: String,
    /// Optional human-friendly label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional container hint, e.g. "mp4", "flac", "opus".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Optional codec hint, e.g. "h264", "aac", "flac".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Optional provenance hint, e.g. "master", "lossless", "transcode".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional quality rank; higher is better.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<i32>,
    /// Optional approximate bitrate in kbps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate_kbps: Option<u32>,
    /// Optional video width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// Optional video height.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
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

    /// Additional named content variants / quality ladder entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub qualities: Vec<ReleaseQuality>,

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

    // === Moderation fields ===
    /// Moderation status (defaults to Approved for backward compatibility)
    #[serde(default)]
    pub status: ReleaseStatus,

    /// Public key of the moderator who approved/rejected this release
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moderated_by: Option<String>,

    /// Timestamp when moderation action was taken (ISO 8601)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moderated_at: Option<String>,

    /// Reason for rejection (if status is Rejected)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,

    /// Last modification timestamp (ISO 8601) - for LWW merge
    #[serde(default = "default_modified_at")]
    pub modified_at: String,

    /// Optional version info used by optional CRDT-aware sync flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

fn default_modified_at() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl Release {
    /// Create a new release with required fields.
    /// Status defaults to Approved for backward compatibility.
    pub fn new(id: String, title: String, category_id: String) -> Self {
        let category_slug = Some(category_id.clone());
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id,
            title,
            creator: None,
            year: None,
            category_slug,
            category_id,
            thumbnail_cid: None,
            content_cid: None,
            qualities: Vec::new(),
            description: None,
            tags: Vec::new(),
            schema_version: default_schema_version(),
            site_address: None,
            created_at: Some(now.clone()),
            metadata: None,
            status: ReleaseStatus::default(),
            moderated_by: None,
            moderated_at: None,
            rejection_reason: None,
            modified_at: now,
            version_info: None,
        }
    }

    /// Create a new release in pending state (for moderation queue).
    pub fn new_pending(id: String, title: String, category_id: String) -> Self {
        let mut release = Self::new(id, title, category_id);
        release.status = ReleaseStatus::Pending;
        release
    }

    /// Mark this release as approved by a moderator.
    pub fn approve(&mut self, moderator_pubkey: &str) {
        self.status = ReleaseStatus::Approved;
        self.moderated_by = Some(moderator_pubkey.to_string());
        self.moderated_at = Some(chrono::Utc::now().to_rfc3339());
        self.rejection_reason = None;
    }

    /// Mark this release as rejected by a moderator.
    pub fn reject(&mut self, moderator_pubkey: &str, reason: Option<String>) {
        self.status = ReleaseStatus::Rejected;
        self.moderated_by = Some(moderator_pubkey.to_string());
        self.moderated_at = Some(chrono::Utc::now().to_rfc3339());
        self.rejection_reason = reason;
    }

    /// Check if this release is visible in the public catalog.
    pub fn is_public(&self) -> bool {
        self.status == ReleaseStatus::Approved
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

    /// Compute content hash for version metadata (excluding version_info).
    pub fn compute_content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.title.as_bytes());
        if let Some(creator) = &self.creator {
            hasher.update(creator.as_bytes());
        }
        if let Some(year) = self.year {
            hasher.update(&year.to_le_bytes());
        }
        hasher.update(self.category_id.as_bytes());
        if let Some(slug) = &self.category_slug {
            hasher.update(slug.as_bytes());
        }
        if let Some(thumb) = &self.thumbnail_cid {
            hasher.update(thumb.as_bytes());
        }
        if let Some(content) = &self.content_cid {
            hasher.update(content.as_bytes());
        }
        for quality in &self.qualities {
            hasher.update(quality.key.as_bytes());
            hasher.update(quality.cid.as_bytes());
            if let Some(label) = &quality.label {
                hasher.update(label.as_bytes());
            }
            if let Some(container) = &quality.container {
                hasher.update(container.as_bytes());
            }
            if let Some(codec) = &quality.codec {
                hasher.update(codec.as_bytes());
            }
            if let Some(source) = &quality.source {
                hasher.update(source.as_bytes());
            }
            if let Some(rank) = quality.rank {
                hasher.update(&rank.to_le_bytes());
            }
            if let Some(bitrate_kbps) = quality.bitrate_kbps {
                hasher.update(&bitrate_kbps.to_le_bytes());
            }
            if let Some(width) = quality.width {
                hasher.update(&width.to_le_bytes());
            }
            if let Some(height) = quality.height {
                hasher.update(&height.to_le_bytes());
            }
        }
        if let Some(description) = &self.description {
            hasher.update(description.as_bytes());
        }
        for tag in &self.tags {
            hasher.update(tag.as_bytes());
        }
        if let Some(site_address) = &self.site_address {
            hasher.update(site_address.as_bytes());
        }
        if let Some(created_at) = &self.created_at {
            hasher.update(created_at.as_bytes());
        }
        if let Some(meta) = &self.metadata {
            hasher.update(meta.to_string().as_bytes());
        }
        hasher.update(self.modified_at.as_bytes());
        hasher.update(self.status.to_string().as_bytes());
        if let Some(moderated_by) = &self.moderated_by {
            hasher.update(moderated_by.as_bytes());
        }
        if let Some(moderated_at) = &self.moderated_at {
            hasher.update(moderated_at.as_bytes());
        }
        if let Some(rejection_reason) = &self.rejection_reason {
            hasher.update(rejection_reason.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Initialize version info for new releases.
    pub fn init_version(&mut self, node_id: [u8; 8]) {
        let content_hash = self.compute_content_hash();
        self.version_info = Some(VersionInfo::new(node_id, content_hash));
    }

    /// Update version info after changes.
    pub fn update_version(&mut self, node_id: [u8; 8]) {
        let content_hash = self.compute_content_hash();
        self.version_info = Some(match self.version_info {
            Some(ref old) => old.update(node_id, content_hash),
            None => VersionInfo::new(node_id, content_hash),
        });
    }

    /// Return deterministic SPORE seed for current release state.
    pub fn spore_position(&self) -> [u8; 32] {
        if let Some(ref vi) = self.version_info {
            vi.spore_position(&self.id)
        } else {
            let content_hash = self.compute_content_hash();
            let mut hasher = blake3::Hasher::new();
            hasher.update(self.id.as_bytes());
            hasher.update(&content_hash);
            *hasher.finalize().as_bytes()
        }
    }

    /// CRDT-style precedence check for versioned records.
    pub fn should_replace_with(&self, other: &Release) -> bool {
        match (&self.version_info, &other.version_info) {
            (Some(self_vi), Some(other_vi)) => self_vi.should_replace_with(other_vi),
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (None, None) => false,
        }
    }

    /// Populate the legacy primary content CID from the quality list if needed.
    pub fn ensure_primary_content_cid(&mut self) {
        if self.content_cid.is_none() {
            self.content_cid = self.primary_quality_cid();
        }
    }

    /// Pick the best available quality CID using explicit rank first, then heuristics.
    pub fn primary_quality_cid(&self) -> Option<String> {
        self.qualities
            .iter()
            .max_by_key(|quality| {
                (
                    quality.rank.unwrap_or_else(|| default_quality_rank(&quality.key)),
                    quality.height.unwrap_or(0),
                    quality.width.unwrap_or(0),
                    quality.bitrate_kbps.unwrap_or(0),
                )
            })
            .map(|quality| quality.cid.clone())
    }
}

fn default_quality_rank(key: &str) -> i32 {
    match key {
        "master" => 10_000,
        "24bit_lossless" => 9_600,
        "lossless" => 9_500,
        "2160p" => 9_400,
        "1440p" => 9_200,
        "1080p" => 9_000,
        "720p" => 8_800,
        "480p" => 8_600,
        "360p" => 8_400,
        "opus_320" => 8_300,
        "opus_256" => 8_200,
        "mp3_320" => 8_100,
        "opus_192" => 8_000,
        "mp3_v0" => 7_950,
        "mobile" => 7_900,
        "opus_128" => 7_800,
        "mp3_256" => 7_700,
        "mp3_192" => 7_600,
        "aac" => 7_500,
        "mp3_128" => 7_400,
        _ => 0,
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
            qualities: vec![ReleaseQuality {
                key: "lossless".to_string(),
                cid: "QmContentCid".to_string(),
                label: Some("Lossless".to_string()),
                container: Some("flac".to_string()),
                codec: Some("flac".to_string()),
                source: Some("master".to_string()),
                rank: Some(9500),
                bitrate_kbps: None,
                width: None,
                height: None,
            }],
            description: Some("A test release".to_string()),
            tags: vec!["rock".to_string(), "indie".to_string()],
            schema_version: "1.0.0".to_string(),
            site_address: None,
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            metadata: None,
            status: ReleaseStatus::Approved,
            moderated_by: None,
            moderated_at: None,
            rejection_reason: None,
            modified_at: "2024-01-01T00:00:00Z".to_string(),
            version_info: None,
        };

        let json = serde_json::to_string(&release).unwrap();
        let parsed: Release = serde_json::from_str(&json).unwrap();
        assert_eq!(release, parsed);
    }

    #[test]
    fn default_status_is_approved() {
        let release = Release::new(
            "abc123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );
        assert_eq!(release.status, ReleaseStatus::Approved);
        assert!(release.is_public());
    }

    #[test]
    fn pending_release_not_public() {
        let release = Release::new_pending(
            "abc123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );
        assert_eq!(release.status, ReleaseStatus::Pending);
        assert!(!release.is_public());
    }

    #[test]
    fn approve_release() {
        let mut release = Release::new_pending(
            "abc123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );
        release.approve("ed25519p/abc123");
        assert_eq!(release.status, ReleaseStatus::Approved);
        assert_eq!(release.moderated_by, Some("ed25519p/abc123".to_string()));
        assert!(release.moderated_at.is_some());
        assert!(release.is_public());
    }

    #[test]
    fn reject_release() {
        let mut release = Release::new_pending(
            "abc123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );
        release.reject("ed25519p/abc123", Some("Low quality".to_string()));
        assert_eq!(release.status, ReleaseStatus::Rejected);
        assert_eq!(release.moderated_by, Some("ed25519p/abc123".to_string()));
        assert_eq!(release.rejection_reason, Some("Low quality".to_string()));
        assert!(!release.is_public());
    }

    #[test]
    fn deserialize_legacy_release_without_status() {
        // Legacy releases without status field should default to Approved
        let json = r#"{
            "id": "test",
            "name": "Test Album",
            "categoryId": "music"
        }"#;
        let release: Release = serde_json::from_str(json).unwrap();
        assert_eq!(release.status, ReleaseStatus::Approved);
        assert!(release.is_public());
    }

    #[test]
    fn test_merge_lww_semantics() {
        // Release uses LWW (Last-Writer-Wins) based on modified_at
        let mut older = Release::new(
            "release-123".to_string(),
            "Original Title".to_string(),
            "music".to_string(),
        );
        older.modified_at = "2025-06-01T00:00:00Z".to_string();
        older.created_at = Some("2025-06-01T00:00:00Z".to_string()); // Earlier created_at
        older.description = Some("Original description".to_string());
        older.tags = vec!["rock".to_string()];

        let mut newer = Release::new(
            "release-123".to_string(),
            "Updated Title".to_string(),
            "music".to_string(),
        );
        newer.modified_at = "2025-06-02T00:00:00Z".to_string();
        newer.description = Some("Updated description".to_string());
        newer.tags = vec!["indie".to_string()];
        newer.created_at = Some("2025-06-02T00:00:00Z".to_string()); // Later created_at

        // Merge: newer modified_at wins for all fields
        let merged = older.merge(&newer);

        // LWW: content from newer
        assert_eq!(merged.title, "Updated Title");
        assert_eq!(merged.description, Some("Updated description".to_string()));
        assert_eq!(merged.tags, vec!["indie".to_string()]);

        // modified_at from newer
        assert_eq!(merged.modified_at, "2025-06-02T00:00:00Z");

        // created_at uses min (preserve original creation time)
        assert_eq!(merged.created_at, Some("2025-06-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_merge_commutativity() {
        let mut a = Release::new(
            "release-123".to_string(),
            "Title A".to_string(),
            "music".to_string(),
        );
        a.modified_at = "2025-06-01T00:00:00Z".to_string();

        let mut b = Release::new(
            "release-123".to_string(),
            "Title B".to_string(),
            "music".to_string(),
        );
        b.modified_at = "2025-06-02T00:00:00Z".to_string();

        // merge(a, b) == merge(b, a)
        let ab = a.merge(&b);
        let ba = b.merge(&a);

        assert_eq!(ab.title, ba.title);
        assert_eq!(ab.modified_at, ba.modified_at);
    }

    #[test]
    fn test_merge_idempotency() {
        let release = Release::new(
            "release-123".to_string(),
            "Test Title".to_string(),
            "music".to_string(),
        );

        // merge(a, a) == a
        let merged = release.merge(&release);

        assert_eq!(merged.title, release.title);
        assert_eq!(merged.modified_at, release.modified_at);
    }

    #[test]
    fn primary_content_cid_falls_back_to_best_quality() {
        let mut release = Release::new(
            "release-123".to_string(),
            "Test Title".to_string(),
            "music".to_string(),
        );
        release.qualities = vec![
            ReleaseQuality {
                key: "opus_192".to_string(),
                cid: "cid-opus".to_string(),
                label: None,
                container: Some("opus".to_string()),
                codec: Some("opus".to_string()),
                source: Some("lossless".to_string()),
                rank: None,
                bitrate_kbps: Some(192),
                width: None,
                height: None,
            },
            ReleaseQuality {
                key: "lossless".to_string(),
                cid: "cid-lossless".to_string(),
                label: None,
                container: Some("flac".to_string()),
                codec: Some("flac".to_string()),
                source: Some("master".to_string()),
                rank: None,
                bitrate_kbps: None,
                width: None,
                height: None,
            },
        ];

        release.ensure_primary_content_cid();
        assert_eq!(release.content_cid, Some("cid-lossless".to_string()));
    }
}

// ============================================================================
// CRDT Implementation: LWW (Last-Writer-Wins)
// ============================================================================

/// Merge Option<String> timestamps: pick the earlier one (min).
fn merge_timestamp_min(a: &Option<String>, b: &Option<String>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v.clone()),
        (Some(va), Some(vb)) => Some(std::cmp::min(va, vb).clone()),
    }
}

impl TotalMerge for Release {
    /// LWW merge for release content.
    ///
    /// - All fields: later modified_at wins
    /// - created_at: min (preserve original creation time)
    fn merge(&self, other: &Self) -> Self {
        // Determine which document is newer
        let (newer, older) = if self.modified_at >= other.modified_at {
            (self, other)
        } else {
            (other, self)
        };

        Release {
            // Identity - always preserve
            id: self.id.clone(),

            // LWW: all content fields from newer document
            title: newer.title.clone(),
            creator: newer.creator.clone(),
            year: newer.year,
            category_id: newer.category_id.clone(),
            category_slug: newer.category_slug.clone(),
            thumbnail_cid: newer.thumbnail_cid.clone(),
            content_cid: newer.content_cid.clone(),
            qualities: newer.qualities.clone(),
            description: newer.description.clone(),
            tags: newer.tags.clone(),
            schema_version: newer.schema_version.clone(),
            site_address: newer.site_address.clone(),
            metadata: newer.metadata.clone(),

            // LWW: moderation fields from newer
            status: newer.status,
            moderated_by: newer.moderated_by.clone(),
            moderated_at: newer.moderated_at.clone(),
            rejection_reason: newer.rejection_reason.clone(),

            // modified_at from newer
            modified_at: newer.modified_at.clone(),

            version_info: newer.version_info.clone(),

            // created_at: min (preserve original creation time)
            created_at: merge_timestamp_min(&self.created_at, &other.created_at),
        }
    }
}

// Marker traits for IsCRDT - proves merge is commutative, associative, idempotent
impl CommutativeMerge for Release {}
impl AssociativeMerge for Release {}
impl IdempotentMerge for Release {}

// ============================================================================
// Document Implementation for SPORE sync
// ============================================================================

impl Document for Release {
    /// Type prefix for storage keys
    const TYPE_PREFIX: &'static str = "release";

    /// Content ID is hash of the stable identifier (id field)
    fn content_id(&self) -> ContentId {
        ContentId::hash(self.id.as_bytes())
    }
}
