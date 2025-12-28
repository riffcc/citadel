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
            status: ReleaseStatus::Approved,
            moderated_by: None,
            moderated_at: None,
            rejection_reason: None,
            modified_at: "2024-01-01T00:00:00Z".to_string(),
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
