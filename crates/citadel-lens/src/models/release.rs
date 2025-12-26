//! Release model - albums, movies, TV series, etc.

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
}

impl std::fmt::Display for ReleaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseStatus::Pending => write!(f, "pending"),
            ReleaseStatus::Approved => write!(f, "approved"),
            ReleaseStatus::Rejected => write!(f, "rejected"),
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
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

impl Release {
    /// Create a new release with required fields.
    /// Status defaults to Approved for backward compatibility.
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
            status: ReleaseStatus::default(),
            moderated_by: None,
            moderated_at: None,
            rejection_reason: None,
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
}
