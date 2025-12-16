//! Release model - albums, movies, TV series, etc.

use serde::{Deserialize, Serialize};

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
