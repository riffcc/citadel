//! Category model for content organization.

use serde::{Deserialize, Serialize};

/// A category for organizing content.
/// Compatible with lens-v2 ContentCategory format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    /// Unique identifier
    pub id: String,

    /// Category ID (same as id, for lens-sdk compatibility)
    #[serde(default)]
    pub category_id: Option<String>,

    /// Human-readable name
    pub name: String,

    /// Display name (same as name, for lens-sdk compatibility)
    #[serde(default)]
    pub display_name: Option<String>,

    /// URL-friendly slug
    pub slug: String,

    /// Metadata schema for this category type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_schema: Option<serde_json::Value>,

    /// Site address (for lens-v2 compatibility)
    pub site_address: String,

    /// Whether this category is featured
    #[serde(default)]
    pub featured: bool,
}

impl Category {
    /// Create a new category.
    pub fn new(id: String, name: String) -> Self {
        let slug = id.clone();
        Self {
            category_id: Some(id.clone()),
            display_name: Some(name.clone()),
            id,
            name,
            slug,
            metadata_schema: None,
            site_address: "zb2rhkfHMKY7nsrC6QYcuAi1imgAAUXwPM3WYCajL3Evxmq2w".to_string(),
            featured: false,
        }
    }

    /// Create a new category with full options
    pub fn with_schema(id: String, name: String, featured: bool, schema: Option<serde_json::Value>) -> Self {
        let slug = id.clone();
        Self {
            category_id: Some(id.clone()),
            display_name: Some(name.clone()),
            id,
            name,
            slug,
            metadata_schema: schema,
            site_address: "zb2rhkfHMKY7nsrC6QYcuAi1imgAAUXwPM3WYCajL3Evxmq2w".to_string(),
            featured,
        }
    }

    /// DHT key prefix for categories.
    pub const DHT_PREFIX: &'static str = "category";

    /// Get the DHT key for this category.
    pub fn dht_key(&self) -> citadel_dht::DhtKey {
        citadel_dht::hash_prefixed_key(Self::DHT_PREFIX, &self.id)
    }

    /// Default categories for common content types (matching lens-v2).
    pub fn defaults() -> Vec<Self> {
        vec![
            Self::with_schema(
                "music".to_string(),
                "Music".to_string(),
                true,
                Some(serde_json::json!({
                    "artist": "string",
                    "album": "string",
                    "trackMetadata": "string"
                })),
            ),
            Self::with_schema(
                "movies".to_string(),
                "Movies".to_string(),
                true,
                Some(serde_json::json!({
                    "director": "string",
                    "releaseYear": "string",
                    "duration": "string",
                    "classification": "string"
                })),
            ),
            Self::with_schema(
                "tv-shows".to_string(),
                "TV Shows".to_string(),
                true,
                Some(serde_json::json!({
                    "seasons": "number",
                    "episodes": "number",
                    "releaseYear": "string"
                })),
            ),
            Self::with_schema(
                "books".to_string(),
                "Books".to_string(),
                false,
                Some(serde_json::json!({
                    "author": "string",
                    "isbn": "string",
                    "publisher": "string",
                    "publicationYear": "string"
                })),
            ),
            Self::with_schema(
                "audiobooks".to_string(),
                "Audiobooks".to_string(),
                false,
                Some(serde_json::json!({
                    "narrator": "string",
                    "author": "string",
                    "duration": "string"
                })),
            ),
            Self::with_schema(
                "games".to_string(),
                "Games".to_string(),
                false,
                Some(serde_json::json!({
                    "platform": "string",
                    "developer": "string",
                    "releaseYear": "string"
                })),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_category() {
        let cat = Category::new("music".to_string(), "Music".to_string());
        assert_eq!(cat.id, "music");
        assert_eq!(cat.name, "Music");
    }

    #[test]
    fn defaults_not_empty() {
        let defaults = Category::defaults();
        assert!(!defaults.is_empty());
        assert!(defaults.iter().any(|c| c.id == "music"));
    }
}
