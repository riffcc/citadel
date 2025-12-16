//! Featured Release model for homepage/promotional content.
//!
//! Featured releases are time-bound promotional entries that highlight
//! specific releases on the homepage. They support:
//! - Temporal activation (startTime/endTime)
//! - Priority ordering
//! - Custom display overrides (title, description, thumbnail)
//! - Regional/language targeting
//! - Promoted flag for hero slider placement

use serde::{Deserialize, Serialize};

/// A featured release entry for promotional display.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeaturedRelease {
    /// Unique identifier for this featured entry
    pub id: String,

    /// Reference to the actual Release being featured
    pub release_id: String,

    /// When this featured entry becomes active (ISO 8601)
    pub start_time: String,

    /// When this featured entry expires (ISO 8601)
    pub end_time: String,

    /// If true, appears in hero slider carousel (prominent placement)
    #[serde(default)]
    pub promoted: bool,

    /// Priority for ordering (1-1000, higher = first)
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Display order (for manual ordering via drag-drop)
    #[serde(default)]
    pub order: u32,

    /// Override the release title for featured display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_title: Option<String>,

    /// Override the release description for featured display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_description: Option<String>,

    /// Custom thumbnail CID for featured display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_thumbnail: Option<String>,

    /// Target regions (empty = all regions)
    /// Codes: US, EU, UK, CA, AU, JP, CN, IN, BR
    #[serde(default)]
    pub regions: Vec<String>,

    /// Target languages (empty = all languages)
    /// Codes: en, es, fr, de, it, pt, ja, zh, ko, ru
    #[serde(default)]
    pub languages: Vec<String>,

    /// Custom tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,

    /// A/B test variant identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    /// Custom metadata object (extensible)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// View count (analytics, read-only from client perspective)
    #[serde(default)]
    pub views: u64,

    /// Click count (analytics, read-only from client perspective)
    #[serde(default)]
    pub clicks: u64,

    /// Creation timestamp (ISO 8601)
    #[serde(default = "default_created")]
    pub created: String,
}

fn default_created() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn default_priority() -> u32 {
    500
}

impl FeaturedRelease {
    /// Create a new featured release with minimal required fields.
    pub fn new(
        id: String,
        release_id: String,
        start_time: String,
        end_time: String,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id,
            release_id,
            start_time,
            end_time,
            promoted: false,
            priority: default_priority(),
            order: 0,
            custom_title: None,
            custom_description: None,
            custom_thumbnail: None,
            regions: Vec::new(),
            languages: Vec::new(),
            tags: Vec::new(),
            variant: None,
            metadata: None,
            views: 0,
            clicks: 0,
            created: now,
        }
    }

    /// Check if this featured release is currently active based on time.
    pub fn is_active(&self) -> bool {
        let now = chrono::Utc::now();

        let start = match chrono::DateTime::parse_from_rfc3339(&self.start_time) {
            Ok(dt) => dt.with_timezone(&chrono::Utc),
            Err(_) => return false,
        };

        let end = match chrono::DateTime::parse_from_rfc3339(&self.end_time) {
            Ok(dt) => dt.with_timezone(&chrono::Utc),
            Err(_) => return false,
        };

        now >= start && now <= end
    }

    /// Generate a unique ID for a new featured release.
    pub fn generate_id() -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random: u32 = rand::random();
        format!("feat-{}-{:08x}", timestamp, random)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_featured_release_creation() {
        let fr = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );

        assert_eq!(fr.id, "feat-123");
        assert_eq!(fr.release_id, "release-456");
        assert!(!fr.promoted);
        assert_eq!(fr.priority, 500);
    }

    #[test]
    fn test_is_active() {
        // Create a featured release that's currently active
        let now = chrono::Utc::now();
        let start = (now - chrono::Duration::hours(1)).to_rfc3339();
        let end = (now + chrono::Duration::hours(1)).to_rfc3339();

        let fr = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            start,
            end,
        );

        assert!(fr.is_active());
    }

    #[test]
    fn test_is_not_active_future() {
        // Create a featured release that starts in the future
        let now = chrono::Utc::now();
        let start = (now + chrono::Duration::hours(1)).to_rfc3339();
        let end = (now + chrono::Duration::hours(2)).to_rfc3339();

        let fr = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            start,
            end,
        );

        assert!(!fr.is_active());
    }
}
