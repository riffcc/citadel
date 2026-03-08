//! Featured Release model for homepage/promotional content.
//!
//! Featured releases are time-bound promotional entries that highlight
//! specific releases on the homepage. They support:
//! - Temporal activation (startTime/endTime)
//! - Priority ordering
//! - Custom display overrides (title, description, thumbnail)
//! - Regional/language targeting
//! - Promoted flag for hero slider placement
//!
//! ## CRDT Semantics
//!
//! FeaturedRelease uses **LWW (Last-Writer-Wins)** merge based on `modified_at`.
//!
//! This is appropriate because:
//! - FeaturedRelease is admin-controlled with a single source of truth
//! - Concurrent admin edits are rare
//! - Admin intent should be respected (later edit = correct state)
//!
//! | Field Type | Merge Strategy | Fields |
//! |------------|----------------|--------|
//! | LWW        | later modified_at wins | all admin-editable fields |
//! | Counter    | max (preserves increments) | views, clicks |
//! | Timestamp  | min | created |
//!
//! For user-generated content with concurrent edits, use rich merges instead.

use citadel_crdt::{AssociativeMerge, CommutativeMerge, ContentId, IdempotentMerge, TotalMerge};
use citadel_docs::Document;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
    #[serde(default)]
    pub custom_title: Option<String>,

    /// Override the release description for featured display
    #[serde(default)]
    pub custom_description: Option<String>,

    /// Custom thumbnail CID for featured display
    #[serde(default)]
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
    #[serde(default)]
    pub variant: Option<String>,

    /// Custom metadata object (extensible)
    /// Note: serde_json::Value serializes correctly with bincode
    #[serde(default)]
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

    /// Last modification timestamp (ISO 8601) - for LWW merge of editable fields
    #[serde(default = "default_created")]
    pub modified_at: String,

    // Deprecated fields - kept for backward compatibility with stored data
    // Note: Cannot use skip_serializing with bincode - it breaks byte layout
    #[serde(default)]
    #[allow(dead_code)]
    order_version: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    promoted_version: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    priority_version: Option<u64>,
}

fn default_created() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn default_priority() -> u32 {
    500
}

impl FeaturedRelease {
    /// Create a new featured release with minimal required fields.
    pub fn new(id: String, release_id: String, start_time: String, end_time: String) -> Self {
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
            created: now.clone(),
            modified_at: now,
            // Deprecated fields
            order_version: None,
            promoted_version: None,
            priority_version: None,
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

    #[test]
    fn test_merge_lww_semantics() {
        // FeaturedRelease uses LWW (Last-Writer-Wins) for admin-editable fields
        // Only counters (views, clicks) use max, and created uses min
        let base = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );

        // Node A: older edit
        let mut node_a = base.clone();
        node_a.modified_at = "2025-06-01T00:00:00Z".to_string();
        node_a.regions = vec!["US".to_string(), "EU".to_string()];
        node_a.views = 100;
        node_a.promoted = true;

        // Node B: newer edit (later modified_at wins)
        let mut node_b = base.clone();
        node_b.modified_at = "2025-06-02T00:00:00Z".to_string();
        node_b.regions = vec!["JP".to_string(), "AU".to_string()];
        node_b.clicks = 50;
        node_b.tags = vec!["featured".to_string()];
        node_b.promoted = false;

        // Merge: LWW fields from node_b (newer), counters use max
        let merged = node_a.merge(&node_b);

        // LWW: regions from newer (node_b)
        assert_eq!(merged.regions, vec!["JP".to_string(), "AU".to_string()]);

        // LWW: tags from newer (node_b)
        assert!(merged.tags.contains(&"featured".to_string()));

        // LWW: promoted from newer (node_b = false)
        assert!(!merged.promoted);

        // Counters: max (preserves both increments)
        assert_eq!(merged.views, 100);
        assert_eq!(merged.clicks, 50);

        // modified_at: from newer
        assert_eq!(merged.modified_at, "2025-06-02T00:00:00Z");
    }

    #[test]
    fn test_merge_commutativity() {
        let mut a = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        a.views = 100;
        a.regions = vec!["US".to_string()];

        let mut b = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        b.clicks = 50;
        b.regions = vec!["EU".to_string()];

        // merge(a, b) == merge(b, a)
        let ab = a.merge(&b);
        let ba = b.merge(&a);

        assert_eq!(ab.views, ba.views);
        assert_eq!(ab.clicks, ba.clicks);
        assert_eq!(ab.regions.len(), ba.regions.len());
    }

    #[test]
    fn test_merge_idempotency() {
        let mut fr = FeaturedRelease::new(
            "feat-123".to_string(),
            "release-456".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        fr.views = 100;
        fr.regions = vec!["US".to_string()];

        // merge(a, a) == a
        let merged = fr.merge(&fr);

        assert_eq!(merged.views, fr.views);
        assert_eq!(merged.regions.len(), fr.regions.len());
    }
}

// ============================================================================
// CRDT Implementation: Rich Semantic Merges
// ============================================================================

/// Commutative merge for Option<String>.
///
/// - Both None → None
/// - One Some → that one
/// - Both Some → lexicographically smaller (deterministic, commutative)
fn merge_option_string(a: &Option<String>, b: &Option<String>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v.clone()),
        (Some(va), Some(vb)) => Some(std::cmp::min(va, vb).clone()),
    }
}

/// Commutative merge for Option<serde_json::Value>.
///
/// For now, uses same lexicographic strategy on JSON string representation.
/// TODO: Deep object merge for richer semantics.
fn merge_option_json(
    a: &Option<serde_json::Value>,
    b: &Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (a, b) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v.clone()),
        (Some(va), Some(vb)) => {
            // Deterministic: compare string representations
            let sa = serde_json::to_string(va).unwrap_or_default();
            let sb = serde_json::to_string(vb).unwrap_or_default();
            if sa <= sb {
                Some(va.clone())
            } else {
                Some(vb.clone())
            }
        }
    }
}

/// Merge Vec<String> as a set (union), return sorted Vec.
fn merge_vec_as_set(a: &[String], b: &[String]) -> Vec<String> {
    let set_a: BTreeSet<_> = a.iter().cloned().collect();
    let set_b: BTreeSet<_> = b.iter().cloned().collect();
    set_a.union(&set_b).cloned().collect()
}

/// Merge timestamps: pick the earlier one (min).
fn merge_timestamp_min(a: &str, b: &str) -> String {
    // ISO 8601 strings are lexicographically orderable
    std::cmp::min(a, b).to_string()
}

/// Merge timestamps: pick the later one (max).
fn merge_timestamp_max(a: &str, b: &str) -> String {
    std::cmp::max(a, b).to_string()
}

impl TotalMerge for FeaturedRelease {
    /// LWW merge for admin-controlled content.
    ///
    /// - Admin-editable fields: later modified_at wins
    /// - Counters (views, clicks): max (preserve all increments)
    /// - Created: min (first creation time)
    fn merge(&self, other: &Self) -> Self {
        // Determine which document is newer
        let (newer, _older) = if self.modified_at >= other.modified_at {
            (self, other)
        } else {
            (other, self)
        };

        FeaturedRelease {
            // Identity
            id: self.id.clone(),

            // LWW: all admin-editable fields from newer document
            release_id: newer.release_id.clone(),
            start_time: newer.start_time.clone(),
            end_time: newer.end_time.clone(),
            promoted: newer.promoted,
            priority: newer.priority,
            order: newer.order,
            custom_title: newer.custom_title.clone(),
            custom_description: newer.custom_description.clone(),
            custom_thumbnail: newer.custom_thumbnail.clone(),
            regions: newer.regions.clone(),
            languages: newer.languages.clone(),
            tags: newer.tags.clone(),
            variant: newer.variant.clone(),
            metadata: newer.metadata.clone(),
            modified_at: newer.modified_at.clone(),

            // Counters: max (these accumulate independently of admin edits)
            views: self.views.max(other.views),
            clicks: self.clicks.max(other.clicks),

            // Created: min (preserve original creation time)
            created: merge_timestamp_min(&self.created, &other.created),

            // Deprecated fields - ignore during merge
            order_version: None,
            promoted_version: None,
            priority_version: None,
        }
    }
}

// Marker traits for IsCRDT
impl CommutativeMerge for FeaturedRelease {}
impl AssociativeMerge for FeaturedRelease {}
impl IdempotentMerge for FeaturedRelease {}

// ============================================================================
// Document Implementation for SPORE sync
// ============================================================================

impl Document for FeaturedRelease {
    /// Type prefix for storage keys
    const TYPE_PREFIX: &'static str = "featured";

    /// Content ID is hash of the stable identifier (id field)
    fn content_id(&self) -> ContentId {
        ContentId::hash(self.id.as_bytes())
    }
}
