//! Content type definitions and supporting types.

use serde::{Deserialize, Serialize};

/// Content type discriminator - extensible enum for all possible content types.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    // Media - Video
    Movie,
    TvSeries,
    TvEpisode,
    Video,
    VideoClip,

    // Media - Audio
    MusicAlbum,
    MusicTrack,
    Playlist,
    Podcast,
    PodcastEpisode,
    Audiobook,
    AudioProduction,

    // Publications
    Book,
    Ebook,
    Magazine,
    Comic,
    ScientificPaper,
    Thesis,
    Report,
    Article,

    // Educational
    Course,
    Lesson,
    Tutorial,
    Lecture,
    Workshop,

    // Scientific
    Dataset,
    Experiment,
    Observation,
    Sample,
    Specimen,
    Model,

    // Software & Technology
    Software,
    Library,
    Framework,
    Application,
    Game,
    AiModel,
    MachineLearningModel,
    ContainerImage,
    VirtualMachine,

    // Visual Arts & Design
    Photo,
    PhotoAlbum,
    Artwork,
    Drawing,
    Blueprint,
    CadModel,
    ThreeDModel,
    Animation,

    // Archival & Museum
    MuseumArtifact,
    HistoricalDocument,
    Manuscript,
    ArchivalRecord,
    Collection,

    // Data & Backup
    Backup,
    Archive,
    Snapshot,

    // Other
    Website,
    WebPage,
    #[default]
    Document,
    Presentation,
    Spreadsheet,
    Database,

    // Extensibility: allows any custom type
    Custom(String),
}

/// Creator/contributor role.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorRole {
    Author,
    Artist,
    Director,
    Producer,
    Actor,
    Musician,
    Singer,
    Composer,
    Conductor,
    Editor,
    Photographer,
    Illustrator,
    Translator,
    Narrator,
    Developer,
    Maintainer,
    #[default]
    Contributor,
    Curator,
    Researcher,
    DataCollector,
    Custom(String),
}

/// A creator/contributor with their role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Creator {
    /// Creator name
    pub name: String,
    /// Role in creation
    pub role: CreatorRole,
    /// Optional identifier (ORCID, ISNI, etc.)
    pub identifier: Option<String>,
}

impl Creator {
    /// Create a new creator with name and role.
    pub fn new(name: String, role: CreatorRole) -> Self {
        Self {
            name,
            role,
            identifier: None,
        }
    }

    /// Create a new creator with an identifier.
    pub fn with_identifier(name: String, role: CreatorRole, identifier: String) -> Self {
        Self {
            name,
            role,
            identifier: Some(identifier),
        }
    }
}

/// License information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct License {
    /// License name (e.g., "CC-BY-4.0", "MIT", "Apache-2.0")
    pub name: String,
    /// URL to license text
    pub url: Option<String>,
    /// SPDX identifier if applicable
    pub spdx_id: Option<String>,
}

impl License {
    /// Create a new license with just a name.
    pub fn new(name: String) -> Self {
        Self {
            name,
            url: None,
            spdx_id: None,
        }
    }

    /// Create a license with SPDX identifier.
    pub fn spdx(spdx_id: &str) -> Self {
        Self {
            name: spdx_id.to_string(),
            url: Some(format!("https://spdx.org/licenses/{}.html", spdx_id)),
            spdx_id: Some(spdx_id.to_string()),
        }
    }

    /// Common licenses
    pub fn cc_by_4() -> Self {
        Self::spdx("CC-BY-4.0")
    }

    pub fn cc_by_sa_4() -> Self {
        Self::spdx("CC-BY-SA-4.0")
    }

    pub fn cc0() -> Self {
        Self::spdx("CC0-1.0")
    }

    pub fn mit() -> Self {
        Self::spdx("MIT")
    }

    pub fn apache_2() -> Self {
        Self::spdx("Apache-2.0")
    }
}

/// File/resource reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// Resource identifier (CID, URL, etc.)
    pub id: String,
    /// MIME type
    pub mime_type: Option<String>,
    /// Size in bytes
    pub size: Option<u64>,
    /// Checksum/hash
    pub checksum: Option<String>,
    /// Purpose (thumbnail, preview, master, etc.)
    pub purpose: Option<String>,
}

impl Resource {
    /// Create a new resource with just an ID.
    pub fn new(id: String) -> Self {
        Self {
            id,
            mime_type: None,
            size: None,
            checksum: None,
            purpose: None,
        }
    }

    /// Create a resource with full details.
    pub fn with_details(
        id: String,
        mime_type: Option<String>,
        size: Option<u64>,
        purpose: Option<String>,
    ) -> Self {
        Self {
            id,
            mime_type,
            size,
            checksum: None,
            purpose,
        }
    }

    /// Create a thumbnail resource.
    pub fn thumbnail(id: String) -> Self {
        Self {
            id,
            mime_type: Some("image/jpeg".to_string()),
            size: None,
            checksum: None,
            purpose: Some("thumbnail".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_serialization() {
        let types = vec![
            ContentType::Movie,
            ContentType::MusicAlbum,
            ContentType::ScientificPaper,
            ContentType::AiModel,
            ContentType::Custom("NFT".to_string()),
        ];

        for content_type in types {
            let json = serde_json::to_string(&content_type).unwrap();
            let deserialized: ContentType = serde_json::from_str(&json).unwrap();
            assert_eq!(content_type, deserialized);
        }
    }

    #[test]
    fn content_type_snake_case() {
        let json = serde_json::to_string(&ContentType::MusicAlbum).unwrap();
        assert_eq!(json, "\"music_album\"");

        let json = serde_json::to_string(&ContentType::ScientificPaper).unwrap();
        assert_eq!(json, "\"scientific_paper\"");
    }

    #[test]
    fn creator_with_role() {
        let creator = Creator::with_identifier(
            "Jane Smith".to_string(),
            CreatorRole::Director,
            "https://orcid.org/0000-0001-2345-6789".to_string(),
        );

        let json = serde_json::to_string(&creator).unwrap();
        let deserialized: Creator = serde_json::from_str(&json).unwrap();
        assert_eq!(creator, deserialized);
    }

    #[test]
    fn custom_roles() {
        let role = CreatorRole::Custom("VoiceActor".to_string());
        let json = serde_json::to_string(&role).unwrap();
        let deserialized: CreatorRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, deserialized);
    }

    #[test]
    fn license_spdx() {
        let license = License::mit();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.spdx_id, Some("MIT".to_string()));
        assert!(license.url.unwrap().contains("spdx.org"));
    }

    #[test]
    fn resource_thumbnail() {
        let resource = Resource::thumbnail("QmTest123".to_string());
        assert_eq!(resource.purpose, Some("thumbnail".to_string()));
        assert_eq!(resource.mime_type, Some("image/jpeg".to_string()));
    }
}
