//! Site manifest model for a Citadel-backed publication surface.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RendererMode {
    Compiled,
    Live,
}

impl Default for RendererMode {
    fn default() -> Self {
        Self::Compiled
    }
}

/// Public site metadata stored by Lens/Citadel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiteManifest {
    /// Stable identifier for this site record.
    pub id: String,
    /// Stable address used by clients to associate releases with the site.
    pub address: String,
    /// Human-readable site name.
    pub name: String,
    /// Optional description/tagline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional Archivist/Neverust asset reference for the site logo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// Optional canonical URL for this site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Renderer delivery mode for all Flagship clients using this Citadel node.
    #[serde(default)]
    pub renderer_mode: RendererMode,
    /// Optional live Vite/dev origin to redirect clients to when renderer_mode=Live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_preview_url: Option<String>,
    /// Optional theme payload for renderer customization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<serde_json::Value>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last update timestamp.
    pub updated_at: String,
}

impl SiteManifest {
    pub fn new(address: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: address.clone(),
            address,
            name: "Untitled Site".to_string(),
            description: None,
            logo: None,
            url: None,
            renderer_mode: RendererMode::Compiled,
            live_preview_url: None,
            theme: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }
}
