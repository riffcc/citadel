use serde::{Deserialize, Serialize};

/// Site-level manifest describing an instance/lens node's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteManifest {
    pub id: String,
    pub address: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<serde_json::Value>,
    pub modified_at: String,
}

impl SiteManifest {
    pub fn new(address: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: address.clone(),
            address,
            name: "Unnamed Site".to_string(),
            description: None,
            logo: None,
            url: None,
            theme: None,
            modified_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.modified_at = chrono::Utc::now().to_rfc3339();
    }
}
