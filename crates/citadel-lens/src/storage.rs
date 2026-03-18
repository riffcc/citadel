//! Persistent storage using ReDB.

use crate::error::Result;
use crate::models::{Category, ContentItem, FeaturedRelease, Release, ReleaseStatus, SiteManifest};
use ed25519_dalek::SigningKey;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;

// Table definitions
const RELEASES: TableDefinition<&str, &[u8]> = TableDefinition::new("releases");
const CONTENT: TableDefinition<&str, &[u8]> = TableDefinition::new("content");
const CATEGORIES: TableDefinition<&str, &[u8]> = TableDefinition::new("categories");
const FEATURED: TableDefinition<&str, &[u8]> = TableDefinition::new("featured");
const SITE: TableDefinition<&str, &[u8]> = TableDefinition::new("site");
const ADMINS: TableDefinition<&str, &[u8]> = TableDefinition::new("admins");
const PERMISSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("permissions");
const NODE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("node_meta");

/// Storage backend for Lens data.
pub struct Storage {
    db: Database,
}

impl Storage {
    /// Open or create storage at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Ensure parent directory exists
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // ReDB uses a file, not a directory like RocksDB
        let db_path = if path.is_dir() {
            path.join("lens.redb")
        } else {
            path.to_path_buf()
        };

        let db = Database::create(&db_path)?;
        Ok(Self { db })
    }

    // --- Releases ---

    /// Store a release.
    pub fn put_release(&self, release: &Release) -> Result<()> {
        let value = serde_json::to_vec(release)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(RELEASES)?;
            table.insert(release.id.as_str(), value.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a release by ID.
    pub fn get_release(&self, id: &str) -> Result<Option<Release>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(RELEASES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get(id)? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(serde_json::from_slice(bytes)?))
            }
            None => Ok(None),
        }
    }

    /// Delete a release.
    pub fn delete_release(&self, id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(RELEASES)?;
            table.remove(id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Delete ALL releases (use with caution!).
    pub fn delete_all_releases(&self) -> Result<usize> {
        let write_txn = self.db.begin_write()?;
        let count = {
            let mut table = write_txn.open_table(RELEASES)?;

            // Collect keys first
            let keys: Vec<String> = table
                .iter()?
                .filter_map(|item| item.ok().map(|(k, _)| k.value().to_string()))
                .collect();

            let count = keys.len();
            for key in keys {
                table.remove(key.as_str())?;
            }
            count
        };
        write_txn.commit()?;
        Ok(count)
    }

    /// List all releases.
    pub fn list_releases(&self) -> Result<Vec<Release>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(RELEASES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut releases = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let bytes: &[u8] = value.value();
            let release: Release = serde_json::from_slice(bytes)?;
            releases.push(release);
        }

        Ok(releases)
    }

    /// List releases filtered by status.
    pub fn list_releases_by_status(&self, status: ReleaseStatus) -> Result<Vec<Release>> {
        let all = self.list_releases()?;
        Ok(all.into_iter().filter(|r| r.status == status).collect())
    }

    /// List only pending releases (for moderation queue).
    pub fn list_pending_releases(&self) -> Result<Vec<Release>> {
        self.list_releases_by_status(ReleaseStatus::Pending)
    }

    /// List only approved releases (public catalog).
    pub fn list_public_releases(&self) -> Result<Vec<Release>> {
        self.list_releases_by_status(ReleaseStatus::Approved)
    }

    /// Count releases grouped by status.
    pub fn count_releases_by_status(&self) -> Result<HashMap<String, usize>> {
        let releases = self.list_releases()?;
        let mut counts = HashMap::new();

        for release in releases {
            let status_str = release.status.to_string();
            *counts.entry(status_str).or_insert(0) += 1;
        }

        Ok(counts)
    }

    /// Approve a release by ID.
    /// Returns the updated release, or None if not found.
    pub fn approve_release(&self, id: &str, moderator_pubkey: &str) -> Result<Option<Release>> {
        if let Some(mut release) = self.get_release(id)? {
            release.approve(moderator_pubkey);
            self.put_release(&release)?;
            Ok(Some(release))
        } else {
            Ok(None)
        }
    }

    /// Reject a release by ID.
    /// Returns the updated release, or None if not found.
    pub fn reject_release(
        &self,
        id: &str,
        moderator_pubkey: &str,
        reason: Option<String>,
    ) -> Result<Option<Release>> {
        if let Some(mut release) = self.get_release(id)? {
            release.reject(moderator_pubkey, reason);
            self.put_release(&release)?;
            Ok(Some(release))
        } else {
            Ok(None)
        }
    }

    // --- Content Items ---

    /// Store a content item.
    pub fn put_content_item(&self, item: &ContentItem) -> Result<()> {
        let value = serde_json::to_vec(item)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTENT)?;
            table.insert(item.id.as_str(), value.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a content item by ID.
    pub fn get_content_item(&self, id: &str) -> Result<Option<ContentItem>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CONTENT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get(id)? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(serde_json::from_slice(bytes)?))
            }
            None => Ok(None),
        }
    }

    // --- Categories ---

    /// Store a category.
    pub fn put_category(&self, category: &Category) -> Result<()> {
        let value = serde_json::to_vec(category)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CATEGORIES)?;
            table.insert(category.id.as_str(), value.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a category by ID.
    pub fn get_category(&self, id: &str) -> Result<Option<Category>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CATEGORIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get(id)? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(serde_json::from_slice(bytes)?))
            }
            None => Ok(None),
        }
    }

    /// Save a category (alias for put_category).
    pub fn save_category(&self, category: &Category) -> Result<()> {
        self.put_category(category)
    }

    /// Delete a category by ID.
    pub fn delete_category(&self, id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CATEGORIES)?;
            table.remove(id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Initialize default categories if not present.
    pub fn init_default_categories(&self) -> Result<()> {
        for category in Category::defaults() {
            if self.get_category(&category.id)?.is_none() {
                self.put_category(&category)?;
            }
        }
        Ok(())
    }

    /// List all categories.
    pub fn list_categories(&self) -> Result<Vec<Category>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CATEGORIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut categories = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let bytes: &[u8] = value.value();
            let category: Category = serde_json::from_slice(bytes)?;
            categories.push(category);
        }

        Ok(categories)
    }

    // --- Site manifest ---

    /// Store the singleton site manifest.
    pub fn put_site_manifest(&self, manifest: &SiteManifest) -> Result<()> {
        let value = serde_json::to_vec(manifest)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SITE)?;
            table.insert("default", value.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get the singleton site manifest, if it exists.
    pub fn get_site_manifest(&self) -> Result<Option<SiteManifest>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(SITE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get("default")? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(serde_json::from_slice(bytes)?))
            }
            None => Ok(None),
        }
    }

    /// Ensure a site manifest exists, creating a default one on first boot.
    pub fn ensure_site_manifest(&self, address: &str) -> Result<SiteManifest> {
        if let Some(existing) = self.get_site_manifest()? {
            return Ok(existing);
        }

        let manifest = SiteManifest::new(address.to_string());
        self.put_site_manifest(&manifest)?;
        Ok(manifest)
    }

    // --- Account/Permission management ---

    /// Check if a public key is an admin.
    pub fn is_admin(&self, public_key: &str) -> Result<bool> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(ADMINS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };

        let result: Option<redb::AccessGuard<&[u8]>> = table.get(public_key)?;
        Ok(result.is_some())
    }

    /// Set a public key as admin.
    pub fn set_admin(&self, public_key: &str, is_admin: bool) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADMINS)?;
            if is_admin {
                table.insert(public_key, &[1u8][..])?;
            } else {
                table.remove(public_key)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Check if a public key has a specific permission.
    pub fn has_permission(&self, public_key: &str, permission: &str) -> Result<bool> {
        let key = format!("{}:{}", public_key, permission);
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(PERMISSIONS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };

        let result: Option<redb::AccessGuard<&[u8]>> = table.get(key.as_str())?;
        Ok(result.is_some())
    }

    /// Grant a permission to a public key.
    pub fn grant_permission(&self, public_key: &str, permission: &str) -> Result<()> {
        let key = format!("{}:{}", public_key, permission);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(PERMISSIONS)?;
            table.insert(key.as_str(), &[1u8][..])?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Revoke a permission from a public key.
    pub fn revoke_permission(&self, public_key: &str, permission: &str) -> Result<()> {
        let key = format!("{}:{}", public_key, permission);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(PERMISSIONS)?;
            table.remove(key.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all admin public keys.
    pub fn list_admins(&self) -> Result<Vec<String>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(ADMINS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut admins = Vec::new();
        for item in table.iter()? {
            let (key, _) = item?;
            admins.push(key.value().to_string());
        }

        Ok(admins)
    }

    // --- Node Identity ---

    /// Get or create the node's signing key (persistent identity).
    pub fn get_or_create_node_key(&self) -> Result<SigningKey> {
        let read_txn = self.db.begin_read()?;

        // Try to read existing key
        if let Ok(table) = read_txn.open_table(NODE_META) {
            if let Some(guard) = table.get("signing_key")? {
                let bytes: &[u8] = guard.value();
                let key_bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| crate::error::Error::Storage("Invalid stored key".into()))?;
                return Ok(SigningKey::from_bytes(&key_bytes));
            }
        }
        drop(read_txn);

        // Generate new key and persist it
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(NODE_META)?;
            table.insert("signing_key", signing_key.as_bytes().as_slice())?;
        }
        write_txn.commit()?;

        Ok(signing_key)
    }

    // --- Featured Releases ---

    /// Store a featured release.
    pub fn put_featured_release(&self, featured: &FeaturedRelease) -> Result<()> {
        let value = serde_json::to_vec(featured)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(FEATURED)?;
            table.insert(featured.id.as_str(), value.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a featured release by ID.
    pub fn get_featured_release(&self, id: &str) -> Result<Option<FeaturedRelease>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(FEATURED) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get(id)? {
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(serde_json::from_slice(bytes)?))
            }
            None => Ok(None),
        }
    }

    /// Delete a featured release.
    pub fn delete_featured_release(&self, id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(FEATURED)?;
            table.remove(id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all featured releases.
    pub fn list_featured_releases(&self) -> Result<Vec<FeaturedRelease>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(FEATURED) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut featured = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let bytes: &[u8] = value.value();
            let fr: FeaturedRelease = serde_json::from_slice(bytes)?;
            featured.push(fr);
        }

        Ok(featured)
    }

    /// List only active featured releases (within time window).
    pub fn list_active_featured_releases(&self) -> Result<Vec<FeaturedRelease>> {
        let all = self.list_featured_releases()?;
        Ok(all.into_iter().filter(|fr| fr.is_active()).collect())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RendererMode;
    use tempfile::tempdir;

    #[test]
    fn storage_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.redb")).unwrap();

        let release = Release::new(
            "test123".to_string(),
            "Test Album".to_string(),
            "music".to_string(),
        );

        storage.put_release(&release).unwrap();
        let loaded = storage.get_release("test123").unwrap().unwrap();
        assert_eq!(release, loaded);
    }

    #[test]
    fn list_releases() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.redb")).unwrap();

        storage
            .put_release(&Release::new("a".into(), "A".into(), "music".into()))
            .unwrap();
        storage
            .put_release(&Release::new("b".into(), "B".into(), "music".into()))
            .unwrap();

        let releases = storage.list_releases().unwrap();
        assert_eq!(releases.len(), 2);
    }

    #[test]
    fn default_categories() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.redb")).unwrap();

        storage.init_default_categories().unwrap();

        let music = storage.get_category("music").unwrap();
        assert!(music.is_some());
    }

    #[test]
    fn site_manifest_round_trip_and_bootstrap() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let created = storage
            .ensure_site_manifest("ed25519p/test-site-address")
            .unwrap();
        assert_eq!(created.address, "ed25519p/test-site-address");
        assert_eq!(created.name, "Untitled Site");

        let mut updated = created.clone();
        updated.name = "Riff Archive".to_string();
        updated.description = Some("Metadata in Citadel, assets in Archivist".to_string());
        updated.logo = Some("archivist://logo".to_string());
        updated.url = Some("https://riff.cc".to_string());
        updated.renderer_mode = RendererMode::Live;
        updated.live_preview_url = Some("https://play.dev.riff.cc".to_string());
        updated.touch();
        storage.put_site_manifest(&updated).unwrap();

        let loaded = storage.get_site_manifest().unwrap().unwrap();
        assert_eq!(loaded.name, "Riff Archive");
        assert_eq!(
            loaded.description.as_deref(),
            Some("Metadata in Citadel, assets in Archivist")
        );
        assert_eq!(loaded.logo.as_deref(), Some("archivist://logo"));
        assert_eq!(loaded.url.as_deref(), Some("https://riff.cc"));
        assert_eq!(loaded.renderer_mode, RendererMode::Live);
        assert_eq!(
            loaded.live_preview_url.as_deref(),
            Some("https://play.dev.riff.cc")
        );

        let again = storage
            .ensure_site_manifest("ed25519p/other-address")
            .unwrap();
        assert_eq!(again.address, "ed25519p/test-site-address");
        assert_eq!(again.name, "Riff Archive");
    }
}
