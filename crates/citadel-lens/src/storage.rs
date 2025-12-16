//! Persistent storage using RocksDB.

use crate::error::Result;
use crate::models::{Category, ContentItem, FeaturedRelease, Release};
use ed25519_dalek::SigningKey;
use rocksdb::{Options, DB};
use std::path::Path;

/// Storage backend for Lens data.
pub struct Storage {
    db: DB,
}

impl Storage {
    /// Open or create storage at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self { db })
    }

    // --- Releases ---

    /// Store a release.
    pub fn put_release(&self, release: &Release) -> Result<()> {
        let key = format!("release:{}", release.id);
        let value = serde_json::to_vec(release)?;
        self.db.put(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a release by ID.
    pub fn get_release(&self, id: &str) -> Result<Option<Release>> {
        let key = format!("release:{}", id);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    /// Delete a release.
    pub fn delete_release(&self, id: &str) -> Result<()> {
        let key = format!("release:{}", id);
        self.db.delete(key.as_bytes())?;
        Ok(())
    }

    /// Delete ALL releases (use with caution!).
    pub fn delete_all_releases(&self) -> Result<usize> {
        let prefix = b"release:";
        let mut count = 0;

        // Collect keys first to avoid iterator invalidation
        let keys: Vec<Vec<u8>> = self.db.prefix_iterator(prefix)
            .take_while(|item| {
                item.as_ref().map(|(k, _)| k.starts_with(prefix)).unwrap_or(false)
            })
            .filter_map(|item| item.ok().map(|(k, _)| k.to_vec()))
            .collect();

        for key in keys {
            self.db.delete(&key)?;
            count += 1;
        }

        Ok(count)
    }

    /// List all releases.
    pub fn list_releases(&self) -> Result<Vec<Release>> {
        let prefix = b"release:";
        let mut releases = Vec::new();

        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (key, value) = item?;
            if key.starts_with(prefix) {
                let release: Release = serde_json::from_slice(&value)?;
                releases.push(release);
            } else {
                break;
            }
        }

        Ok(releases)
    }

    // --- Content Items ---

    /// Store a content item.
    pub fn put_content_item(&self, item: &ContentItem) -> Result<()> {
        let key = format!("content:{}", item.id);
        let value = serde_json::to_vec(item)?;
        self.db.put(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a content item by ID.
    pub fn get_content_item(&self, id: &str) -> Result<Option<ContentItem>> {
        let key = format!("content:{}", id);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    // --- Categories ---

    /// Store a category.
    pub fn put_category(&self, category: &Category) -> Result<()> {
        let key = format!("category:{}", category.id);
        let value = serde_json::to_vec(category)?;
        self.db.put(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a category by ID.
    pub fn get_category(&self, id: &str) -> Result<Option<Category>> {
        let key = format!("category:{}", id);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    /// Save a category (alias for put_category).
    pub fn save_category(&self, category: &Category) -> Result<()> {
        self.put_category(category)
    }

    /// Delete a category by ID.
    pub fn delete_category(&self, id: &str) -> Result<()> {
        let key = format!("category:{}", id);
        self.db.delete(key.as_bytes())?;
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
        let prefix = b"category:";
        let mut categories = Vec::new();

        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (key, value) = item?;
            if key.starts_with(prefix) {
                let category: Category = serde_json::from_slice(&value)?;
                categories.push(category);
            } else {
                break;
            }
        }

        Ok(categories)
    }

    // --- Account/Permission management ---

    /// Check if a public key is an admin.
    pub fn is_admin(&self, public_key: &str) -> Result<bool> {
        let key = format!("admin:{}", public_key);
        Ok(self.db.get(key.as_bytes())?.is_some())
    }

    /// Set a public key as admin.
    pub fn set_admin(&self, public_key: &str, is_admin: bool) -> Result<()> {
        let key = format!("admin:{}", public_key);
        if is_admin {
            self.db.put(key.as_bytes(), b"1")?;
        } else {
            self.db.delete(key.as_bytes())?;
        }
        Ok(())
    }

    /// Check if a public key has a specific permission.
    pub fn has_permission(&self, public_key: &str, permission: &str) -> Result<bool> {
        let key = format!("perm:{}:{}", public_key, permission);
        Ok(self.db.get(key.as_bytes())?.is_some())
    }

    /// Grant a permission to a public key.
    pub fn grant_permission(&self, public_key: &str, permission: &str) -> Result<()> {
        let key = format!("perm:{}:{}", public_key, permission);
        self.db.put(key.as_bytes(), b"1")?;
        Ok(())
    }

    /// Revoke a permission from a public key.
    pub fn revoke_permission(&self, public_key: &str, permission: &str) -> Result<()> {
        let key = format!("perm:{}:{}", public_key, permission);
        self.db.delete(key.as_bytes())?;
        Ok(())
    }

    /// List all admin public keys.
    pub fn list_admins(&self) -> Result<Vec<String>> {
        let prefix = b"admin:";
        let mut admins = Vec::new();

        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (key, _) = item?;
            if key.starts_with(prefix) {
                // Extract public key from "admin:{key}"
                let key_str = String::from_utf8_lossy(&key);
                if let Some(pk) = key_str.strip_prefix("admin:") {
                    admins.push(pk.to_string());
                }
            } else {
                break;
            }
        }

        Ok(admins)
    }

    // --- Node Identity ---

    /// Get or create the node's signing key (persistent identity).
    pub fn get_or_create_node_key(&self) -> Result<SigningKey> {
        let key = b"node:signing_key";

        if let Some(data) = self.db.get(key)? {
            // Load existing key
            let bytes: [u8; 32] = data.as_slice().try_into()
                .map_err(|_| crate::error::Error::Storage("Invalid stored key".into()))?;
            Ok(SigningKey::from_bytes(&bytes))
        } else {
            // Generate new key and persist it
            let mut rng = rand::thread_rng();
            let signing_key = SigningKey::generate(&mut rng);
            self.db.put(key, signing_key.as_bytes())?;
            Ok(signing_key)
        }
    }

    // --- Featured Releases ---

    /// Store a featured release.
    pub fn put_featured_release(&self, featured: &FeaturedRelease) -> Result<()> {
        let key = format!("featured:{}", featured.id);
        let value = serde_json::to_vec(featured)?;
        self.db.put(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a featured release by ID.
    pub fn get_featured_release(&self, id: &str) -> Result<Option<FeaturedRelease>> {
        let key = format!("featured:{}", id);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    /// Delete a featured release.
    pub fn delete_featured_release(&self, id: &str) -> Result<()> {
        let key = format!("featured:{}", id);
        self.db.delete(key.as_bytes())?;
        Ok(())
    }

    /// List all featured releases.
    pub fn list_featured_releases(&self) -> Result<Vec<FeaturedRelease>> {
        let prefix = b"featured:";
        let mut featured = Vec::new();

        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (key, value) = item?;
            if key.starts_with(prefix) {
                let fr: FeaturedRelease = serde_json::from_slice(&value)?;
                featured.push(fr);
            } else {
                break;
            }
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
    use tempfile::tempdir;

    #[test]
    fn storage_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

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
        let storage = Storage::open(dir.path()).unwrap();

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
        let storage = Storage::open(dir.path()).unwrap();

        storage.init_default_categories().unwrap();

        let music = storage.get_category("music").unwrap();
        assert!(music.is_some());
    }
}
