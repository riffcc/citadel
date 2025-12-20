//! HTTP API for Lens.

use crate::mesh::{double_hash_id, FloodMessage};
use crate::models::{Category, FeaturedRelease, Release};
use crate::node::LensState;
use crate::ws::ws_mesh_handler;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

// ============================================================================
// SIGNED REQUEST AUTHENTICATION
// ============================================================================
// All write endpoints require:
// 1. A valid ed25519 public key (in "ed25519p/{hex}" format)
// 2. A signature over the message (format: "{timestamp}:{body}" or "{timestamp}:{method}:{path}")
// 3. The public key must be in the admin list
//
// For POST/PUT: signature is over "{timestamp}:{json_body}"
// For DELETE: signature is over "{timestamp}:DELETE:{path}"
// The timestamp header (X-Timestamp) must be provided to reconstruct the signed message.
// ============================================================================

/// Verify an ed25519 signature over a message.
///
/// # Arguments
/// * `public_key` - The public key in "ed25519p/{hex}" format
/// * `message` - The message that was signed (the request body)
/// * `signature_hex` - The signature in hex format
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
fn verify_signature(public_key: &str, message: &[u8], signature_hex: &str) -> Result<(), String> {
    // Parse public key (format: "ed25519p/{hex}")
    let key_hex = public_key
        .strip_prefix("ed25519p/")
        .ok_or_else(|| "Invalid public key format: must start with 'ed25519p/'")?;

    let key_bytes = hex::decode(key_hex)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!("Invalid public key length: expected 32 bytes, got {}", key_bytes.len()));
    }

    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Failed to convert public key to array")?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    // Parse signature
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: expected 64 bytes, got {}", sig_bytes.len()));
    }

    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "Failed to convert signature to array")?;

    let signature = Signature::from_bytes(&sig_array);

    // Verify
    verifying_key.verify(message, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

/// Helper to check if a request is properly signed by an admin.
///
/// This is the main authentication function for write endpoints.
/// It verifies:
/// 1. The signature is valid for the given public key and message
/// 2. The public key is in the admin list
///
/// # Arguments
/// * `storage` - The storage backend to check admin status
/// * `public_key` - The public key claiming to sign the request
/// * `signature` - The hex-encoded signature
/// * `timestamp` - The timestamp from X-Timestamp header
/// * `body` - The request body bytes (for POST/PUT)
///
/// # Returns
/// * `Ok(())` if authenticated as admin
/// * `Err(String)` with error message if not
fn require_admin_signature(
    storage: &crate::storage::Storage,
    public_key: &str,
    signature: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<(), String> {
    // Reconstruct the signed message: "{timestamp}:{body}"
    // This matches what Flagship signs
    let body_str = std::str::from_utf8(body)
        .map_err(|e| format!("Invalid UTF-8 in request body: {}", e))?;
    let message = format!("{}:{}", timestamp, body_str);

    // Verify the signature
    verify_signature(public_key, message.as_bytes(), signature)?;

    // Then check if the key is an admin
    if !storage.is_admin(public_key).unwrap_or(false) {
        return Err(format!("Public key {} is not an admin", public_key));
    }

    Ok(())
}

/// Helper to check if a DELETE request is properly signed by an admin.
///
/// For DELETE requests, the message format is "{timestamp}:DELETE:{path}"
fn require_admin_signature_delete(
    storage: &crate::storage::Storage,
    public_key: &str,
    signature: &str,
    timestamp: &str,
    path: &str,
) -> Result<(), String> {
    // Reconstruct the signed message: "{timestamp}:DELETE:{path}"
    let message = format!("{}:DELETE:{}", timestamp, path);

    // Verify the signature
    verify_signature(public_key, message.as_bytes(), signature)?;

    // Then check if the key is an admin
    if !storage.is_admin(public_key).unwrap_or(false) {
        return Err(format!("Public key {} is not an admin", public_key));
    }

    Ok(())
}

type AppState = Arc<RwLock<LensState>>;

/// Build the API router.
pub fn build_router(state: AppState) -> Router {
    // CORS layer for browser access
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health (at root and under /api/v1 for compatibility)
        .route("/health", get(health))
        .route("/api/v1/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/ready", get(ready))
        // Releases
        .route("/api/v1/releases", get(list_releases))
        .route("/api/v1/releases", post(create_release))
        .route("/api/v1/releases/:id", get(get_release))
        .route("/api/v1/releases/:id", put(update_release))
        .route("/api/v1/releases/:id", delete(delete_release))
        // Categories
        .route("/api/v1/content-categories", get(list_categories))
        .route("/api/v1/content-categories", post(create_category))
        .route("/api/v1/content-categories/:id", get(get_category))
        .route("/api/v1/content-categories/:id", put(update_category))
        .route("/api/v1/content-categories/:id", delete(delete_category))
        // Featured releases (for flagship home page)
        .route("/api/v1/featured-releases", get(list_featured_releases))
        // Admin: Featured releases management
        .route("/api/v1/admin/featured-releases", post(create_featured_release))
        .route("/api/v1/admin/featured-releases/:id", get(get_featured_release))
        .route("/api/v1/admin/featured-releases/:id", put(update_featured_release))
        .route("/api/v1/admin/featured-releases/:id", delete(delete_featured_release))
        // Account (identity management)
        .route("/api/v1/account/:public_key", get(get_account))
        // Network mesh topology map
        .route("/api/v1/map", get(get_network_map))
        // Mesh state (slots, peers, TGP sessions)
        .route("/api/v1/mesh/state", get(get_mesh_state))
        // WebSocket for real-time mesh updates
        .route("/api/v1/ws/mesh", get(ws_mesh_handler))
        // Import/Export
        .route("/api/v1/import", post(import_releases))
        .route("/api/v1/export", get(export_releases))
        .route("/api/v1/admin/releases", delete(delete_all_releases))
        .layer(cors)
        .with_state(state)
}

// --- Health endpoints ---

async fn health() -> &'static str {
    "OK"
}

/// Ready check response with sync status details
#[derive(Debug, Serialize)]
struct ReadyResponse {
    ready: bool,
    synced_peers: usize,
    total_peers: usize,
    message: String,
}

/// GET /ready, /api/v1/ready - Check if node is synced and ready to serve traffic
/// Returns 200 OK when all peers are content-synced (HaveList XOR = 0)
/// Returns 503 Service Unavailable when still syncing
async fn ready(
    State(state): State<AppState>,
) -> Result<Json<ReadyResponse>, (StatusCode, Json<ReadyResponse>)> {
    let state = state.read().await;

    // Check mesh state for sync status
    let (synced, total, is_ready) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        let (synced, total) = mesh.sync_status();
        let ready = mesh.is_content_ready();
        (synced, total, ready)
    } else {
        // No mesh state = standalone mode, trivially ready
        (0, 0, true)
    };

    let response = ReadyResponse {
        ready: is_ready,
        synced_peers: synced,
        total_peers: total,
        message: if is_ready {
            "Content ready (WantList=∅ from all peers)".to_string()
        } else {
            format!("Syncing: have all content from {}/{} peers", synced, total)
        },
    };

    if is_ready {
        Ok(Json(response))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(response)))
    }
}

// --- Release endpoints ---

async fn list_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<Release>>, StatusCode> {
    let state = state.read().await;
    let releases = state
        .storage
        .list_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(|r| r.with_defaults())
        .collect();
    Ok(Json(releases))
}

/// Request for creating a release.
/// Accepts both camelCase (Flagship) and snake_case field names.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateReleaseRequest {
    /// Title/name of the release
    #[serde(alias = "title")]
    name: String,
    /// Category ID
    #[serde(alias = "category_id")]
    category_id: String,
    /// Creator/artist (optional)
    #[serde(alias = "postedBy")]
    creator: Option<String>,
    /// Release year (optional)
    year: Option<u32>,
    /// Description (optional)
    description: Option<String>,
    /// Tags (optional)
    tags: Option<Vec<String>>,
    /// Content CID (optional)
    #[serde(alias = "content_cid")]
    content_cid: Option<String>,
    /// Thumbnail CID (optional)
    #[serde(alias = "thumbnail_cid")]
    thumbnail_cid: Option<String>,
    /// Arbitrary metadata (optional) - for artist type, series, etc.
    metadata: Option<serde_json::Value>,
}

async fn create_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Release>), (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Public-Key header"
        }))))?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Signature header"
        }))))?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Timestamp header"
        }))))?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) = require_admin_signature(&state.storage, public_key, signature, timestamp, &body) {
            tracing::warn!("Auth failed for create_release: {}", e);
            return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": e
            }))));
        }
    }

    // Parse the request body
    let req: CreateReleaseRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        }))))?;

    // Generate ID from name + timestamp
    let content = format!("{}:{}", req.name, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());
    let id = Release::generate_id(content.as_bytes());

    // BadBits: Check if this release is on the permanent blocklist
    // (DMCA, abuse material, illegal content - prevents re-upload)
    {
        let state = state.read().await;
        if let Some(ref mesh_state) = state.mesh_state {
            let mesh = mesh_state.read().await;
            let release_hash = double_hash_id(&id);
            if mesh.bad_bits.contains(&release_hash) {
                tracing::warn!("BadBits: Rejected upload of blocked content (hash matches blocklist)");
                return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
                    "error": "Content is on blocklist"
                }))));
            }
        }
    }

    let mut release = Release::new(id, req.name, req.category_id);
    release.creator = req.creator;
    release.year = req.year;
    release.description = req.description;
    release.tags = req.tags.unwrap_or_default();
    release.content_cid = req.content_cid;
    release.thumbnail_cid = req.thumbnail_cid;
    release.metadata = req.metadata;

    let state = state.read().await;
    state
        .storage
        .put_release(&release)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to save release"
        }))))?;

    // SPORE: Flood the release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding new release {}", release.id);
        }

        // SPORE: Broadcast our updated ContentHaveList so peers know our new state
        if let Ok(all_releases) = state.storage.list_releases() {
            let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
            let _ = flood_tx.send(FloodMessage::ContentHaveList {
                peer_id: "api-create".to_string(),
                release_ids,
            });
        }
    }

    Ok((StatusCode::CREATED, Json(release)))
}

async fn get_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Release>, StatusCode> {
    let state = state.read().await;
    match state.storage.get_release(&id) {
        Ok(Some(release)) => Ok(Json(release.with_defaults())),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Request for updating a release (same fields as create, all optional except what's changing)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateReleaseRequest {
    /// Title/name of the release
    #[serde(alias = "title")]
    name: Option<String>,
    /// Category ID (frontend sends categoryId)
    #[serde(alias = "categoryId")]
    category_id: Option<String>,
    /// Creator/artist (optional) - frontend may send postedBy
    #[serde(alias = "postedBy")]
    creator: Option<String>,
    /// Release year (optional)
    year: Option<u32>,
    /// Description (optional)
    description: Option<String>,
    /// Tags (optional)
    tags: Option<Vec<String>>,
    /// Content CID (frontend sends contentCID)
    #[serde(alias = "contentCID")]
    content_cid: Option<String>,
    /// Thumbnail CID (frontend sends thumbnailCID)
    #[serde(alias = "thumbnailCID")]
    thumbnail_cid: Option<String>,
    /// Site address (frontend sends siteAddress)
    #[serde(alias = "siteAddress")]
    site_address: Option<String>,
    /// Arbitrary metadata (optional)
    metadata: Option<serde_json::Value>,
}

async fn update_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Release>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Public-Key header"
        }))))?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Signature header"
        }))))?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Timestamp header"
        }))))?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) = require_admin_signature(&state.storage, public_key, signature, timestamp, &body) {
            tracing::warn!("Auth failed for update_release: {}", e);
            return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": e
            }))));
        }
    }

    // Parse the request body
    let req: UpdateReleaseRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        }))))?;

    let state = state.read().await;

    // Get existing release
    let mut release = match state.storage.get_release(&id) {
        Ok(Some(r)) => r,
        Ok(None) => return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Release not found"
        })))),
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to get release"
        })))),
    };

    // Update fields if provided
    if let Some(name) = req.name {
        release.title = name;
    }
    if let Some(category_id) = req.category_id {
        release.category_id = category_id.clone();
        release.category_slug = Some(category_id);
    }
    if let Some(creator) = req.creator {
        release.creator = Some(creator);
    }
    if let Some(year) = req.year {
        release.year = Some(year);
    }
    if let Some(description) = req.description {
        release.description = Some(description);
    }
    if let Some(tags) = req.tags {
        release.tags = tags;
    }
    if let Some(content_cid) = req.content_cid {
        release.content_cid = Some(content_cid);
    }
    if let Some(thumbnail_cid) = req.thumbnail_cid {
        release.thumbnail_cid = Some(thumbnail_cid);
    }
    if let Some(site_address) = req.site_address {
        release.site_address = Some(site_address);
    }
    if let Some(new_metadata) = req.metadata {
        // Merge new metadata with existing metadata instead of replacing
        if let Some(existing) = release.metadata.as_mut() {
            if let (Some(existing_obj), Some(new_obj)) = (existing.as_object_mut(), new_metadata.as_object()) {
                for (key, value) in new_obj {
                    existing_obj.insert(key.clone(), value.clone());
                }
            } else {
                // If not both objects, just replace
                release.metadata = Some(new_metadata);
            }
        } else {
            release.metadata = Some(new_metadata);
        }
    }

    // Save updated release
    state
        .storage
        .put_release(&release)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to save release"
        }))))?;

    // SPORE: Flood the updated release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding updated release {}", release.id);
        }
    }

    Ok(Json(release.with_defaults()))
}

async fn delete_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Public-Key header"
        }))))?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Signature header"
        }))))?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Timestamp header"
        }))))?;

    // For DELETE, signature is over "{timestamp}:DELETE:/releases/{id}"
    let path = format!("/releases/{}", id);

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) = require_admin_signature_delete(&state.storage, public_key, signature, timestamp, &path) {
            tracing::warn!("Auth failed for delete_release: {}", e);
            return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": e
            }))));
        }
    }

    let state = state.read().await;

    // Delete from storage
    if let Err(_) = state.storage.delete_release(&id) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to delete release"
        }))));
    }

    // SPORE: Compute double-hash tombstone and add to DoNotWantList
    let tombstone = double_hash_id(&id);

    // Add to mesh state's do_not_want set
    if let Some(ref mesh_state) = state.mesh_state {
        let mut mesh = mesh_state.write().await;
        mesh.do_not_want.insert(tombstone);
        let self_id = mesh.self_id.clone();
        drop(mesh); // Release lock before flooding

        // Flood the tombstone to propagate deletion through mesh
        if let Some(ref flood_tx) = state.flood_tx {
            let _ = flood_tx.send(FloodMessage::DoNotWantList {
                peer_id: self_id,
                double_hashes: vec![tombstone],
            });
            tracing::info!("SPORE: Flooding tombstone for deleted release {}", id);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

// --- Category endpoints ---

async fn list_categories(
    State(state): State<AppState>,
) -> Result<Json<Vec<Category>>, StatusCode> {
    let state = state.read().await;
    let categories = state
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(categories))
}

async fn get_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Category>, StatusCode> {
    let state = state.read().await;
    let categories = state
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    categories
        .into_iter()
        .find(|c| c.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCategoryRequest {
    /// Public key for authentication
    public_key: String,
    id: Option<String>,
    category_id: Option<String>,
    name: Option<String>,
    display_name: Option<String>,
    slug: Option<String>,
    metadata_schema: Option<serde_json::Value>,
    featured: Option<bool>,
}

async fn create_category(
    State(state): State<AppState>,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state_read = state.read().await;

    // Check if requester is admin
    if !state_read.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to create categories"
        })));
    }
    drop(state_read);

    // Use categoryId or id
    let id = match req.category_id.or(req.id) {
        Some(id) => id,
        None => return Ok(Json(serde_json::json!({
            "error": "Category ID is required"
        }))),
    };
    // Use displayName or name
    let name = match req.display_name.or(req.name) {
        Some(name) => name,
        None => return Ok(Json(serde_json::json!({
            "error": "Category name is required"
        }))),
    };

    let category = Category::with_schema(
        id,
        name,
        req.featured.unwrap_or(false),
        req.metadata_schema,
    );

    let state = state.write().await;
    state
        .storage
        .save_category(&category)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::to_value(&category).unwrap()))
}

async fn update_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state_write = state.write().await;

    // Check if requester is admin
    if !state_write.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to update categories"
        })));
    }

    // Get existing category
    let categories = state_write
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let existing = match categories.into_iter().find(|c| c.id == id) {
        Some(cat) => cat,
        None => return Ok(Json(serde_json::json!({
            "error": "Category not found"
        }))),
    };

    // Update fields
    let name = req.display_name.or(req.name).unwrap_or(existing.name);
    let category = Category::with_schema(
        id,
        name,
        req.featured.unwrap_or(existing.featured),
        req.metadata_schema.or(existing.metadata_schema),
    );

    state_write
        .storage
        .save_category(&category)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::to_value(&category).unwrap()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteCategoryRequest {
    /// Public key for authentication
    public_key: String,
}

async fn delete_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DeleteCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.write().await;

    // Check if requester is admin
    if !state.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to delete categories"
        })));
    }

    state
        .storage
        .delete_category(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "deleted": id
    })))
}

// --- Featured releases endpoints ---

/// List all featured releases (returns all, client filters by time)
async fn list_featured_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<FeaturedRelease>>, StatusCode> {
    let state = state.read().await;
    let featured = state
        .storage
        .list_featured_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(featured))
}

/// Get a single featured release by ID
async fn get_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FeaturedRelease>, StatusCode> {
    let state = state.read().await;
    state
        .storage
        .get_featured_release(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Request body for creating/updating a featured release
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FeaturedReleaseRequest {
    release_id: String,
    start_time: String,
    end_time: String,
    #[serde(default)]
    promoted: bool,
    #[serde(default = "default_priority")]
    priority: u32,
    #[serde(default)]
    order: u32,
    custom_title: Option<String>,
    custom_description: Option<String>,
    custom_thumbnail: Option<String>,
    #[serde(default)]
    regions: Vec<String>,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    variant: Option<String>,
    metadata: Option<serde_json::Value>,
}

fn default_priority() -> u32 {
    500
}

/// Create a new featured release (admin only)
async fn create_featured_release(
    State(state): State<AppState>,
    Json(req): Json<FeaturedReleaseRequest>,
) -> Result<(StatusCode, Json<FeaturedRelease>), StatusCode> {
    // Verify the release exists
    {
        let state = state.read().await;
        if state.storage.get_release(&req.release_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.is_none() {
            return Err(StatusCode::BAD_REQUEST); // Release doesn't exist
        }
    }

    let id = FeaturedRelease::generate_id();
    let mut featured = FeaturedRelease::new(
        id,
        req.release_id,
        req.start_time,
        req.end_time,
    );

    // Apply optional fields
    featured.promoted = req.promoted;
    featured.priority = req.priority;
    featured.order = req.order;
    featured.custom_title = req.custom_title;
    featured.custom_description = req.custom_description;
    featured.custom_thumbnail = req.custom_thumbnail;
    featured.regions = req.regions;
    featured.languages = req.languages;
    featured.tags = req.tags;
    featured.variant = req.variant;
    featured.metadata = req.metadata;

    let state = state.read().await;
    state
        .storage
        .put_featured_release(&featured)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(featured)))
}

/// Update an existing featured release (admin only)
async fn update_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FeaturedReleaseRequest>,
) -> Result<Json<FeaturedRelease>, StatusCode> {
    let state = state.read().await;

    // Get existing featured release
    let mut featured = state
        .storage
        .get_featured_release(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify the release exists if changing releaseId
    if featured.release_id != req.release_id {
        if state.storage.get_release(&req.release_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Update fields
    featured.release_id = req.release_id;
    featured.start_time = req.start_time;
    featured.end_time = req.end_time;
    featured.promoted = req.promoted;
    featured.priority = req.priority;
    featured.order = req.order;
    featured.custom_title = req.custom_title;
    featured.custom_description = req.custom_description;
    featured.custom_thumbnail = req.custom_thumbnail;
    featured.regions = req.regions;
    featured.languages = req.languages;
    featured.tags = req.tags;
    featured.variant = req.variant;
    featured.metadata = req.metadata;

    state
        .storage
        .put_featured_release(&featured)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(featured))
}

/// Delete a featured release (admin only)
async fn delete_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    let state = state.read().await;

    // Check if exists
    match state.storage.get_featured_release(&id) {
        Ok(Some(_)) => {
            if state.storage.delete_featured_release(&id).is_ok() {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
        Ok(None) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// --- Account endpoints ---

/// Account status response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountStatus {
    public_key: String,
    is_admin: bool,
    roles: Vec<String>,
    permissions: Vec<String>,
}

async fn get_account(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<Json<AccountStatus>, StatusCode> {
    let state = state.read().await;

    // Check if this public key is an admin (managed via lens-admin CLI)
    let is_admin = state.storage.is_admin(&public_key).unwrap_or(false);

    let (roles, permissions) = if is_admin {
        (
            vec!["admin".to_string()],
            vec![
                "upload".to_string(),
                "delete".to_string(),
                "moderate".to_string(),
                "admin".to_string(),
            ],
        )
    } else {
        // Regular user - check if they have upload permission
        let has_upload = state.storage.has_permission(&public_key, "upload").unwrap_or(false);
        let permissions = if has_upload {
            vec!["upload".to_string()]
        } else {
            vec![]
        };
        (vec!["user".to_string()], permissions)
    };

    Ok(Json(AccountStatus {
        public_key,
        is_admin,
        roles,
        permissions,
    }))
}

// --- Network Map endpoints ---

/// Network map showing actual mesh state (emergent topology, no predefined dimensions)
#[derive(Debug, Serialize)]
struct NetworkMap {
    /// This node's view of the mesh
    self_node: PeerNode,
    /// All known nodes in the mesh
    nodes: Vec<PeerNode>,
    /// Active connections between nodes
    edges: Vec<PeerEdge>,
    /// Live mesh statistics
    stats: NetworkStats,
}

#[derive(Debug, Clone, Serialize)]
struct PeerNode {
    id: String,
    label: String,
    /// Hex coordinates in the mesh (emergent from node ID hash)
    slot: HexSlot,
    peer_type: String,
    last_heartbeat: u64,
    capabilities: Vec<String>,
    online: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HexSlot {
    /// SPIRAL index (slot number in enumeration order)
    index: Option<u64>,
    /// Hex axial coordinate q
    q: i64,
    /// Hex axial coordinate r
    r: i64,
    /// Vertical layer z (2.5D)
    z: i64,
}

/// Latency statistics over multiple time windows
#[derive(Debug, Serialize, Clone, Default)]
pub struct LatencyStats {
    /// Average latency over last 1 second
    pub last_1s_ms: Option<f64>,
    /// Average latency over last 60 seconds
    pub last_60s_ms: Option<f64>,
    /// Average latency over last hour
    pub last_1h_ms: Option<f64>,
    /// Sample count in each window
    pub samples_1s: u32,
    pub samples_60s: u32,
    pub samples_1h: u32,
}

#[derive(Debug, Serialize)]
struct PeerEdge {
    from: String,
    to: String,
    connection_type: String,  // "neighbor" or "relay"
    latency_ms: Option<u32>,  // Most recent measurement
    latency_stats: LatencyStats,  // Multi-window averages for hover display
    bidirectional: bool,
}

#[derive(Debug, Serialize)]
struct NetworkStats {
    total_nodes: u32,
    server_nodes: u32,
    browser_nodes: u32,
    total_edges: u32,
    avg_latency_ms: Option<f64>,
}

async fn get_network_map(
    State(state): State<AppState>,
) -> Json<NetworkMap> {
    let state = state.read().await;
    let config = &state.config;

    // Get our actual PeerID and SPIRAL slot from mesh state
    let (self_id, self_slot_opt) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        (mesh.self_id.clone(), mesh.self_slot.clone())
    } else {
        (format!("lens-{}", config.p2p_addr.port()), None)
    };

    // Pure SPIRAL slot - only use actual claimed slot
    let slot = if let Some(ref claim) = self_slot_opt {
        HexSlot {
            index: Some(claim.index),
            q: claim.coord.q,
            r: claim.coord.r,
            z: claim.coord.z,
        }
    } else {
        // No slot claimed yet - position at origin until claimed
        HexSlot { index: None, q: 0, r: 0, z: 0 }
    };

    let short_self_id = short_peer_id(&self_id);
    let self_node = PeerNode {
        id: short_self_id.clone(),
        label: short_self_id.clone(),  // Use peer ID as label, not IP
        slot: slot.clone(),
        peer_type: "server".to_string(),
        last_heartbeat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        capabilities: vec!["storage".to_string(), "relay".to_string(), "api".to_string()],
        online: true,
    };

    // Query actual mesh state from mesh service
    let mut nodes = vec![self_node.clone()];
    let mut edges = Vec::new();

    if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;

        // Build a map of coordinates to node IDs for SPIRAL edge computation
        use citadel_topology::{HexCoord, Neighbors};
        let mut coord_to_node: HashMap<HexCoord, String> = HashMap::new();

        // Add self to coord map if we have a slot
        if let Some(ref claim) = self_slot_opt {
            coord_to_node.insert(claim.coord, short_self_id.clone());
        }

        // First pass: collect all nodes from claimed_slots (the authoritative source)
        for (slot_index, claim) in &mesh.claimed_slots {
            let short_id = short_peer_id(&claim.peer_id);

            // Skip self (already added)
            if short_id == short_self_id {
                continue;
            }

            // TGP-NATIVE: Check authorized_peers (QuadProof-verified), not TCP peers
            let (online, last_heartbeat) = if let Some(auth_peer) = mesh.authorized_peers.get(&claim.peer_id) {
                // Authorized via QuadProof - definitely connected
                (true, auth_peer.established.elapsed().as_secs())
            } else {
                // Check by short ID prefix match in authorized_peers
                let connected = mesh.authorized_peers.keys().any(|k| short_peer_id(k) == short_id);
                (connected, 0)
            };

            nodes.push(PeerNode {
                id: short_id.clone(),
                label: short_id.clone(),
                slot: HexSlot {
                    index: Some(*slot_index),
                    q: claim.coord.q,
                    r: claim.coord.r,
                    z: claim.coord.z,
                },
                peer_type: "server".to_string(),
                last_heartbeat,
                capabilities: vec!["storage".to_string(), "relay".to_string()],
                online,
            });

            coord_to_node.insert(claim.coord, short_id);
        }

        // Second pass: compute SPIRAL edges based on actual hex neighbor topology
        // For each node, check which of its 20 theoretical neighbors exist in the mesh
        let mut seen_edges: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

        for (coord, node_id) in &coord_to_node {
            let neighbor_coords = Neighbors::of(*coord);

            for neighbor_coord in neighbor_coords {
                if let Some(neighbor_id) = coord_to_node.get(&neighbor_coord) {
                    // Create canonical edge (smaller ID first to avoid duplicates)
                    let (from, to) = if node_id < neighbor_id {
                        (node_id.clone(), neighbor_id.clone())
                    } else {
                        (neighbor_id.clone(), node_id.clone())
                    };

                    if !seen_edges.contains(&(from.clone(), to.clone())) {
                        seen_edges.insert((from.clone(), to.clone()));

                        // Look up latency stats from accountability tracker if available
                        let latency_stats = mesh.latency_history
                            .get(node_id)
                            .and_then(|history| history.get(neighbor_id))
                            .map(|h| h.compute_stats())
                            .unwrap_or_default();

                        let latency_ms = latency_stats.last_1s_ms.map(|v| v as u32);

                        edges.push(PeerEdge {
                            from,
                            to,
                            connection_type: "neighbor".to_string(),
                            latency_ms,
                            latency_stats,
                            bidirectional: true,
                        });
                    }
                }
            }
        }
    }

    let stats = NetworkStats {
        total_nodes: nodes.len() as u32,
        server_nodes: nodes.iter().filter(|n| n.peer_type == "server").count() as u32,
        browser_nodes: nodes.iter().filter(|n| n.peer_type == "browser").count() as u32,
        total_edges: edges.len() as u32,
        avg_latency_ms: if edges.is_empty() {
            None
        } else {
            let total: u32 = edges.iter().filter_map(|e| e.latency_ms).sum();
            Some(total as f64 / edges.len() as f64)
        },
    };

    Json(NetworkMap {
        self_node,
        nodes,
        edges,
        stats,
    })
}

/// Shorten a peer ID for display (first 12 chars of hash)
pub fn short_peer_id(id: &str) -> String {
    let hash = id.strip_prefix("b3b3/").unwrap_or(id);
    hash.chars().take(12).collect()
}

// --- Mesh State endpoint ---

#[derive(Debug, Serialize)]
struct MeshStateResponse {
    /// Our peer ID
    self_id: String,
    /// Our claimed slot (if any)
    our_slot: Option<SlotInfo>,
    /// Number of connected peers
    peer_count: usize,
    /// All claimed slots in the mesh
    slot_claims: Vec<SlotInfo>,
    /// Connected peers
    peers: Vec<PeerSummary>,
    /// Active TGP sessions count
    tgp_sessions: usize,
}

#[derive(Debug, Serialize)]
struct SlotInfo {
    index: u64,
    peer_id: String,
    coord: CoordInfo,
}

#[derive(Debug, Serialize)]
struct CoordInfo {
    q: i64,
    r: i64,
    z: i64,
}

#[derive(Debug, Serialize)]
struct PeerSummary {
    id: String,
    addr: String,
    slot: Option<u64>,
    coordinated: bool,
    last_seen_ms: u64,
}

async fn get_mesh_state(
    State(state): State<AppState>,
) -> Json<MeshStateResponse> {
    let state = state.read().await;

    let (self_id, our_slot, peer_count, slot_claims, peers) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;

        let our_slot = mesh.self_slot.as_ref().map(|s| SlotInfo {
            index: s.index,
            peer_id: short_peer_id(&mesh.self_id),
            coord: CoordInfo { q: s.coord.q, r: s.coord.r, z: s.coord.z },
        });

        let slot_claims: Vec<SlotInfo> = mesh.claimed_slots.iter()
            .map(|(idx, claim)| SlotInfo {
                index: *idx,
                peer_id: short_peer_id(&claim.peer_id),
                coord: CoordInfo { q: claim.coord.q, r: claim.coord.r, z: claim.coord.z },
            })
            .collect();

        // TGP-NATIVE: Use authorized_peers (QuadProof-verified) instead of TCP peers
        let peers: Vec<PeerSummary> = mesh.authorized_peers.iter()
            .map(|(id, auth_peer)| PeerSummary {
                id: short_peer_id(id),
                addr: auth_peer.last_addr.to_string(),
                slot: auth_peer.slot.as_ref().map(|s| s.index),
                coordinated: true, // Always true - only QuadProof-verified peers are in authorized_peers
                last_seen_ms: auth_peer.established.elapsed().as_millis() as u64,
            })
            .collect();

        (mesh.self_id.clone(), our_slot, mesh.authorized_peers.len(), slot_claims, peers)
    } else {
        (String::new(), None, 0, Vec::new(), Vec::new())
    };

    Json(MeshStateResponse {
        self_id: short_peer_id(&self_id),
        our_slot,
        peer_count,
        slot_claims,
        peers,
        tgp_sessions: 0, // TODO: expose TGP session count
    })
}

// --- Import/Export endpoints ---

/// Legacy Lens SDK v1 export format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyExport {
    version: String,
    export_date: String,
    releases: Vec<LegacyRelease>,
    /// Featured releases (optional for backwards compatibility)
    #[serde(default)]
    featured_releases: Vec<FeaturedRelease>,
}

/// Legacy release format from Lens SDK v1
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyRelease {
    id: String,
    /// Can be either a string ("ed25519p/...") or legacy byte array object
    #[serde(deserialize_with = "deserialize_posted_by")]
    posted_by: Option<String>,
    site_address: Option<String>,
    name: String,
    category_id: String,
    category_slug: Option<String>,
    #[serde(alias = "contentCID")]
    content_cid: Option<String>,
    #[serde(alias = "thumbnailCID")]
    thumbnail_cid: Option<String>,
    metadata: Option<serde_json::Value>,
}

/// Legacy public key format (byte array object)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPublicKey {
    public_key: Option<HashMap<String, u8>>,
}

/// Custom deserializer for posted_by that handles both string and legacy object formats
fn deserialize_posted_by<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;

    match value {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            // Already a string like "ed25519p/..."
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        Some(serde_json::Value::Object(obj)) => {
            // Legacy format: { "publicKey": { "0": 123, "1": 45, ... } }
            if let Some(public_key_val) = obj.get("publicKey").or(obj.get("public_key")) {
                if let Some(key_map) = public_key_val.as_object() {
                    let mut bytes = Vec::new();
                    for i in 0..32 {
                        if let Some(byte_val) = key_map.get(&i.to_string()) {
                            if let Some(byte) = byte_val.as_u64() {
                                bytes.push(byte as u8);
                            }
                        }
                    }
                    if bytes.len() == 32 {
                        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        return Ok(Some(format!("ed25519p/{}", hex)));
                    }
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Export data format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportData {
    version: String,
    export_date: String,
    releases: Vec<Release>,
    featured_releases: Vec<FeaturedRelease>,
}

/// Import response
#[derive(Debug, Serialize)]
struct ImportResponse {
    success: bool,
    imported: usize,
    skipped: usize,
    errors: Vec<String>,
}

/// POST /api/v1/import - Import releases from legacy format
/// Requires admin signature authentication via X-Public-Key, X-Signature, X-Timestamp headers
async fn import_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ImportResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Public-Key header"
        }))))?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Signature header"
        }))))?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing X-Timestamp header"
        }))))?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) = require_admin_signature(&state.storage, public_key, signature, timestamp, &body) {
            tracing::warn!("Auth failed for import_releases: {}", e);
            return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": e
            }))));
        }
    }

    // Parse the import data (body is the legacy export JSON directly)
    let legacy_export: LegacyExport = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Failed to parse import data: {}", e)
        }))))?;

    let state = state.read().await;

    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    tracing::info!(
        "Importing {} releases from legacy format v{}",
        legacy_export.releases.len(),
        legacy_export.version
    );

    for legacy_release in legacy_export.releases {
        // Check if release already exists
        if state.storage.get_release(&legacy_release.id).ok().flatten().is_some() {
            tracing::debug!("Skipping existing release: {}", legacy_release.id);
            skipped += 1;
            continue;
        }

        // Use posted_by directly (already converted by deserializer)
        let creator = legacy_release.posted_by.clone();

        let mut release = Release::new(
            legacy_release.id.clone(),
            legacy_release.name,
            legacy_release.category_slug.unwrap_or(legacy_release.category_id),
        );
        release.creator = creator;
        release.thumbnail_cid = legacy_release.thumbnail_cid;
        release.content_cid = legacy_release.content_cid;
        release.site_address = legacy_release.site_address;
        // Store raw metadata for Flagship compatibility
        release.metadata = legacy_release.metadata.clone();

        // Extract metadata fields if available
        if let Some(metadata) = &legacy_release.metadata {
            if let Some(year) = metadata.get("year").and_then(|y| y.as_u64()) {
                release.year = Some(year as u32);
            }
            if let Some(desc) = metadata.get("description").and_then(|d| d.as_str()) {
                release.description = Some(desc.to_string());
            }
        }

        // Save release
        if let Err(e) = state.storage.put_release(&release) {
            errors.push(format!("Failed to save release {}: {}", legacy_release.id, e));
            continue;
        }

        // SPORE: Flood the release to propagate across mesh
        if let Some(ref flood_tx) = state.flood_tx {
            if let Ok(json) = serde_json::to_string(&release) {
                let _ = flood_tx.send(FloodMessage::Release { release_json: json });
                tracing::debug!("SPORE: Flooding imported release {}", release.id);
            }
        }

        imported += 1;
    }

    tracing::info!("Releases import complete: {} imported, {} skipped", imported, skipped);

    // Import featured releases if present
    let mut featured_imported = 0;
    let mut featured_skipped = 0;
    for featured in legacy_export.featured_releases {
        // Check if featured release already exists
        if state.storage.get_featured_release(&featured.id).ok().flatten().is_some() {
            tracing::debug!("Skipping existing featured release: {}", featured.id);
            featured_skipped += 1;
            continue;
        }

        // Save featured release
        if let Err(e) = state.storage.put_featured_release(&featured) {
            errors.push(format!("Failed to save featured release {}: {}", featured.id, e));
            continue;
        }

        featured_imported += 1;
    }

    if featured_imported > 0 || featured_skipped > 0 {
        tracing::info!("Featured releases import: {} imported, {} skipped", featured_imported, featured_skipped);
    }

    // SPORE: Broadcast our updated ContentHaveList so peers know our complete state
    if imported > 0 {
        if let Some(ref flood_tx) = state.flood_tx {
            if let Ok(all_releases) = state.storage.list_releases() {
                let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
                let _ = flood_tx.send(FloodMessage::ContentHaveList {
                    peer_id: "api-import".to_string(), // API doesn't have mesh identity
                    release_ids,
                });
                tracing::info!("SPORE: Broadcast ContentHaveList with {} releases after import", all_releases.len());
            }
        }
    }

    Ok(Json(ImportResponse {
        success: errors.is_empty(),
        imported,
        skipped,
        errors,
    }))
}

/// GET /api/v1/export - Export all releases and featured releases
async fn export_releases(
    State(state): State<AppState>,
) -> Result<Json<ExportData>, StatusCode> {
    let state = state.read().await;

    let releases = state.storage
        .list_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let featured_releases = state.storage
        .list_featured_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Exporting {} releases and {} featured releases", releases.len(), featured_releases.len());

    Ok(Json(ExportData {
        version: "2.0".to_string(),
        export_date: chrono::Utc::now().to_rfc3339(),
        releases,
        featured_releases,
    }))
}

/// Delete all releases request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteAllRequest {
    public_key: String,
}

/// DELETE /api/v1/admin/releases - Delete ALL releases
async fn delete_all_releases(
    State(state): State<AppState>,
    Json(req): Json<DeleteAllRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.read().await;

    // Check if requester is admin
    if !state.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Admin permission required"
        })));
    }

    match state.storage.delete_all_releases() {
        Ok(count) => {
            tracing::warn!("Deleted {} releases by admin {}", count, req.public_key);
            Ok(Json(serde_json::json!({
                "success": true,
                "deleted": count
            })))
        }
        Err(e) => {
            tracing::error!("Failed to delete releases: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

