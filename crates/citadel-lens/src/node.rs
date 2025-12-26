//! Lens Node - the main application entry point.
//!
//! Architecture:
//! - Single daemon process with shared RocksDB storage
//! - HTTP API for clients (releases, categories, accounts)
//! - Unix admin socket for local admin ops (lens-admin CLI)

use crate::admin_socket::AdminSocket;
use crate::api;
use crate::error::Result;
use crate::mesh::{MeshService, MeshState};
use crate::storage::Storage;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for a Lens node.
#[derive(Debug, Clone)]
pub struct LensConfig {
    /// Data directory for storage
    pub data_dir: PathBuf,

    /// HTTP API listen address
    pub api_addr: SocketAddr,

    /// P2P listen address (for mesh)
    pub p2p_addr: SocketAddr,

    /// P2P announce address (public IP for other peers)
    /// If not set, uses p2p_addr (which may be 0.0.0.0)
    pub announce_addr: Option<SocketAddr>,

    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,

    /// Admin socket path (for lens-admin CLI)
    pub admin_socket: PathBuf,

    /// Initial admin public key (hex-encoded ed25519 public key)
    pub admin_public_key: Option<String>,
}

impl Default for LensConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl LensConfig {
    /// Create config from CLI arguments with defaults.
    /// CLI arguments take precedence (clap already handles env var fallback).
    pub fn from_cli(
        data_dir: Option<String>,
        api_bind: Option<String>,
        p2p_bind: Option<String>,
        announce_addr: Option<String>,
        peers: Option<Vec<String>>,
        admin_socket: Option<String>,
        admin_key: Option<String>,
    ) -> Self {
        let data_dir = PathBuf::from(data_dir.unwrap_or_else(|| "./lens-data".to_string()));

        let api_addr = api_bind
            .unwrap_or_else(|| "0.0.0.0:8080".to_string())
            .parse()
            .expect("Invalid api-bind address");

        let p2p_addr = p2p_bind
            .unwrap_or_else(|| "0.0.0.0:9000".to_string())
            .parse()
            .expect("Invalid p2p-bind address");

        let announce_addr = announce_addr
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok());

        // Normalize peers - add default port if missing
        let bootstrap_peers = peers
            .map(|v| {
                v.into_iter()
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        if p.contains(':') {
                            p
                        } else {
                            format!("{}:9000", p)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let admin_socket = admin_socket
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("admin.sock"));

        let admin_public_key = admin_key.filter(|s| !s.is_empty());

        Self {
            data_dir,
            api_addr,
            p2p_addr,
            announce_addr,
            bootstrap_peers,
            admin_socket,
            admin_public_key,
        }
    }

    /// Create config from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        let data_dir = PathBuf::from(
            std::env::var("LENS_DATA_DIR").unwrap_or_else(|_| "./lens-data".to_string())
        );

        let api_addr = std::env::var("LENS_API_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .expect("Invalid LENS_API_BIND");

        let p2p_addr = std::env::var("LENS_P2P_BIND")
            .unwrap_or_else(|_| "0.0.0.0:9000".to_string())
            .parse()
            .expect("Invalid LENS_P2P_BIND");

        // Optional announce address - the public IP:port that other peers should use
        // If not set, we try to use p2p_addr, but that may be 0.0.0.0 which won't work
        let announce_addr = std::env::var("LENS_ANNOUNCE_ADDR")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok());

        // Parse CITADEL_PEERS - accepts DNS names and portless entries (default 9000)
        let bootstrap_peers = std::env::var("CITADEL_PEERS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        // If no port specified, append :9000
                        if p.contains(':') {
                            p
                        } else {
                            format!("{}:9000", p)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let admin_socket = std::env::var("LENS_ADMIN_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("admin.sock"));

        let admin_public_key = std::env::var("ADMIN_PUBLIC_KEY").ok()
            .filter(|s| !s.is_empty());

        Self {
            data_dir,
            api_addr,
            p2p_addr,
            announce_addr,
            bootstrap_peers,
            admin_socket,
            admin_public_key,
        }
    }
}

/// Shared state for the Lens node - single storage instance shared by all components.
pub struct LensState {
    pub storage: Arc<Storage>,
    pub config: LensConfig,
    pub mesh_state: Option<Arc<RwLock<MeshState>>>,
    /// Flood sender for SPORE content propagation
    pub flood_tx: Option<tokio::sync::broadcast::Sender<crate::mesh::FloodMessage>>,
    /// Admin event sender for real-time moderation updates via WebSocket
    pub admin_event_tx: Option<crate::ws_admin::AdminEventSender>,
}

/// A Lens node instance.
pub struct LensNode {
    state: Arc<RwLock<LensState>>,
    config: LensConfig,
}

impl LensNode {
    /// Create a new Lens node.
    pub async fn new(config: LensConfig) -> Result<Self> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Open single shared storage instance
        let storage = Arc::new(Storage::open(&config.data_dir)?);

        // Initialize default categories
        storage.init_default_categories()?;

        // Set initial admin public key(s) if provided via env var
        // Supports comma-separated list, keeps ed25519p/ prefix as part of key
        if let Some(ref admin_keys) = config.admin_public_key {
            for key in admin_keys.split(',') {
                let key = key.trim();
                if !key.is_empty() {
                    storage.set_admin(key, true)?;
                    tracing::info!("Admin public key set: {}", key);
                }
            }
        }

        let state = Arc::new(RwLock::new(LensState {
            storage,
            config: config.clone(),
            mesh_state: None,
            flood_tx: None,
            admin_event_tx: None,
        }));

        Ok(Self { state, config })
    }

    /// Get the shared state (for API handlers).
    pub fn state(&self) -> Arc<RwLock<LensState>> {
        Arc::clone(&self.state)
    }

    /// Get shared storage for admin socket.
    pub async fn storage(&self) -> Arc<Storage> {
        Arc::clone(&self.state.read().await.storage)
    }

    /// Run the node (starts HTTP server, admin socket, and P2P mesh).
    pub async fn run(self) -> Result<()> {
        tracing::info!("Lens node starting");
        tracing::info!("  API: http://{}", self.config.api_addr);
        tracing::info!("  P2P: {}", self.config.p2p_addr);
        tracing::info!("  Admin: {:?}", self.config.admin_socket);
        tracing::info!("  Data: {:?}", self.config.data_dir);
        if self.config.bootstrap_peers.is_empty() {
            tracing::info!("  Peers: none (genesis mode)");
        } else {
            tracing::info!("  Peers: {:?}", self.config.bootstrap_peers);
        }

        // Get shared storage for services
        let storage = self.storage().await;

        // Start mesh service first to get flood sender
        let mesh_storage = self.storage().await;
        let mesh_service = Arc::new(MeshService::new(
            self.config.p2p_addr,
            self.config.announce_addr,
            self.config.bootstrap_peers.clone(),
            mesh_storage,
        ));

        // Get flood sender for admin socket and API
        let flood_tx = mesh_service.flood_tx();

        // Start admin socket server in background (with flood capability)
        let admin_socket = AdminSocket::new(
            Arc::clone(&storage),
            self.config.admin_socket.to_str().unwrap_or("./lens-data/admin.sock"),
        ).with_flood_tx(flood_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = admin_socket.run().await {
                tracing::error!("Admin socket error: {}", e);
            }
        });

        // Create admin event channel for real-time moderation updates
        let (admin_event_tx, _admin_event_rx) = crate::ws_admin::create_admin_channel();

        // Share mesh state, flood_tx, and admin_event_tx with API layer
        {
            let mut state = self.state.write().await;
            state.mesh_state = Some(mesh_service.mesh_state());
            state.flood_tx = Some(flood_tx);
            state.admin_event_tx = Some(admin_event_tx);
        }

        let mesh_clone = Arc::clone(&mesh_service);
        tokio::spawn(async move {
            if let Err(e) = mesh_clone.run().await {
                tracing::error!("Mesh service error: {}", e);
            }
        });

        // Build HTTP API
        let app = api::build_router(self.state.clone());

        // Start HTTP server
        let listener = tokio::net::TcpListener::bind(self.config.api_addr).await?;
        tracing::info!("HTTP server listening on {}", self.config.api_addr);

        axum::serve(listener, app).await?;

        Ok(())
    }
}
