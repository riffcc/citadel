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

    // BenPH review: consider something like `type BsPeers(string)`
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
    // BenPH review: go to all places where read and write guards are obtained imediately on
    // function entry, and consider passing in the RwLockRead|WriteGuard<MeshState> in some way
    pub mesh_state: Option<Arc<RwLock<MeshState>>>,
}

/// A Lens node instance.
pub struct LensNode {
    // BenPH review: go to all places where read and write guards are obtained imediately on
    // function entry, and consider passing in the RwLockRead|WriteGuard<LensState> in some way
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

        // Set initial admin public key if provided via env var
        if let Some(ref admin_key) = config.admin_public_key {
            storage.set_admin(admin_key, true)?;
            tracing::info!("Admin public key set: {}", admin_key);
        }

        let state = Arc::new(RwLock::new(LensState {
            storage,
            config: config.clone(),
            mesh_state: None,
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
    }.

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
            self.config.bootstrap_peers.clone(),
            mesh_storage,
        ));

        // Get flood sender for admin socket
        let flood_tx = mesh_service.flood_tx();

        // Start admin socket server in background (with flood capability)
        let admin_socket = AdminSocket::new(
            Arc::clone(&storage),
            self.config.admin_socket.to_str().unwrap_or("./lens-data/admin.sock"),
        ).with_flood_tx(flood_tx);
        tokio::spawn(async move {
            if let Err(e) = admin_socket.run().await {
                tracing::error!("Admin socket error: {}", e);
            }
        });

        // Share mesh state with API layer
        {
            let mut state = self.state.write().await;
            state.mesh_state = Some(mesh_service.mesh_state());
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
