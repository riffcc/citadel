//! Citadel Lens - Distributed Content Platform
//!
//! A peer-to-peer content distribution node built on the Citadel mesh.
//! Provides content storage, synchronization, and an HTTP API for clients.
//!
//! # Architecture
//!
//! - **Models**: Content types (Release, ContentItem, etc.)
//! - **Storage**: RocksDB-backed persistent storage
//! - **Mesh**: Integration with Citadel DHT and protocols
//! - **API**: HTTP endpoints for content management
//! - **Admin Socket**: Unix socket for local admin commands (lens-admin CLI)
//!
//! # Example
//!
//! ```no_run
//! use citadel_lens::{LensNode, LensConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = LensConfig::default();
//!     let node = LensNode::new(config).await?;
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

pub mod models;
pub mod storage;
pub mod node;
pub mod api;
pub mod admin_socket;
pub mod mesh;
pub mod ws;
pub mod error;
pub mod vdf_race;
pub mod proof_of_latency;
pub mod pvdf;
pub mod cvdf;
pub mod accountability;
#[cfg(test)]
mod convergence_test;

pub use models::{
    Category, ContentItem, ContentType, Creator, CreatorRole, DataCiteCreator,
    DataCiteResourceType, DataCiteTitle, License, MetadataContainer, NameIdentifier, Release,
    Resource, StandardMetadata,
};
pub use storage::Storage;
pub use node::{LensNode, LensConfig};
pub use error::{Error, Result};
