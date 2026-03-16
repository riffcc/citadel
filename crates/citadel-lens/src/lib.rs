//! Citadel Lens - Distributed Content Platform
//!
//! A peer-to-peer content distribution node built on the Citadel mesh.
//!
//! # Feature Flags
//!
//! - `server` (default): Enables the full Lens node with HTTP API, storage,
//!   mesh service, and binary targets. Without this feature, only the FVDF
//!   (Fungible VDF) types and logic are available — suitable for consumers
//!   that need cooperative VDF without pulling in the entire server stack.
//!
//! # FVDF Core (always available)
//!
//! - [`cvdf`] - Cooperative VDF chain, coordinator, attestation washing
//! - [`pvdf`] - Parallel VDF swarm merge evaluation
//! - [`vdf_race`] - Anchored slot claims, VDF chain types
//! - [`proof_of_latency`] - VDF-backed latency proofs
//! - [`accountability`] - Mesh accountability tracking
//! - [`liveness`] - Structure-aware vouch propagation
//!
//! # Server (requires `server` feature)
//!
//! - [`models`] - Content types (Release, ContentItem, etc.)
//! - [`storage`] - redb-backed persistent storage
//! - [`mesh`] - Integration with Citadel DHT and protocols
//! - [`api`] - HTTP endpoints for content management
//! - [`node`] - LensNode server orchestration

// === CVDF Core — always available ===
pub mod accountability;
pub mod cvdf;
pub mod error;
pub mod liveness;
pub mod proof_of_latency;
pub mod pvdf;
pub mod service;
pub mod vdf_race;

// === Server — gated behind "server" feature ===
#[cfg(feature = "server")]
pub mod admin_socket;
#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
pub mod mesh;
#[cfg(feature = "server")]
pub mod models;
#[cfg(feature = "server")]
pub mod node;
#[cfg(feature = "server")]
pub mod storage;
#[cfg(feature = "server")]
pub mod ws;
#[cfg(feature = "server")]
pub mod ws_admin;

#[cfg(all(test, feature = "server"))]
mod convergence_test;

// === Re-exports ===

// FVDF core re-exports (always available)
pub use error::{Error, Result};

// Server re-exports
#[cfg(feature = "server")]
pub use models::{
    Category, ContentItem, ContentType, Creator, CreatorRole, DataCiteCreator,
    DataCiteResourceType, DataCiteTitle, License, MetadataContainer, NameIdentifier, Release,
    Resource, SiteManifest, StandardMetadata,
};
#[cfg(feature = "server")]
pub use node::{LensConfig, LensNode};
#[cfg(feature = "server")]
pub use storage::Storage;
