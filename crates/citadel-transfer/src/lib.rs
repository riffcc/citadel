//! Citadel Transfer - High-performance UDP transport and streaming
//!
//! This crate provides:
//! - High-speed UDP transport with configurable buffers
//! - TGP-style continuous streaming for bulk data transfer
//! - Compatible API for applications migrating from palace-consensus
//!
//! # Design Philosophy
//!
//! Unlike TCP which requests retransmissions, TGP-style streaming floods data
//! continuously at a target rate. Packet loss is compensated by redundant
//! transmissions, achieving linear degradation (50% loss → 50% throughput)
//! rather than TCP's exponential backoff.
//!
//! # Example
//!
//! ```rust,ignore
//! use citadel_transfer::{TransportConfig, TransportHandle, TgpConfig, TgpHandle};
//!
//! // Create UDP transport
//! let config = TransportConfig {
//!     bind: "0.0.0.0:9000".parse()?,
//!     batch: 64,
//!     sndbuf: 4 * 1024 * 1024,
//!     rcvbuf: 4 * 1024 * 1024,
//! };
//! let transport = TransportHandle::new(config).await?;
//! ```

pub mod streaming;
pub mod transport;
pub mod types;

// Re-export main types at crate root
pub use streaming::{ContinuousStreamer, PacketReceiver, TgpConfig, TgpHandle};
pub use transport::{TransportConfig, TransportHandle};
pub use types::{
    Epoch, MsgKind, NodeId, Packet, PacketHeader, SeqNo, StreamId, DEFAULT_PAYLOAD_MTU,
};
