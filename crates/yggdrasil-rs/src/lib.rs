//! yggdrasil-rs — Pure Rust Yggdrasil implementation.
//!
//! Wire-compatible with stock Yggdrasil 0.5.x. No Go. No FFI. No goroutines.
//!
//! # Architecture
//!
//! - **crypto**: Ed25519 identity, 200::/7 address derivation, Blake2b signatures
//! - **meta**: "meta" TLV handshake protocol (peer authentication)
//! - **wire**: Ironwood uvarint framing and packet types
//! - **peer**: TCP peer connection management (sessions, keepalive)
//! - **node**: Public API — `YggNode` manages peers and provides identity

pub mod crypto;
pub mod error;
pub mod meta;
pub mod node;
pub mod peer;
pub mod wire;

// Re-export primary types for convenience
pub use crypto::Identity;
pub use error::{MetaError, WireError, YggError};
pub use node::YggNode;
pub use peer::PeerInfo;
pub use wire::PacketType;
