use std::io;

/// Errors from the Yggdrasil node.
#[derive(Debug, thiserror::Error)]
pub enum YggError {
    #[error("invalid peer URI: {0}")]
    InvalidUri(String),

    #[error("meta handshake failed: {0}")]
    Handshake(#[from] MetaError),

    #[error("wire protocol error: {0}")]
    Wire(#[from] WireError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("node is shut down")]
    NodeShutdown,

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("send failed: channel closed")]
    SendFailed,
}

/// Errors from the "meta" handshake protocol.
#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("invalid preamble (expected \"meta\")")]
    InvalidPreamble,

    #[error("message truncated")]
    Truncated,

    #[error("TLV field truncated")]
    TruncatedTlv,

    #[error("missing public key in handshake")]
    MissingPublicKey,

    #[error("missing version fields")]
    MissingVersion,

    #[error("version mismatch: got {major}.{minor}, expected 0.5")]
    VersionMismatch { major: u16, minor: u16 },

    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("no signature in handshake message")]
    NoSignature,

    #[error("I/O error during handshake: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the wire framing layer.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("invalid uvarint encoding")]
    InvalidUvarint,

    #[error("empty frame")]
    EmptyFrame,

    #[error("frame too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    FrameTooLarge(u64),

    #[error("unknown packet type: {0}")]
    UnknownPacketType(u8),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Maximum ironwood message size (1 MiB).
pub const MAX_MESSAGE_SIZE: u64 = 1_048_576;
