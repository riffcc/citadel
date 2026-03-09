//! Peer connection management.
//!
//! A peer is a TCP connection that has completed the meta handshake.
//! Each peer runs two concurrent tasks:
//!   - Read loop: reads ironwood frames, forwards to the node event channel
//!   - Write loop: sends keepalives and outbound frames

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::crypto::{self, Identity};
use crate::error::YggError;
use crate::meta;
use crate::wire::{self, PacketType};

/// Keepalive interval — stock Yggdrasil uses ~2 seconds.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// Keepalive timeout — if no message received within this window, peer is dead.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Remote Ed25519 public key (32 bytes).
    pub key: [u8; 32],
    /// Remote Yggdrasil overlay address (200::/7).
    pub addr: Ipv6Addr,
    /// Link priority (from meta handshake).
    pub priority: u8,
    /// Peer URI (e.g. "tcp://10.0.0.1:9443").
    pub uri: String,
    /// Whether this peer connected to us (true) or we dialed them (false).
    pub inbound: bool,
    /// Remote TCP address.
    pub remote_addr: Option<SocketAddr>,
}

/// Commands sent to a peer's write task.
pub enum PeerCommand {
    /// Send an ironwood frame.
    Send(PacketType, Vec<u8>),
    /// Graceful shutdown.
    Shutdown,
}

/// Events emitted by a peer session to the node.
pub enum PeerEvent {
    /// Peer connected and meta handshake completed.
    Connected {
        info: PeerInfo,
        cmd_tx: mpsc::Sender<PeerCommand>,
    },
    /// Received an ironwood frame from this peer.
    Frame {
        peer_key: [u8; 32],
        packet_type: PacketType,
        payload: Vec<u8>,
    },
    /// Peer disconnected (clean or error).
    Disconnected {
        peer_key: [u8; 32],
        reason: String,
    },
}

/// Handle to a running peer session (held by the node's peer table).
pub struct PeerHandle {
    pub info: PeerInfo,
    pub cmd_tx: mpsc::Sender<PeerCommand>,
}

impl PeerHandle {
    /// Create a new peer handle.
    pub fn new(info: PeerInfo, cmd_tx: mpsc::Sender<PeerCommand>) -> Self {
        Self { info, cmd_tx }
    }

    /// Send a frame to this peer.
    pub fn send(&self, packet_type: PacketType, payload: Vec<u8>) -> Result<(), YggError> {
        self.cmd_tx
            .try_send(PeerCommand::Send(packet_type, payload))
            .map_err(|_| YggError::SendFailed)
    }
}

/// Parse a peer URI ("tcp://host:port" or "tls://host:port").
///
/// Returns (host, port, tls).
pub fn parse_uri(uri: &str) -> Result<(String, u16, bool), YggError> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| YggError::InvalidUri(uri.to_string()))?;

    let tls = match scheme {
        "tcp" => false,
        "tls" => true,
        _ => return Err(YggError::InvalidUri(uri.to_string())),
    };

    // Handle IPv6 bracket notation: [::1]:9443
    let (host, port_str) = if rest.starts_with('[') {
        let bracket_end = rest
            .find(']')
            .ok_or_else(|| YggError::InvalidUri(uri.to_string()))?;
        let host = &rest[1..bracket_end];
        let port_str = rest[bracket_end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| YggError::InvalidUri(uri.to_string()))?;
        (host.to_string(), port_str)
    } else {
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| YggError::InvalidUri(uri.to_string()))?;
        (host.to_string(), port)
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| YggError::InvalidUri(uri.to_string()))?;

    Ok((host, port, tls))
}

/// Spawn a peer session from an already-connected TCP stream.
///
/// Performs the meta handshake, then splits into read/write tasks.
/// All events are sent to `event_tx`.
pub fn spawn_session(
    stream: TcpStream,
    identity: Arc<Identity>,
    uri: String,
    inbound: bool,
    event_tx: mpsc::Sender<PeerEvent>,
    password: Option<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let remote_addr = stream.peer_addr().ok();
        if let Err(e) = run_session(stream, identity, uri.clone(), inbound, remote_addr, event_tx.clone(), password).await {
            tracing::debug!(uri = %uri, error = %e, "peer session ended");
        }
    })
}

async fn run_session(
    mut stream: TcpStream,
    identity: Arc<Identity>,
    uri: String,
    inbound: bool,
    remote_addr: Option<SocketAddr>,
    event_tx: mpsc::Sender<PeerEvent>,
    password: Option<Vec<u8>>,
) -> Result<(), YggError> {
    // Meta handshake
    let pw = password.as_deref();
    let remote = meta::handshake(&mut stream, &identity, 0, pw).await?;

    let peer_key = remote.public_key;
    let peer_addr = crypto::address_for_key(&peer_key);

    tracing::info!(
        peer_addr = %peer_addr,
        peer_key = %hex::encode(peer_key),
        uri = %uri,
        inbound,
        "peer: meta handshake complete"
    );

    let info = PeerInfo {
        key: peer_key,
        addr: peer_addr,
        priority: remote.priority,
        uri: uri.clone(),
        inbound,
        remote_addr,
    };

    // Split stream for concurrent read/write
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // Command channel for the write task
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<PeerCommand>(64);

    // Notify node that peer is connected
    let _ = event_tx
        .send(PeerEvent::Connected {
            info: info.clone(),
            cmd_tx: cmd_tx.clone(),
        })
        .await;

    // Write task: keepalives + outbound frames
    let write_task = tokio::spawn(async move {
        let mut keepalive_tick = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(PeerCommand::Send(ptype, payload)) => {
                            if let Err(e) = wire::write_frame(&mut writer, ptype, &payload).await {
                                tracing::debug!(error = %e, "peer write failed");
                                break;
                            }
                        }
                        Some(PeerCommand::Shutdown) | None => break,
                    }
                }
                _ = keepalive_tick.tick() => {
                    if let Err(e) = wire::write_keepalive(&mut writer).await {
                        tracing::debug!(error = %e, "keepalive write failed");
                        break;
                    }
                }
            }
        }
    });

    // Read loop (runs on this task): read frames, forward to node
    let disconnect_reason = read_loop(&mut reader, peer_key, &event_tx).await;

    // Peer disconnected — clean up
    let _ = event_tx
        .send(PeerEvent::Disconnected {
            peer_key,
            reason: disconnect_reason,
        })
        .await;

    write_task.abort();
    let _ = write_task.await;

    Ok(())
}

async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    peer_key: [u8; 32],
    event_tx: &mpsc::Sender<PeerEvent>,
) -> String {
    let mut last_message = tokio::time::Instant::now();

    loop {
        let frame_result = tokio::time::timeout(KEEPALIVE_TIMEOUT, wire::read_frame(reader)).await;

        match frame_result {
            Ok(Ok((PacketType::KeepAlive, _))) => {
                last_message = tokio::time::Instant::now();
            }
            Ok(Ok((packet_type, payload))) => {
                last_message = tokio::time::Instant::now();
                let _ = event_tx
                    .send(PeerEvent::Frame {
                        peer_key,
                        packet_type,
                        payload,
                    })
                    .await;
            }
            Ok(Err(e)) => {
                return format!("read error: {e}");
            }
            Err(_) => {
                let elapsed = last_message.elapsed();
                return format!("keepalive timeout ({elapsed:.1?} since last message)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_uri() {
        let (host, port, tls) = parse_uri("tcp://10.0.0.1:9443").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9443);
        assert!(!tls);
    }

    #[test]
    fn parse_tls_uri() {
        let (host, port, tls) = parse_uri("tls://example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_ipv6_uri() {
        let (host, port, tls) = parse_uri("tcp://[::1]:9443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9443);
        assert!(!tls);
    }

    #[test]
    fn parse_ipv6_full_uri() {
        let (host, port, _) = parse_uri("tcp://[fdaa:0:5b3e:a7b:b3b3:0:a:2]:9443").unwrap();
        assert_eq!(host, "fdaa:0:5b3e:a7b:b3b3:0:a:2");
        assert_eq!(port, 9443);
    }

    #[test]
    fn parse_invalid_uri() {
        assert!(parse_uri("not-a-uri").is_err());
        assert!(parse_uri("udp://host:1234").is_err());
        assert!(parse_uri("tcp://no-port").is_err());
    }
}
