//! Yggdrasil node — manages peer connections and provides the public API.
//!
//! Pure Rust Yggdrasil node — manages peer connections and provides the public API.
//!   - `new(private_key, peers, listen_addrs)` — start a node
//!   - `address()`, `public_key_hex()` — synchronous identity queries
//!   - `add_peer()`, `remove_peer()` — peer management
//!   - `peers()` — list connected peers

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;

use crate::crypto::Identity;
use crate::error::YggError;
use crate::peer::{self, PeerCommand, PeerEvent, PeerHandle, PeerInfo};
use crate::wire::PacketType;

/// A pure-Rust Yggdrasil node.
///
/// Pure Rust Yggdrasil node. No Go. No FFI. No goroutines.
pub struct YggNode {
    identity: Arc<Identity>,
    peers: Arc<RwLock<HashMap<[u8; 32], PeerHandle>>>,
    event_tx: mpsc::Sender<PeerEvent>,
    event_rx_handle: JoinHandle<()>,
    listener_handles: Vec<JoinHandle<()>>,
    /// Channel for the consumer to receive peer events.
    consumer_rx: mpsc::Receiver<PeerEvent>,
    password: Option<Vec<u8>>,
    /// Actual bound addresses of all listeners (resolved from :0 etc).
    bound_addrs: Vec<SocketAddr>,
    /// Watch channel broadcasting current peer count (event-driven, no polling).
    peer_count_tx: watch::Sender<usize>,
}

/// Builder for configuring a node before starting it.
pub struct NodeBuilder {
    private_key: [u8; 64],
    peers: Vec<String>,
    listen_addrs: Vec<String>,
    password: Option<Vec<u8>>,
}

impl NodeBuilder {
    pub fn new(private_key: &[u8; 64]) -> Self {
        Self {
            private_key: *private_key,
            peers: Vec::new(),
            listen_addrs: Vec::new(),
            password: None,
        }
    }

    pub fn peers(mut self, peers: &[String]) -> Self {
        self.peers = peers.to_vec();
        self
    }

    pub fn listen(mut self, addrs: &[String]) -> Self {
        self.listen_addrs = addrs.to_vec();
        self
    }

    pub fn password(mut self, pw: Vec<u8>) -> Self {
        self.password = Some(pw);
        self
    }

    pub async fn build(self) -> Result<YggNode, YggError> {
        YggNode::start(self.private_key, self.peers, self.listen_addrs, self.password).await
    }
}

impl YggNode {
    /// Create and start a new Yggdrasil node.
    ///
    /// Create and start a node with the given identity and initial peers.
    pub async fn new(
        private_key: &[u8; 64],
        peers: &[String],
        listen_addrs: &[String],
    ) -> Result<Self, YggError> {
        Self::start(*private_key, peers.to_vec(), listen_addrs.to_vec(), None).await
    }

    async fn start(
        private_key: [u8; 64],
        initial_peers: Vec<String>,
        listen_addrs: Vec<String>,
        password: Option<Vec<u8>>,
    ) -> Result<Self, YggError> {
        let identity = Arc::new(Identity::from_privkey_bytes(&private_key));

        tracing::info!(
            address = %identity.address,
            public_key = %identity.public_key_hex(),
            "yggdrasil-rs: node starting"
        );

        let peers: Arc<RwLock<HashMap<[u8; 32], PeerHandle>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Internal event channel (peer sessions → event processor)
        let (event_tx, mut event_rx) = mpsc::channel::<PeerEvent>(256);
        // Consumer channel (event processor → application)
        let (consumer_tx, consumer_rx) = mpsc::channel::<PeerEvent>(256);
        // Watch channel for peer count (event-driven observation)
        let (peer_count_tx, _) = watch::channel(0usize);
        let peer_count_tx_clone = peer_count_tx.clone();

        // Event processor task
        let peers_clone = peers.clone();
        let event_rx_handle = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match &event {
                    PeerEvent::Connected { info, cmd_tx } => {
                        tracing::info!(
                            addr = %info.addr,
                            uri = %info.uri,
                            inbound = info.inbound,
                            "yggdrasil-rs: peer connected"
                        );
                        let handle = PeerHandle::new(info.clone(), cmd_tx.clone());
                        let mut peers = peers_clone.write().await;
                        peers.insert(info.key, handle);
                        let _ = peer_count_tx_clone.send(peers.len());
                        drop(peers);
                        // try_send: never block. If nobody is consuming events,
                        // dropping them is better than stalling the event processor
                        // (which blocks ALL peer management).
                        let _ = consumer_tx.try_send(event);
                    }
                    PeerEvent::Disconnected { peer_key, reason } => {
                        tracing::info!(
                            peer = %hex::encode(peer_key),
                            reason = %reason,
                            "yggdrasil-rs: peer disconnected"
                        );
                        let mut peers = peers_clone.write().await;
                        peers.remove(peer_key);
                        let _ = peer_count_tx_clone.send(peers.len());
                        drop(peers);
                        let _ = consumer_tx.try_send(event);
                    }
                    PeerEvent::Frame { .. } => {
                        let _ = consumer_tx.try_send(event);
                    }
                }
            }
        });

        // Start listeners
        let mut listener_handles = Vec::new();
        let mut bound_addrs = Vec::new();
        for addr_str in &listen_addrs {
            let bind_addr = addr_str
                .strip_prefix("tcp://")
                .unwrap_or(addr_str);

            match TcpListener::bind(bind_addr).await {
                Ok(listener) => {
                    let local_addr = listener.local_addr()
                        .expect("bound listener must have local address");
                    tracing::info!(addr = %local_addr, "yggdrasil-rs: listening");
                    bound_addrs.push(local_addr);
                    let identity = identity.clone();
                    let event_tx = event_tx.clone();
                    let password = password.clone();
                    let handle = tokio::spawn(async move {
                        accept_loop(listener, identity, event_tx, password).await;
                    });
                    listener_handles.push(handle);
                }
                Err(e) => {
                    tracing::warn!(addr = %bind_addr, error = %e, "yggdrasil-rs: bind failed");
                }
            }
        }

        let node = Self {
            identity,
            peers,
            event_tx,
            event_rx_handle,
            listener_handles,
            consumer_rx,
            password,
            bound_addrs,
            peer_count_tx,
        };

        // Dial initial peers
        for uri in &initial_peers {
            if let Err(e) = node.add_peer(uri) {
                tracing::warn!(uri = %uri, error = %e, "yggdrasil-rs: initial peer dial failed");
            }
        }

        Ok(node)
    }

    /// Our Yggdrasil overlay address (200::/7).
    pub fn address(&self) -> Ipv6Addr {
        self.identity.address
    }

    /// Our Ed25519 public key as lowercase hex (64 characters).
    pub fn public_key_hex(&self) -> String {
        self.identity.public_key_hex()
    }

    /// Our identity (for external use — e.g. building handshake payloads).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// List currently connected peers.
    pub async fn peers(&self) -> Vec<PeerInfo> {
        self.peers
            .read()
            .await
            .values()
            .map(|h| h.info.clone())
            .collect()
    }

    /// Add a peer by URI ("tcp://host:port").
    ///
    /// The connection attempt happens asynchronously.
    /// Returns immediately after queuing the dial.
    pub fn add_peer(&self, uri: &str) -> Result<(), YggError> {
        // Validate URI first
        let _ = peer::parse_uri(uri)?;

        let uri = uri.to_string();
        let identity = self.identity.clone();
        let event_tx = self.event_tx.clone();
        let password = self.password.clone();

        tokio::spawn(async move {
            if let Err(e) = dial_peer(&uri, identity, event_tx, password).await {
                tracing::warn!(uri = %uri, error = %e, "yggdrasil-rs: dial failed");
            }
        });

        Ok(())
    }

    /// Remove a peer by URI.
    ///
    /// Finds the peer matching this URI and shuts down the connection.
    pub async fn remove_peer(&self, uri: &str) -> Result<(), YggError> {
        let mut peers = self.peers.write().await;
        let key_to_remove = peers
            .iter()
            .find(|(_, h)| h.info.uri == uri)
            .map(|(k, _)| *k);

        if let Some(key) = key_to_remove {
            if let Some(handle) = peers.remove(&key) {
                let _ = handle.cmd_tx.try_send(PeerCommand::Shutdown);
            }
            Ok(())
        } else {
            Err(YggError::PeerNotFound(uri.to_string()))
        }
    }

    /// Send an ironwood frame to a specific peer (by public key).
    pub async fn send_to(
        &self,
        peer_key: &[u8; 32],
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Result<(), YggError> {
        let peers = self.peers.read().await;
        let handle = peers
            .get(peer_key)
            .ok_or_else(|| YggError::PeerNotFound(hex::encode(peer_key)))?;
        handle.send(packet_type, payload)
    }

    /// Receive the next peer event (connected, disconnected, frame).
    ///
    /// Returns `None` when the node is shut down.
    pub async fn recv_event(&mut self) -> Option<PeerEvent> {
        self.consumer_rx.recv().await
    }

    /// Broadcast a frame to all connected peers.
    pub async fn broadcast(&self, packet_type: PacketType, payload: &[u8]) {
        let peers = self.peers.read().await;
        for handle in peers.values() {
            let _ = handle.send(packet_type, payload.to_vec());
        }
    }

    /// Accept an externally-provided TCP connection as an inbound peer.
    ///
    /// The switchboard on port 9443 detects "meta" first bytes and hands the
    /// stream here. `spawn_session` performs the full meta handshake and enters
    /// the ironwood read/write loop — identical to what the internal accept_loop does.
    pub fn accept_inbound(&self, stream: TcpStream, uri: String) {
        peer::spawn_session(
            stream,
            self.identity.clone(),
            uri,
            true, // inbound
            self.event_tx.clone(),
            self.password.clone(),
        );
    }

    /// Dial a peer using a pre-connected TCP stream (outbound).
    ///
    /// Used for Ygg-over-switchboard: the caller completes the switchboard
    /// half-dial to get a stream that's L4-spliced to the target's port 9443,
    /// then hands the stream here for the Ygg meta handshake.
    pub fn dial_via_stream(&self, stream: TcpStream, uri: String) {
        peer::spawn_session(
            stream,
            self.identity.clone(),
            uri,
            false, // outbound
            self.event_tx.clone(),
            self.password.clone(),
        );
    }

    /// Number of currently connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Actual bound addresses of all listeners.
    ///
    /// When binding to port 0, the OS assigns a port. This method returns the
    /// resolved addresses so callers (tests, switchboard) know where to connect.
    pub fn listener_addrs(&self) -> &[SocketAddr] {
        &self.bound_addrs
    }

    /// Subscribe to peer count changes (event-driven, no polling).
    ///
    /// Returns a watch receiver whose value updates on every connect/disconnect.
    /// Use `rx.changed().await` to wait for the next change, then `*rx.borrow()`
    /// to read the current count.
    pub fn peer_count_watch(&self) -> watch::Receiver<usize> {
        self.peer_count_tx.subscribe()
    }
}

impl Drop for YggNode {
    fn drop(&mut self) {
        // Abort all background tasks
        self.event_rx_handle.abort();
        for handle in &self.listener_handles {
            handle.abort();
        }
    }
}

/// Accept loop for a TCP listener.
async fn accept_loop(
    listener: TcpListener,
    identity: Arc<Identity>,
    event_tx: mpsc::Sender<PeerEvent>,
    password: Option<Vec<u8>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!(remote = %addr, "yggdrasil-rs: accepted connection");
                let uri = format!("tcp://[{}]:{}", addr.ip(), addr.port());
                peer::spawn_session(
                    stream,
                    identity.clone(),
                    uri,
                    true, // inbound
                    event_tx.clone(),
                    password.clone(),
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "yggdrasil-rs: accept failed");
            }
        }
    }
}

/// Dial a peer by URI, perform meta handshake, and enter session.
async fn dial_peer(
    uri: &str,
    identity: Arc<Identity>,
    event_tx: mpsc::Sender<PeerEvent>,
    password: Option<Vec<u8>>,
) -> Result<(), YggError> {
    let (host, port, _tls) = peer::parse_uri(uri)?;

    // TODO: TLS support via tokio-rustls when scheme is "tls://"
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let stream = tokio::net::TcpStream::connect(&addr).await?;

    tracing::debug!(uri = %uri, "yggdrasil-rs: connected, starting handshake");

    peer::spawn_session(
        stream,
        identity,
        uri.to_string(),
        false, // outbound
        event_tx,
        password,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn test_privkey(seed_byte: u8) -> [u8; 64] {
        let seed = [seed_byte; 32];
        let id = Identity::from_seed(&seed);
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&seed);
        key[32..].copy_from_slice(&id.public_key_bytes);
        key
    }

    #[tokio::test]
    async fn node_creates_with_identity() {
        let key = test_privkey(1);
        let node = YggNode::new(&key, &[], &[]).await.unwrap();

        assert!(crypto::is_yggdrasil_addr(&node.address()));
        assert_eq!(node.public_key_hex().len(), 64);
    }

    #[tokio::test]
    async fn two_nodes_different_addresses() {
        let node_a = YggNode::new(&test_privkey(1), &[], &[]).await.unwrap();
        let node_b = YggNode::new(&test_privkey(2), &[], &[]).await.unwrap();

        assert_ne!(node_a.address(), node_b.address());
    }

    #[tokio::test]
    async fn node_starts_with_zero_peers() {
        let node = YggNode::new(&test_privkey(1), &[], &[]).await.unwrap();
        assert_eq!(node.peer_count().await, 0);
    }

    #[tokio::test]
    async fn two_nodes_peer_directly() {
        // Node A listens on OS-assigned port
        let node_a = YggNode::new(
            &test_privkey(1),
            &[],
            &["tcp://127.0.0.1:0".to_string()],
        )
        .await
        .unwrap();

        let port_a = node_a.listener_addrs()[0].port();
        assert_eq!(node_a.peer_count().await, 0);

        // Node B dials Node A
        let node_b = YggNode::new(
            &test_privkey(2),
            &[format!("tcp://127.0.0.1:{port_a}")],
            &[],
        )
        .await
        .unwrap();

        // Wait for connections (event-driven via watch channel)
        let mut rx_a = node_a.peer_count_watch();
        let mut rx_b = node_b.peer_count_watch();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Wait for A to see 1 peer (inbound from B)
            while *rx_a.borrow_and_update() < 1 {
                rx_a.changed().await.unwrap();
            }
            // Wait for B to see 1 peer (outbound to A)
            while *rx_b.borrow_and_update() < 1 {
                rx_b.changed().await.unwrap();
            }
        })
        .await
        .expect("peers should connect within 5 seconds");

        assert_eq!(node_a.peer_count().await, 1);
        assert_eq!(node_b.peer_count().await, 1);

        // Verify B sees A's key
        let a_peers = node_a.peers().await;
        assert_eq!(a_peers[0].key, Identity::from_seed(&[2; 32]).public_key_bytes);

        // Verify A sees B's key
        let b_peers = node_b.peers().await;
        assert_eq!(b_peers[0].key, Identity::from_seed(&[1; 32]).public_key_bytes);
    }

    #[tokio::test]
    async fn two_nodes_peer_over_ipv6() {
        // Node A listens on IPv6 loopback
        let node_a = YggNode::new(
            &test_privkey(3),
            &[],
            &["tcp://[::1]:0".to_string()],
        )
        .await
        .unwrap();

        let port_a = node_a.listener_addrs()[0].port();
        assert_eq!(node_a.peer_count().await, 0);

        // Node B dials Node A via IPv6 URI (tests bracket handling in dial_peer)
        let node_b = YggNode::new(
            &test_privkey(4),
            &[format!("tcp://[::1]:{port_a}")],
            &[],
        )
        .await
        .unwrap();

        // Wait for connections
        let mut rx_a = node_a.peer_count_watch();
        let mut rx_b = node_b.peer_count_watch();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while *rx_a.borrow_and_update() < 1 {
                rx_a.changed().await.unwrap();
            }
            while *rx_b.borrow_and_update() < 1 {
                rx_b.changed().await.unwrap();
            }
        })
        .await
        .expect("IPv6 peers should connect within 5 seconds");

        assert_eq!(node_a.peer_count().await, 1);
        assert_eq!(node_b.peer_count().await, 1);
    }
}
