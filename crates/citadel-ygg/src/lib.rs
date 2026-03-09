//! Yggdrasil support primitives for Citadel.
//!
//! This crate is a direct donor seam from Lagoon's Yggdrasil transport work.
//! It intentionally starts small: peer parsing, key-to-address derivation,
//! remote-IP matching, admin-socket discovery/query helpers, and a tiny
//! metrics cache. The full pure-Rust Ygg node now lives in the workspace too,
//! and this crate is the bridge layer that can gradually stop duplicating it.

use std::collections::HashMap;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};
pub use yggdrasil_rs::{
    Identity as YggIdentity, PacketType as YggPacketType, PeerInfo as YggPeerInfo,
    YggError as NodeYggError, YggNode,
};

pub async fn spawn_ygg_node(
    private_key: &[u8; 64],
    peers: &[String],
    listen_addrs: &[String],
) -> Result<YggNode, NodeYggError> {
    YggNode::new(private_key, peers, listen_addrs).await
}

#[derive(Debug, thiserror::Error)]
pub enum YggError {
    #[error("admin socket not available: {0}")]
    SocketUnavailable(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct YggPeer {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub bytes_recvd: u64,
    #[serde(default)]
    pub latency: f64,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub port: u64,
    #[serde(default)]
    pub uptime: f64,
    #[serde(default)]
    pub up: bool,
    #[serde(default)]
    pub inbound: bool,
}

#[derive(Debug, serde::Deserialize)]
struct GetPeersResponse {
    #[serde(default)]
    response: Option<GetPeersInner>,
}

#[derive(Debug, serde::Deserialize)]
struct GetPeersInner {
    #[serde(default)]
    peers: Option<serde_json::Value>,
}

fn parse_peers(value: serde_json::Value) -> Vec<YggPeer> {
    let mut peers = Vec::new();

    if let Ok(arr) = serde_json::from_value::<Vec<YggPeer>>(value.clone()) {
        peers = arr;
    } else if let Ok(map) = serde_json::from_value::<HashMap<String, YggPeer>>(value) {
        peers = map.into_values().collect();
    }

    for peer in &mut peers {
        if peer.address.is_empty() && !peer.key.is_empty() {
            if let Some(addr) = key_to_address(&peer.key) {
                peer.address = addr.to_string();
            }
        }
    }

    peers
}

pub fn key_to_address(key_hex: &str) -> Option<std::net::Ipv6Addr> {
    let key_bytes = hex::decode(key_hex).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }
    let pubkey: [u8; 32] = key_bytes.try_into().ok()?;
    Some(yggdrasil_rs::crypto::address_for_key(&pubkey))
}

async fn resolve_remote_hostname(remote: &str) -> Option<String> {
    let (scheme, host_port) = if let Some(idx) = remote.find("://") {
        (&remote[..idx], &remote[idx + 3..])
    } else {
        ("tcp", remote)
    };

    if host_port.starts_with('[') {
        return None;
    }

    let (host, port) = host_port.rsplit_once(':')?;

    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let lookup = format!("{host}:{port}");
    let mut addrs = tokio::net::lookup_host(&lookup).await.ok()?;
    let first = addrs.next()?;
    let ip = first.ip();

    match ip {
        std::net::IpAddr::V4(v4) => Some(format!("{scheme}://{v4}:{port}")),
        std::net::IpAddr::V6(v6) => Some(format!("{scheme}://[{v6}]:{port}")),
    }
}

pub fn find_peer_by_remote_ip(
    peers: &[YggPeer],
    target_ip: &std::net::IpAddr,
) -> Option<std::net::Ipv6Addr> {
    for peer in peers {
        if peer.remote.is_empty() {
            continue;
        }
        let host_port = peer
            .remote
            .find("://")
            .map(|i| &peer.remote[i + 3..])
            .unwrap_or(&peer.remote);
        let ip_str = if host_port.starts_with('[') {
            host_port
                .find(']')
                .map(|i| &host_port[1..i])
                .unwrap_or(host_port)
        } else {
            host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port)
        };
        let matches = ip_str
            .parse::<std::net::IpAddr>()
            .map(|peer_ip| &peer_ip == target_ip)
            .unwrap_or(false);
        if matches {
            if let Ok(ygg_addr) = peer.address.parse::<std::net::Ipv6Addr>() {
                return Some(ygg_addr);
            }
        }
    }
    None
}

pub async fn query_peers(socket_path: &str) -> Result<Vec<YggPeer>, YggError> {
    let request = b"{\"request\":\"getpeers\"}\n";

    let response_bytes = if socket_path.starts_with("tcp://") {
        let addr = &socket_path["tcp://".len()..];
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        buf
    } else {
        let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        buf
    };

    let envelope: GetPeersResponse = serde_json::from_slice(&response_bytes)?;

    let mut peers = envelope
        .response
        .and_then(|r| r.peers)
        .map(parse_peers)
        .unwrap_or_default();

    for peer in &mut peers {
        if let Some(resolved) = resolve_remote_hostname(&peer.remote).await {
            debug!(
                original = %peer.remote,
                resolved = %resolved,
                address = %peer.address,
                "yggdrasil: resolved peer remote hostname"
            );
            peer.remote = resolved;
        }
    }

    debug!(peer_count = peers.len(), "yggdrasil: getPeers parsed");

    Ok(peers)
}

#[derive(Debug, serde::Deserialize)]
struct GetSelfResponse {
    #[serde(default)]
    response: Option<GetSelfInner>,
}

#[derive(Debug, serde::Deserialize)]
struct GetSelfInner {
    #[serde(default)]
    address: Option<String>,
}

pub fn query_self_sync(socket_path: &str) -> Result<Option<std::net::Ipv6Addr>, YggError> {
    use std::io::{Read, Write};
    let request = b"{\"request\":\"getself\"}\n";

    let response_bytes = if socket_path.starts_with("tcp://") {
        let addr = &socket_path["tcp://".len()..];
        let mut stream = std::net::TcpStream::connect(addr)
            .map_err(|e| YggError::SocketUnavailable(format!("TCP connect to {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .ok();
        stream.write_all(request)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        buf
    } else {
        #[cfg(unix)]
        {
            let mut stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
                YggError::SocketUnavailable(format!("Unix connect to {socket_path}: {e}"))
            })?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            stream.write_all(request)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            buf
        }
        #[cfg(not(unix))]
        {
            return Err(YggError::SocketUnavailable(
                "Unix sockets not supported on this platform".into(),
            ));
        }
    };

    let envelope: GetSelfResponse = serde_json::from_slice(&response_bytes)?;
    Ok(envelope
        .response
        .and_then(|r| r.address)
        .and_then(|s| s.parse().ok()))
}

pub fn detect_admin_socket() -> Option<String> {
    if let Ok(path) = std::env::var("YGGDRASIL_ADMIN_SOCKET") {
        if !path.is_empty() {
            info!(path, "yggdrasil: using admin socket from env");
            return Some(path);
        }
    }

    let unix_path = "/var/run/yggdrasil.sock";
    if std::path::Path::new(unix_path).exists() {
        info!(path = unix_path, "yggdrasil: detected Unix admin socket");
        return Some(unix_path.to_string());
    }

    let tcp_addr = "tcp://localhost:9001";
    debug!("yggdrasil: no Unix socket found, will try TCP at {tcp_addr}");
    Some(tcp_addr.to_string())
}

pub fn is_yggdrasil_ipv6(addr: &std::net::Ipv6Addr) -> bool {
    yggdrasil_rs::crypto::is_yggdrasil_addr(addr)
}

pub fn detect_yggdrasil_addr() -> Option<std::net::Ipv6Addr> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let hex = line.split_whitespace().next().unwrap_or("");
            if hex.len() == 32 && hex.starts_with("02") {
                let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..(i + 1) * 4]).collect();
                let addr_str = groups.join(":");
                if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
                    return Some(addr);
                }
            }
        }
    }

    if let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "addr", "show", "scope", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("inet6 ") {
                if let Some(addr_str) = rest.split('/').next() {
                    if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
                        if is_yggdrasil_ipv6(&addr) {
                            return Some(addr);
                        }
                    }
                }
            }
        }
    }

    None
}

fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr_part, len_part) = s.split_once('/')?;
    let addr = addr_part.parse().ok()?;
    let prefix_len = len_part.parse().ok()?;
    Some((addr, prefix_len))
}

fn addr_in_cidr(addr: std::net::IpAddr, net_addr: std::net::IpAddr, prefix_len: u8) -> bool {
    match (addr, net_addr) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

pub fn detect_underlay_addr() -> Option<std::net::IpAddr> {
    if let Ok(val) = std::env::var("CITADEL_UNDERLAY_ADDR")
        .or_else(|_| std::env::var("LAGOON_UNDERLAY_ADDR"))
    {
        if let Ok(addr) = val.parse::<std::net::IpAddr>() {
            info!(%addr, "underlay: using explicit override");
            return Some(addr);
        }
        debug!(value = %val, "underlay: invalid explicit override, falling back");
    }

    let exclude_cidr = std::env::var("CITADEL_UNDERLAY_EXCLUDE")
        .or_else(|_| std::env::var("LAGOON_UNDERLAY_EXCLUDE"))
        .ok()
        .and_then(|val| parse_cidr(&val));
    let include_cidr = std::env::var("CITADEL_UNDERLAY_INCLUDE")
        .or_else(|_| std::env::var("LAGOON_UNDERLAY_INCLUDE"))
        .ok()
        .and_then(|val| parse_cidr(&val));

    let mut candidates: Vec<std::net::IpAddr> = Vec::new();

    if let Ok(output) = std::process::Command::new("hostname").args(["-I"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for token in stdout.split_whitespace() {
            if let Ok(ip) = token.parse::<std::net::IpAddr>() {
                if !ip.is_loopback() {
                    candidates.push(ip);
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let hex = fields.first().copied().unwrap_or("");
            let dev = fields.get(5).copied().unwrap_or("");
            if hex.len() != 32 {
                continue;
            }
            if dev.starts_with("br-")
                || dev.starts_with("docker")
                || dev.starts_with("veth")
                || dev.starts_with("virbr")
                || dev.starts_with("tun")
                || dev.starts_with("tap")
                || dev.starts_with("wg")
            {
                continue;
            }
            if hex.starts_with("02") || hex.starts_with("03") {
                continue;
            }
            if hex == "00000000000000000000000000000001" || hex.starts_with("fe80") {
                continue;
            }
            let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..(i + 1) * 4]).collect();
            let addr_str = groups.join(":");
            if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
                candidates.push(std::net::IpAddr::V6(addr));
            }
        }
    }

    if let Some((net_addr, prefix_len)) = exclude_cidr {
        candidates.retain(|c| !addr_in_cidr(*c, net_addr, prefix_len));
    }
    if let Some((net_addr, prefix_len)) = include_cidr {
        candidates.retain(|c| addr_in_cidr(*c, net_addr, prefix_len));
    }

    let mut private_ipv4: Option<std::net::IpAddr> = None;
    let mut ula_v6: Option<std::net::IpAddr> = None;
    let mut global_v6: Option<std::net::IpAddr> = None;
    let mut any_addr: Option<std::net::IpAddr> = None;

    for candidate in &candidates {
        match candidate {
            std::net::IpAddr::V4(v4) => {
                if private_ipv4.is_none() && (v4.is_private() || v4.is_link_local()) {
                    private_ipv4 = Some(*candidate);
                }
                if any_addr.is_none() {
                    any_addr = Some(*candidate);
                }
            }
            std::net::IpAddr::V6(v6) => {
                let first_byte = v6.octets()[0];
                if (first_byte == 0xfc || first_byte == 0xfd) && ula_v6.is_none() {
                    ula_v6 = Some(*candidate);
                } else if global_v6.is_none() && first_byte != 0xfc && first_byte != 0xfd {
                    global_v6 = Some(*candidate);
                }
                if any_addr.is_none() {
                    any_addr = Some(*candidate);
                }
            }
        }
    }

    private_ipv4.or(ula_v6).or(global_v6).or(any_addr)
}

pub fn format_tcp_peer_uri(addr: std::net::IpAddr, port: u16) -> String {
    match addr {
        std::net::IpAddr::V6(v6) => format!("tcp://[{v6}]:{port}"),
        std::net::IpAddr::V4(v4) => format!("tcp://{v4}:{port}"),
    }
}

#[derive(Debug, Clone)]
pub struct YggPeerMetrics {
    pub address: String,
    pub upload_bps: f64,
    pub download_bps: f64,
    pub latency_ms: f64,
    prev_bytes_sent: u64,
    prev_bytes_recvd: u64,
    prev_sample: Instant,
}

#[derive(Debug)]
pub struct YggMetricsStore {
    peers: HashMap<String, YggPeerMetrics>,
}

impl YggMetricsStore {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn update(&mut self, peers: Vec<YggPeer>) {
        let now = Instant::now();

        for peer in peers {
            let latency_ms = peer.latency / 1_000_000.0;

            let entry = self.peers.entry(peer.address.clone());
            match entry {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let m = e.get_mut();
                    let elapsed = now.duration_since(m.prev_sample).as_secs_f64();
                    if elapsed > 0.001 {
                        let sent_delta = peer.bytes_sent.saturating_sub(m.prev_bytes_sent);
                        let recv_delta = peer.bytes_recvd.saturating_sub(m.prev_bytes_recvd);
                        m.upload_bps = sent_delta as f64 / elapsed;
                        m.download_bps = recv_delta as f64 / elapsed;
                    }
                    m.latency_ms = latency_ms;
                    m.prev_bytes_sent = peer.bytes_sent;
                    m.prev_bytes_recvd = peer.bytes_recvd;
                    m.prev_sample = now;
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(YggPeerMetrics {
                        address: peer.address,
                        upload_bps: 0.0,
                        download_bps: 0.0,
                        latency_ms,
                        prev_bytes_sent: peer.bytes_sent,
                        prev_bytes_recvd: peer.bytes_recvd,
                        prev_sample: now,
                    });
                }
            }
        }
    }

    pub fn get(&self, ygg_addr: &str) -> Option<&YggPeerMetrics> {
        self.peers.get(ygg_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(address: &str) -> YggPeer {
        YggPeer {
            address: address.into(),
            remote: String::new(),
            bytes_sent: 0,
            bytes_recvd: 0,
            latency: 0.0,
            key: String::new(),
            port: 1,
            uptime: 0.0,
            up: false,
            inbound: false,
        }
    }

    #[test]
    fn test_is_yggdrasil_ipv6() {
        assert!(is_yggdrasil_ipv6(&"200:abcd::1".parse().unwrap()));
        assert!(!is_yggdrasil_ipv6(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_format_tcp_peer_uri() {
        assert_eq!(
            format_tcp_peer_uri("10.7.1.37".parse().unwrap(), 9443),
            "tcp://10.7.1.37:9443"
        );
        assert_eq!(
            format_tcp_peer_uri("fdaa::1".parse().unwrap(), 9443),
            "tcp://[fdaa::1]:9443"
        );
    }

    #[test]
    fn first_sample_returns_zero_rates() {
        let mut store = YggMetricsStore::new();
        store.update(vec![YggPeer {
            latency: 15_000_000.0,
            bytes_sent: 10_000,
            bytes_recvd: 20_000,
            ..test_peer("200:abcd::1")
        }]);

        let m = store.get("200:abcd::1").unwrap();
        assert_eq!(m.upload_bps, 0.0);
        assert_eq!(m.download_bps, 0.0);
        assert!((m.latency_ms - 15.0).abs() < 0.001);
    }

    #[test]
    fn rate_computation_from_deltas() {
        let mut store = YggMetricsStore::new();
        store.update(vec![YggPeer {
            bytes_sent: 1_000_000,
            bytes_recvd: 2_000_000,
            latency: 10_000_000.0,
            uptime: 100.0,
            ..test_peer("200:abcd::1")
        }]);

        {
            let m = store.peers.get_mut("200:abcd::1").unwrap();
            m.prev_sample = Instant::now() - std::time::Duration::from_secs(1);
        }

        store.update(vec![YggPeer {
            bytes_sent: 1_500_000,
            bytes_recvd: 3_000_000,
            latency: 12_000_000.0,
            uptime: 101.0,
            ..test_peer("200:abcd::1")
        }]);

        let m = store.get("200:abcd::1").unwrap();
        assert!(m.upload_bps > 450_000.0 && m.upload_bps < 550_000.0,
            "upload_bps was {}", m.upload_bps);
        assert!(m.download_bps > 900_000.0 && m.download_bps < 1_100_000.0,
            "download_bps was {}", m.download_bps);
        assert!((m.latency_ms - 12.0).abs() < 0.001);
    }

    #[test]
    fn missing_peer_returns_none() {
        let store = YggMetricsStore::new();
        assert!(store.get("200:nonexistent::1").is_none());
    }

    #[test]
    fn parse_getpeers_response_array() {
        let json = r#"{
            "request": "getpeers",
            "status": "success",
            "response": {
                "peers": [
                    {
                        "address": "200:1234::1",
                        "bytes_sent": 12345,
                        "bytes_recvd": 67890,
                        "latency": 15000000,
                        "key": "abc123",
                        "port": 1,
                        "uptime": 3600.0
                    }
                ]
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "200:1234::1");
        assert_eq!(peers[0].bytes_sent, 12345);
        assert_eq!(peers[0].bytes_recvd, 67890);
        assert!((peers[0].latency - 15_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_getpeers_response_map() {
        let json = r#"{
            "response": {
                "peers": {
                    "200:aaaa::1": {
                        "address": "200:aaaa::1",
                        "bytes_sent": 100,
                        "bytes_recvd": 200,
                        "latency": 5000000,
                        "key": "def456",
                        "port": 2,
                        "uptime": 1800.0
                    }
                }
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "200:aaaa::1");
    }

    #[test]
    fn find_peer_by_remote_ip_tcp_uri() {
        let peers = vec![YggPeer {
            remote: "tcp://195.5.161.109:12345".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(
            result,
            Some("200:fcf:205:9dec:ff7b:e2f:7b00:51ac".parse().unwrap())
        );
    }

    #[test]
    fn find_peer_by_remote_ip_no_match() {
        let peers = vec![YggPeer {
            remote: "tcp://10.0.0.1:12345".into(),
            ..test_peer("200:abcd::1")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        assert!(find_peer_by_remote_ip(&peers, &target).is_none());
    }

    #[test]
    fn find_peer_by_remote_ip_no_scheme() {
        let peers = vec![YggPeer {
            remote: "195.5.161.109:12345".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(
            result,
            Some("200:fcf:205:9dec:ff7b:e2f:7b00:51ac".parse().unwrap())
        );
    }

    #[test]
    fn find_peer_by_remote_ip_bracketed_ipv6() {
        let peers = vec![YggPeer {
            remote: "tcp://[2a09:8280:5d::d2:e42f:0]:9443".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "2a09:8280:5d::d2:e42f:0".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(
            result,
            Some("200:fcf:205:9dec:ff7b:e2f:7b00:51ac".parse().unwrap())
        );
    }

    #[test]
    fn find_peer_by_remote_ip_empty_remote() {
        let peers = vec![test_peer("200:abcd::1")];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        assert!(find_peer_by_remote_ip(&peers, &target).is_none());
    }

    #[test]
    fn key_to_address_produces_200_prefix() {
        let key = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        assert!(octets[0] == 0x02 || octets[0] == 0x03, "got {:02x}", octets[0]);
    }

    #[test]
    fn key_to_address_deterministic() {
        let key = "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011";
        let a = key_to_address(key).unwrap();
        let b = key_to_address(key).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn key_to_address_different_keys_different_addrs() {
        let k1 = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let k2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let a1 = key_to_address(k1).unwrap();
        let a2 = key_to_address(k2).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn key_to_address_invalid_hex() {
        assert!(key_to_address("not_hex").is_none());
    }

    #[test]
    fn key_to_address_wrong_length() {
        assert!(key_to_address("aabbccdd").is_none());
    }

    #[test]
    fn key_to_address_all_zeros() {
        let key = "0000000000000000000000000000000000000000000000000000000000000000";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        assert_eq!(octets[0], 0x02);
        assert_eq!(octets[1], 0x00);
    }

    #[test]
    fn key_to_address_all_ff() {
        let key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        assert_eq!(octets[0], 0x02);
        assert_eq!(octets[1], 0x00);
    }

    #[test]
    fn parse_yggstack_format_peers() {
        let json = r#"{
            "request": "getpeers",
            "status": "success",
            "response": {
                "peers": [
                    {
                        "cost": 65535,
                        "inbound": false,
                        "key": "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011",
                        "last_error": "",
                        "last_error_time": "0001-01-01T00:00:00Z",
                        "port": 1,
                        "priority": 0,
                        "remote": "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443",
                        "up": true
                    }
                ]
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert!(!peers[0].address.is_empty());
        assert!(peers[0].address.starts_with('2'));
        assert_eq!(peers[0].remote, "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443");
        assert!(peers[0].up);
        assert!(!peers[0].inbound);
    }

    #[test]
    fn parse_yggstack_format_with_hostname_remote() {
        let json = r#"{
            "response": {
                "peers": [
                    {
                        "key": "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011",
                        "remote": "tcp://lhr.anycast-mesh.internal:9443",
                        "up": true,
                        "port": 1
                    }
                ]
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert!(!peers[0].address.is_empty());
        assert_eq!(peers[0].key, "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011");
    }

    #[test]
    fn find_peer_by_remote_ip_with_derived_address() {
        let key = "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011";
        let derived_addr = key_to_address(key).unwrap();

        let peers = vec![YggPeer {
            address: derived_addr.to_string(),
            remote: "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443".into(),
            key: key.into(),
            up: true,
            ..test_peer("")
        }];

        let target: std::net::IpAddr = "fdaa:0:bca3:a7b:0:0:eb5a:2".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(result, Some(derived_addr));
    }
}
