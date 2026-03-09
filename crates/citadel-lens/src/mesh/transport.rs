//! Mesh transport resolution.
//!
//! Donor-inspired transport chooser for Citadel mesh. The current policy is
//! intentionally Ygg-first and Ygg-required for outbound dialing.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use citadel_ygg::{find_peer_by_remote_ip, is_yggdrasil_ipv6, query_peers};

use super::peer::MeshPeer;

pub fn extract_host_from_uri(uri: &str) -> String {
    let stripped = uri.strip_prefix("tcp://").unwrap_or(uri);
    if stripped.starts_with('[') {
        if let Some(bracket_end) = stripped.find(']') {
            return stripped[1..bracket_end].to_string();
        }
    }
    if let Some(colon) = stripped.rfind(':') {
        let host = &stripped[..colon];
        if !host.is_empty() {
            return host.to_string();
        }
    }
    stripped.to_string()
}

async fn resolve_remote_ip_via_ygg(
    ygg_admin_socket: Option<&str>,
    remote_ip: IpAddr,
    port: u16,
) -> Option<SocketAddr> {
    let socket_path = ygg_admin_socket?;
    let peers = query_peers(socket_path).await.ok()?;
    let ygg_addr = find_peer_by_remote_ip(&peers, &remote_ip)?;
    Some(SocketAddr::new(IpAddr::V6(ygg_addr), port))
}

pub async fn resolve_socket_hint_target(
    socket_hint: SocketAddr,
    ygg_admin_socket: Option<&str>,
) -> Option<SocketAddr> {
    if let IpAddr::V6(v6) = socket_hint.ip() {
        if is_yggdrasil_ipv6(&v6) {
            return Some(socket_hint);
        }
    }
    resolve_remote_ip_via_ygg(ygg_admin_socket, socket_hint.ip(), socket_hint.port()).await
}

pub async fn resolve_peer_dial_target(
    peer: &MeshPeer,
    ygg_admin_socket: Option<&str>,
) -> Option<SocketAddr> {
    if let Some(ygg_addr) = peer.yggdrasil_addr.as_deref() {
        if let Ok(v6) = ygg_addr.parse::<Ipv6Addr>() {
            return Some(SocketAddr::new(IpAddr::V6(v6), peer.addr.port()));
        }
    }

    for uri in [peer.underlay_uri.as_deref(), peer.ygg_peer_uri.as_deref()] {
        let Some(uri) = uri else { continue; };
        let host = extract_host_from_uri(uri);
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let IpAddr::V6(v6) = ip {
                if is_yggdrasil_ipv6(&v6) {
                    return Some(SocketAddr::new(IpAddr::V6(v6), peer.addr.port()));
                }
            }
            if let Some(addr) = resolve_remote_ip_via_ygg(ygg_admin_socket, ip, peer.addr.port()).await {
                return Some(addr);
            }
        }
    }

    let hint_ip = peer.addr.ip();
    if let IpAddr::V6(v6) = hint_ip {
        if is_yggdrasil_ipv6(&v6) {
            return Some(peer.addr);
        }
    }
    resolve_remote_ip_via_ygg(ygg_admin_socket, hint_ip, peer.addr.port()).await
}

pub async fn resolve_entry_peer_target(
    entry_peer: &str,
    ygg_admin_socket: Option<&str>,
) -> Option<SocketAddr> {
    let resolved_addrs: Vec<SocketAddr> = tokio::net::lookup_host(entry_peer).await.ok()?.collect();
    for resolved_addr in &resolved_addrs {
        if let IpAddr::V6(v6) = resolved_addr.ip() {
            if is_yggdrasil_ipv6(&v6) {
                return Some(*resolved_addr);
            }
        }
        if let Some(addr) = resolve_remote_ip_via_ygg(ygg_admin_socket, resolved_addr.ip(), resolved_addr.port()).await {
            return Some(addr);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_from_uri_ipv4() {
        assert_eq!(extract_host_from_uri("tcp://10.7.1.37:9443"), "10.7.1.37");
    }

    #[test]
    fn test_extract_host_from_uri_ipv6() {
        assert_eq!(extract_host_from_uri("tcp://[fdaa::1]:9443"), "fdaa::1");
    }

    #[tokio::test]
    async fn test_resolve_peer_dial_target_prefers_explicit_ygg() {
        let peer = MeshPeer {
            id: "b3b3/test".into(),
            addr: "10.7.1.37:9000".parse().unwrap(),
            yggdrasil_addr: Some("200:abcd::1".into()),
            underlay_uri: Some("tcp://10.7.1.37:9443".into()),
            ygg_peer_uri: Some("tcp://10.7.1.37:9443".into()),
            public_key: None,
            last_seen: std::time::Instant::now(),
            coordinated: false,
            slot: None,
            is_entry_peer: false,
            content_synced: false,
            their_have: None,
        };

        let addr = resolve_peer_dial_target(&peer, None).await.unwrap();
        assert_eq!(addr, "[200:abcd::1]:9000".parse().unwrap());
    }
}
