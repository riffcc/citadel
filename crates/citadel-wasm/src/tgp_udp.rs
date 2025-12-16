//! TGP (Two Generals Protocol) packet format for Citadel
//!
//! Provides packet headers and types for P2P communication.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// TGP packet header
#[derive(Debug, Clone)]
pub struct TgpPacketHeader {
    pub version: u8,
    pub packet_type: u8,
    pub source_hex: u64,
    pub dest_hex: u64,
    pub ttl: u8,
    pub payload_length: u16,
}

impl TgpPacketHeader {
    pub const SIZE: usize = 21; // version(1) + type(1) + source(8) + dest(8) + ttl(1) + length(2)

    pub fn new(packet_type: u8, source_hex: u64, dest_hex: u64, payload_length: u16) -> Self {
        Self {
            version: 1,
            packet_type,
            source_hex,
            dest_hex,
            ttl: 64,
            payload_length,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.push(self.version);
        bytes.push(self.packet_type);
        bytes.extend_from_slice(&self.source_hex.to_be_bytes());
        bytes.extend_from_slice(&self.dest_hex.to_be_bytes());
        bytes.push(self.ttl);
        bytes.extend_from_slice(&self.payload_length.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        let version = bytes[0];
        let packet_type = bytes[1];
        let source_hex = u64::from_be_bytes(bytes[2..10].try_into().ok()?);
        let dest_hex = u64::from_be_bytes(bytes[10..18].try_into().ok()?);
        let ttl = bytes[18];
        let payload_length = u16::from_be_bytes(bytes[19..21].try_into().ok()?);

        Some(Self {
            version,
            packet_type,
            source_hex,
            dest_hex,
            ttl,
            payload_length,
        })
    }
}

/// TGP packet types
#[allow(dead_code)]
pub mod packet_types {
    // UBTS/Blockchain packets
    pub const UBTS_BLOCK: u8 = 0x01;
    pub const WANTLIST: u8 = 0x02;
    pub const DELETE_WANTLIST: u8 = 0x03;

    // Peer discovery packets
    pub const PEER_ANNOUNCE: u8 = 0x04;
    pub const PEER_REQUEST: u8 = 0x05;

    // DHT packets (Citadel DHT integration)
    pub const DHT_GET: u8 = 0x06;
    pub const DHT_PUT: u8 = 0x07;
    pub const DHT_RESPONSE: u8 = 0x08;
}

/// Calculate hex coordinate for a peer ID (consistent hashing)
pub fn peer_id_to_hex(peer_id: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    peer_id.hash(&mut hasher);
    hasher.finish()
}

/// Create a TGP packet with header + payload
pub fn create_tgp_packet(
    packet_type: u8,
    source_hex: u64,
    dest_hex: u64,
    payload: &[u8],
) -> Vec<u8> {
    let header = TgpPacketHeader::new(packet_type, source_hex, dest_hex, payload.len() as u16);
    let mut packet = header.to_bytes();
    packet.extend_from_slice(payload);
    packet
}

/// Parse a TGP packet and return header + payload
pub fn parse_tgp_packet(packet: &[u8]) -> Option<(TgpPacketHeader, &[u8])> {
    let header = TgpPacketHeader::from_bytes(packet)?;
    if packet.len() < TgpPacketHeader::SIZE + header.payload_length as usize {
        return None;
    }
    let payload = &packet[TgpPacketHeader::SIZE..];
    Some((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = TgpPacketHeader::new(packet_types::UBTS_BLOCK, 0x1234567890abcdef, 0xfedcba0987654321, 256);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), TgpPacketHeader::SIZE);

        let parsed = TgpPacketHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.packet_type, packet_types::UBTS_BLOCK);
        assert_eq!(parsed.source_hex, 0x1234567890abcdef);
        assert_eq!(parsed.dest_hex, 0xfedcba0987654321);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.payload_length, 256);
    }

    #[test]
    fn test_header_too_short() {
        let bytes = vec![0u8; 10]; // Too short
        assert!(TgpPacketHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_create_and_parse_packet() {
        let payload = b"Hello, Citadel!";
        let packet = create_tgp_packet(
            packet_types::DHT_PUT,
            0xAAAAAAAAAAAAAAAA,
            0xBBBBBBBBBBBBBBBB,
            payload,
        );

        let (header, parsed_payload) = parse_tgp_packet(&packet).unwrap();

        assert_eq!(header.packet_type, packet_types::DHT_PUT);
        assert_eq!(header.source_hex, 0xAAAAAAAAAAAAAAAA);
        assert_eq!(header.dest_hex, 0xBBBBBBBBBBBBBBBB);
        assert_eq!(header.payload_length, payload.len() as u16);
        assert_eq!(&parsed_payload[..payload.len()], payload);
    }

    #[test]
    fn test_peer_id_to_hex_deterministic() {
        let peer_id = "browser-0.12345";
        let hex1 = peer_id_to_hex(peer_id);
        let hex2 = peer_id_to_hex(peer_id);
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_peer_id_to_hex_different_ids() {
        let hex1 = peer_id_to_hex("peer-1");
        let hex2 = peer_id_to_hex("peer-2");
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn test_packet_types() {
        assert_eq!(packet_types::UBTS_BLOCK, 0x01);
        assert_eq!(packet_types::WANTLIST, 0x02);
        assert_eq!(packet_types::DHT_GET, 0x06);
        assert_eq!(packet_types::DHT_PUT, 0x07);
        assert_eq!(packet_types::DHT_RESPONSE, 0x08);
    }
}
