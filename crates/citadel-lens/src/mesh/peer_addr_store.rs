//! Peer address store: SPORE-indexed storage for mesh peer address records.
//!
//! This is a donor port from Lagoon. It gives Citadel a stable replicated
//! address plane instead of overloading `MeshPeer.addr` with every dialing fact.

use std::collections::HashMap;

use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};

use super::peer::MeshPeer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddrRecord {
    pub peer_id: String,
    pub server_name: String,
    pub node_name: String,
    pub site_name: String,
    pub public_key_hex: String,
    pub port: u16,
    pub tls: bool,
    pub yggdrasil_addr: Option<String>,
    pub underlay_uri: Option<String>,
    pub ygg_peer_uri: Option<String>,
    pub timestamp_ms: i64,
    pub content_id: [u8; 32],
}

#[derive(Debug)]
pub struct PeerAddrStore {
    records: HashMap<String, PeerAddrRecord>,
    spore: Spore,
    ttl_ms: i64,
}

fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

impl PeerAddrRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: String,
        server_name: String,
        node_name: String,
        site_name: String,
        public_key_hex: String,
        port: u16,
        tls: bool,
        yggdrasil_addr: Option<String>,
        underlay_uri: Option<String>,
        ygg_peer_uri: Option<String>,
        timestamp_ms: i64,
    ) -> Self {
        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            peer_id,
            timestamp_ms,
            underlay_uri.as_deref().unwrap_or(""),
            ygg_peer_uri.as_deref().unwrap_or(""),
            yggdrasil_addr.as_deref().unwrap_or(""),
        );
        let content_id: [u8; 32] = *blake3::hash(hash_input.as_bytes()).as_bytes();
        Self {
            peer_id,
            server_name,
            node_name,
            site_name,
            public_key_hex,
            port,
            tls,
            yggdrasil_addr,
            underlay_uri,
            ygg_peer_uri,
            timestamp_ms,
            content_id,
        }
    }

    pub fn from_mesh_peer(peer: &MeshPeer, timestamp_ms: i64) -> Self {
        Self::new(
            peer.id.clone(),
            String::new(),
            String::new(),
            String::new(),
            peer.public_key
                .as_ref()
                .map(hex::encode)
                .unwrap_or_default(),
            peer.addr.port(),
            false,
            peer.yggdrasil_addr.clone(),
            peer.underlay_uri.clone(),
            peer.ygg_peer_uri.clone(),
            timestamp_ms,
        )
    }

    pub fn from_local(
        peer_id: String,
        public_key_hex: String,
        port: u16,
        yggdrasil_addr: Option<String>,
        underlay_uri: Option<String>,
        ygg_peer_uri: Option<String>,
        timestamp_ms: i64,
    ) -> Self {
        Self::new(
            peer_id,
            String::new(),
            String::new(),
            String::new(),
            public_key_hex,
            port,
            false,
            yggdrasil_addr,
            underlay_uri,
            ygg_peer_uri,
            timestamp_ms,
        )
    }
}

impl PeerAddrStore {
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            records: HashMap::new(),
            spore: Spore::empty(),
            ttl_ms,
        }
    }

    pub fn insert(&mut self, record: PeerAddrRecord) -> bool {
        if !record.peer_id.starts_with("b3b3/") {
            return false;
        }
        if let Some(existing) = self.records.get(&record.peer_id) {
            if record.timestamp_ms <= existing.timestamp_ms {
                return false;
            }
        }

        let content_u256 = U256::from_be_bytes(&record.content_id);
        let point = Spore::from_range(point_range(content_u256));
        self.spore = self.spore.union(&point);
        self.records.insert(record.peer_id.clone(), record);
        true
    }

    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    pub fn diff_for_peer(&self, peer_spore: &Spore) -> Vec<PeerAddrRecord> {
        let missing = self.spore.subtract(peer_spore);
        self.records
            .values()
            .filter(|r| {
                let cid = U256::from_be_bytes(&r.content_id);
                missing.covers(&cid)
            })
            .cloned()
            .collect()
    }

    pub fn merge(&mut self, records: Vec<PeerAddrRecord>, now_ms: i64) -> Vec<PeerAddrRecord> {
        let mut accepted = Vec::new();
        for rec in records {
            if now_ms - rec.timestamp_ms > self.ttl_ms {
                continue;
            }
            if self.insert(rec.clone()) {
                accepted.push(rec);
            }
        }
        accepted
    }

    pub fn prune_stale(&mut self, now_ms: i64) {
        self.records
            .retain(|_, r| now_ms - r.timestamp_ms <= self.ttl_ms);
    }

    pub fn get(&self, peer_id: &str) -> Option<&PeerAddrRecord> {
        self.records.get(peer_id)
    }

    pub fn record_data_for_gossip(&self) -> Vec<(Vec<u8>, [u8; 32])> {
        self.records
            .values()
            .map(|r| {
                let serialized = bincode::serialize(r).unwrap_or_default();
                (serialized, r.content_id)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(peer_id: &str, ts: i64) -> PeerAddrRecord {
        PeerAddrRecord::new(
            peer_id.to_owned(),
            format!("{peer_id}.lagun.co"),
            peer_id.to_owned(),
            "lagun.co".to_owned(),
            "aabbccdd".to_owned(),
            9443,
            false,
            None,
            None,
            None,
            ts,
        )
    }

    fn make_record_with_addr(peer_id: &str, ts: i64, underlay: &str) -> PeerAddrRecord {
        PeerAddrRecord::new(
            peer_id.to_owned(),
            format!("{peer_id}.lagun.co"),
            peer_id.to_owned(),
            "lagun.co".to_owned(),
            "aabbccdd".to_owned(),
            9443,
            false,
            None,
            Some(underlay.to_owned()),
            None,
            ts,
        )
    }

    #[test]
    fn test_insert_new() {
        let mut store = PeerAddrStore::new(120_000);
        assert!(store.insert(make_record("node-a", 1000)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_older_rejected() {
        let mut store = PeerAddrStore::new(120_000);
        assert!(store.insert(make_record("node-a", 2000)));
        assert!(!store.insert(make_record("node-a", 1000)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_merge_accepts_fresh() {
        let mut store = PeerAddrStore::new(120_000);
        let records = vec![make_record("node-a", 5000), make_record("node-b", 5000)];
        let accepted = store.merge(records, 10_000);
        assert_eq!(accepted.len(), 2);
    }

    #[test]
    fn test_diff_synced_peer() {
        let mut store = PeerAddrStore::new(120_000);
        store.insert(make_record("node-a", 5000));
        let diff = store.diff_for_peer(store.spore());
        assert!(diff.is_empty());
    }

    #[test]
    fn test_record_roundtrip_bincode() {
        let record = make_record_with_addr("node-a", 5000, "tcp://[200:1234::1]:9443");
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: PeerAddrRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.peer_id, record.peer_id);
        assert_eq!(decoded.underlay_uri, record.underlay_uri);
    }
}
