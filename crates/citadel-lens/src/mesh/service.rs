//! MeshService implementation.
//!
//! This module contains the core MeshService that manages:
//! - Peer connections (TCP)
//! - Live slot claiming
//! - VDF/CVDF consensus
//! - SPORE sync

use crate::accountability::{AccountabilityTracker, FailureType};
use crate::cvdf::{CvdfCoordinator, CvdfRound, RoundAttestation};
use crate::error::Result;
use crate::liveness::{LivenessManager, MeshVouch, PropagationDecision};
use crate::models::FeaturedRelease;
use crate::storage::Storage;
use crate::vdf_race::{claim_has_priority, AnchoredSlotClaim, VdfLink, VdfRace};
use citadel_docs::DocumentStore;
use citadel_protocols::{
    CoordinatorConfig, FloodRateConfig, KeyPair, Message as TgpMessage, MessagePayload,
    PeerCoordinator, PublicKey, QuadProof, SporeSyncManager,
};
use citadel_spore::{Spore, U256};
use citadel_topology::{spiral3d_to_coord, Direction, HexCoord, Neighbors, Spiral3DIndex};
use citadel_ygg::{query_self_sync, YggMetricsStore};
use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, Notify, RwLock};
use tracing::{debug, error, info, warn};

// Import types from sibling modules
use super::flood::FloodMessage;
use super::peer::{compute_peer_id, compute_peer_id_from_bytes, double_hash_id, AuthorizedPeer, MeshPeer};
use super::peer_addr_store::PeerAddrRecord;
use super::slot::{consensus_threshold, SlotClaim};
use super::spore::{build_spore_havelist, release_id_to_u256};
use super::state::MeshState;
use super::tgp::TgpSession;

/// Citadel Mesh Service
pub struct MeshService {
    /// P2P listen address (TCP and UDP share this port)
    listen_addr: SocketAddr,
    /// P2P announce address (public IP for other peers to connect to)
    /// If None, uses listen_addr (which may be 0.0.0.0 - won't work!)
    announce_addr: Option<SocketAddr>,
    /// Bootstrap peers to connect to
    entry_peers: Vec<String>,
    /// Optional Yggdrasil admin socket for overlay-aware entry-peer routing.
    ygg_admin_socket: Option<String>,
    /// Cached local Yggdrasil overlay address.
    local_yggdrasil_addr: Option<String>,
    /// Cached local underlay URI used for Ygg peering.
    local_underlay_uri: Option<String>,
    /// Shared storage for replication
    storage: Arc<Storage>,
    /// Document store for CRDT documents with SPORE sync (featured releases, etc.)
    /// Uses rich semantic merges (NOT LWW) - proven convergent in Lean.
    doc_store: Arc<tokio::sync::RwLock<DocumentStore>>,
    /// Mesh state (peers, slots, etc.)
    state: Arc<RwLock<MeshState>>,
    /// Cached TGP keypair for legacy helper paths.
    tgp_keypair: Arc<KeyPair>,
    /// TGP sessions - SEPARATE lock for contention-free TGP operations
    /// This allows send_tgp_messages to run without blocking on mesh state
    tgp_sessions: Arc<RwLock<HashMap<String, TgpSession>>>,
    /// Legacy TGP UDP socket, intentionally unused by the live mesh runtime.
    tgp_udp_socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
    /// Legacy bilateral authorization records retained for helper paths and tests.
    authorized_peers: Arc<RwLock<HashMap<String, AuthorizedPeer>>>,
    /// Canonical/provisional peer IDs with active TCP connection counts.
    /// Multiple simultaneous sockets to the same peer can exist briefly during
    /// mutual dial races, so a set is not structurally sufficient here.
    active_tcp_peers: Arc<RwLock<HashMap<String, usize>>>,
    /// Broadcast channel for continuous flooding
    flood_tx: broadcast::Sender<FloodMessage>,
    /// Notification for when CVDF is initialized (genesis or join)
    cvdf_init_notify: Arc<Notify>,
    /// Channel for pending connections to spawn from listener
    pending_connect_tx: mpsc::Sender<(String, SocketAddr)>,
    pending_connect_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(String, SocketAddr)>>>,
    /// Atomic flag to prevent concurrent slot claiming attempts
    claiming_in_progress: std::sync::atomic::AtomicBool,
    /// Traffic statistics for aggregate logging
    traffic_stats: Arc<super::state::TrafficStats>,
    /// Cached Yggdrasil link metrics from admin socket queries.
    ygg_metrics: Arc<RwLock<YggMetricsStore>>,
}

impl MeshService {
    const STALE_PEER_SECS: u64 = 120;

    fn active_peer_count(state: &MeshState, active_peer_ids: &HashSet<String>) -> usize {
        state
            .peers
            .keys()
            .filter(|peer_id| active_peer_ids.contains(*peer_id))
            .count()
    }

    fn inactive_peer_ids(state: &MeshState, active_peer_ids: &HashSet<String>) -> HashSet<String> {
        state
            .peers
            .keys()
            .filter(|peer_id| !active_peer_ids.contains(*peer_id))
            .cloned()
            .collect()
    }

    async fn active_peer_ids_snapshot(&self) -> HashSet<String> {
        self.active_tcp_peers
            .read()
            .await
            .iter()
            .filter_map(|(peer_id, count)| (*count > 0).then_some(peer_id.clone()))
            .collect()
    }

    fn active_tgp_candidates(
        state: &MeshState,
        active_peer_ids: &HashSet<String>,
    ) -> Vec<(String, SocketAddr, [u8; 32])> {
        state
            .peers
            .values()
            .filter(|peer| active_peer_ids.contains(&peer.id))
            .filter_map(|p| {
                p.public_key.as_ref().and_then(|pk| {
                    if pk.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(pk);
                        Some((p.id.clone(), p.addr, arr))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    fn occupied_theoretical_neighbor_validators(
        state: &MeshState,
        active_peer_ids: &HashSet<String>,
        target_slot: u64,
    ) -> Vec<(String, SocketAddr, [u8; 32])> {
        let target_coord = spiral3d_to_coord(Spiral3DIndex::new(target_slot));
        let mut validators = Vec::new();
        let mut seen = HashSet::new();

        for neighbor_coord in Neighbors::of(target_coord) {
            let Some(slot_claim) = state
                .claimed_slots
                .values()
                .find(|claim| claim.coord == neighbor_coord)
            else {
                continue;
            };

            if !active_peer_ids.contains(&slot_claim.peer_id) || !seen.insert(slot_claim.peer_id.clone()) {
                continue;
            }

            let Some(peer) = state.peers.get(&slot_claim.peer_id) else {
                continue;
            };

            let Some(public_key) = peer.public_key.as_ref() else {
                continue;
            };

            if public_key.len() != 32 {
                continue;
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(public_key);
            validators.push((peer.id.clone(), peer.addr, arr));
        }

        validators
    }

    fn occupied_theoretical_neighbor_validator_ids(
        state: &MeshState,
        active_peer_ids: &HashSet<String>,
        target_slot: u64,
    ) -> HashSet<String> {
        Self::occupied_theoretical_neighbor_validators(state, active_peer_ids, target_slot)
            .into_iter()
            .map(|(peer_id, _, _)| peer_id)
            .collect()
    }

    async fn rekey_tgp_session(&self, old_peer_id: &str, new_peer_id: &str) {
        if old_peer_id == new_peer_id {
            return;
        }

        let mut sessions = self.tgp_sessions.write().await;
        if let Some(session) = sessions.remove(old_peer_id) {
            if sessions.contains_key(new_peer_id) {
                debug!(
                    "Dropping provisional TGP session {} after peer re-key to {} (canonical session already exists)",
                    old_peer_id, new_peer_id
                );
            } else {
                info!(
                    "Re-keying TGP session {} -> {} after peer identification",
                    old_peer_id, new_peer_id
                );
                sessions.insert(new_peer_id.to_string(), session);
            }
        }
    }

    async fn rekey_active_peer(&self, old_peer_id: &str, new_peer_id: &str) {
        if old_peer_id == new_peer_id {
            return;
        }

        let mut active_peers = self.active_tcp_peers.write().await;
        let old_count = active_peers.remove(old_peer_id).unwrap_or(0);
        if old_count > 0 {
            *active_peers.entry(new_peer_id.to_string()).or_insert(0) += old_count;
        }
    }

    fn is_usable_peer_addr(addr: SocketAddr) -> bool {
        !(addr.ip().is_unspecified() || addr.ip().is_loopback())
    }

    async fn prune_stale_mesh_state(&self) {
        let now_ms = Self::now_ms();
        let active_peer_ids = self.active_peer_ids_snapshot().await;
        let mut state = self.state.write().await;
        state.peer_addr_store.prune_stale(now_ms);
        let self_id = state.self_id.clone();
        let inactive_peer_ids = Self::inactive_peer_ids(&state, &active_peer_ids);

        state.peers.retain(|peer_id, _peer| {
            if active_peer_ids.contains(peer_id) {
                return true;
            }
            debug!("Pruning inactive peer {} from live mesh state", peer_id);
            false
        });
        state.claimed_slots.retain(|_, claim| {
            claim.peer_id == self_id || !inactive_peer_ids.contains(&claim.peer_id)
        });
        state.slot_coords = state.claimed_slots.values().map(|claim| claim.coord).collect();
        state.vdf_claims.retain(|_, claim| {
            let claim_peer_id = compute_peer_id_from_bytes(&claim.claimer);
            claim_peer_id == self_id || !inactive_peer_ids.contains(&claim_peer_id)
        });
        let should_retry_claim = state.self_slot.is_none() && !active_peer_ids.is_empty();
        drop(state);

        if should_retry_claim {
            debug!("Live mesh changed after stale-peer prune; re-entering slot claim path");
            self.try_claim_slot_from_live_state().await;
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn should_refresh_peer_hint(current: SocketAddr, candidate: SocketAddr) -> bool {
        if current == candidate {
            return false;
        }

        if current.ip() == candidate.ip() && current.port() != candidate.port() {
            return true;
        }

        if candidate.ip().is_ipv6() && !current.ip().is_ipv6() {
            return true;
        }

        if (current.ip().is_loopback() || current.ip().is_unspecified())
            && !(candidate.ip().is_loopback() || candidate.ip().is_unspecified())
        {
            return true;
        }

        false
    }

    fn socket_hint_from_peer_addr_record(record: &PeerAddrRecord) -> Option<SocketAddr> {
        if let Some(yggdrasil_addr) = record.yggdrasil_addr.as_deref() {
            if let Ok(ipv6) = yggdrasil_addr.parse::<std::net::Ipv6Addr>() {
                return Some(SocketAddr::new(std::net::IpAddr::V6(ipv6), record.port));
            }
        }

        for uri in [
            record.ygg_peer_uri.as_deref(),
            record.underlay_uri.as_deref(),
        ] {
            let Some(uri) = uri else {
                continue;
            };
            let host = super::transport::extract_host_from_uri(uri);
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return Some(SocketAddr::new(ip, record.port));
            }
        }

        None
    }

    fn evict_stale_slots_from_state(state: &mut MeshState, stale_slots: &[u64]) -> Vec<(u64, String)> {
        let mut evicted = Vec::new();

        for slot_idx in stale_slots {
            let removed_claim = state.claimed_slots.remove(slot_idx);
            state.vdf_claims.remove(slot_idx);

            let Some(claim) = removed_claim else {
                continue;
            };

            state.slot_coords.remove(&claim.coord);
            if let Some(peer) = state.peers.get_mut(&claim.peer_id) {
                peer.slot = None;
            }
            if state.self_slot.as_ref().map(|slot| slot.index) == Some(*slot_idx) {
                state.self_slot = None;
            }
            evicted.push((*slot_idx, claim.peer_id));
        }

        evicted
    }

    async fn merge_peer_addr_records(
        &self,
        records: Vec<PeerAddrRecord>,
    ) -> Vec<(String, SocketAddr)> {
        let now_ms = Self::now_ms();
        let mut peers_to_connect = Vec::new();
        let mut state = self.state.write().await;
        let self_id = state.self_id.clone();
        let accepted = state.peer_addr_store.merge(records, now_ms);

        for record in accepted {
            if record.peer_id == self_id {
                continue;
            }

            let public_key = hex::decode(&record.public_key_hex)
                .ok()
                .filter(|bytes| !bytes.is_empty());
            let addr_hint = Self::socket_hint_from_peer_addr_record(&record);

            if let Some(existing_peer) = state.peers.get_mut(&record.peer_id) {
                if let Some(addr_hint) = addr_hint {
                    if Self::should_refresh_peer_hint(existing_peer.addr, addr_hint) {
                        debug!(
                            "Refreshing peer {} hint via peer-addr sync: {} -> {}",
                            record.peer_id, existing_peer.addr, addr_hint
                        );
                        existing_peer.addr = addr_hint;
                    }
                }
                if existing_peer.yggdrasil_addr.is_none() && record.yggdrasil_addr.is_some() {
                    existing_peer.yggdrasil_addr = record.yggdrasil_addr.clone();
                }
                if existing_peer.underlay_uri.is_none() && record.underlay_uri.is_some() {
                    existing_peer.underlay_uri = record.underlay_uri.clone();
                }
                if existing_peer.ygg_peer_uri.is_none() && record.ygg_peer_uri.is_some() {
                    existing_peer.ygg_peer_uri = record.ygg_peer_uri.clone();
                }
                if existing_peer.public_key.is_none() && public_key.is_some() {
                    existing_peer.public_key = public_key.clone();
                }
                continue;
            }

            let Some(addr_hint) = addr_hint else {
                debug!(
                    "Accepted peer-addr record for {} but it has no dialable hint yet",
                    record.peer_id
                );
                continue;
            };

            state.peers.insert(
                record.peer_id.clone(),
                MeshPeer {
                    id: record.peer_id.clone(),
                    addr: addr_hint,
                    yggdrasil_addr: record.yggdrasil_addr.clone(),
                    underlay_uri: record.underlay_uri.clone(),
                    ygg_peer_uri: record.ygg_peer_uri.clone(),
                    public_key,
                    last_seen: std::time::Instant::now(),
                    coordinated: false,
                    slot: None,
                    is_entry_peer: false,
                    content_synced: false,
                    their_have: None,
                    their_peer_addr_have: None,
                },
            );
            peers_to_connect.push((record.peer_id.clone(), addr_hint));
        }

        peers_to_connect
    }

    fn scaled_slot_claim_threshold(mesh_size: usize, validator_count: usize) -> usize {
        if validator_count == 0 {
            return 0;
        }
        let threshold = consensus_threshold(mesh_size);
        if validator_count >= 20 {
            threshold
        } else {
            (validator_count * threshold + 19) / 20
        }
    }

    fn cvdf_attestation_json(att: &RoundAttestation, vouch: Option<&MeshVouch>) -> serde_json::Value {
        let mut flood_msg = serde_json::json!({
            "type": "cvdf_attestation",
            "round": att.round,
            "slot": att.slot,
            "prev_output": hex::encode(att.prev_output),
            "attester": hex::encode(att.attester),
            "signature": hex::encode(att.signature),
        });

        if let Some(v) = vouch {
            flood_msg["vouch"] = serde_json::json!({
                "voucher": hex::encode(v.voucher),
                "voucher_slot": v.voucher_slot,
                "alive_neighbors": v.alive_neighbors.iter().map(hex::encode).collect::<Vec<_>>(),
                "vdf_height": v.vdf_height,
                "latencies": v.latencies.iter().map(|(n, l)| serde_json::json!({
                    "node": hex::encode(n),
                    "latency_ms": l,
                })).collect::<Vec<_>>(),
                "signature": hex::encode(v.signature),
            });
        }

        flood_msg
    }

    fn cvdf_round_json(round: &CvdfRound, spore_ranges: Option<usize>) -> serde_json::Value {
        let mut round_json = serde_json::json!({
            "type": "cvdf_new_round",
            "round": round.round,
            "prev_output": hex::encode(round.prev_output),
            "washed_input": hex::encode(round.washed_input),
            "output": hex::encode(round.output),
            "producer": hex::encode(round.producer),
            "producer_signature": hex::encode(round.producer_signature),
            "timestamp_ms": round.timestamp_ms,
            "iterations": round.iterations,
            "weight": round.weight(),
            "attestation_count": round.attestations.len(),
            "attestations": round.attestations.iter().map(|a| serde_json::json!({
                "round": a.round,
                "prev_output": hex::encode(a.prev_output),
                "attester": hex::encode(a.attester),
                "slot": a.slot,
                "signature": hex::encode(a.signature),
            })).collect::<Vec<_>>(),
        });

        if let Some(spore_ranges) = spore_ranges {
            round_json["spore_ranges"] = serde_json::json!(spore_ranges);
        }

        round_json
    }

    fn parse_cvdf_attestation_json(msg: &serde_json::Value) -> Option<RoundAttestation> {
        let round = msg.get("round")?.as_u64()?;
        let prev_output = hex::decode(msg.get("prev_output")?.as_str()?).ok()?;
        let attester = hex::decode(msg.get("attester")?.as_str()?).ok()?;
        let signature = hex::decode(msg.get("signature")?.as_str()?).ok()?;

        if prev_output.len() != 32 || attester.len() != 32 || signature.len() != 64 {
            return None;
        }

        Some(RoundAttestation {
            round,
            prev_output: prev_output.try_into().ok()?,
            attester: attester.try_into().ok()?,
            slot: msg.get("slot").and_then(|s| s.as_u64()),
            signature: signature.try_into().ok()?,
        })
    }

    fn parse_cvdf_round_json(round_json: &serde_json::Value) -> Option<CvdfRound> {
        let round = round_json.get("round")?.as_u64()?;
        let prev_output = hex::decode(round_json.get("prev_output")?.as_str()?).ok()?;
        let washed_input = hex::decode(round_json.get("washed_input")?.as_str()?).ok()?;
        let output = hex::decode(round_json.get("output")?.as_str()?).ok()?;
        let producer = hex::decode(round_json.get("producer")?.as_str()?).ok()?;
        let producer_signature =
            hex::decode(round_json.get("producer_signature")?.as_str()?).ok()?;
        let timestamp_ms = round_json.get("timestamp_ms")?.as_u64()?;

        if prev_output.len() != 32
            || washed_input.len() != 32
            || output.len() != 32
            || producer.len() != 32
            || producer_signature.len() != 64
        {
            return None;
        }

        let attestations = round_json
            .get("attestations")?
            .as_array()?
            .iter()
            .map(Self::parse_cvdf_attestation_json)
            .collect::<Option<Vec<_>>>()?;

        let iterations = round_json
            .get("iterations")
            .and_then(|i| i.as_u64())
            .map(|i| i as u32)
            .unwrap_or(crate::cvdf::CVDF_ITERATIONS_BASE);

        Some(CvdfRound {
            round,
            prev_output: prev_output.try_into().ok()?,
            washed_input: washed_input.try_into().ok()?,
            output: output.try_into().ok()?,
            producer: producer.try_into().ok()?,
            producer_signature: producer_signature.try_into().ok()?,
            timestamp_ms,
            attestations,
            iterations,
        })
    }

    async fn prime_ygg_public_addr(&self) {
        if self.announce_addr.is_some() {
            return;
        }

        let Some(socket_path) = self.ygg_admin_socket.clone() else {
            return;
        };

        let listen_port = self.listen_addr.port();
        let ygg_addr =
            match tokio::task::spawn_blocking(move || query_self_sync(&socket_path)).await {
                Ok(Ok(Some(addr))) => addr,
                Ok(Ok(None)) => return,
                Ok(Err(err)) => {
                    debug!("ygg self query failed: {}", err);
                    return;
                }
                Err(err) => {
                    debug!("ygg self query join failure: {}", err);
                    return;
                }
            };

        let public_addr = SocketAddr::new(std::net::IpAddr::V6(ygg_addr), listen_port);
        let mut state = self.state.write().await;
        if state.observed_public_addr.is_none() {
            state.observed_public_addr = Some(public_addr);
            info!("Advertising Ygg public address {}", public_addr);
        }
    }

    /// Create a new mesh service
    pub fn new(
        listen_addr: SocketAddr,
        announce_addr: Option<SocketAddr>,
        entry_peers: Vec<String>,
        ygg_admin_socket: Option<String>,
        local_yggdrasil_addr: Option<String>,
        local_underlay_uri: Option<String>,
        storage: Arc<Storage>,
        doc_store: Arc<tokio::sync::RwLock<DocumentStore>>,
    ) -> Self {
        // Generate or load node keypair for peer identity
        let signing_key = storage.get_or_create_node_key().unwrap_or_else(|_| {
            // Fallback: generate ephemeral key
            let mut rng = rand::thread_rng();
            SigningKey::generate(&mut rng)
        });

        // PeerID is double-BLAKE3 hash of ed25519 public key (Archivist/IPFS style)
        let verifying_key = signing_key.verifying_key();
        let self_id = compute_peer_id(&verifying_key);

        info!("Node PeerID: {}", self_id);

        // Create broadcast channel for continuous flooding (capacity for burst)
        let (flood_tx, _) = broadcast::channel(1024);

        // Initialize SPORE sync manager with peer ID derived from public key hash
        let peer_id_u256 = {
            let hash = blake3::hash(verifying_key.as_bytes());
            U256::from_be_bytes(hash.as_bytes())
        };
        let spore_sync = SporeSyncManager::new(peer_id_u256);

        // Pre-compute TGP keypair once for zerocopy/CoW responder sessions
        // This is derived from signing_key and shared via Arc across all sessions
        let tgp_keypair = Arc::new(
            KeyPair::from_seed(&signing_key.to_bytes())
                .expect("Failed to create TGP keypair from signing key"),
        );

        // Channel for pending connections to spawn from listener
        let (pending_connect_tx, pending_connect_rx) = mpsc::channel(256);

        Self {
            listen_addr,
            announce_addr,
            entry_peers,
            ygg_admin_socket,
            local_yggdrasil_addr,
            local_underlay_uri,
            storage,
            doc_store,
            state: Arc::new(RwLock::new(MeshState {
                self_id,
                signing_key: signing_key.clone(),
                self_slot: None,
                peers: HashMap::new(),
                peer_addr_store: super::peer_addr_store::PeerAddrStore::new(120_000),
                claimed_slots: HashMap::new(),
                slot_coords: HashSet::new(),
                spore_sync: Some(spore_sync),
                vdf_race: None, // Initialized when joining mesh or as genesis
                vdf_claims: HashMap::new(),
                pol_manager: None, // Initialized after claiming a slot
                pol_pending_pings: HashMap::new(),
                cvdf: None, // Initialized as genesis or when joining mesh
                latency_history: HashMap::new(),
                observed_public_addr: None, // Learned from peers via hello
                // SPORE⁻¹: Deletion sync (inverse of SPORE) - GDPR Art. 17 compliant
                do_not_want: Spore::empty(), // Deletions as ranges in 256-bit space
                erasure_confirmed: Spore::empty(), // Ranges peers confirmed they deleted
                erasure_synced: HashMap::new(), // Peer sync status for GC/audit
                // BadBits: Permanent blocklist (NOT for normal deletes)
                bad_bits: HashSet::new(), // DMCA, abuse - never GC, blocks re-upload
                accountability: Some(AccountabilityTracker::new(signing_key.clone())), // Misbehaviour tracking
                liveness: Some(LivenessManager::new(signing_key)), // Structure-aware liveness (2-hop vouches)
            })),
            tgp_keypair,
            // Separate lock for TGP sessions - contention-free TGP operations
            tgp_sessions: Arc::new(RwLock::new(HashMap::new())),
            tgp_udp_socket: Arc::new(RwLock::new(None)),
            authorized_peers: Arc::new(RwLock::new(HashMap::new())),
            active_tcp_peers: Arc::new(RwLock::new(HashMap::new())),
            flood_tx,
            // Notification for CVDF initialization
            cvdf_init_notify: Arc::new(Notify::new()),
            // Channel for pending peer connections
            pending_connect_tx,
            pending_connect_rx: Arc::new(tokio::sync::Mutex::new(pending_connect_rx)),
            // Atomic flag for slot claiming (prevents concurrent claims)
            claiming_in_progress: std::sync::atomic::AtomicBool::new(false),
            // Traffic statistics for aggregate logging (instead of per-packet spam)
            traffic_stats: Arc::new(super::state::TrafficStats::new()),
            ygg_metrics: Arc::new(RwLock::new(YggMetricsStore::new())),
        }
    }

    /// Attempt to occupy a SPIRAL slot.
    ///
    /// # CURRENT LIMITATION
    ///
    /// This function currently "claims" a slot by flooding an announcement.
    /// This is WRONG. The correct protocol is:
    ///
    /// ```text
    /// WRONG (current):
    /// 1. Pick slot N
    /// 2. Flood "I am slot N"
    /// 3. Hope for the best, use tiebreaker if contested
    ///
    /// RIGHT (should be):
    /// 1. Pick slot N
    /// 2. Calculate N's 20 theoretical neighbors
    /// 3. Attempt TGP bilateral connection with each existing neighbor
    /// 4. Count successful TGP agreements (bilateral triples)
    /// 5. If count >= consensus_threshold(mesh_size):
    ///    → You ARE slot N (connections prove it)
    /// 6. If count < threshold:
    ///    → Try slot N+1
    /// ```
    ///
    /// The slot doesn't exist because you claim it.
    /// The slot exists because you have the connections.
    /// THE MESH IS THE SOURCE OF TRUTH.
    ///
    /// # TODO
    ///
    /// Claim a slot (delegates to VDF-anchored claiming)
    /// All slot claims MUST be VDF-signed to prevent forgery and oscillation.
    pub async fn claim_slot(&self, index: u64) -> bool {
        self.claim_slot_with_vdf(index).await.is_some()
    }

    /// EVENT-DRIVEN slot claiming trigger for the live validator/VDF path.
    pub fn trigger_slot_claim_if_ready(self: &Arc<Self>) {
        let mesh = Arc::clone(self);
        tokio::spawn(async move {
            mesh.try_claim_slot_from_live_state().await;
        });
    }

    async fn try_claim_slot_from_live_state(&self) {
        if self
            .claiming_in_progress
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        let active_peer_ids = self.active_peer_ids_snapshot().await;
        let claim_inputs = {
            let state = self.state.read().await;

            if state.self_slot.is_some() {
                None
            } else {
                let live_peer_count = Self::active_peer_count(&state, &active_peer_ids);
                if live_peer_count == 0 {
                    None
                } else {
                    let target_slot = state.next_available_slot();
                    if state.claimed_slots.contains_key(&target_slot) {
                        info!("Slot {} already claimed, waiting for next live mesh event", target_slot);
                        None
                    } else {
                        let validator_count =
                            Self::occupied_theoretical_neighbor_validators(&state, &active_peer_ids, target_slot)
                                .len();
                        let mesh_size = state.claimed_slots.len();
                        let scaled_threshold =
                            Self::scaled_slot_claim_threshold(mesh_size, validator_count);
                        Some((target_slot, live_peer_count, validator_count, scaled_threshold, mesh_size))
                    }
                }
            }
        };

        if let Some((target_slot, live_peer_count, validator_count, scaled_threshold, mesh_size)) =
            claim_inputs
        {
            if scaled_threshold == 0 {
                info!(
                    "Claiming genesis/frontier slot {} directly (live peers {}, mesh size {})",
                    target_slot, live_peer_count, mesh_size
                );
                let _ = self.claim_slot_with_vdf(target_slot).await;
            } else if validator_count == 0 {
                debug!(
                    "Slot {} has no active occupied theoretical neighbors yet; deferring claim",
                    target_slot
                );
            } else if validator_count >= scaled_threshold {
                info!(
                    "Claiming live slot {} with {} active validator peer(s) over threshold {} (live peers {}, mesh size {})",
                    target_slot, validator_count, scaled_threshold, live_peer_count, mesh_size
                );
                if self.claim_slot_with_vdf(target_slot).await.is_none() {
                    warn!(
                        "Failed to create live VDF claim for slot {} despite validator threshold",
                        target_slot
                    );
                }
            }
        }

        self.claiming_in_progress
            .store(false, std::sync::atomic::Ordering::Release);
    }

    // ==================== VDF RACE METHODS ====================
    //
    // VDF Race provides deterministic bootstrap coordination and split-brain merge.
    // Longest chain = largest swarm. Priority ordering resolves conflicts.

    /// Genesis seed for VDF chain (shared across all nodes in the mesh)
    /// In production, this would be derived from network genesis block or similar
    const VDF_GENESIS_SEED: [u8; 32] = [
        0x43, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x2d, // "CITADEL-"
        0x56, 0x44, 0x46, 0x2d, 0x47, 0x45, 0x4e, 0x45, // "VDF-GENE"
        0x53, 0x49, 0x53, 0x2d, 0x53, 0x45, 0x45, 0x44, // "SIS-SEED"
        0x2d, 0x56, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x00, // "-V1.0.0\0"
    ];

    /// Initialize VDF race as genesis node (first node in mesh)
    pub async fn init_vdf_genesis(&self) {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        let vdf_race = VdfRace::new_genesis(Self::VDF_GENESIS_SEED, signing_key);
        info!("VDF Race initialized as genesis (height 0)");

        state.vdf_race = Some(vdf_race);
    }

    /// Initialize VDF race when joining existing mesh
    /// Takes chain links from bootstrap peer
    pub async fn init_vdf_join(&self, chain_links: Vec<VdfLink>) -> bool {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        match VdfRace::join(Self::VDF_GENESIS_SEED, signing_key, chain_links) {
            Some(vdf_race) => {
                let height = vdf_race.height();
                info!("VDF Race initialized by joining (height {})", height);
                state.vdf_race = Some(vdf_race);
                true
            }
            None => {
                warn!("Failed to join VDF race - invalid chain");
                false
            }
        }
    }

    /// Claim a slot with VDF anchoring for deterministic priority
    /// Returns the anchored claim for flooding to the network
    pub async fn claim_slot_with_vdf(&self, index: u64) -> Option<AnchoredSlotClaim> {
        let mut state = self.state.write().await;

        // Ensure VDF race is initialized
        let vdf_race = state.vdf_race.as_mut()?;

        // Extend VDF chain before claiming (proves we did work)
        vdf_race.extend_chain();

        // Create VDF-anchored claim
        let claim = vdf_race.claim_slot(index);
        let vdf_height = claim.vdf_height;

        // Store our claim
        state.vdf_claims.insert(index, claim.clone());

        // Also create regular slot claim for compatibility
        let peer_id = state.self_id.clone();
        let public_key_bytes = state.signing_key.verifying_key().as_bytes().to_vec();
        let slot_claim =
            SlotClaim::with_public_key(index, peer_id.clone(), Some(public_key_bytes.clone()));
        let coord = slot_claim.coord;

        state.self_slot = Some(slot_claim.clone());
        state.claimed_slots.insert(index, slot_claim);
        state.slot_coords.insert(coord);

        info!(
            "Claimed slot {} with VDF anchor at height {} (coord: {}, {}, {})",
            index, vdf_height, coord.q, coord.r, coord.z
        );

        drop(state);

        // Set our slot in CVDF for duty rotation
        self.cvdf_set_slot(index).await;

        // Also register ourselves in CVDF
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&public_key_bytes);
        self.cvdf_register_slot(index, pubkey_arr).await;

        // Flood the VDF claim (signed, with VDF height for ordering)
        self.flood(FloodMessage::VdfSlotClaim {
            claim: claim.clone(),
        });

        Some(claim)
    }

    /// Process incoming VDF-anchored claim
    /// Uses VDF priority ordering for deterministic conflict resolution
    /// Returns true if this claim wins (has priority)
    pub async fn process_vdf_claim(&self, claim: AnchoredSlotClaim) -> bool {
        let mut state = self.state.write().await;

        let slot = claim.slot;
        let claimer_pubkey = claim.claimer;

        // Check if we have an existing claim for this slot
        let wins = if let Some(existing) = state.vdf_claims.get(&slot) {
            // Compare using proven priority ordering
            if claim_has_priority(&claim, existing) {
                info!(
                    "VDF claim for slot {} wins by priority (incoming height {}, existing height {})",
                    slot, claim.vdf_height, existing.vdf_height
                );

                // Check if we lost our slot
                if let Some(ref our_slot) = state.self_slot {
                    if our_slot.index == slot {
                        let our_pubkey = state.signing_key.verifying_key().to_bytes();
                        if claim.claimer != our_pubkey {
                            warn!("We lost slot {} to node with earlier VDF claim!", slot);
                            state.self_slot = None;
                        }
                    }
                }

                state.vdf_claims.insert(slot, claim);
                true
            } else {
                debug!(
                    "VDF claim for slot {} rejected: height {} >= existing height {}",
                    slot, claim.vdf_height, existing.vdf_height
                );
                false
            }
        } else {
            // No existing claim - this one wins
            info!(
                "VDF claim for slot {} accepted (first claim at height {})",
                slot, claim.vdf_height
            );
            state.vdf_claims.insert(slot, claim);
            true
        };

        // If claim won, also update claimed_slots for REST API / WebSocket visibility
        let mut register_cvdf = None;
        if wins {
            // Canonicalize peer IDs from pubkeys so VDF/TGP/TCP all agree.
            let peer_id = compute_peer_id_from_bytes(&claimer_pubkey);

            // Remove old slot if this peer claimed a different one
            let old_slot = state
                .claimed_slots
                .iter()
                .find(|(_, c)| c.peer_id == peer_id)
                .map(|(idx, c)| (*idx, c.coord));
            if let Some((old_idx, old_coord)) = old_slot {
                if old_idx != slot {
                    debug!(
                        "Peer {} moving from slot {} to slot {}",
                        peer_id, old_idx, slot
                    );
                    state.claimed_slots.remove(&old_idx);
                    state.slot_coords.remove(&old_coord);
                }
            }

            // Create SlotClaim from VDF claim
            let slot_claim =
                SlotClaim::with_public_key(slot, peer_id, Some(claimer_pubkey.to_vec()));
            state.slot_coords.insert(slot_claim.coord);
            state.claimed_slots.insert(slot, slot_claim);
            register_cvdf = Some((slot, claimer_pubkey));
        }

        drop(state);

        if let Some((slot, pubkey)) = register_cvdf {
            self.cvdf_register_slot(slot, pubkey).await;
        }

        wins
    }

    /// Try to adopt a longer VDF chain (for split-brain merge)
    /// Returns true if we switched to the longer chain
    pub async fn try_adopt_vdf_chain(&self, other_links: Vec<VdfLink>) -> bool {
        let mut state = self.state.write().await;

        let vdf_race = match state.vdf_race.as_mut() {
            Some(v) => v,
            None => {
                // Initialize VDF race with the received chain
                drop(state);
                return self.init_vdf_join(other_links).await;
            }
        };

        let our_height = vdf_race.height();
        let other_height = other_links.last().map(|l| l.height).unwrap_or(0);

        if vdf_race.try_adopt_chain(other_links) {
            info!(
                "Adopted longer VDF chain: {} -> {} (split-brain merge)",
                our_height,
                vdf_race.height()
            );
            true
        } else {
            debug!(
                "Rejected VDF chain: our height {} >= their height {}",
                our_height, other_height
            );
            false
        }
    }

    /// Get VDF chain links for syncing to peers
    pub async fn get_vdf_chain_links(&self) -> Vec<VdfLink> {
        let state = self.state.read().await;
        state
            .vdf_race
            .as_ref()
            .map(|v| v.chain_links().to_vec())
            .unwrap_or_default()
    }

    /// Extend VDF chain (collaborative - nodes take turns)
    pub async fn extend_vdf_chain(&self) -> Option<VdfLink> {
        let mut state = self.state.write().await;
        let vdf_race = state.vdf_race.as_mut()?;
        let link = vdf_race.extend_chain();

        let height = link.height;
        drop(state);

        // Flood the updated chain periodically
        if height % 10 == 0 {
            let links = self.get_vdf_chain_links().await;
            self.flood(FloodMessage::VdfChain { links });
        }

        Some(link)
    }

    /// Get current VDF height
    pub async fn vdf_height(&self) -> u64 {
        let state = self.state.read().await;
        state.vdf_race.as_ref().map(|v| v.height()).unwrap_or(0)
    }

    // ==================== END VDF RACE METHODS ====================

    // ==================== CVDF METHODS ====================
    //
    // Collaborative VDF: weight-based consensus where heavier chains win.
    // Weight = Σ(base + attestation_count) - more attesters = heavier chain
    // This is THE core of Constitutional P2P - collaboration beats competition.

    /// CVDF Genesis seed (same as VDF for compatibility)
    const CVDF_GENESIS_SEED: [u8; 32] = Self::VDF_GENESIS_SEED;

    /// Initialize CVDF as genesis node
    pub async fn init_cvdf_genesis(&self) {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        let cvdf = CvdfCoordinator::new_genesis(Self::CVDF_GENESIS_SEED, signing_key);
        info!("CVDF initialized as genesis (height 0, weight 1)");

        state.cvdf = Some(cvdf);
        drop(state); // Release lock before notify

        // Signal that CVDF is ready - unblocks the coordination loop
        self.cvdf_init_notify.notify_waiters();
    }

    /// Initialize CVDF by joining existing swarm
    /// Takes rounds from bootstrap peer and slot registrations
    pub async fn init_cvdf_join(
        &self,
        rounds: Vec<CvdfRound>,
        slots: Vec<(u64, [u8; 32])>,
    ) -> bool {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        match CvdfCoordinator::join(Self::CVDF_GENESIS_SEED, rounds, signing_key) {
            Some(mut cvdf) => {
                // Register known slots
                for (slot, pubkey) in slots {
                    cvdf.register_slot(slot, pubkey);
                }
                let height = cvdf.height();
                let weight = cvdf.weight();
                info!("CVDF joined (height {}, weight {})", height, weight);
                state.cvdf = Some(cvdf);
                drop(state);
                self.cvdf_init_notify.notify_waiters();
                true
            }
            None => {
                warn!("Failed to join CVDF - invalid chain");
                false
            }
        }
    }

    /// Register a slot in CVDF (for attestation tracking)
    pub async fn cvdf_register_slot(&self, slot: u64, pubkey: [u8; 32]) {
        let mut state = self.state.write().await;
        if let Some(ref mut cvdf) = state.cvdf {
            cvdf.register_slot(slot, pubkey);
            debug!(
                "CVDF registered slot {} with pubkey {:?}",
                slot,
                &pubkey[..8]
            );
        }
    }

    /// Set our slot in CVDF
    pub async fn cvdf_set_slot(&self, slot: u64) {
        let mut state = self.state.write().await;
        if let Some(ref mut cvdf) = state.cvdf {
            cvdf.set_slot(slot);
            info!("CVDF set our slot to {}", slot);
        }
    }

    /// Create attestation for current round
    pub async fn cvdf_attest(&self) -> Option<RoundAttestation> {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref()?;
        let att = cvdf.attest();
        Some(att)
    }

    /// Process incoming attestation
    pub async fn cvdf_process_attestation(&self, att: RoundAttestation) -> bool {
        let mut state = self.state.write().await;
        if let Some(cvdf) = state.cvdf.as_mut() {
            cvdf.receive_attestation(att)
        } else {
            false
        }
    }

    /// Try to produce a round (if it's our turn)
    pub async fn cvdf_try_produce(&self) -> Option<CvdfRound> {
        let mut state = self.state.write().await;
        let cvdf = state.cvdf.as_mut()?;

        if cvdf.is_our_turn() {
            cvdf.try_produce()
        } else {
            None
        }
    }

    /// Process incoming round
    pub async fn cvdf_process_round(&self, round: CvdfRound) -> bool {
        let mut state = self.state.write().await;
        if let Some(cvdf) = state.cvdf.as_mut() {
            cvdf.process_round(round)
        } else {
            false
        }
    }

    /// Get CVDF chain state for syncing
    pub async fn cvdf_chain_state(&self) -> Option<(Vec<CvdfRound>, Vec<AnchoredSlotClaim>)> {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref()?;

        let rounds = cvdf.chain().all_rounds().to_vec();
        let claims: Vec<AnchoredSlotClaim> = state.vdf_claims.values().cloned().collect();

        Some((rounds, claims))
    }

    /// Check if we should adopt another chain (heavier)
    pub async fn cvdf_should_adopt(&self, other_rounds: &[CvdfRound]) -> bool {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref();
        cvdf.map(|c| c.should_adopt(other_rounds)).unwrap_or(true)
    }

    /// Adopt heavier chain
    pub async fn cvdf_adopt(&self, rounds: Vec<CvdfRound>) -> bool {
        let mut state = self.state.write().await;
        let cvdf = state.cvdf.as_mut();
        cvdf.map(|c| c.adopt(rounds)).unwrap_or(false)
    }

    /// Get CVDF height
    pub async fn cvdf_height(&self) -> u64 {
        let state = self.state.read().await;
        state.cvdf.as_ref().map(|c| c.height()).unwrap_or(0)
    }

    /// Get CVDF weight
    pub async fn cvdf_weight(&self) -> u64 {
        let state = self.state.read().await;
        state.cvdf.as_ref().map(|c| c.weight()).unwrap_or(0)
    }

    /// Get CVDF tip hash
    pub async fn cvdf_tip(&self) -> [u8; 32] {
        let state = self.state.read().await;
        state
            .cvdf
            .as_ref()
            .map(|c| c.chain().tip_output())
            .unwrap_or([0u8; 32])
    }

    /// Check if CVDF is initialized
    pub async fn cvdf_initialized(&self) -> bool {
        let state = self.state.read().await;
        state.cvdf.is_some()
    }

    /// Check if this node has claimed a slot
    pub async fn has_claimed_slot(&self) -> bool {
        let state = self.state.read().await;
        state.self_slot.is_some()
    }

    /// Run CVDF coordination loop
    /// This handles periodic attestation and round production
    pub async fn run_cvdf_loop(&self) {
        use tokio::time::{interval, Duration};

        // Wait for CVDF to be initialized (event-driven, no polling)
        self.cvdf_init_notify.notified().await;

        // Run coordination loop
        let mut tick = interval(Duration::from_millis(100)); // 10Hz coordination

        loop {
            tick.tick().await;

            // Create and broadcast attestation (with piggybacked vouch when needed)
            if let Some(att) = self.cvdf_attest().await {
                // CRITICAL: Process our OWN attestation first (add to pending queue)
                // Without this, try_produce() has no attestations to work with!
                self.cvdf_process_attestation(att.clone()).await;

                // Piggyback vouch on attestation - zero extra traffic
                let vouch = if self.should_create_mesh_vouch().await {
                    self.create_mesh_vouch().await
                } else {
                    None
                };
                self.flood(FloodMessage::CvdfAttestation { att, vouch });
            }

            // Try to produce a round
            if let Some(round) = self.cvdf_try_produce().await {
                info!(
                    "CVDF produced round {} (weight {})",
                    round.round,
                    round.weight()
                );
                // Staple SPORE proof to heartbeat - empty at convergence (zero overhead)
                let spore_proof = citadel_spore::Spore::empty();
                self.flood(FloodMessage::CvdfNewRound { round, spore_proof });

                // EVENT-DRIVEN SLOT EVICTION: On round production, evict stale slots.
                // Slots that haven't attested in SLOT_LIVENESS_THRESHOLD rounds are dead.
                // This keeps claimed_slots bounded and accurate.
                let stale = self.prune_stale_slots().await;
                if !stale.is_empty() {
                    let mut state = self.state.write().await;
                    for (slot_idx, peer_id) in Self::evict_stale_slots_from_state(&mut state, &stale)
                    {
                        info!(
                            "Evicted stale slot {} and VDF claim (peer {} - no attestation for {} rounds)",
                            slot_idx,
                            peer_id,
                            crate::cvdf::SLOT_LIVENESS_THRESHOLD
                        );
                    }
                }
            }

            // Periodically broadcast chain state for sync
            let height = self.cvdf_height().await;
            if height > 0 && height % 10 == 0 {
                if let Some((rounds, claims)) = self.cvdf_chain_state().await {
                    let self_id = self.self_id().await;
                    self.flood(FloodMessage::CvdfSyncResponse { rounds, claims });
                }
            }
        }
    }

    // ==================== LIVENESS MONITORING ====================

    /// Check if a slot is live (has attested recently in CVDF)
    pub async fn is_slot_live(&self, slot: u64) -> bool {
        let state = self.state.read().await;
        state
            .cvdf
            .as_ref()
            .map(|c| c.is_slot_live(slot))
            .unwrap_or(false)
    }

    /// Get all stale slots (haven't attested in SLOT_LIVENESS_THRESHOLD rounds)
    pub async fn get_stale_slots(&self) -> Vec<u64> {
        let state = self.state.read().await;
        state
            .cvdf
            .as_ref()
            .map(|c| c.stale_slots())
            .unwrap_or_default()
    }

    /// Get liveness status for all registered slots
    /// Returns Vec<(slot, is_live, last_attestation_round)>
    pub async fn get_slot_liveness_status(&self) -> Vec<(u64, bool, Option<u64>)> {
        let state = self.state.read().await;
        state
            .cvdf
            .as_ref()
            .map(|c| c.slot_liveness_status())
            .unwrap_or_default()
    }

    /// Get liveness status for ghost neighbors (our actual connections via GnW)
    /// Returns live/stale status for each direction
    pub async fn ghost_neighbor_liveness(&self) -> Vec<(Direction, u64, bool)> {
        let state = self.state.read().await;

        let Some(ref self_slot) = state.self_slot else {
            return Vec::new();
        };

        let connections = self_slot.ghost_connections(&state.slot_coords);
        let cvdf = state.cvdf.as_ref();

        connections
            .iter()
            .filter_map(|conn| {
                // Find slot index at target coord
                let slot_idx = state
                    .claimed_slots
                    .values()
                    .find(|s| s.coord == conn.target)
                    .map(|s| s.index)?;

                // Check liveness
                let is_live = cvdf.map(|c| c.is_slot_live(slot_idx)).unwrap_or(false);

                Some((conn.direction, slot_idx, is_live))
            })
            .collect()
    }

    /// Count live ghost neighbors
    pub async fn live_ghost_neighbor_count(&self) -> usize {
        self.ghost_neighbor_liveness()
            .await
            .iter()
            .filter(|(_, _, live)| *live)
            .count()
    }

    /// Prune stale slots from CVDF tracking
    /// Returns list of pruned slot indices
    pub async fn prune_stale_slots(&self) -> Vec<u64> {
        let mut state = self.state.write().await;
        state
            .cvdf
            .as_mut()
            .map(|c| c.prune_stale_slots())
            .unwrap_or_default()
    }

    // ==================== MISBEHAVIOUR DETECTION ====================
    //
    // Track and report protocol violations using the accountability system.
    // Types of misbehaviour detected:
    // - Unresponsive: Node stopped responding to challenges
    // - InvalidResponse: Node provided invalid/lying responses
    // - BftFailure: Node failed BFT coordination
    // - PositionLie: Node claimed wrong position in mesh
    // - RelayFailure: Node failed to relay messages properly

    /// Start tracking a failure for a node
    pub async fn start_failure_tracking(
        &self,
        failed_pubkey: [u8; 32],
        failed_slot: Option<u64>,
        failure_type: FailureType,
    ) {
        let mut state = self.state.write().await;
        if let Some(ref mut accountability) = state.accountability {
            accountability.start_failure_tracking(failed_pubkey, failed_slot, failure_type);
        }
    }

    /// Report misbehaviour (unresponsive neighbor detected via liveness)
    pub async fn report_unresponsive(&self, slot: u64) {
        let state = self.state.read().await;

        // Get pubkey for the slot
        let slot_claim = state.claimed_slots.get(&slot);
        if let Some(claim) = slot_claim {
            if let Some(ref pubkey_bytes) = claim.public_key {
                if pubkey_bytes.len() == 32 {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(pubkey_bytes);
                    drop(state);
                    self.start_failure_tracking(pubkey, Some(slot), FailureType::Unresponsive)
                        .await;
                }
            }
        }
    }

    /// Check if a node is under failure tracking
    pub async fn is_tracking_failure(&self, pubkey: &[u8; 32]) -> bool {
        let state = self.state.read().await;
        state
            .accountability
            .as_ref()
            .map(|a| a.get_failure_proof(pubkey, 20).is_some())
            .unwrap_or(false)
    }

    /// Get all nodes currently being tracked for failure
    pub async fn get_failure_candidates(&self) -> Vec<[u8; 32]> {
        // Combine stale slots (from CVDF liveness) with accountability tracking
        let stale_slots = self.get_stale_slots().await;
        let state = self.state.read().await;

        stale_slots
            .iter()
            .filter_map(|&slot| {
                state
                    .claimed_slots
                    .get(&slot)
                    .and_then(|claim| claim.public_key.as_ref())
                    .and_then(|pk| {
                        if pk.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(pk);
                            Some(arr)
                        } else {
                            None
                        }
                    })
            })
            .collect()
    }

    /// Trigger misbehaviour check for all stale ghost neighbors
    pub async fn check_ghost_neighbor_misbehaviour(&self) {
        let liveness = self.ghost_neighbor_liveness().await;

        for (direction, slot, is_live) in liveness {
            if !is_live {
                debug!(
                    "Ghost neighbor at slot {} (direction {:?}) is stale - reporting unresponsive",
                    slot, direction
                );
                self.report_unresponsive(slot).await;
            }
        }
    }

    // ==================== END CVDF METHODS ====================

    // ==================== STRUCTURE-AWARE LIVENESS ====================
    //
    // MeshVouch: One signature attesting to all 20 neighbors.
    // Propagation: Origin → Judged → Witness → STOP (2 hops max)
    // Event-driven: Zero traffic at steady state.
    //
    // This is the symmetric protocol for join/leave:
    // - JOIN:  Accumulate vouches until threshold → slot valid
    // - LEAVE: Vouches expire until below threshold → slot invalid

    /// Initialize the liveness manager with our signing key
    pub async fn init_liveness_manager(&self) {
        let mut state = self.state.write().await;
        if state.liveness.is_none() {
            let manager = LivenessManager::new(state.signing_key.clone());
            state.liveness = Some(manager);
        }
    }

    /// Update liveness manager with current VDF height and neighbors
    pub async fn update_liveness_context(&self) {
        let mut state = self.state.write().await;

        // Get current VDF height
        let vdf_height = state.cvdf.as_ref().map(|c| c.current_round()).unwrap_or(0);

        // Get our slot
        let our_slot = state.self_slot.as_ref().map(|s| s.index);

        // Get neighbor public keys
        let neighbors: Vec<[u8; 32]> = state
            .present_neighbors()
            .iter()
            .filter_map(|claim| {
                claim.public_key.as_ref().and_then(|pk| {
                    if pk.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(pk);
                        Some(arr)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Update liveness manager
        if let Some(ref mut liveness) = state.liveness {
            liveness.set_vdf_height(vdf_height);
            if let Some(slot) = our_slot {
                liveness.set_slot(slot);
            }
            liveness.set_neighbors(neighbors);
        }
    }

    /// Record a latency measurement for liveness purposes
    pub async fn record_liveness_latency(&self, neighbor_pubkey: [u8; 32], latency_ms: u64) {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.record_latency(neighbor_pubkey, latency_ms);
        }
    }

    /// Handle an incoming mesh vouch - returns propagation decision
    ///
    /// Based on the decision:
    /// - Drop: Ignore (not relevant to us)
    /// - Stop: Record and don't propagate further (we're a witness)
    /// - ForwardToNeighbors: Record and forward to our neighbors (we're judged)
    pub async fn handle_mesh_vouch(&self, vouch: MeshVouch) -> PropagationDecision {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.handle_vouch(vouch)
        } else {
            PropagationDecision::Drop
        }
    }

    /// Check if we should create a new mesh vouch (event-driven)
    pub async fn should_create_mesh_vouch(&self) -> bool {
        let state = self.state.read().await;
        state
            .liveness
            .as_ref()
            .map(|l| l.should_create_vouch())
            .unwrap_or(false)
    }

    /// Create a mesh vouch for all alive neighbors
    ///
    /// Returns the vouch to be broadcast via the mesh.
    /// Call this when should_create_mesh_vouch() returns true.
    pub async fn create_mesh_vouch(&self) -> Option<MeshVouch> {
        let mut state = self.state.write().await;
        state.liveness.as_mut()?.create_vouch()
    }

    /// Check if a node is valid (has sufficient vouches)
    pub async fn is_node_valid(&self, pubkey: &[u8; 32]) -> bool {
        let state = self.state.read().await;
        state
            .liveness
            .as_ref()
            .map(|l| l.is_node_valid(pubkey))
            .unwrap_or(false)
    }

    /// Get all nodes that have become invalid (for slot reclamation)
    ///
    /// These are nodes whose vouches have expired below threshold.
    /// Their slots can now be claimed by new nodes.
    pub async fn get_invalid_nodes(&self) -> Vec<[u8; 32]> {
        let state = self.state.read().await;
        state
            .liveness
            .as_ref()
            .map(|l| l.invalid_nodes())
            .unwrap_or_default()
    }

    /// Get vouch count for a node
    pub async fn get_vouch_count(&self, pubkey: &[u8; 32]) -> usize {
        let state = self.state.read().await;
        state
            .liveness
            .as_ref()
            .map(|l| l.vouch_count(pubkey))
            .unwrap_or(0)
    }

    /// Prune expired liveness data
    pub async fn prune_liveness(&self) {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.prune_expired();
        }
    }

    /// Get slots that have become invalid and can be reclaimed
    ///
    /// Maps invalid node pubkeys to their slot indices.
    /// These slots are available for new nodes to claim.
    pub async fn get_reclaimable_slots(&self) -> Vec<u64> {
        let invalid_nodes = self.get_invalid_nodes().await;
        let state = self.state.read().await;

        invalid_nodes
            .iter()
            .filter_map(|pubkey| {
                state
                    .claimed_slots
                    .values()
                    .find(|claim| {
                        claim
                            .public_key
                            .as_ref()
                            .map(|pk| pk.as_slice() == pubkey.as_slice())
                            .unwrap_or(false)
                    })
                    .map(|claim| claim.index)
            })
            .collect()
    }

    // ==================== END STRUCTURE-AWARE LIVENESS ====================

    /// Attempt to occupy a SPIRAL slot through TGP bilateral connections.
    ///
    /// This is the CORRECT protocol for slot acquisition:
    /// 1. Calculate target slot's 20 theoretical neighbors
    /// 2. Find existing nodes at those neighbor positions
    /// 3. Attempt TGP bilateral connection with each
    /// 4. Count successful TGP agreements (bilateral triples)
    /// 5. If count >= consensus_threshold(mesh_size), we occupy the slot
    ///
    /// # The Optimized 4-Packet Handshake
    ///
    /// ```text
    /// PACKET 1 (A→B): C_A                         # A's commitment
    /// PACKET 2 (B→A): C_B + D_B                   # B's commitment + proof of A's
    /// PACKET 3 (A→B): D_A + T_A                   # A's double + triple
    /// PACKET 4 (B→A): T_B + Q_B                   # B's triple + quad
    ///
    /// RESULT: Both have the bilateral triple ("The Knot"). Forever.
    /// ```
    ///
    /// Returns `true` if slot was successfully occupied.
    pub async fn attempt_slot_via_tgp(&self, target_slot: u64) -> bool {
        let state = self.state.read().await;

        // Get mesh size for threshold calculation
        let mesh_size = state.claimed_slots.len();
        let threshold = consensus_threshold(mesh_size);

        // Calculate target slot's coordinate and its 20 theoretical neighbors
        let target_coord = spiral3d_to_coord(Spiral3DIndex::new(target_slot));
        let neighbor_coords = Neighbors::of(target_coord);

        // Find validators for this slot claim:
        // 1. First, look for SPIRAL neighbors (nodes at neighboring coordinates)
        // 2. If mesh is empty/forming, use ANY connected peer as witness
        let active_peer_ids = self.active_peer_ids_snapshot().await;
        let potential_validators = Self::occupied_theoretical_neighbor_validators(
            &state,
            &active_peer_ids,
            target_slot,
        )
        .into_iter()
        .map(|(peer_id, peer_addr, pubkey)| (peer_id, peer_addr, Some(pubkey.to_vec())))
        .collect::<Vec<_>>();

        let validator_count = potential_validators.len();
        drop(state);

        info!(
            "Attempting slot {} via TGP: {} validators, threshold {} (mesh size {})",
            target_slot, validator_count, threshold, mesh_size
        );

        // Calculate scaled threshold based on existing neighbors
        // If only 6 neighbors exist, we need ceil(6 * threshold / 20)
        let scaled_threshold = Self::scaled_slot_claim_threshold(mesh_size, validator_count);

        if scaled_threshold == 0 {
            info!(
                "Slot {} has zero existing neighbors and zero threshold - claiming immediately",
                target_slot
            );
            return self.claim_slot(target_slot).await;
        }

        // A slot can only be occupied through its existing theoretical neighbors.
        if validator_count == 0 {
            info!(
                "Cannot claim slot {} - no occupied theoretical neighbors to validate with",
                target_slot
            );
            return false;
        }

        info!(
            "Scaled threshold: {} of {} existing neighbors (full threshold: {} of 20)",
            scaled_threshold, validator_count, threshold
        );

        // Create TGP sessions with each neighbor and collect result receivers
        let mut result_receivers = Vec::new();
        let mut session_peer_ids = Vec::new();
        let commitment_msg = format!(
            "mesh_slot:{}:{}:{}",
            target_slot, target_coord.q, target_coord.r
        );

        for (peer_id, peer_addr, maybe_pubkey) in potential_validators {
            // Skip if we don't have their public key
            let Some(pubkey_bytes) = maybe_pubkey else {
                warn!("Cannot attempt TGP with {} - no public key", peer_id);
                continue;
            };

            // Convert to TGP PublicKey
            let Ok(pubkey_array): std::result::Result<[u8; 32], _> = pubkey_bytes.try_into() else {
                warn!("Invalid public key length for {}", peer_id);
                continue;
            };
            let Ok(counterparty_key) = PublicKey::from_bytes(&pubkey_array) else {
                warn!("Invalid public key for {}", peer_id);
                continue;
            };

            // Get cached TGP keypair (zerocopy - just clone the Arc's content)
            let my_keypair = (*self.tgp_keypair).clone();

            // Peer's TGP UDP address (same port as TCP - UDP and TCP share port)
            let peer_tgp_addr = peer_addr;

            // Create oneshot channel for result notification
            let (result_tx, result_rx) = oneshot::channel();

            // Create SYMMETRIC coordinator - role determined by public key comparison
            let mut coordinator = PeerCoordinator::symmetric(
                my_keypair,
                counterparty_key,
                CoordinatorConfig::default()
                    .with_commitment(commitment_msg.clone().into_bytes())
                    .with_timeout(std::time::Duration::from_secs(10))
                    .with_flood_rate(FloodRateConfig::fast()),
            );
            coordinator.set_active(true);

            // Store session in separate lock (contention-free)
            self.tgp_sessions.write().await.insert(
                peer_id.clone(),
                TgpSession {
                    coordinator,
                    commitment: commitment_msg.clone(),
                    result_tx: Some(result_tx),
                    peer_tgp_addr,
                },
            );

            session_peer_ids.push(peer_id.clone());
            result_receivers.push((peer_id.clone(), result_rx));
            debug!(
                "Created TGP session with {} for slot {} (TGP addr: {})",
                peer_id, target_slot, peer_tgp_addr
            );
        }

        debug!(
            "Created {} TGP sessions for slot {}",
            session_peer_ids.len(),
            target_slot
        );
        // Event-driven: immediately send TGP messages for all created sessions
        if let Some(udp_socket) = self.tgp_udp_socket.read().await.clone() {
            for peer_id in &session_peer_ids {
                self.send_tgp_messages(&udp_socket, peer_id).await;
            }
        } else {
            warn!("No UDP socket available for TGP!");
        }

        // Wait for all TGP sessions to complete (with timeout)
        let mut successful_coordinations = 0;
        let timeout = tokio::time::Duration::from_secs(10);

        for (peer_id, result_rx) in result_receivers {
            match tokio::time::timeout(timeout, result_rx).await {
                Ok(Ok(true)) => {
                    successful_coordinations += 1;
                    info!(
                        "TGP coordination with {} succeeded (bilateral triple achieved)",
                        peer_id
                    );
                }
                Ok(Ok(false)) => {
                    debug!("TGP coordination with {} failed", peer_id);
                }
                Ok(Err(_)) => {
                    debug!("TGP session with {} was dropped", peer_id);
                }
                Err(_) => {
                    debug!("TGP coordination with {} timed out", peer_id);
                    // Clean up timed out session (separate lock - contention-free)
                    self.tgp_sessions.write().await.remove(&peer_id);
                }
            }
        }

        info!(
            "TGP slot {} attempt: {} of {} coordinations (need {})",
            target_slot, successful_coordinations, validator_count, scaled_threshold
        );

        // Check if we reached threshold
        if successful_coordinations >= scaled_threshold {
            info!(
                "Slot {} acquired via TGP ({} >= {} threshold)",
                target_slot, successful_coordinations, scaled_threshold
            );
            self.claim_slot(target_slot).await
        } else {
            warn!(
                "Failed to acquire slot {} - only {} of {} required coordinations",
                target_slot, successful_coordinations, scaled_threshold
            );
            false
        }
    }

    /// Compute ungameable tiebreaker for slot claims
    /// Formula: hash(blake3(peer_id) XOR blake3(transaction))
    /// where transaction = "slot_claim:{index}"
    /// Lower hash wins. Impossible to influence since you can't predict the slot index
    /// when choosing your peer ID.
    fn slot_claim_priority(peer_id: &str, slot_index: u64) -> [u8; 32] {
        let peer_hash = blake3::hash(peer_id.as_bytes());
        let tx_data = format!("slot_claim:{}", slot_index);
        let tx_hash = blake3::hash(tx_data.as_bytes());

        // XOR the hashes
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = peer_hash.as_bytes()[i] ^ tx_hash.as_bytes()[i];
        }

        // Hash the XOR result for final priority
        *blake3::hash(&xored).as_bytes()
    }

    /// Compare two peers' priority for a slot (true if a beats b)
    fn peer_wins_slot(peer_a: &str, peer_b: &str, slot_index: u64) -> bool {
        let priority_a = Self::slot_claim_priority(peer_a, slot_index);
        let priority_b = Self::slot_claim_priority(peer_b, slot_index);
        priority_a < priority_b // Lower hash wins
    }

    /// Process a slot claim. Returns (we_lost, race_won) where:
    /// - we_lost: true if we lost our own slot to this claimer
    /// - race_won: true if this claimer beat a previous claimer (needs re-flooding)
    pub async fn process_slot_claim(
        &self,
        index: u64,
        peer_id: String,
        coord: (i64, i64, i64),
        public_key: Option<Vec<u8>>,
    ) -> (bool, bool) {
        let mut state = self.state.write().await;
        let hex_coord = HexCoord::new(coord.0, coord.1, coord.2);

        // Verify the coord matches the index
        let expected_coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        if hex_coord != expected_coord {
            warn!(
                "Invalid slot claim: index {} should be at {:?}, not {:?}",
                index, expected_coord, hex_coord
            );
            return (false, false);
        }

        let self_id = state.self_id.clone();

        // Check if this claim conflicts with OUR slot
        let our_slot_info = state.self_slot.as_ref().map(|s| (s.index, s.coord));
        let we_lost = if let Some((our_index, our_coord)) = our_slot_info {
            if our_index == index && peer_id != self_id {
                // Ungameable tiebreaker: hash(blake3(peer_id) XOR blake3(tx))
                if Self::peer_wins_slot(&peer_id, &self_id, index) {
                    warn!(
                        "Lost slot {} race to {} (their priority wins), will reclaim",
                        index, peer_id
                    );
                    // Remove our claim from the global map
                    state.claimed_slots.remove(&index);
                    state.slot_coords.remove(&our_coord);
                    state.self_slot = None;
                    true
                } else {
                    // We win, keep our slot
                    debug!(
                        "Won slot {} race against {} (our priority wins)",
                        index, peer_id
                    );
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Check if already claimed
        let mut race_won = false;
        if let Some(existing) = state.claimed_slots.get(&index) {
            if existing.peer_id == peer_id {
                // Same claim we already have - skip (deduplication)
                return (we_lost, false);
            }
            // Different claimer - use ungameable tiebreaker
            if Self::peer_wins_slot(&peer_id, &existing.peer_id, index) {
                let loser_id = existing.peer_id.clone();
                info!(
                    "Slot {} taken by {} (beats previous claimer {} by priority)",
                    index, peer_id, loser_id
                );
                // Clear the loser's slot in our peer records
                if let Some(loser_peer) = state.peers.get_mut(&loser_id) {
                    loser_peer.slot = None;
                }
                // Mark that a race was won - this needs re-flooding!
                race_won = true;
                // Fall through to accept the new claim
            } else {
                debug!(
                    "Slot {} stays with {} (beats new claimer {} by priority)",
                    index, existing.peer_id, peer_id
                );
                return (we_lost, false);
            }
        }

        // BUG FIX: Check if this peer already has a DIFFERENT slot claimed.
        // Each peer can only have ONE slot - remove any old claim before accepting new one.
        // This prevents nodes from appearing to claim multiple slots (e.g., slots 3, 25, 48).
        let old_slot_to_remove: Option<(u64, HexCoord)> = state
            .claimed_slots
            .iter()
            .find(|(slot_idx, claim)| claim.peer_id == peer_id && **slot_idx != index)
            .map(|(slot_idx, claim)| (*slot_idx, claim.coord));

        if let Some((old_index, old_coord)) = old_slot_to_remove {
            info!(
                "Peer {} moving from slot {} to slot {} - removing old claim",
                peer_id, old_index, index
            );
            state.claimed_slots.remove(&old_index);
            state.slot_coords.remove(&old_coord);
        }

        // Accept the claim (with public key for TGP)
        let claim = SlotClaim::with_public_key(index, peer_id.clone(), public_key.clone());
        state.claimed_slots.insert(index, claim);
        state.slot_coords.insert(hex_coord);

        info!(
            "Accepted slot claim {} from {} at ({}, {}, {})",
            index, peer_id, coord.0, coord.1, coord.2
        );

        // If this peer is connected to us, update their slot info and public key
        if let Some(peer) = state.peers.get_mut(&peer_id) {
            peer.slot = Some(SlotClaim::with_public_key(
                index,
                peer_id,
                public_key.clone(),
            ));
            // Also store public key in peer if we didn't have it
            if peer.public_key.is_none() {
                peer.public_key = public_key;
            }
        }

        (we_lost, race_won)
    }

    /// Get a receiver for flood messages (for connections to subscribe)
    pub fn subscribe_floods(&self) -> broadcast::Receiver<FloodMessage> {
        self.flood_tx.subscribe()
    }

    /// Broadcast a flood message to all connections
    pub fn flood(&self, msg: FloodMessage) {
        let _ = self.flood_tx.send(msg);
    }

    /// Get current mesh state for API
    pub async fn get_peers(&self) -> Vec<MeshPeer> {
        self.state.read().await.peers.values().cloned().collect()
    }

    /// Get self ID
    pub async fn self_id(&self) -> String {
        self.state.read().await.self_id.clone()
    }

    /// Get the shared mesh state (for API access)
    pub fn mesh_state(&self) -> Arc<RwLock<MeshState>> {
        Arc::clone(&self.state)
    }

    /// Get the flood sender (for admin socket to propagate changes)
    pub fn flood_tx(&self) -> broadcast::Sender<FloodMessage> {
        self.flood_tx.clone()
    }

    /// Get access to the DocumentStore for CRDT document operations.
    ///
    /// Documents stored here use rich semantic merges (NOT LWW):
    /// - Counters: max(a, b)
    /// - Sets: union(a, b)
    /// - Booleans: or(a, b)
    ///
    /// Proven convergent in proofs/CitadelProofs/CRDT/Convergence.lean
    pub fn doc_store(&self) -> Arc<tokio::sync::RwLock<DocumentStore>> {
        Arc::clone(&self.doc_store)
    }

    /// Run TGP UDP listener - receives incoming TGP messages from any peer
    /// This is connectionless - we can receive from anyone who knows our address
    /// Event-driven: immediately responds after receiving each message
    async fn run_tgp_udp_listener(&self, socket: Arc<UdpSocket>) {
        // TGP messages include cryptographic proofs and can be 2-4KB
        let mut buf = [0u8; 8192];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    self.traffic_stats.record_recv(len as u64);
                    // Deserialize TGP message
                    match serde_json::from_slice::<TgpMessage>(&buf[..len]) {
                        Ok(tgp_msg) => {
                            self.traffic_stats.record_tgp_message();
                            // Handle message and immediately send response (event-driven)
                            if let Some(peer_id) = self.handle_tgp_message(src_addr, tgp_msg).await
                            {
                                self.send_tgp_messages(&socket, &peer_id).await;
                            } else {
                                debug!("UDP from {} - no peer found for TGP message", src_addr);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to deserialize TGP from {} ({} bytes): {}",
                                src_addr, len, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("TGP UDP recv error: {}", e);
                }
            }
        }
    }

    /// Extract the sender's public key from a TGP message payload.
    /// The sender's commitment is always in the `own_*` field.
    fn extract_sender_pubkey(msg: &TgpMessage) -> Option<[u8; 32]> {
        match &msg.payload {
            MessagePayload::Commitment(c) => Some(*c.public_key.as_bytes()),
            MessagePayload::DoubleProof(d) => Some(*d.own_commitment.public_key.as_bytes()),
            MessagePayload::TripleProof(t) => Some(*t.own_double.own_commitment.public_key.as_bytes()),
            MessagePayload::QuadProof(q) => Some(*q.own_triple.own_double.own_commitment.public_key.as_bytes()),
            // Legacy Full Solve phases - extract from embedded proofs
            MessagePayload::QuadConfirmation(qc) => Some(*qc.quad_proof.own_triple.own_double.own_commitment.public_key.as_bytes()),
            MessagePayload::QuadConfirmationFinal(qcf) => Some(*qcf.own_conf.quad_proof.own_triple.own_double.own_commitment.public_key.as_bytes()),
        }
    }

    /// Extract slot claim info from a Commitment message.
    /// Returns Some(slot_index) if this is a slot claim commitment.
    fn extract_slot_claim_from_commitment(
        commitment: &citadel_protocols::Commitment,
    ) -> Option<u64> {
        // The commitment message is "mesh_slot:X:q:r" where X is the slot index
        let msg_bytes = commitment.message.as_slice();
        let msg_str = std::str::from_utf8(msg_bytes).ok()?;
        if !msg_str.starts_with("mesh_slot:") {
            return None;
        }
        // Parse "mesh_slot:123:0:0" -> 123
        let parts: Vec<&str> = msg_str.split(':').collect();
        if parts.len() >= 2 {
            parts[1].parse::<u64>().ok()
        } else {
            None
        }
    }

    /// Handle incoming TGP message from UDP.
    /// Returns the peer_id if message was processed (for sending response).
    /// Uses symmetric TGP - party roles determined by public key comparison.
    async fn handle_tgp_message(&self, src_addr: SocketAddr, msg: TgpMessage) -> Option<String> {
        // Extract sender's public key from the message itself (cryptographically authenticated)
        let sender_pubkey = Self::extract_sender_pubkey(&msg)?;

        // Find peer by public key (not by IP - multiple peers may share localhost IP)
        let (peer_id, my_keypair, counterparty_key) = {
            let state = self.state.read().await;

            // Match by public key extracted from the TGP message (primary method)
            let peer = state.peers.iter().find(|(_, p)| {
                p.public_key
                    .as_ref()
                    .map(|pk| pk.as_slice() == sender_pubkey.as_slice())
                    .unwrap_or(false)
            });

            // TGP is TCP-free: we can establish coordination with ANY node that sends us
            // a valid TGP message, using just the public key from the message itself.
            // No pre-existing TCP peer relationship required!
            let keypair = (*self.tgp_keypair).clone();

            match peer {
                Some((id, _peer)) => {
                    // Known peer - use their stored info
                    let Ok(counterparty) = PublicKey::from_bytes(&sender_pubkey) else {
                        warn!("Invalid public key from peer {}", id);
                        return None;
                    };
                    debug!("TGP from known peer {} at {}", id, src_addr);
                    (id.clone(), keypair, counterparty)
                }
                None => {
                    // Unknown peer - create canonical peer_id from their public key.
                    let peer_id = compute_peer_id_from_bytes(&sender_pubkey);
                    let Ok(counterparty) = PublicKey::from_bytes(&sender_pubkey) else {
                        warn!("Invalid public key from unknown peer at {}", src_addr);
                        return None;
                    };
                    debug!(
                        "TGP: Accepting coordination from {} at {}",
                        &peer_id[..12],
                        src_addr
                    );
                    (peer_id, keypair, counterparty)
                }
            }
        };

        // SLOT VALIDATION: If this is a slot claim, check if the slot is available
        // Per MESH_PROTOCOL.md: "Loser's neighbors reject (slot already filling)"
        if let MessagePayload::Commitment(c) = &msg.payload {
            if let Some(claimed_slot) = Self::extract_slot_claim_from_commitment(c) {
                let state = self.state.read().await;
                // Check if this slot is already claimed by someone else
                if let Some(existing_claim) = state.claimed_slots.get(&claimed_slot) {
                    // Slot is taken - reject this TGP
                    info!("SLOT VALIDATION: Rejecting TGP for slot {} from {} - slot already claimed by {}",
                          claimed_slot, peer_id, existing_claim.peer_id);
                    return None;
                }
                debug!(
                    "SLOT VALIDATION: Slot {} is available for {}",
                    claimed_slot, peer_id
                );
            }
        }

        // Create session if needed (SYMMETRIC - no tiebreaker needed!)
        // With symmetric TGP, both peers can create sessions independently
        // and they'll automatically have opposite roles based on public key comparison.
        {
            let mut sessions = self.tgp_sessions.write().await;
            let is_commitment = matches!(&msg.payload, MessagePayload::Commitment(_));
            let need_new_session = if let Some(existing) = sessions.get(&peer_id) {
                // If we receive a Commitment and our session is Complete, a new TGP is starting
                // This happens when a peer starts claiming a different slot after their first claim
                is_commitment && existing.coordinator.is_coordinated()
            } else {
                true
            };

            if need_new_session {
                if sessions.contains_key(&peer_id) {
                    info!(
                        "Resetting TGP session for {} (new Commitment received after Complete)",
                        peer_id
                    );
                } else {
                    debug!(
                        "Creating SYMMETRIC TGP session for {} (incoming message)",
                        peer_id
                    );
                }
                let mut coordinator = PeerCoordinator::symmetric(
                    my_keypair.clone(),
                    counterparty_key.clone(),
                    CoordinatorConfig::default()
                        .with_timeout(std::time::Duration::from_secs(30))
                        .with_flood_rate(FloodRateConfig::fast()),
                );
                coordinator.set_active(true);
                sessions.insert(
                    peer_id.clone(),
                    TgpSession {
                        coordinator,
                        commitment: String::new(),
                        result_tx: None,
                        peer_tgp_addr: src_addr,
                    },
                );
            }
        }

        // Process the message (separate lock)
        // If coordination completes, extract receipt for AuthorizedPeer storage
        let completed_auth: Option<(QuadProof, QuadProof, [u8; 32], SocketAddr)> = {
            let mut sessions = self.tgp_sessions.write().await;
            if let Some(session) = sessions.get_mut(&peer_id) {
                let old_state = session.coordinator.tgp_state();
                // Log message party for debugging
                let msg_party = match &msg.payload {
                    MessagePayload::Commitment(c) => format!("Commitment({})", c.party),
                    MessagePayload::DoubleProof(d) => format!("Double({})", d.party),
                    MessagePayload::TripleProof(t) => format!("Triple({})", t.party),
                    MessagePayload::QuadProof(q) => format!("Quad({})", q.party),
                    MessagePayload::QuadConfirmation(q) => format!("QuadConf({})", q.party),
                    MessagePayload::QuadConfirmationFinal(q) => {
                        format!("QuadConfFinal({})", q.party)
                    }
                };
                debug!(
                    "TGP recv: {} msg={} (state: {:?})",
                    peer_id, msg_party, old_state
                );
                match session.coordinator.receive(&msg) {
                    Ok(advanced) => {
                        let new_state = session.coordinator.tgp_state();
                        if advanced {
                            debug!(
                                "TGP with {} advanced: {:?} -> {:?}",
                                peer_id, old_state, new_state
                            );
                        } else {
                            debug!(
                                "TGP with {} receive ok but state unchanged: {:?}",
                                peer_id, old_state
                            );
                        }
                        if session.coordinator.is_coordinated() {
                            info!("TGP with {} complete - QuadProof achieved!", peer_id);
                            if let Some(tx) = session.result_tx.take() {
                                let _ = tx.send(true);
                            }
                            // Extract bilateral receipt for AuthorizedPeer storage
                            if let Some((our_quad, their_quad)) = session.coordinator.get_bilateral_receipt() {
                                // Get peer's public key from message
                                let pubkey = Self::extract_sender_pubkey(&msg).unwrap_or([0u8; 32]);
                                Some((our_quad.clone(), their_quad.clone(), pubkey, session.peer_tgp_addr))
                            } else {
                                warn!("TGP coordinated but no bilateral receipt - should never happen");
                                None
                            }
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        debug!(
                            "TGP message from {} rejected (state: {:?}): {:?}",
                            peer_id, old_state, e
                        );
                        None
                    }
                }
            } else {
                debug!(
                    "TGP recv: no session for {} (sessions: {:?})",
                    peer_id,
                    sessions.keys().collect::<Vec<_>>()
                );
                None
            }
        };

        // If coordination completed, store in authorized_peers AND claim our slot
        if let Some((our_quad, their_quad, pubkey, addr)) = completed_auth {
            self.traffic_stats.record_tgp_completion();
            debug!("TGP: Adding {} to authorized_peers", peer_id);
            let authorized = AuthorizedPeer::new(
                peer_id.clone(),
                pubkey,
                our_quad,
                their_quad,
                addr,
            );

            let mut authorized_peers = self.authorized_peers.write().await;
            authorized_peers.insert(peer_id.clone(), authorized);
            debug!("TGP: {} authorized peers total", authorized_peers.len());

            if self.state.read().await.self_slot.is_none() {
                self.try_claim_slot_from_live_state().await;
            }
        }

        Some(peer_id)
    }

    /// Send TGP messages for a session immediately (event-driven, no polling)
    /// Called when session is created or when a message is received
    /// CONTENTION-FREE: Uses separate tgp_sessions lock, never blocks on mesh state
    async fn send_tgp_messages(&self, socket: &UdpSocket, peer_id: &str) {
        let messages_to_send: Vec<(SocketAddr, Vec<u8>)> = {
            let mut sessions = self.tgp_sessions.write().await;
            let mut to_send = Vec::new();

            if let Some(session) = sessions.get_mut(peer_id) {
                // Check if coordinated
                if session.coordinator.is_coordinated() {
                    info!("TGP with {} complete - bilateral triple achieved!", peer_id);
                    if let Some(tx) = session.result_tx.take() {
                        let _ = tx.send(true);
                    }
                    // Don't remove yet - let attempt_slot_via_tgp clean up
                } else {
                    // Poll for messages to send
                    let state = session.coordinator.tgp_state();
                    match session.coordinator.poll() {
                        Ok(Some(messages)) => {
                            let tgp_addr = session.peer_tgp_addr;
                            debug!(
                                "TGP poll: {} messages for {} (state: {:?}, addr: {})",
                                messages.len(),
                                peer_id,
                                state,
                                tgp_addr
                            );
                            for msg in messages {
                                if let Ok(data) = serde_json::to_vec(&msg) {
                                    to_send.push((tgp_addr, data));
                                }
                            }
                        }
                        Ok(None) => {
                            // Rate limited - but log for debugging
                            debug!(
                                "TGP poll: rate limited for {} (state: {:?})",
                                peer_id, state
                            );
                        }
                        Err(e) => {
                            debug!(
                                "TGP poll error for {} (state: {:?}): {:?}",
                                peer_id, state, e
                            );
                            if let Some(tx) = session.result_tx.take() {
                                let _ = tx.send(false);
                            }
                        }
                    }
                }
            }

            to_send
        };

        // Send messages (outside of lock)
        for (addr, data) in messages_to_send {
            let len = data.len();
            if let Err(e) = socket.send_to(&data, addr).await {
                warn!("Failed to send TGP to {}: {}", addr, e);
            } else {
                self.traffic_stats.record_send(len as u64);
            }
        }
    }

    /// Run the mesh service
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("Starting mesh service on {}", self.listen_addr);
        if let Some(announce) = self.announce_addr {
            info!("Announcing as {} (public address)", announce);
        }
        self.prime_ygg_public_addr().await;

        // Start TCP listener for incoming connections
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Mesh P2P (TCP) listening on {}", self.listen_addr);

        // Spawn task to initialize consensus state and connect to entry peers.
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            // CVDF Swarm Merge Theorem: Every node starts as genesis.
            // When nodes meet, heavier chain wins (more attesters = heavier).
            // See proofs/CitadelProofs/CVDF.lean theorems 9-11:
            //   - merge_deterministic: Merge is deterministic
            //   - merge_takes_heavier: Merge always produces heavier chain
            //   - heavier_survives_merge: Heavier chain survives merge
            //
            // This means: ALWAYS init genesis immediately, then adopt heavier chains on connection.
            // No waiting, no "am I first?" logic - chain merge handles everything.
            info!("CVDF: Initializing as genesis (heavier chains adopted on connection)");
            self_clone.init_cvdf_genesis().await;
            self_clone.init_vdf_genesis().await;

            // Try connecting to entry peers (if any configured)
            // This is just a hint - connections can come from anywhere
            let _ = self_clone.connect_to_entry_peers().await;

            // Slot claiming is EVENT-DRIVEN, triggered by:
            // - on_peer_connected() when any peer connects (inbound or outbound)
            // - on_slot_claim_received() when we learn about the mesh state
            // - on_slot_lost() when we lose a priority race
            //
            // NO TIMEOUTS. NO GIVING UP. The mesh is dynamic.
            // See: trigger_slot_claim_if_ready()
            info!("Node initialized - slot claiming will trigger on first peer connection");
        });

        // Spawn CVDF coordination loop
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.run_cvdf_loop().await;
        });

        // Spawn traffic stats logging loop (every 10s)
        let traffic_stats = Arc::clone(&self.traffic_stats);
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            use tokio::time::{interval, Duration};
            let mut tick = interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                self_clone.prune_stale_mesh_state().await;
                let (sent, recv, pkt_sent, pkt_recv, _tgp_msgs, _tgp_done) =
                    traffic_stats.take_snapshot();
                // Only log if there was any traffic
                if sent > 0 || recv > 0 {
                    info!(
                        "Traffic: {} tx, {} rx | {}/s tx, {}/s rx",
                        pkt_sent,
                        pkt_recv,
                        super::state::TrafficStats::format_rate(sent, 10),
                        super::state::TrafficStats::format_rate(recv, 10)
                    );
                }
            }
        });

        // Spawn entry peer retry loop - keeps trying to connect when isolated or slotless
        // Uses exponential backoff: 1s -> 2s -> 4s -> 8s -> ... -> 60s max
        // All peers are equal - CITADEL_PEERS are just entry points, not "bootstrap" nodes
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            const MIN_RETRY_SECS: u64 = 1;
            const MAX_RETRY_SECS: u64 = 60;
            let mut retry_secs = MIN_RETRY_SECS;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;

                let (live_peer_count, has_slot) = {
                    let active_peer_ids = self_clone.active_peer_ids_snapshot().await;
                    let state = self_clone.state.read().await;
                    (Self::active_peer_count(&state, &active_peer_ids), state.self_slot.is_some())
                };

                if live_peer_count == 0 && !self_clone.entry_peers.is_empty() {
                    info!(
                        "Isolated (0 live peers) - retrying entry peers (backoff {}s)",
                        retry_secs
                    );
                    let connected = self_clone.connect_to_entry_peers().await;
                    if connected > 0 {
                        info!("Reconnected to {} entry peer(s)", connected);
                        retry_secs = MIN_RETRY_SECS; // Reset backoff on success
                    } else {
                        // Exponential backoff on failure
                        retry_secs = std::cmp::min(retry_secs * 2, MAX_RETRY_SECS);
                    }
                } else {
                    if !has_slot {
                        debug!(
                            "Slotless with {} live peer(s) - re-entering slot claim path",
                            live_peer_count
                        );
                        self_clone.trigger_slot_claim_if_ready();
                    }

                    // Have live peers - reset backoff for when we next become isolated
                    retry_secs = MIN_RETRY_SECS;
                }
            }
        });

        // Accept incoming connections and handle pending outbound connections
        let mut pending_rx = self.pending_connect_rx.lock().await;
        loop {
            tokio::select! {
                // Handle incoming connections
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!("Incoming mesh connection from {}", addr);
                            let self_clone = Arc::clone(&self);
                            tokio::spawn(async move {
                                // Incoming connections are not entry peers
                                if let Err(e) = self_clone.handle_connection(stream, addr, false).await {
                                    warn!("Connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                // Handle pending outbound connections (queued by handle_message)
                Some((discovered_id, addr_hint)) = pending_rx.recv() => {
                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        let known_peer = {
                            self_clone.state.read().await.peers.get(&discovered_id).cloned()
                        };
                        let addr = if let Some(peer) = known_peer.as_ref() {
                            super::transport::resolve_peer_dial_target(
                                peer,
                                self_clone.ygg_admin_socket.as_deref(),
                            )
                            .await
                        } else {
                            super::transport::resolve_socket_hint_target(
                                addr_hint,
                                self_clone.ygg_admin_socket.as_deref(),
                            )
                            .await
                        };
                        let Some(addr) = addr else {
                            debug!(
                                "Skipping discovered peer {}: no Ygg dial path for hint {}",
                                discovered_id, addr_hint
                            );
                            return;
                        };

                        match TcpStream::connect(&addr).await {
                            Ok(stream) => {
                                debug!(
                                    "Connected to discovered peer {} via Ygg {} (hint {})",
                                    discovered_id, addr, addr_hint
                                );
                                // Discovered peers are not entry peers
                                if let Err(e) = self_clone.handle_connection(stream, addr, false).await {
                                    debug!("Discovered peer {} connection closed: {}", discovered_id, e);
                                }
                            }
                            Err(e) => {
                                debug!("Failed to connect to discovered peer {}: {}", discovered_id, e);
                            }
                        }
                    });
                }
            }
        }
    }

    /// Connect to bootstrap peers, returns count of successful connections
    async fn connect_to_entry_peers(self: &Arc<Self>) -> usize {
        let mut connected = 0;

        for peer_addr in &self.entry_peers {
            info!("Connecting to peer: {}", peer_addr);

            let candidate_addrs = super::transport::resolve_entry_peer_targets(
                peer_addr,
                self.ygg_admin_socket.as_deref(),
            )
            .await;
            if candidate_addrs.is_empty() {
                warn!("No Ygg dial path found for entry peer {}", peer_addr);
                continue;
            }

            let mut peer_connected = false;
            let addr_count = candidate_addrs.len();
            let connect_timeout = std::time::Duration::from_secs(5);

            for resolved_addr in candidate_addrs {
                debug!("Trying {} -> {}", peer_addr, resolved_addr);

                match tokio::time::timeout(connect_timeout, TcpStream::connect(resolved_addr)).await
                {
                    Ok(Ok(stream)) => {
                        info!("Connected to entry peer {} at {}", peer_addr, resolved_addr);
                        connected += 1;
                        peer_connected = true;

                        // Spawn connection handler as task - don't block!
                        // Entry peers are marked as such for later pruning when we have enough SPIRAL neighbors
                        let self_clone = Arc::clone(self);
                        let addr = resolved_addr;
                        tokio::spawn(async move {
                            if let Err(e) = self_clone.handle_connection(stream, addr, true).await {
                                warn!("Entry peer {} disconnected: {}", addr, e);
                            }
                        });
                        break; // Connected successfully, don't try other addresses
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "Failed to connect to {} ({}): {}",
                            peer_addr, resolved_addr, e
                        );
                    }
                    Err(_) => {
                        debug!("Timeout connecting to {} ({})", peer_addr, resolved_addr);
                    }
                }
            }

            if !peer_connected {
                warn!(
                    "Failed to connect to peer {} (tried {} addresses)",
                    peer_addr, addr_count
                );
            }
        }

        connected
    }

    /// Handle a peer connection
    async fn handle_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
        is_entry_peer: bool,
    ) -> Result<()> {
        // Use full IP:port as initial peer_id to avoid collisions when connecting to
        // multiple peers that listen on the same port (e.g., all bootstrap nodes on :9000)
        let peer_id = format!("peer-{}", addr);

        // Register peer (slot unknown until they announce it via SPORE flood)
        {
            let mut state = self.state.write().await;
            state.peers.insert(
                peer_id.clone(),
                MeshPeer {
                    id: peer_id.clone(),
                    addr,
                    yggdrasil_addr: None,
                    underlay_uri: None,
                    ygg_peer_uri: None,
                    public_key: None,
                    last_seen: std::time::Instant::now(),
                    coordinated: false,
                    slot: None, // Will be learned via SPORE slot_claim flood
                    is_entry_peer,
                    content_synced: false, // Will become true when HaveLists match
                    their_have: None,      // SPORE: received via SporeSync
                    their_peer_addr_have: None,
                },
            );
        }

        {
            let mut active_peers = self.active_tcp_peers.write().await;
            *active_peers.entry(peer_id.clone()).or_insert(0) += 1;
        }

        info!("Peer {} registered", peer_id);

        // EVENT: Peer connected - trigger slot claiming if we don't have a slot yet
            self.try_claim_slot_from_live_state().await;

        // Simple protocol: exchange node info and sync state
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send our node info with public key for TGP
        let state = self.state.read().await;
        let self_id = state.self_id.clone();
        let self_pubkey = state.signing_key.verifying_key();
        let pubkey_hex = hex::encode(self_pubkey.as_bytes());
        // Priority: 1) explicit announce_addr, 2) learned from peers, 3) listen_addr
        let our_addr = self
            .announce_addr
            .or(state.observed_public_addr)
            .unwrap_or(self.listen_addr);
        drop(state);
        let hello = serde_json::json!({
            "type": "hello",
            "node_id": self_id,
            "addr": our_addr.to_string(),
            "public_key": pubkey_hex,
            "yggdrasil_addr": self.local_yggdrasil_addr,
            "underlay_uri": self.local_underlay_uri,
            "ygg_peer_uri": self.local_underlay_uri,
            // Tell peer what IP we see them as (STUN-like)
            "your_addr": addr.to_string(),
        });
        {
            let mut state = self.state.write().await;
            let _ = state.peer_addr_store.insert(PeerAddrRecord::from_local(
                self_id.clone(),
                pubkey_hex.clone(),
                self.listen_addr.port(),
                self.local_yggdrasil_addr.clone(),
                self.local_underlay_uri.clone(),
                self.local_underlay_uri.clone(),
                Self::now_ms(),
            ));
        }
        writer.write_all(hello.to_string().as_bytes()).await?;
        writer.write_all(b"\n").await?;

        // Flood our complete state to this peer (event-driven, no request/response)
        // Admin list
        if let Ok(admins) = self.storage.list_admins() {
            if !admins.is_empty() {
                let flood_admins = serde_json::json!({
                    "type": "flood_admins",
                    "admins": admins,
                });
                writer
                    .write_all(flood_admins.to_string().as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                debug!("Flooded {} admins to peer {}", admins.len(), peer_id);
            }
        }

        // Peer list - flood our complete view of the mesh with slot info and public keys
        // SPORE: only flood real peer IDs (b3b3/...), never temp IDs
        {
            let state = self.state.read().await;
            let self_slot = state.self_slot.as_ref().map(|s| s.index);
            let self_pubkey = hex::encode(state.signing_key.verifying_key().as_bytes());
            // Priority: 1) explicit announce_addr, 2) learned from peers, 3) listen_addr
            let our_addr_for_flood = self
                .announce_addr
                .or(state.observed_public_addr)
                .unwrap_or(self.listen_addr);
            let mut all_peers = vec![serde_json::json!({
                "id": state.self_id,
                "addr": our_addr_for_flood.to_string(),
                "slot": self_slot,
                "public_key": self_pubkey,
                "yggdrasil_addr": self.local_yggdrasil_addr,
                "underlay_uri": self.local_underlay_uri,
                "ygg_peer_uri": self.local_underlay_uri,
            })];
            for peer in state.peers.values() {
                // Only flood peers with real IDs (b3b3/...), skip temp IDs
                if !peer.id.starts_with("b3b3/") {
                    continue;
                }
                if !Self::is_usable_peer_addr(peer.addr) {
                    continue;
                }
                all_peers.push(serde_json::json!({
                    "id": peer.id,
                    "addr": peer.addr.to_string(),
                    "slot": peer.slot.as_ref().map(|s| s.index),
                    "public_key": peer.public_key.as_ref().map(hex::encode),
                    "yggdrasil_addr": peer.yggdrasil_addr,
                    "underlay_uri": peer.underlay_uri,
                    "ygg_peer_uri": peer.ygg_peer_uri,
                }));
            }

            let flood_peers = serde_json::json!({
                "type": "flood_peers",
                "peers": all_peers,
            });
            writer.write_all(flood_peers.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;

            // Also flood all claimed slots (with public keys for TGP)
            for claim in state.claimed_slots.values() {
                let slot_msg = serde_json::json!({
                    "type": "slot_claim",
                    "index": claim.index,
                    "peer_id": claim.peer_id,
                    "coord": [claim.coord.q, claim.coord.r, claim.coord.z],
                    "public_key": claim.public_key.as_ref().map(hex::encode),
                });
                writer.write_all(slot_msg.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }

            // SPORE: Send our HaveList so peer can identify missing slots
            let have_slots: Vec<u64> = state.claimed_slots.keys().copied().collect();
            let have_list = serde_json::json!({
                "type": "spore_have_list",
                "peer_id": state.self_id,
                "slots": have_slots,
            });
            writer.write_all(have_list.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        // SPORE: Send range-based HaveList for optimal sync
        // Sync cost = O(|XOR difference|), converges to 0 at steady state
        // WantList = HaveList.complement() - receiver derives it
        {
            let doc_store = self.doc_store.read().await;
            let releases = doc_store
                .list::<crate::models::Release>()
                .unwrap_or_default();
            let release_ids: Vec<String> = releases.iter().map(|r| r.id.clone()).collect();
            let have_list = build_spore_havelist(&release_ids);
            let self_id = self.state.read().await.self_id.clone();

            let spore_sync = serde_json::json!({
                "type": "spore_sync",
                "peer_id": self_id,
                "have_list": have_list,
            });
            writer.write_all(spore_sync.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            debug!(
                "SPORE: Sent HaveList with {} ranges to peer {}",
                have_list.range_count(),
                peer_id
            );
        }

        // Peer address SPORE: advertise our replicated address plane on connect.
        {
            let state = self.state.read().await;
            let peer_addr_sync = serde_json::json!({
                "type": "peer_addr_sync",
                "peer_id": state.self_id,
                "have_list": state.peer_addr_store.spore().clone(),
            });
            writer
                .write_all(peer_addr_sync.to_string().as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }

        // SPORE: Send featured releases for homepage sync (from DocumentStore)
        // Featured releases use rich semantic merges (NOT LWW) - proven convergent in Lean
        // When peers receive, they merge via TotalMerge, ensuring no data loss
        {
            let doc_store = self.doc_store.read().await;
            let featured = doc_store.list::<FeaturedRelease>().unwrap_or_default();
            if !featured.is_empty() {
                let self_id = self.state.read().await.self_id.clone();
                let featured_json: Vec<String> = featured
                    .iter()
                    .filter_map(|f| serde_json::to_string(f).ok())
                    .collect();
                let featured_sync = serde_json::json!({
                    "type": "featured_sync",
                    "peer_id": self_id,
                    "featured": featured_json,
                });
                writer
                    .write_all(featured_sync.to_string().as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                debug!(
                    "SPORE: Sent {} featured releases to peer {}",
                    featured.len(),
                    peer_id
                );
            }
        }

        // SPORE⁻¹: Send DoNotWantList (deletion ranges) for deletion sync
        // Uses range-based Spore for O(|diff|) → 0 convergence
        {
            let state = self.state.read().await;
            if !state.do_not_want.is_empty() {
                let do_not_want_list = serde_json::json!({
                    "type": "do_not_want_list",
                    "ranges": state.do_not_want_spore(),
                });
                writer
                    .write_all(do_not_want_list.to_string().as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                debug!(
                    "SPORE⁻¹: Sent DoNotWantList with {} ranges to peer {}",
                    state.do_not_want.range_count(),
                    peer_id
                );
            }
        }

        // SPORE⁻¹: Send ErasureConfirmation (confirmed deletion ranges) for GDPR sync
        // Enables XOR-based erasure convergence detection
        {
            let state = self.state.read().await;
            if !state.erasure_confirmed.is_empty() {
                let erasure_msg = serde_json::json!({
                    "type": "erasure_confirmation",
                    "ranges": &state.erasure_confirmed,
                });
                writer.write_all(erasure_msg.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!(
                    "SPORE⁻¹: Sent ErasureConfirmation with {} ranges to peer {}",
                    state.erasure_confirmed.range_count(),
                    peer_id
                );
            }
        }

        // BadBits: Send PERMANENT blocklist (DMCA, abuse material, illegal content)
        // Unlike GDPR tombstones, BadBits are never garbage collected
        {
            let state = self.state.read().await;
            if !state.bad_bits.is_empty() {
                let bad_bits_hex: Vec<String> =
                    state.bad_bits.iter().map(|h| hex::encode(h)).collect();
                let bad_bits_msg = serde_json::json!({
                    "type": "bad_bits",
                    "double_hashes": bad_bits_hex,
                });
                writer
                    .write_all(bad_bits_msg.to_string().as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                debug!(
                    "Sent BadBits with {} entries to peer {}",
                    bad_bits_hex.len(),
                    peer_id
                );
            }
        }

        // CVDF chain sync: Send our chain state so peer can adopt heavier chain
        // CRITICAL: This enables swarm merge during initial connection
        if let Some((rounds, claims)) = self.cvdf_chain_state().await {
            let rounds_json: Vec<serde_json::Value> = rounds
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "round": r.round,
                        "prev_output": hex::encode(r.prev_output),
                        "washed_input": hex::encode(r.washed_input),
                        "output": hex::encode(r.output),
                        "producer": hex::encode(r.producer),
                        "producer_signature": hex::encode(r.producer_signature),
                        "timestamp_ms": r.timestamp_ms,
                        "attestations": r.attestations.iter().map(|a| {
                            serde_json::json!({
                                "round": a.round,
                                "prev_output": hex::encode(a.prev_output),
                                "attester": hex::encode(a.attester),
                                "slot": a.slot,
                                "signature": hex::encode(a.signature),
                            })
                        }).collect::<Vec<_>>(),
                    })
                })
                .collect();
            let claims_json: Vec<serde_json::Value> = claims
                .iter()
                .map(|claim| {
                    serde_json::json!({
                        "slot": claim.slot,
                        "claimer": hex::encode(claim.claimer),
                        "vdf_height": claim.vdf_height,
                        "vdf_output": hex::encode(claim.vdf_output),
                        "signature": hex::encode(claim.signature),
                    })
                })
                .collect();
            let cvdf_sync = serde_json::json!({
                "type": "cvdf_sync_response",
                "rounds": rounds_json,
                "claims": claims_json,
                "height": rounds.last().map(|r| r.round).unwrap_or(0),
                "total_weight": rounds.iter().map(|r| r.weight() as u64).sum::<u64>(),
            });
            writer.write_all(cvdf_sync.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            debug!(
                "Sent CVDF chain state to peer {} (height {}, {} claims)",
                peer_id,
                rounds.last().map(|r| r.round).unwrap_or(0),
                claims.len()
            );
        }

        // Subscribe to broadcast floods
        let mut flood_rx = self.flood_tx.subscribe();

        // Track current peer key (may change from peer-{port} to real PeerID)
        let mut current_peer_key = peer_id.clone();

        // Timer for checking if this entry peer should be disconnected
        // Only relevant if is_entry_peer=true
        let mut entry_peer_check_interval =
            tokio::time::interval(std::time::Duration::from_secs(10));

        // Read peer messages and forward floods concurrently
        // NOTE: TGP is now over UDP (connectionless), not TCP
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                // Check if this entry peer should be disconnected (have enough SPIRAL neighbors)
                _ = entry_peer_check_interval.tick(), if is_entry_peer => {
                    let state = self.state.read().await;
                    if state.entry_peers_to_disconnect().contains(&current_peer_key) {
                        info!("Disconnecting entry peer {} - have sufficient SPIRAL neighbors ({})",
                            current_peer_key, state.connected_neighbor_count());
                        break;
                    }
                }
                // Handle incoming messages from peer
                read_result = reader.read_line(&mut line) => {
                    match read_result {
                        Ok(0) => {
                            info!("Peer {} disconnected", current_peer_key);
                            break;
                        }
                        Ok(_) => {
                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                                // handle_message returns (real_id, peers_to_connect)
                                if let Ok((real_id, peers_to_connect)) = self.handle_message(&current_peer_key, msg).await {
                                    if let Some(id) = real_id {
                                        current_peer_key = id;
                                    }
                                    // Queue discovered peers for connection (spawned by listener)
                                    for (discovered_id, addr) in peers_to_connect {
                                        let _ = self.pending_connect_tx.send((discovered_id, addr)).await;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Read error from {}: {}", current_peer_key, e);
                            break;
                        }
                    }
                }
                // Forward broadcast floods to this peer
                flood_result = flood_rx.recv() => {
                    match flood_result {
                        Ok(FloodMessage::Peers(peers)) => {
                            let flood_msg = serde_json::json!({
                                "type": "flood_peers",
                                "peers": peers.into_iter().map(|(id, addr, slot, public_key)| {
                                    serde_json::json!({
                                        "id": id,
                                        "addr": addr,
                                        "slot": slot,
                                        "public_key": public_key.map(hex::encode),
                                    })
                                }).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::Admins(admins)) => {
                            let flood_msg = serde_json::json!({
                                "type": "flood_admins",
                                "admins": admins,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        // NOTE: Unsigned SlotClaim removed - use VdfSlotClaim only
                        Ok(FloodMessage::SporeHaveList { peer_id, slots }) => {
                            let flood_msg = serde_json::json!({
                                "type": "spore_have_list",
                                "peer_id": peer_id,
                                "slots": slots,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::VdfChain { links }) => {
                            let flood_msg = serde_json::json!({
                                "type": "vdf_chain",
                                "links": links.iter().map(|l| serde_json::json!({
                                    "height": l.height,
                                    "output": hex::encode(l.output),
                                    "producer": hex::encode(l.producer),
                                    "previous": hex::encode(l.previous),
                                    "timestamp_ms": l.timestamp_ms,
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::VdfSlotClaim { claim }) => {
                            let flood_msg = serde_json::json!({
                                "type": "vdf_slot_claim",
                                "slot": claim.slot,
                                "claimer": hex::encode(claim.claimer),
                                "vdf_height": claim.vdf_height,
                                "vdf_output": hex::encode(claim.vdf_output),
                                "signature": hex::encode(claim.signature),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLPing { from, nonce, vdf_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_ping",
                                "from": hex::encode(from),
                                "nonce": nonce,
                                "vdf_height": vdf_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLPong { from, nonce, vdf_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_pong",
                                "from": hex::encode(from),
                                "nonce": nonce,
                                "vdf_height": vdf_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLSwapProposal { proposal }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_swap_proposal",
                                "initiator": hex::encode(proposal.initiator),
                                "target": hex::encode(proposal.target),
                                "initiator_slot": proposal.initiator_slot,
                                "target_slot": proposal.target_slot,
                                "proposal_height": proposal.proposal_height,
                                "proposal_vdf_output": hex::encode(proposal.proposal_vdf_output),
                                "signature": hex::encode(proposal.signature),
                                "initiator_proofs": proposal.initiator_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                                "initiator_at_target_proofs": proposal.initiator_at_target_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLSwapResponse { response }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_swap_response",
                                "responder": hex::encode(response.responder),
                                "proposal_height": response.proposal_height,
                                "decision": match response.decision {
                                    crate::proof_of_latency::SwapDecision::Attack => "attack",
                                    crate::proof_of_latency::SwapDecision::Retreat => "retreat",
                                },
                                "response_height": response.response_height,
                                "signature": hex::encode(response.signature),
                                "target_proofs": response.target_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                                "target_at_initiator_proofs": response.target_at_initiator_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfAttestation { att, vouch }) => {
                            let flood_msg = Self::cvdf_attestation_json(&att, vouch.as_ref());
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfNewRound { round, spore_proof }) => {
                            let flood_msg =
                                Self::cvdf_round_json(&round, Some(spore_proof.range_count()));
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfSyncRequest { from_node, from_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_sync_request",
                                "from_node": from_node,
                                "from_height": from_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfSyncResponse { rounds, claims }) => {
                            // Serialize full chain data for proper sync
                            // Rounds contain attestations, claims carry the signed occupancy truth
                            let rounds_json: Vec<serde_json::Value> =
                                rounds.iter().map(|r| Self::cvdf_round_json(r, None)).collect();
                            let claims_json: Vec<serde_json::Value> = claims.iter().map(|claim| {
                                serde_json::json!({
                                    "slot": claim.slot,
                                    "claimer": hex::encode(claim.claimer),
                                    "vdf_height": claim.vdf_height,
                                    "vdf_output": hex::encode(claim.vdf_output),
                                    "signature": hex::encode(claim.signature),
                                })
                            }).collect();
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_sync_response",
                                "rounds": rounds_json,
                                "claims": claims_json,
                                "height": rounds.last().map(|r| r.round).unwrap_or(0),
                                "total_weight": rounds.iter().map(|r| r.weight() as u64).sum::<u64>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::ContentHaveList { peer_id, release_ids }) => {
                            let flood_msg = serde_json::json!({
                                "type": "content_have_list",
                                "peer_id": peer_id,
                                "release_ids": release_ids,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::Release { release_json }) => {
                            let flood_msg = serde_json::json!({
                                "type": "release_flood",
                                "release": serde_json::from_str::<serde_json::Value>(&release_json).unwrap_or_default(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::DoNotWantList { peer_id, do_not_want }) => {
                            // SPORE⁻¹: Send deletion ranges directly as Spore
                            let flood_msg = serde_json::json!({
                                "type": "do_not_want_list",
                                "peer_id": peer_id,
                                "ranges": do_not_want,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::ErasureConfirmation { peer_id, confirmed }) => {
                            // SPORE⁻¹: GDPR erasure confirmation with ranges
                            let flood_msg = serde_json::json!({
                                "type": "erasure_confirmation",
                                "peer_id": peer_id,
                                "ranges": confirmed,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::BadBits { double_hashes }) => {
                            // BadBits: PERMANENT blocklist (DMCA, abuse, illegal content)
                            let hashes_hex: Vec<String> = double_hashes.iter()
                                .map(|h| hex::encode(h))
                                .collect();
                            let flood_msg = serde_json::json!({
                                "type": "bad_bits",
                                "double_hashes": hashes_hex,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SporeSync { peer_id, have_list }) => {
                            // SPORE: Bilateral sync with range-based HaveList
                            // WantList = HaveList.complement() - derived by receiver
                            // Sync cost = O(|XOR difference|), converges to 0 at steady state
                            let flood_msg = serde_json::json!({
                                "type": "spore_sync",
                                "peer_id": peer_id,
                                "have_list": have_list,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PeerAddrSync { peer_id, have_list }) => {
                            let flood_msg = serde_json::json!({
                                "type": "peer_addr_sync",
                                "peer_id": peer_id,
                                "have_list": have_list,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SporeDelta { releases }) => {
                            // SPORE: Delta transfer - only send what they want that we have
                            let flood_msg = serde_json::json!({
                                "type": "spore_delta",
                                "releases": releases,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PeerAddrDelta { records }) => {
                            let flood_msg = serde_json::json!({
                                "type": "peer_addr_delta",
                                "records": records,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::FeaturedSync { peer_id, featured }) => {
                            // SPORE: Featured releases sync for homepage
                            let flood_msg = serde_json::json!({
                                "type": "featured_sync",
                                "peer_id": peer_id,
                                "featured": featured,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Err(_) => {
                            // Channel closed or lagged, continue
                        }
                    }
                }
            }
        }

        // Remove peer from the live mesh on disconnect.
        // A dead peer does not remain in the live peer set and cannot continue occupying a slot.
        {
            let still_active = {
                let mut active_peers = self.active_tcp_peers.write().await;
                match active_peers.get_mut(&current_peer_key) {
                    Some(count) if *count > 1 => {
                        *count -= 1;
                        true
                    }
                    Some(_) => {
                        active_peers.remove(&current_peer_key);
                        false
                    }
                    None => false,
                }
            };
            let mut state = self.state.write().await;
            let evicted = if still_active {
                if let Some(peer) = state.peers.get_mut(&current_peer_key) {
                    peer.last_seen = std::time::Instant::now();
                }
                Vec::new()
            } else {
                if let Some(_peer) = state.peers.remove(&current_peer_key) {
                    debug!("Peer {} disconnected and removed from live mesh", current_peer_key);
                }

                let stale_slots: Vec<u64> = state
                    .claimed_slots
                    .iter()
                    .filter_map(|(slot_idx, claim)| {
                        (claim.peer_id == current_peer_key).then_some(*slot_idx)
                    })
                    .collect();
                Self::evict_stale_slots_from_state(&mut state, &stale_slots)
            };

            // Clean up latency history for this peer to prevent memory leak
            // latency_history uses short peer IDs (first 8 chars after b3b3/)
            let short_peer = crate::api::short_peer_id(&current_peer_key);
            state.latency_history.remove(&short_peer);
            // Also remove any entries where this peer was the target
            for (_, targets) in state.latency_history.iter_mut() {
                targets.remove(&short_peer);
            }
            let should_retry_claim = state.self_slot.is_none();
            drop(state);

            for (slot_idx, peer_id) in evicted {
                info!(
                    "Evicted slot {} after peer {} disconnected from live mesh",
                    slot_idx, peer_id
                );
            }

            if should_retry_claim {
                debug!(
                    "Peer {} disconnected while slotless; re-entering slot claim path",
                    current_peer_key
                );
                self.try_claim_slot_from_live_state().await;
            }
        }

        Ok(())
    }

    /// Handle incoming message from peer
    /// Returns (real_peer_id, peers_to_connect) where:
    /// - real_peer_id: Some(id) if learned from hello (for re-keying)
    /// - peers_to_connect: Vec of (peer_id, addr) to connect to in background
    async fn handle_message(
        self: &Arc<Self>,
        peer_id: &str,
        msg: serde_json::Value,
    ) -> Result<(Option<String>, Vec<(String, SocketAddr)>)> {
        let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match msg_type {
            "hello" => {
                debug!("Received hello from {}: {:?}", peer_id, msg);
                // Re-key peer entry with the canonical PeerID and store public key metadata.
                if let Some(node_id) = msg.get("node_id").and_then(|n| n.as_str()) {
                    // Extract public key from hello (hex-encoded ed25519 public key)
                    let public_key = msg
                        .get("public_key")
                        .and_then(|p| p.as_str())
                        .and_then(|hex_str| hex::decode(hex_str).ok());

                    // Treat the peer's advertised address as an underlay hint that can be fed
                    // back into Ygg peer resolution. We only fall back to the transport socket
                    // when the peer didn't give us anything usable.
                    let advertised_addr = msg
                        .get("addr")
                        .and_then(|a| a.as_str())
                        .and_then(|addr_str| addr_str.parse::<SocketAddr>().ok());
                    let advertised_addr = advertised_addr.filter(|addr| {
                        !(addr.ip().is_unspecified() || addr.ip().is_loopback())
                    });
                    let advertised_port = advertised_addr.map(|addr| addr.port());

                    // Learn our public IP from what the peer sees us as (STUN-like)
                    let their_view_of_us = msg
                        .get("your_addr")
                        .and_then(|a| a.as_str())
                        .and_then(|addr_str| addr_str.parse::<SocketAddr>().ok());
                    let yggdrasil_addr = msg
                        .get("yggdrasil_addr")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    let underlay_uri = msg
                        .get("underlay_uri")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    let ygg_peer_uri = msg
                        .get("ygg_peer_uri")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);

                    let mut state = self.state.write().await;

                    // Update our observed public address if peer told us what they see
                    if let Some(observed) = their_view_of_us {
                        if state.observed_public_addr.is_none() {
                            // Use our listen port, but the IP the peer sees
                            let public_addr =
                                SocketAddr::new(observed.ip(), self.listen_addr.port());
                            info!("Learned our public IP from {}: {}", peer_id, public_addr);
                            state.observed_public_addr = Some(public_addr);
                        }
                    }
                    // Remove temporary peer-{addr} entry and merge it into the canonical peer ID.
                    // Multiple sockets can race to the same peer; we keep the canonical peer
                    // state and simply move this connection's liveness accounting over to it.
                    if let Some(mut peer) = state.peers.remove(peer_id) {
                        if node_id != state.self_id {
                            let canonical_id = node_id.to_string();
                            let merged_addr = advertised_addr.unwrap_or_else(|| {
                                SocketAddr::new(
                                    peer.addr.ip(),
                                    advertised_port.unwrap_or(peer.addr.port()),
                                )
                            });

                            if let Some(existing_peer) = state.peers.get_mut(&canonical_id) {
                                if Self::should_refresh_peer_hint(existing_peer.addr, merged_addr) {
                                    existing_peer.addr = merged_addr;
                                }
                                if existing_peer.yggdrasil_addr.is_none() && yggdrasil_addr.is_some() {
                                    existing_peer.yggdrasil_addr = yggdrasil_addr.clone();
                                }
                                if existing_peer.underlay_uri.is_none() && underlay_uri.is_some() {
                                    existing_peer.underlay_uri = underlay_uri.clone();
                                }
                                if existing_peer.ygg_peer_uri.is_none() && ygg_peer_uri.is_some() {
                                    existing_peer.ygg_peer_uri = ygg_peer_uri.clone();
                                }
                                if existing_peer.public_key.is_none() && public_key.is_some() {
                                    existing_peer.public_key = public_key.clone();
                                }
                                existing_peer.last_seen = std::time::Instant::now();
                                existing_peer.is_entry_peer |= peer.is_entry_peer;
                            } else {
                                peer.id = canonical_id.clone();
                                peer.yggdrasil_addr = yggdrasil_addr;
                                peer.underlay_uri = underlay_uri;
                                peer.ygg_peer_uri = ygg_peer_uri;
                                peer.public_key = public_key;
                                peer.addr = merged_addr;
                                peer.last_seen = std::time::Instant::now();
                                let peer_addr = peer.addr;
                                state.peers.insert(canonical_id.clone(), peer);
                                info!(
                                    "Peer {} identified as {} at {}",
                                    peer_id, canonical_id, peer_addr
                                );
                            }

                            if let Some(stored_peer) = state.peers.get(&canonical_id).cloned() {
                                let _ = state.peer_addr_store.insert(
                                    PeerAddrRecord::from_mesh_peer(&stored_peer, Self::now_ms()),
                                );
                            }

                            let should_start_claim = state.self_slot.is_none();
                            drop(state);

                            self.rekey_active_peer(peer_id, &canonical_id).await;
                            if should_start_claim {
                                self.trigger_slot_claim_if_ready();
                            }

                            return Ok((Some(canonical_id), vec![]));
                        }
                    }
                }
            }
            "flood_admins" | "sync_admins" => {
                // Merge flooded admin list into our state
                if let Some(admins) = msg.get("admins").and_then(|a| a.as_array()) {
                    for admin in admins {
                        if let Some(key) = admin.as_str() {
                            let key = key.trim();
                            // Skip malformed combo strings from old nodes
                            if key.contains(',') {
                                continue;
                            }
                            // Accept ed25519p/... (prefix + 64 hex) or raw 64 hex
                            let valid = if let Some(hex) = key.strip_prefix("ed25519p/") {
                                hex.len() == 64
                            } else {
                                key.len() == 64
                            };
                            if valid {
                                // Only log if this is a NEW admin (deduplication)
                                let is_new = !self.storage.is_admin(key).unwrap_or(true);
                                if is_new {
                                    let _ = self.storage.set_admin(key, true);
                                    info!("Merged admin from {}: {}", peer_id, key);
                                }
                            }
                        }
                    }
                }
            }
            "flood_peers" | "sync_peers" => {
                // Merge flooded peer list - this propagates mesh topology
                // SPORE: only accept real peer IDs, skip those we already know
                // Parse peer data OUTSIDE the lock to minimize lock hold time
                let parsed_peers: Vec<_> = msg
                    .get("peers")
                    .and_then(|p| p.as_array())
                    .map(|peers| {
                        peers
                            .iter()
                            .filter_map(|peer_info| {
                                let id = peer_info.get("id").and_then(|i| i.as_str())?;
                                let addr_str = peer_info.get("addr").and_then(|a| a.as_str())?;
                                // SPORE: only accept real peer IDs (b3b3/...)
                                if !id.starts_with("b3b3/") {
                                    return None;
                                }
                                let slot_index = peer_info.get("slot").and_then(|s| s.as_u64());
                                let public_key = peer_info
                                    .get("public_key")
                                    .and_then(|p| p.as_str())
                                    .and_then(|hex_str| hex::decode(hex_str).ok());
                                let yggdrasil_addr = peer_info
                                    .get("yggdrasil_addr")
                                    .and_then(|v| v.as_str())
                                    .map(ToOwned::to_owned);
                                let underlay_uri = peer_info
                                    .get("underlay_uri")
                                    .and_then(|v| v.as_str())
                                    .map(ToOwned::to_owned);
                                let ygg_peer_uri = peer_info
                                    .get("ygg_peer_uri")
                                    .and_then(|v| v.as_str())
                                    .map(ToOwned::to_owned);
                                let addr: SocketAddr = addr_str.parse().ok()?;
                                if !Self::is_usable_peer_addr(addr) {
                                    return None;
                                }
                                Some((
                                    id.to_string(),
                                    addr_str.to_string(),
                                    addr,
                                    slot_index,
                                    public_key,
                                    yggdrasil_addr,
                                    underlay_uri,
                                    ygg_peer_uri,
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Now acquire lock briefly to update state
                let mut new_peers: Vec<(String, String, Option<u64>, Option<Vec<u8>>)> =
                    Vec::new();
                if !parsed_peers.is_empty() {
                    let mut state = self.state.write().await;
                    for (
                        id,
                        addr_str,
                        addr,
                        slot_index,
                        public_key,
                        yggdrasil_addr,
                        underlay_uri,
                        ygg_peer_uri,
                    ) in parsed_peers
                    {
                        // Don't add ourselves. Known peers may still need a refreshed underlay
                        // hint if the peer has told the mesh about a better clue for Ygg routing.
                        if id == state.self_id {
                            continue;
                        }

                        if let Some(existing_peer) = state.peers.get_mut(&id) {
                            if Self::should_refresh_peer_hint(existing_peer.addr, addr) {
                                debug!(
                                    "Refreshing peer {} route hint via flood: {} -> {}",
                                    id, existing_peer.addr, addr
                                );
                                existing_peer.addr = addr;
                            }
                            if existing_peer.yggdrasil_addr.is_none() && yggdrasil_addr.is_some() {
                                existing_peer.yggdrasil_addr = yggdrasil_addr.clone();
                            }
                            if existing_peer.underlay_uri.is_none() && underlay_uri.is_some() {
                                existing_peer.underlay_uri = underlay_uri.clone();
                            }
                            if existing_peer.ygg_peer_uri.is_none() && ygg_peer_uri.is_some() {
                                existing_peer.ygg_peer_uri = ygg_peer_uri.clone();
                            }
                            if existing_peer.public_key.is_none() && public_key.is_some() {
                                existing_peer.public_key = public_key.clone();
                            }
                            continue;
                        }

                        if let Some(idx) = slot_index {
                            if !state.claimed_slots.contains_key(&idx) {
                                let claim =
                                    SlotClaim::with_public_key(idx, id.clone(), public_key.clone());
                                state.slot_coords.insert(claim.coord);
                                state.claimed_slots.insert(idx, claim);
                            }
                        }
                        debug!(
                            "Ignoring indirect flood-only peer {} at {} from {}; peer-addr sync handles dialable peer discovery",
                            id, addr_str, peer_id
                        );
                    }
                }
                // Re-flood newly discovered peers to propagate through mesh
                if !new_peers.is_empty() {
                    // Get our slot's neighbor coordinates (if we have a slot)
                    // TOPOLOGY FIX: Only connect to spiral neighbors, not full mesh!
                    let our_neighbor_coords: Option<Vec<HexCoord>> = {
                        let state = self.state.read().await;
                        state
                            .self_slot
                            .as_ref()
                            .map(|slot| Neighbors::of(slot.coord).to_vec())
                    };

                    // Collect addresses to connect - ONLY spiral neighbors (or all if no slot yet)
                    let peers_to_connect: Vec<(String, SocketAddr)> = new_peers
                        .iter()
                        .filter_map(|(peer_id, addr_str, slot_opt, _)| {
                            let addr: SocketAddr = addr_str.parse().ok()?;

                            // If we don't have a slot yet, accept any connection for bootstrapping
                            let Some(ref neighbor_coords) = our_neighbor_coords else {
                                return Some((peer_id.clone(), addr));
                            };

                            // Only connect if this peer's slot is one of our spiral neighbors
                            if let Some(their_slot_idx) = slot_opt {
                                let their_coord =
                                    spiral3d_to_coord(Spiral3DIndex::new(*their_slot_idx));
                                if neighbor_coords.contains(&their_coord) {
                                    return Some((peer_id.clone(), addr));
                                }
                            }

                            // Not a neighbor - don't connect
                            None
                        })
                        .collect();

                    self.flood(FloodMessage::Peers(new_peers));

                    // Return peers to connect - caller will spawn connections
                    if !peers_to_connect.is_empty() {
                        return Ok((None, peers_to_connect));
                    }
                }
                // Note: No bootstrap sync signal needed - CVDF swarm merge handles everything.
                // When we receive heavier chains, we adopt them automatically.
            }
            // NOTE: Unsigned "slot_claim" and "slot_validation" handlers REMOVED.
            // They had no signature, so anyone could forge claims for any peer.
            // Use "vdf_slot_claim" instead - it has VDF height for ordering and signature for auth.
            "spore_have_list" => {
                // SPORE: Compare their HaveList with ours and send missing slots
                if let Some(their_slots) = msg.get("slots").and_then(|s| s.as_array()) {
                    let their_slots: std::collections::HashSet<u64> =
                        their_slots.iter().filter_map(|v| v.as_u64()).collect();

                    let state = self.state.read().await;

                    // Find slots we have that they don't
                    let mut missing_slots = Vec::new();
                    for (index, claim) in &state.claimed_slots {
                        if !their_slots.contains(index) {
                            missing_slots.push(claim.clone());
                        }
                    }
                    drop(state);

                    // Send missing slots to this peer via VDF claims
                    if !missing_slots.is_empty() {
                        info!(
                            "SPORE: Peer missing {} slots - they'll sync via VdfSlotClaim",
                            missing_slots.len()
                        );
                        // NOTE: We don't re-flood unsigned claims. Peers sync slots via:
                        // 1. VdfSlotClaim floods (signed, with VDF height)
                        // 2. CvdfSyncResponse (contains all slots with pubkeys)
                        // This prevents the oscillation bug from unsigned claim re-flooding.
                    }
                }
            }
            "vdf_chain" => {
                // VDF chain sync - try to adopt longer chain
                if let Some(links_arr) = msg.get("links").and_then(|l| l.as_array()) {
                    let mut links = Vec::new();
                    for link_json in links_arr {
                        if let (
                            Some(height),
                            Some(output_hex),
                            Some(producer_hex),
                            Some(previous_hex),
                            Some(timestamp_ms),
                        ) = (
                            link_json.get("height").and_then(|h| h.as_u64()),
                            link_json.get("output").and_then(|o| o.as_str()),
                            link_json.get("producer").and_then(|p| p.as_str()),
                            link_json.get("previous").and_then(|p| p.as_str()),
                            link_json.get("timestamp_ms").and_then(|t| t.as_u64()),
                        ) {
                            if let (Ok(output), Ok(producer), Ok(previous)) = (
                                hex::decode(output_hex),
                                hex::decode(producer_hex),
                                hex::decode(previous_hex),
                            ) {
                                if output.len() == 32
                                    && producer.len() == 32
                                    && previous.len() == 32
                                {
                                    let mut output_arr = [0u8; 32];
                                    let mut producer_arr = [0u8; 32];
                                    let mut previous_arr = [0u8; 32];
                                    output_arr.copy_from_slice(&output);
                                    producer_arr.copy_from_slice(&producer);
                                    previous_arr.copy_from_slice(&previous);

                                    links.push(VdfLink {
                                        height,
                                        output: output_arr,
                                        producer: producer_arr,
                                        previous: previous_arr,
                                        timestamp_ms,
                                    });
                                }
                            }
                        }
                    }

                    if !links.is_empty() {
                        let their_height = links.last().map(|l| l.height).unwrap_or(0);
                        let our_height = self.vdf_height().await;
                        debug!(
                            "Received VDF chain from {}: height {} (ours: {})",
                            peer_id, their_height, our_height
                        );

                        // Try to adopt if longer
                        if self.try_adopt_vdf_chain(links.clone()).await {
                            info!(
                                "Adopted VDF chain from {} (new height: {})",
                                peer_id, their_height
                            );
                            // Re-flood to propagate
                            self.flood(FloodMessage::VdfChain { links });
                        }
                    }
                }
            }
            "vdf_slot_claim" => {
                // VDF-anchored slot claim with priority ordering
                if let (
                    Some(slot),
                    Some(claimer_hex),
                    Some(vdf_height),
                    Some(vdf_output_hex),
                    Some(signature_hex),
                ) = (
                    msg.get("slot").and_then(|s| s.as_u64()),
                    msg.get("claimer").and_then(|c| c.as_str()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                    msg.get("vdf_output").and_then(|o| o.as_str()),
                    msg.get("signature").and_then(|s| s.as_str()),
                ) {
                    if let (Ok(claimer), Ok(vdf_output), Ok(signature)) = (
                        hex::decode(claimer_hex),
                        hex::decode(vdf_output_hex),
                        hex::decode(signature_hex),
                    ) {
                        if claimer.len() == 32 && vdf_output.len() == 32 && signature.len() == 64 {
                            let mut claimer_arr = [0u8; 32];
                            let mut vdf_output_arr = [0u8; 32];
                            let mut signature_arr = [0u8; 64];
                            claimer_arr.copy_from_slice(&claimer);
                            vdf_output_arr.copy_from_slice(&vdf_output);
                            signature_arr.copy_from_slice(&signature);

                            let claim = AnchoredSlotClaim {
                                slot,
                                claimer: claimer_arr,
                                vdf_height,
                                vdf_output: vdf_output_arr,
                                signature: signature_arr,
                            };

                            debug!(
                                "Received VDF slot claim from {}: slot {} at height {}",
                                peer_id, slot, vdf_height
                            );

                            // Process with priority ordering
                            if self.process_vdf_claim(claim.clone()).await {
                                // Re-flood winning claim
                                self.flood(FloodMessage::VdfSlotClaim { claim });
                            }
                        }
                    }
                }
            }
            "pol_ping" => {
                // Proof of Latency ping - respond with pong for RTT measurement
                if let (Some(from_hex), Some(nonce), Some(vdf_height)) = (
                    msg.get("from").and_then(|f| f.as_str()),
                    msg.get("nonce").and_then(|n| n.as_u64()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                ) {
                    if let Ok(from) = hex::decode(from_hex) {
                        if from.len() == 32 {
                            let mut from_arr = [0u8; 32];
                            from_arr.copy_from_slice(&from);
                            debug!("Received PoL ping from {}, nonce {}", peer_id, nonce);

                            // Respond with pong using our public key
                            let state = self.state.read().await;
                            let our_pubkey = state.signing_key.verifying_key().to_bytes();
                            drop(state);

                            self.flood(FloodMessage::PoLPong {
                                from: our_pubkey,
                                nonce,
                                vdf_height,
                            });
                        }
                    }
                }
            }
            "pol_pong" => {
                // Proof of Latency pong - complete latency measurement
                if let (Some(from_hex), Some(nonce), Some(vdf_height)) = (
                    msg.get("from").and_then(|f| f.as_str()),
                    msg.get("nonce").and_then(|n| n.as_u64()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                ) {
                    if let Ok(from) = hex::decode(from_hex) {
                        if from.len() == 32 {
                            let mut from_arr = [0u8; 32];
                            from_arr.copy_from_slice(&from);

                            // Check if this pong is for one of our pending pings
                            let mut state = self.state.write().await;
                            if let Some(target) = state.pol_pending_pings.remove(&nonce) {
                                if target == from_arr {
                                    // Complete the latency measurement in PoL manager
                                    // Get VDF output from chain tip
                                    let vdf_output = state
                                        .vdf_race
                                        .as_ref()
                                        .and_then(|v| v.chain_links().last())
                                        .map(|l| l.output)
                                        .unwrap_or([0u8; 32]);

                                    if let Some(ref mut pol) = state.pol_manager {
                                        if let Some(proof) =
                                            pol.complete_ping(from_arr, vdf_height, vdf_output)
                                        {
                                            let latency_ms = proof.latency_us / 1000;
                                            debug!(
                                                "PoL: measured latency to {} = {}ms",
                                                peer_id, latency_ms
                                            );

                                            // Record latency in history for map visualization
                                            let self_id = state.self_id.clone();
                                            let short_self = crate::api::short_peer_id(&self_id);
                                            let short_peer = crate::api::short_peer_id(&peer_id);
                                            state.record_latency(
                                                &short_self,
                                                &short_peer,
                                                latency_ms,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "pol_swap_proposal" => {
                // Proof of Latency swap proposal - check if we should accept
                debug!("Received PoL swap proposal from {}", peer_id);
                // Full implementation would parse the proposal and call pol_manager.process_proposal()
                // For now, log and skip - swap handling requires bidirectional communication
            }
            "pol_swap_response" => {
                // Proof of Latency swap response - process decision
                debug!("Received PoL swap response from {}", peer_id);
                // Full implementation would parse the response and call pol_manager.process_response()
                // For now, log and skip - swap handling requires bidirectional communication
            }
            // ==================== CVDF MESSAGE HANDLERS ====================
            "cvdf_attestation" => {
                // Parse attestation and process it
                if let Some(att) = Self::parse_cvdf_attestation_json(&msg) {
                    if self.cvdf_process_attestation(att.clone()).await {
                        debug!(
                            "Processed CVDF attestation for round {} from {}",
                            att.round, peer_id
                        );
                    }

                    // Handle piggybacked vouch (2-hop propagation)
                    if let Some(vouch_data) = msg.get("vouch") {
                        if let (
                            Some(voucher_hex),
                            Some(voucher_slot),
                            Some(alive_neighbors),
                            Some(vdf_height),
                            Some(vouch_sig_hex),
                        ) = (
                            vouch_data.get("voucher").and_then(|v| v.as_str()),
                            vouch_data.get("voucher_slot").and_then(|v| v.as_u64()),
                            vouch_data.get("alive_neighbors").and_then(|v| v.as_array()),
                            vouch_data.get("vdf_height").and_then(|v| v.as_u64()),
                            vouch_data.get("signature").and_then(|v| v.as_str()),
                        ) {
                            if let (Ok(voucher), Ok(vouch_sig)) =
                                (hex::decode(voucher_hex), hex::decode(vouch_sig_hex))
                            {
                                if voucher.len() == 32 && vouch_sig.len() == 64 {
                                    let mut alive: Vec<[u8; 32]> = Vec::new();
                                    for n in alive_neighbors {
                                        if let Some(n_hex) = n.as_str() {
                                            if let Ok(n_bytes) = hex::decode(n_hex) {
                                                if n_bytes.len() == 32 {
                                                    alive.push(n_bytes.try_into().unwrap());
                                                }
                                            }
                                        }
                                    }

                                    let latencies = vouch_data
                                        .get("latencies")
                                        .and_then(|l| l.as_array())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|item| {
                                                    let node =
                                                        hex::decode(item.get("node")?.as_str()?).ok()?;
                                                    let latency = item.get("latency_ms")?.as_u64()?;
                                                    if node.len() == 32 {
                                                        Some((node.try_into().unwrap(), latency))
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                        })
                                        .unwrap_or_default();

                                    let vouch = MeshVouch {
                                        voucher: voucher.try_into().unwrap(),
                                        voucher_slot,
                                        alive_neighbors: alive,
                                        vdf_height,
                                        latencies,
                                        signature: vouch_sig.try_into().unwrap(),
                                    };

                                    match self.handle_mesh_vouch(vouch.clone()).await {
                                        PropagationDecision::ForwardToNeighbors => {
                                            debug!("Vouch judges me - forwarding to witnesses");
                                            self.flood(FloodMessage::CvdfAttestation {
                                                att,
                                                vouch: Some(vouch),
                                            });
                                        }
                                        PropagationDecision::Stop => {
                                            debug!("Vouch witnessed for neighbor - stopping");
                                        }
                                        PropagationDecision::Drop => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "cvdf_new_round" => {
                if let Some(round) = Self::parse_cvdf_round_json(&msg) {
                    let round_number = round.round;
                    if self.cvdf_process_round(round).await {
                        debug!("Processed cvdf_new_round {} from {}", round_number, peer_id);
                    }
                }
            }
            "cvdf_sync_request" => {
                // Respond with our chain state
                if let Some(from_height) = msg.get("from_height").and_then(|h| h.as_u64()) {
                    debug!(
                        "Received CVDF sync request from {} (from_height {})",
                        peer_id, from_height
                    );
                    // Send our chain state via flood
                    if let Some((rounds, claims)) = self.cvdf_chain_state().await {
                        self.flood(FloodMessage::CvdfSyncResponse { rounds, claims });
                    }
                }
            }
            "cvdf_sync_response" => {
                // Parse chain data, adopt if heavier, process slots with tiebreaker
                debug!("Received CVDF sync response from {}", peer_id);

                // Parse rounds
                let mut parsed_rounds: Vec<CvdfRound> = Vec::new();
                if let Some(rounds_arr) = msg.get("rounds").and_then(|r| r.as_array()) {
                    for round_json in rounds_arr {
                        if let Some(round) = Self::parse_cvdf_round_json(round_json) {
                            parsed_rounds.push(round);
                        }
                    }
                }

                // Parse signed VDF claims
                let mut parsed_claims: Vec<AnchoredSlotClaim> = Vec::new();
                if let Some(claims_arr) = msg.get("claims").and_then(|s| s.as_array()) {
                    for claim_json in claims_arr {
                        if let (
                            Some(slot),
                            Some(claimer_hex),
                            Some(vdf_height),
                            Some(vdf_output_hex),
                            Some(signature_hex),
                        ) = (
                            claim_json.get("slot").and_then(|s| s.as_u64()),
                            claim_json.get("claimer").and_then(|p| p.as_str()),
                            claim_json.get("vdf_height").and_then(|h| h.as_u64()),
                            claim_json.get("vdf_output").and_then(|o| o.as_str()),
                            claim_json.get("signature").and_then(|s| s.as_str()),
                        ) {
                            if let (Ok(claimer), Ok(vdf_output), Ok(signature)) = (
                                hex::decode(claimer_hex),
                                hex::decode(vdf_output_hex),
                                hex::decode(signature_hex),
                            ) {
                                if claimer.len() == 32 && vdf_output.len() == 32 && signature.len() == 64 {
                                    let mut claimer_arr = [0u8; 32];
                                    let mut vdf_output_arr = [0u8; 32];
                                    let mut signature_arr = [0u8; 64];
                                    claimer_arr.copy_from_slice(&claimer);
                                    vdf_output_arr.copy_from_slice(&vdf_output);
                                    signature_arr.copy_from_slice(&signature);
                                    parsed_claims.push(AnchoredSlotClaim {
                                        slot,
                                        claimer: claimer_arr,
                                        vdf_height,
                                        vdf_output: vdf_output_arr,
                                        signature: signature_arr,
                                    });
                                }
                            }
                        }
                    }
                }

                let mut chain_state_changed = false;

                // Check if we should adopt this chain.
                // Even when we do NOT adopt, we still need to reconcile slot holders below.
                if !parsed_rounds.is_empty() && self.cvdf_should_adopt(&parsed_rounds).await {
                    let their_height = parsed_rounds.last().map(|r| r.round).unwrap_or(0);
                    let their_weight: u64 = parsed_rounds.iter().map(|r| r.weight() as u64).sum();
                    info!(
                        "Adopting heavier CVDF chain from {} (height {}, weight {})",
                        peer_id, their_height, their_weight
                    );

                    if self.cvdf_adopt(parsed_rounds).await {
                        chain_state_changed = true;
                    }
                }

                // Reconcile advertised signed claims regardless of whether the chain itself was adopted.
                // Equal-weight peers still need to converge on the same live occupancy set.
                if !parsed_claims.is_empty() {
                    let mut we_lost_our_slot = false;
                    let mut saw_slot_change = chain_state_changed;

                    for claim in &parsed_claims {
                        self.cvdf_register_slot(claim.slot, claim.claimer).await;

                        let had_slot = self.has_claimed_slot().await;
                        if self.process_vdf_claim(claim.clone()).await {
                            saw_slot_change = true;
                            self.flood(FloodMessage::VdfSlotClaim { claim: claim.clone() });
                        }
                        let has_slot = self.has_claimed_slot().await;
                        if had_slot && !has_slot {
                            we_lost_our_slot = true;
                            saw_slot_change = true;
                        }
                    }

                    if we_lost_our_slot {
                        info!("Lost slot during CVDF sync reconciliation - triggering reclaim");
                    }

                    // EVENT: CVDF sync taught us about live topology state.
                    // Per FailureDetectorElimination.lean, this is a valid trigger event.
                    if saw_slot_change {
                        self.trigger_slot_claim_if_ready();
                    }
                }
            }
            // ==================== END CVDF MESSAGE HANDLERS ====================
            // NOTE: TGP messages are now handled over UDP, not TCP
            // See run_tgp_udp_listener() and handle_tgp_message()

            // ==================== SPORE CONTENT SYNC HANDLERS ====================
            // NOTE: Legacy "content_have_list" removed - use "spore_sync" for O(|XOR diff|) sync
            // The old handler did O(n²) comparisons; SPORE uses range-based set operations
            "release_flood" => {
                // Receive a release flooded through the mesh
                if let Some(release_data) = msg.get("release") {
                    // Try to parse as Release
                    if let Ok(release) =
                        serde_json::from_value::<crate::models::Release>(release_data.clone())
                    {
                        // SPORE⁻¹: Check if this release is in our DoNotWantList (tombstoned)
                        let tombstone = double_hash_id(&release.id);
                        let is_tombstoned = self.state.read().await.is_tombstoned(&tombstone);

                        if is_tombstoned {
                            debug!(
                                "SPORE: Ignoring tombstoned release {} (in DoNotWantList)",
                                release.id
                            );
                        } else {
                            // Use DocumentStore for CRDT merge (automatic LWW based on modified_at)
                            let mut doc_store = self.doc_store.write().await;
                            match doc_store.put(&release) {
                                Ok((_, changed)) => {
                                    if changed {
                                        info!(
                                            "SPORE: Merged release {} from mesh (CRDT)",
                                            release.id
                                        );

                                        // SPORE: Broadcast updated HaveList so peers know our new state
                                        // This enables continuous sync as our state changes
                                        if let Ok(all_releases) =
                                            doc_store.list::<crate::models::Release>()
                                        {
                                            let self_id = self.state.read().await.self_id.clone();
                                            let release_ids: Vec<String> =
                                                all_releases.iter().map(|r| r.id.clone()).collect();
                                            let have_list = build_spore_havelist(&release_ids);
                                            self.flood(FloodMessage::SporeSync {
                                                peer_id: self_id,
                                                have_list,
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to merge flooded release {}: {:?}",
                                        release.id, e
                                    );
                                }
                            }
                        }
                    }
                }
            }
            "spore_sync" => {
                // SPORE: Receive peer's HaveList (range-based)
                // Their WantList = their_have.complement()
                if let Some(have_list_value) = msg.get("have_list") {
                    if let Ok(their_have) = serde_json::from_value::<Spore>(have_list_value.clone())
                    {
                        // Compute their WantList (what they don't have)
                        let their_want = their_have.complement();

                        // Build our HaveList from doc_store
                        let doc_store = self.doc_store.read().await;
                        let our_releases = doc_store
                            .list::<crate::models::Release>()
                            .unwrap_or_default();
                        let our_release_ids: Vec<String> =
                            our_releases.iter().map(|r| r.id.clone()).collect();
                        let our_have = build_spore_havelist(&our_release_ids);

                        // Compute what we should send: our_have ∩ their_want
                        let to_send = our_have.intersect(&their_want);

                        // Store their HaveList for future reference
                        {
                            let mut state = self.state.write().await;
                            if let Some(peer) = state.peers.get_mut(peer_id) {
                                peer.their_have = Some(their_have.clone());
                                // Check if we have all their content
                                let our_want = our_have.complement();
                                let we_need = their_have.intersect(&our_want);
                                peer.content_synced = we_need.is_empty();
                                if peer.content_synced {
                                    info!("SPORE: Fully synced with peer {} (their content ⊆ our content)", peer_id);
                                }
                            }
                        }

                        // If we have releases they want, send them as delta
                        if !to_send.is_empty() {
                            // Find which releases match the to_send ranges
                            let releases_to_send: Vec<String> = our_releases
                                .iter()
                                .filter(|r| {
                                    let hash = release_id_to_u256(&r.id);
                                    to_send.covers(&hash)
                                })
                                .filter_map(|r| serde_json::to_string(r).ok())
                                .collect();

                            if !releases_to_send.is_empty() {
                                info!(
                                    "SPORE: Sending {} releases to peer {} (delta transfer)",
                                    releases_to_send.len(),
                                    peer_id
                                );
                                self.flood(FloodMessage::SporeDelta {
                                    releases: releases_to_send,
                                });
                            }
                        }
                        // NOTE: Don't send HaveList back here - we already send on connection
                        // Sending here would create infinite feedback loop
                    }
                }
            }
            "peer_addr_sync" => {
                if let Some(have_list_value) = msg.get("have_list") {
                    if let Ok(their_have) = serde_json::from_value::<Spore>(have_list_value.clone())
                    {
                        let records_to_send = {
                            let mut state = self.state.write().await;
                            if let Some(peer) = state.peers.get_mut(peer_id) {
                                peer.their_peer_addr_have = Some(their_have.clone());
                            }
                            state.peer_addr_store.diff_for_peer(&their_have)
                        };

                        if !records_to_send.is_empty() {
                            info!(
                                "PEER-ADDR: Sending {} address records to peer {}",
                                records_to_send.len(),
                                peer_id
                            );
                            self.flood(FloodMessage::PeerAddrDelta {
                                records: records_to_send,
                            });
                        }
                    }
                }
            }
            "peer_addr_delta" => {
                if let Some(records_value) = msg.get("records").and_then(|r| r.as_array()) {
                    let mut records = Vec::new();
                    for record_value in records_value {
                        if let Ok(record) =
                            serde_json::from_value::<PeerAddrRecord>(record_value.clone())
                        {
                            records.push(record);
                        }
                    }

                    if !records.is_empty() {
                        let peers_to_connect = self.merge_peer_addr_records(records).await;
                        if !peers_to_connect.is_empty() {
                            return Ok((None, peers_to_connect));
                        }
                    }
                }
            }
            "spore_delta" => {
                // SPORE: Receive delta transfer - releases we were missing
                if let Some(releases_value) = msg.get("releases").and_then(|r| r.as_array()) {
                    let mut stored_count = 0;
                    let mut doc_store = self.doc_store.write().await;

                    for release_json in releases_value {
                        if let Some(json_str) = release_json.as_str() {
                            if let Ok(release) =
                                serde_json::from_str::<crate::models::Release>(json_str)
                            {
                                // SPORE⁻¹: Check tombstone
                                let tombstone = double_hash_id(&release.id);
                                let is_tombstoned =
                                    self.state.read().await.is_tombstoned(&tombstone);

                                if is_tombstoned {
                                    debug!(
                                        "SPORE: Ignoring tombstoned release {} from delta",
                                        release.id
                                    );
                                } else {
                                    // Use DocumentStore for CRDT merge
                                    match doc_store.put(&release) {
                                        Ok((_, changed)) => {
                                            if changed {
                                                stored_count += 1;
                                            }
                                        }
                                        Err(e) => {
                                            warn!(
                                                "SPORE: Failed to merge delta release {}: {:?}",
                                                release.id, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if stored_count > 0 {
                        info!(
                            "SPORE: Merged {} releases from delta transfer (CRDT)",
                            stored_count
                        );
                        // NOTE: Don't broadcast HaveList here - would cause feedback loop
                        // HaveLists are exchanged on connection, not on every state change
                    }
                }
            }
            "do_not_want_list" => {
                // SPORE⁻¹: Receive DoNotWantList (deletion ranges) from peer
                // Uses Spore (range-based) for O(|diff|) → 0 convergence
                if let Some(ranges_value) = msg.get("ranges") {
                    if let Ok(their_do_not_want) =
                        serde_json::from_value::<Spore>(ranges_value.clone())
                    {
                        // Compute XOR to find new deletions we didn't know about
                        let our_do_not_want = self.state.read().await.do_not_want_spore().clone();
                        let diff = their_do_not_want.subtract(&our_do_not_want);

                        if !diff.is_empty() {
                            info!(
                                "SPORE⁻¹: Received {} new deletion ranges from peer {}",
                                diff.range_count(),
                                peer_id
                            );

                            // Merge their deletions into ours
                            let self_id = {
                                let mut state = self.state.write().await;
                                state.merge_do_not_want(&their_do_not_want);
                                state.self_id.clone()
                            };

                            // Delete any releases we have that are now tombstoned
                            let mut doc_store = self.doc_store.write().await;
                            if let Ok(releases) = doc_store.list::<crate::models::Release>() {
                                for release in releases {
                                    let tombstone = double_hash_id(&release.id);
                                    if self.state.read().await.is_tombstoned(&tombstone) {
                                        let content_id =
                                            citadel_crdt::ContentId::hash(release.id.as_bytes());
                                        if let Err(e) =
                                            doc_store.delete::<crate::models::Release>(&content_id)
                                        {
                                            warn!(
                                                "Failed to delete tombstoned release {}: {:?}",
                                                release.id, e
                                            );
                                        } else {
                                            info!(
                                                "SPORE⁻¹: Deleted tombstoned release {}",
                                                release.id
                                            );
                                        }
                                    }
                                }
                            }
                            drop(doc_store);

                            // Update our erasure_confirmed with the new ranges
                            // This confirms we've processed the deletion request
                            {
                                let mut state = self.state.write().await;
                                state.erasure_confirmed = state.erasure_confirmed.union(&diff);
                            }

                            // Re-flood our updated do_not_want to propagate through mesh
                            let updated_do_not_want =
                                self.state.read().await.do_not_want_spore().clone();
                            self.flood(FloodMessage::DoNotWantList {
                                peer_id: self_id.clone(),
                                do_not_want: updated_do_not_want,
                            });

                            // GDPR: Send erasure confirmation - we've processed these deletions
                            let confirmed = self.state.read().await.erasure_confirmed.clone();
                            self.flood(FloodMessage::ErasureConfirmation {
                                peer_id: self_id,
                                confirmed,
                            });
                        }
                    }
                }
            }
            "erasure_confirmation" => {
                // SPORE⁻¹: Receive erasure confirmation (ranges) from peer
                // Track which deletion ranges this peer has confirmed processing
                if let Some(ranges_value) = msg.get("ranges") {
                    if let Ok(their_confirmed) =
                        serde_json::from_value::<Spore>(ranges_value.clone())
                    {
                        let mut state = self.state.write().await;

                        // Update sync status using XOR
                        state.confirm_erasure(peer_id, &their_confirmed);

                        let is_synced = state.erasure_synced.get(peer_id).copied().unwrap_or(false);
                        if is_synced {
                            debug!("SPORE⁻¹: Erasure synced with peer {} (XOR=∅)", peer_id);
                        } else {
                            let diff = state.do_not_want.xor(&their_confirmed);
                            debug!(
                                "SPORE⁻¹: Erasure not synced with peer {} ({} range diffs)",
                                peer_id,
                                diff.range_count()
                            );
                        }

                        // Check if ALL peers are synced - if so, we can garbage collect
                        if state.all_erasures_confirmed() && !state.erasure_confirmed.is_empty() {
                            // GDPR: All peers confirmed - tombstones can be garbage collected
                            let gc_range_count = state.erasure_confirmed.range_count();

                            // Clear erasure tracking (keep do_not_want for future sync)
                            state.erasure_confirmed = Spore::empty();
                            state.erasure_synced.clear();

                            info!("SPORE⁻¹: GDPR erasure complete - confirmed {} ranges across all peers",
                                gc_range_count);
                        }
                    }
                }
            }
            "bad_bits" => {
                // BadBits: PERMANENT blocklist (DMCA, abuse material, illegal content)
                // Unlike DoNotWantList (GDPR), these are NEVER garbage collected
                // Also deletes any matching content we currently have
                if let Some(hashes) = msg.get("double_hashes").and_then(|h| h.as_array()) {
                    let mut state = self.state.write().await;
                    let mut new_bad_bits = Vec::new();

                    for hash_val in hashes {
                        if let Some(hash_hex) = hash_val.as_str() {
                            if let Ok(hash_bytes) = hex::decode(hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut bad_bit = [0u8; 32];
                                    bad_bit.copy_from_slice(&hash_bytes);
                                    if state.bad_bits.insert(bad_bit) {
                                        new_bad_bits.push(bad_bit);
                                    }
                                }
                            }
                        }
                    }

                    if !new_bad_bits.is_empty() {
                        info!(
                            "BadBits: Added {} new entries from peer {}",
                            new_bad_bits.len(),
                            peer_id
                        );

                        // Delete any releases that match new bad bits
                        let self_id = state.self_id.clone();
                        drop(state); // Release lock before storage operations

                        let mut doc_store = self.doc_store.write().await;
                        if let Ok(releases) = doc_store.list::<crate::models::Release>() {
                            for release in releases {
                                let release_hash = double_hash_id(&release.id);
                                if new_bad_bits.contains(&release_hash) {
                                    let content_id =
                                        citadel_crdt::ContentId::hash(release.id.as_bytes());
                                    if let Err(e) =
                                        doc_store.delete::<crate::models::Release>(&content_id)
                                    {
                                        warn!(
                                            "BadBits: Failed to delete blocked release {}: {:?}",
                                            release.id, e
                                        );
                                    } else {
                                        info!("BadBits: Deleted blocked release {}", release.id);
                                    }
                                }
                            }
                        }
                        drop(doc_store);

                        // Re-flood the bad bits to propagate through mesh
                        self.flood(FloodMessage::BadBits {
                            double_hashes: new_bad_bits,
                        });
                    }
                }
            }
            "featured_sync" => {
                // SPORE: Receive featured releases from peer (via DocumentStore with merge)
                // Rich semantic merges (NOT LWW) - proven convergent in Lean
                // put() automatically merges via TotalMerge - no data loss
                if let Some(featured_arr) = msg.get("featured").and_then(|f| f.as_array()) {
                    let mut changed_count = 0;
                    let mut doc_store = self.doc_store.write().await;

                    for featured_json in featured_arr {
                        if let Some(json_str) = featured_json.as_str() {
                            if let Ok(featured) = serde_json::from_str::<FeaturedRelease>(json_str)
                            {
                                // put() merges with existing via TotalMerge:
                                // - Counters: max(a, b) - both increments preserved
                                // - Sets: union(a, b) - all elements preserved
                                // - Booleans: or(a, b) - if either promotes, promoted
                                // - Time windows: (min(start), max(end))
                                match doc_store.put(&featured) {
                                    Ok((_, changed)) => {
                                        if changed {
                                            changed_count += 1;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "SPORE: Failed to store/merge featured release {}: {}",
                                            featured.id, e
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Only re-flood if we actually got NEW data (XOR was non-empty)
                    if changed_count > 0 {
                        info!(
                            "SPORE: Merged {} new featured releases from peer {}",
                            changed_count, peer_id
                        );

                        // Re-flood merged state to propagate convergence
                        let self_id = self.state.read().await.self_id.clone();
                        if let Ok(all_featured) = doc_store.list::<FeaturedRelease>() {
                            let featured_json: Vec<String> = all_featured
                                .iter()
                                .filter_map(|f| serde_json::to_string(f).ok())
                                .collect();
                            self.flood(FloodMessage::FeaturedSync {
                                peer_id: self_id,
                                featured: featured_json,
                            });
                        }
                    }
                }
            }
            // ==================== END SPORE CONTENT SYNC HANDLERS ====================
            _ => {
                debug!("Unknown message type from {}: {}", peer_id, msg_type);
            }
        }

        Ok((None, vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::PeerAddrStore;
    use crate::storage::Storage;
    use citadel_docs::DocumentStore;
    use citadel_protocols::{CoordinatorConfig, FloodRateConfig, PeerCoordinator, QuadProof};
    use std::net::SocketAddr;
    use std::thread::sleep;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_should_refresh_peer_hint_prefers_ipv6_overlay() {
        let current: SocketAddr = "10.0.0.5:9000".parse().unwrap();
        let candidate: SocketAddr = "[200:1111:2222:3333:4444:5555:6666:7777]:9000"
            .parse()
            .unwrap();

        assert!(MeshService::should_refresh_peer_hint(current, candidate));
    }

    #[test]
    fn test_should_refresh_peer_hint_keeps_same_family_churn_down() {
        let current: SocketAddr = "10.0.0.5:9000".parse().unwrap();
        let candidate: SocketAddr = "10.0.0.6:9000".parse().unwrap();

        assert!(!MeshService::should_refresh_peer_hint(current, candidate));
    }

    /// Helper to create a keypair from a deterministic seed
    fn keypair_from_seed(seed: u8) -> citadel_protocols::KeyPair {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = seed;
        citadel_protocols::KeyPair::from_seed(&secret_bytes).expect("valid 32-byte seed")
    }

    /// Test SYMMETRIC TGP handshake - both peers use same constructor, roles assigned by key comparison
    #[test]
    fn test_tgp_symmetric_handshake() {
        let kp_a = keypair_from_seed(1);
        let kp_b = keypair_from_seed(2);

        // Both use symmetric constructor - roles determined by public key comparison
        let mut peer_a = PeerCoordinator::symmetric(
            kp_a.clone(),
            kp_b.public_key().clone(),
            CoordinatorConfig::default()
                .with_commitment(b"test_slot_0".to_vec())
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        let mut peer_b = PeerCoordinator::symmetric(
            kp_b,
            kp_a.public_key().clone(),
            CoordinatorConfig::default()
                .with_commitment(b"test_slot_0".to_vec())
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        peer_a.set_active(true);
        peer_b.set_active(true);

        // Run handshake - no tiebreaker needed!
        for _ in 0..100 {
            if let Ok(Some(messages)) = peer_a.poll() {
                for msg in messages {
                    let _ = peer_b.receive(&msg);
                }
            }

            if let Ok(Some(messages)) = peer_b.poll() {
                for msg in messages {
                    let _ = peer_a.receive(&msg);
                }
            }

            if peer_a.is_coordinated() && peer_b.is_coordinated() {
                break;
            }

            sleep(Duration::from_micros(100));
        }

        assert!(peer_a.is_coordinated(), "Peer A should reach coordination");
        assert!(peer_b.is_coordinated(), "Peer B should reach coordination");
        assert!(peer_a.get_bilateral_receipt().is_some(), "Peer A should have bilateral receipt");
        assert!(peer_b.get_bilateral_receipt().is_some(), "Peer B should have bilateral receipt");
    }

    /// Test that SPIRAL slot indices produce the correct coordinates
    #[test]
    fn test_spiral_slot_coordinates() {
        // Slot 0 should be at origin
        let coord_0 = spiral3d_to_coord(Spiral3DIndex(0));
        assert_eq!(coord_0.q, 0);
        assert_eq!(coord_0.r, 0);
        assert_eq!(coord_0.z, 0);

        // Slots 1-6 should be the first ring around origin
        for slot in 1..=6u64 {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            // First ring is at distance 1 from origin
            let dist = (coord.q.abs() + coord.r.abs()) / 2;
            assert!(
                dist <= 2,
                "Slot {} should be near origin, got ({}, {}, {})",
                slot,
                coord.q,
                coord.r,
                coord.z
            );
        }
    }

    /// Test threshold scaling based on mesh size
    #[test]
    fn test_threshold_scaling() {
        let mesh_size_3_neighbors_2 = MeshService::scaled_slot_claim_threshold(3, 2);
        assert_eq!(
            mesh_size_3_neighbors_2, 1,
            "With 2 neighbors in mesh of 3, need 1 confirmation"
        );

        let mesh_size_10_neighbors_5 = MeshService::scaled_slot_claim_threshold(10, 5);
        assert_eq!(
            mesh_size_10_neighbors_5, 2,
            "With 5 neighbors in mesh of 10, need 2 confirmations"
        );

        let full_mesh = MeshService::scaled_slot_claim_threshold(20, 20);
        assert_eq!(full_mesh, 11, "Full mesh requires 11/20 confirmations");
    }

    #[test]
    fn test_threshold_scaling_allows_zero_neighbor_genesis() {
        assert_eq!(
            MeshService::scaled_slot_claim_threshold(0, 0),
            0,
            "Genesis slot must be occupiable with zero existing neighbors"
        );
    }

    #[test]
    fn test_cvdf_attestation_json_roundtrip_preserves_signature() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let att = RoundAttestation::new(7, [9u8; 32], Some(3), &signing_key);

        let json = MeshService::cvdf_attestation_json(&att, None);
        let parsed = MeshService::parse_cvdf_attestation_json(&json).expect("attestation should parse");

        assert_eq!(parsed.round, att.round);
        assert_eq!(parsed.slot, att.slot);
        assert_eq!(parsed.prev_output, att.prev_output);
        assert_eq!(parsed.attester, att.attester);
        assert_eq!(parsed.signature, att.signature);
    }

    #[test]
    fn test_cvdf_round_json_roundtrip_preserves_attestations() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let round = CvdfRound::genesis(b"mesh-test", &signing_key);

        let json = MeshService::cvdf_round_json(&round, Some(0));
        let parsed = MeshService::parse_cvdf_round_json(&json).expect("round should parse");

        assert_eq!(parsed.round, round.round);
        assert_eq!(parsed.output, round.output);
        assert_eq!(parsed.producer, round.producer);
        assert_eq!(parsed.producer_signature, round.producer_signature);
        assert_eq!(parsed.attestations, round.attestations);
    }

    fn test_mesh_service() -> MeshService {
        let dir = tempdir().expect("tempdir");
        let storage = Arc::new(Storage::open(dir.path().join("lens.redb")).expect("storage"));
        let doc_store = DocumentStore::open(dir.path().join("docs.redb")).expect("doc_store");
        let doc_store = Arc::new(tokio::sync::RwLock::new(doc_store));
        MeshService::new(
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
            None,
            None,
            None,
            storage,
            doc_store,
        )
    }

    #[tokio::test]
    async fn test_process_vdf_claim_registers_remote_slot_in_cvdf() {
        let mesh = test_mesh_service();
        mesh.init_cvdf_genesis().await;

        let claimer = [7u8; 32];
        let claim = AnchoredSlotClaim {
            slot: 4,
            claimer,
            vdf_height: 1,
            vdf_output: [9u8; 32],
            signature: [0u8; 64],
        };

        assert!(mesh.process_vdf_claim(claim).await);

        let (_rounds, slots) = mesh.cvdf_chain_state().await.expect("cvdf state");
        assert!(slots.iter().any(|claim| claim.slot == 4 && claim.claimer == claimer));
    }

    #[test]
    fn test_evict_stale_slots_clears_claim_and_vdf_entry() {
        let peer_id = "b3b3/test-peer".to_string();
        let claim = SlotClaim::new(2, peer_id.clone());
        let coord = claim.coord;
        let mut state = MeshState {
            self_id: "b3b3/self".to_string(),
            signing_key: SigningKey::generate(&mut rand::thread_rng()),
            self_slot: None,
            peers: HashMap::new(),
            peer_addr_store: PeerAddrStore::new(120_000),
            claimed_slots: HashMap::from([(2, claim.clone())]),
            slot_coords: HashSet::from([coord]),
            spore_sync: None,
            vdf_race: None,
            vdf_claims: HashMap::from([(
                2,
                AnchoredSlotClaim {
                    slot: 2,
                    claimer: [3u8; 32],
                    vdf_height: 5,
                    vdf_output: [4u8; 32],
                    signature: [0u8; 64],
                },
            )]),
            pol_manager: None,
            pol_pending_pings: HashMap::new(),
            cvdf: None,
            latency_history: HashMap::new(),
            observed_public_addr: None,
            do_not_want: Spore::empty(),
            erasure_confirmed: Spore::empty(),
            erasure_synced: HashMap::new(),
            bad_bits: HashSet::new(),
            accountability: None,
            liveness: None,
        };

        let evicted = MeshService::evict_stale_slots_from_state(&mut state, &[2]);

        assert_eq!(evicted, vec![(2, peer_id)]);
        assert!(!state.claimed_slots.contains_key(&2));
        assert!(!state.vdf_claims.contains_key(&2));
        assert!(!state.slot_coords.contains(&coord));
    }

    #[test]
    fn test_slot_claim_validators_require_occupied_theoretical_neighbors() {
        let occupied_peer_id = "b3b3/occupied".to_string();
        let slotless_peer_id = "b3b3/slotless".to_string();
        let occupied_claim = SlotClaim::with_public_key(0, occupied_peer_id.clone(), Some(vec![1u8; 32]));
        let mut peers = HashMap::new();
        peers.insert(
            occupied_peer_id.clone(),
            MeshPeer {
                id: occupied_peer_id.clone(),
                addr: "10.0.0.10:9000".parse().unwrap(),
                yggdrasil_addr: None,
                underlay_uri: None,
                ygg_peer_uri: None,
                public_key: Some(vec![1u8; 32]),
                last_seen: std::time::Instant::now(),
                coordinated: false,
                slot: Some(occupied_claim.clone()),
                is_entry_peer: false,
                content_synced: false,
                their_have: None,
                their_peer_addr_have: None,
            },
        );
        peers.insert(
            slotless_peer_id.clone(),
            MeshPeer {
                id: slotless_peer_id.clone(),
                addr: "10.0.0.11:9000".parse().unwrap(),
                yggdrasil_addr: None,
                underlay_uri: None,
                ygg_peer_uri: None,
                public_key: Some(vec![2u8; 32]),
                last_seen: std::time::Instant::now(),
                coordinated: false,
                slot: None,
                is_entry_peer: false,
                content_synced: false,
                their_have: None,
                their_peer_addr_have: None,
            },
        );

        let state = MeshState {
            self_id: "b3b3/self".to_string(),
            signing_key: SigningKey::generate(&mut rand::thread_rng()),
            self_slot: None,
            peers,
            peer_addr_store: PeerAddrStore::new(120_000),
            claimed_slots: HashMap::from([(0, occupied_claim.clone())]),
            slot_coords: HashSet::from([occupied_claim.coord]),
            spore_sync: None,
            vdf_race: None,
            vdf_claims: HashMap::new(),
            pol_manager: None,
            pol_pending_pings: HashMap::new(),
            cvdf: None,
            latency_history: HashMap::new(),
            observed_public_addr: None,
            do_not_want: Spore::empty(),
            erasure_confirmed: Spore::empty(),
            erasure_synced: HashMap::new(),
            bad_bits: HashSet::new(),
            accountability: None,
            liveness: None,
        };

        let active_peer_ids = HashSet::from([occupied_peer_id.clone(), slotless_peer_id.clone()]);

        let slot_one_validators =
            MeshService::occupied_theoretical_neighbor_validator_ids(&state, &active_peer_ids, 1);
        assert!(slot_one_validators.contains(&occupied_peer_id));
        assert!(!slot_one_validators.contains(&slotless_peer_id));

        let slot_zero_validators =
            MeshService::occupied_theoretical_neighbor_validator_ids(&state, &active_peer_ids, 0);
        assert!(
            slot_zero_validators.is_empty(),
            "slotless peers must not witness a duplicate slot 0 claim"
        );
    }

    /// 1000-node mesh formation test with flooding-based coordination
    ///
    /// Simulates 1000 nodes joining the mesh via ANY existing node (no special bootstraps).
    /// Uses flooding for slot claims and validations - O(N) packets, not O(N²).
    ///
    /// Protocol:
    /// 1. Genesis node claims slot 0 (origin)
    /// 2. Each new node contacts ANY random existing node
    /// 3. New node broadcasts slot claim (1 packet, floods to all)
    /// 4. Neighbors validate and flood validations
    /// 5. Slot confirmed when 11/20 threshold met (or scaled threshold for small mesh)
    #[test]
    fn test_1000_node_mesh_formation() {
        use citadel_topology::{
            coord_to_spiral3d, spiral3d_to_coord, HexCoord, Neighbors, Spiral3DIndex,
        };
        use std::collections::{HashMap, HashSet, VecDeque};

        const NODE_COUNT: u64 = 1000;

        /// A slot claim message (floods through mesh)
        #[derive(Clone, Debug)]
        struct SlotClaim {
            slot: u64,
            coord: HexCoord,
            peer_id: String,
            signature: [u8; 64], // Ed25519 signature
        }

        /// A validation message (floods through mesh)
        #[derive(Clone, Debug)]
        struct SlotValidation {
            slot: u64,
            claimer_id: String,
            validator_id: String,
            accepted: bool,
        }

        /// Simulated node state
        struct SimNode {
            peer_id: String,
            coord: HexCoord,
            validations_received: HashSet<String>, // validator IDs
            neighbors_at_join: usize, // how many neighbors existed when this node joined
        }

        /// Flooding network simulation
        struct FloodNetwork {
            nodes: HashMap<u64, SimNode>,
            coord_to_slot: HashMap<HexCoord, u64>,
            pending_claims: VecDeque<SlotClaim>,
            pending_validations: VecDeque<SlotValidation>,
            packets_sent: u64,
        }

        impl FloodNetwork {
            fn new() -> Self {
                Self {
                    nodes: HashMap::new(),
                    coord_to_slot: HashMap::new(),
                    pending_claims: VecDeque::new(),
                    pending_validations: VecDeque::new(),
                    packets_sent: 0,
                }
            }

            /// Broadcast a slot claim (1 packet that floods)
            fn broadcast_claim(&mut self, claim: SlotClaim) {
                self.packets_sent += 1;
                self.pending_claims.push_back(claim);
            }

            /// Process all pending messages (event-driven, non-blocking)
            fn process_all(&mut self) {
                // Process claims
                while let Some(claim) = self.pending_claims.pop_front() {
                    self.process_claim(claim);
                }

                // Process validations
                while let Some(validation) = self.pending_validations.pop_front() {
                    self.process_validation(validation);
                }
            }

            fn process_claim(&mut self, claim: SlotClaim) {
                // Each neighbor that exists validates the claim
                let neighbors = Neighbors::of(claim.coord);

                // Count neighbors at join time (for threshold calculation)
                let neighbors_at_join = neighbors
                    .iter()
                    .filter(|n| self.coord_to_slot.contains_key(n))
                    .count();

                for neighbor_coord in neighbors {
                    if let Some(&neighbor_slot) = self.coord_to_slot.get(&neighbor_coord) {
                        let neighbor = self.nodes.get(&neighbor_slot).unwrap();

                        // Neighbor validates: first-writer-wins check
                        // (In simulation, claims arrive in order, so always valid)
                        let validation = SlotValidation {
                            slot: claim.slot,
                            claimer_id: claim.peer_id.clone(),
                            validator_id: neighbor.peer_id.clone(),
                            accepted: true,
                        };

                        // Validation floods back (1 packet per validator, but floods)
                        self.packets_sent += 1;
                        self.pending_validations.push_back(validation);
                    }
                }

                // Add the node to the mesh (optimistically, validations confirm)
                self.nodes.insert(
                    claim.slot,
                    SimNode {
                        peer_id: claim.peer_id,
                        coord: claim.coord,
                        validations_received: HashSet::new(),
                        neighbors_at_join,
                    },
                );
                self.coord_to_slot.insert(claim.coord, claim.slot);
            }

            fn process_validation(&mut self, validation: SlotValidation) {
                if let Some(node) = self.nodes.get_mut(&validation.slot) {
                    if validation.accepted {
                        node.validations_received.insert(validation.validator_id);
                    }
                }
            }

            /// Calculate required threshold based on mesh size and available neighbors
            fn required_threshold(&self, coord: HexCoord) -> usize {
                let neighbors = Neighbors::of(coord);
                let existing_neighbors = neighbors
                    .iter()
                    .filter(|n| self.coord_to_slot.contains_key(n))
                    .count();

                if existing_neighbors == 0 {
                    return 0; // Genesis node
                }

                // Scale threshold: at full mesh 11/20, but proportional for smaller meshes
                // Formula: max(1, ceil(existing_neighbors * 11 / 20))
                std::cmp::max(1, (existing_neighbors * 11 + 19) / 20)
            }
        }

        // Generate deterministic peer ID
        fn make_peer_id(seed: u64) -> String {
            let hash = blake3::hash(&seed.to_le_bytes());
            format!("b3b3/{}", hex::encode(&hash.as_bytes()[..32]))
        }

        let mut network = FloodNetwork::new();

        println!("\n=== 1000-Node Flooding Mesh Formation Test ===\n");

        // Genesis: Node 0 claims slot 0 (no neighbors to validate)
        println!("Phase 1: Genesis node claims origin...");
        let genesis_claim = SlotClaim {
            slot: 0,
            coord: spiral3d_to_coord(Spiral3DIndex(0)),
            peer_id: make_peer_id(0),
            signature: [0u8; 64], // Simulated signature
        };
        network.broadcast_claim(genesis_claim);
        network.process_all();
        println!(
            "  Genesis node at origin, {} packet(s)",
            network.packets_sent
        );

        // Remaining nodes join via flooding
        println!("Phase 2: {} nodes joining via flooding...", NODE_COUNT - 1);
        let progress_points = [100u64, 250, 500, 750, 999];
        let mut progress_idx = 0;

        for slot in 1..NODE_COUNT {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let peer_id = make_peer_id(slot);

            // Node joins by contacting ANY existing node (simulated: just broadcast claim)
            let claim = SlotClaim {
                slot,
                coord,
                peer_id,
                signature: [0u8; 64],
            };

            network.broadcast_claim(claim);
            network.process_all();

            // Progress reporting
            if progress_idx < progress_points.len() && slot >= progress_points[progress_idx] {
                println!(
                    "  {} nodes, {} packets so far ({:.2} packets/node)",
                    slot + 1,
                    network.packets_sent,
                    network.packets_sent as f64 / (slot + 1) as f64
                );
                progress_idx += 1;
            }
        }

        // Verification
        println!("\nPhase 3: Verifying mesh geometry...");

        assert_eq!(network.nodes.len(), NODE_COUNT as usize);
        assert_eq!(network.coord_to_slot.len(), NODE_COUNT as usize);

        // Verify SPIRAL bijection
        for slot in 0..NODE_COUNT {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);

            let node = network.nodes.get(&slot).unwrap();
            assert_eq!(node.coord, coord, "Node {} has wrong coordinate", slot);
        }
        println!(
            "  ✓ All {} slots filled in correct SPIRAL order",
            NODE_COUNT
        );

        // Verify validation thresholds met (based on neighbors at join time)
        let mut validation_failures = 0u64;
        let mut total_validations = 0u64;

        for slot in 0..NODE_COUNT {
            let node = network.nodes.get(&slot).unwrap();
            let received = node.validations_received.len();
            total_validations += received as u64;

            // Threshold based on neighbors at join time, not current neighbors
            let required = if node.neighbors_at_join == 0 {
                0 // Genesis node
            } else {
                std::cmp::max(1, (node.neighbors_at_join * 11 + 19) / 20)
            };

            // Each neighbor at join time sends a validation, so received should equal neighbors_at_join
            if received < required {
                validation_failures += 1;
            }
        }
        println!(
            "  ✓ Validation thresholds: {} failures out of {} nodes",
            validation_failures, NODE_COUNT
        );
        assert_eq!(
            validation_failures, 0,
            "All nodes should meet validation threshold"
        );

        // Verify 20-neighbor topology
        let mut total_edges = 0u64;
        let mut max_neighbors = 0usize;
        let mut min_neighbors = 20usize;

        for slot in 0..NODE_COUNT {
            let node = network.nodes.get(&slot).unwrap();
            let neighbors = Neighbors::of(node.coord);
            let existing = neighbors
                .iter()
                .filter(|n| network.coord_to_slot.contains_key(n))
                .count();

            total_edges += existing as u64;
            max_neighbors = max_neighbors.max(existing);
            min_neighbors = min_neighbors.min(existing);
        }

        let unique_edges = total_edges / 2;
        println!(
            "  ✓ Topology: {} unique edges, neighbors range {} to {}",
            unique_edges, min_neighbors, max_neighbors
        );

        // Packet efficiency
        println!("\nPhase 4: Packet efficiency...");
        println!("  Total packets: {}", network.packets_sent);
        println!(
            "  Packets per node: {:.2}",
            network.packets_sent as f64 / NODE_COUNT as f64
        );
        println!("  Total validations: {}", total_validations);

        // We want < 1000 packets for 1000 nodes? Let's see the actual count
        // Each node sends 1 claim, neighbors send validations
        // With ~10 avg neighbors, that's ~11 packets per node = ~11,000 total
        // But with efficient flooding, validations can be batched

        // For now, verify it's O(N), not O(N²)
        // O(N²) would be ~1,000,000 packets
        // O(N) with small constant should be < 50,000
        assert!(
            network.packets_sent < 50000,
            "Should be O(N) packets, got {} for {} nodes",
            network.packets_sent,
            NODE_COUNT
        );
        println!(
            "  ✓ Packet count is O(N): {} << {} (N²)",
            network.packets_sent,
            NODE_COUNT * NODE_COUNT
        );

        // Geometric balance
        let coords: Vec<HexCoord> = (0..NODE_COUNT)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        let min_q = coords.iter().map(|c| c.q).min().unwrap();
        let max_q = coords.iter().map(|c| c.q).max().unwrap();
        let min_z = coords.iter().map(|c| c.z).min().unwrap();
        let max_z = coords.iter().map(|c| c.z).max().unwrap();

        let q_span = max_q - min_q;
        let z_span = max_z - min_z;

        println!("\nMesh statistics:");
        println!("  Nodes: {}", NODE_COUNT);
        println!("  Unique edges: {}", unique_edges);
        println!(
            "  Spatial extent: Q [{}, {}], Z [{}, {}]",
            min_q, max_q, min_z, max_z
        );
        println!(
            "  Avg neighbors: {:.2}",
            total_edges as f64 / NODE_COUNT as f64
        );

        assert!(
            (q_span - z_span).abs() <= 2,
            "Mesh should be balanced: Q span {} vs Z span {}",
            q_span,
            z_span
        );
        println!("  ✓ Geometrically balanced (spherical growth)");

        println!("\n=== 1000-Node Flooding Mesh Test PASSED ===\n");
    }

    /// Tests concurrent node startup with staggered joining.
    ///
    /// The key insight: nodes must join SEQUENTIALLY through the mesh,
    /// not all start simultaneously. Each new node contacts ONE existing
    /// node, learns mesh state, then claims the next available slot.
    ///
    /// This models Docker's depends_on ordering where node N depends on node N-1.
    #[test]
    fn test_sequential_mesh_formation() {
        use citadel_topology::{coord_to_spiral3d, spiral3d_to_coord, Spiral3DIndex};
        use std::collections::HashMap;

        const NODE_COUNT: u64 = 50;

        /// Simulated node state
        struct SimNode {
            slot: u64,
            known_slots: HashMap<u64, u64>, // slot -> node_id
        }

        struct Mesh {
            nodes: HashMap<u64, SimNode>,
        }

        impl Mesh {
            fn new() -> Self {
                Self {
                    nodes: HashMap::new(),
                }
            }

            /// Node joins by contacting any existing node, learning state, then claiming
            fn join(&mut self, node_id: u64, contact_node: Option<u64>) {
                // Learn state from contact node (or start fresh if genesis)
                let known_slots = match contact_node {
                    Some(contact) => {
                        let contact_node = self.nodes.get(&contact).unwrap();
                        contact_node.known_slots.clone()
                    }
                    None => HashMap::new(),
                };

                // Find next available slot
                let mut slot = 0u64;
                while known_slots.contains_key(&slot) {
                    slot += 1;
                }

                // Record our claim
                let mut final_known = known_slots;
                final_known.insert(slot, node_id);

                self.nodes.insert(
                    node_id,
                    SimNode {
                        slot,
                        known_slots: final_known,
                    },
                );

                // Propagate our claim to all existing nodes
                let node_ids: Vec<u64> = self
                    .nodes
                    .keys()
                    .copied()
                    .filter(|&id| id != node_id)
                    .collect();
                for other_id in node_ids {
                    self.nodes
                        .get_mut(&other_id)
                        .unwrap()
                        .known_slots
                        .insert(slot, node_id);
                }
            }
        }

        println!("\n=== Sequential Mesh Formation Test (50 nodes) ===\n");

        let mut mesh = Mesh::new();

        // Genesis node
        println!("Phase 1: Genesis node claims origin...");
        mesh.join(0, None);

        // Each subsequent node joins via the previous node
        // This is the "sequential dependency" model
        println!("Phase 2: {} nodes joining sequentially...", NODE_COUNT - 1);
        for node_id in 1..NODE_COUNT {
            mesh.join(node_id, Some(node_id - 1));
        }

        // Verify results
        println!("Phase 3: Verifying mesh...\n");

        let mut slot_to_node: HashMap<u64, u64> = HashMap::new();
        for (&node_id, node) in &mesh.nodes {
            if let Some(&existing) = slot_to_node.get(&node.slot) {
                panic!(
                    "DUPLICATE: Slot {} claimed by both node {} and node {}",
                    node.slot, existing, node_id
                );
            }
            slot_to_node.insert(node.slot, node_id);
        }

        // Verify all slots are contiguous [0, NODE_COUNT)
        for slot in 0..NODE_COUNT {
            assert!(slot_to_node.contains_key(&slot), "Missing slot {}", slot);
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);
        }

        println!("Results:");
        println!("  Total nodes: {}", mesh.nodes.len());
        println!("  Unique slots: {}", slot_to_node.len());
        println!("  ✓ All {} slots filled [0, {})", NODE_COUNT, NODE_COUNT);
        println!("  ✓ All slots have valid SPIRAL-3D coordinates");
        println!("  ✓ No duplicate slot assignments");

        println!("\n=== Sequential Mesh Formation Test PASSED ===\n");
    }

    /// Tests what happens when nodes DON'T wait for state sync (the Docker bug).
    /// All nodes start simultaneously and claim slot 0 - demonstrating the race.
    #[test]
    fn test_concurrent_race_demonstrates_bug() {
        use std::collections::HashMap;

        const NODE_COUNT: u64 = 10; // Small count to demonstrate

        println!("\n=== Concurrent Race Bug Demonstration ===\n");
        println!("This test shows what happens when nodes don't sync before claiming.\n");

        // Simulate: all nodes start at once, each thinks mesh is empty
        let mut claims: Vec<(u64, u64)> = Vec::new(); // (node_id, claimed_slot)

        for node_id in 0..NODE_COUNT {
            // Each node sees empty mesh (no sync happened)
            let claimed_slot = 0; // Everyone claims slot 0!
            claims.push((node_id, claimed_slot));
        }

        // Count how many claimed each slot
        let mut slot_counts: HashMap<u64, usize> = HashMap::new();
        for (_, slot) in &claims {
            *slot_counts.entry(*slot).or_insert(0) += 1;
        }

        println!(
            "Without state sync, {} nodes all claimed slot 0!",
            slot_counts.get(&0).unwrap()
        );
        println!("This is exactly what we see in Docker logs.\n");

        // The fix: priority-based tiebreaker resolves, but requires many re-claims
        // Better fix: ensure state sync BEFORE claiming

        // Calculate how many iterations needed to resolve (worst case)
        // With priority tiebreaker, one node wins slot 0, others must retry
        // Those retrying all claim slot 1, one wins, others retry for slot 2...
        // This takes O(N) rounds of resolution!

        println!("With naive tiebreaker resolution:");
        println!(
            "  Round 1: {} nodes fight for slot 0, 1 wins, {} retry",
            NODE_COUNT,
            NODE_COUNT - 1
        );
        println!(
            "  Round 2: {} nodes fight for slot 1, 1 wins, {} retry",
            NODE_COUNT - 1,
            NODE_COUNT - 2
        );
        println!("  ...");
        println!("  Total rounds: {} (O(N))", NODE_COUNT);
        println!(
            "  Total slot changes: {} (O(N²))\n",
            NODE_COUNT * (NODE_COUNT - 1) / 2
        );

        println!("The FIX: Nodes must sync mesh state BEFORE claiming.");
        println!("With proper sync, each node claims a unique slot immediately.\n");

        println!("=== Bug Demonstration Complete ===\n");
    }

    /// Integration test: 50 nodes with proper state propagation.
    /// Models the CORRECT behavior we want in Docker.
    #[test]
    fn test_50_node_mesh_with_state_propagation() {
        use citadel_topology::{coord_to_spiral3d, spiral3d_to_coord, Neighbors, Spiral3DIndex};
        use std::cmp::Ordering;
        use std::collections::{BinaryHeap, HashMap};

        const NODE_COUNT: u64 = 50;

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct Event {
            time: u64,
            seq: u64, // For deterministic ordering at same time
            event_type: EventType,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        enum EventType {
            NodeStartup {
                node_id: u64,
            },
            StateReceived {
                node_id: u64,
                from_peer: u64,
            },
            SlotClaimReceived {
                receiver: u64,
                claimer: u64,
                slot: u64,
            },
        }

        impl Ord for Event {
            fn cmp(&self, other: &Self) -> Ordering {
                other
                    .time
                    .cmp(&self.time)
                    .then_with(|| other.seq.cmp(&self.seq))
            }
        }

        impl PartialOrd for Event {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        struct SimNode {
            claimed_slot: Option<u64>,
            known_slots: HashMap<u64, u64>,
            state_received: bool,
        }

        struct Simulation {
            nodes: HashMap<u64, SimNode>,
            events: BinaryHeap<Event>,
            time: u64,
            seq: u64,
        }

        impl Simulation {
            fn new() -> Self {
                Self {
                    nodes: HashMap::new(),
                    events: BinaryHeap::new(),
                    time: 0,
                    seq: 0,
                }
            }

            fn schedule(&mut self, delay: u64, event_type: EventType) {
                self.seq += 1;
                self.events.push(Event {
                    time: self.time + delay,
                    seq: self.seq,
                    event_type,
                });
            }

            fn run(&mut self) {
                while let Some(event) = self.events.pop() {
                    self.time = event.time;
                    match event.event_type {
                        EventType::NodeStartup { node_id } => {
                            self.handle_startup(node_id);
                        }
                        EventType::StateReceived { node_id, from_peer } => {
                            self.handle_state_received(node_id, from_peer);
                        }
                        EventType::SlotClaimReceived {
                            receiver,
                            claimer,
                            slot,
                        } => {
                            self.handle_slot_claim(receiver, claimer, slot);
                        }
                    }
                }
            }

            fn handle_startup(&mut self, node_id: u64) {
                // Node starts but does NOT claim immediately
                self.nodes.insert(
                    node_id,
                    SimNode {
                        claimed_slot: None,
                        known_slots: HashMap::new(),
                        state_received: false,
                    },
                );

                if node_id == 0 {
                    // Genesis: no peers to sync from, claim immediately
                    let node = self.nodes.get_mut(&node_id).unwrap();
                    node.claimed_slot = Some(0);
                    node.known_slots.insert(0, node_id);
                    node.state_received = true;
                    // Broadcast to future nodes (will happen when they connect)
                } else {
                    // Connect to previous node and wait for state
                    let bootstrap_peer = node_id - 1;
                    // Network delay for connection + state transfer
                    self.schedule(
                        50,
                        EventType::StateReceived {
                            node_id,
                            from_peer: bootstrap_peer,
                        },
                    );
                }
            }

            fn handle_state_received(&mut self, node_id: u64, from_peer: u64) {
                // Copy state from peer
                let peer_slots = self.nodes.get(&from_peer).unwrap().known_slots.clone();

                let node = self.nodes.get_mut(&node_id).unwrap();
                node.known_slots = peer_slots;
                node.state_received = true;

                // NOW claim next available slot
                let mut target = 0u64;
                while node.known_slots.contains_key(&target) {
                    target += 1;
                }
                node.claimed_slot = Some(target);
                node.known_slots.insert(target, node_id);

                // Broadcast claim to all existing nodes
                let node_ids: Vec<u64> = self
                    .nodes
                    .keys()
                    .copied()
                    .filter(|&id| id != node_id)
                    .collect();

                for other_id in node_ids {
                    // Variable network delay
                    let delay = 10 + (node_id ^ other_id) % 30;
                    self.schedule(
                        delay,
                        EventType::SlotClaimReceived {
                            receiver: other_id,
                            claimer: node_id,
                            slot: target,
                        },
                    );
                }
            }

            fn handle_slot_claim(&mut self, receiver: u64, claimer: u64, slot: u64) {
                if let Some(node) = self.nodes.get_mut(&receiver) {
                    node.known_slots.insert(slot, claimer);
                }
            }
        }

        println!("\n=== 50-Node Mesh with State Propagation ===\n");

        let mut sim = Simulation::new();

        // Staggered startup: each node starts 5ms after previous
        // This models Docker's depends_on chain
        println!(
            "Phase 1: Scheduling {} nodes with staggered startup...",
            NODE_COUNT
        );
        for i in 0..NODE_COUNT {
            sim.schedule(i * 5, EventType::NodeStartup { node_id: i });
        }

        println!("Phase 2: Running simulation...");
        sim.run();

        println!("Phase 3: Verifying mesh...\n");

        // Verify all nodes claimed unique slots
        let mut slot_to_node: HashMap<u64, u64> = HashMap::new();
        let mut duplicate_count = 0;

        for (&node_id, node) in &sim.nodes {
            if let Some(slot) = node.claimed_slot {
                if let Some(&existing) = slot_to_node.get(&slot) {
                    println!(
                        "  DUPLICATE: Slot {} claimed by nodes {} and {}",
                        slot, existing, node_id
                    );
                    duplicate_count += 1;
                } else {
                    slot_to_node.insert(slot, node_id);
                }
            }
        }

        // Verify slots are valid SPIRAL coordinates
        for &slot in slot_to_node.keys() {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);
        }

        // Verify topology
        let mut total_neighbors = 0usize;
        for &slot in slot_to_node.keys() {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let neighbors = Neighbors::of(coord);
            let count = neighbors
                .iter()
                .filter(|n| {
                    let neighbor_slot = coord_to_spiral3d(**n).0;
                    slot_to_node.contains_key(&neighbor_slot)
                })
                .count();
            total_neighbors += count;
        }

        println!("Results:");
        println!("  Total nodes: {}", sim.nodes.len());
        println!("  Unique slots: {}", slot_to_node.len());
        println!("  Duplicate claims: {}", duplicate_count);
        println!(
            "  Avg neighbors: {:.2}",
            total_neighbors as f64 / NODE_COUNT as f64
        );

        assert_eq!(duplicate_count, 0, "No duplicates with proper state sync");
        assert_eq!(
            slot_to_node.len(),
            NODE_COUNT as usize,
            "All nodes got slots"
        );

        println!("  ✓ All {} nodes claimed unique slots", NODE_COUNT);
        println!("  ✓ State propagation prevents races");

        println!("\n=== 50-Node Mesh Test PASSED ===\n");
    }

    /// Test TGP-native AuthorizedPeer struct creation and storage
    #[test]
    fn test_authorized_peer_creation() {
        let kp_a = keypair_from_seed(1);
        let kp_b = keypair_from_seed(2);

        // Complete TGP handshake to get bilateral triple proofs
        let mut peer_a = PeerCoordinator::symmetric(
            kp_a.clone(),
            kp_b.public_key().clone(),
            CoordinatorConfig::default()
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        let mut peer_b = PeerCoordinator::symmetric(
            kp_b.clone(),
            kp_a.public_key().clone(),
            CoordinatorConfig::default()
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        peer_a.set_active(true);
        peer_b.set_active(true);

        // Run handshake to completion
        for _ in 0..100 {
            if let Ok(Some(msgs)) = peer_a.poll() {
                for msg in msgs {
                    let _ = peer_b.receive(&msg);
                }
            }
            if let Ok(Some(msgs)) = peer_b.poll() {
                for msg in msgs {
                    let _ = peer_a.receive(&msg);
                }
            }
            if peer_a.is_coordinated() && peer_b.is_coordinated() {
                break;
            }
            sleep(Duration::from_micros(100));
        }

        assert!(peer_a.is_coordinated(), "Peer A should be coordinated");
        assert!(peer_b.is_coordinated(), "Peer B should be coordinated");

        // Get bilateral receipts
        let (a_our, a_their) = peer_a.get_bilateral_receipt().expect("Should have bilateral receipt");
        let (b_our, b_their) = peer_b.get_bilateral_receipt().expect("Should have bilateral receipt");

        // Create AuthorizedPeer from A's perspective
        let peer_id = compute_peer_id_from_bytes(kp_b.public_key().as_bytes());
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let authorized = AuthorizedPeer::new(
            peer_id.clone(),
            *kp_b.public_key().as_bytes(),
            a_our.clone(),
            a_their.clone(),
            addr,
        );

        // Verify AuthorizedPeer properties
        assert_eq!(authorized.peer_id, peer_id);
        assert_eq!(authorized.public_key, *kp_b.public_key().as_bytes());
        assert!(
            authorized.is_authorized(),
            "AuthorizedPeer should always be authorized"
        );
        assert!(authorized.slot.is_none(), "New AuthorizedPeer has no slot");
        assert_eq!(authorized.last_addr, addr);

        // Verify bilateral construction property:
        // If A has the bilateral triple, B must also have it (and vice versa)
        // This is TGP's core invariant: ∃QA ⇔ ∃QB
        assert!(peer_b.get_bilateral_receipt().is_some(),
            "Bilateral construction: if A has Q, B must have Q");

        println!("AuthorizedPeer created successfully:");
        println!("  peer_id: {}...", &peer_id[..20]);
        println!("  addr: {}", authorized.last_addr);
        println!("  established: {:?} ago", authorized.established.elapsed());
    }

    /// Test that authorized_peers HashMap can store and retrieve peers
    #[test]
    fn test_authorized_peers_hashmap() {
        use std::collections::HashMap;

        let kp_a = keypair_from_seed(10);
        let kp_b = keypair_from_seed(20);
        let kp_c = keypair_from_seed(30);

        // Create mock bilateral triples (using coordinated handshake)
        let mut create_auth_peer =
            |our_kp: &citadel_protocols::KeyPair, their_kp: &citadel_protocols::KeyPair| {
                let mut peer_a = PeerCoordinator::symmetric(
                    our_kp.clone(),
                    their_kp.public_key().clone(),
                    CoordinatorConfig::default()
                        .without_timeout()
                        .with_flood_rate(FloodRateConfig::fast()),
                );
                let mut peer_b = PeerCoordinator::symmetric(
                    their_kp.clone(),
                    our_kp.public_key().clone(),
                    CoordinatorConfig::default()
                        .without_timeout()
                        .with_flood_rate(FloodRateConfig::fast()),
                );
                peer_a.set_active(true);
                peer_b.set_active(true);

                for _ in 0..100 {
                    if let Ok(Some(msgs)) = peer_a.poll() {
                        for msg in msgs {
                            let _ = peer_b.receive(&msg);
                        }
                    }
                    if let Ok(Some(msgs)) = peer_b.poll() {
                        for msg in msgs {
                            let _ = peer_a.receive(&msg);
                        }
                    }
                    if peer_a.is_coordinated() && peer_b.is_coordinated() {
                        break;
                    }
                    sleep(Duration::from_micros(100));
                }

            let (our_q, their_q) = peer_a.get_bilateral_receipt().unwrap();
            let peer_id = compute_peer_id_from_bytes(their_kp.public_key().as_bytes());
            AuthorizedPeer::new(
                peer_id,
                *their_kp.public_key().as_bytes(),
                our_q.clone(),
                their_q.clone(),
                "127.0.0.1:9000".parse().unwrap(),
            )
        };

        // Create authorized peers
        let auth_b = create_auth_peer(&kp_a, &kp_b);
        let auth_c = create_auth_peer(&kp_a, &kp_c);

        // Store in HashMap (mimics MeshState.authorized_peers)
        let mut authorized_peers: HashMap<String, AuthorizedPeer> = HashMap::new();

        authorized_peers.insert(auth_b.peer_id.clone(), auth_b);
        authorized_peers.insert(auth_c.peer_id.clone(), auth_c);

        assert_eq!(authorized_peers.len(), 2, "Should have 2 authorized peers");

        // Verify lookup
        let peer_b_id = compute_peer_id_from_bytes(kp_b.public_key().as_bytes());
        let peer_c_id = compute_peer_id_from_bytes(kp_c.public_key().as_bytes());

        assert!(
            authorized_peers.contains_key(&peer_b_id),
            "Should find peer B"
        );
        assert!(
            authorized_peers.contains_key(&peer_c_id),
            "Should find peer C"
        );

        // Verify authorization check
        for (id, peer) in &authorized_peers {
            assert!(peer.is_authorized(), "Peer {} should be authorized", id);
        }

        println!("authorized_peers HashMap test passed:");
        println!("  Stored {} peers", authorized_peers.len());
    }
}
