//! Peer Coordinator - Bilateral coordination using TGP with continuous adaptive flooding.
//!
//! This module provides the [`PeerCoordinator`] abstraction for reliable
//! bilateral coordination between two peers in the Citadel mesh.
//!
//! # 6-Packet Protocol Model
//!
//! The coordinator uses the 6-packet TGP model:
//! - C_A, C_B: Commitments (unilateral)
//! - D_A, D_B: Double proofs (bilateral at C level)
//! - T_A, T_B: Triple proofs (bilateral at D level) - THE KNOT
//!
//! Coordination is achieved when the **attack key exists** - both parties have
//! constructed their triple proofs. This is an emergent state, not a decision.
//!
//! # Continuous Flooding
//!
//! The coordinator uses continuous adaptive flooding rather than single message exchanges.
//! This is essential to TGP's design - messages are continuously flooded at an adaptive rate:
//!
//! - **Drip mode**: 1 packet every ~300s when idle (connection keepalive)
//! - **Burst mode**: Up to 50MB/s+ when data transfer is active
//!
//! The rate ramps up instantly when data is needed and slowly decays back to drip mode.

use std::time::{Duration, Instant};

use adaptive_flooding::AdaptiveTGP;
use tracing::{debug, trace, warn};
use two_generals::{
    crypto::{KeyPair, PublicKey},
    types::Party,
    Message, ProtocolState, QuadProof,
};

use crate::error::{Error, Result};

/// Flood rate configuration for adaptive rate control.
#[derive(Debug, Clone, Copy)]
pub struct FloodRateConfig {
    /// Minimum packets per second (drip mode).
    /// Default: 1 pkt/300s (0.003 pkt/s) for idle keepalive.
    pub min_rate: u64,

    /// Maximum packets per second (burst mode).
    /// Default: 10000 pkt/s for fast coordination.
    pub max_rate: u64,
}

impl Default for FloodRateConfig {
    fn default() -> Self {
        Self {
            // Drip mode: ~1 packet every few seconds for keepalive
            // (Use 1 pkt/s as minimum since the flooder requires min_rate > 0)
            min_rate: 1,
            // Burst mode: high rate for fast coordination
            max_rate: 10_000,
        }
    }
}

impl FloodRateConfig {
    /// Create a config optimized for fast coordination (tests, local).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            min_rate: 100,
            max_rate: 100_000,
        }
    }

    /// Create a config optimized for low bandwidth usage.
    #[must_use]
    pub fn low_bandwidth() -> Self {
        Self {
            min_rate: 1,
            max_rate: 1_000,
        }
    }
}

/// Configuration for a peer coordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Timeout for coordination to complete.
    /// If not achieved within this duration, the coordinator will abort.
    pub timeout: Option<Duration>,

    /// Custom commitment message for the coordination.
    /// Defaults to TGP's default commitment message.
    pub commitment_message: Option<Vec<u8>>,

    /// Whether this peer initiated the coordination (Alice role).
    /// If false, this peer is the responder (Bob role).
    pub is_initiator: bool,

    /// Flood rate configuration.
    pub flood_rate: FloodRateConfig,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(30)),
            commitment_message: None,
            is_initiator: true,
            flood_rate: FloodRateConfig::default(),
        }
    }
}

impl CoordinatorConfig {
    /// Create a new config for an initiating peer (Alice role).
    #[must_use]
    pub fn initiator() -> Self {
        Self {
            is_initiator: true,
            ..Default::default()
        }
    }

    /// Create a new config for a responding peer (Bob role).
    #[must_use]
    pub fn responder() -> Self {
        Self {
            is_initiator: false,
            ..Default::default()
        }
    }

    /// Set the coordination timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable the coordination timeout.
    #[must_use]
    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Set a custom commitment message.
    #[must_use]
    pub fn with_commitment(mut self, message: Vec<u8>) -> Self {
        self.commitment_message = Some(message);
        self
    }

    /// Set the flood rate configuration.
    #[must_use]
    pub fn with_flood_rate(mut self, config: FloodRateConfig) -> Self {
        self.flood_rate = config;
        self
    }
}

/// State of the peer coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorState {
    /// Coordination is in progress (continuous flooding active).
    Coordinating,
    /// Coordination achieved - peers can proceed.
    Coordinated,
    /// Coordination failed or was aborted.
    Aborted,
}

impl std::fmt::Display for CoordinatorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Coordinating => write!(f, "Coordinating"),
            Self::Coordinated => write!(f, "Coordinated"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

/// Bilateral peer coordinator using the Two Generals Protocol with adaptive flooding.
///
/// Provides reliable coordination between two peers using continuous flooding
/// with adaptive rate control. The flood rate automatically ramps up when
/// data transfer is active and decays to drip mode when idle.
///
/// # Continuous Flooding
///
/// Unlike simple request-response protocols, TGP requires continuous flooding
/// of proof messages. The coordinator manages this automatically:
///
/// 1. Call [`poll()`](Self::poll) regularly to get messages to send
/// 2. Call [`receive()`](Self::receive) when messages arrive
/// 3. The flooder automatically adjusts rate based on activity
///
/// # Protocol Phases (6-Packet Model)
///
/// The coordinator wraps TGP's C → D → T proof escalation:
///
/// 1. **Commitment (C)**: Exchange signed intent to coordinate
/// 2. **Double (D)**: Prove receipt of counterparty's commitment
/// 3. **Triple (T)**: Prove knowledge of counterparty's double proof - THE KNOT
///
/// Coordination is achieved when the attack key exists (both T_A and T_B present).
#[derive(Debug)]
pub struct PeerCoordinator {
    /// The adaptive TGP protocol instance (includes flood controller).
    protocol: AdaptiveTGP,

    /// Coordinator configuration.
    config: CoordinatorConfig,

    /// Current coordinator state.
    state: CoordinatorState,

    /// When coordination started (for timeout tracking).
    started_at: Instant,
}

impl PeerCoordinator {
    /// Create a new peer coordinator with adaptive flooding.
    ///
    /// The coordinator immediately begins in drip mode, sending keepalive
    /// proofs at the minimum rate. Call [`set_active(true)`](Self::set_active)
    /// to ramp up to burst mode for fast coordination.
    ///
    /// # Arguments
    ///
    /// * `keypair` - This peer's Ed25519 signing key pair
    /// * `counterparty_key` - The counterparty's public key
    /// * `config` - Coordinator configuration
    ///
    /// # Deprecated
    ///
    /// Prefer [`symmetric()`](Self::symmetric) which automatically assigns
    /// party roles based on public key comparison.
    #[must_use]
    pub fn new(keypair: KeyPair, counterparty_key: PublicKey, config: CoordinatorConfig) -> Self {
        let party = if config.is_initiator {
            Party::Alice
        } else {
            Party::Bob
        };

        let protocol = if let Some(ref msg) = config.commitment_message {
            AdaptiveTGP::with_commitment_message(
                party,
                keypair,
                counterparty_key,
                msg.clone(),
                config.flood_rate.min_rate,
                config.flood_rate.max_rate,
            )
        } else {
            AdaptiveTGP::new(
                party,
                keypair,
                counterparty_key,
                config.flood_rate.min_rate,
                config.flood_rate.max_rate,
            )
        };

        debug!(
            party = ?party,
            timeout = ?config.timeout,
            min_rate = config.flood_rate.min_rate,
            max_rate = config.flood_rate.max_rate,
            "Created new peer coordinator with adaptive flooding"
        );

        Self {
            protocol,
            config,
            state: CoordinatorState::Coordinating,
            started_at: Instant::now(),
        }
    }

    /// Create a SYMMETRIC peer coordinator with adaptive flooding.
    ///
    /// Party role (Alice/Bob) is determined automatically from public key
    /// comparison - no need to coordinate who is "initiator". Both peers
    /// call this with the same parameters and get opposite roles.
    ///
    /// # Arguments
    ///
    /// * `keypair` - This peer's Ed25519 signing key pair
    /// * `counterparty_key` - The counterparty's public key
    /// * `config` - Coordinator configuration (is_initiator is ignored)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Both peers use the same constructor - roles are automatic
    /// let peer_a = PeerCoordinator::symmetric(kp_a, pk_b, config.clone());
    /// let peer_b = PeerCoordinator::symmetric(kp_b, pk_a, config);
    /// // They will have opposite Alice/Bob roles automatically
    /// ```
    #[must_use]
    pub fn symmetric(
        keypair: KeyPair,
        counterparty_key: PublicKey,
        config: CoordinatorConfig,
    ) -> Self {
        let protocol = if let Some(ref msg) = config.commitment_message {
            AdaptiveTGP::symmetric_with_commitment(
                keypair,
                counterparty_key,
                msg.clone(),
                config.flood_rate.min_rate,
                config.flood_rate.max_rate,
            )
        } else {
            AdaptiveTGP::symmetric(
                keypair,
                counterparty_key,
                config.flood_rate.min_rate,
                config.flood_rate.max_rate,
            )
        };

        debug!(
            timeout = ?config.timeout,
            min_rate = config.flood_rate.min_rate,
            max_rate = config.flood_rate.max_rate,
            "Created SYMMETRIC peer coordinator with adaptive flooding"
        );

        Self {
            protocol,
            config,
            state: CoordinatorState::Coordinating,
            started_at: Instant::now(),
        }
    }

    /// Get the current coordinator state.
    #[must_use]
    pub const fn state(&self) -> CoordinatorState {
        self.state
    }

    /// Get the underlying TGP protocol state.
    #[must_use]
    pub fn tgp_state(&self) -> ProtocolState {
        self.protocol.state()
    }

    /// Check if coordination has been achieved.
    #[must_use]
    pub fn is_coordinated(&self) -> bool {
        self.state == CoordinatorState::Coordinated
    }

    /// Check if the coordinator has been aborted.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.state == CoordinatorState::Aborted
    }

    /// Check if this peer can proceed with the coordinated action.
    #[must_use]
    pub fn can_proceed(&self) -> bool {
        self.is_coordinated() && self.protocol.can_attack()
    }

    /// Check if the coordinator has timed out.
    #[must_use]
    pub fn has_timed_out(&self) -> bool {
        if let Some(timeout) = self.config.timeout {
            self.started_at.elapsed() > timeout
        } else {
            false
        }
    }

    /// Set whether data transfer is active.
    ///
    /// When active, the flooder ramps up to burst mode for fast coordination.
    /// When inactive, it slowly decays to drip mode for keepalive.
    ///
    /// # Arguments
    ///
    /// * `active` - `true` to enable burst mode, `false` for drip mode
    pub fn set_active(&mut self, active: bool) {
        self.protocol.set_data_pending(active);
    }

    /// Abort the coordination.
    pub fn abort(&mut self) {
        if self.state == CoordinatorState::Coordinating {
            warn!("Aborting peer coordination");
            self.protocol.abort();
            self.state = CoordinatorState::Aborted;
        }
    }

    /// Poll for messages to send.
    ///
    /// This method should be called regularly (e.g., in a loop or timer).
    /// It returns messages when the adaptive flooder determines it's time
    /// to send based on the current rate.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(msgs))` - Messages to send to the counterparty
    /// - `Ok(None)` - Not time to send yet (rate limited)
    /// - `Err(_)` - Coordinator has been aborted or timed out
    pub fn poll(&mut self) -> Result<Option<Vec<Message>>> {
        // Check for timeout
        if self.has_timed_out() {
            self.abort();
            return Err(Error::Timeout(self.config.timeout.unwrap_or_default()));
        }

        // Check for abort
        if self.is_aborted() {
            return Err(Error::Aborted);
        }

        // NOTE: We do NOT stop sending when coordinated!
        // In TGP, after reaching Q state, we must continue flooding our Q proof
        // so the counterparty can receive it and also reach coordination.
        // The adaptive flooder will naturally decay to drip mode.

        // Get messages from the adaptive flooder (respects rate control)
        let messages = self.protocol.get_messages_to_send();

        if messages.is_empty() {
            return Ok(None);
        }

        trace!(
            message_count = messages.len(),
            rate = self.protocol.current_rate(),
            tgp_state = ?self.protocol.state(),
            "Generated flood messages"
        );

        Ok(Some(messages))
    }

    /// Receive a message from the counterparty.
    ///
    /// # Arguments
    ///
    /// * `msg` - The received TGP message
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Message advanced the protocol state
    /// - `Ok(false)` - Message was valid but didn't advance state
    /// - `Err(_)` - Message was invalid or coordinator aborted
    pub fn receive(&mut self, msg: &Message) -> Result<bool> {
        // Check for timeout
        if self.has_timed_out() {
            self.abort();
            return Err(Error::Timeout(self.config.timeout.unwrap_or_default()));
        }

        // Check for abort
        if self.is_aborted() {
            return Err(Error::Aborted);
        }

        // Already coordinated - ignore messages
        if self.is_coordinated() {
            return Ok(false);
        }

        // Process the message
        let advanced = self.protocol.receive(msg)?;

        trace!(
            advanced,
            tgp_state = ?self.protocol.state(),
            "Received coordination message"
        );

        // Check if we've achieved coordination
        if self.protocol.is_complete() {
            debug!("Coordination achieved!");
            self.state = CoordinatorState::Coordinated;
        }

        Ok(advanced)
    }

    /// Get the bilateral receipt if coordination is complete.
    #[must_use]
    pub fn get_bilateral_receipt(&self) -> Option<(&QuadProof, &QuadProof)> {
        if self.is_coordinated() {
            self.protocol.get_bilateral_receipt()
        } else {
            None
        }
    }

    /// Get the coordination decision.
    #[must_use]
    pub fn get_decision(&self) -> two_generals::Decision {
        self.protocol.get_decision()
    }

    /// Get the current flood rate in packets per second.
    #[must_use]
    pub fn current_rate(&self) -> u64 {
        self.protocol.current_rate()
    }

    /// Get the total number of packets sent.
    #[must_use]
    pub fn packet_count(&self) -> u64 {
        self.protocol.packet_count()
    }

    /// Get elapsed time since coordination started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get remaining time until timeout, if configured.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.config.timeout.map(|timeout| {
            let elapsed = self.started_at.elapsed();
            if elapsed >= timeout {
                Duration::ZERO
            } else {
                timeout - elapsed
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn create_keypairs() -> (KeyPair, KeyPair) {
        (KeyPair::generate(), KeyPair::generate())
    }

    #[test]
    fn test_coordinator_creation() {
        let (alice_kp, bob_kp) = create_keypairs();

        let alice = PeerCoordinator::new(
            alice_kp,
            bob_kp.public_key().clone(),
            CoordinatorConfig::initiator().with_flood_rate(FloodRateConfig::fast()),
        );

        assert_eq!(alice.state(), CoordinatorState::Coordinating);
        assert!(!alice.is_coordinated());
        assert!(!alice.is_aborted());
        assert!(!alice.can_proceed());
    }

    #[test]
    fn test_flood_rate_config() {
        let default = FloodRateConfig::default();
        assert_eq!(default.min_rate, 1);
        assert_eq!(default.max_rate, 10_000);

        let fast = FloodRateConfig::fast();
        assert_eq!(fast.min_rate, 100);
        assert_eq!(fast.max_rate, 100_000);

        let low = FloodRateConfig::low_bandwidth();
        assert_eq!(low.min_rate, 1);
        assert_eq!(low.max_rate, 1_000);
    }

    #[test]
    fn test_full_coordination_with_flooding() {
        let (alice_kp, bob_kp) = create_keypairs();

        // Use fast flood rates for test
        let config = CoordinatorConfig::initiator()
            .without_timeout()
            .with_flood_rate(FloodRateConfig::fast());

        let mut alice = PeerCoordinator::new(
            alice_kp.clone(),
            bob_kp.public_key().clone(),
            config.clone(),
        );

        let mut bob = PeerCoordinator::new(
            bob_kp,
            alice_kp.public_key().clone(),
            CoordinatorConfig::responder()
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        // Enable burst mode for fast coordination
        alice.set_active(true);
        bob.set_active(true);

        // Simulate continuous flooding with polling
        let mut rounds_after_first_complete = 0;
        for _ in 0..100 {
            // Alice polls and sends
            if let Ok(Some(messages)) = alice.poll() {
                for msg in messages {
                    let _ = bob.receive(&msg);
                }
            }

            // Bob polls and sends
            if let Ok(Some(messages)) = bob.poll() {
                for msg in messages {
                    let _ = alice.receive(&msg);
                }
            }

            // Track completion
            if alice.is_coordinated() || bob.is_coordinated() {
                rounds_after_first_complete += 1;
            }

            if alice.is_coordinated() && bob.is_coordinated() {
                break;
            }

            // Allow extra rounds for final Q exchange
            if rounds_after_first_complete > 10 {
                break;
            }

            // Small delay for rate control
            sleep(Duration::from_micros(100));
        }

        assert!(alice.is_coordinated(), "Alice should be coordinated");
        assert!(bob.is_coordinated(), "Bob should be coordinated");
        assert!(alice.can_proceed());
        assert!(bob.can_proceed());

        // Verify bilateral receipts
        assert!(alice.get_bilateral_receipt().is_some());
        assert!(bob.get_bilateral_receipt().is_some());

        // Verify packets were sent
        assert!(alice.packet_count() > 0);
        assert!(bob.packet_count() > 0);
    }

    #[test]
    fn test_rate_modulation() {
        let (alice_kp, bob_kp) = create_keypairs();

        let mut alice = PeerCoordinator::new(
            alice_kp,
            bob_kp.public_key().clone(),
            CoordinatorConfig::initiator()
                .without_timeout()
                .with_flood_rate(FloodRateConfig {
                    min_rate: 1,
                    max_rate: 1000,
                }),
        );

        // Initially in drip mode
        assert_eq!(alice.current_rate(), 1);

        // Enable burst mode
        alice.set_active(true);
        for _ in 0..20 {
            let _ = alice.poll();
            sleep(Duration::from_millis(1));
        }

        // Rate should have increased
        let burst_rate = alice.current_rate();
        assert!(
            burst_rate > 1,
            "Rate should increase in burst mode: {}",
            burst_rate
        );

        // Disable burst mode
        alice.set_active(false);
        for _ in 0..20 {
            let _ = alice.poll();
            sleep(Duration::from_millis(1));
        }

        // Rate should decrease
        let drip_rate = alice.current_rate();
        assert!(drip_rate < burst_rate, "Rate should decrease in drip mode");
    }

    #[test]
    fn test_coordinator_abort() {
        let (alice_kp, bob_kp) = create_keypairs();

        let mut alice = PeerCoordinator::new(
            alice_kp,
            bob_kp.public_key().clone(),
            CoordinatorConfig::initiator(),
        );

        alice.abort();

        assert!(alice.is_aborted());
        assert!(!alice.can_proceed());
        assert!(matches!(
            alice.get_decision(),
            two_generals::Decision::Abort
        ));
    }

    #[test]
    fn test_aborted_coordinator_rejects_poll() {
        let (alice_kp, bob_kp) = create_keypairs();

        let mut alice = PeerCoordinator::new(
            alice_kp,
            bob_kp.public_key().clone(),
            CoordinatorConfig::initiator(),
        );

        alice.abort();

        // Should return error when polling
        assert!(alice.poll().is_err());
    }

    #[test]
    fn test_symmetric_outcomes_with_flooding() {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        // Test with lossy channel - outcomes must be symmetric
        for seed in 0..10u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (alice_kp, bob_kp) = create_keypairs();

            let mut alice = PeerCoordinator::new(
                alice_kp.clone(),
                bob_kp.public_key().clone(),
                CoordinatorConfig::initiator()
                    .without_timeout()
                    .with_flood_rate(FloodRateConfig::fast()),
            );

            let mut bob = PeerCoordinator::new(
                bob_kp,
                alice_kp.public_key().clone(),
                CoordinatorConfig::responder()
                    .without_timeout()
                    .with_flood_rate(FloodRateConfig::fast()),
            );

            alice.set_active(true);
            bob.set_active(true);

            // Run with 50% packet loss
            let mut rounds_after_first_complete = 0;
            for _ in 0..500 {
                if let Ok(Some(messages)) = alice.poll() {
                    for msg in messages {
                        if rng.gen_bool(0.5) {
                            let _ = bob.receive(&msg);
                        }
                    }
                }

                if let Ok(Some(messages)) = bob.poll() {
                    for msg in messages {
                        if rng.gen_bool(0.5) {
                            let _ = alice.receive(&msg);
                        }
                    }
                }

                if alice.is_coordinated() || bob.is_coordinated() {
                    rounds_after_first_complete += 1;
                }

                if alice.is_coordinated() && bob.is_coordinated() {
                    break;
                }

                if rounds_after_first_complete > 50 {
                    break;
                }

                sleep(Duration::from_micros(10));
            }

            // Verify symmetric outcome
            let alice_can = alice.can_proceed();
            let bob_can = bob.can_proceed();

            assert_eq!(
                alice_can, bob_can,
                "Asymmetric outcome detected! Alice: {}, Bob: {} (seed={})",
                alice_can, bob_can, seed
            );
        }
    }

    #[test]
    fn test_coordinator_state_display() {
        assert_eq!(
            format!("{}", CoordinatorState::Coordinating),
            "Coordinating"
        );
        assert_eq!(format!("{}", CoordinatorState::Coordinated), "Coordinated");
        assert_eq!(format!("{}", CoordinatorState::Aborted), "Aborted");
    }
}
