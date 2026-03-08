//! Citadel Mesh Visualization
//!
//! Real-time visualization of mesh self-assembly with playback controls.
//!
//! # Architecture
//!
//! - **Simulation**: Records mesh assembly events into a timeline
//! - **Playback**: Scrub through timeline at any speed
//! - **WebSocket**: Streams events to Vue.js frontend
//! - **REST API**: Control playback, get mesh state
//!
//! # Usage
//!
//! ```ignore
//! let mut sim = Simulation::new();
//! sim.run_assembly(1000); // Assemble 1000 nodes
//!
//! let server = VisServer::new(sim);
//! server.serve(3000).await;
//! ```

mod events;
mod playback;
mod server;
mod simulation;

pub use events::{ConnectionState as ConnState, MeshEvent, NodeState};
pub use playback::{Playback, PlaybackSpeed, PlaybackState};
pub use server::VisServer;
pub use simulation::{Simulation, SimulationConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_records_events() {
        let mut sim = Simulation::new(SimulationConfig::default());
        sim.add_node();
        sim.add_node();
        sim.add_node();

        // Events include NodeJoined + connections, so count >= node_count
        assert!(sim.event_count() >= 3);
        assert_eq!(sim.node_count(), 3);
    }

    #[test]
    fn playback_can_seek() {
        let mut sim = Simulation::new(SimulationConfig::default());
        for _ in 0..10 {
            sim.add_node();
        }

        let total_events = sim.event_count();
        let mut playback = Playback::new(sim.events().to_vec());

        // Start at beginning
        assert_eq!(playback.current_frame(), 0);

        // Seek to middle
        playback.seek(total_events / 2);
        assert_eq!(playback.current_frame(), total_events / 2);

        // Seek to end
        playback.seek(total_events);
        assert_eq!(playback.current_frame(), total_events);
    }

    #[test]
    fn playback_respects_bounds() {
        let mut sim = Simulation::new(SimulationConfig::default());
        for _ in 0..5 {
            sim.add_node();
        }

        let total_events = sim.event_count();
        let mut playback = Playback::new(sim.events().to_vec());

        // Can't seek past end
        playback.seek(1000);
        assert_eq!(playback.current_frame(), total_events);

        // Can't seek before start
        playback.seek(0);
        assert_eq!(playback.current_frame(), 0);
    }
}
