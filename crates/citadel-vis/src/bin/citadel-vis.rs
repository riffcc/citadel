//! Citadel Mesh Visualization Server
//!
//! Run a simulation and serve the visualization frontend.

use citadel_vis::{Simulation, SimulationConfig, VisServer};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line args
    let args: Vec<String> = env::args().collect();

    let node_count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);

    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3000);

    println!("Citadel Mesh Visualizer");
    println!("=======================");
    println!();
    println!("Assembling mesh with {} nodes...", node_count);

    // Create and run simulation
    let mut sim = Simulation::new(SimulationConfig::default());
    for i in 0..node_count {
        sim.add_node();
        if (i + 1) % 100 == 0 {
            println!("  Added {} nodes...", i + 1);
        }
    }

    println!();
    println!("Simulation complete:");
    println!("  Nodes: {}", sim.node_count());
    println!("  Events: {}", sim.event_count());
    println!();
    println!("Starting visualization server on http://localhost:{}", port);
    println!("Open in browser to view mesh assembly playback.");
    println!();

    // Start server
    let server = VisServer::new(sim);
    server.serve(port).await?;

    Ok(())
}
