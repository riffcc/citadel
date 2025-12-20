//! Lens Node binary
//!
//! A Citadel mesh node for distributed content distribution.

use citadel_lens::{LensConfig, LensNode};
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Lens Node - Citadel mesh node for distributed content distribution
#[derive(Parser, Debug)]
#[command(name = "lens-node")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Data directory for storage
    #[arg(short = 'd', long, env = "LENS_DATA_DIR")]
    data_dir: Option<String>,

    /// HTTP API listen address
    #[arg(long, env = "LENS_API_BIND")]
    api_bind: Option<String>,

    /// P2P listen address (for mesh)
    #[arg(long, env = "LENS_P2P_BIND")]
    p2p_bind: Option<String>,

    /// P2P announce address (public IP:port for other peers)
    #[arg(long, env = "LENS_ANNOUNCE_ADDR")]
    announce_addr: Option<String>,

    /// Bootstrap peers (comma-separated list of host:port or DNS names)
    #[arg(short = 'p', long, env = "CITADEL_PEERS", value_delimiter = ',')]
    peers: Option<Vec<String>>,

    /// Admin socket path (for lens-admin CLI)
    #[arg(long, env = "LENS_ADMIN_SOCKET")]
    admin_socket: Option<String>,

    /// Initial admin public key(s) (comma-separated hex-encoded ed25519 keys)
    #[arg(long, env = "ADMIN_PUBLIC_KEY")]
    admin_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI args first (clap handles -h/--help automatically)
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lens_node=info,citadel=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Lens Node");

    // Build config from CLI args (which includes env var fallbacks via clap)
    let config = LensConfig::from_cli(
        cli.data_dir,
        cli.api_bind,
        cli.p2p_bind,
        cli.announce_addr,
        cli.peers,
        cli.admin_socket,
        cli.admin_key,
    );

    // Create and run node
    let node = LensNode::new(config).await?;
    node.run().await?;

    Ok(())
}
