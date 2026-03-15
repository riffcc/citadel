//! Unix socket server for admin commands.
//!
//! Provides a local IPC interface for managing users, uploaders, and admins.

use crate::error::Result;
use crate::mesh::FloodMessage;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

/// Admin command sent over the socket.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminCommand {
    /// Add an admin
    AddAdmin { public_key: String },
    /// Remove an admin
    RemoveAdmin { public_key: String },
    /// Grant upload permission
    GrantUpload { public_key: String },
    /// Revoke upload permission
    RevokeUpload { public_key: String },
    /// List all admins
    ListAdmins,
    /// Check if a key is admin
    IsAdmin { public_key: String },
    /// Ping (health check)
    Ping,
    /// Start CPU/memory profiling
    StartProfiling,
    /// Stop profiling
    StopProfiling,
    /// Get CPU profile data
    CpuProfile,
    /// Get memory profile data
    MemProfile,
    /// Get mesh connection stats
    MeshStats,
}

/// Response from admin command.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok { message: String },
    Error { error: String },
    List { items: Vec<String> },
    Bool { value: bool },
    Pong,
    Profile { data: serde_json::Value },
}

/// Admin socket server.
pub struct AdminSocket {
    storage: Arc<Storage>,
    socket_path: String,
    flood_tx: Option<broadcast::Sender<FloodMessage>>,
}

impl AdminSocket {
    /// Create a new admin socket server.
    pub fn new(storage: Arc<Storage>, socket_path: &str) -> Self {
        Self {
            storage,
            socket_path: socket_path.to_string(),
            flood_tx: None,
        }
    }

    /// Set the flood sender for mesh propagation.
    pub fn with_flood_tx(mut self, tx: broadcast::Sender<FloodMessage>) -> Self {
        self.flood_tx = Some(tx);
        self
    }

    /// Run the admin socket server.
    pub async fn run(&self) -> Result<()> {
        // Remove existing socket file if present
        let _ = std::fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)?;
        tracing::info!("Admin socket listening on {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let storage = Arc::clone(&self.storage);
                    let flood_tx = self.flood_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, storage, flood_tx).await {
                            tracing::error!("Admin connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept admin connection: {}", e);
                }
            }
        }
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}

async fn handle_connection(
    stream: UnixStream,
    storage: Arc<Storage>,
    flood_tx: Option<broadcast::Sender<FloodMessage>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = match serde_json::from_str::<AdminCommand>(&line) {
            Ok(cmd) => execute_command(cmd, &storage, &flood_tx),
            Err(e) => AdminResponse::Error {
                error: format!("Invalid command: {}", e),
            },
        };

        let response_json = serde_json::to_string(&response)? + "\n";
        writer.write_all(response_json.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

/// Flood the current admin list to the mesh
fn flood_admins(storage: &Arc<Storage>, flood_tx: &Option<broadcast::Sender<FloodMessage>>) {
    if let Some(tx) = flood_tx {
        if let Ok(admins) = storage.list_admins() {
            let _ = tx.send(FloodMessage::Admins(admins));
            tracing::info!("Flooded admin list to mesh");
        }
    }
}

fn execute_command(
    cmd: AdminCommand,
    storage: &Arc<Storage>,
    flood_tx: &Option<broadcast::Sender<FloodMessage>>,
) -> AdminResponse {
    match cmd {
        AdminCommand::AddAdmin { public_key } => {
            match storage.set_admin(&public_key, true) {
                Ok(()) => {
                    tracing::info!("Added admin: {}", public_key);
                    // Flood updated admin list to mesh
                    flood_admins(storage, flood_tx);
                    AdminResponse::Ok {
                        message: format!("Added admin: {}", public_key),
                    }
                }
                Err(e) => AdminResponse::Error {
                    error: e.to_string(),
                },
            }
        }

        AdminCommand::RemoveAdmin { public_key } => {
            match storage.set_admin(&public_key, false) {
                Ok(()) => {
                    tracing::info!("Removed admin: {}", public_key);
                    // Flood updated admin list to mesh
                    flood_admins(storage, flood_tx);
                    AdminResponse::Ok {
                        message: format!("Removed admin: {}", public_key),
                    }
                }
                Err(e) => AdminResponse::Error {
                    error: e.to_string(),
                },
            }
        }

        AdminCommand::GrantUpload { public_key } => {
            match storage.grant_permission(&public_key, "upload") {
                Ok(()) => {
                    tracing::info!("Granted upload to: {}", public_key);
                    AdminResponse::Ok {
                        message: format!("Granted upload permission to: {}", public_key),
                    }
                }
                Err(e) => AdminResponse::Error {
                    error: e.to_string(),
                },
            }
        }

        AdminCommand::RevokeUpload { public_key } => {
            match storage.revoke_permission(&public_key, "upload") {
                Ok(()) => {
                    tracing::info!("Revoked upload from: {}", public_key);
                    AdminResponse::Ok {
                        message: format!("Revoked upload permission from: {}", public_key),
                    }
                }
                Err(e) => AdminResponse::Error {
                    error: e.to_string(),
                },
            }
        }

        AdminCommand::ListAdmins => match storage.list_admins() {
            Ok(admins) => AdminResponse::List { items: admins },
            Err(e) => AdminResponse::Error {
                error: e.to_string(),
            },
        },

        AdminCommand::IsAdmin { public_key } => match storage.is_admin(&public_key) {
            Ok(is_admin) => AdminResponse::Bool { value: is_admin },
            Err(e) => AdminResponse::Error {
                error: e.to_string(),
            },
        },

        AdminCommand::Ping => AdminResponse::Pong,

        AdminCommand::StartProfiling => {
            tracing::info!("Profiling mode enabled");
            AdminResponse::Ok {
                message: "Profiling enabled. cpu-profile will auto-collect when called."
                    .to_string(),
            }
        }

        AdminCommand::StopProfiling => {
            tracing::info!("Profiling stopped");
            AdminResponse::Ok {
                message: "Profiling stopped.".to_string(),
            }
        }

        AdminCommand::CpuProfile => {
            // Auto-start profiler, collect for 5 seconds, return flamegraph
            tracing::info!("CPU profiling: collecting for 5 seconds...");
            match collect_cpu_profile(5) {
                Ok(profile_data) => AdminResponse::Profile { data: profile_data },
                Err(e) => AdminResponse::Error {
                    error: e.to_string(),
                },
            }
        }

        AdminCommand::MemProfile => {
            // Get memory stats + allocation info
            let mem_data = get_memory_stats();
            AdminResponse::Profile { data: mem_data }
        }

        AdminCommand::MeshStats => {
            // Note: This handler doesn't have access to mesh state
            // Return error suggesting to use the HTTP API instead
            AdminResponse::Error {
                error: "Mesh stats not available via socket. Use HTTP API with --url flag."
                    .to_string(),
            }
        }
    }
}

/// Collect CPU profile using pprof for N seconds
/// Returns flamegraph data and top functions
pub fn collect_cpu_profile(
    duration_secs: u64,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    use pprof::ProfilerGuard;

    // Start the profiler (100 Hz sampling)
    let guard = ProfilerGuard::new(100)?;

    // Wait for the specified duration
    std::thread::sleep(std::time::Duration::from_secs(duration_secs));

    // Build the report
    let report = guard.report().build()?;

    let mut result = serde_json::Map::new();
    result.insert(
        "duration_secs".to_string(),
        serde_json::json!(duration_secs),
    );
    result.insert("sample_rate_hz".to_string(), serde_json::json!(100));

    // Get flamegraph as SVG
    let mut flamegraph_svg = Vec::new();
    if report.flamegraph(&mut flamegraph_svg).is_ok() {
        // Base64 encode the SVG for JSON transport
        result.insert(
            "flamegraph_svg_base64".to_string(),
            serde_json::json!(base64_encode(&flamegraph_svg)),
        );
        result.insert(
            "flamegraph_size_bytes".to_string(),
            serde_json::json!(flamegraph_svg.len()),
        );
    }

    // Get top frames for quick view
    let mut top_frames = Vec::new();
    for (frames, count) in report.data.iter().take(20) {
        let frame_names: Vec<String> = frames.frames.iter().flatten().map(|f| f.name()).collect();
        if !frame_names.is_empty() {
            top_frames.push(serde_json::json!({
                "count": count,
                "stack": frame_names,
            }));
        }
    }
    result.insert("top_stacks".to_string(), serde_json::json!(top_frames));

    // Add timestamp
    result.insert(
        "timestamp".to_string(),
        serde_json::json!(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    );

    Ok(serde_json::Value::Object(result))
}

/// Simple base64 encoding
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Get memory statistics from /proc/self/status and /proc/self/smaps
pub fn get_memory_stats() -> serde_json::Value {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut result = serde_json::Map::new();

    // Read /proc/self/status for memory info
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("rss_kb".to_string(), serde_json::json!(kb));
                        result.insert("rss_mb".to_string(), serde_json::json!(kb / 1024));
                    }
                }
            } else if line.starts_with("VmSize:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("vm_size_kb".to_string(), serde_json::json!(kb));
                        result.insert("vm_size_mb".to_string(), serde_json::json!(kb / 1024));
                    }
                }
            } else if line.starts_with("VmPeak:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("vm_peak_mb".to_string(), serde_json::json!(kb / 1024));
                    }
                }
            } else if line.starts_with("VmHWM:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("rss_peak_mb".to_string(), serde_json::json!(kb / 1024));
                    }
                }
            } else if line.starts_with("VmData:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("heap_kb".to_string(), serde_json::json!(kb));
                    }
                }
            } else if line.starts_with("VmStk:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = val.parse::<u64>() {
                        result.insert("stack_kb".to_string(), serde_json::json!(kb));
                    }
                }
            } else if line.starts_with("Threads:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(threads) = val.parse::<u64>() {
                        result.insert("threads".to_string(), serde_json::json!(threads));
                    }
                }
            }
        }
    }

    // Read /proc/self/stat for additional CPU info
    if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
        let parts: Vec<&str> = stat.split_whitespace().collect();
        if parts.len() > 22 {
            if let (Ok(utime), Ok(stime)) = (parts[13].parse::<u64>(), parts[14].parse::<u64>()) {
                let ticks_per_sec = 100u64;
                result.insert(
                    "cpu_user_secs".to_string(),
                    serde_json::json!(utime / ticks_per_sec),
                );
                result.insert(
                    "cpu_system_secs".to_string(),
                    serde_json::json!(stime / ticks_per_sec),
                );
            }
        }
    }

    // Add timestamp
    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
        result.insert("timestamp".to_string(), serde_json::json!(now.as_secs()));
    }

    serde_json::Value::Object(result)
}

/// Default socket path.
pub fn default_socket_path() -> String {
    "./lens-data/admin.sock".to_string()
}
