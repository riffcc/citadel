//! lens-admin CLI tool
//!
//! Manages Lens nodes locally (via Unix socket) or remotely (via HTTP API).
//!
//! # Configuration
//!
//! On first run of `lens-admin init`, creates ~/.citadel/ with:
//! - auth.key: Ed25519 keypair for signing API requests
//!
//! # Usage
//!
//! Local (Unix socket):
//!   lens-admin ping
//!   lens-admin add-admin <public_key>
//!
//! Remote (HTTP API):
//!   lens-admin --url https://lens.example.com ping
//!   lens-admin --url https://lens.example.com upload ./folder/
//!
//! Setup:
//!   lens-admin init     # Generate keypair
//!   lens-admin show     # Show configuration

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Lens node administration tool
#[derive(Parser)]
#[command(name = "lens-admin")]
#[command(about = "Manage Lens nodes locally or remotely")]
struct Cli {
    /// Remote Lens API URL (if not provided, uses local Unix socket)
    #[arg(long, short, env = "LENS_URL")]
    url: Option<String>,

    /// Archivist base URL for uploads (e.g. https://archivist.example.com)
    #[arg(long, env = "ARCHIVIST_URL")]
    archivist: Option<String>,

    /// Path to config directory (default: ~/.citadel)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Path to lens-node data directory (for local socket mode)
    #[arg(short = 'd', long)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize configuration (generate keypair)
    Init,

    /// Show configuration (public key, API URL, etc.)
    Show,

    /// Check if node is running
    Ping,

    /// Add an admin by public key
    AddAdmin {
        /// Hex-encoded public key
        public_key: String,
    },

    /// Remove an admin by public key
    RemoveAdmin {
        /// Hex-encoded public key
        public_key: String,
    },

    /// Grant upload permission to a public key
    GrantUpload {
        /// Hex-encoded public key
        public_key: String,
    },

    /// Revoke upload permission from a public key
    RevokeUpload {
        /// Hex-encoded public key
        public_key: String,
    },

    /// List all admins
    ListAdmins,

    /// Check if a public key is an admin
    IsAdmin {
        /// Hex-encoded public key
        public_key: String,
    },

    /// Upload a file or folder to the node
    Upload {
        /// Path to file or folder to upload
        path: PathBuf,
    },

    /// Start CPU/memory profiling (recording begins)
    StartProfiling,

    /// Stop profiling and return to normal operation
    StopProfiling,

    /// Get CPU profile data (requires profiling to be active)
    CpuProfile,

    /// Get memory profile data (requires profiling to be active)
    MemProfile,

    /// Get mesh connection statistics (always available, no profiling needed)
    MeshStats,

    /// List all releases
    ListReleases,

    /// Get a release by ID
    GetRelease {
        /// Release ID
        id: String,
    },

    /// Update a release (provide fields as JSON)
    UpdateRelease {
        /// Release ID
        id: String,
        /// JSON body with fields to update (e.g. '{"contentCID":"..."}')
        #[arg(long, short)]
        json: String,
    },

    /// Create a new release from JSON
    CreateRelease {
        /// JSON body for the new release
        #[arg(long, short)]
        json: String,
    },
}

/// Admin command sent over the socket (legacy local mode)
#[derive(Debug, Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum AdminCommand {
    AddAdmin { public_key: String },
    RemoveAdmin { public_key: String },
    GrantUpload { public_key: String },
    RevokeUpload { public_key: String },
    ListAdmins,
    IsAdmin { public_key: String },
    Ping,
    StartProfiling,
    StopProfiling,
    CpuProfile,
    MemProfile,
    MeshStats,
}

/// Response from admin command
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AdminResponse {
    Ok { message: String },
    Error { error: String },
    List { items: Vec<String> },
    Bool { value: bool },
    Pong,
    Profile { data: serde_json::Value },
}

/// Get the config directory path
fn get_config_dir(cli_config: Option<&PathBuf>) -> PathBuf {
    if let Some(config) = cli_config {
        config.clone()
    } else {
        dirs::home_dir()
            .expect("Could not find home directory")
            .join(".citadel")
    }
}

/// Get the keypair file path
fn get_keypair_path(config_dir: &PathBuf) -> PathBuf {
    config_dir.join("auth.key")
}

/// Load or generate keypair
fn load_keypair(config_dir: &PathBuf) -> Result<SigningKey, String> {
    let keypair_path = get_keypair_path(config_dir);

    if keypair_path.exists() {
        let key_bytes =
            fs::read(&keypair_path).map_err(|e| format!("Failed to read keypair: {}", e))?;

        if key_bytes.len() != SECRET_KEY_LENGTH {
            return Err(format!(
                "Invalid keypair file: expected {} bytes, got {}",
                SECRET_KEY_LENGTH,
                key_bytes.len()
            ));
        }

        let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
        secret_bytes.copy_from_slice(&key_bytes);
        Ok(SigningKey::from_bytes(&secret_bytes))
    } else {
        Err(format!(
            "No keypair found at {:?}\nRun 'lens-admin init' first",
            keypair_path
        ))
    }
}

/// Initialize configuration
fn cmd_init(config_dir: &PathBuf) -> Result<(), String> {
    // Create config directory
    fs::create_dir_all(config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;

    let keypair_path = get_keypair_path(config_dir);

    if keypair_path.exists() {
        return Err(format!(
            "Keypair already exists at {:?}\nDelete it first if you want to regenerate",
            keypair_path
        ));
    }

    // Generate new keypair
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Save private key
    fs::write(&keypair_path, signing_key.to_bytes())
        .map_err(|e| format!("Failed to write keypair: {}", e))?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&keypair_path, perms)
            .map_err(|e| format!("Failed to set keypair permissions: {}", e))?;
    }

    println!("Initialized lens-admin configuration");
    println!();
    println!("Config directory: {:?}", config_dir);
    println!("Keypair file:     {:?}", keypair_path);
    println!();
    println!("Your public key:");
    println!("  ed25519p/{}", hex::encode(verifying_key.to_bytes()));
    println!();
    println!("Add this key as an admin on your Lens node to authenticate.");

    Ok(())
}

/// Show configuration
fn cmd_show(
    config_dir: &PathBuf,
    api_url: Option<&String>,
    data_dir: Option<&PathBuf>,
) -> Result<(), String> {
    println!("lens-admin configuration");
    println!("========================");
    println!();
    println!("Config directory: {:?}", config_dir);

    let keypair_path = get_keypair_path(config_dir);
    if keypair_path.exists() {
        let signing_key = load_keypair(config_dir)?;
        let verifying_key = signing_key.verifying_key();
        println!("Keypair file:     {:?}", keypair_path);
        println!();
        println!("Public key:");
        println!("  ed25519p/{}", hex::encode(verifying_key.to_bytes()));
    } else {
        println!("Keypair file:     (not initialized)");
        println!();
        println!("Run 'lens-admin init' to generate a keypair.");
    }

    println!();
    if let Some(url) = api_url {
        println!("API URL: {}", url);
    } else {
        let socket_path = get_socket_path(data_dir);
        println!("Mode: Local (Unix socket)");
        println!("Socket: {:?}", socket_path);
    }

    Ok(())
}

fn get_socket_path(data_dir: Option<&PathBuf>) -> PathBuf {
    if let Some(dir) = data_dir {
        return dir.join("admin.sock");
    }
    PathBuf::from("./lens-data/admin.sock")
}

/// Send command via local Unix socket
fn send_socket_command(
    cmd: AdminCommand,
    data_dir: Option<&PathBuf>,
) -> Result<AdminResponse, String> {
    let socket_path = get_socket_path(data_dir);

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        format!(
            "Failed to connect to lens-node at {:?}: {}\n\
             Is the lens-node running?",
            socket_path, e
        )
    })?;

    // Send command
    let cmd_json = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    writeln!(stream, "{}", cmd_json).map_err(|e| e.to_string())?;

    // Read response
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| e.to_string())?;

    serde_json::from_str(&response_line).map_err(|e| format!("Invalid response: {}", e))
}

/// Create signed request headers for upload API
fn create_auth_headers(signing_key: &SigningKey) -> Result<Vec<(String, String)>, String> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = format!("ed25519p/{}", hex::encode(verifying_key.to_bytes()));

    // Sign "{timestamp}:UPLOAD" as expected by validate_upload endpoint
    let message = format!("{}:UPLOAD", timestamp);
    let signature = signing_key.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(vec![
        ("X-Pubkey".to_string(), public_key_hex),
        ("X-Timestamp".to_string(), timestamp),
        ("X-Signature".to_string(), signature_hex),
    ])
}

/// Create signed headers for the release API.
///
/// The release API expects `X-Public-Key`, `X-Signature`, `X-Timestamp`
/// where the signature covers `{timestamp}:{body}`.
fn create_release_auth_headers(
    signing_key: &SigningKey,
    body: &str,
) -> Result<Vec<(String, String)>, String> {
    let timestamp = chrono::Utc::now().timestamp_millis().to_string();
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = format!("ed25519p/{}", hex::encode(verifying_key.to_bytes()));

    let message = format!("{}:{}", timestamp, body);
    let signature = signing_key.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(vec![
        ("X-Public-Key".to_string(), public_key_hex),
        ("X-Timestamp".to_string(), timestamp),
        ("X-Signature".to_string(), signature_hex),
    ])
}

/// Send command via HTTP API
async fn send_http_command(
    client: &reqwest::Client,
    base_url: &str,
    signing_key: &SigningKey,
    cmd: AdminCommand,
) -> Result<AdminResponse, String> {
    let headers = create_auth_headers(signing_key)?;

    let endpoint = match &cmd {
        AdminCommand::Ping => "/api/admin/ping",
        AdminCommand::AddAdmin { .. } => "/api/admin/add-admin",
        AdminCommand::RemoveAdmin { .. } => "/api/admin/remove-admin",
        AdminCommand::GrantUpload { .. } => "/api/admin/grant-upload",
        AdminCommand::RevokeUpload { .. } => "/api/admin/revoke-upload",
        AdminCommand::ListAdmins => "/api/admin/list-admins",
        AdminCommand::IsAdmin { .. } => "/api/admin/is-admin",
        AdminCommand::StartProfiling => "/api/admin/start-profiling",
        AdminCommand::StopProfiling => "/api/admin/stop-profiling",
        AdminCommand::CpuProfile => "/api/admin/cpu-profile",
        AdminCommand::MemProfile => "/api/admin/mem-profile",
        AdminCommand::MeshStats => "/api/admin/mesh-stats",
    };

    let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

    let mut req = client.post(&url);
    for (key, value) in headers {
        req = req.header(&key, &value);
    }

    let response = req
        .json(&cmd)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error ({}): {}", status, body));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))
}

/// List all releases from the Lens API
async fn cmd_list_releases(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<(), String> {
    let url = format!("{}/api/v1/releases", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error ({}): {}", status, body));
    }

    let body = response.text().await.map_err(|e| format!("Read error: {}", e))?;
    let releases: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("Parse error: {}", e))?;

    for release in &releases {
        let id = release["id"].as_str().unwrap_or("?");
        let name = release["name"].as_str().unwrap_or("Untitled");
        let cid = release["contentCID"].as_str().unwrap_or("none");
        let status = release["status"].as_str().unwrap_or("?");
        println!("[{}] {} (content: {}) - {}", status, name, cid, id);
    }
    println!("\n{} releases total", releases.len());
    Ok(())
}

/// Get a single release by ID
async fn cmd_get_release(
    client: &reqwest::Client,
    base_url: &str,
    id: &str,
) -> Result<(), String> {
    let url = format!("{}/api/v1/releases/{}", base_url.trim_end_matches('/'), id);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error ({}): {}", status, body));
    }

    let body = response.text().await.map_err(|e| format!("Read error: {}", e))?;
    let release: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Parse error: {}", e))?;
    println!("{}", serde_json::to_string_pretty(&release).unwrap());
    Ok(())
}

/// Update a release by ID with a JSON body
async fn cmd_update_release(
    client: &reqwest::Client,
    base_url: &str,
    signing_key: &SigningKey,
    id: &str,
    json_body: &str,
) -> Result<(), String> {
    // Validate JSON
    let _: serde_json::Value =
        serde_json::from_str(json_body).map_err(|e| format!("Invalid JSON: {}", e))?;

    let url = format!("{}/api/v1/releases/{}", base_url.trim_end_matches('/'), id);
    let headers = create_release_auth_headers(signing_key, json_body)?;

    let mut req = client.put(&url);
    for (key, value) in headers {
        req = req.header(&key, &value);
    }

    let response = req
        .header("Content-Type", "application/json")
        .body(json_body.to_string())
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error ({}): {}", status, body));
    }

    let body = response.text().await.map_err(|e| format!("Read error: {}", e))?;
    let release: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Parse error: {}", e))?;
    println!("Updated release:");
    println!("{}", serde_json::to_string_pretty(&release).unwrap());
    Ok(())
}

/// Create a new release from JSON
async fn cmd_create_release(
    client: &reqwest::Client,
    base_url: &str,
    signing_key: &SigningKey,
    json_body: &str,
) -> Result<(), String> {
    let _: serde_json::Value =
        serde_json::from_str(json_body).map_err(|e| format!("Invalid JSON: {}", e))?;

    let url = format!("{}/api/v1/releases", base_url.trim_end_matches('/'));
    let headers = create_release_auth_headers(signing_key, json_body)?;

    let mut req = client.post(&url);
    for (key, value) in headers {
        req = req.header(&key, &value);
    }

    let response = req
        .header("Content-Type", "application/json")
        .body(json_body.to_string())
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error ({}): {}", status, body));
    }

    let body = response.text().await.map_err(|e| format!("Read error: {}", e))?;
    let release: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Parse error: {}", e))?;
    println!("Created release:");
    println!("{}", serde_json::to_string_pretty(&release).unwrap());
    Ok(())
}

/// Upload a file or folder to Archivist
async fn cmd_upload(
    client: &reqwest::Client,
    archivist_url: &str,
    signing_key: &SigningKey,
    path: &PathBuf,
) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {:?}", path));
    }

    let headers = create_auth_headers(signing_key)?;

    if path.is_file() {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");

        let cid = upload_file(client, archivist_url, &headers, path).await?;
        println!("Uploaded: {}", file_name);
        println!("CID: {}", cid);
        Ok(())
    } else if path.is_dir() {
        upload_directory(client, archivist_url, &headers, path).await
    } else {
        Err(format!("Path is neither a file nor directory: {:?}", path))
    }
}

/// Upload a single file to Archivist
async fn upload_file(
    client: &reqwest::Client,
    archivist_url: &str,
    headers: &[(String, String)],
    path: &PathBuf,
) -> Result<String, String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let file_bytes = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Guess content type from extension
    let content_type = match path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("flac") => "audio/flac",
        Some("ogg") => "audio/ogg",
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        _ => "application/octet-stream",
    };

    // Archivist upload endpoint: POST /api/archivist/v1/data
    let url = format!(
        "{}/api/archivist/v1/data",
        archivist_url.trim_end_matches('/')
    );

    let mut req = client.post(&url);

    // Add auth headers (X-Pubkey, X-Signature, X-Timestamp)
    for (key, value) in headers {
        req = req.header(key, value);
    }

    // Add content headers
    req = req.header("content-type", content_type).header(
        "content-disposition",
        format!("attachment; filename=\"{}\"", file_name),
    );

    let response = req
        .body(file_bytes)
        .send()
        .await
        .map_err(|e| format!("Upload failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Upload failed ({}): {}", status, body));
    }

    // Archivist returns CID as plain text
    let cid = response
        .text()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?
        .trim()
        .to_string();

    Ok(cid)
}

/// Upload a directory recursively
async fn upload_directory(
    client: &reqwest::Client,
    archivist_url: &str,
    headers: &[(String, String)],
    path: &PathBuf,
) -> Result<(), String> {
    let entries: Vec<_> = walkdir(path)?;
    let file_count = entries.iter().filter(|e| e.is_file()).count();

    println!("Uploading {} files from {:?}", file_count, path);
    println!();

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in entries {
        if entry.is_file() {
            let relative = entry.strip_prefix(path).unwrap_or(&entry);
            print!("  {} ... ", relative.display());
            std::io::stdout().flush().ok();

            match upload_file(client, archivist_url, headers, &entry).await {
                Ok(cid) => {
                    println!("{}", cid);
                    success_count += 1;
                }
                Err(e) => {
                    println!("FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!();
    println!("Done: {} succeeded, {} failed", success_count, fail_count);

    if fail_count > 0 {
        Err(format!("{} uploads failed", fail_count))
    } else {
        Ok(())
    }
}

/// Walk directory recursively
fn walkdir(path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    let mut entries = Vec::new();

    fn walk_recursive(dir: &PathBuf, entries: &mut Vec<PathBuf>) -> Result<(), String> {
        let read_dir =
            fs::read_dir(dir).map_err(|e| format!("Failed to read directory {:?}: {}", dir, e))?;

        for entry in read_dir {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();

            if path.is_dir() {
                walk_recursive(&path, entries)?;
            } else {
                entries.push(path);
            }
        }
        Ok(())
    }

    walk_recursive(path, &mut entries)?;
    Ok(entries)
}

/// Handle admin response
fn handle_response(response: AdminResponse) -> Result<(), String> {
    match response {
        AdminResponse::Ok { message } => {
            println!("{}", message);
            Ok(())
        }
        AdminResponse::Error { error } => Err(error),
        AdminResponse::List { items } => {
            if items.is_empty() {
                println!("(none)");
            } else {
                for item in items {
                    println!("{}", item);
                }
            }
            Ok(())
        }
        AdminResponse::Bool { value } => {
            println!("{}", value);
            if !value {
                std::process::exit(1);
            }
            Ok(())
        }
        AdminResponse::Pong => {
            println!("pong - lens-node is running");
            Ok(())
        }
        AdminResponse::Profile { data } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
            );
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let config_dir = get_config_dir(cli.config.as_ref());
    let data_dir = cli.data_dir.as_ref();

    match cli.command {
        Commands::Init => cmd_init(&config_dir),
        Commands::Show => cmd_show(&config_dir, cli.url.as_ref(), data_dir),

        // Upload goes directly to Archivist (auth validated by Lens via forward_auth)
        Commands::Upload { path } => {
            let archivist_url = cli
                .archivist
                .as_ref()
                .ok_or("Upload requires --archivist <URL> for the Archivist endpoint")?;

            let signing_key = load_keypair(&config_dir)?;
            let client = reqwest::Client::new();
            cmd_upload(&client, archivist_url, &signing_key, &path).await
        }

        // Release commands go directly to the Lens release API
        Commands::ListReleases => {
            let url = cli.url.as_ref().ok_or("list-releases requires --url <URL>")?;
            let client = reqwest::Client::new();
            cmd_list_releases(&client, url).await
        }

        Commands::GetRelease { id } => {
            let url = cli.url.as_ref().ok_or("get-release requires --url <URL>")?;
            let client = reqwest::Client::new();
            cmd_get_release(&client, url, &id).await
        }

        Commands::UpdateRelease { id, json } => {
            let url = cli.url.as_ref().ok_or("update-release requires --url <URL>")?;
            let signing_key = load_keypair(&config_dir)?;
            let client = reqwest::Client::new();
            cmd_update_release(&client, url, &signing_key, &id, &json).await
        }

        Commands::CreateRelease { json } => {
            let url = cli.url.as_ref().ok_or("create-release requires --url <URL>")?;
            let signing_key = load_keypair(&config_dir)?;
            let client = reqwest::Client::new();
            cmd_create_release(&client, url, &signing_key, &json).await
        }

        // Admin commands go to Lens
        cmd => {
            if let Some(ref url) = cli.url {
                // Remote HTTP mode
                let signing_key = load_keypair(&config_dir)?;
                let client = reqwest::Client::new();

                match cmd {
                    Commands::Ping => {
                        let resp =
                            send_http_command(&client, url, &signing_key, AdminCommand::Ping)
                                .await?;
                        handle_response(resp)
                    }
                    Commands::AddAdmin { public_key } => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::AddAdmin { public_key },
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::RemoveAdmin { public_key } => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::RemoveAdmin { public_key },
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::GrantUpload { public_key } => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::GrantUpload { public_key },
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::RevokeUpload { public_key } => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::RevokeUpload { public_key },
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::ListAdmins => {
                        let resp =
                            send_http_command(&client, url, &signing_key, AdminCommand::ListAdmins)
                                .await?;
                        handle_response(resp)
                    }
                    Commands::IsAdmin { public_key } => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::IsAdmin { public_key },
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::StartProfiling => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::StartProfiling,
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::StopProfiling => {
                        let resp = send_http_command(
                            &client,
                            url,
                            &signing_key,
                            AdminCommand::StopProfiling,
                        )
                        .await?;
                        handle_response(resp)
                    }
                    Commands::CpuProfile => {
                        let resp =
                            send_http_command(&client, url, &signing_key, AdminCommand::CpuProfile)
                                .await?;
                        handle_response(resp)
                    }
                    Commands::MemProfile => {
                        let resp =
                            send_http_command(&client, url, &signing_key, AdminCommand::MemProfile)
                                .await?;
                        handle_response(resp)
                    }
                    Commands::MeshStats => {
                        let resp =
                            send_http_command(&client, url, &signing_key, AdminCommand::MeshStats)
                                .await?;
                        handle_response(resp)
                    }
                    Commands::Init | Commands::Show | Commands::Upload { .. }
                    | Commands::ListReleases | Commands::GetRelease { .. }
                    | Commands::UpdateRelease { .. } | Commands::CreateRelease { .. } => unreachable!(),
                }
            } else {
                // Local socket mode
                let admin_cmd = match cmd {
                    Commands::Ping => AdminCommand::Ping,
                    Commands::AddAdmin { public_key } => AdminCommand::AddAdmin { public_key },
                    Commands::RemoveAdmin { public_key } => {
                        AdminCommand::RemoveAdmin { public_key }
                    }
                    Commands::GrantUpload { public_key } => {
                        AdminCommand::GrantUpload { public_key }
                    }
                    Commands::RevokeUpload { public_key } => {
                        AdminCommand::RevokeUpload { public_key }
                    }
                    Commands::ListAdmins => AdminCommand::ListAdmins,
                    Commands::IsAdmin { public_key } => AdminCommand::IsAdmin { public_key },
                    Commands::StartProfiling => AdminCommand::StartProfiling,
                    Commands::StopProfiling => AdminCommand::StopProfiling,
                    Commands::CpuProfile => AdminCommand::CpuProfile,
                    Commands::MemProfile => AdminCommand::MemProfile,
                    Commands::MeshStats => AdminCommand::MeshStats,
                    Commands::Init | Commands::Show | Commands::Upload { .. }
                    | Commands::ListReleases | Commands::GetRelease { .. }
                    | Commands::UpdateRelease { .. } | Commands::CreateRelease { .. } => unreachable!(),
                };

                let response = send_socket_command(admin_cmd, data_dir)?;
                handle_response(response)
            }
        }
    }
}
