//! Axum web server with WebSocket streaming for visualization.

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::events::MeshSnapshot;
use crate::playback::{Playback, PlaybackSpeed, PlaybackStatus};
use crate::simulation::Simulation;

/// Shared application state.
pub struct AppState {
    simulation: RwLock<Simulation>,
    playback: RwLock<Playback>,
}

/// Visualization server.
pub struct VisServer {
    state: Arc<AppState>,
}

impl VisServer {
    /// Create a new visualization server from a simulation.
    pub fn new(simulation: Simulation) -> Self {
        let events = simulation.events().to_vec();
        Self {
            state: Arc::new(AppState {
                simulation: RwLock::new(simulation),
                playback: RwLock::new(Playback::new(events)),
            }),
        }
    }

    /// Build the router for the server.
    pub fn router(&self) -> Router {
        Router::new()
            // Serve the Vue.js app
            .route("/", get(index_handler))
            // API routes
            .route("/api/status", get(status_handler))
            .route("/api/snapshot", get(snapshot_handler))
            .route("/api/playback", get(playback_status_handler))
            .route("/api/playback/play", post(play_handler))
            .route("/api/playback/pause", post(pause_handler))
            .route("/api/playback/stop", post(stop_handler))
            .route("/api/playback/seek", post(seek_handler))
            .route("/api/playback/speed", post(speed_handler))
            .route("/api/playback/step", post(step_handler))
            // WebSocket for real-time updates
            .route("/ws", get(ws_handler))
            .layer(CorsLayer::permissive())
            .with_state(self.state.clone())
    }

    /// Run the server on the given port.
    pub async fn serve(self, port: u16) -> Result<(), std::io::Error> {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Visualization server running on http://localhost:{}", port);
        axum::serve(listener, self.router()).await
    }
}

/// Serve the Vue.js index page.
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// Server status response.
#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    node_count: usize,
    event_count: usize,
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let sim = state.simulation.read().await;
    Json(StatusResponse {
        status: "ok",
        node_count: sim.node_count(),
        event_count: sim.event_count(),
    })
}

async fn snapshot_handler(State(state): State<Arc<AppState>>) -> Json<MeshSnapshot> {
    let sim = state.simulation.read().await;
    let playback = state.playback.read().await;
    let events = sim.events();
    let frame = playback.current_frame();
    Json(MeshSnapshot::from_events(events, frame))
}

async fn playback_status_handler(State(state): State<Arc<AppState>>) -> Json<PlaybackStatus> {
    let playback = state.playback.read().await;
    Json(PlaybackStatus::from(&*playback))
}

async fn play_handler(State(state): State<Arc<AppState>>) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    playback.play();
    Json(PlaybackStatus::from(&*playback))
}

async fn pause_handler(State(state): State<Arc<AppState>>) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    playback.pause();
    Json(PlaybackStatus::from(&*playback))
}

async fn stop_handler(State(state): State<Arc<AppState>>) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    playback.stop();
    Json(PlaybackStatus::from(&*playback))
}

#[derive(Deserialize)]
struct SeekRequest {
    frame: usize,
}

async fn seek_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SeekRequest>,
) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    playback.seek(req.frame);
    Json(PlaybackStatus::from(&*playback))
}

#[derive(Deserialize)]
struct SpeedRequest {
    speed: PlaybackSpeed,
}

async fn speed_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SpeedRequest>,
) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    playback.set_speed(req.speed);
    Json(PlaybackStatus::from(&*playback))
}

#[derive(Deserialize)]
struct StepRequest {
    direction: String, // "forward" or "backward"
}

async fn step_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StepRequest>,
) -> Json<PlaybackStatus> {
    let mut playback = state.playback.write().await;
    match req.direction.as_str() {
        "forward" => {
            playback.step_forward();
        }
        "backward" => {
            playback.step_backward();
        }
        _ => {}
    }
    Json(PlaybackStatus::from(&*playback))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    // Send initial state at current playback frame
    let sim = state.simulation.read().await;
    let playback = state.playback.read().await;
    let events = sim.events();
    let frame = playback.current_frame();
    let snapshot = MeshSnapshot::from_events(events, frame);
    drop(playback);
    drop(sim);

    if let Ok(json) = serde_json::to_string(&snapshot) {
        let _ = socket.send(Message::Text(json.into())).await;
    }

    // Handle incoming messages
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                // Parse command and respond
                if let Ok(cmd) = serde_json::from_str::<WsCommand>(&text) {
                    let response = handle_ws_command(&state, cmd).await;
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = socket.send(Message::Text(json.into())).await;
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum WsCommand {
    #[serde(rename = "get_snapshot")]
    GetSnapshot,
    #[serde(rename = "get_status")]
    GetStatus,
    #[serde(rename = "seek")]
    Seek { frame: usize },
    #[serde(rename = "play")]
    Play,
    #[serde(rename = "pause")]
    Pause,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum WsResponse {
    #[serde(rename = "snapshot")]
    Snapshot(MeshSnapshot),
    #[serde(rename = "status")]
    Status(PlaybackStatus),
}

async fn handle_ws_command(state: &Arc<AppState>, cmd: WsCommand) -> WsResponse {
    match cmd {
        WsCommand::GetSnapshot => {
            let sim = state.simulation.read().await;
            let playback = state.playback.read().await;
            let events = sim.events();
            let frame = playback.current_frame();
            WsResponse::Snapshot(MeshSnapshot::from_events(events, frame))
        }
        WsCommand::GetStatus => {
            let playback = state.playback.read().await;
            WsResponse::Status(PlaybackStatus::from(&*playback))
        }
        WsCommand::Seek { frame } => {
            let mut playback = state.playback.write().await;
            playback.seek(frame);
            WsResponse::Status(PlaybackStatus::from(&*playback))
        }
        WsCommand::Play => {
            let mut playback = state.playback.write().await;
            playback.play();
            WsResponse::Status(PlaybackStatus::from(&*playback))
        }
        WsCommand::Pause => {
            let mut playback = state.playback.write().await;
            playback.pause();
            WsResponse::Status(PlaybackStatus::from(&*playback))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulation::SimulationConfig;

    #[test]
    fn server_creation() {
        let sim = Simulation::new(SimulationConfig::default());
        let _server = VisServer::new(sim);
    }

    #[test]
    fn router_builds() {
        let sim = Simulation::new(SimulationConfig::default());
        let server = VisServer::new(sim);
        let _router = server.router();
    }
}
