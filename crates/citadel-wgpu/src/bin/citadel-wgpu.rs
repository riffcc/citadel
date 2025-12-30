//! High-performance 3D mesh visualization for Citadel topology.
//!
//! Controls:
//! - WASD: Move camera
//! - Space/Shift: Move up/down
//! - Right-click + mouse: Look around
//! - Scroll wheel: Adjust speed
//! - +/-: Increase/decrease speed
//! - Home: Reset camera to origin
//! - P: Toggle playback
//! - R: Reset playback
//! - [/]: Decrease/increase playback speed
//! - F1: Toggle stats display
//! - Escape: Quit
//!
//! Traffic Controls:
//! - 1-9: Hold for unicast traffic (higher = more)
//! - B: Hold for broadcast traffic
//! - 0: Clear all traffic
//!
//! Gamepad Controls:
//! - Left stick: Move camera
//! - Right stick: Look around
//! - LT: Unicast traffic (pull harder = more)
//! - RT: Broadcast traffic (pull harder = more)
//! - A/Start: Toggle playback
//! - B/Back: Reset playback
//! - LB/RB: Decrease/increase playback speed
//! - Y: Reset camera

use citadel_wgpu::{Renderer, TrafficSimulation};
use gilrs::{Axis, Button, Event as GilrsEvent, Gilrs};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use winit::application::ApplicationHandler;
use winit::event::{ElementState, KeyEvent, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Window, WindowId};

const DEFAULT_NODE_COUNT: u32 = 100_000;
const DEADZONE: f32 = 0.15;
const STATS_INTERVAL: f32 = 1.0; // Print stats every second

fn apply_deadzone(value: f32) -> f32 {
    if value.abs() < DEADZONE {
        0.0
    } else {
        (value - value.signum() * DEADZONE) / (1.0 - DEADZONE)
    }
}

/// Frame timing for FPS calculation.
struct FrameTiming {
    frame_times: VecDeque<f32>,
    max_samples: usize,
}

impl FrameTiming {
    fn new() -> Self {
        Self {
            frame_times: VecDeque::with_capacity(120),
            max_samples: 120,
        }
    }

    fn push(&mut self, dt: f32) {
        if self.frame_times.len() >= self.max_samples {
            self.frame_times.pop_front();
        }
        self.frame_times.push_back(dt);
    }

    fn fps(&self) -> f32 {
        if self.frame_times.is_empty() {
            return 0.0;
        }
        let avg = self.frame_times.iter().sum::<f32>() / self.frame_times.len() as f32;
        if avg > 0.0 {
            1.0 / avg
        } else {
            0.0
        }
    }

    fn frame_time_ms(&self) -> f32 {
        if self.frame_times.is_empty() {
            return 0.0;
        }
        (self.frame_times.iter().sum::<f32>() / self.frame_times.len() as f32) * 1000.0
    }
}

struct App {
    window: Option<Arc<Window>>,
    renderer: Option<Renderer>,
    gilrs: Option<Gilrs>,
    node_count: u32,
    last_frame: Instant,

    // Playback state
    playing: bool,
    playback_speed: f32,
    playback_frame: f32,

    // Traffic simulation
    traffic: Option<TrafficSimulation>,
    unicast_intensity: f32,
    broadcast_intensity: f32,

    // Single-shot traffic modes (L3/R3 held = 1/sec)
    l3_held: bool,
    r3_held: bool,
    single_shot_timer: f32,

    // Continuous single-shot toggle (L4/R4)
    continuous_broadcast: bool,
    continuous_unicast: bool,

    // Stats
    show_stats: bool,
    frame_timing: FrameTiming,
    stats_accumulator: f32,
}

impl App {
    fn new(node_count: u32) -> Self {
        Self {
            window: None,
            renderer: None,
            gilrs: None,
            node_count,
            last_frame: Instant::now(),
            playing: false,
            playback_speed: 1000.0,
            playback_frame: 0.0,
            traffic: None,
            unicast_intensity: 0.0,
            broadcast_intensity: 0.0,
            l3_held: false,
            r3_held: false,
            single_shot_timer: 0.0,
            continuous_broadcast: false,
            continuous_unicast: false,
            show_stats: true,
            frame_timing: FrameTiming::new(),
            stats_accumulator: 0.0,
        }
    }

    fn update_gamepad(&mut self) {
        let Some(gilrs) = &mut self.gilrs else {
            return;
        };
        let Some(renderer) = &mut self.renderer else {
            return;
        };

        // Process gamepad events
        while let Some(GilrsEvent { id, event, .. }) = gilrs.next_event() {
            if let gilrs::EventType::ButtonPressed(btn, _) = event { match btn {
                Button::South | Button::Start => {
                    self.playing = !self.playing;
                    tracing::info!(
                        "Playback: {}",
                        if self.playing { "playing" } else { "paused" }
                    );
                }
                Button::East | Button::Select => {
                    self.playback_frame = 0.0;
                    if let Some(mesh) = &mut renderer.mesh_data {
                        mesh.set_visible(0);
                    }
                    if let Some(traffic) = &mut self.traffic {
                        traffic.clear();
                    }
                    tracing::info!("Playback reset");
                }
                Button::LeftTrigger => {
                    self.playback_speed = (self.playback_speed / 1.5).max(100.0);
                    tracing::info!("Playback speed: {:.0} nodes/s", self.playback_speed);
                }
                Button::RightTrigger => {
                    self.playback_speed = (self.playback_speed * 1.5).min(100000.0);
                    tracing::info!("Playback speed: {:.0} nodes/s", self.playback_speed);
                }
                Button::North => {
                    renderer.camera.reset();
                    tracing::info!("Camera reset");
                }
                Button::DPadUp => {
                    renderer.camera.speed *= 1.5;
                    tracing::info!("Speed: {:.0}", renderer.camera.speed);
                }
                Button::DPadDown => {
                    renderer.camera.speed /= 1.5;
                    tracing::info!("Speed: {:.0}", renderer.camera.speed);
                }
                // L4/R4 - try multiple button mappings
                // 8BitDo might map back paddles as C, Z, Mode, or other buttons
                Button::C | Button::Z | Button::Mode => {
                    // Toggle based on which one - C/Mode for broadcast, Z for unicast
                    if btn == Button::C || btn == Button::Mode {
                        self.continuous_broadcast = !self.continuous_broadcast;
                        tracing::info!("Continuous broadcast: {}", if self.continuous_broadcast { "ON" } else { "OFF" });
                    } else {
                        self.continuous_unicast = !self.continuous_unicast;
                        tracing::info!("Continuous unicast: {}", if self.continuous_unicast { "ON" } else { "OFF" });
                    }
                }
                Button::Unknown => {
                    tracing::info!("Unknown button pressed - might be L4/R4");
                }
                _ => {}
            } }
            tracing::debug!("Gamepad {:?} event: {:?}", id, event);
        }

        // Read current gamepad state
        for (_id, gamepad) in gilrs.gamepads() {
            if !gamepad.is_connected() {
                continue;
            }

            // Left stick for movement
            let move_x = apply_deadzone(gamepad.value(Axis::LeftStickX));
            let move_y = apply_deadzone(-gamepad.value(Axis::LeftStickY));
            renderer.camera.set_gamepad_move(move_x, move_y);

            // Right stick for looking
            let look_x = apply_deadzone(gamepad.value(Axis::RightStickX));
            let look_y = apply_deadzone(gamepad.value(Axis::RightStickY));
            renderer.camera.set_gamepad_look(look_x, look_y);

            // LT for unicast traffic, RT for broadcast traffic
            // Triggers are reported as buttons with analog values (0.0 to 1.0)
            let lt = gamepad.button_data(Button::LeftTrigger2)
                .map(|d| d.value())
                .unwrap_or(0.0);
            let rt = gamepad.button_data(Button::RightTrigger2)
                .map(|d| d.value())
                .unwrap_or(0.0);

            self.unicast_intensity = lt;
            self.broadcast_intensity = rt;

            // L3/R3 continuous state (thumbstick buttons)
            self.l3_held = gamepad.is_pressed(Button::LeftThumb);
            self.r3_held = gamepad.is_pressed(Button::RightThumb);

            // Only use first connected gamepad
            break;
        }
    }

    fn print_stats(&mut self) {
        if !self.show_stats {
            return;
        }

        let Some(renderer) = &self.renderer else {
            return;
        };

        let visible = renderer
            .mesh_data
            .as_ref()
            .map(|m| m.visible_count)
            .unwrap_or(0);

        let traffic_stats = self.traffic.as_ref().map(|t| {
            format!(
                "Packets: {} active, {} sent (U:{}/B:{}), {} delivered",
                t.active_packets(),
                t.stats.packets_sent,
                t.stats.unicast_sent,
                t.stats.broadcast_sent,
                t.stats.packets_delivered
            )
        });

        let pos = renderer.camera.position;

        tracing::info!(
            "FPS: {:.1} ({:.2}ms) | Nodes: {}/{} | {} | Pos: ({:.0},{:.0},{:.0}) | LT:{:.0}% RT:{:.0}%",
            self.frame_timing.fps(),
            self.frame_timing.frame_time_ms(),
            visible,
            self.node_count,
            traffic_stats.unwrap_or_default(),
            pos.x, pos.y, pos.z,
            self.unicast_intensity * 100.0,
            self.broadcast_intensity * 100.0
        );
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }

        let window_attrs = Window::default_attributes()
            .with_title(format!("Citadel Mesh - {} nodes", self.node_count))
            .with_inner_size(winit::dpi::LogicalSize::new(1280, 720));

        let window = Arc::new(event_loop.create_window(window_attrs).unwrap());
        self.window = Some(window.clone());

        // Initialize gilrs for gamepad support
        match Gilrs::new() {
            Ok(gilrs) => {
                for (_id, gamepad) in gilrs.gamepads() {
                    tracing::info!(
                        "Gamepad found: {} ({:?})",
                        gamepad.name(),
                        gamepad.power_info()
                    );
                }
                self.gilrs = Some(gilrs);
            }
            Err(e) => {
                tracing::warn!("Failed to initialize gamepad support: {}", e);
            }
        }

        // Create renderer
        let mut renderer = pollster::block_on(Renderer::new(window));

        // Generate mesh
        tracing::info!("Generating mesh with {} nodes...", self.node_count);
        renderer.generate_mesh(self.node_count);

        // Start with all nodes visible
        if let Some(mesh) = &mut renderer.mesh_data {
            mesh.set_visible(self.node_count);
        }

        // Create traffic simulation
        self.traffic = Some(TrafficSimulation::new(self.node_count));

        self.renderer = Some(renderer);
        self.last_frame = Instant::now();
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(renderer) = &mut self.renderer else {
            return;
        };

        match event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
            }

            WindowEvent::Resized(size) => {
                renderer.resize(size);
            }

            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(key),
                        state,
                        ..
                    },
                ..
            } => {
                if state == ElementState::Pressed {
                    match key {
                        KeyCode::Escape => {
                            event_loop.exit();
                        }
                        KeyCode::KeyP => {
                            self.playing = !self.playing;
                            tracing::info!(
                                "Playback: {}",
                                if self.playing { "playing" } else { "paused" }
                            );
                        }
                        KeyCode::KeyR => {
                            self.playback_frame = 0.0;
                            if let Some(mesh) = &mut renderer.mesh_data {
                                mesh.set_visible(0);
                            }
                            if let Some(traffic) = &mut self.traffic {
                                traffic.clear();
                            }
                            tracing::info!("Playback reset");
                        }
                        KeyCode::BracketLeft => {
                            self.playback_speed = (self.playback_speed / 1.5).max(100.0);
                            tracing::info!("Playback speed: {:.0} nodes/s", self.playback_speed);
                        }
                        KeyCode::BracketRight => {
                            self.playback_speed = (self.playback_speed * 1.5).min(100000.0);
                            tracing::info!("Playback speed: {:.0} nodes/s", self.playback_speed);
                        }
                        KeyCode::F1 => {
                            self.show_stats = !self.show_stats;
                            tracing::info!("Stats: {}", if self.show_stats { "on" } else { "off" });
                        }
                        // Keyboard traffic controls
                        KeyCode::Digit1 => self.unicast_intensity = 0.1,
                        KeyCode::Digit2 => self.unicast_intensity = 0.2,
                        KeyCode::Digit3 => self.unicast_intensity = 0.3,
                        KeyCode::Digit4 => self.unicast_intensity = 0.4,
                        KeyCode::Digit5 => self.unicast_intensity = 0.5,
                        KeyCode::Digit6 => self.unicast_intensity = 0.6,
                        KeyCode::Digit7 => self.unicast_intensity = 0.7,
                        KeyCode::Digit8 => self.unicast_intensity = 0.8,
                        KeyCode::Digit9 => self.unicast_intensity = 0.9,
                        KeyCode::Digit0 => {
                            self.unicast_intensity = 0.0;
                            self.broadcast_intensity = 0.0;
                            if let Some(traffic) = &mut self.traffic {
                                traffic.clear();
                            }
                        }
                        KeyCode::KeyB => {
                            self.broadcast_intensity = 0.5;
                        }
                        _ => {}
                    }
                } else if state == ElementState::Released {
                    match key {
                        KeyCode::Digit1
                        | KeyCode::Digit2
                        | KeyCode::Digit3
                        | KeyCode::Digit4
                        | KeyCode::Digit5
                        | KeyCode::Digit6
                        | KeyCode::Digit7
                        | KeyCode::Digit8
                        | KeyCode::Digit9 => {
                            self.unicast_intensity = 0.0;
                        }
                        KeyCode::KeyB => {
                            self.broadcast_intensity = 0.0;
                        }
                        _ => {}
                    }
                }

                renderer.camera.handle_keyboard(key, state);
            }

            WindowEvent::MouseInput { button, state, .. } => {
                renderer.camera.handle_mouse_button(button, state);
            }

            WindowEvent::CursorMoved { position, .. } => {
                renderer.camera.handle_mouse_motion(position.x, position.y);
            }

            WindowEvent::MouseWheel { delta, .. } => {
                let scroll = match delta {
                    winit::event::MouseScrollDelta::LineDelta(_, y) => y,
                    winit::event::MouseScrollDelta::PixelDelta(pos) => pos.y as f32 / 100.0,
                };
                renderer.camera.handle_scroll(scroll);
            }

            WindowEvent::RedrawRequested => {
                let now = Instant::now();
                let dt = (now - self.last_frame).as_secs_f32();
                self.last_frame = now;
                self.frame_timing.push(dt);

                // Update gamepad
                self.update_gamepad();

                // Update camera
                if let Some(renderer) = &mut self.renderer {
                    renderer.camera.update(dt);

                    // Update playback
                    if self.playing {
                        self.playback_frame += self.playback_speed * dt;
                        let visible = (self.playback_frame as u32).min(self.node_count);
                        if let Some(mesh) = &mut renderer.mesh_data {
                            mesh.set_visible(visible);
                        }

                        if self.playback_frame >= self.node_count as f32 {
                            self.playing = false;
                        }
                    }

                    // Get visible node count for traffic bounds
                    let visible_nodes = renderer.mesh_data.as_ref()
                        .map(|m| m.visible_count)
                        .unwrap_or(0);

                    // Update traffic
                    if let Some(traffic) = &mut self.traffic {
                        // Set visible node limit so packets only go between existing nodes
                        traffic.set_visible_nodes(visible_nodes);

                        // Spawn traffic based on trigger intensity
                        // Scale by intensity directly - spawn_unicast/broadcast handle packet counts
                        if self.unicast_intensity > 0.01 {
                            traffic.spawn_unicast(self.unicast_intensity);
                        }
                        if self.broadcast_intensity > 0.01 {
                            traffic.spawn_broadcast(self.broadcast_intensity);
                        }

                        // Single-shot timer for L3/R3 and continuous modes
                        self.single_shot_timer += dt;
                        let should_fire = self.single_shot_timer >= 1.0;

                        if should_fire {
                            self.single_shot_timer = 0.0;

                            // L3 held or continuous broadcast: single broadcast
                            if self.l3_held || self.continuous_broadcast {
                                traffic.spawn_single_broadcast();
                            }

                            // R3 held or continuous unicast: single unicast
                            if self.r3_held || self.continuous_unicast {
                                traffic.spawn_single_unicast();
                            }
                        }

                        // Update packet positions
                        traffic.update(dt);

                        // Update line buffer (trails)
                        let line_vertices = traffic.get_line_vertices();
                        renderer.update_lines(&line_vertices);

                        // Update point buffer (packet heads)
                        let point_vertices = traffic.get_point_vertices();
                        renderer.update_traffic_points(&point_vertices);

                        // Update mesh alpha for transparency when path visualization is active
                        renderer.mesh_alpha = 1.0 - traffic.mesh_transparency();
                    }

                    // Render mesh and traffic
                    match renderer.render() {
                        Ok(_) => {}
                        Err(wgpu::SurfaceError::Lost) => {
                            renderer.resize(renderer.size());
                        }
                        Err(wgpu::SurfaceError::OutOfMemory) => {
                            tracing::error!("Out of GPU memory");
                            event_loop.exit();
                        }
                        Err(e) => {
                            tracing::warn!("Render error: {:?}", e);
                        }
                    }
                }

                // Print stats periodically
                self.stats_accumulator += dt;
                if self.stats_accumulator >= STATS_INTERVAL {
                    self.stats_accumulator = 0.0;
                    self.print_stats();
                }

                // Request next frame
                if let Some(window) = &self.window {
                    window.request_redraw();
                }
            }

            _ => {}
        }
    }
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse node count from args
    let node_count = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NODE_COUNT);

    tracing::info!("Citadel wgpu visualization");
    tracing::info!("Node count: {}", node_count);
    tracing::info!("Controls:");
    tracing::info!("  WASD - Move camera");
    tracing::info!("  Space/Shift - Up/Down");
    tracing::info!("  Right-click + mouse - Look around");
    tracing::info!("  Scroll wheel - Adjust speed");
    tracing::info!("  P - Toggle playback");
    tracing::info!("  R - Reset playback");
    tracing::info!("  [/] - Adjust playback speed");
    tracing::info!("  F1 - Toggle stats");
    tracing::info!("  1-9 - Unicast traffic intensity (hold)");
    tracing::info!("  B - Broadcast traffic (hold)");
    tracing::info!("  0 - Clear traffic");
    tracing::info!("  Home - Reset camera");
    tracing::info!("  Escape - Quit");
    tracing::info!("Gamepad:");
    tracing::info!("  Left stick - Move");
    tracing::info!("  Right stick - Look");
    tracing::info!("  LT - Unicast traffic (intensity by pressure)");
    tracing::info!("  RT - Broadcast traffic (intensity by pressure)");
    tracing::info!("  L3 (hold) - Single broadcast per second");
    tracing::info!("  R3 (hold) - Single unicast per second");
    tracing::info!("  L4/C - Toggle continuous broadcast");
    tracing::info!("  R4/Z - Toggle continuous unicast");
    tracing::info!("  A/Start - Toggle playback");
    tracing::info!("  B/Back - Reset playback");
    tracing::info!("  LB/RB - Playback speed");
    tracing::info!("  Y - Reset camera");
    tracing::info!("  DPad Up/Down - Speed");

    // Create event loop
    let event_loop = EventLoop::new().unwrap();
    event_loop.set_control_flow(ControlFlow::Poll);

    // Run application
    let mut app = App::new(node_count);
    event_loop.run_app(&mut app).unwrap();
}
