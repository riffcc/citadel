//! High-performance wgpu visualization for Citadel mesh topology.
//!
//! Renders millions of nodes at 60fps using instanced point rendering.
//!
//! # Features
//! - Static exploration: fly around the full mesh
//! - Growth animation: watch mesh assemble node-by-node
//! - Point-based rendering: handles 3M+ nodes at 60fps
//! - Sparse edges: show connections for selected/nearby nodes

pub mod camera;
pub mod mesh_data;
pub mod renderer;
pub mod traffic;

pub use camera::FlyCamera;
pub use mesh_data::MeshData;
pub use renderer::Renderer;
pub use traffic::{LineVertex, TrafficSimulation, TrafficStats};

use citadel_topology::HexCoord;

/// Convert hex coordinate to world space position.
///
/// Uses the same scaling as the web visualization for consistency.
#[inline]
pub fn hex_to_world(coord: HexCoord) -> [f32; 3] {
    let size = 1.0_f32;
    let sqrt3 = 3.0_f32.sqrt();

    let x = size * 1.5 * coord.q as f32;
    let y = size * (sqrt3 * 0.5 * coord.q as f32 + sqrt3 * coord.r as f32);
    let z = coord.z as f32 * size * sqrt3;

    [x, y, z]
}

/// GPU instance data for a single node.
#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct NodeInstance {
    /// World position (x, y, z)
    pub position: [f32; 3],
    /// Packed RGBA color
    pub color: u32,
}

impl NodeInstance {
    /// Create a new node instance.
    pub fn new(position: [f32; 3], color: u32) -> Self {
        Self { position, color }
    }

    /// Create from hex coordinate with shell-based coloring.
    pub fn from_hex(coord: HexCoord, shell: u64) -> Self {
        let position = hex_to_world(coord);
        let color = shell_to_color(shell);
        Self { position, color }
    }
}

/// Convert shell number to a rainbow gradient color.
fn shell_to_color(shell: u64) -> u32 {
    // HSV to RGB with hue based on shell
    let hue = (shell as f32 * 0.1) % 1.0;
    let (r, g, b) = hsv_to_rgb(hue, 0.8, 1.0);

    let r = (r * 255.0) as u32;
    let g = (g * 255.0) as u32;
    let b = (b * 255.0) as u32;
    let a = 255u32;

    (a << 24) | (b << 16) | (g << 8) | r
}

/// HSV to RGB conversion.
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (f32, f32, f32) {
    let c = v * s;
    let x = c * (1.0 - ((h * 6.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = match (h * 6.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };

    (r + m, g + m, b + m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_topology::HexCoord;

    #[test]
    fn origin_maps_to_zero() {
        let pos = hex_to_world(HexCoord::ORIGIN);
        assert_eq!(pos, [0.0, 0.0, 0.0]);
    }

    #[test]
    fn z_axis_maps_correctly() {
        let coord = HexCoord::new(0, 0, 1);
        let pos = hex_to_world(coord);
        assert!(pos[2] > 0.0);
        assert_eq!(pos[0], 0.0);
        assert_eq!(pos[1], 0.0);
    }

    #[test]
    fn node_instance_size() {
        // Should be 16 bytes for efficient GPU transfer
        assert_eq!(std::mem::size_of::<NodeInstance>(), 16);
    }

    #[test]
    fn shell_colors_are_different() {
        let c0 = shell_to_color(0);
        let c1 = shell_to_color(1);
        let c5 = shell_to_color(5);

        assert_ne!(c0, c1);
        assert_ne!(c1, c5);
    }
}
