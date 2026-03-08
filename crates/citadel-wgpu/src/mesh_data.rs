//! GPU buffer management for mesh nodes and edges.

use crate::NodeInstance;
use citadel_topology::{Spiral3D, Spiral3DIndex};
use wgpu::util::DeviceExt;

/// Mesh data for GPU rendering.
pub struct MeshData {
    /// Instance buffer containing all node data
    pub instance_buffer: wgpu::Buffer,
    /// Total number of nodes in the buffer
    pub node_count: u32,
    /// Number of nodes currently visible (for growth animation)
    pub visible_count: u32,
}

impl MeshData {
    /// Generate mesh data for the given number of nodes.
    ///
    /// This pre-computes all node positions and colors based on the
    /// 3D SPIRAL enumeration, creating a single GPU buffer.
    pub fn generate(device: &wgpu::Device, node_count: u32) -> Self {
        tracing::info!("Generating {} node instances...", node_count);

        let start = std::time::Instant::now();

        // Generate all instances
        let instances: Vec<NodeInstance> = Spiral3D::take_slots(node_count as u64)
            .enumerate()
            .map(|(idx, coord)| {
                let shell = Spiral3DIndex::new(idx as u64).shell();
                NodeInstance::from_hex(coord, shell)
            })
            .collect();

        let gen_time = start.elapsed();
        tracing::info!("Generated {} instances in {:?}", instances.len(), gen_time);

        // Create GPU buffer
        let instance_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Node Instance Buffer"),
            contents: bytemuck::cast_slice(&instances),
            usage: wgpu::BufferUsages::VERTEX,
        });

        let buffer_size = (instances.len() * std::mem::size_of::<NodeInstance>()) as f64;
        tracing::info!(
            "Created instance buffer: {:.2} MB",
            buffer_size / 1_000_000.0
        );

        Self {
            instance_buffer,
            node_count: instances.len() as u32,
            visible_count: instances.len() as u32,
        }
    }

    /// Set the number of visible nodes (for growth animation).
    pub fn set_visible(&mut self, count: u32) {
        self.visible_count = count.min(self.node_count);
    }

    /// Get the vertex buffer layout for the instance data.
    pub fn instance_buffer_layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<NodeInstance>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Instance,
            attributes: &[
                // Position
                wgpu::VertexAttribute {
                    offset: 0,
                    shader_location: 0,
                    format: wgpu::VertexFormat::Float32x3,
                },
                // Color (packed u32)
                wgpu::VertexAttribute {
                    offset: 12,
                    shader_location: 1,
                    format: wgpu::VertexFormat::Uint32,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_layout_matches_struct() {
        let layout = MeshData::instance_buffer_layout();
        assert_eq!(
            layout.array_stride,
            std::mem::size_of::<NodeInstance>() as u64
        );
    }
}
