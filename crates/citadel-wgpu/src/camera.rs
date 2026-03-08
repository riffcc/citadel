//! Fly camera for 3D navigation.

use glam::{Mat4, Vec3};
use winit::event::{ElementState, MouseButton};
use winit::keyboard::KeyCode;

/// First-person fly camera with WASD + mouse + gamepad controls.
pub struct FlyCamera {
    /// Camera position in world space
    pub position: Vec3,
    /// Yaw angle in radians (horizontal rotation)
    pub yaw: f32,
    /// Pitch angle in radians (vertical rotation)
    pub pitch: f32,
    /// Movement speed (units per second)
    pub speed: f32,
    /// Mouse sensitivity
    pub sensitivity: f32,
    /// Gamepad stick sensitivity
    pub gamepad_sensitivity: f32,
    /// Field of view in radians
    pub fov: f32,
    /// Near clipping plane
    pub near: f32,
    /// Far clipping plane
    pub far: f32,

    // Input state (keyboard)
    forward: bool,
    backward: bool,
    left: bool,
    right: bool,
    up: bool,
    down: bool,
    mouse_captured: bool,
    last_mouse: Option<(f64, f64)>,

    // Gamepad analog input (-1.0 to 1.0)
    gamepad_move_x: f32,
    gamepad_move_y: f32,
    gamepad_look_x: f32,
    gamepad_look_y: f32,
    gamepad_up: f32,
    gamepad_down: f32,
}

impl Default for FlyCamera {
    fn default() -> Self {
        Self {
            position: Vec3::new(0.0, 0.0, 50.0),
            yaw: 0.0,
            pitch: 0.0,
            speed: 50.0,
            sensitivity: 0.002,
            gamepad_sensitivity: 2.0,
            fov: std::f32::consts::FRAC_PI_4,
            near: 0.1,
            far: 10000.0,
            forward: false,
            backward: false,
            left: false,
            right: false,
            up: false,
            down: false,
            mouse_captured: false,
            last_mouse: None,
            gamepad_move_x: 0.0,
            gamepad_move_y: 0.0,
            gamepad_look_x: 0.0,
            gamepad_look_y: 0.0,
            gamepad_up: 0.0,
            gamepad_down: 0.0,
        }
    }
}

impl FlyCamera {
    /// Create a new fly camera at the given position.
    pub fn new(position: Vec3) -> Self {
        Self {
            position,
            ..Default::default()
        }
    }

    /// Get the view matrix.
    pub fn view_matrix(&self) -> Mat4 {
        let direction = self.direction();
        let up = Vec3::Y;
        Mat4::look_at_rh(self.position, self.position + direction, up)
    }

    /// Get the projection matrix for the given aspect ratio.
    pub fn projection_matrix(&self, aspect: f32) -> Mat4 {
        Mat4::perspective_rh(self.fov, aspect, self.near, self.far)
    }

    /// Get the combined view-projection matrix.
    pub fn view_projection_matrix(&self, aspect: f32) -> Mat4 {
        self.projection_matrix(aspect) * self.view_matrix()
    }

    /// Get the camera's forward direction.
    pub fn direction(&self) -> Vec3 {
        Vec3::new(
            self.yaw.cos() * self.pitch.cos(),
            self.pitch.sin(),
            self.yaw.sin() * self.pitch.cos(),
        )
        .normalize()
    }

    /// Get the camera's right direction.
    pub fn right(&self) -> Vec3 {
        self.direction().cross(Vec3::Y).normalize()
    }

    /// Update camera position based on input state (keyboard + gamepad).
    pub fn update(&mut self, dt: f32) {
        let forward_dir = self.direction();
        let right_dir = self.right();
        let up_dir = Vec3::Y;

        // Apply gamepad look (right stick)
        if self.gamepad_look_x.abs() > 0.1 || self.gamepad_look_y.abs() > 0.1 {
            self.yaw += self.gamepad_look_x * self.gamepad_sensitivity * dt;
            self.pitch -= self.gamepad_look_y * self.gamepad_sensitivity * dt;

            // Clamp pitch
            let max_pitch = std::f32::consts::FRAC_PI_2 - 0.01;
            self.pitch = self.pitch.clamp(-max_pitch, max_pitch);
        }

        // Calculate movement from keyboard
        let mut move_input = Vec3::ZERO;

        if self.forward {
            move_input.z += 1.0;
        }
        if self.backward {
            move_input.z -= 1.0;
        }
        if self.right_pressed() {
            move_input.x += 1.0;
        }
        if self.left {
            move_input.x -= 1.0;
        }
        if self.up {
            move_input.y += 1.0;
        }
        if self.down {
            move_input.y -= 1.0;
        }

        // Add gamepad movement (left stick + triggers)
        if self.gamepad_move_x.abs() > 0.1 {
            move_input.x += self.gamepad_move_x;
        }
        if self.gamepad_move_y.abs() > 0.1 {
            move_input.z += self.gamepad_move_y;
        }
        move_input.y += self.gamepad_up - self.gamepad_down;

        // Apply movement in world space
        if move_input.length_squared() > 0.0 {
            let velocity =
                (forward_dir * move_input.z + right_dir * move_input.x + up_dir * move_input.y)
                    .normalize_or_zero()
                    * self.speed
                    * dt;
            self.position += velocity;
        }
    }

    fn right_pressed(&self) -> bool {
        self.right
    }

    /// Set gamepad left stick input for movement.
    pub fn set_gamepad_move(&mut self, x: f32, y: f32) {
        self.gamepad_move_x = x;
        self.gamepad_move_y = y;
    }

    /// Set gamepad right stick input for looking.
    pub fn set_gamepad_look(&mut self, x: f32, y: f32) {
        self.gamepad_look_x = x;
        self.gamepad_look_y = y;
    }

    /// Set gamepad trigger input for up/down.
    pub fn set_gamepad_triggers(&mut self, up: f32, down: f32) {
        self.gamepad_up = up;
        self.gamepad_down = down;
    }

    /// Reset camera to default position and orientation.
    pub fn reset(&mut self) {
        self.position = Vec3::new(0.0, 0.0, 50.0);
        self.yaw = 0.0;
        self.pitch = 0.0;
    }

    /// Handle keyboard input.
    pub fn handle_keyboard(&mut self, key: KeyCode, state: ElementState) {
        let pressed = state == ElementState::Pressed;

        match key {
            KeyCode::KeyW => self.forward = pressed,
            KeyCode::KeyS => self.backward = pressed,
            KeyCode::KeyA => self.left = pressed,
            KeyCode::KeyD => self.right = pressed,
            KeyCode::Space => self.up = pressed,
            KeyCode::ShiftLeft | KeyCode::ShiftRight => self.down = pressed,
            KeyCode::Home => {
                if pressed {
                    self.reset();
                }
            }
            KeyCode::Equal | KeyCode::NumpadAdd => {
                if pressed {
                    self.speed *= 1.5;
                }
            }
            KeyCode::Minus | KeyCode::NumpadSubtract => {
                if pressed {
                    self.speed /= 1.5;
                }
            }
            _ => {}
        }
    }

    /// Handle mouse button input.
    pub fn handle_mouse_button(&mut self, button: MouseButton, state: ElementState) {
        if button == MouseButton::Right {
            self.mouse_captured = state == ElementState::Pressed;
            if !self.mouse_captured {
                self.last_mouse = None;
            }
        }
    }

    /// Handle mouse movement.
    pub fn handle_mouse_motion(&mut self, x: f64, y: f64) {
        if !self.mouse_captured {
            return;
        }

        if let Some((last_x, last_y)) = self.last_mouse {
            let dx = (x - last_x) as f32;
            let dy = (y - last_y) as f32;

            self.yaw += dx * self.sensitivity;
            self.pitch -= dy * self.sensitivity;

            // Clamp pitch to avoid gimbal lock
            let max_pitch = std::f32::consts::FRAC_PI_2 - 0.01;
            self.pitch = self.pitch.clamp(-max_pitch, max_pitch);
        }

        self.last_mouse = Some((x, y));
    }

    /// Handle scroll wheel for speed adjustment.
    pub fn handle_scroll(&mut self, delta: f32) {
        self.speed *= 1.0 + delta * 0.1;
        self.speed = self.speed.clamp(1.0, 10000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_camera_looks_forward() {
        let cam = FlyCamera::default();
        let dir = cam.direction();
        // Default yaw=0, pitch=0 should look along +X
        assert!(dir.x > 0.9);
    }

    #[test]
    fn view_matrix_is_valid() {
        let cam = FlyCamera::default();
        let view = cam.view_matrix();
        // Should be invertible
        assert!(view.determinant().abs() > 0.0001);
    }

    #[test]
    fn keyboard_input_sets_flags() {
        let mut cam = FlyCamera::default();
        cam.handle_keyboard(KeyCode::KeyW, ElementState::Pressed);
        assert!(cam.forward);
        cam.handle_keyboard(KeyCode::KeyW, ElementState::Released);
        assert!(!cam.forward);
    }
}
