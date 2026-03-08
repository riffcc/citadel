//! Playback controls for mesh assembly timeline.

use crate::events::MeshEvent;
use serde::{Deserialize, Serialize};

/// Playback speed multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PlaybackSpeed {
    /// Pause playback
    Paused,
    /// 0.25x speed
    QuarterSpeed,
    /// 0.5x speed
    HalfSpeed,
    /// Normal speed (1x)
    Normal,
    /// 2x speed
    Double,
    /// 4x speed
    Quadruple,
    /// 10x speed
    TenX,
    /// Maximum speed (as fast as possible)
    Maximum,
}

impl PlaybackSpeed {
    /// Get the speed multiplier.
    pub fn multiplier(&self) -> f64 {
        match self {
            PlaybackSpeed::Paused => 0.0,
            PlaybackSpeed::QuarterSpeed => 0.25,
            PlaybackSpeed::HalfSpeed => 0.5,
            PlaybackSpeed::Normal => 1.0,
            PlaybackSpeed::Double => 2.0,
            PlaybackSpeed::Quadruple => 4.0,
            PlaybackSpeed::TenX => 10.0,
            PlaybackSpeed::Maximum => f64::INFINITY,
        }
    }

    /// Get milliseconds per frame at this speed.
    pub fn ms_per_frame(&self, base_ms: u64) -> Option<u64> {
        match self {
            PlaybackSpeed::Paused => None,
            PlaybackSpeed::Maximum => Some(0),
            speed => Some((base_ms as f64 / speed.multiplier()) as u64),
        }
    }
}

/// Current state of playback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaybackState {
    /// Playback is stopped at beginning
    Stopped,
    /// Playback is running forward
    Playing,
    /// Playback is paused
    Paused,
    /// Playback reached the end
    Finished,
}

/// Playback controller for event timeline.
pub struct Playback {
    events: Vec<MeshEvent>,
    current_frame: usize,
    state: PlaybackState,
    speed: PlaybackSpeed,
    loop_enabled: bool,
}

impl Playback {
    /// Create a new playback controller.
    pub fn new(events: Vec<MeshEvent>) -> Self {
        Self {
            events,
            current_frame: 0,
            state: PlaybackState::Stopped,
            speed: PlaybackSpeed::Normal,
            loop_enabled: false,
        }
    }

    /// Get the current frame number.
    pub fn current_frame(&self) -> usize {
        self.current_frame
    }

    /// Get the total number of frames.
    pub fn total_frames(&self) -> usize {
        self.events.len()
    }

    /// Get the current playback state.
    pub fn state(&self) -> PlaybackState {
        self.state
    }

    /// Get the current playback speed.
    pub fn speed(&self) -> PlaybackSpeed {
        self.speed
    }

    /// Seek to a specific frame.
    pub fn seek(&mut self, frame: usize) {
        self.current_frame = frame.min(self.events.len());
        if self.current_frame == self.events.len() && !self.loop_enabled {
            self.state = PlaybackState::Finished;
        }
    }

    /// Start playback.
    pub fn play(&mut self) {
        if self.current_frame >= self.events.len() {
            self.current_frame = 0;
        }
        self.state = PlaybackState::Playing;
    }

    /// Pause playback.
    pub fn pause(&mut self) {
        self.state = PlaybackState::Paused;
    }

    /// Stop playback and return to beginning.
    pub fn stop(&mut self) {
        self.current_frame = 0;
        self.state = PlaybackState::Stopped;
    }

    /// Set playback speed.
    pub fn set_speed(&mut self, speed: PlaybackSpeed) {
        self.speed = speed;
        if matches!(speed, PlaybackSpeed::Paused) {
            self.state = PlaybackState::Paused;
        }
    }

    /// Enable or disable looping.
    pub fn set_loop(&mut self, enabled: bool) {
        self.loop_enabled = enabled;
    }

    /// Step forward one frame.
    pub fn step_forward(&mut self) -> Option<&MeshEvent> {
        if self.current_frame < self.events.len() {
            let event = &self.events[self.current_frame];
            self.current_frame += 1;
            if self.current_frame >= self.events.len() {
                if self.loop_enabled {
                    self.current_frame = 0;
                } else {
                    self.state = PlaybackState::Finished;
                }
            }
            Some(event)
        } else {
            None
        }
    }

    /// Step backward one frame.
    pub fn step_backward(&mut self) {
        if self.current_frame > 0 {
            self.current_frame -= 1;
            self.state = PlaybackState::Paused;
        }
    }

    /// Get events in a frame range.
    pub fn events_in_range(&self, start: usize, end: usize) -> &[MeshEvent] {
        let start = start.min(self.events.len());
        let end = end.min(self.events.len());
        &self.events[start..end]
    }

    /// Get all events up to current frame (for rebuilding state).
    pub fn events_to_current(&self) -> &[MeshEvent] {
        &self.events[..self.current_frame]
    }

    /// Get the event at the current frame (if any).
    pub fn current_event(&self) -> Option<&MeshEvent> {
        self.events.get(self.current_frame)
    }

    /// Calculate progress as percentage (0.0 - 1.0).
    pub fn progress(&self) -> f64 {
        if self.events.is_empty() {
            0.0
        } else {
            self.current_frame as f64 / self.events.len() as f64
        }
    }
}

/// Playback status for sending to frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackStatus {
    pub current_frame: usize,
    pub total_frames: usize,
    pub state: PlaybackState,
    pub speed: PlaybackSpeed,
    pub progress: f64,
    pub loop_enabled: bool,
}

impl From<&Playback> for PlaybackStatus {
    fn from(playback: &Playback) -> Self {
        Self {
            current_frame: playback.current_frame,
            total_frames: playback.total_frames(),
            state: playback.state,
            speed: playback.speed,
            progress: playback.progress(),
            loop_enabled: playback.loop_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NodeId;
    use citadel_topology::{HexCoord, SpiralIndex};

    fn make_events(count: usize) -> Vec<MeshEvent> {
        (0..count)
            .map(|i| MeshEvent::NodeJoined {
                node: NodeId(i as u64),
                slot: SpiralIndex::new(i as u64),
                coord: HexCoord::ORIGIN,
                frame: i as u64,
            })
            .collect()
    }

    #[test]
    fn playback_starts_at_zero() {
        let playback = Playback::new(make_events(10));
        assert_eq!(playback.current_frame(), 0);
        assert_eq!(playback.state(), PlaybackState::Stopped);
    }

    #[test]
    fn seek_clamps_to_bounds() {
        let mut playback = Playback::new(make_events(10));

        playback.seek(5);
        assert_eq!(playback.current_frame(), 5);

        playback.seek(100);
        assert_eq!(playback.current_frame(), 10);

        playback.seek(0);
        assert_eq!(playback.current_frame(), 0);
    }

    #[test]
    fn step_forward_advances() {
        let mut playback = Playback::new(make_events(5));

        let event = playback.step_forward();
        assert!(event.is_some());
        assert_eq!(playback.current_frame(), 1);

        playback.step_forward();
        playback.step_forward();
        assert_eq!(playback.current_frame(), 3);
    }

    #[test]
    fn step_forward_stops_at_end() {
        let mut playback = Playback::new(make_events(3));

        playback.step_forward();
        playback.step_forward();
        playback.step_forward();
        assert_eq!(playback.state(), PlaybackState::Finished);

        let event = playback.step_forward();
        assert!(event.is_none());
    }

    #[test]
    fn loop_wraps_around() {
        let mut playback = Playback::new(make_events(3));
        playback.set_loop(true);

        playback.step_forward();
        playback.step_forward();
        playback.step_forward();
        assert_eq!(playback.current_frame(), 0);
        assert_ne!(playback.state(), PlaybackState::Finished);
    }

    #[test]
    fn progress_calculation() {
        let mut playback = Playback::new(make_events(10));

        assert_eq!(playback.progress(), 0.0);

        playback.seek(5);
        assert_eq!(playback.progress(), 0.5);

        playback.seek(10);
        assert_eq!(playback.progress(), 1.0);
    }

    #[test]
    fn speed_multipliers() {
        assert_eq!(PlaybackSpeed::Paused.multiplier(), 0.0);
        assert_eq!(PlaybackSpeed::Normal.multiplier(), 1.0);
        assert_eq!(PlaybackSpeed::Double.multiplier(), 2.0);
        assert!(PlaybackSpeed::Maximum.multiplier().is_infinite());
    }

    #[test]
    fn status_conversion() {
        let mut playback = Playback::new(make_events(10));
        playback.seek(3);
        playback.set_speed(PlaybackSpeed::Double);

        let status: PlaybackStatus = (&playback).into();
        assert_eq!(status.current_frame, 3);
        assert_eq!(status.total_frames, 10);
        assert_eq!(status.speed, PlaybackSpeed::Double);
    }
}
