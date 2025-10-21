//! # The Ghost Module
//!
//! This module implements the "Chameleon Steganography" layer of the
//! Matryoshka Protocol. It is responsible for hiding encrypted MTP packets
//! inside various forms of plausible-looking cover traffic.

pub mod engine;
pub mod strategies;
pub mod cover_traffic;
pub mod fast_ghost;
pub mod dead_drop;
pub mod service_rotation;
pub mod timing;

pub use engine::GhostEngine;
pub use fast_ghost::FastGhost;
pub use dead_drop::DeadDropProtocol;
pub use service_rotation::ServiceRotation;
pub use timing::{TimingRandomizer, GhostStatistics};

// Define a common, top-level error type for all steganography operations.
#[derive(Debug, thiserror::Error)]
pub enum GhostError {
    #[error("Failed to embed payload into cover traffic: {0}")]
    EmbeddingError(String),
    #[error("Failed to extract payload from ghost packet: {0}")]
    ExtractionError(String),
}

/// Complete Ghost Mode with all features
pub struct CompleteGhostMode {
    #[allow(dead_code)]
    engine: GhostEngine,
    dead_drop: DeadDropProtocol,
    service_rotation: ServiceRotation,
    timing: TimingRandomizer,
    stats: GhostStatistics,
}

impl CompleteGhostMode {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            engine: GhostEngine::new(),
            dead_drop: DeadDropProtocol::new(key),
            service_rotation: ServiceRotation::new(key),
            timing: TimingRandomizer::default(),
            stats: GhostStatistics::new(),
        }
    }
    
    /// Send invisible message with timing randomization
    pub fn send_invisible(&mut self, message: &str) -> Result<(serde_json::Value, String), GhostError> {
        self.stats.messages_sent += 1;
        self.stats.update_send_time();
        self.service_rotation.send_rotated(message)
    }
    
    /// Send with behavioral camouflage (mix with real traffic)
    pub fn send_with_camouflage(&mut self, message: &str, real_traffic_ratio: f64) 
        -> Result<(serde_json::Value, String), GhostError> 
    {
        // Send real traffic first
        let num_real = ((1.0 / (1.0 - real_traffic_ratio)) - 1.0) as u64;
        
        for _ in 0..num_real {
            self.stats.real_traffic_sent += 1;
            // Simulate real API call delay
            std::thread::sleep(std::time::Duration::from_millis(
                rand::random::<u64>() % 3000 + 500
            ));
        }
        
        // Now send hidden message
        self.send_invisible(message)
    }
    
    /// Drop message at dead drop location
    pub fn drop_message(&mut self, drop_id: &str, message: &str, service: &str) 
        -> Result<String, GhostError> 
    {
        self.dead_drop.drop_message(drop_id, message, service)
    }
    
    /// Pickup message from dead drop
    pub fn pickup_message(&self, drop_location: &str) -> Result<String, GhostError> {
        self.dead_drop.pickup_message(drop_location)
    }
    
    /// Wait random delay (human-like)
    pub fn wait_random_delay(&self) {
        self.timing.wait_random_delay();
    }
    
    /// Get statistics
    pub fn get_statistics(&self) -> &GhostStatistics {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_complete_ghost_mode() {
        let key = [42u8; 32];
        let mut ghost = CompleteGhostMode::new(key);
        
        let (cover, service) = ghost.send_invisible("Secret message").unwrap();
        assert!(cover.is_object());
        assert!(service.len() > 0);
        
        let stats = ghost.get_statistics();
        assert_eq!(stats.messages_sent, 1);
    }
}
