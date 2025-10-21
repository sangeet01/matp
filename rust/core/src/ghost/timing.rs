//! # Timing Randomization
//!
//! Human-like timing patterns with exponential distribution.

use std::time::Duration;
use rand::Rng;

/// Timing randomization for human-like behavior
pub struct TimingRandomizer {
    avg_delay_seconds: f64,
}

impl TimingRandomizer {
    pub fn new(avg_delay_seconds: f64) -> Self {
        Self { avg_delay_seconds }
    }
    
    /// Wait random time with exponential distribution (human-like)
    pub fn wait_random_delay(&self) {
        let delay = self.generate_delay();
        std::thread::sleep(delay);
    }
    
    /// Generate random delay without blocking
    pub fn generate_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        
        // Exponential distribution: -ln(U) / λ where λ = 1/avg
        let u: f64 = rng.gen();
        let delay_secs = -u.ln() * self.avg_delay_seconds;
        
        // Clamp to reasonable bounds (0.1s to 10x avg)
        let clamped = delay_secs.max(0.1).min(self.avg_delay_seconds * 10.0);
        
        Duration::from_secs_f64(clamped)
    }
    
    /// Generate jitter (small random variation)
    pub fn jitter(&self, base_ms: u64) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter_ms = rng.gen_range(-(base_ms as i64 / 2)..(base_ms as i64 / 2));
        let total_ms = (base_ms as i64 + jitter_ms).max(0) as u64;
        Duration::from_millis(total_ms)
    }
}

impl Default for TimingRandomizer {
    fn default() -> Self {
        Self::new(300.0) // 5 minutes default
    }
}

/// Statistics for behavioral camouflage
pub struct GhostStatistics {
    pub messages_sent: u64,
    pub real_traffic_sent: u64,
    pub last_send_time: f64,
}

impl GhostStatistics {
    pub fn new() -> Self {
        Self {
            messages_sent: 0,
            real_traffic_sent: 0,
            last_send_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        }
    }
    
    /// Get total traffic count
    pub fn total_traffic(&self) -> u64 {
        self.messages_sent + self.real_traffic_sent
    }
    
    /// Get hidden message ratio
    pub fn hidden_ratio(&self) -> f64 {
        let total = self.total_traffic();
        if total == 0 {
            0.0
        } else {
            self.messages_sent as f64 / total as f64
        }
    }
    
    /// Estimate detection probability (ε approximation)
    pub fn detection_probability(&self) -> f64 {
        self.hidden_ratio() * 0.001
    }
    
    /// Update last send time
    pub fn update_send_time(&mut self) {
        self.last_send_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
    }
}

impl Default for GhostStatistics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_randomizer() {
        let timer = TimingRandomizer::new(1.0);
        
        // Generate multiple delays
        let delays: Vec<Duration> = (0..100)
            .map(|_| timer.generate_delay())
            .collect();
        
        // Check they're in reasonable range
        for delay in delays {
            let secs = delay.as_secs_f64();
            assert!(secs >= 0.1 && secs <= 10.0);
        }
    }
    
    #[test]
    fn test_jitter() {
        let timer = TimingRandomizer::new(1.0);
        let jittered = timer.jitter(1000);
        
        let ms = jittered.as_millis();
        assert!(ms >= 500 && ms <= 1500);
    }
    
    #[test]
    fn test_statistics() {
        let mut stats = GhostStatistics::new();
        
        stats.messages_sent = 10;
        stats.real_traffic_sent = 90;
        
        assert_eq!(stats.total_traffic(), 100);
        assert_eq!(stats.hidden_ratio(), 0.1);
        assert!(stats.detection_probability() < 0.001);
    }
}
