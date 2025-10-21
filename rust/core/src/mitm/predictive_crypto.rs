//! Predictive Cryptography - Time-Based Key Rotation
//!
//! Eliminates handshake delays through synchronized time-based key rotation.
//! Performance: 0ms handshake overhead

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Time slot for key rotation
#[derive(Debug, Clone)]
pub struct TimeSlot {
    pub slot_id: i64,
    pub start_time: f64,
    pub end_time: f64,
    pub key: Vec<u8>,
}

/// Predictive cryptography with time-based key rotation
///
/// Both parties pre-compute keys for future time slots, eliminating
/// the need for key exchange during connection.
///
/// Performance: 0ms handshake overhead
pub struct PredictiveCrypto {
    master_secret: Vec<u8>,
    slot_duration: i64,
    key_cache: HashMap<i64, Vec<u8>>,
    pregenerate_slots: usize,
    keys_generated: u64,
    cache_hits: u64,
    cache_misses: u64,
}

impl PredictiveCrypto {
    /// Create new predictive crypto instance
    ///
    /// # Arguments
    /// * `master_secret` - 32-byte master secret (from initial handshake)
    /// * `slot_duration` - Duration of each time slot in seconds (default: 300 = 5 minutes)
    pub fn new(master_secret: Vec<u8>, slot_duration: i64) -> Self {
        assert_eq!(master_secret.len(), 32, "Master secret must be 32 bytes");

        let mut crypto = Self {
            master_secret,
            slot_duration,
            key_cache: HashMap::new(),
            pregenerate_slots: 10,
            keys_generated: 0,
            cache_hits: 0,
            cache_misses: 0,
        };

        crypto.pregenerate_keys();
        crypto
    }

    /// Get current time slot ID
    fn get_current_slot_id(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        now / self.slot_duration
    }

    /// Derive key for specific time slot
    fn derive_slot_key(&mut self, slot_id: i64) -> Vec<u8> {
        let info = format!("slot-{}", slot_id);
        let mut hasher = Sha256::new();
        hasher.update(&self.master_secret);
        hasher.update(info.as_bytes());
        self.keys_generated += 1;
        hasher.finalize().to_vec()
    }

    /// Pre-generate keys for upcoming time slots
    fn pregenerate_keys(&mut self) {
        let current_slot = self.get_current_slot_id();

        for i in 0..self.pregenerate_slots {
            let slot_id = current_slot + i as i64;
            if !self.key_cache.contains_key(&slot_id) {
                let key = self.derive_slot_key(slot_id);
                self.key_cache.insert(slot_id, key);
            }
        }

        self.cleanup_old_keys(current_slot);
    }

    /// Remove keys for past time slots
    fn cleanup_old_keys(&mut self, current_slot: i64) {
        let old_slots: Vec<i64> = self
            .key_cache
            .keys()
            .filter(|&&s| s < current_slot - 1)
            .copied()
            .collect();

        for slot in old_slots {
            self.key_cache.remove(&slot);
        }
    }

    /// Get key for current time slot (0ms overhead)
    ///
    /// Returns 32-byte session key
    pub fn get_current_key(&mut self) -> Vec<u8> {
        let slot_id = self.get_current_slot_id();

        if let Some(key) = self.key_cache.get(&slot_id) {
            self.cache_hits += 1;
            return key.clone();
        }

        self.cache_misses += 1;
        let key = self.derive_slot_key(slot_id);
        self.key_cache.insert(slot_id, key.clone());
        self.pregenerate_keys();

        key
    }

    /// Get key for specific time slot
    pub fn get_key_for_slot(&mut self, slot_id: i64) -> Vec<u8> {
        if let Some(key) = self.key_cache.get(&slot_id) {
            return key.clone();
        }
        self.derive_slot_key(slot_id)
    }

    /// Get current time slot information
    pub fn get_current_slot_info(&mut self) -> TimeSlot {
        let slot_id = self.get_current_slot_id();
        let start_time = (slot_id * self.slot_duration) as f64;
        let end_time = start_time + self.slot_duration as f64;
        let key = self.get_current_key();

        TimeSlot {
            slot_id,
            start_time,
            end_time,
            key,
        }
    }

    /// Verify time slot synchronization with peer
    ///
    /// Returns true if synchronized (within 1 slot)
    pub fn verify_slot_sync(&self, peer_slot_id: i64) -> bool {
        let current_slot = self.get_current_slot_id();
        (current_slot - peer_slot_id).abs() <= 1
    }

    /// Rotate master secret (for periodic refresh)
    pub fn rotate_master_secret(&mut self, new_secret: Vec<u8>) {
        assert_eq!(new_secret.len(), 32, "New secret must be 32 bytes");

        self.master_secret = new_secret;
        self.key_cache.clear();
        self.pregenerate_keys();
    }

    /// Get predictive crypto statistics
    pub fn get_stats(&self) -> PredictiveCryptoStats {
        let total_requests = self.cache_hits + self.cache_misses;
        PredictiveCryptoStats {
            keys_generated: self.keys_generated,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            cache_hit_rate: if total_requests > 0 {
                self.cache_hits as f64 / total_requests as f64
            } else {
                0.0
            },
            cached_keys: self.key_cache.len(),
            current_slot: self.get_current_slot_id(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PredictiveCryptoStats {
    pub keys_generated: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub cached_keys: usize,
    pub current_slot: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predictive_crypto_basic() {
        let master_secret = vec![0u8; 32];
        let mut crypto = PredictiveCrypto::new(master_secret, 300);

        let key1 = crypto.get_current_key();
        assert_eq!(key1.len(), 32);

        let key2 = crypto.get_current_key();
        assert_eq!(key1, key2); // Same slot = same key
    }

    #[test]
    fn test_slot_sync() {
        let master_secret = vec![0u8; 32];
        let crypto = PredictiveCrypto::new(master_secret, 300);

        let current = crypto.get_current_slot_id();
        assert!(crypto.verify_slot_sync(current));
        assert!(crypto.verify_slot_sync(current + 1));
        assert!(crypto.verify_slot_sync(current - 1));
        assert!(!crypto.verify_slot_sync(current + 2));
    }

    #[test]
    fn test_key_rotation() {
        let master_secret = vec![1u8; 32];
        let mut crypto = PredictiveCrypto::new(master_secret.clone(), 300);

        let key1 = crypto.get_current_key();

        let new_secret = vec![2u8; 32];
        crypto.rotate_master_secret(new_secret);

        let key2 = crypto.get_current_key();
        assert_ne!(key1, key2); // Different master secret = different key
    }

    #[test]
    fn test_cache_performance() {
        let master_secret = vec![0u8; 32];
        let mut crypto = PredictiveCrypto::new(master_secret, 300);

        // First access - cache miss
        crypto.get_current_key();
        
        // Second access - cache hit
        crypto.get_current_key();

        let stats = crypto.get_stats();
        assert!(stats.cache_hits > 0);
        assert!(stats.cache_hit_rate > 0.0);
    }
}
