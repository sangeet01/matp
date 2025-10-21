//! # Fractal Group Ratchet
//!
//! Original design for multi-party encrypted communication.
//! Like Russian dolls: Each message encrypted in layers.
//! Fractal tree structure: Keys derived from single seed.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use rand::Rng;

use super::GroupError;

const VERSION: &str = "1.0.0";
const ALGORITHM: &str = "fractal-group-ratchet-v1";

/// Encrypted message envelope for group communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupEnvelope {
    pub version: String,
    pub algorithm: String,
    pub layer: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub seed_fingerprint: String,
    pub timestamp: f64,
}

/// Fractal Group Ratchet for efficient group encryption
pub struct FractalGroupRatchet {
    group_seed: [u8; 32],
    pub message_counter: u32,
    seed_fingerprint: String,
}

impl FractalGroupRatchet {
    /// Create new ratchet with optional seed
    pub fn new(group_seed: Option<[u8; 32]>) -> Self {
        let seed = group_seed.unwrap_or_else(|| {
            let mut s = [0u8; 32];
            rand::thread_rng().fill(&mut s);
            s
        });
        
        let fingerprint = Self::compute_fingerprint(&seed);
        
        Self {
            group_seed: seed,
            message_counter: 0,
            seed_fingerprint: fingerprint,
        }
    }
    
    /// Compute fingerprint of group seed
    fn compute_fingerprint(seed: &[u8; 32]) -> String {
        use sha2::Digest;
        let hash = Sha256::digest(seed);
        hex::encode(&hash[..16])
    }
    
    /// Derive encryption key for specific message layer
    fn derive_layer_key(&self, layer_index: u32) -> Result<[u8; 32], GroupError> {
        let info = format!("fractal-layer-{}", layer_index);
        let mut key = [0u8; 32];
        
        Hkdf::<Sha256>::new(Some(b"matp-fractal-layer-key-salt"), &self.group_seed)
            .expand(info.as_bytes(), &mut key)
            .map_err(|_| GroupError::EncryptionError("Key derivation failed".to_string()))?;
        
        Ok(key)
    }
    
    /// Encrypt message for entire group
    pub fn encrypt_for_group(&mut self, plaintext: &str) -> Result<GroupEnvelope, GroupError> {
        let layer_key = self.derive_layer_key(self.message_counter)?;
        
        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&layer_key)
            .map_err(|_| GroupError::EncryptionError("Cipher init failed".to_string()))?;
        
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
        let nonce = Nonce::from(nonce_bytes);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| GroupError::EncryptionError("Encryption failed".to_string()))?;
        
        let envelope = GroupEnvelope {
            version: VERSION.to_string(),
            algorithm: ALGORITHM.to_string(),
            layer: self.message_counter,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            seed_fingerprint: self.seed_fingerprint.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        };
        
        self.message_counter += 1;
        Ok(envelope)
    }
    
    /// Decrypt message from group
    pub fn decrypt_from_group(&self, envelope: &GroupEnvelope) -> Result<String, GroupError> {
        // Verify version
        if envelope.version != VERSION {
            return Err(GroupError::DecryptionError(format!("Unsupported version: {}", envelope.version)));
        }
        
        // Verify algorithm
        if envelope.algorithm != ALGORITHM {
            return Err(GroupError::DecryptionError(format!("Unsupported algorithm: {}", envelope.algorithm)));
        }
        
        // Verify seed fingerprint
        if envelope.seed_fingerprint != self.seed_fingerprint {
            return Err(GroupError::DecryptionError("Wrong group seed".to_string()));
        }
        
        // Derive key for this layer
        let layer_key = self.derive_layer_key(envelope.layer)?;
        
        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&layer_key)
            .map_err(|_| GroupError::DecryptionError("Cipher init failed".to_string()))?;
        
        let nonce_bytes: [u8; 12] = envelope.nonce.as_slice().try_into().unwrap();
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = cipher.decrypt(&nonce, envelope.ciphertext.as_slice())
            .map_err(|_| GroupError::DecryptionError("Decryption failed".to_string()))?;
        
        String::from_utf8(plaintext)
            .map_err(|_| GroupError::DecryptionError("UTF-8 decode failed".to_string()))
    }
    
    /// Export session for new member
    pub fn export_session(&self, from_layer: u32) -> SessionExport {
        SessionExport {
            version: VERSION.to_string(),
            algorithm: ALGORITHM.to_string(),
            group_seed: self.group_seed,
            start_layer: from_layer,
            seed_fingerprint: self.seed_fingerprint.clone(),
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        }
    }
    
    /// Import session from admin
    pub fn import_session(&mut self, session: &SessionExport) -> Result<(), GroupError> {
        if session.version != VERSION {
            return Err(GroupError::InvalidState(format!("Incompatible version: {}", session.version)));
        }
        
        if session.algorithm != ALGORITHM {
            return Err(GroupError::InvalidState(format!("Incompatible algorithm: {}", session.algorithm)));
        }
        
        self.group_seed = session.group_seed;
        self.message_counter = session.start_layer;
        self.seed_fingerprint = Self::compute_fingerprint(&self.group_seed);
        
        if self.seed_fingerprint != session.seed_fingerprint {
            return Err(GroupError::InvalidState("Session fingerprint mismatch".to_string()));
        }
        
        Ok(())
    }
    
    /// Rotate group seed for backward secrecy
    pub fn rotate_seed(&mut self) -> [u8; 32] {
        let mut new_seed = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"matp-fractal-seed-rotation-salt"), &self.group_seed)
            .expand(b"seed-rotation", &mut new_seed)
            .expect("HKDF expand failed");
        
        self.group_seed = new_seed;
        self.message_counter = 0;
        self.seed_fingerprint = Self::compute_fingerprint(&self.group_seed);
        
        new_seed
    }
    
    /// Get group seed fingerprint
    pub fn get_fingerprint(&self) -> &str {
        &self.seed_fingerprint
    }
    
    /// Get group seed (for sharing with new members)
    pub fn get_group_seed(&self) -> [u8; 32] {
        self.group_seed
    }
}

/// Session export for new members
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionExport {
    pub version: String,
    pub algorithm: String,
    pub group_seed: [u8; 32],
    pub start_layer: u32,
    pub seed_fingerprint: String,
    pub exported_at: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_group_ratchet() {
        let mut alice = FractalGroupRatchet::new(None);
        let seed = alice.get_group_seed();
        let bob = FractalGroupRatchet::new(Some(seed));
        
        assert_eq!(alice.get_fingerprint(), bob.get_fingerprint());
        
        let msg = alice.encrypt_for_group("Hello group!").unwrap();
        let decrypted = bob.decrypt_from_group(&msg).unwrap();
        
        assert_eq!(decrypted, "Hello group!");
    }
    
    #[test]
    fn test_session_export() {
        let mut alice = FractalGroupRatchet::new(None);
        
        // Send some messages
        for i in 0..3 {
            alice.encrypt_for_group(&format!("Message {}", i)).unwrap();
        }
        
        // Export session for new member
        let session = alice.export_session(alice.message_counter);
        
        let mut dave = FractalGroupRatchet::new(None);
        dave.import_session(&session).unwrap();
        
        assert_eq!(dave.get_fingerprint(), alice.get_fingerprint());
    }
    
    #[test]
    fn test_seed_rotation() {
        let mut ratchet = FractalGroupRatchet::new(None);
        let old_fingerprint = ratchet.get_fingerprint().to_string();
        
        ratchet.rotate_seed();
        let new_fingerprint = ratchet.get_fingerprint();
        
        assert_ne!(old_fingerprint, new_fingerprint);
    }
}
