//! # The Session Manager
//!
//! This module provides the top-level `MatryoshkaSession` struct, which manages
//! the entire state for a secure communication session. Its primary responsibility
//! is to maintain and route traffic between the real and decoy ratchets,
//! providing the plausible deniability layer.
//!
//! Enhanced to match Python's MatryoshkaProtocol with compression, statistics,
//! and key exchange utilities.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand_core::OsRng;
use hkdf::Hkdf;
use sha2::Sha256;

use super::{
    ratchet::{
        adaptive::{AdaptiveRatchet, QuantumTrigger},
        state::MtpPacket,
        RatchetError,
    },
    ghost::GhostEngine,
};

/// Manages a full session between two users, including real and decoy ratchets.
/// This is the primary entry point for applications using the mtp-core library.
pub struct MatryoshkaSession {
    real_ratchet: AdaptiveRatchet,
    decoy_ratchet: AdaptiveRatchet,
    ghost_engine: GhostEngine,
    
    // Statistics
    message_counter: u64,
    bytes_sent: u64,
    bytes_received: u64,
    
    // Session metadata
    session_id: [u8; 16],
    is_initiator: bool,
}

impl MatryoshkaSession {
    /// Creates a new session manager with both a real and a decoy ratchet.
    pub fn new(
        initial_shared_secret: &[u8],
        decoy_shared_secret: &[u8],
        remote_dh_public_key: X25519PublicKey,
        is_initiator: bool,
    ) -> Result<Self, RatchetError> {
        let real_ratchet = AdaptiveRatchet::new(initial_shared_secret, remote_dh_public_key, is_initiator, false, None)?;
        let decoy_ratchet = AdaptiveRatchet::new(decoy_shared_secret, remote_dh_public_key, is_initiator, true, None)?;
        
        // Generate session ID
        let mut session_id = [0u8; 16];
        use rand::Rng;
        rand::thread_rng().fill(&mut session_id);

        Ok(Self {
            real_ratchet,
            decoy_ratchet,
            ghost_engine: GhostEngine::new(),
            message_counter: 0,
            bytes_sent: 0,
            bytes_received: 0,
            session_id,
            is_initiator,
        })
    }

    /// Encrypts a plaintext message for either the real or decoy conversation.
    pub fn encrypt(&mut self, plaintext: &[u8], is_decoy: bool) -> Result<MtpPacket, RatchetError> {
        self.message_counter += 1;
        self.bytes_sent += plaintext.len() as u64;
        
        if is_decoy {
            self.decoy_ratchet.ratchet_encrypt(plaintext)
        } else {
            self.real_ratchet.ratchet_encrypt(plaintext)
        }
    }

    /// Decrypts a received MTP packet.
    ///
    /// It inspects the packet's header to determine whether it belongs to the
    /// real or decoy conversation and routes it to the appropriate ratchet.
    pub fn decrypt(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        let plaintext = if packet.header.decoy_flag {
            self.decoy_ratchet.ratchet_decrypt(packet)
        } else {
            self.real_ratchet.ratchet_decrypt(packet)
        }?;
        
        self.bytes_received += plaintext.len() as u64;
        Ok(plaintext)
    }
    
    /// Send message with steganography
    pub fn send_message(&mut self, message: &str, use_steganography: bool, is_decoy: bool) -> Result<Vec<u8>, RatchetError> {
        let plaintext = message.as_bytes();
        let packet = self.encrypt(plaintext, is_decoy)?;
        
        if use_steganography {
            self.ghost_engine.embed(&packet)
                .map_err(|e| RatchetError::StateError(format!("Ghost embedding failed: {:?}", e)))
        } else {
            // Serialize packet without steganography
            rmp_serde::to_vec_named(&packet)
                .map_err(|e| RatchetError::StateError(format!("Serialization failed: {}", e)))
        }
    }
    
    /// Receive message with steganography extraction
    pub fn receive_message(&mut self, ghost_data: &[u8]) -> Result<String, RatchetError> {
        // Try to extract from steganography first
        let packet = match self.ghost_engine.extract(ghost_data) {
            Ok(p) => p,
            Err(_) => {
                // Fallback: try direct deserialization
                rmp_serde::from_slice(ghost_data)
                    .map_err(|e| RatchetError::StateError(format!("Deserialization failed: {}", e)))?
            }
        };
        
        let plaintext = self.decrypt(&packet)?;
        String::from_utf8(plaintext)
            .map_err(|e| RatchetError::StateError(format!("UTF-8 decode failed: {}", e)))
    }
    
    /// Compress data before encryption
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, RatchetError> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)
            .map_err(|e| RatchetError::StateError(format!("Compression failed: {}", e)))?;
        encoder.finish()
            .map_err(|e| RatchetError::StateError(format!("Compression finish failed: {}", e)))
    }
    
    /// Decompress data after decryption
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, RatchetError> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| RatchetError::StateError(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }
    
    /// Trigger quantum mode on real ratchet
    pub fn trigger_quantum_mode(&mut self, reason: QuantumTrigger) {
        self.real_ratchet.trigger_quantum_mode(reason);
    }
    
    /// Get session statistics
    pub fn get_stats(&self) -> SessionStats {
        SessionStats {
            message_counter: self.message_counter,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            session_id: self.session_id,
            is_initiator: self.is_initiator,
        }
    }
    
    /// Generate X25519 keypair for key exchange
    pub fn generate_keypair() -> (StaticSecret, X25519PublicKey) {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        (private_key, public_key)
    }
    
    /// Derive shared secret from X25519 key exchange
    pub fn derive_shared_secret(private_key: &StaticSecret, peer_public_key: &X25519PublicKey) -> [u8; 32] {
        let shared_secret = private_key.diffie_hellman(peer_public_key);
        
        // Derive 32-byte key from shared secret using HKDF
        let mut output = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"matryoshka-x25519"), shared_secret.as_bytes())
            .expand(b"shared-secret", &mut output)
            .expect("HKDF expand failed");
        output
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub message_counter: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub session_id: [u8; 16],
    pub is_initiator: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_creation() {
        let shared_secret = [42u8; 32];
        let decoy_secret = [24u8; 32];
        let (_, remote_pk) = MatryoshkaSession::generate_keypair();
        
        let session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true);
        assert!(session.is_ok());
    }
    
    #[test]
    fn test_key_exchange() {
        let (alice_sk, alice_pk) = MatryoshkaSession::generate_keypair();
        let (bob_sk, bob_pk) = MatryoshkaSession::generate_keypair();
        
        let alice_shared = MatryoshkaSession::derive_shared_secret(&alice_sk, &bob_pk);
        let bob_shared = MatryoshkaSession::derive_shared_secret(&bob_sk, &alice_pk);
        
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_compression() {
        let shared_secret = [42u8; 32];
        let decoy_secret = [24u8; 32];
        let (_, remote_pk) = MatryoshkaSession::generate_keypair();
        
        let session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
        
        let data = b"test data to compress";
        let compressed = session.compress(data).unwrap();
        let decompressed = session.decompress(&compressed).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}