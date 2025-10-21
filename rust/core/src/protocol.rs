//! # High-Level Protocol Wrapper
//!
//! Provides MatryoshkaProtocol class matching Python's protocol.py
//! with send_message/receive_message API.

use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose, Engine as _};

use crate::crypto::classical::ChainKey;
use crate::crypto::fractal::PQFractalBundle;
use crate::zkp::InnocenceProofData;

/// GhostMessage wrapper with steganographic cover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostMessage {
    pub cover_data: serde_json::Value,
    pub encrypted_payload: String,
    pub cover_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_decoys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub innocence_proof: Option<InnocenceProofData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub future_bundle: Option<PQFractalBundle>,
}

impl GhostMessage {
    pub fn new(cover_data: serde_json::Value, encrypted_payload: String) -> Self {
        Self {
            cover_data,
            encrypted_payload,
            cover_type: "JSON_API".to_string(),
            quantum_decoys: None,
            innocence_proof: None,
            future_bundle: None,
        }
    }
}

/// Future key bundle for forward secrecy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FutureBundle {
    pub classical_keys: Vec<[u8; 32]>,
    pub quantum_seed: [u8; 32],
}

impl FutureBundle {
    pub fn new(chain_key: Option<[u8; 32]>) -> Self {
        let key = chain_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            use rand::Rng;
            rand::thread_rng().fill(&mut k);
            k
        });
        
        Self {
            classical_keys: Self::generate_classical_keys(&key),
            quantum_seed: Self::generate_quantum_seed(&key),
        }
    }
    
    fn generate_classical_keys(chain_key: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut keys = Vec::new();
        for i in 1..=3 {
            let info = format!("future-key-{}", i);
            let mut key = [0u8; 32];
            Hkdf::<Sha256>::new(Some(chain_key), chain_key)
                .expand(info.as_bytes(), &mut key)
                .expect("HKDF expand failed");
            keys.push(key);
        }
        keys
    }
    
    fn generate_quantum_seed(chain_key: &[u8; 32]) -> [u8; 32] {
        let mut seed = [0u8; 32];
        Hkdf::<Sha256>::new(Some(chain_key), chain_key)
            .expand(b"quantum-seed", &mut seed)
            .expect("HKDF expand failed");
        seed
    }
    
    pub fn get_recovery_key(&self, index: usize) -> Option<[u8; 32]> {
        if index < 3 {
            Some(self.classical_keys[index])
        } else {
            None
        }
    }
}

/// High-level Matryoshka Protocol
pub struct MatryoshkaProtocol {
    #[allow(dead_code)]
    key: [u8; 32],
    #[allow(dead_code)]
    cipher: Aes256Gcm,
    message_counter: u64,
    send_chain_key: ChainKey,
    recv_chain_key: ChainKey,
}

impl MatryoshkaProtocol {
    /// Create new protocol instance with key
    pub fn new(key: Option<&[u8]>) -> Self {
        let root_key = if let Some(k) = key {
            if k.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(k);
                arr
            } else {
                Self::derive_key_from_string(k)
            }
        } else {
            let mut k = [0u8; 32];
            use rand::Rng;
            rand::thread_rng().fill(&mut k);
            k
        };
        
        let cipher = Aes256Gcm::new_from_slice(&root_key).expect("Invalid key");
        
        // Use same chain key for both send and recv (for single-instance use)
        let chain_key = Self::derive_chain_key(&root_key, b"chain");
        let send_chain_key = chain_key;
        let recv_chain_key = chain_key;
        
        Self {
            key: root_key,
            cipher,
            message_counter: 0,
            send_chain_key: ChainKey(send_chain_key),
            recv_chain_key: ChainKey(recv_chain_key),
        }
    }
    
    fn derive_key_from_string(s: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"matryoshka-v1"), s)
            .expand(b"root-key", &mut key)
            .expect("HKDF expand failed");
        key
    }
    
    fn derive_chain_key(root_key: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
        let mut chain_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(root_key), root_key)
            .expand(&[b"chain-", purpose].concat(), &mut chain_key)
            .expect("HKDF expand failed");
        chain_key
    }
    
    /// Encrypt plaintext
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Ratchet forward
        let (new_chain_key, message_key) = self.ratchet_key(&self.send_chain_key.0);
        self.send_chain_key = ChainKey(new_chain_key);
        
        // Generate nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = aes_gcm::Nonce::from(nonce_bytes);
        
        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|_| "Cipher init failed")?;
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|_| "Encryption failed")?;
        
        // Return nonce + ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    /// Decrypt ciphertext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 12 {
            return Err("Invalid ciphertext".to_string());
        }
        
        // Ratchet forward
        let (new_chain_key, message_key) = self.ratchet_key(&self.recv_chain_key.0);
        self.recv_chain_key = ChainKey(new_chain_key);
        
        // Split nonce and ciphertext
        let nonce_bytes: [u8; 12] = ciphertext[..12].try_into().unwrap();
        let nonce = aes_gcm::Nonce::from(nonce_bytes);
        let ct = &ciphertext[12..];
        
        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|_| "Cipher init failed")?;
        cipher.decrypt(&nonce, ct)
            .map_err(|_| "Decryption failed".to_string())
    }
    
    fn ratchet_key(&self, chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut new_chain_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(chain_key), chain_key)
            .expand(b"ratchet", &mut new_chain_key)
            .expect("HKDF expand failed");
        
        let mut message_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(chain_key), chain_key)
            .expand(b"message", &mut message_key)
            .expect("HKDF expand failed");
        
        (new_chain_key, message_key)
    }
    
    /// Send message with steganography
    pub fn send_message(
        &mut self,
        message: &str,
        use_steganography: bool,
        include_quantum_decoys: bool,
        generate_innocence_proof: bool,
    ) -> Result<GhostMessage, String> {
        self.message_counter += 1;
        
        // Encrypt
        let encrypted = self.encrypt(message.as_bytes())?;
        let encoded = general_purpose::STANDARD.encode(&encrypted);
        
        let cover = if use_steganography {
            // Hide in JSON API response
            serde_json::json!({
                "status": "success",
                "data": {
                    "user_id": 12345 + self.message_counter,
                    "session_token": encoded.clone(),
                    "preferences": {"theme": "dark", "lang": "en"},
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                },
                "meta": {"version": "2.1.0", "server": "api-01"}
            })
        } else {
            serde_json::json!({"encrypted": encoded.clone()})
        };
        
        let mut ghost_msg = GhostMessage::new(cover, encoded);
        
        // Add quantum decoys if requested
        if include_quantum_decoys {
            let decoys: Vec<String> = (0..3)
                .map(|i| general_purpose::STANDARD.encode(format!("fake_rsa_data_{}", i)))
                .collect();
            ghost_msg.quantum_decoys = Some(decoys);
        }
        
        // Add innocence proof if requested
        if generate_innocence_proof {
            use crate::zkp::{generate_innocence_proof, TrafficPattern};
            let traffic = TrafficPattern {
                request_sizes: vec![1024, 2048, 512],
                timing_intervals: vec![100, 150, 200],
                content_types: vec!["application/json".to_string()],
            };
            // Using the new, working ZKP engine
            if let Ok(proof) = generate_innocence_proof(&traffic) {
                ghost_msg.innocence_proof = Some(proof);
            }
        }
        
        Ok(ghost_msg)
    }
    
    /// Receive and decrypt message
    pub fn receive_message(&mut self, ghost_msg: &GhostMessage) -> Result<String, String> {
        // Extract payload
        let encoded = if let Some(data) = ghost_msg.cover_data.get("data") {
            if let Some(token) = data.get("session_token") {
                token.as_str().ok_or("Invalid token")?
            } else {
                ghost_msg.encrypted_payload.as_str()
            }
        } else if let Some(enc) = ghost_msg.cover_data.get("encrypted") {
            enc.as_str().ok_or("Invalid encrypted field")?
        } else {
            ghost_msg.encrypted_payload.as_str()
        };
        
        // Decrypt
        let encrypted = general_purpose::STANDARD.decode(encoded)
            .map_err(|_| "Base64 decode failed")?;
        let plaintext = self.decrypt(&encrypted)?;
        
        String::from_utf8(plaintext)
            .map_err(|_| "UTF-8 decode failed".to_string())
    }
    
    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|e| e.to_string())?;
        encoder.finish().map_err(|e| e.to_string())
    }
    
    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|e| e.to_string())?;
        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_encrypt_decrypt() {
        let mut protocol = MatryoshkaProtocol::new(Some(b"test_key_32_bytes_long_padding!!"));
        
        let encrypted = protocol.encrypt(b"Hello Bob!").unwrap();
        let decrypted = protocol.decrypt(&encrypted).unwrap();
        
        assert_eq!(decrypted, b"Hello Bob!");
    }
    
    #[test]
    fn test_send_receive_message() {
        let mut protocol = MatryoshkaProtocol::new(Some(b"test_key"));
        
        let ghost_msg = protocol.send_message("Secret message", true, false, false).unwrap();
        let received = protocol.receive_message(&ghost_msg).unwrap();
        
        assert_eq!(received, "Secret message");
    }
    
    #[test]
    fn test_future_bundle() {
        let bundle = FutureBundle::new(None);
        
        assert_eq!(bundle.classical_keys.len(), 3);
        assert!(bundle.get_recovery_key(0).is_some());
        assert!(bundle.get_recovery_key(3).is_none());
    }
    
    #[test]
    fn test_compression() {
        let protocol = MatryoshkaProtocol::new(None);
        let data = b"test data to compress";
        
        let compressed = protocol.compress(data).unwrap();
        let decompressed = protocol.decompress(&compressed).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
