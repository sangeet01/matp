//! # Service Rotation
//!
//! Rotate between multiple services for diversity and resilience.

use super::{GhostError, cover_traffic::json_templates::RealTrafficCapture};
use serde_json::Value;

const SERVICES: &[&str] = &["github", "stripe", "aws"];

/// Service rotation for diversity
pub struct ServiceRotation {
    key: [u8; 32],
    current_service_idx: usize,
    traffic_capture: RealTrafficCapture,
}

impl ServiceRotation {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            current_service_idx: 0,
            traffic_capture: RealTrafficCapture::new(),
        }
    }
    
    /// Send message with automatic service rotation
    pub fn send_rotated(&mut self, message: &str) -> Result<(Value, String), GhostError> {
        let service = SERVICES[self.current_service_idx];
        
        // Encrypt message
        let encrypted = self.encrypt_message(message)?;
        
        // Get cover traffic for this service
        let mut cover = self.traffic_capture.get_real_cover(service);
        
        // Embed payload
        self.embed_payload(&mut cover, &encrypted, service);
        
        // Rotate to next service
        self.current_service_idx = (self.current_service_idx + 1) % SERVICES.len();
        
        Ok((cover, service.to_string()))
    }
    
    /// Receive message from any service
    pub fn receive(&self, cover: &Value, service: &str) -> Result<String, GhostError> {
        let encrypted = self.extract_payload(cover, service)?;
        self.decrypt_message(&encrypted)
    }
    
    fn encrypt_message(&self, message: &str) -> Result<String, GhostError> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        use base64::{engine::general_purpose, Engine as _};
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| GhostError::EmbeddingError("Cipher init failed".to_string()))?;
        
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = aes_gcm::Nonce::from(nonce_bytes);
        
        let ciphertext = cipher.encrypt(&nonce, message.as_bytes())
            .map_err(|_| GhostError::EmbeddingError("Encryption failed".to_string()))?;
        
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        
        Ok(general_purpose::STANDARD.encode(&combined))
    }
    
    fn decrypt_message(&self, encrypted: &str) -> Result<String, GhostError> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        use base64::{engine::general_purpose, Engine as _};
        
        let combined = general_purpose::STANDARD.decode(encrypted)
            .map_err(|e| GhostError::ExtractionError(e.to_string()))?;
        
        if combined.len() < 12 {
            return Err(GhostError::ExtractionError("Invalid ciphertext".to_string()));
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| GhostError::ExtractionError("Cipher init failed".to_string()))?;
        
        let nonce_bytes: [u8; 12] = combined[..12].try_into().unwrap();
        let nonce = aes_gcm::Nonce::from(nonce_bytes);
        let ciphertext = &combined[12..];
        
        let plaintext = cipher.decrypt(&nonce, ciphertext)
            .map_err(|_| GhostError::ExtractionError("Decryption failed".to_string()))?;
        
        String::from_utf8(plaintext)
            .map_err(|_| GhostError::ExtractionError("UTF-8 decode failed".to_string()))
    }
    
    fn embed_payload(&self, cover: &mut Value, payload: &str, service: &str) {
        if let Some(obj) = cover.as_object_mut() {
            match service {
                "github" => {
                    obj.insert("bio".to_string(), Value::String(payload.to_string()));
                },
                "stripe" => {
                    obj.insert("description".to_string(), Value::String(payload.to_string()));
                },
                "aws" => {
                    if let Some(instances) = obj.get_mut("Instances") {
                        if let Some(arr) = instances.as_array_mut() {
                            if let Some(inst) = arr.get_mut(0) {
                                if let Some(inst_obj) = inst.as_object_mut() {
                                    inst_obj.insert("Tags".to_string(), 
                                        serde_json::json!([{"Key": "session", "Value": payload}]));
                                }
                            }
                        }
                    }
                },
                _ => {
                    obj.insert("_data".to_string(), Value::String(payload.to_string()));
                }
            }
        }
    }
    
    fn extract_payload(&self, cover: &Value, service: &str) -> Result<String, GhostError> {
        let payload = match service {
            "github" => cover.get("bio").and_then(|v| v.as_str()),
            "stripe" => cover.get("description").and_then(|v| v.as_str()),
            "aws" => {
                cover.get("Instances")
                    .and_then(|i| i.as_array())
                    .and_then(|a| a.get(0))
                    .and_then(|inst| inst.get("Tags"))
                    .and_then(|t| t.as_array())
                    .and_then(|tags| tags.get(0))
                    .and_then(|tag| tag.get("Value"))
                    .and_then(|v| v.as_str())
            },
            _ => cover.get("_data").and_then(|v| v.as_str()),
        };
        
        payload.map(|s| s.to_string())
            .ok_or_else(|| GhostError::ExtractionError("Payload not found".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_service_rotation() {
        let key = [42u8; 32];
        let mut rotator = ServiceRotation::new(key);
        
        let (cover1, service1) = rotator.send_rotated("Message 1").unwrap();
        let (_cover2, service2) = rotator.send_rotated("Message 2").unwrap();
        let (_cover3, service3) = rotator.send_rotated("Message 3").unwrap();
        
        // Should rotate through services
        assert_eq!(service1, "github");
        assert_eq!(service2, "stripe");
        assert_eq!(service3, "aws");
        
        // Should be able to decrypt
        let msg1 = rotator.receive(&cover1, &service1).unwrap();
        assert_eq!(msg1, "Message 1");
    }
}
