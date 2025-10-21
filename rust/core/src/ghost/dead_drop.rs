//! # Dead Drop Protocol
//!
//! Never communicate directly. Messages posted to public locations
//! and retrieved later. No direct connection between sender and receiver.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value;

use super::{GhostError, cover_traffic::json_templates::RealTrafficCapture};

/// Dead drop protocol - no direct communication
pub struct DeadDropProtocol {
    key: [u8; 32],
    drops: HashMap<String, Value>,
    traffic_capture: RealTrafficCapture,
}

impl DeadDropProtocol {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            drops: HashMap::new(),
            traffic_capture: RealTrafficCapture::new(),
        }
    }
    
    /// Drop message at public location
    pub fn drop_message(&mut self, drop_id: &str, message: &str, service: &str) 
        -> Result<String, GhostError> 
    {
        // Encrypt message
        let encrypted = self.encrypt_message(message)?;
        
        // Get real cover traffic
        let mut cover = self.traffic_capture.get_real_cover(service);
        
        // Embed encrypted message in service-specific field
        self.embed_in_cover(&mut cover, &encrypted, service);
        
        // Store in "public" location
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let drop_location = format!("{}:{}:{}", service, drop_id, timestamp);
        
        self.drops.insert(drop_location.clone(), cover);
        
        Ok(drop_location)
    }
    
    /// Pick up message from public location
    pub fn pickup_message(&self, drop_location: &str) -> Result<String, GhostError> {
        let cover = self.drops.get(drop_location)
            .ok_or_else(|| GhostError::ExtractionError("Drop not found".to_string()))?;
        
        // Extract encrypted message
        let encrypted = self.extract_from_cover(cover, drop_location)?;
        
        // Decrypt
        self.decrypt_message(&encrypted)
    }
    
    /// List available drop locations
    pub fn list_drops(&self, service: Option<&str>) -> Vec<String> {
        match service {
            Some(svc) => self.drops.keys()
                .filter(|k| k.starts_with(svc))
                .cloned()
                .collect(),
            None => self.drops.keys().cloned().collect(),
        }
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
    
    fn embed_in_cover(&self, cover: &mut Value, payload: &str, service: &str) {
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
    
    fn extract_from_cover(&self, cover: &Value, drop_location: &str) -> Result<String, GhostError> {
        let service = drop_location.split(':').next().unwrap_or("github");
        
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
    fn test_dead_drop() {
        let key = [42u8; 32];
        let mut protocol = DeadDropProtocol::new(key);
        
        let location = protocol.drop_message("secret_001", "The package is ready", "github").unwrap();
        let message = protocol.pickup_message(&location).unwrap();
        
        assert_eq!(message, "The package is ready");
    }
    
    #[test]
    fn test_list_drops() {
        let key = [42u8; 32];
        let mut protocol = DeadDropProtocol::new(key);
        
        protocol.drop_message("drop1", "msg1", "github").unwrap();
        protocol.drop_message("drop2", "msg2", "stripe").unwrap();
        
        let github_drops = protocol.list_drops(Some("github"));
        assert_eq!(github_drops.len(), 1);
        
        let all_drops = protocol.list_drops(None);
        assert_eq!(all_drops.len(), 2);
    }
}
