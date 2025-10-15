//! # JSON API Steganography Strategy
//!
//! Hides data within a plausible-looking JSON API response.

use serde_json::Value;

use crate::ghost::{
    cover_traffic::{find_and_replace_payload, get_random_json_template},
    engine::EmbeddingStrategy,
    GhostError,
};

pub struct JsonApiStrategy;

impl JsonApiStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Recursively searches a JSON Value for a likely payload (long string).
    fn find_payload_in_json(&self, data: &Value) -> Option<String> {
        if let Some(s) = data.as_str() {
            // Heuristic: our payload is a long base64 string.
            if s.len() > 100 {
                return Some(s.to_string());
            }
        } else if let Some(obj) = data.as_object() {
            for value in obj.values() {
                if let Some(p) = self.find_payload_in_json(value) {
                    return Some(p);
                }
            }
        } else if let Some(arr) = data.as_array() {
            for item in arr {
                if let Some(p) = self.find_payload_in_json(item) {
                    return Some(p);
                }
            }
        }
        None
    }
}

impl EmbeddingStrategy for JsonApiStrategy {
    fn embed(&self, payload: &str) -> Result<Vec<u8>, GhostError> {
        let mut template = get_random_json_template();
        if !find_and_replace_payload(&mut template, payload) {
            return Err(GhostError::EmbeddingError(
                "Failed to find payload placeholder in JSON template".to_string(),
            ));
        }
        Ok(template.to_string().into_bytes())
    }

    fn extract(&self, data: &[u8]) -> Option<String> {
        let json_data: Value = serde_json::from_slice(data).ok()?;
        self.find_payload_in_json(&json_data)
    }
}