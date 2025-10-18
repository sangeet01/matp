//! # Hybrid Cover Traffic Generator
//!
//! No-training approach: Pre-analyzed templates + cryptographic randomness

use rand::{Rng, seq::SliceRandom};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Pre-analyzed templates based on public API patterns
#[derive(Clone)]
pub struct CoverTemplate {
    pub name: &'static str,
    pub structure: Value,
    pub realistic_ranges: RealisticRanges,
}

#[derive(Clone)]
pub struct RealisticRanges {
    pub user_id_range: (u32, u32),
    pub page_range: (u32, u32),
    pub item_count_range: (usize, usize),
}

pub struct HybridCoverGenerator {
    templates: Vec<CoverTemplate>,
    rng: ChaCha20Rng,
}

impl HybridCoverGenerator {
    pub fn new() -> Self {
        Self {
            templates: Self::load_builtin_templates(),
            rng: ChaCha20Rng::from_entropy(),
        }
    }
    
    /// Load pre-analyzed templates (no training needed)
    fn load_builtin_templates() -> Vec<CoverTemplate> {
        vec![
            // GitHub-style API
            CoverTemplate {
                name: "github_api",
                structure: json!({
                    "status": "success",
                    "data": {
                        "user_id": 0,
                        "session_token": "__MTP_PAYLOAD__",
                        "repos": [],
                        "followers": 0,
                        "following": 0
                    },
                    "meta": {
                        "version": "v3",
                        "server": "api-01"
                    }
                }),
                realistic_ranges: RealisticRanges {
                    user_id_range: (100000, 99999999),
                    page_range: (1, 100),
                    item_count_range: (0, 30),
                },
            },
            // E-commerce API
            CoverTemplate {
                name: "ecommerce_api",
                structure: json!({
                    "status": "ok",
                    "result": {
                        "order_id": 0,
                        "tracking_code": "__MTP_PAYLOAD__",
                        "items": [],
                        "total": 0.0,
                        "currency": "USD"
                    },
                    "timestamp": 0
                }),
                realistic_ranges: RealisticRanges {
                    user_id_range: (10000, 9999999),
                    page_range: (1, 50),
                    item_count_range: (1, 10),
                },
            },
            // Social Media API
            CoverTemplate {
                name: "social_api",
                structure: json!({
                    "success": true,
                    "posts": [],
                    "pagination": {
                        "page": 0,
                        "total_pages": 0,
                        "cursor": "__MTP_PAYLOAD__"
                    },
                    "user": {
                        "id": 0,
                        "verified": false
                    }
                }),
                realistic_ranges: RealisticRanges {
                    user_id_range: (1000, 999999999),
                    page_range: (1, 200),
                    item_count_range: (5, 50),
                },
            },
            // Generic REST API
            CoverTemplate {
                name: "generic_rest",
                structure: json!({
                    "status": "completed",
                    "data": {
                        "items": [],
                        "session": "__MTP_PAYLOAD__",
                        "preferences": {"theme": "dark", "lang": "en"}
                    },
                    "timestamp": 0,
                    "request_id": ""
                }),
                realistic_ranges: RealisticRanges {
                    user_id_range: (1000, 9999999),
                    page_range: (1, 100),
                    item_count_range: (0, 20),
                },
            },
        ]
    }
    
    /// Generate realistic cover with embedded payload (no training)
    pub fn generate_cover(&mut self, payload: &str) -> Value {
        // 1. Select random template
        let template = self.templates.choose(&mut self.rng).unwrap().clone();
        
        // 2. Clone structure
        let mut cover = template.structure.clone();
        
        // 3. Apply cryptographic randomness
        self.randomize_fields(&mut cover, &template.realistic_ranges);
        
        // 4. Embed payload
        find_and_replace_payload(&mut cover, payload);
        
        cover
    }
    
    /// Apply cryptographic randomness to make cover realistic
    fn randomize_fields(&mut self, cover: &mut Value, ranges: &RealisticRanges) {
        self.randomize_recursive(cover, ranges);
    }
    
    fn randomize_recursive(&mut self, value: &mut Value, ranges: &RealisticRanges) {
        match value {
            Value::Object(obj) => {
                for (key, val) in obj.iter_mut() {
                    match key.as_str() {
                        "user_id" | "order_id" | "id" => {
                            *val = json!(self.rng.gen_range(ranges.user_id_range.0..ranges.user_id_range.1));
                        },
                        "page" | "current_page" => {
                            *val = json!(self.rng.gen_range(ranges.page_range.0..ranges.page_range.1));
                        },
                        "total_pages" => {
                            *val = json!(self.rng.gen_range(ranges.page_range.0..ranges.page_range.1 * 2));
                        },
                        "timestamp" => {
                            *val = json!(self.realistic_timestamp());
                        },
                        "request_id" => {
                            *val = json!(self.random_request_id());
                        },
                        "server" => {
                            *val = json!(format!("api-{:02}", self.rng.gen_range(1..20)));
                        },
                        "followers" | "following" => {
                            *val = json!(self.rng.gen_range(0..10000));
                        },
                        "total" => {
                            *val = json!(self.rng.gen_range(10.0..1000.0));
                        },
                        "verified" => {
                            *val = json!(self.rng.gen_bool(0.1)); // 10% verified
                        },
                        _ => self.randomize_recursive(val, ranges),
                    }
                }
            },
            Value::Array(arr) => {
                // Generate realistic array items
                if arr.is_empty() {
                    let count = self.rng.gen_range(ranges.item_count_range.0..ranges.item_count_range.1);
                    for i in 0..count {
                        arr.push(json!({
                            "id": self.rng.gen::<u32>(),
                            "name": format!("item_{}", i),
                            "value": self.rng.gen_range(1..100)
                        }));
                    }
                }
            },
            _ => {},
        }
    }
    
    fn realistic_timestamp(&mut self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Add random jitter ±5 minutes
        let jitter = self.rng.gen_range(0..600) as i64 - 300;
        (now as i64 + jitter) as u64
    }
    
    fn random_request_id(&mut self) -> String {
        format!("req_{:x}", self.rng.gen::<u64>())
    }
}

/// Legacy function for compatibility
fn get_json_api_templates() -> Vec<Value> {
    HybridCoverGenerator::new()
        .templates
        .iter()
        .map(|t| t.structure.clone())
        .collect()
}

/// Selects a random JSON template (legacy - use HybridCoverGenerator instead)
pub fn get_random_json_template() -> Value {
    let mut generator = HybridCoverGenerator::new();
    let template = generator.templates.choose(&mut generator.rng).unwrap().clone();
    let mut cover = template.structure.clone();
    generator.randomize_fields(&mut cover, &template.realistic_ranges);
    cover
}

/// Recursively finds the `__MTP_PAYLOAD__` placeholder in a JSON Value and replaces it.
pub fn find_and_replace_payload(template: &mut Value, payload: &str) -> bool {
    if let Some(obj) = template.as_object_mut() {
        for (_key, value) in obj.iter_mut() {
            if value.is_string() && value.as_str() == Some("__MTP_PAYLOAD__") {
                *value = Value::String(payload.to_string());
                return true;
            }
            if find_and_replace_payload(value, payload) {
                return true;
            }
        }
    } else if let Some(arr) = template.as_array_mut() {
        for item in arr.iter_mut() {
            if find_and_replace_payload(item, payload) {
                return true;
            }
        }
    }
    false
}