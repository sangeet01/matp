//! # JSON API Cover Traffic
//!
//! This module provides templates and data for the `JsonApiStrategy`.

use rand::seq::SliceRandom;
use serde_json::{json, Value};

/// Returns a vector of plausible JSON API response templates.
fn get_json_api_templates() -> Vec<Value> {
    vec![
        json!({
            "status": "success",
            "data": {
                "items": ["item_A", "item_B", "item_C"],
                "metadata": "__MTP_PAYLOAD__",
                "last_updated": 1678886400
            },
            "request_id": "req_12345"
        }),
        json!({
            "user_id": "user_abc",
            "session_id": "sess_xyz",
            "config": {
                "features": {"feature_A": true, "feature_B": false},
                "telemetry_id": "__MTP_PAYLOAD__"
            },
            "timestamp": 1678886400
        }),
        json!({
            "event": "log_data",
            "level": "INFO",
            "payload": {
                "source": "client_app",
                "metrics": [
                    {"name": "cpu_usage", "value": 0.45},
                    {"name": "mem_usage", "value": 0.62}
                ],
                "diagnostics_blob": "__MTP_PAYLOAD__"
            }
        })
    ]
}

/// Selects a random JSON template from the available list.
pub fn get_random_json_template() -> Value {
    let templates = get_json_api_templates();
    // In a real implementation, we would add more dynamic data generation here.
    templates.choose(&mut rand::thread_rng()).unwrap().clone()
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