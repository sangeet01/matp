// Simple test function to verify ZKP functionality
pub fn test_innocence_proof() -> bool {
    use crate::zkp::{ZkpEngine, TrafficPattern};
    
    let engine = ZkpEngine::new();
    
    // Normal web traffic pattern
    let normal_traffic = TrafficPattern {
        request_sizes: vec![1024, 2048, 1536, 800],
        timing_intervals: vec![200, 150, 300, 100],
        content_types: vec![
            "application/json".to_string(),
            "text/html".to_string(),
            "image/jpeg".to_string(),
            "application/json".to_string(),
        ],
    };
    
    // Generate and verify proof
    match engine.prove_innocence(&normal_traffic) {
        Ok(proof) => engine.verify_innocence(&proof),
        Err(_) => false,
    }
}

// Suspicious traffic pattern for testing
pub fn test_suspicious_traffic() -> bool {
    use crate::zkp::{ZkpEngine, TrafficPattern};
    
    let engine = ZkpEngine::new();
    
    // Suspicious traffic (too large requests)
    let suspicious_traffic = TrafficPattern {
        request_sizes: vec![100000, 200000, 150000], // Way too large
        timing_intervals: vec![10, 5, 8], // Too fast
        content_types: vec![
            "application/octet-stream".to_string(),
            "application/octet-stream".to_string(),
            "application/octet-stream".to_string(),
        ],
    };
    
    // This should fail to generate a proof
    engine.prove_innocence(&suspicious_traffic).is_err()
}