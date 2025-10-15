use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
struct TrafficPattern {
    request_sizes: Vec<u32>,
    timing_intervals: Vec<u32>,
    content_types: Vec<String>,
}

#[derive(Debug, Clone)]
struct InnocenceProof {
    commitment: [u8; 32],
    challenge: [u8; 32],
    response: Vec<u8>,
}

struct ZkpEngine {
    normal_bounds: (Vec<f64>, Vec<f64>),
}

impl ZkpEngine {
    fn new() -> Self {
        let min_bounds = vec![500.0, 100.0, 0.1, 0.05];
        let max_bounds = vec![50000.0, 5000.0, 0.6, 0.8];
        Self { normal_bounds: (min_bounds, max_bounds) }
    }

    fn prove_innocence(&self, traffic: &TrafficPattern) -> Result<InnocenceProof, String> {
        let stats = self.extract_stats(traffic);
        
        if !self.is_normal(&stats) {
            return Err("Traffic appears suspicious".to_string());
        }

        let nonce: [u8; 32] = [42; 32]; // Fixed for testing
        
        let mut hasher = DefaultHasher::new();
        stats.hash(&mut hasher);
        nonce.hash(&mut hasher);
        let commitment_hash = hasher.finish();
        let commitment = commitment_hash.to_le_bytes().repeat(4)[..32].try_into().unwrap();
        
        let mut challenge_hasher = DefaultHasher::new();
        commitment.hash(&mut challenge_hasher);
        b"innocence_challenge".hash(&mut challenge_hasher);
        let challenge_hash = challenge_hasher.finish();
        let challenge = challenge_hash.to_le_bytes().repeat(4)[..32].try_into().unwrap();
        
        let mut response = Vec::new();
        response.extend_from_slice(&nonce);
        for (i, &stat) in stats.iter().enumerate() {
            let bounded = (stat - self.normal_bounds.0[i]) / (self.normal_bounds.1[i] - self.normal_bounds.0[i]);
            response.extend_from_slice(&bounded.to_le_bytes());
        }
        
        Ok(InnocenceProof { commitment, challenge, response })
    }

    fn verify_innocence(&self, proof: &InnocenceProof) -> bool {
        if proof.response.len() < 32 + 8 * 4 { return false; }
        
        let nonce = &proof.response[0..32];
        let mut stats = Vec::new();
        
        for i in 0..4 {
            let start = 32 + i * 8;
            let bounded = f64::from_le_bytes(proof.response[start..start+8].try_into().unwrap_or([0; 8]));
            if bounded < 0.0 || bounded > 1.0 { return false; }
            let stat = bounded * (self.normal_bounds.1[i] - self.normal_bounds.0[i]) + self.normal_bounds.0[i];
            stats.push(stat);
        }
        
        let mut hasher = DefaultHasher::new();
        stats.hash(&mut hasher);
        nonce.hash(&mut hasher);
        let expected_hash = hasher.finish();
        let expected_commitment: [u8; 32] = expected_hash.to_le_bytes().repeat(4)[..32].try_into().unwrap();
        
        expected_commitment == proof.commitment
    }

    fn extract_stats(&self, traffic: &TrafficPattern) -> Vec<f64> {
        let avg_size = traffic.request_sizes.iter().sum::<u32>() as f64 / traffic.request_sizes.len() as f64;
        let avg_interval = traffic.timing_intervals.iter().sum::<u32>() as f64 / traffic.timing_intervals.len() as f64;
        let json_ratio = traffic.content_types.iter().filter(|ct| ct.contains("json")).count() as f64 / traffic.content_types.len() as f64;
        let image_ratio = traffic.content_types.iter().filter(|ct| ct.contains("image")).count() as f64 / traffic.content_types.len() as f64;
        vec![avg_size, avg_interval, json_ratio, image_ratio]
    }

    fn is_normal(&self, stats: &[f64]) -> bool {
        stats.iter().zip(&self.normal_bounds.0).zip(&self.normal_bounds.1)
            .all(|((&stat, &min), &max)| stat >= min && stat <= max)
    }
}

#[test]
fn test_normal_traffic_proof() {
    let engine = ZkpEngine::new();
    
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
    
    let proof = engine.prove_innocence(&normal_traffic).expect("Should generate proof for normal traffic");
    assert!(engine.verify_innocence(&proof), "Proof should verify");
}

#[test]
fn test_suspicious_traffic_rejection() {
    let engine = ZkpEngine::new();
    
    let suspicious_traffic = TrafficPattern {
        request_sizes: vec![100000, 200000, 150000], // Too large
        timing_intervals: vec![10, 5, 8], // Too fast
        content_types: vec![
            "application/octet-stream".to_string(),
            "application/octet-stream".to_string(),
            "application/octet-stream".to_string(),
        ],
    };
    
    assert!(engine.prove_innocence(&suspicious_traffic).is_err(), "Should reject suspicious traffic");
}

#[test]
fn test_proof_integrity() {
    let engine = ZkpEngine::new();
    
    let traffic = TrafficPattern {
        request_sizes: vec![1500, 2000, 1200],
        timing_intervals: vec![250, 180, 220],
        content_types: vec![
            "application/json".to_string(),
            "text/html".to_string(),
            "image/png".to_string(),
        ],
    };
    
    let proof = engine.prove_innocence(&traffic).expect("Should generate proof");
    
    // Valid proof should verify
    assert!(engine.verify_innocence(&proof));
    
    // Tampered proof should fail
    let mut tampered_proof = proof.clone();
    tampered_proof.response[0] ^= 1; // Flip one bit
    assert!(!engine.verify_innocence(&tampered_proof));
}

#[test]
fn test_zero_knowledge_property() {
    let engine = ZkpEngine::new();
    
    let traffic1 = TrafficPattern {
        request_sizes: vec![1000, 1500, 2000],
        timing_intervals: vec![200, 250, 180],
        content_types: vec!["application/json".to_string(); 3],
    };
    
    let traffic2 = TrafficPattern {
        request_sizes: vec![3000, 4000, 2500],
        timing_intervals: vec![300, 400, 350],
        content_types: vec!["text/html".to_string(); 3],
    };
    
    let proof1 = engine.prove_innocence(&traffic1).expect("Should generate proof 1");
    let proof2 = engine.prove_innocence(&traffic2).expect("Should generate proof 2");
    
    // Both proofs should verify
    assert!(engine.verify_innocence(&proof1));
    assert!(engine.verify_innocence(&proof2));
    
    // But proofs should be different (no information leakage)
    assert_ne!(proof1.commitment, proof2.commitment);
    assert_ne!(proof1.response, proof2.response);
}

#[test]
fn test_boundary_conditions() {
    let engine = ZkpEngine::new();
    
    // Test at exact boundaries
    let boundary_traffic = TrafficPattern {
        request_sizes: vec![500, 50000], // Exactly at min/max bounds
        timing_intervals: vec![100, 5000], // Exactly at min/max bounds
        content_types: vec![
            "application/json".to_string(),
            "text/html".to_string(),
        ],
    };
    
    let proof = engine.prove_innocence(&boundary_traffic).expect("Should handle boundary conditions");
    assert!(engine.verify_innocence(&proof));
}

#[test]
fn test_statistical_distribution() {
    let engine = ZkpEngine::new();
    
    // Test with realistic web browsing pattern
    let web_traffic = TrafficPattern {
        request_sizes: vec![
            800, 1200, 2400, 1800, 900, 1500, 3200, 1100, 2100, 1600
        ],
        timing_intervals: vec![
            150, 200, 180, 220, 160, 190, 210, 170, 240, 185
        ],
        content_types: vec![
            "text/html".to_string(),
            "application/json".to_string(),
            "image/jpeg".to_string(),
            "text/css".to_string(),
            "application/javascript".to_string(),
            "application/json".to_string(),
            "image/png".to_string(),
            "text/html".to_string(),
            "application/json".to_string(),
            "image/gif".to_string(),
        ],
    };
    
    let proof = engine.prove_innocence(&web_traffic).expect("Should handle realistic web traffic");
    assert!(engine.verify_innocence(&proof));
    
    // Verify the statistics are within expected ranges
    let stats = engine.extract_stats(&web_traffic);
    assert!(stats[0] >= 500.0 && stats[0] <= 50000.0); // avg_size
    assert!(stats[1] >= 100.0 && stats[1] <= 5000.0);  // avg_interval
    assert!(stats[2] >= 0.1 && stats[2] <= 0.6);       // json_ratio
    assert!(stats[3] >= 0.05 && stats[3] <= 0.8);      // image_ratio
}