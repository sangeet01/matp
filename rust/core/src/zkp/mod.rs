use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnocenceProof {
    pub commitment: [u8; 32],
    pub challenge: [u8; 32], 
    pub response: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrafficPattern {
    pub request_sizes: Vec<u32>,
    pub timing_intervals: Vec<u32>,
    pub content_types: Vec<String>,
}

pub struct ZkpEngine {
    normal_bounds: (Vec<f64>, Vec<f64>),
}

impl ZkpEngine {
    pub fn new() -> Self {
        let min_bounds = vec![500.0, 100.0, 0.1, 0.05];
        let max_bounds = vec![50000.0, 5000.0, 0.6, 0.8];
        Self { normal_bounds: (min_bounds, max_bounds) }
    }

    pub fn prove_innocence(&self, traffic: &TrafficPattern) -> Result<InnocenceProof, String> {
        let stats = self.extract_stats(traffic);
        
        if !self.is_normal(&stats) {
            return Err("Traffic appears suspicious".to_string());
        }

        let mut rng = thread_rng();
        let nonce: [u8; 32] = rng.gen();
        
        let mut hasher = Sha256::new();
        hasher.update(&stats.iter().flat_map(|f| f.to_le_bytes()).collect::<Vec<_>>());
        hasher.update(&nonce);
        let commitment = hasher.finalize().into();
        
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(&commitment);
        challenge_hasher.update(b"innocence_challenge");
        let challenge = challenge_hasher.finalize().into();
        
        let mut response = Vec::new();
        response.extend_from_slice(&nonce);
        for (i, &stat) in stats.iter().enumerate() {
            let bounded = (stat - self.normal_bounds.0[i]) / (self.normal_bounds.1[i] - self.normal_bounds.0[i]);
            response.extend_from_slice(&bounded.to_le_bytes());
        }
        
        Ok(InnocenceProof { commitment, challenge, response })
    }

    pub fn verify_innocence(&self, proof: &InnocenceProof) -> bool {
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
        
        let mut hasher = Sha256::new();
        hasher.update(&stats.iter().flat_map(|f| f.to_le_bytes()).collect::<Vec<_>>());
        hasher.update(nonce);
        let expected_commitment: [u8; 32] = hasher.finalize().into();
        
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
