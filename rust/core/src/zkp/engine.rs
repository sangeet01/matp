//! # ZKP Engine - Advanced Zero-Knowledge Proof Utilities
//!
//! Provides high-level ZKP operations for the Matryoshka Protocol.
use crate::zkp::circuit::{InnocenceProofData, SigmaProtocol, TrafficPattern as ZkpTrafficPattern};

/// High-level innocence proof generator
pub struct InnocenceProofZKP {
    sigma: SigmaProtocol,
}

impl InnocenceProofZKP {
    pub fn new() -> Self {
        Self {
            sigma: SigmaProtocol::new(),
        }
    }
    
    /// Generate ZK proof of innocence for cover data
    pub fn generate_proof(&self, cover_data: &ZkpTrafficPattern) -> Result<InnocenceProofData, String> {
        // Generate secret for this proof
        let (secret, public_key) = self.sigma.generate_keypair();
        
        // Bind proof to cover data
        let message = serde_json::to_vec(cover_data).map_err(|e| e.to_string())?;
        
        // Generate ZK proof
        let proof = self.sigma.prove(secret, &message);
        
        Ok(InnocenceProofData {
            public_key,
            proof,
        })
    }
    
    /// Verify ZK proof of innocence
    pub fn verify_proof(&self, proof_data: &InnocenceProofData, cover_data: &ZkpTrafficPattern) -> bool {
        let message = match serde_json::to_vec(cover_data) {
            Ok(m) => m,
            Err(_) => return false,
        };
        
        self.sigma.verify(&proof_data.proof, proof_data.public_key, &message)
    }
}

/// Simplified API functions
pub fn generate_innocence_proof(cover_data: &ZkpTrafficPattern) -> Result<InnocenceProofData, String> {
    let zkp = InnocenceProofZKP::new();
    zkp.generate_proof(cover_data)
}

pub fn verify_innocence_proof(proof_data: &InnocenceProofData, cover_data: &ZkpTrafficPattern) -> bool {
    let zkp = InnocenceProofZKP::new();
    zkp.verify_proof(proof_data, cover_data)
}

/// Generate traffic-based innocence proof
pub fn generate_traffic_proof(traffic: &ZkpTrafficPattern) -> Result<InnocenceProofData, String> {
    // This now correctly uses the new cryptographic ZKP engine.
    generate_innocence_proof(traffic)
}

/// Verify traffic-based innocence proof
pub fn verify_traffic_proof(proof: &InnocenceProofData, traffic: &ZkpTrafficPattern) -> bool {
    // This now correctly uses the new cryptographic ZKP engine for verification.
    verify_innocence_proof(proof, traffic)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_innocence_proof_generation() {
        let cover = ZkpTrafficPattern {
            request_sizes: vec![1024, 2048],
            timing_intervals: vec![100, 200],
            content_types: vec!["application/json".to_string()],
        };
        
        let proof = generate_innocence_proof(&cover).unwrap();
        // Verify with same cover data
        let verified = verify_innocence_proof(&proof, &cover);
        assert!(verified, "Proof verification failed");

        let different_cover = ZkpTrafficPattern { request_sizes: vec![1], timing_intervals: vec![1], content_types: vec![] };
        let not_verified = verify_innocence_proof(&proof, &different_cover);
        assert!(!not_verified, "Proof should not verify with different data");
    }
    
    #[test]
    fn test_traffic_proof() {
        let traffic = ZkpTrafficPattern {
            request_sizes: vec![1024, 2048, 1536, 800],
            timing_intervals: vec![150, 200, 180, 120],
            content_types: vec![
                "application/json".to_string(), 
                "text/html".to_string(),
                "image/jpeg".to_string(),
                "application/json".to_string()
            ],
        };
        
        let proof = generate_traffic_proof(&traffic).unwrap();
        assert!(verify_traffic_proof(&proof, &traffic));
    }
}