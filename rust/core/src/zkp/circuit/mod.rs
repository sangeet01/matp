//! # Sigma Protocol Circuit for Zero-Knowledge Proofs
//!
//! Implements Schnorr-like Sigma protocol for proving knowledge of discrete log
//! without revealing the secret. Used for plausible deniability.

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use std::ops::{Add, Mul};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct ZkProof {
    #[serde(with = "affine_point_serde")]
    pub commitment: AffinePoint,
    #[serde(with = "scalar_serde")]
    pub response: Scalar,
}

/// Represents the data structure for cover traffic patterns.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrafficPattern {
    pub request_sizes: Vec<u32>,
    pub timing_intervals: Vec<u32>,
    pub content_types: Vec<String>,
}

/// The complete proof data to be serialized, including the public key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InnocenceProofData {
    #[serde(with = "affine_point_serde")]
    pub public_key: AffinePoint,
    #[serde(with = "ZkProof")]
    pub proof: ZkProof,
}

/// Serde module for AffinePoint
mod affine_point_serde {
    use super::*;
    use serde::{Serializer, Deserializer, de::{self, Visitor}};

    struct AffinePointVisitor;

    impl<'de> Visitor<'de> for AffinePointVisitor {
        type Value = AffinePoint;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("bytes")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let encoded_point = EncodedPoint::from_bytes(v)
                .map_err(|e| E::custom(format!("Invalid commitment point: {}", e)))?;
            AffinePoint::from_encoded_point(&encoded_point).into_option()
                .ok_or_else(|| E::custom("Failed to decode commitment point"))
        }
    }

    pub fn serialize<S>(point: &AffinePoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(point.to_encoded_point(true).as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AffinePoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AffinePointVisitor)
    }
}

/// Serde module for Scalar
mod scalar_serde {
    use super::*;
    use serde::{Serializer, Deserializer, de::Error};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer, {
        serializer.serialize_bytes(&scalar.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where D: Deserializer<'de>, {
        let bytes: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| Error::custom("Invalid scalar length"))?;
        Option::<Scalar>::from(Scalar::from_repr(array.into()))
            .ok_or_else(|| Error::custom("Failed to decode response scalar"))
    }
}

/// Sigma Protocol implementation for ZK proofs
pub struct SigmaProtocol;

impl SigmaProtocol {
    pub fn new() -> Self {
        Self
    }
    
    /// Generate keypair for ZKP
    pub fn generate_keypair(&self) -> (Scalar, AffinePoint) {
        let secret = Scalar::random(&mut OsRng);
        let public_key = (ProjectivePoint::GENERATOR * secret).to_affine();
        (secret, public_key)
    }
    
    /// Generate zero-knowledge proof
    pub fn prove(&self, secret: Scalar, message: &[u8]) -> ZkProof {
        let public_key = (ProjectivePoint::GENERATOR * secret).to_affine();
        
        // Step 1: Commitment (random r)
        let r = Scalar::random(&mut OsRng);
        let commitment = (ProjectivePoint::GENERATOR * r).to_affine();
        
        // Step 2: Challenge (Fiat-Shamir)
        let challenge = self.compute_challenge(commitment, public_key, message);
        
        // Step 3: Response: s = (r + c*secret) mod N
        let response = r.add(&challenge.mul(&secret));

        ZkProof { commitment, response }
    }
    
    /// Verify zero-knowledge proof
    pub fn verify(&self, proof: &ZkProof, public_key: AffinePoint, message: &[u8]) -> bool {
        // Recompute challenge
        let c = self.compute_challenge(proof.commitment, public_key, message);
        
        // Verify: s*G = R + c*P
        let sg = (ProjectivePoint::GENERATOR * proof.response).to_affine();
        let cp = (ProjectivePoint::from(public_key) * c).to_affine();
        let r_plus_cp = (ProjectivePoint::from(proof.commitment) + cp).to_affine();
        
        sg == r_plus_cp
    }
    
    fn compute_challenge(&self, r: AffinePoint, p: AffinePoint, message: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(r.to_encoded_point(true).as_bytes());
        hasher.update(p.to_encoded_point(true).as_bytes());
        hasher.update(message);
        
        let hash = hasher.finalize();
        Scalar::from_repr(hash).unwrap()
    }
}

/// High-level engine for generating and verifying "Innocence Proofs".
/// This is the Rust equivalent of the `InnocenceProofZKP` class in Python.
pub struct InnocenceProofZkp {
    sigma: SigmaProtocol,
}

impl InnocenceProofZkp {
    pub fn new() -> Self {
        Self { sigma: SigmaProtocol::new() }
    }

    /// Generate a ZK proof of innocence for the given cover traffic.
    pub fn generate_proof(&self, cover_data: &TrafficPattern) -> Result<InnocenceProofData, serde_json::Error> {
        // Generate a secret for this specific proof
        let (secret, public_key) = self.sigma.generate_keypair();

        // Bind the proof to the cover data by serializing it to a canonical JSON string.
        let message = serde_json::to_vec(cover_data)?;

        // Generate the core ZK proof
        Ok(InnocenceProofData { public_key, proof: self.sigma.prove(secret, &message) })
    }

    /// Verify a ZK proof of innocence against the cover traffic.
    pub fn verify_proof(&self, proof_data: &InnocenceProofData, cover_data: &TrafficPattern) -> Result<bool, serde_json::Error> {
        // Re-create the message from the cover data to verify against.
        let message = serde_json::to_vec(cover_data)?;

        // The challenge is not serialized, so we recompute it for verification.
        Ok(self.sigma.verify(&proof_data.proof, proof_data.public_key, &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_innocence_proof_e2e() {
        let engine = InnocenceProofZkp::new();
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

        // 1. Prover generates a proof for the innocent traffic pattern.
        let proof_data = engine.generate_proof(&normal_traffic).unwrap();

        // 2. Verifier checks the proof against the same traffic pattern.
        let is_valid = engine.verify_proof(&proof_data, &normal_traffic).unwrap();
        assert!(is_valid);

        // 3. Verifier checks the proof against different traffic, which should fail.
        let suspicious_traffic = TrafficPattern {
            request_sizes: vec![9999],
            timing_intervals: vec![1],
            content_types: vec!["application/octet-stream".to_string()],
        };
        let is_invalid = engine.verify_proof(&proof_data, &suspicious_traffic).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_zkp_sigma() {
        let sigma = SigmaProtocol::new();
        let (secret, public_key) = sigma.generate_keypair();
        let message = b"test message";
        let proof = sigma.prove(secret, message);
        assert!(sigma.verify(&proof, public_key, message));
    }
}
