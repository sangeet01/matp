//! # Zero-Knowledge Proof Module
//!
//! Provides ZKP primitives for plausible deniability and innocence proofs.

pub mod circuit;
pub mod engine;

use serde::{Serialize, Deserialize};

pub use circuit::{InnocenceProofData, SigmaProtocol, TrafficPattern, ZkProof};
pub use engine::{generate_innocence_proof, verify_innocence_proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnocenceProof(pub String);