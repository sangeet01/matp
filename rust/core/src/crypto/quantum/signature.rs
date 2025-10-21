//! Signature operations

use super::{Quantum, SigVerificationKey, SigSigningKey, Signature};
use crate::crypto::CryptoError;

pub fn generate_signature_keypair() -> (SigVerificationKey, SigSigningKey) {
    Quantum::generate_sign_keys().expect("Signature keygen failed")
}

pub fn sign_message(sk: &SigSigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
    Quantum::sign(sk, message)
}

pub fn verify_signature(pk: &SigVerificationKey, message: &[u8], sig: &Signature) -> Result<bool, CryptoError> {
    Quantum::verify(pk, message, sig).map(|_| true).or(Ok(false))
}
