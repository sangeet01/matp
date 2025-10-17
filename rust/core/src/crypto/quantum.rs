//! # Post-Quantum Cryptography Primitives
//!
//! This module provides wrappers around the `oqs` crate to expose a clean,
//! safe interface for Kyber (KEM) and Dilithium (Digital Signatures).

use oqs::kem::{Kem, Algorithm as KemAlgorithm};
use oqs::sig::{Sig, Algorithm as SigAlgorithm};
use serde::{Serialize, Deserialize};

use super::CryptoError;

// --- Type-safe wrappers for Post-Quantum keys ---

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KemPublicKey(Vec<u8>);

#[derive(Clone)]
pub struct KemSecretKey(Vec<u8>);

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SigVerificationKey(pub Vec<u8>);

#[derive(Clone)]
pub struct SigSigningKey(Vec<u8>);

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext(Vec<u8>);

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Signature(Vec<u8>);

/// A namespace struct for post-quantum operations.
pub struct Quantum;

impl Quantum {
    /// Generates a Kyber512 keypair for Key Encapsulation.
    pub fn generate_kem_keys() -> Result<(KemPublicKey, KemSecretKey), CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let (pk, sk) = kem.keypair().map_err(|_| CryptoError::KdfError)?;
        Ok((KemPublicKey(pk.into_vec()), KemSecretKey(sk.into_vec())))
    }

    /// Generates a Dilithium2 keypair for signing.
    pub fn generate_sign_keys() -> Result<(SigVerificationKey, SigSigningKey), CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let (pk, sk) = sig.keypair().map_err(|_| CryptoError::KdfError)?;
        Ok((SigVerificationKey(pk.into_vec()), SigSigningKey(sk.into_vec())))
    }

    /// Encapsulates a shared secret for a given Kyber public key.
    pub fn kem_encapsulate(pk: &KemPublicKey) -> Result<(Vec<u8>, KemCiphertext), CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let public_key = kem.public_key_from_bytes(&pk.0).map_err(|_| CryptoError::KdfError)?;
        let (shared_secret, ciphertext) = kem.encapsulate(&public_key).map_err(|_| CryptoError::KdfError)?;
        Ok((shared_secret.into_vec(), KemCiphertext(ciphertext.into_vec())))
    }

    /// Decapsulates a shared secret from a Kyber ciphertext.
    pub fn kem_decapsulate(sk: &KemSecretKey, ciphertext: &KemCiphertext) -> Result<Vec<u8>, CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let secret_key = kem.secret_key_from_bytes(&sk.0).map_err(|_| CryptoError::KdfError)?;
        let shared_secret = kem.decapsulate(&secret_key, &ciphertext.0).map_err(|_| CryptoError::DecryptionError)?;
        Ok(shared_secret.into_vec())
    }

    /// Signs a message using a Dilithium signing key.
    pub fn sign(sk: &SigSigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let secret_key = sig.secret_key_from_bytes(&sk.0).map_err(|_| CryptoError::KdfError)?;
        let signature = sig.sign(message, &secret_key).map_err(|_| CryptoError::EncryptionError)?;
        Ok(Signature(signature.into_vec()))
    }

    /// Verifies a signature using a Dilithium verification key.
    pub fn verify(pk: &SigVerificationKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let public_key = sig.public_key_from_bytes(&pk.0).map_err(|_| CryptoError::KdfError)?;
        sig.verify(message, &signature.0, &public_key).map_err(|_| CryptoError::DecryptionError)
    }
}
