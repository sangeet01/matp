//! # Post-Quantum Cryptography Primitives
//!
//! This module provides wrappers around the `oqs` crate to expose a clean,
//! safe interface for Kyber (KEM) and Dilithium (Digital Signatures).

pub mod kem;
pub mod signature;

use oqs::kem::{Kem, Algorithm as KemAlgorithm};
use oqs::sig::{Sig, Algorithm as SigAlgorithm};
use serde::{Serialize, Deserialize};

use super::CryptoError;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KemPublicKey(Vec<u8>);

impl KemPublicKey {
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

#[derive(Clone)]
pub struct KemSecretKey(Vec<u8>);

impl KemSecretKey {
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SigVerificationKey(pub Vec<u8>);

impl SigVerificationKey {
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

#[derive(Clone)]
pub struct SigSigningKey(Vec<u8>);

impl SigSigningKey {
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext(Vec<u8>);

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Signature(Vec<u8>);

pub struct Quantum;

impl Quantum {
    pub fn generate_kem_keys() -> Result<(KemPublicKey, KemSecretKey), CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let (pk, sk) = kem.keypair().map_err(|_| CryptoError::KdfError)?;
        Ok((KemPublicKey(pk.into_vec()), KemSecretKey(sk.into_vec())))
    }

    pub fn generate_sign_keys() -> Result<(SigVerificationKey, SigSigningKey), CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let (pk, sk) = sig.keypair().map_err(|_| CryptoError::KdfError)?;
        Ok((SigVerificationKey(pk.into_vec()), SigSigningKey(sk.into_vec())))
    }

    pub fn kem_encapsulate(pk: &KemPublicKey) -> Result<(Vec<u8>, KemCiphertext), CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let public_key = kem.public_key_from_bytes(&pk.0).ok_or(CryptoError::KdfError)?;
        let (shared_secret, ciphertext) = kem.encapsulate(&public_key).map_err(|_| CryptoError::KdfError)?;
        Ok((shared_secret.into_vec(), KemCiphertext(ciphertext.into_vec())))
    }

    pub fn kem_decapsulate(sk: &KemSecretKey, ciphertext: &KemCiphertext) -> Result<Vec<u8>, CryptoError> {
        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(|_| CryptoError::KdfError)?;
        let secret_key = kem.secret_key_from_bytes(&sk.0).ok_or(CryptoError::KdfError)?;
        let ct = kem.ciphertext_from_bytes(&ciphertext.0).ok_or(CryptoError::DecryptionError)?;
        let shared_secret = kem.decapsulate(&secret_key, &ct).map_err(|_| CryptoError::DecryptionError)?;
        Ok(shared_secret.into_vec())
    }

    pub fn sign(sk: &SigSigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let secret_key = sig.secret_key_from_bytes(&sk.0).ok_or(CryptoError::KdfError)?;
        let signature = sig.sign(message, &secret_key).map_err(|_| CryptoError::EncryptionError)?;
        Ok(Signature(signature.into_vec()))
    }

    pub fn verify(pk: &SigVerificationKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let sig = Sig::new(SigAlgorithm::Dilithium2).map_err(|_| CryptoError::KdfError)?;
        let public_key = sig.public_key_from_bytes(&pk.0).ok_or(CryptoError::KdfError)?;
        let sig_obj = sig.signature_from_bytes(&signature.0).ok_or(CryptoError::DecryptionError)?;
        sig.verify(message, &sig_obj, &public_key).map_err(|_| CryptoError::DecryptionError)
    }
}
