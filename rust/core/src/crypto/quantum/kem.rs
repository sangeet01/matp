//! KEM operations

use super::{Quantum, KemPublicKey, KemSecretKey, KemCiphertext};
use crate::crypto::CryptoError;

pub fn generate_kem_keypair() -> (KemPublicKey, KemSecretKey) {
    Quantum::generate_kem_keys().expect("KEM keygen failed")
}

pub fn kem_encapsulate(pk: &KemPublicKey) -> Result<(KemCiphertext, Vec<u8>), CryptoError> {
    let (ss, ct) = Quantum::kem_encapsulate(pk)?;
    Ok((ct, ss))
}

pub fn kem_decapsulate(sk: &KemSecretKey, ct: &KemCiphertext) -> Result<Vec<u8>, CryptoError> {
    Quantum::kem_decapsulate(sk, ct)
}
