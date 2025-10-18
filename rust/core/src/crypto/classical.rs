//! # Classical Cryptography Primitives
//!
//! This module provides the core classical cryptographic functions based on
//! industry-standard, audited libraries, including HKDF for key derivation
//! and AES-256-GCM for authenticated encryption.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::CryptoError;

// --- Type-safe wrappers for keys to prevent misuse ---
#[derive(Clone, Copy)]
pub struct RootKey(pub [u8; 32]);
#[derive(Clone, Copy)]
pub struct ChainKey(pub [u8; 32]);
#[derive(Clone, Copy)]
pub struct MessageKey(pub [u8; 32]);

/// Derives a new pair of chain keys from a root key.
/// This corresponds to the `_kdf_root` function in our design.
pub fn kdf_root(root_key: &RootKey, info: &[u8]) -> Result<(ChainKey, ChainKey), CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, &root_key.0);
    let mut okm = [0u8; 64]; // Output Keying Material for two 32-byte keys

    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfError)?;

    let (key1, key2) = okm.split_at(32);
    Ok((ChainKey(key1.try_into().unwrap()), ChainKey(key2.try_into().unwrap())))
}

/// Derives a message key and the next chain key from a current chain key.
/// This corresponds to the `_kdf_chain` function in our design.
pub fn kdf_chain(chain_key: &ChainKey, info: &[u8]) -> Result<(MessageKey, ChainKey), CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, &chain_key.0);
    let mut okm = [0u8; 64];

    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfError)?;

    let (msg_key, next_chain_key) = okm.split_at(32);
    Ok((
        MessageKey(msg_key.try_into().unwrap()),
        ChainKey(next_chain_key.try_into().unwrap()),
    ))
}

/// Encrypts a plaintext using AES-256-GCM.
pub fn encrypt(
    key: &MessageKey,
    plaintext: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(&key.0).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit nonce
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionError)?;

    // Prepend the nonce to the ciphertext for storage/transmission
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}

/// Decrypts a ciphertext using AES-256-GCM.
pub fn decrypt(
    key: &MessageKey,
    ciphertext_with_nonce: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(&key.0).unwrap();
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionError)
}