//! # The Crypto Module
//!
//! This module contains all core cryptographic primitives and operations
//! for the Matryoshka Protocol, separated into logical sub-modules.

// Declare the sub-modules as per our architecture.
pub mod classical;
pub mod quantum;
pub mod hybrid;
pub mod fractal;

// Define a common, top-level error type for all cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptionError,
    #[error("AEAD decryption failed: tag mismatch or invalid ciphertext")]
    DecryptionError,
    #[error("Key derivation failed")]
    KdfError,
}