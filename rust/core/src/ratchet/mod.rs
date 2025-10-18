//! # The Ratchet Module
//!
//! This module contains the core state machine logic for the Matryoshka
//! double ratchet algorithm and its variants.

pub mod rclassical;
pub mod state;
pub mod adaptive;

// Define a common, top-level error type for all ratchet operations.
#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("State error: {0}")]
    StateError(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

}
