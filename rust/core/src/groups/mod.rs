//! # Group Messaging Module
//!
//! Provides multi-party encrypted communication using Fractal Group Ratchet.

pub mod fractal_ratchet;
pub mod manager;

pub use fractal_ratchet::FractalGroupRatchet;
pub use manager::{MatryoshkaGroup, MatryoshkaGroupManager};

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Invalid group state: {0}")]
    InvalidState(String),
}
