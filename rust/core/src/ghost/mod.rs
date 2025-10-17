//! # The Ghost Module
//!
//! This module implements the "Chameleon Steganography" layer of the
//! Matryoshka Protocol. It is responsible for hiding encrypted MTP packets
//! inside various forms of plausible-looking cover traffic.

pub mod engine;
pub mod strategies;
pub mod cover_traffic;

pub use engine::GhostEngine;
pub use fast_ghost::FastGhost;

// Define a common, top-level error type for all steganography operations.
#[derive(Debug, thiserror::Error)]
pub enum GhostError {
    #[error("Failed to embed payload into cover traffic: {0}")]
    EmbeddingError(String),
    #[error("Failed to extract payload from ghost packet: {0}")]
    ExtractionError(String),

}
