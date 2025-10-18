//! # The Chameleon Steganography Engine
//!
//! This module contains the main `GhostEngine`, which orchestrates the process
//! of hiding and revealing data using a variety of strategies.

use base64::{engine::general_purpose, Engine as _};
use rand::seq::SliceRandom;

use crate::ratchet::state::MtpPacket;
use super::{
    GhostError,
    strategies::{json_api::JsonApiStrategy, exif_image::ExifImageStrategy},
};

/// A trait for any steganographic embedding strategy.
/// Each strategy knows how to hide a payload within a specific type of cover traffic.
pub trait EmbeddingStrategy: Send + Sync {
    /// Hides a base64-encoded payload within a specific cover traffic format.
    fn embed(&self, payload: &str) -> Result<Vec<u8>, GhostError>;

    /// Attempts to extract a base64-encoded payload from a blob of data.
    /// Returns `None` if the data is not in the expected format for this strategy.
    fn extract(&self, data: &[u8]) -> Option<String>;
}

/// The production-grade "Chameleon" steganography engine.
pub struct GhostEngine {
    strategies: Vec<Box<dyn EmbeddingStrategy>>,
}

impl GhostEngine {
    /// Creates a new `GhostEngine` with a default set of strategies.
    pub fn new() -> Self {
        let strategies: Vec<Box<dyn EmbeddingStrategy>> = vec![
            Box::new(JsonApiStrategy::new()),
            Box::new(ExifImageStrategy::new()),
        ];
        Self { strategies }
    }

    /// Takes an MTP packet, serializes it, and hides it using a randomly chosen strategy.
    pub fn embed(&self, mtp_packet: &MtpPacket) -> Result<Vec<u8>, GhostError> {
        let serialized_payload = rmp_serde::to_vec_named(mtp_packet)
            .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        let encoded_payload = general_purpose::STANDARD.encode(&serialized_payload);

        // Choose a random strategy for this message.
        let strategy = self.strategies.choose(&mut rand::thread_rng()).ok_or_else(|| GhostError::EmbeddingError("No embedding strategies available".to_string()))?;

        strategy.embed(&encoded_payload)
    }

    /// Intelligently extracts an MTP packet by trying all available strategies.
    pub fn extract(&self, ghost_packet: &[u8]) -> Result<MtpPacket, GhostError> {
        for strategy in &self.strategies {
            if let Some(encoded_payload) = strategy.extract(ghost_packet) {
                let serialized_payload = general_purpose::STANDARD.decode(encoded_payload)
                    .map_err(|e| GhostError::ExtractionError(e.to_string()))?;
                let mtp_packet: MtpPacket = rmp_serde::from_slice(&serialized_payload)
                    .map_err(|e| GhostError::ExtractionError(e.to_string()))?;
                return Ok(mtp_packet);
            }
        }
        Err(GhostError::ExtractionError("No MTP payload found using any known strategy".to_string()))
    }
}
