//! # The Session Manager
//!
//! This module provides the top-level `MatryoshkaSession` struct, which manages
//! the entire state for a secure communication session. Its primary responsibility
//! is to maintain and route traffic between the real and decoy ratchets,
//! providing the plausible deniability layer.

use x25519_dalek::PublicKey as X25519PublicKey;

use super::{
    ratchet::{
        adaptive::AdaptiveRatchet,
        state::MtpPacket,
        RatchetError,
    },
};

/// Manages a full session between two users, including real and decoy ratchets.
/// This is the primary entry point for applications using the mtp-core library.
pub struct MatryoshkaSession {
    real_ratchet: AdaptiveRatchet,
    decoy_ratchet: AdaptiveRatchet,
}

impl MatryoshkaSession {
    /// Creates a new session manager with both a real and a decoy ratchet.
    pub fn new(
        initial_shared_secret: &[u8],
        decoy_shared_secret: &[u8],
        remote_dh_public_key: X25519PublicKey,
        is_initiator: bool,
    ) -> Result<Self, RatchetError> {
        let real_ratchet = AdaptiveRatchet::new(initial_shared_secret, remote_dh_public_key, is_initiator, false)?;
        let decoy_ratchet = AdaptiveRatchet::new(decoy_shared_secret, remote_dh_public_key, is_initiator, true)?;

        Ok(Self {
            real_ratchet,
            decoy_ratchet,
        })
    }

    /// Encrypts a plaintext message for either the real or decoy conversation.
    pub fn encrypt(&mut self, plaintext: &[u8], is_decoy: bool) -> Result<MtpPacket, RatchetError> {
        if is_decoy {
            self.decoy_ratchet.ratchet_encrypt(plaintext)
        } else {
            self.real_ratchet.ratchet_encrypt(plaintext)
        }
    }

    /// Decrypts a received MTP packet.
    ///
    /// It inspects the packet's header to determine whether it belongs to the
    /// real or decoy conversation and routes it to the appropriate ratchet.
    pub fn decrypt(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        if packet.header.decoy_flag {
            self.decoy_ratchet.ratchet_decrypt(packet)
        } else {
            self.real_ratchet.ratchet_decrypt(packet)
        }
    }
}