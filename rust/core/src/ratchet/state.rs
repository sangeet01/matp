//! # Ratchet State
//!
//! This module defines the data structures that represent the state of a
//! Matryoshka ratchet session.

use x25519_dalek::PublicKey as X25519PublicKey;
use serde::{Serialize, Deserialize};

use crate::crypto::fractal::PQFractalBundle;
use crate::zkp;
use crate::ratchet::rclassical::ZkpRecoveryProof;

// Type alias for clarity
pub type ZkpOfInnocence = zkp::InnocenceProof;

/// The header attached to every encrypted message. It contains the necessary
/// public information for the recipient to decrypt the message.
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageHeader {
    /// The recipient's public key that this message is intended for.
    pub dh_ratchet_pub_key: X25519PublicKey,
    /// The message number in the current sending chain.
    pub chain_msg_num: u32,
    /// An optional new ephemeral public key for the next DH ratchet step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dh_new_pub_key: Option<X25519PublicKey>,
    /// A flag indicating if this is a message for the decoy conversation.
    pub decoy_flag: bool,
    /// An optional Zero-Knowledge Proof of Innocence for decoy messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zkp_innocence: Option<ZkpOfInnocence>,
}

/// The full, encrypted message packet.
#[derive(Serialize, Deserialize, Debug)]
pub struct MtpPacket {
    pub header: MessageHeader,
    /// The AEAD-encrypted ciphertext (nonce is prepended).
    pub ciphertext: Vec<u8>,
    /// The PQ-Optimized Fractal Bundle for future recovery.
    pub fractal_bundle: PQFractalBundle,
    /// Optional ZKP proof for session recovery (MITM protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zkp_recovery_proof: Option<ZkpRecoveryProof>,
}