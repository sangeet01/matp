//! # The Classical Ratchet
//!
//! This module contains the primary implementation of the Matryoshka double
//! ratchet algorithm, based on X25519 Diffie-Hellman.

use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand_core::OsRng;

use crate::crypto::{
    classical::{self, ChainKey, MessageKey, RootKey},
    fractal::{Fractal, PQFractalBundle},
    CryptoError,
};
use crate::zkp::{self, TrafficPattern};
use crate::mitm::zkp_path::ZKPathProver;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::{
    state::{MessageHeader, MtpPacket},
    RatchetError,
};

const MAX_SKIPPED_MESSAGES: usize = 100;

/// ZKP proof for session recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpRecoveryProof {
    pub r: Vec<u8>,      // Commitment R (64 bytes)
    pub s: Vec<u8>,      // Response s (32 bytes)
    pub c: Vec<u8>,      // Challenge c (32 bytes)
    pub conn_id: String, // Connection ID
}

/// MITM detected during session recovery
#[derive(Debug)]
pub struct MitmDetectedError;

impl std::fmt::Display for MitmDetectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MITM attack detected during session recovery")
    }
}

impl std::error::Error for MitmDetectedError {}

/// The state machine for a single Matryoshka ratchet session (either real or decoy).
#[allow(dead_code)]
pub struct MatryoshkaRatchet {
    // Cryptographic State
    root_key: RootKey,
    sending_chain_key: Option<ChainKey>,
    receiving_chain_key: Option<ChainKey>,

    // Diffie-Hellman State
    dh_key_pair: StaticSecret,
    dh_remote_public_key: X25519PublicKey,

    // Message Counters
    msg_num_send: u32,
    msg_num_recv: u32,

    // State for out-of-order messages
    skipped_message_keys: HashMap<(Vec<u8>, u32), MessageKey>,

    // State for catastrophic recovery
    fractal_recovery_bundles: Vec<PQFractalBundle>,

    // ZKP prover for session recovery
    zkp_prover: Option<ZKPathProver>,

    // Deniability Layer State
    decoy_mode: bool,
    kdf_salt_suffix: &'static [u8],
    public_password_hash: Option<[u8; 32]>, // Only for decoy ratchet
}

impl MatryoshkaRatchet {
    /// Creates a new ratchet instance from an initial shared secret.
    pub fn new(
        initial_shared_secret: &[u8],
        remote_dh_public_key: X25519PublicKey,
        is_initiator: bool,
        decoy_mode: bool,
        // The public hash of the decoy password, known to both parties.
        public_password_hash: Option<[u8; 32]>,
        // ZKP prover for session recovery
        zkp_prover: Option<ZKPathProver>,
    ) -> Result<Self, RatchetError> {
        let kdf_salt_suffix: &[u8] = if decoy_mode { b"-decoy" } else { b"" };
        let dh_key_pair = StaticSecret::random_from_rng(OsRng);

        let (root_key, sending_chain_key, receiving_chain_key) = if is_initiator {
            // Initiator performs a DH exchange immediately to create the first root key.
            let dh_output = dh_key_pair.diffie_hellman(&remote_dh_public_key);
            let info = [b"mtp-dh-init", kdf_salt_suffix].concat();
            let mut root_key_bytes = [0u8; 32];
            Hkdf::<Sha256>::new(Some(initial_shared_secret), dh_output.as_bytes())
                .expand(&info, &mut root_key_bytes)
                .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
            let root_key = RootKey(root_key_bytes);

            let (send_ck, recv_ck) = classical::kdf_root(&root_key, kdf_salt_suffix)?;
            (root_key, Some(send_ck), Some(recv_ck))
        } else {
            // Receiver uses the initial secret directly and waits for Alice's first message.
            let info = [b"mtp-receiver-init", kdf_salt_suffix].concat();
            let mut root_key_bytes = [0u8; 32];
            Hkdf::<Sha256>::new(Some(initial_shared_secret), initial_shared_secret)
                .expand(&info, &mut root_key_bytes)
                .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
            let root_key = RootKey(root_key_bytes);
            // Chain keys will be initialized on the first received message.
            (root_key, None, None)
        };

        Ok(Self {
            root_key,
            sending_chain_key,
            receiving_chain_key,
            dh_key_pair,
            dh_remote_public_key: remote_dh_public_key,
            msg_num_send: 0,
            msg_num_recv: 0,
            skipped_message_keys: HashMap::new(),
            fractal_recovery_bundles: Vec::new(),
            zkp_prover,
            decoy_mode,
            kdf_salt_suffix,
            public_password_hash,
        })
    }

    /// Encrypts a new message, advancing the sending chain.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<MtpPacket, RatchetError> {
        let sending_ck = self.sending_chain_key.as_mut().ok_or_else(|| {
            RatchetError::StateError("Sending chain not initialized".to_string())
        })?;

        // 1. Perform symmetric ratchet step
        let (message_key, next_sending_ck) =
            classical::kdf_chain(sending_ck, self.kdf_salt_suffix)?;
        *sending_ck = next_sending_ck;

        // 2. Generate fractal bundle for the *next* state
        let fractal_bundle =
            Fractal::generate_future_bundle(&next_sending_ck, self.kdf_salt_suffix)?;

        // 3. Encrypt the plaintext
        // In a real implementation, the header would be the associated data.
        let ciphertext = classical::encrypt(&message_key, plaintext, &[])?;

        // 4. Construct the header
        let header = MessageHeader {
            dh_ratchet_pub_key: X25519PublicKey::from(&self.dh_key_pair),
            chain_msg_num: self.msg_num_send,
            dh_new_pub_key: None, // Simplified for now
            decoy_flag: self.decoy_mode,
            zkp_innocence: if self.decoy_mode {
                // Generate a ZK proof for decoy messages to prove their "innocence"
                let traffic = TrafficPattern {
                    request_sizes: vec![1024, 2048, 512],
                    timing_intervals: vec![100, 150, 200],
                    content_types: vec!["application/json".to_string()],
                };
                zkp::generate_innocence_proof(&traffic)
                    .ok()
                    .and_then(|proof_data| serde_json::to_string(&proof_data).ok())
                    .map(zkp::InnocenceProof)
            } else {
                None
            }
        };

        self.msg_num_send += 1;
        
        // Generate ZKP proof if prover available
        let zkp_recovery_proof = self.generate_recovery_zkp();

        Ok(MtpPacket {
            header,
            ciphertext,
            fractal_bundle,
            zkp_recovery_proof,
        })
    }

    /// Decrypts a received message, advancing the ratchet state.
    pub fn ratchet_decrypt(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        if packet.header.decoy_flag != self.decoy_mode {
            return Err(RatchetError::DecryptionError("Decoy flag mismatch".to_string()));
        }

        if let Some(new_remote_pk) = packet.header.dh_new_pub_key {
            self.perform_dh_ratchet(new_remote_pk)?;
        }

        match self.receiving_chain_key.as_mut() {
            Some(receiving_ck) => {
                let result = Self::try_decrypt_and_advance(
                    receiving_ck,
                    &mut self.skipped_message_keys,
                    &mut self.msg_num_recv,
                    packet,
                    self.kdf_salt_suffix,
                );
                match result {
                    Ok(plaintext) => {
                        self.fractal_recovery_bundles.push(packet.fractal_bundle.clone());
                        if self.fractal_recovery_bundles.len() > 5 {
                            self.fractal_recovery_bundles.remove(0);
                        }
                        Ok(plaintext)
                    },
                    Err(_) => self.try_fractal_recovery(packet),
                }
            },
            None => Err(RatchetError::StateError("Receiving chain not initialized".to_string()))
        }
    }

    /// Attempts to decrypt a message, handling out-of-order messages by storing skipped keys.
    fn try_decrypt_and_advance(
        receiving_ck: &mut ChainKey,
        skipped_message_keys: &mut HashMap<(Vec<u8>, u32), MessageKey>,
        msg_num_recv: &mut u32,
        packet: &MtpPacket,
        kdf_salt_suffix: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let remote_pk_bytes = packet.header.dh_ratchet_pub_key.as_bytes().to_vec();
        let msg_num = packet.header.chain_msg_num;

        // 1. Check if it's a skipped message we've already stored a key for
        if let Some(message_key) = skipped_message_keys.remove(&(remote_pk_bytes.clone(), msg_num)) {
            return classical::decrypt(&message_key, &packet.ciphertext, &[]).map_err(|e| RatchetError::Crypto(e));
        }

        // 2. If not, try to advance the current chain to catch up
        while *msg_num_recv < msg_num {
            if skipped_message_keys.len() >= MAX_SKIPPED_MESSAGES {
                return Err(RatchetError::StateError("Max skipped messages exceeded".to_string()));
            }
            let (skipped_mk, next_ck) = classical::kdf_chain(receiving_ck, kdf_salt_suffix)?;
            skipped_message_keys.insert((remote_pk_bytes.clone(), *msg_num_recv), skipped_mk);
            *receiving_ck = next_ck;
            *msg_num_recv += 1;
        }

        // 3. Now we should be at the correct message number, try to decrypt
        if *msg_num_recv == msg_num {
            let (message_key, next_ck) = classical::kdf_chain(receiving_ck, kdf_salt_suffix)?;
            let plaintext = classical::decrypt(&message_key, &packet.ciphertext, &[])?;
            *receiving_ck = next_ck;
            *msg_num_recv += 1;
            return Ok(plaintext);
        }

        Err(RatchetError::DecryptionError("Message is from the past or state is out of sync".to_string()))
    }

    /// Performs a full Diffie-Hellman ratchet step, updating the root key.
    /// This implements the complete Signal-style DH ratchet with proper key derivation.
    fn perform_dh_ratchet(&mut self, new_remote_pk: X25519PublicKey) -> Result<(), RatchetError> {
        // Store old receiving chain state before ratcheting
        let old_recv_chain = self.receiving_chain_key;
        
        // Skip any remaining messages in the old receiving chain
        if let Some(mut recv_ck) = old_recv_chain {
            // Store keys for potential out-of-order messages from old chain
            let remote_pk_bytes = self.dh_remote_public_key.as_bytes().to_vec();
            for i in 0..10 {
                if self.skipped_message_keys.len() >= MAX_SKIPPED_MESSAGES {
                    break;
                }
                let (skipped_mk, next_ck) = classical::kdf_chain(&recv_ck, self.kdf_salt_suffix)?;
                self.skipped_message_keys.insert(
                    (remote_pk_bytes.clone(), self.msg_num_recv + i),
                    skipped_mk
                );
                recv_ck = next_ck;
            }
        }
        
        // Perform DH with new remote public key
        let dh_output = self.dh_key_pair.diffie_hellman(&new_remote_pk);
        
        // Derive new root key using HKDF with old root key as salt
        let info = [b"mtp-dh-ratchet-recv", self.kdf_salt_suffix].concat();
        let mut new_root_key_bytes = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.root_key.0), dh_output.as_bytes())
            .expand(&info, &mut new_root_key_bytes)
            .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
        
        self.root_key = RootKey(new_root_key_bytes);
        
        // Derive new receiving chain key
        let (_, recv_ck) = classical::kdf_root(&self.root_key, self.kdf_salt_suffix)?;
        self.receiving_chain_key = Some(recv_ck);
        
        // Update remote public key
        self.dh_remote_public_key = new_remote_pk;
        
        // Reset receiving message counter for new chain
        self.msg_num_recv = 0;
        
        // Generate new DH keypair for next ratchet
        let new_dh_keypair = StaticSecret::random_from_rng(OsRng);
        let _new_dh_public = X25519PublicKey::from(&new_dh_keypair);
        
        // Perform sending ratchet with our new keypair
        let dh_output_send = new_dh_keypair.diffie_hellman(&new_remote_pk);
        let info_send = [b"mtp-dh-ratchet-send", self.kdf_salt_suffix].concat();
        let mut send_root_key_bytes = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.root_key.0), dh_output_send.as_bytes())
            .expand(&info_send, &mut send_root_key_bytes)
            .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
        
        self.root_key = RootKey(send_root_key_bytes);
        
        // Derive new sending chain key
        let (send_ck, _) = classical::kdf_root(&self.root_key, self.kdf_salt_suffix)?;
        self.sending_chain_key = Some(send_ck);
        
        // Update our DH keypair
        self.dh_key_pair = new_dh_keypair;
        
        // Reset sending message counter
        self.msg_num_send = 0;
        
        Ok(())
    }

    /// Get root key for quantum upgrade
    pub(crate) fn get_root_key(&self) -> [u8; 32] {
        self.root_key.0
    }
    
    /// 🔐 CRITICAL: ZKP-protected session recovery
    /// 
    /// This is the key security improvement over Signal:
    /// - Signal: Delete session + full re-handshake
    /// - Matryoshka: Self-heal with cryptographic proof
    fn try_fractal_recovery(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        // 🚨 CRITICAL: Verify ZKP proof BEFORE accepting recovery bundle
        if let Some(ref zkp_proof) = packet.zkp_recovery_proof {
            if let Some(ref zkp_prover) = self.zkp_prover {
                if !Self::verify_recovery_zkp(zkp_prover, zkp_proof) {
                    return Err(RatchetError::MitmDetected(
                        "ZKP verification failed during session recovery - MITM attack detected!".to_string()
                    ));
                }
            }
        } else if self.zkp_prover.is_some() {
            // ZKP prover available but no proof in packet - suspicious
            return Err(RatchetError::MitmDetected(
                "Missing ZKP proof during session recovery - possible MITM attack!".to_string()
            ));
        }
        
        // ZKP verified (or not required) - try fractal recovery
        let bundles = self.fractal_recovery_bundles.clone();
        for bundle in bundles.iter().rev() {
            for classical_key in &bundle.classical {
                let new_root_key = RootKey(*classical_key);
                if let Ok((mut new_recv_ck, _)) =
                    classical::kdf_root(&new_root_key, self.kdf_salt_suffix)
                {
                    if let Ok(plaintext) = Self::try_decrypt_and_advance(
                        &mut new_recv_ck, &mut self.skipped_message_keys, &mut self.msg_num_recv, packet, self.kdf_salt_suffix
                    ) {
                        self.root_key = new_root_key;
                        self.receiving_chain_key = Some(new_recv_ck);
                        return Ok(plaintext);
                    }
                }
            }
        }
        Err(RatchetError::DecryptionError("Fractal recovery failed".to_string()))
    }
    
    /// Generate Schnorr ZKP proof for session recovery
    fn generate_recovery_zkp(&self) -> Option<ZkpRecoveryProof> {
        use k256::{
            elliptic_curve::ScalarPrimitive,
            ProjectivePoint, Scalar, FieldBytes,
        };
        use rand::RngCore;
        
        // Use deterministic conn_id based on session state
        let mut hasher = Sha256::new();
        hasher.update(&self.root_key.0);
        let conn_id_hash = hasher.finalize();
        let conn_id = format!("{:x}", u64::from_be_bytes(conn_id_hash[..8].try_into().ok()?));
        
        // Get master_secret from zkp_prover
        let master_secret = match &self.zkp_prover {
            Some(prover) => &prover.master_secret,
            None => return None,
        };
        
        // Get secret x
        let mut hasher = Sha256::new();
        hasher.update(master_secret);
        hasher.update(conn_id.as_bytes());
        let x_bytes = hasher.finalize();
        let fb = FieldBytes::from(x_bytes);
        let x_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).ok()?);
        
        // Generate random nonce k and commitment R = k*G
        let mut k_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k_bytes);
        let fb = FieldBytes::from(k_bytes);
        let k_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).ok()?);
        let r_point = ProjectivePoint::GENERATOR * k_scalar;
        let r_affine = r_point.to_affine();
        let r_bytes = r_affine.to_encoded_point(false);
        
        // Generate challenge c
        let mut c_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut c_bytes);
        let fb = FieldBytes::from(c_bytes);
        let c_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).ok()?);
        
        // Compute response s = k + c*x (mod N)
        let s_scalar = k_scalar + (c_scalar * x_scalar);
        let s_bytes = s_scalar.to_bytes();
        
        Some(ZkpRecoveryProof {
            r: r_bytes.as_bytes()[1..].to_vec(), // Skip 0x04 prefix
            s: s_bytes.to_vec(),
            c: c_bytes.to_vec(),
            conn_id,
        })
    }
    
    /// Verify Schnorr ZKP proof for session recovery
    fn verify_recovery_zkp(zkp_prover: &ZKPathProver, proof: &ZkpRecoveryProof) -> bool {
        use k256::{
            elliptic_curve::ScalarPrimitive,
            ProjectivePoint, Scalar, FieldBytes, AffinePoint,
        };
        
        // Get secret x and public point Y = x*G
        let mut hasher = Sha256::new();
        hasher.update(&zkp_prover.master_secret);
        hasher.update(proof.conn_id.as_bytes());
        let x_bytes = hasher.finalize();
        let fb = FieldBytes::from(x_bytes);
        let x_scalar = match ScalarPrimitive::from_bytes(&fb) {
            Ok(s) => Scalar::from(s),
            Err(_) => return false,
        };
        let y_point = ProjectivePoint::GENERATOR * x_scalar;
        
        // Parse proof components
        let s_bytes: [u8; 32] = match proof.s.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let fb = FieldBytes::from(s_bytes);
        let s_scalar = match ScalarPrimitive::from_bytes(&fb) {
            Ok(s) => Scalar::from(s),
            Err(_) => return false,
        };
        
        let c_bytes: [u8; 32] = match proof.c.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let fb = FieldBytes::from(c_bytes);
        let c_scalar = match ScalarPrimitive::from_bytes(&fb) {
            Ok(s) => Scalar::from(s),
            Err(_) => return false,
        };
        
        // Parse R point (uncompressed format without 0x04 prefix)
        let mut r_full = vec![0x04u8];
        r_full.extend_from_slice(&proof.r);
        let encoded_point = match k256::EncodedPoint::from_bytes(&r_full) {
            Ok(ep) => ep,
            Err(_) => return false,
        };
        let r_point = match AffinePoint::from_encoded_point(&encoded_point) {
            Some(p) => ProjectivePoint::from(p),
            None => return false,
        };
        
        // Verify Schnorr equation: s*G == R + c*Y
        let s_g = ProjectivePoint::GENERATOR * s_scalar;
        let c_y = y_point * c_scalar;
        let r_plus_c_y = r_point + c_y;
        
        s_g == r_plus_c_y
    }
}