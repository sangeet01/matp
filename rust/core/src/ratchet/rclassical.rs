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
use crate::zkp::{ZkpEngine, TrafficPattern};
use hkdf::Hkdf;
use sha2::Sha256;

use super::{
    state::{MessageHeader, MtpPacket},
    RatchetError,
};

const MAX_SKIPPED_MESSAGES: usize = 100;

/// The state machine for a single Matryoshka ratchet session (either real or decoy).
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
    ) -> Result<Self, RatchetError> {
        let kdf_salt_suffix: &[u8] = if decoy_mode { b"-decoy" } else { b"" };
        let dh_key_pair = StaticSecret::random_from_rng(OsRng);

        let (root_key, sending_chain_key, receiving_chain_key) = if is_initiator {
            // Initiator performs a DH exchange immediately to create the first root key.
            let dh_output = dh_key_pair.diffie_hellman(&remote_dh_public_key);
            let info = [b"mtp-dh-init", kdf_salt_suffix].concat();
            let root_key = RootKey(
                Hkdf::<Sha256>::new(Some(initial_shared_secret), dh_output.as_bytes())
                    .expand(&info, &mut [0u8; 32])
                    .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?
                    .try_into()
                    .unwrap(),
            );

            let (send_ck, recv_ck) = classical::kdf_root(&root_key, kdf_salt_suffix)?;
            (root_key, Some(send_ck), Some(recv_ck))
        } else {
            // Receiver uses the initial secret directly and waits for Alice's first message.
            let info = [b"mtp-receiver-init", kdf_salt_suffix].concat();
            let root_key = RootKey(
                Hkdf::<Sha256>::new(Some(initial_shared_secret), initial_shared_secret)
                    .expand(&info, &mut [0u8; 32])
                    .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?
                    .try_into()
                    .unwrap(),
            );
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
                // Generate a simple proof for decoy messages
                let zkp_engine = ZkpEngine::new();
                let traffic = TrafficPattern {
                    request_sizes: vec![1024, 2048, 512],
                    timing_intervals: vec![100, 150, 200],
                    content_types: vec!["application/json".to_string()],
                };
                zkp_engine.prove_innocence(&traffic).ok()
            } else {
                None
            }
        };

        self.msg_num_send += 1;

        Ok(MtpPacket {
            header,
            ciphertext,
            fractal_bundle,
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

        let plaintext = {
            let receiving_ck = self.receiving_chain_key.as_mut().ok_or_else(|| {
                RatchetError::StateError("Receiving chain not initialized".to_string())
            })?;
            self.try_decrypt_and_advance(receiving_ck, packet)
        }.or_else(|_| self.try_fractal_recovery(packet))?;

        self.fractal_recovery_bundles.push(packet.fractal_bundle.clone());
        if self.fractal_recovery_bundles.len() > 5 {
            self.fractal_recovery_bundles.remove(0);
        }
        Ok(plaintext)
    }

    /// Attempts to decrypt a message, handling out-of-order messages by storing skipped keys.
    fn try_decrypt_and_advance(
        &mut self,
        receiving_ck: &mut ChainKey,
        packet: &MtpPacket,
    ) -> Result<Vec<u8>, RatchetError> {
        let remote_pk_bytes = packet.header.dh_ratchet_pub_key.as_bytes().to_vec();
        let msg_num = packet.header.chain_msg_num;

        // 1. Check if it's a skipped message we've already stored a key for
        if let Some(message_key) = self.skipped_message_keys.remove(&(remote_pk_bytes.clone(), msg_num)) {
            return classical::decrypt(&message_key, &packet.ciphertext, &[]);
        }

        // 2. If not, try to advance the current chain to catch up
        while self.msg_num_recv < msg_num {
            if self.skipped_message_keys.len() >= MAX_SKIPPED_MESSAGES {
                return Err(RatchetError::StateError("Max skipped messages exceeded".to_string()));
            }
            let (skipped_mk, next_ck) = classical::kdf_chain(receiving_ck, self.kdf_salt_suffix)?;
            self.skipped_message_keys.insert((remote_pk_bytes.clone(), self.msg_num_recv), skipped_mk);
            *receiving_ck = next_ck;
            self.msg_num_recv += 1;
        }

        // 3. Now we should be at the correct message number, try to decrypt
        if self.msg_num_recv == msg_num {
            let (message_key, next_ck) = classical::kdf_chain(receiving_ck, self.kdf_salt_suffix)?;
            let plaintext = classical::decrypt(&message_key, &packet.ciphertext, &[])?;
            *receiving_ck = next_ck;
            self.msg_num_recv += 1;
            return Ok(plaintext);
        }

        Err(RatchetError::DecryptionError("Message is from the past or state is out of sync".to_string()))
    }

    /// Performs a Diffie-Hellman ratchet step, updating the root key.
    fn perform_dh_ratchet(&mut self, new_remote_pk: X25519PublicKey) -> Result<(), RatchetError> {
        // This is a simplified DH ratchet step. A full implementation is more complex.
        self.msg_num_recv = 0;
        self.skipped_message_keys.clear();

        let dh_output = self.dh_key_pair.diffie_hellman(&new_remote_pk);
        let info = [b"mtp-dh-ratchet", self.kdf_salt_suffix].concat();
        let new_root_key_bytes = Hkdf::<Sha256>::new(Some(&self.root_key.0), dh_output.as_bytes())
            .expand(&info, &mut [0u8; 32])
            .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?
            .try_into().unwrap();
        
        self.root_key = RootKey(new_root_key_bytes);
        let (send_ck, recv_ck) = classical::kdf_root(&self.root_key, self.kdf_salt_suffix)?;
        self.sending_chain_key = Some(send_ck);
        self.receiving_chain_key = Some(recv_ck);
        self.dh_remote_public_key = new_remote_pk;
        self.dh_key_pair = StaticSecret::random_from_rng(OsRng);

        Ok(())
    }

    /// Attempts to recover the ratchet state using a key from a stored fractal bundle.
    fn try_fractal_recovery(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        let bundles = self.fractal_recovery_bundles.clone();
        for bundle in bundles.iter().rev() {
            for classical_key in &bundle.classical {
                let new_root_key = RootKey(*classical_key);
                if let Ok((mut new_recv_ck, _)) = classical::kdf_root(&new_root_key, self.kdf_salt_suffix) {
                    if let Ok(plaintext) = self.try_decrypt_and_advance(&mut new_recv_ck, packet) {
                        self.root_key = new_root_key;
                        self.receiving_chain_key = Some(new_recv_ck);
                        return Ok(plaintext);
                    }
                }
            }
        }
        Err(RatchetError::DecryptionError("Fractal recovery failed".to_string()))
    }
}
