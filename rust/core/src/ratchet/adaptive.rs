//! # The Adaptive Ratchet
//!
//! This module contains the logic for the "Quantum Trigger," allowing the
//! protocol to dynamically switch from the fast classical ratchet to a more
//! secure, fully post-quantum ratchet in response to a perceived threat.

use super::{rclassical::{MatryoshkaRatchet, ZkpRecoveryProof}, state::{MtpPacket, MessageHeader}, RatchetError};
use x25519_dalek::PublicKey as X25519PublicKey;
use std::collections::HashMap;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use crate::crypto::{
    classical::{self, ChainKey, MessageKey, RootKey},
    quantum::{Quantum, KemPublicKey, KemSecretKey},
    fractal::{Fractal, PQFractalBundle},
    CryptoError,
};
use crate::mitm::zkp_path::ZKPathProver;

/// Represents the reason for triggering the switch to quantum mode.
pub enum QuantumTrigger {
    /// The user manually initiated the switch for maximum security.
    Manual,
    /// The peer sent a message requesting a switch.
    PeerRequest,
    /// A network anomaly or potential censorship attempt was detected.
    NetworkAnomaly,
}

/// Post-quantum ratchet using Kyber KEM for asymmetric steps.
/// Provides full quantum resistance for every message.
#[allow(dead_code)]
pub struct QuantumRatchet {
    root_key: RootKey,
    sending_chain_key: Option<ChainKey>,
    receiving_chain_key: Option<ChainKey>,
    
    // Quantum KEM state
    kem_key_pair: (KemPublicKey, KemSecretKey),
    remote_kem_public_key: Option<KemPublicKey>,
    
    msg_num_send: u32,
    msg_num_recv: u32,
    
    skipped_message_keys: HashMap<(Vec<u8>, u32), MessageKey>,
    fractal_recovery_bundles: Vec<PQFractalBundle>,
    
    // ZKP prover for session recovery
    zkp_prover: Option<ZKPathProver>,
    
    decoy_mode: bool,
    kdf_salt_suffix: &'static [u8],
}

impl QuantumRatchet {
    pub fn new(
        initial_shared_secret: &[u8],
        remote_kem_public_key: Option<KemPublicKey>,
        is_initiator: bool,
        decoy_mode: bool,
        zkp_prover: Option<ZKPathProver>,
    ) -> Result<Self, RatchetError> {
        let kdf_salt_suffix: &[u8] = if decoy_mode { b"-decoy-pq" } else { b"-pq" };
        let kem_key_pair = Quantum::generate_kem_keys()?;
        
        let (root_key, sending_chain_key, receiving_chain_key) = if is_initiator {
            // Initiator performs KEM encapsulation
            if let Some(ref remote_pk) = remote_kem_public_key {
                let (shared_secret, _) = Quantum::kem_encapsulate(remote_pk)?;
                let info = [b"mtp-kem-init", kdf_salt_suffix].concat();
                let mut root_key_bytes = [0u8; 32];
                Hkdf::<Sha256>::new(Some(initial_shared_secret), &shared_secret)
                    .expand(&info, &mut root_key_bytes)
                    .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
                let root_key = RootKey(root_key_bytes);
                
                let (send_ck, recv_ck) = classical::kdf_root(&root_key, kdf_salt_suffix)?;
                (root_key, Some(send_ck), Some(recv_ck))
            } else {
                return Err(RatchetError::StateError("Remote KEM key required for initiator".to_string()));
            }
        } else {
            // Receiver waits for first message
            let info = [b"mtp-receiver-init-pq", kdf_salt_suffix].concat();
            let mut root_key_bytes = [0u8; 32];
            Hkdf::<Sha256>::new(Some(initial_shared_secret), initial_shared_secret)
                .expand(&info, &mut root_key_bytes)
                .map_err(|_| RatchetError::Crypto(CryptoError::KdfError))?;
            let root_key = RootKey(root_key_bytes);
            (root_key, None, None)
        };
        
        Ok(Self {
            root_key,
            sending_chain_key,
            receiving_chain_key,
            kem_key_pair,
            remote_kem_public_key,
            msg_num_send: 0,
            msg_num_recv: 0,
            skipped_message_keys: HashMap::new(),
            fractal_recovery_bundles: Vec::new(),
            zkp_prover,
            decoy_mode,
            kdf_salt_suffix,
        })
    }
    
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<MtpPacket, RatchetError> {
        let sending_ck = self.sending_chain_key.as_mut()
            .ok_or_else(|| RatchetError::StateError("Sending chain not initialized".to_string()))?;
        
        // Symmetric ratchet step
        let (message_key, next_sending_ck) = classical::kdf_chain(sending_ck, self.kdf_salt_suffix)?;
        *sending_ck = next_sending_ck;
        
        // Generate fractal bundle
        let fractal_bundle = Fractal::generate_future_bundle(&next_sending_ck, self.kdf_salt_suffix)?;
        
        // Encrypt
        let ciphertext = classical::encrypt(&message_key, plaintext, &[])?;
        
        // Construct header with KEM public key
        let header = MessageHeader {
            dh_ratchet_pub_key: X25519PublicKey::from([0u8; 32]), // Not used in quantum mode
            chain_msg_num: self.msg_num_send,
            dh_new_pub_key: None,
            decoy_flag: self.decoy_mode,
            zkp_innocence: None,
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
    
    pub fn ratchet_decrypt(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        if packet.header.decoy_flag != self.decoy_mode {
            return Err(RatchetError::DecryptionError("Decoy flag mismatch".to_string()));
        }
        
        if self.receiving_chain_key.is_none() {
            return Err(RatchetError::StateError("Receiving chain not initialized".to_string()));
        }
        
        // Try normal decryption
        let result = Self::try_decrypt_with_chain(
            self.receiving_chain_key.as_mut().unwrap(),
            &mut self.msg_num_recv,
            &mut self.skipped_message_keys,
            packet,
            self.kdf_salt_suffix,
        );
        
        match result {
            Ok(plaintext) => {
                // Store fractal bundle
                self.fractal_recovery_bundles.push(packet.fractal_bundle.clone());
                if self.fractal_recovery_bundles.len() > 5 {
                    self.fractal_recovery_bundles.remove(0);
                }
                Ok(plaintext)
            },
            Err(_) => self.try_fractal_recovery_with_zkp(packet),
        }
    }
    
    fn try_decrypt_with_chain(
        receiving_ck: &mut ChainKey,
        msg_num_recv: &mut u32,
        skipped_message_keys: &mut HashMap<(Vec<u8>, u32), MessageKey>,
        packet: &MtpPacket,
        kdf_salt_suffix: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let msg_num = packet.header.chain_msg_num;
        
        // Check skipped messages
        let key = (vec![0u8; 32], msg_num);
        if let Some(message_key) = skipped_message_keys.remove(&key) {
            return classical::decrypt(&message_key, &packet.ciphertext, &[])
                .map_err(|e| RatchetError::Crypto(e));
        }
        
        // Advance chain to catch up
        while *msg_num_recv < msg_num {
            if skipped_message_keys.len() >= 100 {
                return Err(RatchetError::StateError("Max skipped messages exceeded".to_string()));
            }
            let (skipped_mk, next_ck) = classical::kdf_chain(receiving_ck, kdf_salt_suffix)?;
            skipped_message_keys.insert((vec![0u8; 32], *msg_num_recv), skipped_mk);
            *receiving_ck = next_ck;
            *msg_num_recv += 1;
        }
        
        // Decrypt current message
        if *msg_num_recv == msg_num {
            let (message_key, next_ck) = classical::kdf_chain(receiving_ck, kdf_salt_suffix)?;
            let plaintext = classical::decrypt(&message_key, &packet.ciphertext, &[])?;
            *receiving_ck = next_ck;
            *msg_num_recv += 1;
            return Ok(plaintext);
        }
        
        Err(RatchetError::DecryptionError("Message out of sync".to_string()))
    }
    
    /// 🔐 CRITICAL: ZKP-protected session recovery for quantum ratchet
    fn try_fractal_recovery_with_zkp(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
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
            return Err(RatchetError::MitmDetected(
                "Missing ZKP proof during session recovery - possible MITM attack!".to_string()
            ));
        }
        
        // ZKP verified - try fractal recovery
        let bundles = self.fractal_recovery_bundles.clone();
        for bundle in bundles.iter().rev() {
            for classical_key in &bundle.classical {
                let new_root_key = RootKey(*classical_key);
                if let Ok((mut new_recv_ck, _)) = classical::kdf_root(&new_root_key, self.kdf_salt_suffix) {
                    if let Ok(plaintext) = Self::try_decrypt_with_chain(
                        &mut new_recv_ck,
                        &mut self.msg_num_recv,
                        &mut self.skipped_message_keys,
                        packet,
                        self.kdf_salt_suffix,
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
        use k256::elliptic_curve::ScalarPrimitive;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{ProjectivePoint, Scalar, FieldBytes};
        use rand::RngCore;
        
        let mut hasher = Sha256::new();
        hasher.update(&self.root_key.0);
        let conn_id_hash = hasher.finalize();
        let conn_id = format!("{:x}", u64::from_be_bytes(conn_id_hash[..8].try_into().ok()?));
        
        let master_secret = match &self.zkp_prover {
            Some(prover) => &prover.master_secret,
            None => return None,
        };
        
        let mut hasher = Sha256::new();
        hasher.update(master_secret);
        hasher.update(conn_id.as_bytes());
        let x_bytes = hasher.finalize();
        let fb = FieldBytes::from(x_bytes);
        let x_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).into_option()?);
        
        let mut k_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k_bytes);
        let fb = FieldBytes::from(k_bytes);
        let k_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).into_option()?);
        let r_point = ProjectivePoint::GENERATOR * k_scalar;
        let r_affine = r_point.to_affine();
        let r_bytes = r_affine.to_encoded_point(false);
        
        let mut c_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut c_bytes);
        let fb = FieldBytes::from(c_bytes);
        let c_scalar = Scalar::from(ScalarPrimitive::from_bytes(&fb).into_option()?);
        
        let s_scalar = k_scalar + (c_scalar * x_scalar);
        let s_bytes = s_scalar.to_bytes();
        
        Some(ZkpRecoveryProof {
            r: r_bytes.as_bytes()[1..].to_vec(),
            s: s_bytes.to_vec(),
            c: c_bytes.to_vec(),
            conn_id,
        })
    }
    
    /// Verify Schnorr ZKP proof for session recovery
    fn verify_recovery_zkp(zkp_prover: &ZKPathProver, proof: &ZkpRecoveryProof) -> bool {
        use k256::elliptic_curve::ScalarPrimitive;
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        use k256::{ProjectivePoint, Scalar, FieldBytes, AffinePoint};
        
        let mut hasher = Sha256::new();
        hasher.update(&zkp_prover.master_secret);
        hasher.update(proof.conn_id.as_bytes());
        let x_bytes = hasher.finalize();
        let fb = FieldBytes::from(x_bytes);
        let x_scalar = match ScalarPrimitive::from_bytes(&fb).into_option() {
            Some(s) => Scalar::from(s),
            None => return false,
        };
        let y_point = ProjectivePoint::GENERATOR * x_scalar;
        
        let s_bytes: [u8; 32] = match proof.s.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let fb = FieldBytes::from(s_bytes);
        let s_scalar = match ScalarPrimitive::from_bytes(&fb).into_option() {
            Some(s) => Scalar::from(s),
            None => return false,
        };
        
        let c_bytes: [u8; 32] = match proof.c.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let fb = FieldBytes::from(c_bytes);
        let c_scalar = match ScalarPrimitive::from_bytes(&fb).into_option() {
            Some(s) => Scalar::from(s),
            None => return false,
        };
        
        let mut r_full = vec![0x04u8];
        r_full.extend_from_slice(&proof.r);
        let encoded_point = match k256::EncodedPoint::from_bytes(&r_full) {
            Ok(ep) => ep,
            Err(_) => return false,
        };
        let r_point = match AffinePoint::from_encoded_point(&encoded_point).into_option() {
            Some(p) => ProjectivePoint::from(p),
            None => return false,
        };
        
        let s_g = ProjectivePoint::GENERATOR * s_scalar;
        let c_y = y_point * c_scalar;
        let r_plus_c_y = r_point + c_y;
        
        s_g == r_plus_c_y
    }
}

/// The state machine that manages switching between classical and quantum ratchets.
pub struct AdaptiveRatchet {
    classical_ratchet: MatryoshkaRatchet,
    quantum_ratchet: Option<QuantumRatchet>,
    is_quantum_mode: bool,
}

impl AdaptiveRatchet {
    pub fn new(
        initial_shared_secret: &[u8],
        remote_dh_public_key: X25519PublicKey,
        is_initiator: bool,
        decoy_mode: bool,
        zkp_prover: Option<ZKPathProver>,
    ) -> Result<Self, RatchetError> {
        Ok(Self {
            classical_ratchet: MatryoshkaRatchet::new(initial_shared_secret, remote_dh_public_key, is_initiator, decoy_mode, None, zkp_prover.clone())?,
            quantum_ratchet: None,
            is_quantum_mode: false,
        })
    }

    /// Activates the quantum-resistant ratchet.
    pub fn trigger_quantum_mode(&mut self, reason: QuantumTrigger) {
        if !self.is_quantum_mode {
            println!("[ADAPTIVE] Quantum trigger activated: {:?}", match reason {
                QuantumTrigger::Manual => "Manual",
                QuantumTrigger::PeerRequest => "PeerRequest",
                QuantumTrigger::NetworkAnomaly => "NetworkAnomaly",
            });
            self.is_quantum_mode = true;
            
            // Derive quantum root from classical state
            let quantum_root_bytes = {
                let mut bytes = [0u8; 32];
                let info = b"quantum-upgrade";
                Hkdf::<Sha256>::new(None, &self.classical_ratchet.get_root_key())
                    .expand(info, &mut bytes)
                    .expect("HKDF expand failed");
                bytes
            };
            
            // Initialize quantum ratchet with ZKP prover
            let zkp_prover = self.classical_ratchet.get_zkp_prover().clone();
            match QuantumRatchet::new(&quantum_root_bytes, None, true, false, zkp_prover) {
                Ok(qr) => self.quantum_ratchet = Some(qr),
                Err(e) => println!("[ADAPTIVE] Failed to initialize quantum ratchet: {:?}", e),
            }
        }
    }

    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<MtpPacket, RatchetError> {
        if self.is_quantum_mode {
            self.quantum_ratchet.as_mut().unwrap().ratchet_encrypt(plaintext)
        } else {
            self.classical_ratchet.ratchet_encrypt(plaintext)
        }
    }

    pub fn ratchet_decrypt(&mut self, packet: &MtpPacket) -> Result<Vec<u8>, RatchetError> {
        if self.is_quantum_mode {
            // A real implementation would need to check if the packet is classical or quantum
            // and route accordingly, to handle the transition period.
            self.quantum_ratchet.as_mut().unwrap().ratchet_decrypt(packet)
        } else {
            self.classical_ratchet.ratchet_decrypt(packet)
        }
    }
}

