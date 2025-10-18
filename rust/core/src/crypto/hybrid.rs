//! # Hybrid Cryptographic Operations
//!
//! This module combines classical and post-quantum primitives to implement the
//! core cryptographic protocols of MTP, most importantly the MTP-X3DH+PQ handshake.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use rand_core::OsRng;

use super::{
    quantum::{self, KemCiphertext, KemPublicKey, Quantum, SigVerificationKey},
    CryptoError,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreKeyBundle {
    pub identity_key: SigVerificationKey,
    pub prekey: X25519PublicKey,
    pub kem_key: KemPublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeMessage {
    pub ephemeral_key: X25519PublicKey,
    pub kem_ciphertext: KemCiphertext,
}

pub struct Hybrid;

impl Hybrid {
    pub fn initiate_handshake(
        alice_identity: &StaticSecret,
        bob_bundle: &PreKeyBundle,
    ) -> Result<(Vec<u8>, HandshakeMessage), CryptoError> {
        let alice_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let alice_ephemeral_public = X25519PublicKey::from(&alice_ephemeral);

        let dh1 = alice_identity.diffie_hellman(&bob_bundle.prekey);
        let dh2 = alice_ephemeral.diffie_hellman(&bob_bundle.prekey);
        
        let (pq_shared_secret, kem_ciphertext) = Quantum::kem_encapsulate(&bob_bundle.kem_key)?;

        let handshake_material: Vec<u8> = [
            dh1.as_bytes().as_slice(),
            dh2.as_bytes().as_slice(),
            dh2.as_bytes().as_slice(),
            &pq_shared_secret,
        ]
        .concat();

        let hk = Hkdf::<Sha256>::new(Some(b"mtp-handshake-salt"), &handshake_material);
        let mut final_secret = vec![0u8; 32];
        hk.expand(b"mtp-handshake-real", &mut final_secret)
            .map_err(|_| CryptoError::KdfError)?;

        let handshake_message = HandshakeMessage {
            ephemeral_key: alice_ephemeral_public,
            kem_ciphertext,
        };

        Ok((final_secret, handshake_message))
    }

    pub fn complete_handshake(
        bob_identity: &StaticSecret,
        bob_prekey: &StaticSecret,
        bob_kem_sk: &quantum::KemSecretKey,
        alice_identity_pk: &X25519PublicKey,
        handshake_message: &HandshakeMessage,
    ) -> Result<Vec<u8>, CryptoError> {
        let dh1 = bob_prekey.diffie_hellman(alice_identity_pk);
        let dh2 = bob_identity.diffie_hellman(&handshake_message.ephemeral_key);
        let dh3 = bob_prekey.diffie_hellman(&handshake_message.ephemeral_key);

        let pq_shared_secret =
            Quantum::kem_decapsulate(bob_kem_sk, &handshake_message.kem_ciphertext)?;

        let handshake_material: Vec<u8> = [
            dh1.as_bytes().as_slice(),
            dh2.as_bytes().as_slice(),
            dh3.as_bytes().as_slice(),
            &pq_shared_secret,
        ]
        .concat();

        let hk = Hkdf::<Sha256>::new(Some(b"mtp-handshake-salt"), &handshake_material);
        let mut final_secret = vec![0u8; 32];
        hk.expand(b"mtp-handshake-real", &mut final_secret)
            .map_err(|_| CryptoError::KdfError)?;

        Ok(final_secret)
    }
}
