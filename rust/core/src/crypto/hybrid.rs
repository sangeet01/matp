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

/// The bundle of public keys a user publishes to the DHT.
/// It contains a PQ identity key for signing, a classical prekey for X3DH,
/// and a PQ KEM key for the quantum part of the handshake.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreKeyBundle {
    pub identity_key: SigVerificationKey,
    pub prekey: X25519PublicKey,
    pub kem_key: KemPublicKey,
}

/// The initial message Alice sends to Bob to start a session.
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeMessage {
    pub ephemeral_key: X25519PublicKey,
    pub kem_ciphertext: KemCiphertext,
    // In a real implementation, this would also contain Alice's identity info.
}

/// A namespace struct for hybrid handshake operations.
pub struct Hybrid;

impl Hybrid {
    /// Alice runs this to initiate a session with Bob.
    /// It performs the MTP-X3DH+PQ key agreement.
    pub fn initiate_handshake(
        alice_identity: &StaticSecret,
        bob_bundle: &PreKeyBundle,
    ) -> Result<(Vec<u8>, HandshakeMessage), CryptoError> {
        let alice_ephemeral = EphemeralSecret::random_from_rng(OsRng);

        // --- MTP-X3DH+PQ Handshake ---
        // 1. Perform 3 classical DH exchanges.
        let dh1 = alice_identity.diffie_hellman(&bob_bundle.prekey);
        let dh2 = alice_ephemeral.diffie_hellman(&bob_bundle.prekey); // Simplified X3DH for now
        let dh3 = alice_ephemeral.diffie_hellman(&bob_bundle.prekey); // Placeholder for one-time prekey

        // 2. Perform 1 Post-Quantum KEM exchange.
        let (pq_shared_secret, kem_ciphertext) = Quantum::kem_encapsulate(&bob_bundle.kem_key)?;

        // 3. Combine all secrets into a single input for the KDF.
        let handshake_material: Vec<u8> = [
            dh1.as_bytes().as_slice(),
            dh2.as_bytes().as_slice(),
            dh3.as_bytes().as_slice(),
            &pq_shared_secret,
        ]
        .concat();

        // 4. Derive the final shared secret.
        let hk = Hkdf::<Sha256>::new(Some(b"mtp-handshake-salt"), &handshake_material);
        let mut final_secret = vec![0u8; 32];
        hk.expand(b"mtp-handshake-real", &mut final_secret)
            .map_err(|_| CryptoError::KdfError)?;

        // 5. Create the handshake message for Bob.
        let handshake_message = HandshakeMessage {
            ephemeral_key: X25519PublicKey::from(&alice_ephemeral),
            kem_ciphertext,
        };

        Ok((final_secret, handshake_message))
    }

    /// Bob runs this to complete the handshake after receiving Alice's message.
    pub fn complete_handshake(
        bob_identity: &StaticSecret, // Bob's long-term identity
        bob_prekey: &StaticSecret,   // The prekey from the bundle
        bob_kem_sk: &quantum::KemSecretKey,
        alice_identity_pk: &X25519PublicKey, // Alice's public identity key
        handshake_message: &HandshakeMessage,
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. Perform 3 classical DH exchanges from Bob's perspective.
        let dh1 = bob_prekey.diffie_hellman(alice_identity_pk);
        let dh2 = bob_identity.diffie_hellman(&handshake_message.ephemeral_key);
        let dh3 = bob_prekey.diffie_hellman(&handshake_message.ephemeral_key);

        // 2. Perform 1 Post-Quantum KEM decapsulation.
        let pq_shared_secret =
            Quantum::kem_decapsulate(bob_kem_sk, &handshake_message.kem_ciphertext)?;

        // 3. Combine all secrets in the same order as Alice.
        let handshake_material: Vec<u8> = [
            dh1.as_bytes().as_slice(),
            dh2.as_bytes().as_slice(),
            dh3.as_bytes().as_slice(),
            &pq_shared_secret,
        ]
        .concat();

        // 4. Derive the final shared secret.
        let hk = Hkdf::<Sha256>::new(Some(b"mtp-handshake-salt"), &handshake_material);
        let mut final_secret = vec![0u8; 32];
        hk.expand(b"mtp-handshake-real", &mut final_secret)
            .map_err(|_| CryptoError::KdfError)?;

        Ok(final_secret)
    }
}
