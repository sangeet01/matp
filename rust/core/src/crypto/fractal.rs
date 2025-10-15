//! # PQ-Optimized Fractal Bundles
//!
//! This module implements the logic for generating and recovering from the
//! hybrid fractal key bundles that are central to the Matryoshka Protocol's
//! resilience.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::{
    classical::{ChainKey, RootKey},
    CryptoError,
};

/// A hybrid bundle containing both fast classical recovery keys and a
/// compact, quantum-safe recovery seed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PQFractalBundle {
    /// A list of pre-derived classical keys for fast, common-case recovery.
    pub classical: [[u8; 32]; 3],
    /// A compact seed used to deterministically re-generate a quantum-safe
    /// key in a catastrophic recovery scenario.
    pub quantum_seed: [u8; 32],
}

/// A namespace struct for fractal bundle operations.
pub struct Fractal;

impl Fractal {
    /// Generates a new `PQFractalBundle` from the current chain key.
    /// This is a cheap operation that can be performed for every message sent.
    pub fn generate_future_bundle(
        current_chain_key: &ChainKey,
        kdf_salt_suffix: &[u8],
    ) -> Result<PQFractalBundle, CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, &current_chain_key.0);

        // 1. Generate Classical keys
        let mut classical_keys = [[0u8; 32]; 3];
        let info1 = [b"mtp-fractal-classical-1", kdf_salt_suffix].concat();
        hk.expand(&info1, &mut classical_keys[0])
            .map_err(|_| CryptoError::KdfError)?;
        let info2 = [b"mtp-fractal-classical-2", kdf_salt_suffix].concat();
        hk.expand(&info2, &mut classical_keys[1])
            .map_err(|_| CryptoError::KdfError)?;
        let info3 = [b"mtp-fractal-classical-3", kdf_salt_suffix].concat();
        hk.expand(&info3, &mut classical_keys[2])
            .map_err(|_| CryptoError::KdfError)?;

        // 2. Generate Quantum recovery seed
        let mut quantum_seed = [0u8; 32];
        let info_q = [b"mtp-fractal-quantum-seed", kdf_salt_suffix].concat();
        hk.expand(&info_q, &mut quantum_seed)
            .map_err(|_| CryptoError::KdfError)?;

        Ok(PQFractalBundle {
            classical: classical_keys,
            quantum_seed,
        })
    }
}