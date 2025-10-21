//! # MTP-Core: The Cryptographic Heart of the Matryoshka Protocol
//!
//! This crate provides the core implementation of the Matryoshka Protocol (MTP),
//! a next-generation secure messaging protocol designed for ultimate privacy,
//! security, and deniability.

// Declare the top-level modules of our library.
// The Rust compiler will look for `crypto/mod.rs`, `ratchet/mod.rs`, etc.
pub mod crypto;
pub mod ratchet;
pub mod ghost;
pub mod dht;
pub mod zkp;
pub mod session;
pub mod groups;
pub mod protocol;
pub mod mitm;

// --- Public API ---
// Re-export the most important structs and functions to create a clean public API.
// This allows external users to write `use mtp_core::MatryoshkaSession;`
// instead of `use mtp_core::session::MatryoshkaSession;`.

// The primary entry point for creating and managing a secure session.
pub use session::MatryoshkaSession;

// The steganography engine.
pub use ghost::engine::GhostEngine;

// Group messaging
pub use groups::{FractalGroupRatchet, MatryoshkaGroup, MatryoshkaGroupManager};

// High-level protocol wrapper
pub use protocol::{MatryoshkaProtocol, GhostMessage, FutureBundle};

// MAP (Matryoshka Authentication Protocol) - Lightning MITM Protection
pub use mitm::{
    BloomFilterAuth, CertificateInfo, FlowFingerprinter, FlowMetrics, 
    FlowFingerprint, ZKPathProver, PredictiveCrypto, PreAuthConnectionPool,
    SecureConnection, ContinuousStochasticAuth, LightningMITMProtection, MITMDetectionResult
};

// Quantum cryptography
pub use crypto::quantum;

// A top-level error type for the library.
// Each module will have its own error type that can be converted into this one.
#[derive(Debug)]
pub enum MtpError {
    CryptoError(String),
    RatchetError(String),
    GhostError(String),
}