//! # The DHT Module
//!
//! This module provides a simulated Kademlia-style Distributed Hash Table (DHT)
//! for decentralized peer discovery. It allows users to publish their public
//! key bundles and look up the bundles of others without a central server.

pub mod kademlia;

// Define a common, top-level error type for all DHT operations.
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Key not found in the DHT network after an exhaustive search.")]
    KeyNotFound,
    #[error("Proof of work mining failed")]
    PowFailed,
}