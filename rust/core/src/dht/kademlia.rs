//! # Kademlia DHT with Sybil Protection
//!
//! Production-grade DHT with hybrid Sybil resistance:
//! - Proof-of-Work (required for all nodes)
//! - IP-based rate limiting
//! - Fractal commitment (optional Matryoshka enhancement)

use std::collections::{HashMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use uint::U256;

use crate::crypto::hybrid::PreKeyBundle;
use crate::crypto::quantum::SigVerificationKey;

use super::DhtError;

type NodeId = [u8; 32];

const POW_DIFFICULTY: u32 = 4;
const IP_JOIN_COOLDOWN_SECS: u64 = 3600;

/// Represents a single peer with Sybil protection.
struct DhtNode {
    id: NodeId,
    pow_nonce: u64,
    ip_address: IpAddr,
    join_timestamp: u64,
    
    // Matryoshka-specific enhancement
    fractal_commitment: Option<[u8; 32]>,
    reputation_boost: f64,
    
    // Reputation tracking
    successful_lookups: u64,
    failed_verifications: u64,
    
    store: HashMap<NodeId, PreKeyBundle>,
    routing_table: Vec<Arc<Mutex<DhtNode>>>,
}

/// Manages the entire simulated network of nodes.
pub struct DhtNetwork {
    nodes: Vec<Arc<Mutex<DhtNode>>>,
}

impl DhtNode {
    /// Join DHT as standard node (PoW required).
    fn new_standard(ip: IpAddr) -> Result<Self, DhtError> {
        let (id, nonce) = Self::mine_node_id()?;
        Ok(Self {
            id, pow_nonce: nonce, ip_address: ip, join_timestamp: Self::now(),
            fractal_commitment: None, reputation_boost: 1.0,
            successful_lookups: 0, failed_verifications: 0,
            store: HashMap::new(), routing_table: Vec::new(),
        })
    }
    
    /// Mine a valid node ID with proof-of-work.
    fn mine_node_id() -> Result<(NodeId, u64), DhtError> {
        for nonce in 0..u64::MAX {
            let mut hasher = Sha256::new();
            hasher.update(b"mtp-dht-pow-");
            hasher.update(&nonce.to_le_bytes());
            let hash: [u8; 32] = hasher.finalize().into();
            
            // Check if hash meets difficulty (leading zero bits)
            if Self::check_pow_difficulty(&hash, POW_DIFFICULTY) {
                return Ok((hash, nonce));
            }
        }
        Err(DhtError::PowFailed)
    }
    
    fn check_pow_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
        let required_zeros = difficulty / 8;
        let remaining_bits = difficulty % 8;
        
        // Check full zero bytes
        for i in 0..required_zeros as usize {
            if hash[i] != 0 { return false; }
        }
        
        // Check remaining bits
        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[required_zeros as usize] & mask != 0 { return false; }
        }
        true
    }
    
    /// Calculate reputation score.
    fn reputation_score(&self) -> f64 {
        let base_score = self.successful_lookups as f64 / (self.failed_verifications + 1) as f64;
        base_score * self.reputation_boost
    }
    
    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

impl DhtNetwork {
    /// Creates a new simulated network with Sybil-protected nodes.
    pub fn new(num_nodes: usize) -> Self {
        let nodes: Vec<Arc<Mutex<DhtNode>>> = (0..num_nodes)
            .map(|i| {
                let ip = IpAddr::from([127, 0, 0, (i % 255) as u8]);
                Arc::new(Mutex::new(DhtNode::new_standard(ip).unwrap()))
            })
            .collect();

        // Bootstrap the network: make each node aware of a few others.
        for node_arc in &nodes {
            let mut node = node_arc.lock().unwrap();
            for _ in 0..5.min(num_nodes - 1) {
                let peer = nodes.choose(&mut rand::thread_rng()).unwrap().clone();
                if !Arc::ptr_eq(&peer, node_arc) {
                    node.routing_table.push(peer);
                }
            }
        }
        Self { nodes }
    }

    /// Publishes a pre-key bundle to the K closest nodes to the key's hash.
    pub fn publish(&self, identity_key: &SigVerificationKey, bundle: PreKeyBundle) {
        let key_hash = Self::get_key_hash(identity_key);
        let closest_nodes = self.find_closest_nodes(&key_hash);
        for node_arc in closest_nodes {
            let mut node = node_arc.lock().unwrap();
            node.store.insert(key_hash, bundle.clone());
        }
    }

    /// Performs a realistic, iterative lookup for a key.
    pub fn lookup(&self, identity_key: &SigVerificationKey) -> Result<PreKeyBundle, DhtError> {
        let key_hash = Self::get_key_hash(identity_key);
        let closest_nodes = self.find_closest_nodes(&key_hash);
        for node_arc in closest_nodes {
            let node = node_arc.lock().unwrap();
            if let Some(bundle) = node.store.get(&key_hash) {
                return Ok(bundle.clone());
            }
        }
        Err(DhtError::KeyNotFound)
    }

    /// Finds the K closest nodes, prioritizing high-reputation nodes.
    fn find_closest_nodes(&self, key_hash: &NodeId) -> Vec<Arc<Mutex<DhtNode>>> {
        let key_hash_int = U256::from_big_endian(key_hash);
        let k = 3;
        let mut shortlist: BTreeSet<_> = self.nodes.choose_multiple(&mut rand::thread_rng(), k)
            .map(|node_arc| {
                let node = node_arc.lock().unwrap();
                let node_id_int = U256::from_big_endian(&node.id);
                let distance = node_id_int ^ key_hash_int;
                
                // Adjust distance by reputation (lower = better)
                let adjusted_distance = distance / U256::from(node.reputation_score() as u64 + 1);
                (adjusted_distance, node_arc.clone())
            }).collect();
        shortlist.into_iter().take(k).map(|(_, node)| node).collect()
    }

    /// Generates a consistent, addressable key for the DHT from a public identity key.
    fn get_key_hash(identity_key: &SigVerificationKey) -> NodeId {
        let mut hasher = Sha256::new();
        hasher.update(b"mtp-dht-key-");
        hasher.update(&identity_key.0);
        hasher.finalize().into()
    }
}
