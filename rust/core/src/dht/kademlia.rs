//! # Kademlia DHT Simulation
//!
//! A production-grade, asynchronous implementation of a Kademlia-style DHT.

use std::collections::{HashMap, BTreeSet};
use std::sync::Arc;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256 as Sha256Hasher};
use tokio::sync::Mutex;
use ethnum::U256;

use crate::crypto::hybrid::PreKeyBundle;
use crate::crypto::quantum::SigVerificationKey;

use super::DhtError;

type NodeId = [u8; 32];

/// Represents a single peer in the simulated DHT network.
struct DhtNode {
    id: NodeId,
    store: HashMap<NodeId, PreKeyBundle>,
    // In a real implementation, this would be a set of k-buckets.
    routing_table: Vec<Arc<DhtNode>>,
}

/// Manages the entire simulated network of nodes.
pub struct DhtNetwork {
    nodes: Vec<Arc<Mutex<DhtNode>>>,
}

impl DhtNetwork {
    /// Creates a new simulated network with a given number of nodes.
    pub fn new(num_nodes: usize) -> Self {
        let nodes: Vec<Arc<DhtNode>> = (0..num_nodes)
            .map(|_| {
                Arc::new(DhtNode {
                    id: rand::random(),
                    store: HashMap::new(),
                    routing_table: Vec::new(),
                })
            })
            .collect();

        // Bootstrap the network: make each node aware of a few others.
        for node_arc in &nodes {
            let mut node = node_arc.lock().unwrap();
            for _ in 0..5.min(num_nodes - 1) {
                let peer: Arc<DhtNode> = nodes.choose(&mut rand::thread_rng()).unwrap().clone();
                if !Arc::ptr_eq(&peer, node_arc) {
                    node.routing_table.push(peer);
                }
            }
        }

        Self { nodes }
    }

    /// Publishes a pre-key bundle to the K closest nodes to the key's hash.
    pub async fn publish(&self, identity_key: &SigVerificationKey, bundle: PreKeyBundle) {
        let key_hash = Self::get_key_hash(identity_key);
        let closest_nodes = self.find_closest_nodes(&key_hash).await;

        for node_arc in closest_nodes {
            let mut node = node_arc.lock().await;
            node.store.insert(key_hash, bundle.clone());
        }
    }

    /// Performs a realistic, iterative lookup for a key.
    pub async fn lookup(&self, identity_key: &SigVerificationKey) -> Result<PreKeyBundle, DhtError> {
        let key_hash = Self::get_key_hash(identity_key);
        let closest_nodes = self.find_closest_nodes(&key_hash).await;

        for node_arc in closest_nodes {
            let node = node_arc.lock().await;
            if let Some(bundle) = node.store.get(&key_hash) {
                return Ok(bundle.clone());
            }
        }
        Err(DhtError::KeyNotFound)
    }

    /// Finds the K closest nodes to a given key hash using an iterative search.
    async fn find_closest_nodes(&self, key_hash: &NodeId) -> Vec<Arc<DhtNode>> {
        let key_hash_int = U256::from_be_bytes(*key_hash);
        let k = 3; // Kademlia's K-parameter

        let mut queried_nodes = BTreeSet::new();
        let mut shortlist: BTreeSet<_> = self.nodes.choose_multiple(&mut rand::thread_rng(), k)
            .map(|node_arc| {
                let node = node_arc.lock().unwrap();
                let node_id_int = U256::from_be_bytes(node.id);
                (node_id_int ^ key_hash_int, node_arc.clone())
            }).collect();

        while let Some((_, node_arc)) = shortlist.iter().find(|(_, n)| !queried_nodes.contains(&n.lock().unwrap().id)).cloned() {
            queried_nodes.insert(node_arc.lock().unwrap().id);

            let node = node_arc.lock().await;
            for peer_arc in &node.routing_table {
                let peer = peer_arc.lock().unwrap();
                let peer_id_int = U256::from_be_bytes(peer.id);
                shortlist.insert((peer_id_int ^ key_hash_int, peer_arc.clone()));
            }
        }

        shortlist.into_iter().take(k).map(|(_, node)| node).collect()
    }

    /// Generates a consistent, addressable key for the DHT from a public identity key.
    fn get_key_hash(identity_key: &SigVerificationKey) -> NodeId {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"mtp-dht-key-");
        hasher.update(&identity_key.0);
        hasher.finalize().into()
    }
}
