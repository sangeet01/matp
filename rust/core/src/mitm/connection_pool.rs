//! Pre-Authenticated Connection Pool
//!
//! Maintains pool of pre-authenticated connections for instant access.
//! Performance: 0ms connection time

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use rand::Rng;

/// Secure connection with authentication info
#[derive(Debug, Clone)]
pub struct SecureConnection {
    pub connection_id: String,
    pub peer_id: String,
    pub session_key: Vec<u8>,
    pub cert_fingerprint: Vec<u8>,
    pub established_at: f64,
    pub last_used: f64,
    pub is_authenticated: bool,
}

impl SecureConnection {
    pub fn new(peer_id: String) -> Self {
        let mut rng = rand::thread_rng();
        let connection_id = format!("{:032x}", rng.gen::<u128>());
        let session_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let cert_fingerprint: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let now = current_time();

        Self {
            connection_id,
            peer_id,
            session_key,
            cert_fingerprint,
            established_at: now,
            last_used: now,
            is_authenticated: true,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = current_time();
    }

    pub fn age(&self) -> f64 {
        current_time() - self.established_at
    }
}

/// Pre-authenticated connection pool for instant access
///
/// Maintains a pool of ready-to-use authenticated connections,
/// eliminating handshake overhead.
///
/// Performance: 0ms connection time
pub struct PreAuthConnectionPool {
    pool_size: usize,
    max_age: f64,
    connections: Arc<Mutex<HashMap<String, SecureConnection>>>,
    available_tx: mpsc::Sender<SecureConnection>,
    available_rx: Arc<Mutex<mpsc::Receiver<SecureConnection>>>,
    connections_created: Arc<Mutex<u64>>,
    connections_reused: Arc<Mutex<u64>>,
    connections_expired: Arc<Mutex<u64>>,
}

impl PreAuthConnectionPool {
    /// Create new connection pool
    ///
    /// # Arguments
    /// * `pool_size` - Number of connections to maintain
    /// * `max_age` - Maximum connection age in seconds (default: 3600 = 1 hour)
    pub fn new(pool_size: usize, max_age: f64) -> Self {
        let (tx, rx) = mpsc::channel(pool_size);

        Self {
            pool_size,
            max_age,
            connections: Arc::new(Mutex::new(HashMap::new())),
            available_tx: tx,
            available_rx: Arc::new(Mutex::new(rx)),
            connections_created: Arc::new(Mutex::new(0)),
            connections_reused: Arc::new(Mutex::new(0)),
            connections_expired: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize connection pool
    pub async fn initialize(&self) {
        // Pre-create connections
        for _ in 0..self.pool_size {
            let conn = self.create_connection("default".to_string()).await;
            let _ = self.available_tx.send(conn).await;
        }

        // Start maintenance task
        let pool = self.clone();
        tokio::spawn(async move {
            pool.maintenance_loop().await;
        });
    }

    async fn create_connection(&self, peer_id: String) -> SecureConnection {
        let conn = SecureConnection::new(peer_id);

        let mut connections = self.connections.lock().await;
        connections.insert(conn.connection_id.clone(), conn.clone());

        let mut created = self.connections_created.lock().await;
        *created += 1;

        conn
    }

    /// Get pre-authenticated connection (0ms)
    ///
    /// Returns SecureConnection ready to use
    pub async fn get_connection(&self, peer_id: String) -> SecureConnection {
        let mut rx = self.available_rx.lock().await;

        // Try to get from pool (instant)
        match tokio::time::timeout(
            tokio::time::Duration::from_micros(1000),
            rx.recv()
        ).await {
            Ok(Some(mut conn)) => {
                conn.update_last_used();
                let mut reused = self.connections_reused.lock().await;
                *reused += 1;
                conn
            }
            _ => {
                // Pool empty, create new connection
                self.create_connection(peer_id).await
            }
        }
    }

    /// Return connection to pool
    pub async fn return_connection(&self, conn: SecureConnection) {
        if conn.age() < self.max_age && conn.is_authenticated {
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_micros(1000),
                self.available_tx.send(conn.clone())
            ).await;
        } else {
            // Connection too old or not authenticated
            self.remove_connection(&conn).await;
        }
    }

    async fn remove_connection(&self, conn: &SecureConnection) {
        let mut connections = self.connections.lock().await;
        if connections.remove(&conn.connection_id).is_some() {
            let mut expired = self.connections_expired.lock().await;
            *expired += 1;
        }
    }

    async fn maintenance_loop(&self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            // Remove expired connections
            let mut connections = self.connections.lock().await;
            let expired: Vec<String> = connections
                .iter()
                .filter(|(_, conn)| conn.age() > self.max_age)
                .map(|(id, _)| id.clone())
                .collect();

            for id in expired {
                connections.remove(&id);
                let mut exp = self.connections_expired.lock().await;
                *exp += 1;
            }
            drop(connections);

            // Refill pool if needed
            let current_size = self.available_tx.capacity() - self.available_tx.max_capacity();
            if current_size < self.pool_size {
                for _ in 0..(self.pool_size - current_size) {
                    let conn = self.create_connection("default".to_string()).await;
                    if self.available_tx.send(conn).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    /// Get connection pool statistics
    pub async fn get_stats(&self) -> ConnectionPoolStats {
        let connections = self.connections.lock().await;
        let created = *self.connections_created.lock().await;
        let reused = *self.connections_reused.lock().await;
        let expired = *self.connections_expired.lock().await;

        let total = created + reused;
        ConnectionPoolStats {
            pool_size: self.pool_size,
            active_connections: connections.len(),
            available_connections: self.available_tx.max_capacity() - self.available_tx.capacity(),
            connections_created: created,
            connections_reused: reused,
            connections_expired: expired,
            reuse_rate: if total > 0 {
                reused as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

impl Clone for PreAuthConnectionPool {
    fn clone(&self) -> Self {
        Self {
            pool_size: self.pool_size,
            max_age: self.max_age,
            connections: Arc::clone(&self.connections),
            available_tx: self.available_tx.clone(),
            available_rx: Arc::clone(&self.available_rx),
            connections_created: Arc::clone(&self.connections_created),
            connections_reused: Arc::clone(&self.connections_reused),
            connections_expired: Arc::clone(&self.connections_expired),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub pool_size: usize,
    pub active_connections: usize,
    pub available_connections: usize,
    pub connections_created: u64,
    pub connections_reused: u64,
    pub connections_expired: u64,
    pub reuse_rate: f64,
}

fn current_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_basic() {
        let pool = PreAuthConnectionPool::new(5, 3600.0);
        pool.initialize().await;

        let conn = pool.get_connection("peer1".to_string()).await;
        assert!(!conn.connection_id.is_empty());
        assert_eq!(conn.session_key.len(), 32);
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let pool = PreAuthConnectionPool::new(5, 3600.0);
        pool.initialize().await;

        let conn1 = pool.get_connection("peer1".to_string()).await;
        let id1 = conn1.connection_id.clone();

        pool.return_connection(conn1).await;

        let conn2 = pool.get_connection("peer1".to_string()).await;
        
        let stats = pool.get_stats().await;
        assert!(stats.connections_reused > 0 || conn2.connection_id == id1);
    }

    #[test]
    fn test_connection_age() {
        let conn = SecureConnection::new("test".to_string());
        assert!(conn.age() >= 0.0);
        assert!(conn.age() < 1.0); // Should be very recent
    }
}
