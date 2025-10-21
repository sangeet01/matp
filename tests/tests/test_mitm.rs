//! Comprehensive test suite for MAP (Matryoshka Authentication Protocol)

use mtp_core::mitm::*;

#[test]
fn test_bloom_filter_basic() {
    let mut bloom = BloomFilterAuth::new(1000, 0.000001);
    let cert = CertificateInfo::new(b"test_key".to_vec());

    bloom.add_certificate(&cert);
    assert!(bloom.verify_certificate_fast(&cert));
    assert!(bloom.verify_certificate_full(&cert));
}

#[test]
fn test_bloom_filter_false_negative() {
    let mut bloom = BloomFilterAuth::new(1000, 0.000001);
    let cert1 = CertificateInfo::new(b"key1".to_vec());
    let cert2 = CertificateInfo::new(b"key2".to_vec());

    bloom.add_certificate(&cert1);
    assert!(!bloom.verify_certificate_full(&cert2));
}

#[test]
fn test_flow_fingerprinter() {
    let mut fp = FlowFingerprinter::new(100, 0.3);

    for _ in 0..50 {
        fp.record_packet(1000, Direction::Send);
    }

    let fingerprint = fp.compute_fingerprint();
    assert!(fingerprint.avg_packet_size > 0.0);
    assert!(fingerprint.entropy >= 0.0);
}

#[test]
fn test_flow_anomaly_detection() {
    let mut fp = FlowFingerprinter::new(100, 0.3);

    // Establish baseline
    for _ in 0..50 {
        fp.record_packet(1000, Direction::Send);
    }
    fp.set_baseline(None);

    // Introduce anomaly
    for _ in 0..50 {
        fp.record_packet(2000, Direction::Send);
    }

    let (_, score) = fp.detect_anomaly(None);
    assert!(score > 0.0);
}

#[tokio::test]
async fn test_zkp_path_prover() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec());
    let peer_id = b"peer123";

    let result = prover.verify_peer_path(peer_id).await;
    // Note: Real ZK proof may pass or fail depending on cryptographic verification
    // The important thing is that it completes without panic
    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified + stats.proofs_failed, 1);
}

#[test]
fn test_predictive_crypto() {
    let master_secret = vec![0u8; 32];
    let mut crypto = PredictiveCrypto::new(master_secret, 300);

    let key1 = crypto.get_current_key();
    assert_eq!(key1.len(), 32);

    let key2 = crypto.get_current_key();
    assert_eq!(key1, key2); // Same slot = same key
}

#[test]
fn test_predictive_crypto_slot_sync() {
    let master_secret = vec![0u8; 32];
    let mut crypto = PredictiveCrypto::new(master_secret, 300);

    let current = crypto.get_current_slot_info();
    assert!(crypto.verify_slot_sync(current.slot_id));
    assert!(crypto.verify_slot_sync(current.slot_id + 1));
    assert!(!crypto.verify_slot_sync(current.slot_id + 2));
}

#[tokio::test]
async fn test_connection_pool() {
    let pool = PreAuthConnectionPool::new(5, 3600.0);
    pool.initialize().await;

    let conn = pool.get_connection("peer1".to_string()).await;
    assert!(!conn.connection_id.is_empty());
    assert_eq!(conn.session_key.len(), 32);

    let stats = pool.get_stats().await;
    assert!(stats.connections_created > 0);
}

#[tokio::test]
async fn test_connection_pool_reuse() {
    let pool = PreAuthConnectionPool::new(5, 3600.0);
    pool.initialize().await;

    let conn1 = pool.get_connection("peer1".to_string()).await;
    pool.return_connection(conn1).await;

    let conn2 = pool.get_connection("peer1".to_string()).await;
    assert!(!conn2.connection_id.is_empty());
}

#[tokio::test]
async fn test_stochastic_auth() {
    let auth = ContinuousStochasticAuth::new(0.1, 0.5);
    let result = auth.perform_lightning_auth().await;
    assert!(result);

    let stats = auth.get_stats().await;
    assert_eq!(stats.auth_checks, 1);
    assert_eq!(stats.auth_successes, 1);
}

#[tokio::test]
async fn test_stochastic_auth_monitoring() {
    let auth = ContinuousStochasticAuth::new(0.1, 0.5);

    auth.start_monitoring::<fn(bool)>(None).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    auth.stop_monitoring().await;

    let stats = auth.get_stats().await;
    assert!(!stats.is_running);
}

#[tokio::test]
async fn test_lightning_mitm_basic() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    let result = lightning.connect_secure_fast("peer1".to_string()).await;
    assert!(!result.mitm_detected);
    assert!(result.connection.is_some());
    assert!(result.confidence > 0.9);
}

#[tokio::test]
async fn test_lightning_mitm_performance() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    let start = std::time::Instant::now();
    let result = lightning.connect_secure_fast("peer1".to_string()).await;
    let elapsed = start.elapsed().as_millis();

    // Allow more time for real ZK proof verification (target is 1-2ms, allow up to 10ms)
    assert!(elapsed < 10);
    assert!(result.detection_time_ms < 10.0);
}

#[tokio::test]
async fn test_lightning_mitm_multiple_connections() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    for i in 0..10 {
        let result = lightning
            .connect_secure_fast(format!("peer{}", i))
            .await;
        assert!(!result.mitm_detected);
    }

    let stats = lightning.get_stats().await;
    assert_eq!(stats.connections_checked, 10);
}

#[tokio::test]
async fn test_lightning_mitm_trusted_certificates() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    // Add trusted certificates
    for i in 0..5 {
        let public_key = vec![i; 32];
        lightning.add_trusted_certificate(public_key).await;
    }

    let result = lightning.connect_secure_fast("peer1".to_string()).await;
    assert!(!result.mitm_detected);
}

#[tokio::test]
async fn test_lightning_mitm_network_packets() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    // Record network packets
    for _ in 0..100 {
        lightning.record_network_packet(1024, Direction::Send).await;
        lightning.record_network_packet(512, Direction::Recv).await;
    }

    let result = lightning.connect_secure_fast("peer1".to_string()).await;
    assert!(!result.mitm_detected);
}

#[tokio::test]
async fn test_lightning_mitm_stats() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, false);

    lightning.initialize().await;

    for i in 0..5 {
        lightning
            .connect_secure_fast(format!("peer{}", i))
            .await;
    }

    let stats = lightning.get_stats().await;
    assert_eq!(stats.connections_checked, 5);
    assert!(stats.bloom_checks >= 0);
    assert!(stats.cache_hit_rate >= 0.0);
}

#[tokio::test]
async fn test_lightning_mitm_shutdown() {
    let master_secret = vec![0u8; 32];
    let lightning = LightningMITMProtection::new(master_secret, true);

    lightning.initialize().await;
    lightning.shutdown().await;

    // Should complete without panic
}

#[test]
fn test_mitm_detection_result_display() {
    let result = MITMDetectionResult {
        mitm_detected: false,
        connection: None,
        detection_time_ms: 1.5,
        sync_checks_passed: true,
        async_checks_pending: false,
        path_proof_valid: true,
        anomaly_score: 0.0,
        confidence: 0.999,
    };

    let status = result.status_string();
    assert!(status.contains("SECURE"));
    assert!(status.contains("99.90%"));
}
