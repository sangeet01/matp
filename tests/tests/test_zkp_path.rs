//! Test suite for Zero-Knowledge Proof of Path (ZKPP)

use mtp_core::mitm::ZKPathProver;

#[tokio::test]
async fn test_zkp_path_basic() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = b"peer123";

    let result = prover.verify_peer_path(peer_id).await.unwrap();
    assert!(result);

    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified, 1);
    assert_eq!(stats.proofs_failed, 0);
    assert_eq!(stats.success_rate, 1.0);
}

#[tokio::test]
async fn test_zkp_path_multiple_peers() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    
    for i in 0..5 {
        let peer_id = format!("peer{}", i);
        let result = prover.verify_peer_path(peer_id.as_bytes()).await.unwrap();
        assert!(result);
    }
    
    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified, 5);
    assert_eq!(stats.proofs_failed, 0);
    assert_eq!(stats.success_rate, 1.0);
}

#[tokio::test]
async fn test_zkp_path_caching() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = b"peer_cached";

    // First call - should compute and cache
    let result1 = prover.verify_peer_path(peer_id).await.unwrap();
    assert!(result1);

    // Second call - should use cache
    let result2 = prover.verify_peer_path(peer_id).await.unwrap();
    assert!(result2);

    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified, 2);
}

#[tokio::test]
async fn test_zkp_path_performance() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = b"peer_perf";

    let start = std::time::Instant::now();
    let result = prover.verify_peer_path(peer_id).await.unwrap();
    let elapsed = start.elapsed();

    assert!(result);
    // Should complete in under 2ms (including 0.1ms simulated network delay)
    assert!(elapsed.as_millis() < 2);
}

#[tokio::test]
async fn test_zkp_path_different_secrets() {
    let mut prover1 = ZKPathProver::new(b"secret1".to_vec()).unwrap();
    let mut prover2 = ZKPathProver::new(b"secret2".to_vec()).unwrap();
    
    let peer_id = b"peer_test";

    let result1 = prover1.verify_peer_path(peer_id).await.unwrap();
    let result2 = prover2.verify_peer_path(peer_id).await.unwrap();

    // Both should verify successfully (same peer, different secrets)
    assert!(result1);
    assert!(result2);
}

#[tokio::test]
async fn test_zkp_path_stats_tracking() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    
    // Verify multiple peers
    for i in 0..10 {
        let peer_id = format!("peer{}", i);
        let _ = prover.verify_peer_path(peer_id.as_bytes()).await;
    }
    
    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified + stats.proofs_failed, 10);
    assert!(stats.success_rate >= 0.0 && stats.success_rate <= 1.0);
}

#[tokio::test]
async fn test_zkp_path_concurrent_verifications() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    
    // Note: We need to verify sequentially due to &mut self requirement
    // This tests that the prover can handle rapid sequential calls
    for i in 0..5 {
        let peer_id = format!("peer{}", i);
        let result = prover.verify_peer_path(peer_id.as_bytes()).await.unwrap();
        assert!(result);
    }
    
    let stats = prover.get_stats();
    assert_eq!(stats.proofs_verified, 5);
}

#[tokio::test]
async fn test_zkp_path_empty_peer_id() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = b"";

    let result = prover.verify_peer_path(peer_id).await;
    // Should return error for empty peer_id
    assert!(result.is_err());
}

#[tokio::test]
async fn test_zkp_path_long_peer_id() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = vec![b'x'; 1000]; // 1KB peer ID

    let result = prover.verify_peer_path(&peer_id).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_zkp_path_unicode_peer_id() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    let peer_id = "peer_测试_🔒".as_bytes();

    let result = prover.verify_peer_path(peer_id).await.unwrap();
    assert!(result);
}

#[test]
fn test_input_validation() {
    // Empty master_secret should fail
    assert!(ZKPathProver::new(vec![]).is_err());
    
    // Valid master_secret should succeed
    let prover = ZKPathProver::new(b"test".to_vec());
    assert!(prover.is_ok());
}

#[tokio::test]
async fn test_cache_eviction() {
    let mut prover = ZKPathProver::new(b"test_secret".to_vec()).unwrap();
    
    // Fill cache beyond limit to trigger eviction
    for i in 0..10100 {
        let peer_id = format!("peer{}", i);
        let _ = prover.verify_peer_path(peer_id.as_bytes()).await;
    }
    
    // Should still work after eviction
    let result = prover.verify_peer_path(b"new_peer").await.unwrap();
    assert!(result);
}
