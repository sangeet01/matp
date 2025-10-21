//! Integration tests for session management

use mtp_core::session::{MatryoshkaSession, SessionStats};
use mtp_core::ratchet::adaptive::QuantumTrigger;

#[test]
fn test_session_creation() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true);
    assert!(session.is_ok());
}

#[test]
fn test_session_encrypt_decrypt() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let mut alice = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    let mut bob = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, false).unwrap();
    
    let plaintext = b"Hello Bob!";
    let packet = alice.encrypt(plaintext, false).unwrap();
    let decrypted = bob.decrypt(&packet).unwrap();
    
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_session_send_receive_message() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let mut alice = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    let mut bob = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, false).unwrap();
    
    let msg_data = alice.send_message("Secret message", true, false).unwrap();
    let received = bob.receive_message(&msg_data).unwrap();
    
    assert_eq!(received, "Secret message");
}

#[test]
fn test_session_decoy_messages() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let mut alice = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    let mut bob = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, false).unwrap();
    
    // Send decoy message
    let plaintext = b"Decoy message";
    let packet = alice.encrypt(plaintext, true).unwrap();
    let decrypted = bob.decrypt(&packet).unwrap();
    
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_key_exchange() {
    let (alice_sk, alice_pk) = MatryoshkaSession::generate_keypair();
    let (bob_sk, bob_pk) = MatryoshkaSession::generate_keypair();
    
    let alice_shared = MatryoshkaSession::derive_shared_secret(&alice_sk, &bob_pk);
    let bob_shared = MatryoshkaSession::derive_shared_secret(&bob_sk, &alice_pk);
    
    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_session_compression() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    
    let data = b"test data to compress".repeat(10);
    let compressed = session.compress(&data).unwrap();
    let decompressed = session.decompress(&compressed).unwrap();
    
    assert!(compressed.len() < data.len());
    assert_eq!(data.as_slice(), decompressed.as_slice());
}

#[test]
fn test_session_statistics() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let mut session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    
    // Send some messages
    for _ in 0..5 {
        session.encrypt(b"test", false).unwrap();
    }
    
    let stats = session.get_stats();
    assert_eq!(stats.message_counter, 5);
    assert!(stats.bytes_sent > 0);
}

#[test]
fn test_quantum_trigger() {
    let shared_secret = [42u8; 32];
    let decoy_secret = [24u8; 32];
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    let mut session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true).unwrap();
    
    // Trigger quantum mode
    session.trigger_quantum_mode(QuantumTrigger::Manual);
    
    // Should still work after quantum trigger
    let packet = session.encrypt(b"test", false).unwrap();
    assert!(!packet.ciphertext.is_empty());
}

#[test]
fn test_multiple_sessions() {
    let (_, remote_pk) = MatryoshkaSession::generate_keypair();
    
    for i in 0..5 {
        let shared_secret = [i as u8; 32];
        let decoy_secret = [(i + 1) as u8; 32];
        
        let session = MatryoshkaSession::new(&shared_secret, &decoy_secret, remote_pk, true);
        assert!(session.is_ok());
    }
}
