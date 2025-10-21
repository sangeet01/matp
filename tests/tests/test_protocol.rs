//! Integration tests for MatryoshkaProtocol

use mtp_core::protocol::{MatryoshkaProtocol, GhostMessage, FutureBundle};

#[test]
fn test_protocol_basic_encryption() {
    let mut alice = MatryoshkaProtocol::new(Some(b"test_key_32_bytes_long_padding!!"));
    let mut bob = MatryoshkaProtocol::new(Some(b"test_key_32_bytes_long_padding!!"));
    
    let message = "Hello from Alice!";
    let encrypted = alice.encrypt(message.as_bytes()).unwrap();
    let decrypted = bob.decrypt(&encrypted).unwrap();
    
    assert_eq!(String::from_utf8(decrypted).unwrap(), message);
}

#[test]
fn test_protocol_send_receive() {
    let mut alice = MatryoshkaProtocol::new(Some(b"shared_secret"));
    let mut bob = MatryoshkaProtocol::new(Some(b"shared_secret"));
    
    let ghost_msg = alice.send_message("Secret message", true, false, false).unwrap();
    let received = bob.receive_message(&ghost_msg).unwrap();
    
    assert_eq!(received, "Secret message");
}

#[test]
fn test_protocol_with_quantum_decoys() {
    let mut protocol = MatryoshkaProtocol::new(None);
    
    let ghost_msg = protocol.send_message("Test", true, true, false).unwrap();
    
    assert!(ghost_msg.quantum_decoys.is_some());
    assert_eq!(ghost_msg.quantum_decoys.unwrap().len(), 3);
}

#[test]
fn test_protocol_with_innocence_proof() {
    let mut protocol = MatryoshkaProtocol::new(None);
    
    let ghost_msg = protocol.send_message("Test", true, false, true).unwrap();
    
    assert!(ghost_msg.innocence_proof.is_some());
}

#[test]
fn test_protocol_compression() {
    let protocol = MatryoshkaProtocol::new(None);
    let data = b"This is test data that should compress well. ".repeat(10);
    
    let compressed = protocol.compress(&data).unwrap();
    let decompressed = protocol.decompress(&compressed).unwrap();
    
    assert!(compressed.len() < data.len());
    assert_eq!(data.as_slice(), decompressed.as_slice());
}

#[test]
fn test_future_bundle() {
    let bundle = FutureBundle::new(None);
    
    assert_eq!(bundle.classical_keys.len(), 3);
    assert_eq!(bundle.quantum_seed.len(), 32);
    
    for i in 0..3 {
        assert!(bundle.get_recovery_key(i).is_some());
    }
    assert!(bundle.get_recovery_key(3).is_none());
}

#[test]
fn test_multiple_messages() {
    let mut alice = MatryoshkaProtocol::new(Some(b"key"));
    let mut bob = MatryoshkaProtocol::new(Some(b"key"));
    
    for i in 0..10 {
        let msg = format!("Message {}", i);
        let ghost = alice.send_message(&msg, true, false, false).unwrap();
        let received = bob.receive_message(&ghost).unwrap();
        assert_eq!(received, msg);
    }
}
