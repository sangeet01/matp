//! Integration tests for quantum cryptography

use mtp_core::crypto::quantum::Quantum;

#[test]
fn test_kem_keypair_generation() {
    let result = Quantum::generate_kem_keys();
    assert!(result.is_ok());
    
    let (pk, sk) = result.unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_kem_encapsulation_decapsulation() {
    let (pk, sk) = Quantum::generate_kem_keys().unwrap();
    
    let (shared_secret1, ciphertext) = Quantum::kem_encapsulate(&pk).unwrap();
    let shared_secret2 = Quantum::kem_decapsulate(&sk, &ciphertext).unwrap();
    
    assert_eq!(shared_secret1, shared_secret2);
}

#[test]
fn test_signature_keypair_generation() {
    let result = Quantum::generate_sign_keys();
    assert!(result.is_ok());
    
    let (pk, sk) = result.unwrap();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_sign_verify() {
    let (pk, sk) = Quantum::generate_sign_keys().unwrap();
    let message = b"Test message";
    
    let signature = Quantum::sign(&sk, message).unwrap();
    let result = Quantum::verify(&pk, message, &signature);
    
    assert!(result.is_ok());
}

#[test]
fn test_sign_verify_wrong_message() {
    let (pk, sk) = Quantum::generate_sign_keys().unwrap();
    let message = b"Test message";
    let wrong_message = b"Wrong message";
    
    let signature = Quantum::sign(&sk, message).unwrap();
    let result = Quantum::verify(&pk, wrong_message, &signature);
    
    assert!(result.is_err());
}

#[test]
fn test_multiple_kem_operations() {
    let (pk, sk) = Quantum::generate_kem_keys().unwrap();
    
    for _ in 0..5 {
        let (ss1, ct) = Quantum::kem_encapsulate(&pk).unwrap();
        let ss2 = Quantum::kem_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }
}
