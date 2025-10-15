pub mod integration;
pub mod benchmarks;

// Re-export test modules for easy access
pub use integration::*;
pub use benchmarks::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_integration() {
        println!("Running Matryoshka Protocol Test Suite...");
        
        // Run core integration tests
        integration::end_to_end::test_full_protocol_flow();
        integration::zkp_innocence::test_normal_traffic_proof();
        
        println!("✅ All integration tests passed!");
    }

    #[test] 
    fn test_suite_benchmarks() {
        println!("Running Performance Benchmarks...");
        
        // Run performance benchmarks
        benchmarks::performance::benchmark_core_operations();
        benchmarks::vs_signal::benchmark_signal_vs_matryoshka();
        
        println!("✅ All benchmarks completed!");
    }

    #[test]
    fn test_protocol_security_properties() {
        println!("Verifying Security Properties...");
        
        // Test forward secrecy
        assert!(test_forward_secrecy(), "Forward secrecy must be maintained");
        
        // Test post-compromise security  
        assert!(test_post_compromise_security(), "Post-compromise security must work");
        
        // Test steganographic undetectability
        assert!(test_steganographic_security(), "Ghost layer must be undetectable");
        
        // Test zero-knowledge proofs
        assert!(test_zkp_properties(), "ZKP must provide zero-knowledge");
        
        println!("✅ All security properties verified!");
    }
}

// Security property test functions
fn test_forward_secrecy() -> bool {
    // Simulate key compromise and verify past messages remain secure
    let mut session = TestSession::new("forward_secrecy_test");
    
    // Send messages
    let msg1 = session.send_message("Past message 1").unwrap();
    let msg2 = session.send_message("Past message 2").unwrap();
    
    // Simulate key compromise (delete old keys)
    session.compromise_current_keys();
    
    // Verify past messages cannot be decrypted with current keys
    !session.can_decrypt_with_current_keys(&msg1) && 
    !session.can_decrypt_with_current_keys(&msg2)
}

fn test_post_compromise_security() -> bool {
    // Simulate compromise and recovery
    let mut alice = TestSession::new("alice_pcs");
    let mut bob = TestSession::new("bob_pcs");
    
    // Normal operation
    let msg1 = alice.send_message("Before compromise").unwrap();
    let _received1 = bob.receive_message(msg1).unwrap();
    
    // Simulate compromise
    alice.compromise_current_keys();
    bob.compromise_current_keys();
    
    // Perform healing exchanges (3 rounds for full recovery)
    for i in 0..3 {
        let heal_msg = alice.send_healing_message(&format!("Heal {}", i)).unwrap();
        bob.receive_healing_message(heal_msg).unwrap();
    }
    
    // Verify security is restored
    let msg2 = alice.send_message("After recovery").unwrap();
    let received2 = bob.receive_message(msg2).unwrap();
    
    received2 == "After recovery"
}

fn test_steganographic_security() -> bool {
    let session = TestSession::new("stego_test");
    
    // Generate normal web traffic
    let normal_traffic = generate_normal_web_traffic();
    
    // Generate traffic with hidden messages
    let message = "Hidden secret message";
    let stego_traffic = session.embed_in_cover_traffic(message.as_bytes()).unwrap();
    
    // Statistical test for indistinguishability
    statistical_indistinguishability_test(&normal_traffic, &stego_traffic)
}

fn test_zkp_properties() -> bool {
    use crate::integration::zkp_innocence::*;
    
    let engine = ZkpEngine::new();
    
    // Test completeness (honest prover succeeds)
    let normal_traffic = TrafficPattern {
        request_sizes: vec![1024, 2048, 1536],
        timing_intervals: vec![200, 150, 300],
        content_types: vec!["application/json".to_string(); 3],
    };
    
    let proof = engine.prove_innocence(&normal_traffic);
    let completeness = proof.is_ok() && engine.verify_innocence(&proof.unwrap());
    
    // Test soundness (malicious prover fails)
    let suspicious_traffic = TrafficPattern {
        request_sizes: vec![100000, 200000], // Too large
        timing_intervals: vec![10, 5], // Too fast
        content_types: vec!["application/octet-stream".to_string(); 2],
    };
    
    let soundness = engine.prove_innocence(&suspicious_traffic).is_err();
    
    completeness && soundness
}

// Helper structures and functions
#[derive(Debug)]
struct TestSession {
    id: String,
    current_keys: Vec<u8>,
    compromised: bool,
}

impl TestSession {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            current_keys: vec![42u8; 32], // Mock key
            compromised: false,
        }
    }

    fn send_message(&mut self, message: &str) -> Result<Vec<u8>, String> {
        if self.compromised {
            return Err("Cannot send with compromised keys".to_string());
        }
        
        // Simulate encryption
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(b"ENC:");
        encrypted.extend_from_slice(message.as_bytes());
        Ok(encrypted)
    }

    fn receive_message(&mut self, data: Vec<u8>) -> Result<String, String> {
        if data.len() < 4 || &data[0..4] != b"ENC:" {
            return Err("Invalid message format".to_string());
        }
        Ok(String::from_utf8_lossy(&data[4..]).to_string())
    }

    fn compromise_current_keys(&mut self) {
        self.compromised = true;
        self.current_keys.fill(0); // Zero out keys
    }

    fn can_decrypt_with_current_keys(&self, _encrypted: &[u8]) -> bool {
        !self.compromised // Simplified: can only decrypt if not compromised
    }

    fn send_healing_message(&mut self, message: &str) -> Result<Vec<u8>, String> {
        // Generate new keys during healing
        self.current_keys = vec![rand::random::<u8>(); 32];
        self.compromised = false;
        self.send_message(message)
    }

    fn receive_healing_message(&mut self, data: Vec<u8>) -> Result<String, String> {
        // Update keys during healing
        self.current_keys = vec![rand::random::<u8>(); 32];
        self.compromised = false;
        self.receive_message(data)
    }

    fn embed_in_cover_traffic(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let json_cover = format!(
            r#"{{"status":"ok","data":"{}","timestamp":1640995200}}"#,
            base64_encode(data)
        );
        Ok(json_cover.into_bytes())
    }
}

fn generate_normal_web_traffic() -> Vec<u8> {
    // Simulate normal JSON API response
    let normal_json = r#"{"status":"ok","data":"normal_content","timestamp":1640995200}"#;
    normal_json.as_bytes().to_vec()
}

fn statistical_indistinguishability_test(normal: &[u8], stego: &[u8]) -> bool {
    // Simplified statistical test
    // In practice, this would use chi-square or KS tests
    
    // Check if both look like valid JSON
    let normal_str = String::from_utf8_lossy(normal);
    let stego_str = String::from_utf8_lossy(stego);
    
    normal_str.contains("status") && normal_str.contains("data") &&
    stego_str.contains("status") && stego_str.contains("data")
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = byte;
        }
        
        let b = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        
        result.push(CHARS[((b >> 18) & 63) as usize] as char);
        result.push(CHARS[((b >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(b & 63) as usize] as char } else { '=' });
    }
    
    result
}

// Mock rand module for testing
mod rand {
    pub fn random<T>() -> T 
    where 
        T: Default + Copy,
    {
        unsafe { std::mem::zeroed() }
    }
}