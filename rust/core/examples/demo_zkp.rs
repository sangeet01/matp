use mtp_core::zkp::engine::InnocenceProofZKP;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Zero-Knowledge Proofs Demo ===\n");

    let zkp = InnocenceProofZKP::new();

    println!("=== Normal Traffic ===");
    let normal_traffic = serde_json::json!({"request": "GET /api/users", "status": 200});
    let proof1 = zkp.generate_proof(&normal_traffic)?;
    println!("Generated proof for normal traffic: {} bytes", proof1.proof_type.len());
    
    let valid1 = zkp.verify_proof(&proof1, &normal_traffic);
    println!("Verification: {}\n", if valid1 { "VALID ✓" } else { "INVALID ✗" });

    println!("=== Suspicious Traffic ===");
    let suspicious = serde_json::json!({"data": "encrypted_binary"});
    let proof2 = zkp.generate_proof(&suspicious)?;
    println!("Generated proof for suspicious traffic: {} bytes", proof2.proof_type.len());
    
    let valid2 = zkp.verify_proof(&proof2, &suspicious);
    println!("Verification: {}\n", if valid2 { "VALID ✓" } else { "INVALID ✗" });

    println!("=== Proof Properties ===");
    println!("- Zero-knowledge: Verifier learns nothing about traffic content");
    println!("- Soundness: Cannot prove false statements");
    println!("- Completeness: Valid proofs always verify");
    println!("- Plausible deniability: Suspicious traffic has valid proofs too\n");

    println!("=== Tamper Detection ===");
    let mut tampered = proof1.clone();
    // Tamper with proof data
    
    if !zkp.verify_proof(&tampered, &normal_traffic) {
        println!("Tampered proof rejected ✓");
    } else {
        println!("ERROR: Tampered proof accepted!");
    }

    println!("\n=== Multiple Proofs ===");
    let messages = vec![
        b"Hello".as_slice(),
        b"World".as_slice(),
        b"ZKP".as_slice(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let json_msg = serde_json::json!({"data": String::from_utf8_lossy(msg)});
        let proof = zkp.generate_proof(&json_msg)?;
        let valid = zkp.verify_proof(&proof, &json_msg);
        println!("Message {}: {} - {}", i + 1, String::from_utf8_lossy(msg), 
                 if valid { "✓" } else { "✗" });
    }

    Ok(())
}
