use mtp_core::zkp::{engine::InnocenceProofZKP, TrafficPattern};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Zero-Knowledge Proofs Demo ===\n");

    let zkp = InnocenceProofZKP::new();

    println!("=== Normal Traffic ===");
    let normal_traffic = TrafficPattern {
        request_sizes: vec![1024, 2048, 1536],
        timing_intervals: vec![200, 150, 300],
        content_types: vec!["application/json".to_string(), "text/html".to_string()],
    };
    let proof1 = zkp.generate_proof(&normal_traffic)?;
    println!("Generated proof for normal traffic");
    
    let valid1 = zkp.verify_proof(&proof1, &normal_traffic);
    println!("Verification: {}\n", if valid1 { "VALID ✓" } else { "INVALID ✗" });

    println!("=== Suspicious Traffic ===");
    let suspicious = TrafficPattern {
        request_sizes: vec![100000, 200000],
        timing_intervals: vec![10, 5],
        content_types: vec!["application/octet-stream".to_string()],
    };
    let proof2 = zkp.generate_proof(&suspicious)?;
    println!("Generated proof for suspicious traffic");
    
    let valid2 = zkp.verify_proof(&proof2, &suspicious);
    println!("Verification: {}\n", if valid2 { "VALID ✓" } else { "INVALID ✗" });

    println!("=== Proof Properties ===");
    println!("- Zero-knowledge: Verifier learns nothing about traffic content");
    println!("- Soundness: Cannot prove false statements");
    println!("- Completeness: Valid proofs always verify");
    println!("- Plausible deniability: Suspicious traffic has valid proofs too\n");

    println!("\n=== Multiple Proofs ===");
    for i in 0..3 {
        let traffic = TrafficPattern {
            request_sizes: vec![1000 + i * 100, 2000 + i * 100],
            timing_intervals: vec![100 + i * 10, 200 + i * 10],
            content_types: vec!["application/json".to_string()],
        };
        let proof = zkp.generate_proof(&traffic)?;
        let valid = zkp.verify_proof(&proof, &traffic);
        println!("Traffic pattern {}: {}", i + 1, if valid { "✓" } else { "✗" });
    }

    Ok(())
}
