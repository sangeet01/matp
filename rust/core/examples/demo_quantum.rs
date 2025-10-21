use mtp_core::quantum::kem::{generate_kem_keypair, kem_encapsulate, kem_decapsulate};
use mtp_core::quantum::signature::{generate_signature_keypair, sign_message, verify_signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Quantum Cryptography Demo ===\n");

    println!("=== Post-Quantum KEM (Key Encapsulation) ===");
    
    // Generate keypair
    let (public_key, secret_key) = generate_kem_keypair();
    println!("Generated KEM keypair");
    println!("Public key: {} bytes", public_key.len());
    println!("Secret key: {} bytes\n", secret_key.len());

    // Encapsulate - creates shared secret
    let (ciphertext, shared_secret1) = kem_encapsulate(&public_key)?;
    println!("Encapsulation:");
    println!("Ciphertext generated");
    println!("Shared secret: {} bytes\n", shared_secret1.len());

    // Decapsulate - recovers shared secret
    let shared_secret2 = kem_decapsulate(&secret_key, &ciphertext)?;
    println!("Decapsulation:");
    println!("Recovered secret: {} bytes", shared_secret2.len());
    println!("Secrets match: {}\n", shared_secret1 == shared_secret2);

    println!("=== Post-Quantum Signatures ===");
    
    // Generate signature keypair
    let (sign_pk, sign_sk) = generate_signature_keypair();
    println!("Generated signature keypair");
    println!("Public key: {} bytes", sign_pk.len());
    println!("Secret key: {} bytes\n", sign_sk.len());

    // Sign message
    let message = b"This message is quantum-resistant!";
    let signature = sign_message(&sign_sk, message)?;
    println!("Signed message: {}", String::from_utf8_lossy(message));
    println!("Signature generated\n");

    // Verify signature
    let valid = verify_signature(&sign_pk, message, &signature)?;
    println!("Signature verification: {}\n", if valid { "VALID ✓" } else { "INVALID ✗" });

    // Tamper detection
    println!("=== Tamper Detection ===");
    let tampered_msg = b"This message is quantum-resistant?";
    let valid_tampered = verify_signature(&sign_pk, tampered_msg, &signature)?;
    println!("Tampered message verification: {}", 
             if valid_tampered { "VALID (ERROR!)" } else { "INVALID ✓" });

    println!("Signature tampering would be detected\n");

    println!("=== Quantum Resistance ===");
    println!("- Resistant to Shor's algorithm (breaks RSA/ECC)");
    println!("- Resistant to Grover's algorithm (weakens symmetric crypto)");
    println!("- Based on lattice problems (hard for quantum computers)");
    println!("- Future-proof against quantum attacks");

    Ok(())
}
