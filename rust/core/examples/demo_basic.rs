use mtp_core::protocol::MatryoshkaProtocol;
use mtp_core::quantum::kem::generate_kem_keypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Basic Demo ===\n");

    // Alice and Bob create protocols
    let mut alice = MatryoshkaProtocol::new(Some(b"alice_secret_key"));
    let mut bob = MatryoshkaProtocol::new(Some(b"bob_secret_key"));

    // Alice sends message to Bob
    println!("Alice sending: 'Hello Bob!'");
    let ciphertext = alice.encrypt(b"Hello Bob!")?;
    println!("Ciphertext length: {} bytes\n", ciphertext.len());

    // Bob receives and decrypts
    let plaintext = bob.decrypt(&ciphertext)?;
    println!("Bob received: {}\n", String::from_utf8_lossy(&plaintext));

    // Quantum decoys
    println!("=== Quantum Decoys ===");
    let decoy = alice.encrypt(b"decoy_data")?;
    println!("Created decoy: {} bytes", decoy.len());
    println!("Looks like real ciphertext\n");

    // Multiple messages
    println!("=== Conversation ===");
    let messages = vec![
        ("alice", "bob", "How are you?"),
        ("bob", "alice", "I'm good, thanks!"),
        ("alice", "bob", "Great to hear!"),
    ];

    for (sender, receiver, msg) in messages {
        let (sender_proto, receiver_proto) = if sender == "alice" {
            (&mut alice, &mut bob)
        } else {
            (&mut bob, &mut alice)
        };
        
        let ct = sender_proto.encrypt(msg.as_bytes())?;
        let pt = receiver_proto.decrypt(&ct)?;
        println!("{} -> {}: {}", sender, receiver, String::from_utf8_lossy(&pt));
    }

    Ok(())
}
