use mtp_core::ghost::CompleteGhostMode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Ghost Mode Demo ===\n");

    let key = [42u8; 32];
    let mut ghost = CompleteGhostMode::new(key);

    println!("=== Dead Drop Protocol ===");
    let drop_id = ghost.drop_message("drop1", "secret_message", "github")?;
    println!("Created dead drop: {}", drop_id);
    println!("Message stored indirectly - no direct communication\n");

    let retrieved = ghost.pickup_message(&drop_id)?;
    println!("Retrieved: {}\n", retrieved);

    println!("=== Service Rotation ===");
    for i in 0..3 {
        let (carrier, service) = ghost.send_invisible("secret")?;
        println!("Round {}: Using {} ({} bytes)", i + 1, service, serde_json::to_string(&carrier)?.len());
    }

    println!("\n=== Statistics ===");
    let stats = ghost.get_statistics();
    println!("Messages sent: {}", stats.messages_sent);
    println!("Real traffic sent: {}", stats.real_traffic_sent);

    Ok(())
}
