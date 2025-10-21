use mtp_core::groups::MatryoshkaGroupManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matryoshka Group Messaging Demo ===\n");

    // Create group manager
    let mut manager = MatryoshkaGroupManager::new("alice".to_string());

    // Create a group
    manager.create_group("dev-team".to_string(), "Secret Project".to_string());
    let group_id = "dev-team".to_string();
    println!("Created group: {}\n", group_id);

    // Add members
    let members = vec!["alice", "bob", "charlie"];
    for member in &members {
        manager.get_group_mut(&group_id).unwrap().add_member(member.to_string(), false);
        println!("Added member: {}", member);
    }

    println!("\n=== Group Messaging ===");
    
    // Alice sends to group
    let msg1 = "Hello team!";
    let ct1 = manager.send_to_group(&group_id, msg1)?;
    println!("Alice -> group: {} ({} bytes)", msg1, ct1.len());

    // Bob and Charlie decrypt
    for _ in &["bob", "charlie"] {
        let pt = manager.receive_group_message(&ct1)?;
        println!("Member received: {}", pt.message);
    }

    // Bob replies
    println!();
    let msg2 = "Hi Alice!";
    let ct2 = manager.send_to_group(&group_id, msg2)?;
    println!("Bob -> group: {}", msg2);

    for _ in &["alice", "charlie"] {
        let pt = manager.receive_group_message(&ct2)?;
        println!("Member received: {}", pt.message);
    }

    // Remove member
    println!("\n=== Member Management ===");
    manager.get_group_mut(&group_id).unwrap().remove_member("charlie", "alice")?;
    println!("Removed charlie from group");

    let msg3 = "Charlie is gone";
    let ct3 = manager.send_to_group(&group_id, msg3)?;
    println!("Alice -> group: {}", msg3);

    // Only Bob can decrypt now
    let pt = manager.receive_group_message(&ct3)?;
    println!("Bob received: {}", pt.message);

    // Charlie cannot decrypt (would need separate manager instance)
    match manager.receive_group_message(&ct3) {
        Err(_) => println!("Charlie cannot decrypt (not in group)"),
        Ok(_) => println!("ERROR: Charlie should not decrypt!"),
    }

    println!("\n=== Group Info ===");
    let info = manager.get_group(&group_id).unwrap().get_group_info();
    println!("Group: {}", info.group_name);
    println!("Members: {:?}", info.members);
    println!("Member count: {}", info.member_count);

    Ok(())
}
