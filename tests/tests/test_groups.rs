//! Integration tests for group messaging

use mtp_core::groups::{FractalGroupRatchet, MatryoshkaGroup, MatryoshkaGroupManager};

#[test]
fn test_fractal_group_ratchet() {
    let mut alice = FractalGroupRatchet::new(None);
    let seed = alice.get_group_seed();
    let bob = FractalGroupRatchet::new(Some(seed));
    
    assert_eq!(alice.get_fingerprint(), bob.get_fingerprint());
    
    let envelope = alice.encrypt_for_group("Hello group!").unwrap();
    let decrypted = bob.decrypt_from_group(&envelope).unwrap();
    
    assert_eq!(decrypted, "Hello group!");
}

#[test]
fn test_multiple_group_messages() {
    let mut alice = FractalGroupRatchet::new(None);
    let seed = alice.get_group_seed();
    let bob = FractalGroupRatchet::new(Some(seed));
    let charlie = FractalGroupRatchet::new(Some(seed));
    
    for i in 0..5 {
        let msg = format!("Message {}", i);
        let envelope = alice.encrypt_for_group(&msg).unwrap();
        
        let bob_msg = bob.decrypt_from_group(&envelope).unwrap();
        let charlie_msg = charlie.decrypt_from_group(&envelope).unwrap();
        
        assert_eq!(bob_msg, msg);
        assert_eq!(charlie_msg, msg);
    }
}

#[test]
fn test_session_export_import() {
    let mut alice = FractalGroupRatchet::new(None);
    
    // Send some messages
    for i in 0..3 {
        alice.encrypt_for_group(&format!("Message {}", i)).unwrap();
    }
    
    // Export session for new member
    let session = alice.export_session(alice.message_counter);
    
    let mut dave = FractalGroupRatchet::new(None);
    dave.import_session(&session).unwrap();
    
    assert_eq!(dave.get_fingerprint(), alice.get_fingerprint());
}

#[test]
fn test_seed_rotation() {
    let mut ratchet = FractalGroupRatchet::new(None);
    let old_fingerprint = ratchet.get_fingerprint().to_string();
    
    ratchet.rotate_seed();
    let new_fingerprint = ratchet.get_fingerprint();
    
    assert_ne!(old_fingerprint, new_fingerprint);
}

#[test]
fn test_group_creation() {
    let mut alice = MatryoshkaGroupManager::new("alice".to_string());
    let group = alice.create_group("test-group".to_string(), "Test Group".to_string());
    
    let info = group.get_group_info();
    assert_eq!(info.group_id, "test-group");
    assert_eq!(info.group_name, "Test Group");
    assert_eq!(info.creator, "alice");
    assert_eq!(info.members.len(), 1);
}

#[test]
fn test_group_messaging() {
    let mut alice = MatryoshkaGroupManager::new("alice".to_string());
    let mut bob = MatryoshkaGroupManager::new("bob".to_string());
    
    // Alice creates group
    alice.create_group("project-x".to_string(), "Secret Project".to_string());
    
    // Export invite
    let invite = alice.get_group("project-x").unwrap().export_invite(None);
    
    // Bob joins
    bob.join_group(&invite).unwrap();
    
    // Alice sends message
    let msg_data = alice.send_to_group("project-x", "Hello Bob!").unwrap();
    
    // Bob receives
    let received = bob.receive_group_message(&msg_data).unwrap();
    assert_eq!(received.message, "Hello Bob!");
    assert_eq!(received.sender, "alice");
}

#[test]
fn test_group_member_management() {
    let mut manager = MatryoshkaGroupManager::new("alice".to_string());
    let group = manager.create_group("test".to_string(), "Test".to_string());
    
    group.add_member("bob".to_string(), false);
    group.add_member("charlie".to_string(), true);
    
    let info = group.get_group_info();
    assert_eq!(info.members.len(), 3);
    assert_eq!(info.admins.len(), 2); // alice and charlie
}

#[test]
fn test_multiple_groups() {
    let mut alice = MatryoshkaGroupManager::new("alice".to_string());
    
    alice.create_group("group1".to_string(), "Group 1".to_string());
    alice.create_group("group2".to_string(), "Group 2".to_string());
    
    let groups = alice.get_all_groups();
    assert_eq!(groups.len(), 2);
}
