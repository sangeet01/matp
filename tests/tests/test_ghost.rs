//! Integration tests for Ghost Mode steganography

use mtp_core::ghost::{
    GhostEngine, FastGhost, DeadDropProtocol, ServiceRotation, 
    TimingRandomizer, GhostStatistics, CompleteGhostMode
};
use mtp_core::ratchet::state::{MtpPacket, MessageHeader};
use mtp_core::crypto::fractal::PQFractalBundle;
use x25519_dalek::PublicKey as X25519PublicKey;

fn create_test_packet() -> MtpPacket {
    MtpPacket {
        header: MessageHeader {
            dh_ratchet_pub_key: X25519PublicKey::from([0u8; 32]),
            chain_msg_num: 0,
            dh_new_pub_key: None,
            decoy_flag: false,
            zkp_innocence: None,
        },
        ciphertext: vec![1, 2, 3, 4, 5],
        fractal_bundle: PQFractalBundle {
            classical: [[0u8; 32], [1u8; 32], [2u8; 32]],
            quantum_seed: [42u8; 32],
        },
    }
}

#[test]
fn test_ghost_engine_embed_extract() {
    let engine = GhostEngine::new();
    let packet = create_test_packet();
    
    let embedded = engine.embed(&packet).unwrap();
    let extracted = engine.extract(&embedded).unwrap();
    
    assert_eq!(packet.ciphertext, extracted.ciphertext);
}

#[test]
fn test_fast_ghost() {
    let key = [42u8; 32];
    let alice = FastGhost::new(&key);
    let bob = FastGhost::new(&key);
    
    let message = b"Secret message";
    let cover = alice.send(message).unwrap();
    let received = bob.receive(&cover).unwrap();
    
    assert_eq!(message.as_slice(), received.as_slice());
}

#[test]
fn test_fast_ghost_service_rotation() {
    let key = [42u8; 32];
    let ghost = FastGhost::new(&key);
    
    let cover1 = ghost.send(b"msg1").unwrap();
    let cover2 = ghost.send(b"msg2").unwrap();
    let cover3 = ghost.send(b"msg3").unwrap();
    
    // Should rotate through services
    assert!(cover1.get("bio").is_some());
    assert!(cover2.get("description").is_some());
    assert!(cover3.get("Instances").is_some());
}

#[test]
fn test_dead_drop_protocol() {
    let key = [42u8; 32];
    let mut protocol = DeadDropProtocol::new(key);
    
    let location = protocol.drop_message("secret_001", "The package is ready", "github").unwrap();
    let message = protocol.pickup_message(&location).unwrap();
    
    assert_eq!(message, "The package is ready");
}

#[test]
fn test_dead_drop_list() {
    let key = [42u8; 32];
    let mut protocol = DeadDropProtocol::new(key);
    
    protocol.drop_message("drop1", "msg1", "github").unwrap();
    protocol.drop_message("drop2", "msg2", "stripe").unwrap();
    protocol.drop_message("drop3", "msg3", "github").unwrap();
    
    let github_drops = protocol.list_drops(Some("github"));
    assert_eq!(github_drops.len(), 2);
    
    let all_drops = protocol.list_drops(None);
    assert_eq!(all_drops.len(), 3);
}

#[test]
fn test_service_rotation() {
    let key = [42u8; 32];
    let mut rotator = ServiceRotation::new(key);
    
    let (cover1, service1) = rotator.send_rotated("Message 1").unwrap();
    let (cover2, service2) = rotator.send_rotated("Message 2").unwrap();
    let (cover3, service3) = rotator.send_rotated("Message 3").unwrap();
    
    assert_eq!(service1, "github");
    assert_eq!(service2, "stripe");
    assert_eq!(service3, "aws");
    
    let msg1 = rotator.receive(&cover1, &service1).unwrap();
    assert_eq!(msg1, "Message 1");
}

#[test]
fn test_timing_randomizer() {
    let timer = TimingRandomizer::new(1.0);
    
    let delays: Vec<_> = (0..10)
        .map(|_| timer.generate_delay())
        .collect();
    
    for delay in delays {
        let secs = delay.as_secs_f64();
        assert!(secs >= 0.1 && secs <= 10.0);
    }
}

#[test]
fn test_ghost_statistics() {
    let mut stats = GhostStatistics::new();
    
    stats.messages_sent = 10;
    stats.real_traffic_sent = 90;
    
    assert_eq!(stats.total_traffic(), 100);
    assert_eq!(stats.hidden_ratio(), 0.1);
    assert!(stats.detection_probability() < 0.001);
}

#[test]
fn test_complete_ghost_mode() {
    let key = [42u8; 32];
    let mut ghost = CompleteGhostMode::new(key);
    
    let (cover, service) = ghost.send_invisible("Secret message").unwrap();
    
    assert!(cover.is_object());
    assert!(!service.is_empty());
    
    let stats = ghost.get_statistics();
    assert_eq!(stats.messages_sent, 1);
}

#[test]
fn test_complete_ghost_dead_drop() {
    let key = [42u8; 32];
    let mut ghost = CompleteGhostMode::new(key);
    
    let location = ghost.drop_message("drop1", "Secret", "github").unwrap();
    let message = ghost.pickup_message(&location).unwrap();
    
    assert_eq!(message, "Secret");
}
