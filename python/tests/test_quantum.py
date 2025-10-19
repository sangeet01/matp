# -*- coding: utf-8 -*-
"""
Comprehensive test suite for quantum features.

Tests:
- Quantum cryptography (Kyber KEM, Dilithium signatures)
- PQ Fractal Bundles
- Adaptive Ratchet
- Integration scenarios
"""

import secrets
import time
import sys
from pathlib import Path

# Add parent directory to path to find matp package
sys.path.insert(0, str(Path(__file__).parent.parent))

from matp.crypto.quantum import get_quantum_crypto, QuantumCrypto
from matp.crypto.fractal import (
    FractalBundleGenerator,
    FractalRecoveryManager,
    serialize_bundle,
    deserialize_bundle
)
from matp.ratchet.adaptive import AdaptiveRatchet, QuantumTrigger


def test_quantum_kem():
    """Test Kyber KEM operations"""
    print("=" * 60)
    print("TEST: Quantum KEM (Kyber)")
    print("=" * 60)
    
    qc = get_quantum_crypto()
    
    # Generate keypair
    print("Generating Kyber keypair...")
    keypair = qc.generate_kem_keypair()
    assert len(keypair.public_key) > 0
    assert len(keypair.secret_key) > 0
    print(f" Public key: {len(keypair.public_key)} bytes")
    print(f" Secret key: {len(keypair.secret_key)} bytes")
    
    # Encapsulate
    print("\nEncapsulating shared secret...")
    kem_ct = qc.kem_encapsulate(keypair.public_key)
    assert len(kem_ct.ciphertext) > 0
    assert len(kem_ct.shared_secret) == 32
    print(f" Ciphertext: {len(kem_ct.ciphertext)} bytes")
    print(f" Shared secret: {len(kem_ct.shared_secret)} bytes")
    
    # Decapsulate
    print("\nDecapsulating...")
    shared_secret = qc.kem_decapsulate(keypair.secret_key, kem_ct.ciphertext)
    assert shared_secret == kem_ct.shared_secret
    print(f" Shared secrets match!")
    
    print("\n Quantum KEM test PASSED\n")


def test_quantum_signatures():
    """Test Dilithium signatures"""
    print("=" * 60)
    print("TEST: Quantum Signatures (Dilithium)")
    print("=" * 60)
    
    qc = get_quantum_crypto()
    
    # Generate keypair
    print("Generating Dilithium keypair...")
    keypair = qc.generate_sign_keypair()
    assert len(keypair.public_key) > 0
    assert len(keypair.secret_key) > 0
    print(f" Public key: {len(keypair.public_key)} bytes")
    print(f" Secret key: {len(keypair.secret_key)} bytes")
    
    # Sign message
    message = b"Quantum-secure message for signing"
    print(f"\nSigning message: {message}")
    signature = qc.sign(keypair.secret_key, message)
    assert len(signature) > 0
    print(f" Signature: {len(signature)} bytes")
    
    # Verify signature
    print("\nVerifying signature...")
    valid = qc.verify(keypair.public_key, message, signature)
    assert valid
    print(" Signature is valid!")
    
    # Test invalid signature
    print("\nTesting invalid signature...")
    invalid_sig = secrets.token_bytes(len(signature))
    valid = qc.verify(keypair.public_key, message, invalid_sig)
    assert not valid
    print(" Invalid signature rejected!")
    
    print("\n Quantum signatures test PASSED\n")


def test_fractal_bundles():
    """Test PQ Fractal Bundles"""
    print("=" * 60)
    print("TEST: PQ Fractal Bundles")
    print("=" * 60)
    
    # Generate bundle
    print("Generating fractal bundle...")
    chain_key = secrets.token_bytes(32)
    bundle = FractalBundleGenerator.generate_future_bundle(chain_key)
    
    assert len(bundle.classical) == 3
    assert all(len(k) == 32 for k in bundle.classical)
    assert len(bundle.quantum_seed) == 32
    print(f" Bundle has 3 classical keys + quantum seed")
    
    # Test recovery
    print("\nTesting recovery from bundle...")
    for i in range(3):
        recovered = FractalBundleGenerator.recover_from_bundle(bundle, i)
        assert recovered == bundle.classical[i]
        print(f" Recovery index {i} works")
    
    # Test catastrophic recovery
    print("\nTesting catastrophic recovery...")
    emergency_key = FractalBundleGenerator.catastrophic_recovery(bundle)
    assert len(emergency_key) == 32
    print(f" Emergency recovery key: {emergency_key.hex()[:32]}...")
    
    # Test serialization
    print("\nTesting serialization...")
    data = serialize_bundle(bundle)
    assert len(data) == 128
    bundle2 = deserialize_bundle(data)
    assert bundle.classical == bundle2.classical
    assert bundle.quantum_seed == bundle2.quantum_seed
    print(f" Serialization round-trip works")
    
    print("\n Fractal bundles test PASSED\n")


def test_recovery_manager():
    """Test fractal recovery manager"""
    print("=" * 60)
    print("TEST: Fractal Recovery Manager")
    print("=" * 60)
    
    manager = FractalRecoveryManager(max_bundles=5)
    
    # Store bundles
    print("Storing 10 bundles (max 5)...")
    for i in range(10):
        chain_key = secrets.token_bytes(32)
        bundle = FractalBundleGenerator.generate_future_bundle(chain_key)
        manager.store_bundle(i, bundle)
    
    assert len(manager.bundles) == 5
    print(f" Manager keeps only last 5 bundles")
    
    # Test recovery
    print("\nTesting recovery scenarios...")
    
    # Bundle from message 7 can recover 8, 9, 10
    recovered = manager.attempt_recovery(8)
    assert recovered is not None
    print(f" Can recover message 8 from bundle 7")
    
    recovered = manager.attempt_recovery(9)
    assert recovered is not None
    print(f" Can recover message 9 from bundle 7")
    
    # Message 4 is too old (bundles 5-9 stored)
    recovered = manager.attempt_recovery(4)
    assert recovered is None
    print(f" Cannot recover message 4 (too old)")
    
    print("\n Recovery manager test PASSED\n")


def test_adaptive_ratchet_basic():
    """Test basic adaptive ratchet"""
    print("=" * 60)
    print("TEST: Adaptive Ratchet (Basic)")
    print("=" * 60)
    
    # Initialize
    print("Initializing Alice and Bob...")
    shared_secret = secrets.token_bytes(32)
    alice = AdaptiveRatchet(shared_secret, is_initiator=True)
    bob = AdaptiveRatchet(shared_secret, is_initiator=False)
    
    # Classical mode
    print("\nTesting classical mode...")
    message = b"Hello from Alice in classical mode!"
    packet = alice.encrypt(message)
    assert packet["mode"] == "classical"
    print(f" Encrypted in classical mode")
    
    decrypted = bob.decrypt(packet)
    assert decrypted == message
    print(f" Decrypted successfully: {decrypted}")
    
    # Switch to quantum
    print("\nSwitching to quantum mode...")
    alice.trigger_quantum_mode(QuantumTrigger.MANUAL)
    bob.trigger_quantum_mode(QuantumTrigger.MANUAL)
    
    # Quantum mode
    print("\nTesting quantum mode...")
    message2 = b"Hello from Alice in quantum mode!"
    packet2 = alice.encrypt(message2)
    assert packet2["mode"] == "quantum"
    print(f" Encrypted in quantum mode")
    
    decrypted2 = bob.decrypt(packet2)
    assert decrypted2 == message2
    print(f" Decrypted successfully: {decrypted2}")
    
    # Check stats
    stats = alice.get_stats()
    print(f"\nAlice stats:")
    print(f"  Messages sent: {stats['messages_sent']}")
    print(f"  Quantum triggers: {stats['quantum_triggers']}")
    print(f"  Current mode: {stats['current_mode']}")
    
    print("\n Adaptive ratchet basic test PASSED\n")


def test_anomaly_detection():
    """Test network anomaly detection"""
    print("=" * 60)
    print("TEST: Network Anomaly Detection")
    print("=" * 60)
    
    ratchet = AdaptiveRatchet(secrets.token_bytes(32))
    
    # Normal conditions
    print("Testing normal network conditions...")
    anomaly = ratchet.detect_network_anomaly(latency_ms=50, packet_loss=0.01)
    assert not anomaly
    assert not ratchet.is_quantum_mode
    print(f" Normal conditions: no quantum trigger")
    print(f" Anomaly score: {ratchet.anomaly_score:.2f}")
    
    # Suspicious conditions
    print("\nTesting suspicious network conditions...")
    anomaly = ratchet.detect_network_anomaly(latency_ms=1500, packet_loss=0.15)
    print(f" High latency: 1500ms, Packet loss: 15%")
    print(f" Anomaly score: {ratchet.anomaly_score:.2f}")
    
    if ratchet.is_quantum_mode:
        print(f" Quantum mode triggered by anomaly!")
    
    print("\n Anomaly detection test PASSED\n")


def test_auto_quantum():
    """Test automatic quantum mode"""
    print("=" * 60)
    print("TEST: Auto-Quantum Mode")
    print("=" * 60)
    
    print("Creating ratchet with threshold=5...")
    ratchet = AdaptiveRatchet(
        secrets.token_bytes(32),
        quantum_threshold=5,
        enable_auto_quantum=True
    )
    
    # Send messages
    print("\nSending messages...")
    for i in range(6):
        packet = ratchet.encrypt(b"test message")
        mode = packet["mode"]
        print(f"  Message {i+1}: {mode} mode")
    
    assert ratchet.is_quantum_mode
    print(f"\n Auto-switched to quantum after threshold!")
    
    print("\n Auto-quantum test PASSED\n")


def test_integration_scenario():
    """Test realistic integration scenario"""
    print("=" * 60)
    print("TEST: Integration Scenario")
    print("=" * 60)
    
    print("Scenario: Alice and Bob exchange messages with recovery\n")
    
    # Setup
    shared_secret = secrets.token_bytes(32)
    alice = AdaptiveRatchet(shared_secret, is_initiator=True)
    bob = AdaptiveRatchet(shared_secret, is_initiator=False)
    
    alice_recovery = FractalRecoveryManager()
    bob_recovery = FractalRecoveryManager()
    
    # Exchange messages
    messages = [
        b"Message 1: Hello Bob!",
        b"Message 2: How are you?",
        b"Message 3: Quantum test",
    ]
    
    print("Phase 1: Classical messages")
    for i, msg in enumerate(messages):
        packet = alice.encrypt(msg)
        alice_recovery.store_bundle(i, packet["fractal_bundle"])
        
        decrypted = bob.decrypt(packet)
        bob_recovery.store_bundle(i, packet["fractal_bundle"])
        
        print(f"   Message {i+1} exchanged ({packet['mode']} mode)")
        assert decrypted == msg
    
    # Trigger quantum mode
    print("\nPhase 2: Switching to quantum mode")
    alice.trigger_quantum_mode(QuantumTrigger.MANUAL)
    bob.trigger_quantum_mode(QuantumTrigger.MANUAL)
    
    # More messages in quantum mode
    quantum_messages = [
        b"Message 4: Now quantum secure!",
        b"Message 5: Post-quantum crypto active",
    ]
    
    for i, msg in enumerate(quantum_messages, start=3):
        packet = alice.encrypt(msg)
        alice_recovery.store_bundle(i, packet["fractal_bundle"])
        
        decrypted = bob.decrypt(packet)
        bob_recovery.store_bundle(i, packet["fractal_bundle"])
        
        print(f"   Message {i+1} exchanged ({packet['mode']} mode)")
        assert decrypted == msg
    
    # Test recovery
    print("\nPhase 3: Testing recovery")
    recovered_key = alice_recovery.attempt_recovery(2)
    assert recovered_key is not None
    print(f"   Successfully recovered key for message 2")
    
    # Final stats
    print("\nFinal statistics:")
    alice_stats = alice.get_stats()
    print(f" Alice sent: {alice_stats['messages_sent']} messages")
    print(f" Current mode: {alice_stats['current_mode']}")
    print(f" Quantum triggers: {alice_stats['quantum_triggers']}")
    
    print("\n Integration scenario test PASSED\n")


def run_all_tests():
    """Run all quantum feature tests"""
    print("\n" + "=" * 60)
    print("MATRYOSHKA PROTOCOL - QUANTUM FEATURES TEST SUITE")
    print("=" * 60 + "\n")
    
    start_time = time.time()
    
    try:
        # Quantum crypto tests
        test_quantum_kem()
        test_quantum_signatures()
        
        # Fractal bundle tests
        test_fractal_bundles()
        test_recovery_manager()
        
        # Adaptive ratchet tests
        test_adaptive_ratchet_basic()
        test_anomaly_detection()
        test_auto_quantum()
        
        # Integration test
        test_integration_scenario()
        
        elapsed = time.time() - start_time
        
        print("=" * 60)
        print(f" ALL TESTS PASSED in {elapsed:.2f}s")
        print("=" * 60)
        print("\nProduction-grade quantum features ready! ")
        
    except AssertionError as e:
        print(f"\n TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n ERROR: {e}")
        raise


if __name__ == "__main__":
    run_all_tests()
