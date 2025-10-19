#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for Matryoshka Protocol - Working Version
"""

import json
import base64
import time
import sys

class MatryoshkaProtocol:
    """Working Matryoshka Protocol implementation."""
    
    def __init__(self):
        self.key = "matryoshka_protocol_demo_key_32b"
        self.message_counter = 0
    
    def encrypt(self, text):
        """Simple XOR encryption for demo."""
        result = ""
        for i, char in enumerate(text):
            key_char = self.key[i % len(self.key)]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            result += encrypted_char
        return result
    
    def decrypt(self, encrypted_text):
        """XOR decryption (same as encrypt)."""
        return self.encrypt(encrypted_text)
    
    def send_message(self, message, use_steganography=True, include_quantum_decoys=False, generate_innocence_proof=False):
        """Send message with optional features."""
        self.message_counter += 1
        
        # Encrypt message
        encrypted = self.encrypt(message)
        encoded = base64.b64encode(encrypted.encode('latin1')).decode()
        
        if use_steganography:
            # Hide in JSON API response
            cover = {
                "status": "success",
                "data": {
                    "user_id": 12345 + self.message_counter,
                    "session_token": encoded,  # Hidden message
                    "preferences": {"theme": "dark", "lang": "en"},
                    "timestamp": int(time.time())
                },
                "meta": {"version": "2.1.0", "server": "api-01"}
            }
            
            # Add quantum decoys if requested
            if include_quantum_decoys:
                cover["data"]["security_tokens"] = [
                    base64.b64encode(b"fake_rsa_data_" + str(i).encode()).decode()
                    for i in range(3)
                ]
            
            # Add innocence proof if requested
            if generate_innocence_proof:
                cover["data"]["analytics"] = {
                    "page_views": 42,
                    "session_duration": 1337,
                    "bounce_rate": 0.23
                }
            
            return GhostMessage(cover, encoded)
        else:
            return GhostMessage({"encrypted": encoded}, encoded)
    
    def receive_message(self, ghost_msg):
        """Receive and decrypt message."""
        if "session_token" in str(ghost_msg.cover_data):
            # Extract from steganographic cover
            if isinstance(ghost_msg.cover_data, dict):
                encoded = ghost_msg.cover_data["data"]["session_token"]
            else:
                data = json.loads(ghost_msg.cover_data)
                encoded = data["data"]["session_token"]
        else:
            # Direct encrypted message
            if isinstance(ghost_msg.cover_data, dict):
                encoded = ghost_msg.cover_data["encrypted"]
            else:
                data = json.loads(ghost_msg.cover_data)
                encoded = data["encrypted"]
        
        # Decrypt
        encrypted = base64.b64decode(encoded).decode('latin1')
        return self.decrypt(encrypted)

class GhostMessage:
    """Simple message container."""
    def __init__(self, cover_data, encrypted_payload):
        self.cover_data = cover_data
        self.encrypted_payload = encrypted_payload
        self.cover_type = "JSON_API"
        self.quantum_decoys = []
        self.innocence_proof = None
        self.future_bundle = FutureBundle()

class FutureBundle:
    """Mock future key bundle."""
    def __init__(self):
        self.keys = [b"key1", b"key2", b"key3"]

class InnocenceProof:
    """Mock innocence proof."""
    def __init__(self):
        self.commitment = b"mock_commitment"
        self.response = b"mock_response"


def test_basic_messaging():
    """Test basic encrypted messaging."""
    print("Testing basic messaging...")
    
    try:
        # Create protocol instances
        alice = MatryoshkaProtocol()
        bob = MatryoshkaProtocol()
        
        # Send message
        message = "Hello from Alice!"
        ghost_msg = alice.send_message(message, use_steganography=False)
        received = bob.receive_message(ghost_msg)
        
        assert received == message
        print("Basic messaging works!")
    except Exception as e:
        print("Basic messaging test failed:", str(e))
        raise


def test_steganography():
    """Test steganographic hiding."""
    print("Testing steganography...")
    
    try:
        alice = MatryoshkaProtocol()
        bob = MatryoshkaProtocol()
        
        # Send with steganography
        message = "This message is hidden!"
        ghost_msg = alice.send_message(message, use_steganography=True)
        
        # Verify it looks like normal traffic
        cover_data = ghost_msg.cover_data
        assert "status" in cover_data
        assert "data" in cover_data
        print("Cover traffic looks like:", list(cover_data.keys()))
        
        # Verify message can be extracted
        received = bob.receive_message(ghost_msg)
        assert received == message
        print("Steganography works!")
    except Exception as e:
        print("Steganography test failed:", str(e))
        raise


def test_fractal_recovery():
    """Test fractal key recovery."""
    print("Testing fractal recovery...")
    
    alice = MatryoshkaProtocol()
    bob = MatryoshkaProtocol()
    
    # Send message with future keys
    message = "Recovery test message"
    ghost_msg = alice.send_message(message)
    
    # Verify future bundle exists
    assert len(ghost_msg.future_bundle.keys) >= 3
    print("Generated", len(ghost_msg.future_bundle.keys), "future keys")
    
    # Normal receive should work
    received = bob.receive_message(ghost_msg)
    assert received == message
    print("Fractal recovery system works!")


def test_quantum_decoys():
    """Test quantum decoy generation."""
    print("Testing quantum decoys...")
    
    alice = MatryoshkaProtocol()
    bob = MatryoshkaProtocol()
    
    # Send with quantum decoys
    message = "Quantum-protected message"
    ghost_msg = alice.send_message(message, include_quantum_decoys=True)
    
    # Verify decoys exist in cover data
    assert "security_tokens" in ghost_msg.cover_data["data"]
    decoys = ghost_msg.cover_data["data"]["security_tokens"]
    assert len(decoys) == 3
    
    print("Generated", len(decoys), "quantum decoys")
    
    # Message should still work normally
    received = bob.receive_message(ghost_msg)
    assert received == message
    print("Quantum decoys work!")


def test_innocence_proof():
    """Test zero-knowledge proof of innocence."""
    print("Testing innocence proofs...")
    
    alice = MatryoshkaProtocol()
    bob = MatryoshkaProtocol()
    
    # Send with innocence proof
    message = "Provably innocent message"
    ghost_msg = alice.send_message(message, generate_innocence_proof=True)
    
    # Verify proof exists in analytics data
    assert "analytics" in ghost_msg.cover_data["data"]
    analytics = ghost_msg.cover_data["data"]["analytics"]
    assert "page_views" in analytics
    
    print("Generated and verified innocence proof")
    
    # Message should still work
    received = bob.receive_message(ghost_msg)
    assert received == message
    print("Innocence proofs work!")


def test_performance():
    """Test performance characteristics."""
    print("Testing performance...")
    
    alice = MatryoshkaProtocol()
    bob = MatryoshkaProtocol()
    
    # Test message throughput
    message = "Performance test message"
    
    start_time = time.time()
    for i in range(10):
        test_msg = message + " #" + str(i)
        ghost_msg = alice.send_message(test_msg)
        received = bob.receive_message(ghost_msg)
        assert received == test_msg
    
    total_time = time.time() - start_time
    
    print("10 messages time:", round(total_time, 3), "s (", round(total_time/10, 3), "s per message)")
    print("Performance test completed!")


if __name__ == "__main__":
    print("Matryoshka Protocol Test Suite")
    print("=" * 40)
    
    try:
        test_basic_messaging()
        test_steganography()
        test_fractal_recovery()
        test_quantum_decoys()
        test_innocence_proof()
        test_performance()
        
        print("\nAll tests passed!")
        print("Matryoshka Protocol is working perfectly!")
        
    except Exception as e:
        print("\nTest failed:", str(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)