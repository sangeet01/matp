#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite for Fractal Group Ratchet

Comprehensive tests for group encryption functionality.
"""

import unittest
import secrets
import time
import sys
from pathlib import Path

# Add parent directory to path to find matp package
sys.path.insert(0, str(Path(__file__).parent.parent))

from matp.groups.fractal_ratchet import FractalGroupRatchet


class TestFractalGroupRatchet(unittest.TestCase):
    """Test cases for Fractal Group Ratchet."""
    
    def test_basic_encryption_decryption(self):
        """Test basic encrypt/decrypt cycle."""
        ratchet = FractalGroupRatchet()
        message = "Hello, World!"
        
        encrypted = ratchet.encrypt_for_group(message)
        decrypted = ratchet.decrypt_from_group(encrypted)
        
        self.assertEqual(message, decrypted)
    
    def test_group_communication(self):
        """Test multiple members can decrypt same message."""
        # Create group with shared seed
        group_seed = secrets.token_bytes(32)
        alice = FractalGroupRatchet(group_seed=group_seed)
        bob = FractalGroupRatchet(group_seed=group_seed)
        charlie = FractalGroupRatchet(group_seed=group_seed)
        
        # Alice sends message
        message = "Hello everyone!"
        encrypted = alice.encrypt_for_group(message)
        
        # Bob and Charlie decrypt
        bob_msg = bob.decrypt_from_group(encrypted)
        charlie_msg = charlie.decrypt_from_group(encrypted)
        
        self.assertEqual(message, bob_msg)
        self.assertEqual(message, charlie_msg)
    
    def test_forward_secrecy(self):
        """Test each message uses unique key."""
        ratchet = FractalGroupRatchet()
        
        msg1 = ratchet.encrypt_for_group("Message 1")
        msg2 = ratchet.encrypt_for_group("Message 2")
        msg3 = ratchet.encrypt_for_group("Message 3")
        
        # Different layers
        self.assertEqual(msg1["layer"], 0)
        self.assertEqual(msg2["layer"], 1)
        self.assertEqual(msg3["layer"], 2)
        
        # Different ciphertexts (different keys used)
        self.assertNotEqual(msg1["ciphertext"], msg2["ciphertext"])
        self.assertNotEqual(msg2["ciphertext"], msg3["ciphertext"])
    
    def test_wrong_seed_fails(self):
        """Test decryption fails with wrong seed."""
        alice = FractalGroupRatchet()
        bob = FractalGroupRatchet()  # Different seed
        
        encrypted = alice.encrypt_for_group("Secret")
        
        with self.assertRaises(ValueError):
            bob.decrypt_from_group(encrypted)
    
    def test_session_export_import(self):
        """Test exporting and importing session."""
        alice = FractalGroupRatchet()
        
        # Alice sends some messages
        alice.encrypt_for_group("Message 1")
        alice.encrypt_for_group("Message 2")
        
        # Export session
        session = alice.export_session(from_layer=alice.message_counter)
        
        # Bob imports session
        bob = FractalGroupRatchet()
        bob.import_session(session)
        
        # Bob can decrypt new messages
        msg = alice.encrypt_for_group("Message 3")
        decrypted = bob.decrypt_from_group(msg)
        
        self.assertEqual("Message 3", decrypted)
    
    def test_seed_rotation(self):
        """Test seed rotation for backward secrecy."""
        alice = FractalGroupRatchet()
        old_fingerprint = alice.get_fingerprint()
        
        # Send message with old seed
        old_msg = alice.encrypt_for_group("Old message")
        
        # Rotate seed
        new_seed = alice.rotate_seed()
        new_fingerprint = alice.get_fingerprint()
        
        # Fingerprints should be different
        self.assertNotEqual(old_fingerprint, new_fingerprint)
        
        # New message with new seed
        new_msg = alice.encrypt_for_group("New message")
        
        # Can decrypt new message
        decrypted_new = alice.decrypt_from_group(new_msg)
        self.assertEqual("New message", decrypted_new)
        
        # Cannot decrypt old message with new seed
        with self.assertRaises(ValueError):
            alice.decrypt_from_group(old_msg)
    
    def test_large_message(self):
        """Test encryption of large messages."""
        ratchet = FractalGroupRatchet()
        large_message = "A" * 10000  # 10KB message
        
        encrypted = ratchet.encrypt_for_group(large_message)
        decrypted = ratchet.decrypt_from_group(encrypted)
        
        self.assertEqual(large_message, decrypted)
    
    def test_unicode_message(self):
        """Test encryption of Unicode messages."""
        ratchet = FractalGroupRatchet()
        unicode_msg = "Hello 世界  مرحبا"
        
        encrypted = ratchet.encrypt_for_group(unicode_msg)
        decrypted = ratchet.decrypt_from_group(encrypted)
        
        self.assertEqual(unicode_msg, decrypted)
    
    def test_empty_message(self):
        """Test encryption of empty message."""
        ratchet = FractalGroupRatchet()
        
        encrypted = ratchet.encrypt_for_group("")
        decrypted = ratchet.decrypt_from_group(encrypted)
        
        self.assertEqual("", decrypted)
    
    def test_fingerprint_consistency(self):
        """Test fingerprint is consistent for same seed."""
        seed = secrets.token_bytes(32)
        
        ratchet1 = FractalGroupRatchet(group_seed=seed)
        ratchet2 = FractalGroupRatchet(group_seed=seed)
        
        self.assertEqual(ratchet1.get_fingerprint(), ratchet2.get_fingerprint())
    
    def test_invalid_seed_length(self):
        """Test invalid seed length raises error."""
        with self.assertRaises(ValueError):
            FractalGroupRatchet(group_seed=b"short")
    
    def test_corrupted_ciphertext(self):
        """Test corrupted ciphertext fails to decrypt."""
        ratchet = FractalGroupRatchet()
        encrypted = ratchet.encrypt_for_group("Message")
        
        # Corrupt ciphertext
        encrypted["ciphertext"] = "corrupted_data"
        
        with self.assertRaises(Exception):
            ratchet.decrypt_from_group(encrypted)
    
    def test_message_ordering(self):
        """Test messages can be decrypted in any order."""
        group_seed = secrets.token_bytes(32)
        alice = FractalGroupRatchet(group_seed=group_seed)
        bob = FractalGroupRatchet(group_seed=group_seed)
        
        # Alice sends multiple messages
        msg1 = alice.encrypt_for_group("First")
        msg2 = alice.encrypt_for_group("Second")
        msg3 = alice.encrypt_for_group("Third")
        
        # Bob receives out of order
        dec3 = bob.decrypt_from_group(msg3)
        dec1 = bob.decrypt_from_group(msg1)
        dec2 = bob.decrypt_from_group(msg2)
        
        self.assertEqual("Third", dec3)
        self.assertEqual("First", dec1)
        self.assertEqual("Second", dec2)
    
    def test_multiple_groups(self):
        """Test user can be in multiple groups."""
        # Alice in two groups
        group1_seed = secrets.token_bytes(32)
        group2_seed = secrets.token_bytes(32)
        
        alice_group1 = FractalGroupRatchet(group_seed=group1_seed)
        alice_group2 = FractalGroupRatchet(group_seed=group2_seed)
        
        # Send to different groups
        msg1 = alice_group1.encrypt_for_group("Group 1 message")
        msg2 = alice_group2.encrypt_for_group("Group 2 message")
        
        # Decrypt with correct group
        dec1 = alice_group1.decrypt_from_group(msg1)
        dec2 = alice_group2.decrypt_from_group(msg2)
        
        self.assertEqual("Group 1 message", dec1)
        self.assertEqual("Group 2 message", dec2)
        
        # Cannot decrypt with wrong group
        with self.assertRaises(ValueError):
            alice_group1.decrypt_from_group(msg2)


class TestPerformance(unittest.TestCase):
    """Performance tests for Fractal Group Ratchet."""
    
    def test_encryption_speed(self):
        """Test encryption performance."""
        ratchet = FractalGroupRatchet()
        message = "Test message"
        
        start = time.time()
        for _ in range(1000):
            ratchet.encrypt_for_group(message)
        elapsed = time.time() - start
        
        print(f"\n  Encrypted 1000 messages in {elapsed:.3f}s")
        print(f"  Average: {(elapsed/1000)*1000:.2f}ms per message")
        
        self.assertLess(elapsed, 5.0)  # Should be under 5 seconds
    
    def test_decryption_speed(self):
        """Test decryption performance."""
        ratchet = FractalGroupRatchet()
        messages = [ratchet.encrypt_for_group(f"Message {i}") for i in range(1000)]
        
        start = time.time()
        for msg in messages:
            ratchet.decrypt_from_group(msg)
        elapsed = time.time() - start
        
        print(f"\n  Decrypted 1000 messages in {elapsed:.3f}s")
        print(f"  Average: {(elapsed/1000)*1000:.2f}ms per message")
        
        self.assertLess(elapsed, 5.0)  # Should be under 5 seconds
    
    def test_group_scalability(self):
        """Test performance with many group members."""
        group_seed = secrets.token_bytes(32)
        
        # Create 100 group members
        members = [FractalGroupRatchet(group_seed=group_seed) for _ in range(100)]
        
        # One member sends message
        encrypted = members[0].encrypt_for_group("Broadcast message")
        
        # All members decrypt
        start = time.time()
        for member in members:
            member.decrypt_from_group(encrypted)
        elapsed = time.time() - start
        
        print(f"\n  100 members decrypted in {elapsed:.3f}s")
        print(f"  Average: {(elapsed/100)*1000:.2f}ms per member")
        
        self.assertLess(elapsed, 2.0)  # Should be under 2 seconds


def run_tests():
    """Run all tests with verbose output."""
    print("\n" + "="*60)
    print("FRACTAL GROUP RATCHET - TEST SUITE")
    print("="*60 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all tests
    suite.addTests(loader.loadTestsFromTestCase(TestFractalGroupRatchet))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n ALL TESTS PASSED!")
    else:
        print("\n SOME TESTS FAILED")
    
    print("="*60 + "\n")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
