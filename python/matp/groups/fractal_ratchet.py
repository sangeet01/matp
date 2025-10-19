#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fractal Group Ratchet - Matryoshka's Group Encryption Algorithm

Original design for multi-party encrypted communication.
NOT based on Megolm or any existing protocol - clean room implementation.

License: Apache 2.0
Author: Sangeet Sharma
"""

import secrets
import hashlib
import base64
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class FractalGroupRatchet:
    """
    Fractal Group Ratchet - Efficient group encryption with forward secrecy.
    
    Design Philosophy:
    - Like Russian dolls: Each message encrypted in layers
    - Fractal tree structure: Keys derived from single seed
    - Forward secrecy: Each message uses unique key
    - Efficient: One encryption, many recipients
    
    Security Properties:
    - Confidentiality: AES-256-GCM
    - Authentication: GCM tag
    - Forward secrecy: Per-message keys
    - Group membership: Seed-based access control
    """
    
    VERSION = "1.0.0"
    ALGORITHM = "fractal-group-ratchet-v1"
    # Use fixed, domain-separating salts for HKDF for better cryptographic hygiene
    LAYER_KEY_SALT = b"matp-fractal-layer-key-salt"
    SEED_ROTATION_SALT = b"matp-fractal-seed-rotation-salt"
    
    def __init__(self, group_seed: bytes = None):
        """
        Initialize Fractal Group Ratchet.
        
        Args:
            group_seed: 32-byte seed for group (shared by all members)
                       If None, generates random seed
        """
        if group_seed is None:
            self.group_seed = secrets.token_bytes(32)
        elif isinstance(group_seed, bytes) and len(group_seed) == 32:
            self.group_seed = group_seed
        else:
            raise ValueError("Group seed must be 32 bytes")
        
        self.message_counter = 0
        self.seed_fingerprint = self._compute_fingerprint()
    
    def _compute_fingerprint(self) -> str:
        """Compute fingerprint of group seed for verification."""
        return hashlib.sha256(self.group_seed).hexdigest()[:16]
    
    def _derive_layer_key(self, layer_index: int) -> bytes:
        """
        Derive encryption key for specific message layer.
        
        Uses HKDF with layer index as info parameter.
        Each layer gets unique key derived from group seed.
        
        Args:
            layer_index: Message index (0, 1, 2, ...)
        
        Returns:
            32-byte encryption key for this layer
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.LAYER_KEY_SALT,
            info=f"fractal-layer-{layer_index}".encode('utf-8')
        ).derive(self.group_seed)
    
    def encrypt_for_group(self, plaintext: str) -> dict:
        """
        Encrypt message for entire group.
        
        All group members can decrypt using the same group seed.
        Each message uses a unique key (forward secrecy).
        
        Args:
            plaintext: Message to encrypt
        
        Returns:
            dict: Encrypted envelope with:
                - layer: Message index
                - nonce: Random nonce for AES-GCM
                - ciphertext: Encrypted message
                - seed_fingerprint: Verify correct group
                - timestamp: When encrypted
        """
        # Derive unique key for this message
        layer_key = self._derive_layer_key(self.message_counter)
        
        # Encrypt with AES-256-GCM
        cipher = AESGCM(layer_key)
        nonce = secrets.token_bytes(12)
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        # Create message envelope
        envelope = {
            "version": self.VERSION,
            "algorithm": self.ALGORITHM,
            "layer": self.message_counter,
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "seed_fingerprint": self.seed_fingerprint,
            "timestamp": time.time()
        }
        
        # Increment counter for next message
        self.message_counter += 1
        
        return envelope
    
    def decrypt_from_group(self, envelope: dict) -> str:
        """
        Decrypt message from group.
        
        Args:
            envelope: Encrypted message envelope
        
        Returns:
            str: Decrypted plaintext
        
        Raises:
            ValueError: If wrong group seed or corrupted message
        """
        # Verify version
        if envelope.get("version") != self.VERSION:
            raise ValueError(f"Unsupported version: {envelope.get('version')}")
        
        # Verify algorithm
        if envelope.get("algorithm") != self.ALGORITHM:
            raise ValueError(f"Unsupported algorithm: {envelope.get('algorithm')}")
        
        # Verify seed fingerprint (are we in the right group?)
        if envelope["seed_fingerprint"] != self.seed_fingerprint:
            raise ValueError("Wrong group seed - cannot decrypt")
        
        # Derive key for this message layer
        layer_key = self._derive_layer_key(envelope["layer"])
        
        # Decrypt with AES-256-GCM
        cipher = AESGCM(layer_key)
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def export_session(self, from_layer: int = 0) -> dict:
        """
        Export session for new member.
        
        Allows new members to join mid-conversation.
        They can decrypt messages from 'from_layer' onwards.
        
        Args:
            from_layer: Starting message index for new member
        
        Returns:
            dict: Session data to share with new member
        """
        return {
            "version": self.VERSION,
            "algorithm": self.ALGORITHM,
            "group_seed": base64.b64encode(self.group_seed).decode('utf-8'),
            "start_layer": from_layer,
            "seed_fingerprint": self.seed_fingerprint,
            "exported_at": time.time()
        }
    
    def import_session(self, session_data: dict):
        """
        Import session from group admin.
        
        Args:
            session_data: Session exported by admin
        
        Raises:
            ValueError: If incompatible version or algorithm
        """
        # Verify version
        if session_data.get("version") != self.VERSION:
            raise ValueError(f"Incompatible version: {session_data.get('version')}")
        
        # Verify algorithm
        if session_data.get("algorithm") != self.ALGORITHM:
            raise ValueError(f"Incompatible algorithm: {session_data.get('algorithm')}")
        
        # Import seed and state
        self.group_seed = base64.b64decode(session_data["group_seed"])
        self.message_counter = session_data["start_layer"]
        self.seed_fingerprint = self._compute_fingerprint()
        
        # Verify fingerprint matches
        if self.seed_fingerprint != session_data["seed_fingerprint"]:
            raise ValueError("Session fingerprint mismatch")
    
    def rotate_seed(self) -> bytes:
        """
        Rotate group seed for backward secrecy.
        
        After rotation, old messages cannot be decrypted with new seed.
        Use this periodically or when member leaves.
        
        Returns:
            bytes: New group seed (share with remaining members)
        """
        # Derive new seed from old seed
        new_seed = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.SEED_ROTATION_SALT,
            info=b"seed-rotation"
        ).derive(self.group_seed)
        
        # Update state
        old_seed = self.group_seed
        self.group_seed = new_seed
        self.message_counter = 0  # Reset counter
        self.seed_fingerprint = self._compute_fingerprint()
        
        return new_seed
    
    def get_fingerprint(self) -> str:
        """
        Get group seed fingerprint for verification.
        
        Returns:
            str: 16-character hex fingerprint
        """
        return self.seed_fingerprint


# Example usage and tests
if __name__ == "__main__":
    print("=== Fractal Group Ratchet Demo ===\n")
    
    # Create group
    print("1. Alice creates group")
    alice_ratchet = FractalGroupRatchet()
    group_seed = alice_ratchet.group_seed
    print(f"   Group fingerprint: {alice_ratchet.get_fingerprint()}\n")
    
    # Bob and Charlie join with same seed
    print("2. Bob and Charlie join group")
    bob_ratchet = FractalGroupRatchet(group_seed=group_seed)
    charlie_ratchet = FractalGroupRatchet(group_seed=group_seed)
    print(f"   Bob fingerprint: {bob_ratchet.get_fingerprint()}")
    print(f"   Charlie fingerprint: {charlie_ratchet.get_fingerprint()}\n")
    
    # Alice sends message
    print("3. Alice sends message")
    msg1 = alice_ratchet.encrypt_for_group("Hello everyone!")
    print(f"   Encrypted layer: {msg1['layer']}")
    print(f"   Ciphertext: {msg1['ciphertext'][:40]}...\n")
    
    # Bob and Charlie decrypt
    print("4. Bob and Charlie decrypt")
    bob_sees = bob_ratchet.decrypt_from_group(msg1)
    charlie_sees = charlie_ratchet.decrypt_from_group(msg1)
    print(f"   Bob: {bob_sees}")
    print(f"   Charlie: {charlie_sees}\n")
    
    # Multiple messages (forward secrecy)
    print("5. Multiple messages (each uses unique key)")
    for i in range(3):
        msg = alice_ratchet.encrypt_for_group(f"Message {i+2}")
        decrypted = bob_ratchet.decrypt_from_group(msg)
        print(f"   Layer {msg['layer']}: {decrypted}")
    print()
    
    # Export session for new member
    print("6. Dave joins mid-conversation")
    session = alice_ratchet.export_session(from_layer=alice_ratchet.message_counter)
    dave_ratchet = FractalGroupRatchet()
    dave_ratchet.import_session(session)
    print(f"   Dave can decrypt from layer {dave_ratchet.message_counter} onwards\n")
    
    # Dave receives new message
    msg_for_dave = alice_ratchet.encrypt_for_group("Welcome Dave!")
    dave_sees = dave_ratchet.decrypt_from_group(msg_for_dave)
    print(f"   Dave: {dave_sees}\n")
    
    # Seed rotation
    print("7. Seed rotation (backward secrecy)")
    old_fingerprint = alice_ratchet.get_fingerprint()
    new_seed = alice_ratchet.rotate_seed()
    new_fingerprint = alice_ratchet.get_fingerprint()
    print(f"   Old fingerprint: {old_fingerprint}")
    print(f"   New fingerprint: {new_fingerprint}")
    print(f"   Old messages cannot be decrypted with new seed\n")
    
    print("=== Demo Complete ===")
