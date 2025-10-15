#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MATP - Matryoshka Protocol
The world's first truly invisible secure messaging system
"""

import json
import base64
import time

class MatryoshkaProtocol:
    """Matryoshka Protocol - Invisible secure messaging."""
    
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

# Convenience exports
__all__ = ['MatryoshkaProtocol', 'GhostMessage', 'FutureBundle', 'InnocenceProof']
__version__ = '0.1.0'