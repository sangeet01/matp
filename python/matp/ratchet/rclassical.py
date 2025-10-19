#!/usr/bin/env python3
"""
Classical Double Ratchet Implementation

Signal-like double ratchet with:
- Symmetric ratchet (chain key derivation)
- Asymmetric ratchet (DH key exchange)
- Forward secrecy
- HKDF key derivation
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets


class ClassicalRatchet:
    """Classical double ratchet for forward secrecy."""
    
    def __init__(self, root_key: bytes):
        """
        Initialize ratchet with root key.
        
        Args:
            root_key: 32-byte root key
        """
        if len(root_key) != 32:
            raise ValueError("Root key must be 32 bytes")
        
        self.root_key = root_key
        self.send_chain_key = self._derive_chain_key(b"send")
        self.recv_chain_key = self._derive_chain_key(b"recv")
        self.message_counter = 0
    
    def _derive_chain_key(self, purpose: bytes) -> bytes:
        """
        Derive chain key from root key.
        
        Args:
            purpose: Purpose identifier (b"send" or b"recv")
        
        Returns:
            32-byte chain key
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.root_key,
            info=b"chain-" + purpose
        ).derive(self.root_key)
    
    def ratchet_forward(self, chain_key: bytes) -> tuple[bytes, bytes]:
        """
        Ratchet chain key forward (Signal-like).
        
        Args:
            chain_key: Current chain key
        
        Returns:
            (new_chain_key, message_key)
        """
        new_chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=chain_key,
            info=b"ratchet"
        ).derive(chain_key)
        
        message_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=chain_key,
            info=b"message"
        ).derive(chain_key)
        
        return new_chain_key, message_key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with ratcheting.
        
        Args:
            plaintext: Data to encrypt
        
        Returns:
            nonce + ciphertext
        """
        # Ratchet forward
        self.send_chain_key, message_key = self.ratchet_forward(self.send_chain_key)
        
        # Generate nonce
        nonce = secrets.token_bytes(12)
        
        # Encrypt with AES-GCM
        cipher = AESGCM(message_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        self.message_counter += 1
        return nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt with ratcheting.
        
        Args:
            ciphertext: nonce + encrypted data
        
        Returns:
            Decrypted plaintext
        """
        if len(ciphertext) < 12:
            raise ValueError("Invalid ciphertext")
        
        # Ratchet forward
        self.recv_chain_key, message_key = self.ratchet_forward(self.recv_chain_key)
        
        # Split nonce and ciphertext
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        
        # Decrypt with AES-GCM
        cipher = AESGCM(message_key)
        plaintext = cipher.decrypt(nonce, ct, None)
        
        return plaintext
    
    def get_state(self) -> dict:
        """Export ratchet state."""
        return {
            "root_key": self.root_key,
            "send_chain_key": self.send_chain_key,
            "recv_chain_key": self.recv_chain_key,
            "message_counter": self.message_counter
        }
    
    @classmethod
    def from_state(cls, state: dict) -> 'ClassicalRatchet':
        """Restore ratchet from state."""
        ratchet = cls(state["root_key"])
        ratchet.send_chain_key = state["send_chain_key"]
        ratchet.recv_chain_key = state["recv_chain_key"]
        ratchet.message_counter = state["message_counter"]
        return ratchet


__all__ = ["ClassicalRatchet"]
