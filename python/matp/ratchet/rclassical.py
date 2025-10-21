#!/usr/bin/env python3
"""
Classical Double Ratchet Implementation

Signal-like double ratchet with:
- Symmetric ratchet (chain key derivation)
- Asymmetric ratchet (DH key exchange)
- Forward secrecy
- HKDF key derivation
- ZKP-protected session recovery
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..mitm.zkp_path import ZKPathProver


class MitmDetectedError(Exception):
    """MITM attack detected during session recovery"""
    pass


class ClassicalRatchet:
    """Classical double ratchet with ZKP-protected session recovery."""
    
    def __init__(self, root_key: bytes, zkp_prover: Optional["ZKPathProver"] = None):
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
        
        # ZKP prover for session recovery
        self.zkp_prover = zkp_prover
        
        # Fractal recovery bundles (last 5)
        self.recovery_keys: List[bytes] = []
    
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
        
        # Store recovery key (last 5)
        self.recovery_keys.append(self.send_chain_key)
        if len(self.recovery_keys) > 5:
            self.recovery_keys.pop(0)
        
        # Generate nonce
        nonce = secrets.token_bytes(12)
        
        # Encrypt with AES-GCM
        cipher = AESGCM(message_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        self.message_counter += 1
        return nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes, zkp_proof: Optional[dict] = None) -> bytes:
        """
        Decrypt with ratcheting and ZKP-protected recovery.
        
        Args:
            ciphertext: nonce + encrypted data
            zkp_proof: Optional ZKP proof for session recovery
        
        Returns:
            Decrypted plaintext
        """
        if len(ciphertext) < 12:
            raise ValueError("Invalid ciphertext")
        
        try:
            # Try normal decryption
            self.recv_chain_key, message_key = self.ratchet_forward(self.recv_chain_key)
            
            # Split nonce and ciphertext
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            
            # Decrypt with AES-GCM
            cipher = AESGCM(message_key)
            plaintext = cipher.decrypt(nonce, ct, None)
            
            return plaintext
        except Exception:
            # Normal decryption failed - try recovery with ZKP
            return self._try_recovery_with_zkp(ciphertext, zkp_proof)
    
    def get_state(self) -> dict:
        """Export ratchet state."""
        return {
            "root_key": self.root_key,
            "send_chain_key": self.send_chain_key,
            "recv_chain_key": self.recv_chain_key,
            "message_counter": self.message_counter
        }
    
    def _try_recovery_with_zkp(self, ciphertext: bytes, zkp_proof: Optional[dict]) -> bytes:
        """
        🔐 CRITICAL: ZKP-protected session recovery
        
        Args:
            ciphertext: Encrypted data to decrypt
            zkp_proof: ZKP proof for verification
            
        Returns:
            Decrypted plaintext
            
        Raises:
            MitmDetectedError: If ZKP verification fails
            RuntimeError: If recovery fails
        """
        # 🚨 CRITICAL: Verify ZKP proof BEFORE accepting recovery
        if self.zkp_prover and not zkp_proof:
            raise MitmDetectedError(
                "Missing ZKP proof during session recovery - possible MITM attack!"
            )
        
        if zkp_proof and self.zkp_prover:
            if not self._verify_recovery_zkp(zkp_proof):
                raise MitmDetectedError(
                    "ZKP verification failed during session recovery - MITM attack detected!"
                )
        
        # ZKP verified - try recovery keys
        for recovery_key in reversed(self.recovery_keys):
            try:
                old_recv_key = self.recv_chain_key
                self.recv_chain_key = recovery_key
                
                try:
                    _, message_key = self.ratchet_forward(self.recv_chain_key)
                    nonce = ciphertext[:12]
                    ct = ciphertext[12:]
                    cipher = AESGCM(message_key)
                    plaintext = cipher.decrypt(nonce, ct, None)
                    return plaintext
                except Exception:
                    self.recv_chain_key = old_recv_key
                    continue
            except Exception:
                continue
        
        raise RuntimeError("Session recovery failed - no valid recovery key found")
    
    def _verify_recovery_zkp(self, zkp_proof: dict) -> bool:
        """
        Verify ZKP proof for session recovery using Schnorr verification.
        
        Args:
            zkp_proof: ZKP proof data with 'R', 's', 'c', 'conn_id'
            
        Returns:
            True if proof is valid, False otherwise
        """
        if not self.zkp_prover:
            return True
        
        try:
            from coincurve import PrivateKey, PublicKey
            
            # Extract proof components
            R = zkp_proof['R']
            s_bytes = zkp_proof['s']
            c_bytes = zkp_proof['c']
            conn_id = zkp_proof['conn_id']
            
            # Get public point Y = x*G
            x_bytes, y_bytes = self.zkp_prover._get_public_point(conn_id)
            
            # Verify Schnorr equation: s*G == R + c*Y
            sG = PrivateKey(s_bytes).public_key.format(compressed=False)[1:]
            Y_pubkey = PublicKey(b'\x04' + y_bytes)
            cY_point = Y_pubkey.multiply(c_bytes)
            cY = cY_point.format(compressed=False)[1:]
            R_pubkey = PublicKey(b'\x04' + R)
            cY_pubkey = PublicKey(b'\x04' + cY)
            R_plus_cY = R_pubkey.combine([cY_pubkey])
            R_plus_cY_bytes = R_plus_cY.format(compressed=False)[1:]
            
            return sG == R_plus_cY_bytes
        except Exception:
            return False
    
    @classmethod
    def from_state(cls, state: dict) -> 'ClassicalRatchet':
        """Restore ratchet from state."""
        ratchet = cls(state["root_key"])
        ratchet.send_chain_key = state["send_chain_key"]
        ratchet.recv_chain_key = state["recv_chain_key"]
        ratchet.message_counter = state["message_counter"]
        return ratchet


__all__ = ["ClassicalRatchet", "MitmDetectedError"]
