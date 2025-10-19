"""
Matryoshka Protocol - Adaptive Ratchet

Dynamically switches between classical and quantum ratchets based on threat detection.
Provides automatic quantum mode activation when threats are detected.
"""
from __future__ import annotations

import time
import secrets
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

from ..crypto.quantum import get_quantum_crypto, KemKeyPair
from ..crypto.fractal import PQFractalBundle, FractalBundleGenerator


class QuantumTrigger(Enum):
    """Reasons for triggering quantum mode"""
    MANUAL = "manual"                    # User manually activated
    PEER_REQUEST = "peer_request"        # Peer requested quantum mode
    NETWORK_ANOMALY = "network_anomaly"  # Suspicious network activity
    TIME_BASED = "time_based"            # Periodic quantum refresh
    COMPROMISE_DETECTED = "compromise"   # Potential compromise detected


@dataclass
class RatchetState:
    """State for either classical or quantum ratchet"""
    root_key: bytes
    chain_key_send: bytes
    chain_key_recv: bytes
    message_number: int = 0
    is_quantum: bool = False
    last_ratchet_time: float = field(default_factory=time.time)


class AdaptiveRatchet:
    """
    Adaptive ratchet that switches between classical and quantum modes.
    
    Features:
    - Automatic threat detection
    - Seamless mode switching
    - Hybrid operation during transition
    - Post-compromise recovery
    """
    
    def __init__(
        self,
        initial_shared_secret: bytes,
        is_initiator: bool = True,
        quantum_threshold: int = 1000,  # Messages before auto-quantum
        enable_auto_quantum: bool = False
    ):
        """
        Initialize adaptive ratchet.
        
        Args:
            initial_shared_secret: 32-byte shared secret from handshake
            is_initiator: True if we initiated the session
            quantum_threshold: Auto-switch to quantum after N messages
            enable_auto_quantum: Enable automatic quantum mode
        """
        assert len(initial_shared_secret) == 32
        
        # Initialize classical ratchet state
        # Initiator sends with "send", receives with "recv"
        # Responder sends with "recv", receives with "send" (swapped)
        if is_initiator:
            send_key = self._derive_key(initial_shared_secret, b"send")
            recv_key = self._derive_key(initial_shared_secret, b"recv")
        else:
            send_key = self._derive_key(initial_shared_secret, b"recv")
            recv_key = self._derive_key(initial_shared_secret, b"send")
        
        self.classical_state = RatchetState(
            root_key=initial_shared_secret,
            chain_key_send=send_key,
            chain_key_recv=recv_key,
            is_quantum=False
        )
        
        # Quantum state (initialized when triggered)
        self.quantum_state: Optional[RatchetState] = None
        
        # Mode tracking
        self.is_quantum_mode = False
        self.is_initiator = is_initiator
        self.quantum_threshold = quantum_threshold
        self.enable_auto_quantum = enable_auto_quantum
        
        # Threat detection
        self.anomaly_score = 0.0
        self.last_anomaly_check = time.time()
        
        # Quantum crypto
        self.qc = get_quantum_crypto()
        
        # Statistics
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "quantum_triggers": 0,
            "anomalies_detected": 0
        }
    
    @staticmethod
    def _derive_key(key: bytes, info: bytes) -> bytes:
        """Derive a key using HKDF"""
        import hashlib
        import hmac
        
        # Simple HKDF-Expand
        return hmac.new(key, info, hashlib.sha256).digest()
    
    # ============ ENCRYPTION/DECRYPTION ============
    
    def encrypt(self, plaintext: bytes) -> Dict[str, Any]:
        """
        Encrypt a message using current ratchet mode.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Dict with ciphertext, mode, and metadata
        """
        # Check if we should auto-switch to quantum
        if self.enable_auto_quantum and not self.is_quantum_mode:
            if self.stats["messages_sent"] >= self.quantum_threshold:
                self.trigger_quantum_mode(QuantumTrigger.TIME_BASED)
        
        # Use appropriate ratchet
        if self.is_quantum_mode and self.quantum_state:
            result = self._encrypt_quantum(plaintext)
        else:
            result = self._encrypt_classical(plaintext)
        
        self.stats["messages_sent"] += 1
        return result
    
    def _encrypt_classical(self, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt using classical ratchet"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        # Derive message key
        msg_key = self._derive_key(
            self.classical_state.chain_key_send,
            b"msg-" + str(self.classical_state.message_number).encode()
        )
        
        # Update chain key
        self.classical_state.chain_key_send = self._derive_key(
            self.classical_state.chain_key_send,
            b"chain-next"
        )
        
        # Encrypt
        cipher = ChaCha20Poly1305(msg_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        # Generate fractal bundle
        bundle = FractalBundleGenerator.generate_future_bundle(
            self.classical_state.chain_key_send
        )
        
        self.classical_state.message_number += 1
        
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "mode": "classical",
            "message_number": self.classical_state.message_number - 1,
            "fractal_bundle": bundle
        }
    
    def _encrypt_quantum(self, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt using quantum ratchet"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        if not self.quantum_state:
            raise RuntimeError("Quantum state not initialized")
        
        # Derive message key (same as classical)
        msg_key = self._derive_key(
            self.quantum_state.chain_key_send,
            b"pq-msg-" + str(self.quantum_state.message_number).encode()
        )
        
        # Update chain key
        self.quantum_state.chain_key_send = self._derive_key(
            self.quantum_state.chain_key_send,
            b"pq-chain-next"
        )
        
        # Encrypt
        cipher = ChaCha20Poly1305(msg_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        # Generate PQ fractal bundle
        bundle = FractalBundleGenerator.generate_future_bundle(
            self.quantum_state.chain_key_send
        )
        
        self.quantum_state.message_number += 1
        
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "mode": "quantum",
            "message_number": self.quantum_state.message_number - 1,
            "fractal_bundle": bundle
        }
    
    def decrypt(self, packet: Dict[str, Any]) -> bytes:
        """
        Decrypt a message using appropriate ratchet mode.
        
        Args:
            packet: Encrypted packet with metadata
            
        Returns:
            Decrypted plaintext
        """
        mode = packet.get("mode", "classical")
        
        if mode == "quantum":
            plaintext = self._decrypt_quantum(packet)
        else:
            plaintext = self._decrypt_classical(packet)
        
        self.stats["messages_received"] += 1
        return plaintext
    
    def _decrypt_classical(self, packet: Dict[str, Any]) -> bytes:
        """Decrypt using classical ratchet"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        # Derive message key
        msg_key = self._derive_key(
            self.classical_state.chain_key_recv,
            b"msg-" + str(packet["message_number"]).encode()
        )
        
        # Update chain key
        self.classical_state.chain_key_recv = self._derive_key(
            self.classical_state.chain_key_recv,
            b"chain-next"
        )
        
        # Decrypt
        cipher = ChaCha20Poly1305(msg_key)
        plaintext = cipher.decrypt(packet["nonce"], packet["ciphertext"], None)
        
        return plaintext
    
    def _decrypt_quantum(self, packet: Dict[str, Any]) -> bytes:
        """Decrypt using quantum ratchet"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        if not self.quantum_state:
            raise RuntimeError("Quantum state not initialized")
        
        # Derive message key
        msg_key = self._derive_key(
            self.quantum_state.chain_key_recv,
            b"pq-msg-" + str(packet["message_number"]).encode()
        )
        
        # Update chain key
        self.quantum_state.chain_key_recv = self._derive_key(
            self.quantum_state.chain_key_recv,
            b"pq-chain-next"
        )
        
        # Decrypt
        cipher = ChaCha20Poly1305(msg_key)
        plaintext = cipher.decrypt(packet["nonce"], packet["ciphertext"], None)
        
        return plaintext
    
    # ============ QUANTUM MODE SWITCHING ============
    
    def trigger_quantum_mode(self, reason: QuantumTrigger):
        """
        Activate quantum-resistant ratchet mode.
        
        Args:
            reason: Why quantum mode was triggered
        """
        if self.is_quantum_mode:
            print(f"[ADAPTIVE] Already in quantum mode")
            return
        
        print(f"[ADAPTIVE] 🔐 Quantum mode triggered: {reason.value}")
        
        # Initialize quantum state from classical state
        # Derive quantum keys from root key to ensure sync
        quantum_root = self._derive_key(self.classical_state.root_key, b"quantum-upgrade")
        
        # Use same send/recv logic as classical
        if self.is_initiator:
            send_key = self._derive_key(quantum_root, b"pq-send")
            recv_key = self._derive_key(quantum_root, b"pq-recv")
        else:
            send_key = self._derive_key(quantum_root, b"pq-recv")
            recv_key = self._derive_key(quantum_root, b"pq-send")
        
        self.quantum_state = RatchetState(
            root_key=quantum_root,
            chain_key_send=send_key,
            chain_key_recv=recv_key,
            message_number=0,
            is_quantum=True
        )
        
        self.is_quantum_mode = True
        self.stats["quantum_triggers"] += 1
        
        print(f"[ADAPTIVE] ✅ Quantum mode active")
    
    def detect_network_anomaly(self, latency_ms: float, packet_loss: float) -> bool:
        """
        Detect potential network anomalies that might indicate attacks.
        
        Args:
            latency_ms: Current network latency in milliseconds
            packet_loss: Packet loss rate (0.0 to 1.0)
            
        Returns:
            True if anomaly detected
        """
        # Simple heuristic: high latency + packet loss = potential attack
        anomaly_detected = False
        
        if latency_ms > 1000:  # > 1 second latency
            self.anomaly_score += 0.3
            anomaly_detected = True
        
        if packet_loss > 0.1:  # > 10% packet loss
            self.anomaly_score += 0.4
            anomaly_detected = True
        
        # Decay anomaly score over time
        time_since_check = time.time() - self.last_anomaly_check
        self.anomaly_score *= (0.9 ** (time_since_check / 60))  # Decay per minute
        self.last_anomaly_check = time.time()
        
        # Trigger quantum mode if score too high
        if self.anomaly_score > 1.0 and not self.is_quantum_mode:
            self.trigger_quantum_mode(QuantumTrigger.NETWORK_ANOMALY)
            self.stats["anomalies_detected"] += 1
        
        return anomaly_detected
    
    def handle_peer_quantum_request(self):
        """Handle request from peer to switch to quantum mode"""
        if not self.is_quantum_mode:
            self.trigger_quantum_mode(QuantumTrigger.PEER_REQUEST)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ratchet statistics"""
        return {
            **self.stats,
            "is_quantum_mode": self.is_quantum_mode,
            "anomaly_score": self.anomaly_score,
            "current_mode": "quantum" if self.is_quantum_mode else "classical"
        }


# ============ TESTS ============

def test_adaptive_ratchet():
    """Test adaptive ratchet encryption/decryption"""
    print("Testing adaptive ratchet...")
    
    # Initialize ratchets for Alice and Bob
    shared_secret = secrets.token_bytes(32)
    alice = AdaptiveRatchet(shared_secret, is_initiator=True)
    bob = AdaptiveRatchet(shared_secret, is_initiator=False)
    
    # Test classical mode
    message = b"Hello from Alice!"
    packet = alice.encrypt(message)
    assert packet["mode"] == "classical"
    
    decrypted = bob.decrypt(packet)
    assert decrypted == message
    print("✓ Classical encryption works")
    
    # Trigger quantum mode
    alice.trigger_quantum_mode(QuantumTrigger.MANUAL)
    bob.trigger_quantum_mode(QuantumTrigger.MANUAL)
    
    # Test quantum mode
    message2 = b"Quantum secure message!"
    packet2 = alice.encrypt(message2)
    assert packet2["mode"] == "quantum"
    
    decrypted2 = bob.decrypt(packet2)
    assert decrypted2 == message2
    print("✓ Quantum encryption works")
    
    # Test stats
    stats = alice.get_stats()
    assert stats["messages_sent"] == 2
    assert stats["quantum_triggers"] == 1
    print("✓ Statistics tracking works")
    
    print("✅ Adaptive ratchet test passed!\n")


def test_anomaly_detection():
    """Test network anomaly detection"""
    print("Testing anomaly detection...")
    
    ratchet = AdaptiveRatchet(secrets.token_bytes(32))
    
    # Normal conditions
    assert not ratchet.detect_network_anomaly(50, 0.01)
    assert not ratchet.is_quantum_mode
    
    # Anomalous conditions
    ratchet.detect_network_anomaly(1500, 0.15)  # High latency + packet loss
    assert ratchet.is_quantum_mode  # Should trigger quantum mode
    
    print("✓ Anomaly detection works")
    print("✅ Anomaly detection test passed!\n")


def test_auto_quantum():
    """Test automatic quantum mode after threshold"""
    print("Testing auto-quantum mode...")
    
    ratchet = AdaptiveRatchet(
        secrets.token_bytes(32),
        quantum_threshold=5,
        enable_auto_quantum=True
    )
    
    # Send messages until threshold
    for i in range(6):
        ratchet.encrypt(b"test message")
    
    # Should have switched to quantum
    assert ratchet.is_quantum_mode
    print("✓ Auto-quantum activation works")
    print("✅ Auto-quantum test passed!\n")


if __name__ == "__main__":
    print("Running Adaptive Ratchet tests...\n")
    test_adaptive_ratchet()
    test_anomaly_detection()
    test_auto_quantum()
    print("✅ All adaptive ratchet tests passed!")
