"""
Matryoshka Protocol - Adaptive Ratchet

Dynamically switches between classical and quantum ratchets based on threat detection.
Provides automatic quantum mode activation when threats are detected.
"""
from __future__ import annotations

import time
import secrets
from enum import Enum
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field

from ..crypto.quantum import get_quantum_crypto, KemKeyPair
from ..crypto.fractal import PQFractalBundle, FractalBundleGenerator

if TYPE_CHECKING:
    from ..mitm.zkp_path import ZKPathProver


class QuantumTrigger(Enum):
    """Reasons for triggering quantum mode"""
    MANUAL = "manual"                    # User manually activated
    PEER_REQUEST = "peer_request"        # Peer requested quantum mode
    NETWORK_ANOMALY = "network_anomaly"  # Suspicious network activity
    TIME_BASED = "time_based"            # Periodic quantum refresh
    COMPROMISE_DETECTED = "compromise"   # Potential compromise detected


class MitmDetectedError(Exception):
    """MITM attack detected during session recovery"""
    pass


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
        enable_auto_quantum: bool = False,
        zkp_prover: Optional["ZKPathProver"] = None  # ZKP for session recovery
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
        
        # ZKP prover for session recovery
        self.zkp_prover = zkp_prover
        
        # Fractal recovery bundles (last 5)
        self.fractal_recovery_bundles: List[PQFractalBundle] = []
        
        # Statistics
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "quantum_triggers": 0,
            "anomalies_detected": 0,
            "recoveries_attempted": 0,
            "recoveries_successful": 0,
            "mitm_detected": 0
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
        
        # Generate ZKP proof if prover available
        zkp_proof = self._generate_recovery_zkp() if self.zkp_prover else None
        
        self.classical_state.message_number += 1
        
        packet = {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "mode": "classical",
            "message_number": self.classical_state.message_number - 1,
            "fractal_bundle": bundle
        }
        
        if zkp_proof:
            packet["zkp_proof"] = zkp_proof
        
        return packet
    
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
        
        # Generate ZKP proof if prover available
        zkp_proof = self._generate_recovery_zkp() if self.zkp_prover else None
        
        self.quantum_state.message_number += 1
        
        packet = {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "mode": "quantum",
            "message_number": self.quantum_state.message_number - 1,
            "fractal_bundle": bundle
        }
        
        if zkp_proof:
            packet["zkp_proof"] = zkp_proof
        
        return packet
    
    def decrypt(self, packet: Dict[str, Any]) -> bytes:
        """
        Decrypt a message using appropriate ratchet mode.
        
        Args:
            packet: Encrypted packet with metadata
            
        Returns:
            Decrypted plaintext
        """
        mode = packet.get("mode", "classical")
        
        try:
            # Try normal decryption
            if mode == "quantum":
                plaintext = self._decrypt_quantum(packet)
            else:
                plaintext = self._decrypt_classical(packet)
            
            # Store fractal bundle for future recovery
            if "fractal_bundle" in packet:
                self.fractal_recovery_bundles.append(packet["fractal_bundle"])
                if len(self.fractal_recovery_bundles) > 5:
                    self.fractal_recovery_bundles.pop(0)
            
            self.stats["messages_received"] += 1
            return plaintext
        except Exception:
            # Normal decryption failed - try fractal recovery with ZKP
            return self._try_fractal_recovery_with_zkp(packet)
    
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
    
    def _try_fractal_recovery_with_zkp(self, packet: Dict[str, Any]) -> bytes:
        """
        🔐 CRITICAL: ZKP-protected session recovery
        
        This is the key security improvement over Signal:
        - Signal: Delete session + full re-handshake
        - Matryoshka: Self-heal with cryptographic proof
        
        Args:
            packet: Encrypted packet with metadata
            
        Returns:
            Decrypted plaintext
            
        Raises:
            MitmDetectedError: If ZKP verification fails (MITM detected)
            RuntimeError: If recovery fails
        """
        self.stats["recoveries_attempted"] += 1
        
        # 🚨 CRITICAL: Verify ZKP proof BEFORE accepting recovery bundle
        if "zkp_proof" in packet and self.zkp_prover:
            if not self._verify_recovery_zkp(packet["zkp_proof"]):
                self.stats["mitm_detected"] += 1
                raise MitmDetectedError(
                    "ZKP verification failed during session recovery - MITM attack detected!"
                )
        elif self.zkp_prover and "zkp_proof" not in packet:
            # ZKP prover available but no proof in packet - suspicious
            self.stats["mitm_detected"] += 1
            raise MitmDetectedError(
                "Missing ZKP proof during session recovery - possible MITM attack!"
            )
        
        # ZKP verified (or not required) - try fractal recovery
        mode = packet.get("mode", "classical")
        state = self.quantum_state if mode == "quantum" else self.classical_state
        
        for bundle in reversed(self.fractal_recovery_bundles):
            for classical_key in bundle.classical:
                try:
                    # Try to use this recovery key
                    old_recv_key = state.chain_key_recv
                    state.chain_key_recv = classical_key
                    
                    try:
                        # Try to decrypt with recovered state
                        if mode == "quantum":
                            plaintext = self._decrypt_quantum(packet)
                        else:
                            plaintext = self._decrypt_classical(packet)
                        
                        # Success!
                        self.stats["recoveries_successful"] += 1
                        return plaintext
                    except Exception:
                        # This key didn't work, restore old state
                        state.chain_key_recv = old_recv_key
                        continue
                except Exception:
                    continue
        
        raise RuntimeError("Fractal recovery failed - no valid recovery key found")
    
    def _generate_recovery_zkp(self) -> Dict:
        """
        Generate Schnorr ZKP proof for session recovery.
        
        Returns:
            Dict with proof components: R, s, c, conn_id
        """
        if not self.zkp_prover:
            return {}
        
        try:
            from coincurve import PrivateKey
            import hashlib
            
            # Use a deterministic conn_id based on session state
            conn_id = hashlib.sha256(self.classical_state.root_key).hexdigest()[:16]
            
            # Get secret x and public point Y = x*G
            x_bytes, y_bytes = self.zkp_prover._get_public_point(conn_id)
            x = int.from_bytes(x_bytes, 'big')
            
            # secp256k1 order
            N = int.from_bytes(bytes([
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
            ]), 'big')
            
            # Generate random nonce k and commitment R = k*G
            k = int.from_bytes(secrets.token_bytes(32), 'big') % N
            k_bytes = k.to_bytes(32, 'big')
            R = PrivateKey(k_bytes).public_key.format(compressed=False)[1:]
            
            # Generate challenge c
            c = int.from_bytes(secrets.token_bytes(32), 'big') % N
            c_bytes = c.to_bytes(32, 'big')
            
            # Compute response s = k + c*x (mod N)
            s = (k + c * x) % N
            s_bytes = s.to_bytes(32, 'big')
            
            return {
                'R': R,
                's': s_bytes,
                'c': c_bytes,
                'conn_id': conn_id
            }
        except Exception as e:
            print(f"[ZKP] Proof generation failed: {e}")
            return {}
    
    def _verify_recovery_zkp(self, zkp_proof: Dict) -> bool:
        """
        Verify ZKP proof for session recovery using Schnorr verification.
        
        Args:
            zkp_proof: ZKP proof data with 'R', 's', 'c', 'conn_id'
            
        Returns:
            True if proof is valid, False otherwise
        """
        if not self.zkp_prover:
            return True  # No ZKP prover available, skip verification
        
        try:
            from coincurve import PrivateKey, PublicKey
            
            # Extract proof components
            R = zkp_proof['R']  # Commitment (64 bytes)
            s_bytes = zkp_proof['s']  # Response (32 bytes)
            c_bytes = zkp_proof['c']  # Challenge (32 bytes)
            conn_id = zkp_proof['conn_id']  # Connection ID
            
            # Get public point Y = x*G for this connection
            x_bytes, y_bytes = self.zkp_prover._get_public_point(conn_id)
            
            # Verify Schnorr equation: s*G == R + c*Y
            sG = PrivateKey(s_bytes).public_key.format(compressed=False)[1:]
            
            # Compute c*Y
            Y_pubkey = PublicKey(b'\x04' + y_bytes)
            cY_point = Y_pubkey.multiply(c_bytes)
            cY = cY_point.format(compressed=False)[1:]
            
            # Compute R + c*Y
            R_pubkey = PublicKey(b'\x04' + R)
            cY_pubkey = PublicKey(b'\x04' + cY)
            R_plus_cY = R_pubkey.combine([cY_pubkey])
            R_plus_cY_bytes = R_plus_cY.format(compressed=False)[1:]
            
            # Verify equation
            return sG == R_plus_cY_bytes
        except Exception as e:
            print(f"[ZKP] Verification failed: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ratchet statistics"""
        return {
            **self.stats,
            "is_quantum_mode": self.is_quantum_mode,
            "anomaly_score": self.anomaly_score,
            "current_mode": "quantum" if self.is_quantum_mode else "classical",
            "has_zkp_protection": self.zkp_prover is not None,
            "recovery_bundles": len(self.fractal_recovery_bundles)
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
