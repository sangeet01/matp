"""
Matryoshka Protocol - PQ Fractal Bundles

Implements hybrid classical/quantum recovery bundles for post-compromise security.
Each message contains nested keys for future message recovery.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class PQFractalBundle:
    """
    Hybrid bundle containing both classical and quantum recovery keys.
    
    Structure (like Russian dolls):
    - classical[0]: Recovery key for message N+1
    - classical[1]: Recovery key for message N+2  
    - classical[2]: Recovery key for message N+3
    - quantum_seed: Catastrophic recovery seed (PQ-secure)
    """
    classical: List[bytes]  # 3 classical recovery keys
    quantum_seed: bytes     # 32-byte quantum recovery seed
    
    def __post_init__(self):
        assert len(self.classical) == 3, "Must have exactly 3 classical keys"
        assert all(len(k) == 32 for k in self.classical), "All keys must be 32 bytes"
        assert len(self.quantum_seed) == 32, "Quantum seed must be 32 bytes"


class FractalBundleGenerator:
    """
    Generates and recovers from PQ Fractal Bundles.
    
    Provides O(1) recovery from message loss with 3-step redundancy.
    """
    
    @staticmethod
    def hkdf_expand(key: bytes, info: bytes, length: int = 32) -> bytes:
        """
        HKDF-Expand for key derivation.
        
        Args:
            key: Input key material
            info: Context-specific info string
            length: Output length in bytes
            
        Returns:
            Derived key material
        """
        # HKDF-Expand using HMAC-SHA256
        t = b""
        okm = b""
        counter = 1
        
        while len(okm) < length:
            t = hmac.new(key, t + info + bytes([counter]), hashlib.sha256).digest()
            okm += t
            counter += 1
            
        return okm[:length]
    
    @staticmethod
    def generate_future_bundle(
        current_chain_key: bytes,
        kdf_salt_suffix: bytes = b""
    ) -> PQFractalBundle:
        """
        Generate a PQ Fractal Bundle from current chain key.
        
        This bundle allows recovery of future keys even if messages are lost.
        
        Args:
            current_chain_key: Current 32-byte chain key
            kdf_salt_suffix: Optional salt suffix for domain separation
            
        Returns:
            PQFractalBundle with 3 classical keys + quantum seed
        """
        assert len(current_chain_key) == 32, "Chain key must be 32 bytes"
        
        # Generate 3 classical recovery keys
        classical_keys = []
        for i in range(1, 4):
            info = b"mtp-fractal-classical-" + str(i).encode() + kdf_salt_suffix
            key = FractalBundleGenerator.hkdf_expand(current_chain_key, info)
            classical_keys.append(key)
        
        # Generate quantum recovery seed
        info_q = b"mtp-fractal-quantum-seed" + kdf_salt_suffix
        quantum_seed = FractalBundleGenerator.hkdf_expand(current_chain_key, info_q)
        
        return PQFractalBundle(
            classical=classical_keys,
            quantum_seed=quantum_seed
        )
    
    @staticmethod
    def recover_from_bundle(
        bundle: PQFractalBundle,
        recovery_index: int = 0
    ) -> bytes:
        """
        Recover a chain key from a fractal bundle.
        
        Args:
            bundle: PQFractalBundle to recover from
            recovery_index: Which classical key to use (0-2)
            
        Returns:
            Recovered 32-byte chain key
        """
        assert 0 <= recovery_index < 3, "Recovery index must be 0-2"
        return bundle.classical[recovery_index]
    
    @staticmethod
    def catastrophic_recovery(
        bundle: PQFractalBundle,
        context: bytes = b"emergency"
    ) -> bytes:
        """
        Perform catastrophic recovery using quantum seed.
        
        Used when all classical recovery paths fail.
        
        Args:
            bundle: PQFractalBundle with quantum seed
            context: Recovery context for domain separation
            
        Returns:
            Emergency recovery key
        """
        info = b"mtp-catastrophic-recovery-" + context
        return FractalBundleGenerator.hkdf_expand(bundle.quantum_seed, info)


class FractalRecoveryManager:
    """
    Manages fractal bundle storage and recovery logic.
    
    Tracks recent bundles for multi-step recovery.
    """
    
    def __init__(self, max_bundles: int = 10):
        """
        Initialize recovery manager.
        
        Args:
            max_bundles: Maximum number of bundles to keep in memory
        """
        self.bundles: List[Tuple[int, PQFractalBundle]] = []  # (message_num, bundle)
        self.max_bundles = max_bundles
    
    def store_bundle(self, message_num: int, bundle: PQFractalBundle):
        """
        Store a fractal bundle for future recovery.
        
        Args:
            message_num: Message number this bundle was sent with
            bundle: PQFractalBundle to store
        """
        self.bundles.append((message_num, bundle))
        
        # Keep only recent bundles
        if len(self.bundles) > self.max_bundles:
            self.bundles.pop(0)
    
    def find_recovery_bundle(
        self,
        target_message_num: int
    ) -> Optional[Tuple[PQFractalBundle, int]]:
        """
        Find a bundle that can recover the target message.
        
        Args:
            target_message_num: Message number we want to recover
            
        Returns:
            (bundle, recovery_index) if found, None otherwise
        """
        for msg_num, bundle in reversed(self.bundles):
            # Check if this bundle can recover target
            # Bundle from message N can recover N+1, N+2, N+3
            if msg_num < target_message_num <= msg_num + 3:
                recovery_index = target_message_num - msg_num - 1
                return (bundle, recovery_index)
        
        return None
    
    def attempt_recovery(self, target_message_num: int) -> Optional[bytes]:
        """
        Attempt to recover a chain key for target message.
        
        Args:
            target_message_num: Message number to recover
            
        Returns:
            Recovered chain key if successful, None otherwise
        """
        result = self.find_recovery_bundle(target_message_num)
        if result is None:
            return None
        
        bundle, recovery_index = result
        return FractalBundleGenerator.recover_from_bundle(bundle, recovery_index)
    
    def clear(self):
        """Clear all stored bundles"""
        self.bundles.clear()


# ============ UTILITY FUNCTIONS ============

def serialize_bundle(bundle: PQFractalBundle) -> bytes:
    """
    Serialize a PQFractalBundle to bytes.
    
    Format: classical1 || classical2 || classical3 || quantum_seed
    Total: 128 bytes (32*4)
    """
    return b"".join(bundle.classical) + bundle.quantum_seed


def deserialize_bundle(data: bytes) -> PQFractalBundle:
    """
    Deserialize bytes to PQFractalBundle.
    
    Args:
        data: 128 bytes of serialized bundle
        
    Returns:
        Reconstructed PQFractalBundle
    """
    assert len(data) == 128, "Bundle must be 128 bytes"
    
    classical = [
        data[0:32],
        data[32:64],
        data[64:96]
    ]
    quantum_seed = data[96:128]
    
    return PQFractalBundle(classical=classical, quantum_seed=quantum_seed)


def test_bundle_generation():
    """Test bundle generation and recovery"""
    # Generate test chain key
    chain_key = secrets.token_bytes(32)
    
    # Generate bundle
    bundle = FractalBundleGenerator.generate_future_bundle(chain_key)
    
    # Verify structure
    assert len(bundle.classical) == 3
    assert all(len(k) == 32 for k in bundle.classical)
    assert len(bundle.quantum_seed) == 32
    
    # Test recovery
    for i in range(3):
        recovered = FractalBundleGenerator.recover_from_bundle(bundle, i)
        assert len(recovered) == 32
        assert recovered == bundle.classical[i]
    
    # Test catastrophic recovery
    emergency_key = FractalBundleGenerator.catastrophic_recovery(bundle)
    assert len(emergency_key) == 32
    
    print("✓ Bundle generation test passed")


def test_recovery_manager():
    """Test recovery manager"""
    manager = FractalRecoveryManager(max_bundles=5)
    
    # Generate and store bundles
    for i in range(10):
        chain_key = secrets.token_bytes(32)
        bundle = FractalBundleGenerator.generate_future_bundle(chain_key)
        manager.store_bundle(i, bundle)
    
    # Should only keep last 5
    assert len(manager.bundles) == 5
    
    # Test recovery
    # Bundle from message 7 can recover messages 8, 9, 10
    recovered = manager.attempt_recovery(8)
    assert recovered is not None
    assert len(recovered) == 32
    
    # Message 4 is too old
    recovered = manager.attempt_recovery(4)
    assert recovered is None
    
    print("✓ Recovery manager test passed")


def test_serialization():
    """Test bundle serialization"""
    chain_key = secrets.token_bytes(32)
    bundle = FractalBundleGenerator.generate_future_bundle(chain_key)
    
    # Serialize
    data = serialize_bundle(bundle)
    assert len(data) == 128
    
    # Deserialize
    bundle2 = deserialize_bundle(data)
    assert bundle.classical == bundle2.classical
    assert bundle.quantum_seed == bundle2.quantum_seed
    
    print("✓ Serialization test passed")


if __name__ == "__main__":
    print("Running PQ Fractal Bundle tests...")
    test_bundle_generation()
    test_recovery_manager()
    test_serialization()
    print("\n✅ All tests passed!")
