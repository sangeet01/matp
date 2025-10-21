"""
Predictive Cryptography - Time-Based Key Rotation

Eliminates handshake delays through synchronized time-based key rotation.
Performance: 0ms handshake overhead
"""

import time
import hashlib
from typing import Optional
from dataclasses import dataclass


@dataclass
class TimeSlot:
    """Time slot for key rotation"""
    slot_id: int
    start_time: float
    end_time: float
    key: bytes


class PredictiveCrypto:
    """
    Predictive cryptography with time-based key rotation.
    
    Both parties pre-compute keys for future time slots, eliminating
    the need for key exchange during connection.
    
    Performance: 0ms handshake overhead
    """
    
    def __init__(self, master_secret: bytes, slot_duration: int = 300):
        """
        Initialize predictive crypto.
        
        Args:
            master_secret: 32-byte master secret (from initial handshake)
            slot_duration: Duration of each time slot in seconds (default: 5 minutes)
        """
        assert len(master_secret) == 32, "Master secret must be 32 bytes"
        
        self.master_secret = master_secret
        self.slot_duration = slot_duration
        self.key_cache: dict[int, bytes] = {}
        self.pregenerate_slots = 10
        
        # Initialize stats before pregeneration
        self.keys_generated = 0
        self.cache_hits = 0
        self.cache_misses = 0
        
        self._pregenerate_keys()
    
    def _get_current_slot_id(self) -> int:
        """Get current time slot ID"""
        return int(time.time() // self.slot_duration)
    
    def _derive_slot_key(self, slot_id: int) -> bytes:
        """Derive key for specific time slot"""
        info = f"slot-{slot_id}".encode()
        h = hashlib.sha256(self.master_secret + info).digest()
        self.keys_generated += 1
        return h
    
    def _pregenerate_keys(self):
        """Pre-generate keys for upcoming time slots"""
        current_slot = self._get_current_slot_id()
        
        for i in range(self.pregenerate_slots):
            slot_id = current_slot + i
            if slot_id not in self.key_cache:
                self.key_cache[slot_id] = self._derive_slot_key(slot_id)
        
        self._cleanup_old_keys(current_slot)
    
    def _cleanup_old_keys(self, current_slot: int):
        """Remove keys for past time slots"""
        old_slots = [s for s in self.key_cache.keys() if s < current_slot - 1]
        for slot in old_slots:
            del self.key_cache[slot]
    
    def get_current_key(self) -> bytes:
        """
        Get key for current time slot (0ms overhead).
        
        Returns:
            32-byte session key
        """
        slot_id = self._get_current_slot_id()
        
        if slot_id in self.key_cache:
            self.cache_hits += 1
            return self.key_cache[slot_id]
        
        self.cache_misses += 1
        key = self._derive_slot_key(slot_id)
        self.key_cache[slot_id] = key
        self._pregenerate_keys()
        
        return key
    
    def get_key_for_slot(self, slot_id: int) -> bytes:
        """Get key for specific time slot"""
        if slot_id in self.key_cache:
            return self.key_cache[slot_id]
        return self._derive_slot_key(slot_id)
    
    def get_current_slot_info(self) -> TimeSlot:
        """Get current time slot information"""
        slot_id = self._get_current_slot_id()
        start_time = slot_id * self.slot_duration
        end_time = start_time + self.slot_duration
        key = self.get_current_key()
        
        return TimeSlot(
            slot_id=slot_id,
            start_time=start_time,
            end_time=end_time,
            key=key
        )
    
    def verify_slot_sync(self, peer_slot_id: int) -> bool:
        """
        Verify time slot synchronization with peer.
        
        Args:
            peer_slot_id: Peer's current slot ID
            
        Returns:
            True if synchronized (within 1 slot)
        """
        current_slot = self._get_current_slot_id()
        return abs(current_slot - peer_slot_id) <= 1
    
    def rotate_master_secret(self, new_secret: bytes):
        """
        Rotate master secret (for periodic refresh).
        
        Args:
            new_secret: New 32-byte master secret
        """
        assert len(new_secret) == 32, "New secret must be 32 bytes"
        
        self.master_secret = new_secret
        self.key_cache.clear()
        self._pregenerate_keys()
    
    def get_stats(self) -> dict:
        """Get predictive crypto statistics"""
        return {
            "keys_generated": self.keys_generated,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0,
            "cached_keys": len(self.key_cache),
            "current_slot": self._get_current_slot_id()
        }
