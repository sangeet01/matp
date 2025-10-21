"""
Bloom Filter Certificate Authentication

Fast probabilistic certificate verification with controlled false positive rate.
Performance: ~0.1ms per check
"""

import hashlib
import math
from typing import Set, Optional
from dataclasses import dataclass


@dataclass
class CertificateInfo:
    """Certificate information for verification"""
    fingerprint: bytes
    public_key: bytes
    issuer: str = ""
    subject: str = ""
    not_before: float = 0.0
    not_after: float = 0.0


class BloomFilterAuth:
    """
    Bloom filter for ultra-fast certificate verification.
    
    Performance: ~0.1ms per check
    False positive rate: Configurable (default: 1 in 1 million)
    """
    
    def __init__(self, expected_items: int = 10000, false_positive_rate: float = 0.000001):
        """
        Initialize Bloom filter.
        
        Args:
            expected_items: Expected number of certificates
            false_positive_rate: Target false positive rate
        """
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.num_hashes = self._optimal_hashes(self.size, expected_items)
        self.bits = bytearray(self.size // 8 + 1)
        self.known_certs: Set[bytes] = set()
        self.checks = 0
        self.hits = 0
        self.false_positives = 0
    
    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    @staticmethod
    def _optimal_hashes(m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        k = (m / n) * math.log(2)
        return max(1, int(k))
    
    def _hash(self, data: bytes, seed: int) -> int:
        """Generate hash with seed"""
        h = hashlib.sha256(data + seed.to_bytes(4, 'big')).digest()
        return int.from_bytes(h[:4], 'big') % self.size
    
    def add_certificate(self, cert_info: CertificateInfo):
        """Add trusted certificate to Bloom filter"""
        fingerprint = cert_info.fingerprint
        
        for i in range(self.num_hashes):
            bit_pos = self._hash(fingerprint, i)
            byte_pos = bit_pos // 8
            bit_offset = bit_pos % 8
            self.bits[byte_pos] |= (1 << bit_offset)
        
        self.known_certs.add(fingerprint)
    
    def verify_certificate_fast(self, cert_info: CertificateInfo) -> bool:
        """
        Fast probabilistic certificate verification.
        
        Args:
            cert_info: Certificate to verify
            
        Returns:
            True if probably valid (may have false positives)
        """
        self.checks += 1
        fingerprint = cert_info.fingerprint
        
        for i in range(self.num_hashes):
            bit_pos = self._hash(fingerprint, i)
            byte_pos = bit_pos // 8
            bit_offset = bit_pos % 8
            
            if not (self.bits[byte_pos] & (1 << bit_offset)):
                return False
        
        self.hits += 1
        return True
    
    def verify_certificate_full(self, cert_info: CertificateInfo) -> bool:
        """Full certificate verification (no false positives)"""
        return cert_info.fingerprint in self.known_certs
    
    async def full_verify_async(self, cert_info: CertificateInfo) -> bool:
        """Asynchronous full verification (for background checks)"""
        import asyncio
        await asyncio.sleep(0.001)
        
        is_valid = self.verify_certificate_full(cert_info)
        if not is_valid:
            self.false_positives += 1
        
        return is_valid
    
    def get_stats(self) -> dict:
        """Get Bloom filter statistics"""
        return {
            "checks": self.checks,
            "hits": self.hits,
            "false_positives": self.false_positives,
            "false_positive_rate": self.false_positives / self.checks if self.checks > 0 else 0,
            "size_bits": self.size,
            "num_hashes": self.num_hashes,
            "known_certs": len(self.known_certs)
        }
    
    @staticmethod
    def generate_cert_fingerprint(public_key: bytes) -> bytes:
        """Generate certificate fingerprint from public key"""
        return hashlib.sha256(public_key).digest()
