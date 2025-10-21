"""
Lightning MITM Protection for Matryoshka Protocol

Ultra-fast MITM detection and prevention with:
- Bloom filter certificate verification (0.1ms)
- Flow fingerprinting (1ms)
- Predictive cryptography (0ms handshake)
- Pre-authenticated connection pools
- Continuous stochastic authentication

Performance: ~1ms total overhead (50-100x faster than TLS)
"""

__version__ = "1.0.0"
__author__ = "Sangeet Sharma"

from .bloom_filter import BloomFilterAuth, CertificateInfo
from .flow_fingerprint import FlowFingerprinter, FlowMetrics, FlowFingerprint
from .predictive_crypto import PredictiveCrypto, TimeSlot
from .connection_pool import PreAuthConnectionPool, SecureConnection
from .stochastic_auth import ContinuousStochasticAuth
from .zkp_path import ZKPathProver
from .lightning import LightningMITMProtection, MITMDetectionResult




__all__ = [
    "BloomFilterAuth",
    "CertificateInfo",
    "FlowFingerprinter",
    "FlowMetrics",
    "FlowFingerprint",
    "PredictiveCrypto",
    "TimeSlot",
    "PreAuthConnectionPool",
    "SecureConnection",
    "ContinuousStochasticAuth",
    "ZKPathProver",
    "LightningMITMProtection",
    "MITMDetectionResult",
]
