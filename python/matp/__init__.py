"""
Matryoshka Protocol (MATP) - Invisible Secure Messaging

Production-grade implementation with:
- Classical crypto (X25519, Ed25519, AES-256-GCM)
- Post-quantum crypto (Kyber-512, Dilithium-2)
- Ghost steganography
- Fractal Group Ratchet
- Zero-knowledge proofs
- Lightning MITM Protection (~1ms overhead)
"""

__version__ = "0.6.0"
__author__ = "Sangeet Sharma"

from .protocol import MatryoshkaProtocol, GhostMessage
from .crypto.quantum import QuantumCrypto, get_quantum_crypto
from .crypto.fractal import PQFractalBundle, FractalRecoveryManager
from .ratchet.adaptive import AdaptiveRatchet
from .ghost.engine import GhostMode, DeadDropProtocol, ServiceRotation
from .ghost.fast_ghost import FastGhostMode
from .groups.fractal_ratchet import FractalGroupRatchet
from .groups.manager import MatryoshkaGroup, MatryoshkaGroupManager
from .zkp.sigma import SigmaProtocol, InnocenceProofZKP, generate_innocence_proof, verify_innocence_proof
from .mitm import (
    LightningMITMProtection,
    MITMDetectionResult,
    BloomFilterAuth,
    FlowFingerprinter,
    PredictiveCrypto,
    PreAuthConnectionPool,
    ContinuousStochasticAuth,
)

__all__ = [
    "MatryoshkaProtocol",
    "GhostMessage",
    "QuantumCrypto",
    "get_quantum_crypto",
    "PQFractalBundle",
    "FractalRecoveryManager",
    "AdaptiveRatchet",
    "GhostMode",
    "FastGhostMode",
    "DeadDropProtocol",
    "ServiceRotation",
    "FractalGroupRatchet",
    "MatryoshkaGroup",
    "MatryoshkaGroupManager",
    "SigmaProtocol",
    "InnocenceProofZKP",
    "generate_innocence_proof",
    "verify_innocence_proof",
    "LightningMITMProtection",
    "MITMDetectionResult",
    "BloomFilterAuth",
    "FlowFingerprinter",
    "PredictiveCrypto",
    "PreAuthConnectionPool",
    "ContinuousStochasticAuth",
]
