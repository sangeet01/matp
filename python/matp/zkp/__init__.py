"""Zero-knowledge proofs for plausible deniability."""

from .sigma import SigmaProtocol, InnocenceProofZKP, generate_innocence_proof, verify_innocence_proof

__all__ = ["SigmaProtocol", "InnocenceProofZKP", "generate_innocence_proof", "verify_innocence_proof"]
