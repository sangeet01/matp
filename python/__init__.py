"""
MATP - Matryoshka Protocol
The world's first truly invisible secure messaging system
"""

from .matp import MatryoshkaProtocol, GhostMessage, FutureBundle, InnocenceProof

__version__ = '0.1.0'
__all__ = ['MatryoshkaProtocol', 'GhostMessage', 'FutureBundle', 'InnocenceProof']