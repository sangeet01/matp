#!/usr/bin/env python3
"""Setup script for Matryoshka Protocol Python bindings."""

from setuptools import setup, find_packages

setup(
    name="matp",
    version="0.1.0",
    author="Sangeet Sharma",
    author_email="s..........@gmail.com",
    description="Matryoshka Protocol - The truly invisible secure messaging system",
    long_description="""Secure messaging protocol combining Ghost steganography + Fractal self-healing + Zero-knowledge proofs.
    
    Features:
    - GHOST LAYER: Perfect traffic analysis resistance (looks like normal web browsing)
    - FRACTAL ENCRYPTION: Self-healing Russian doll keys survive message loss
    - QUANTUM DECOYS: Waste quantum computer resources on fake data
    - ZKP INNOCENCE: Mathematical proof you're "just browsing"
    - DECENTRALIZED: No servers, pure P2P discovery
    
    Security Properties (Formally Proven):
    - Undetectable communication (ε-steganographic security)
    - Perfect forward secrecy + post-compromise security  
    - Plausible deniability ("I was just browsing")
    - Quantum resistance (optional post-quantum crypto)
    - k-anonymity in peer discovery
    """,
    long_description_content_type="text/markdown",
    url="https://github.com/sangeet01/matp",
    packages=find_packages(),
    zip_safe=False,
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.4.8",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "mypy>=0.900",
        ],
        "quantum": [
            "pqcrypto>=0.8.0",  # Post-quantum cryptography
        ],
        "full": [
            "pqcrypto>=0.8.0",
            "pillow>=8.0.0",     # Image steganography
            "requests>=2.25.0",  # HTTP cover traffic
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: Chat",
    ],
)
