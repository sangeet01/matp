#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="matp",
    version="0.5.0",
    author="Sangeet Sharma",
    author_email="sangeet.music01@gmail.com",
    description="Matryoshka Protocol - Invisible quantum-resistant messaging",
    long_description="Invisible secure messaging with steganography, post-quantum cryptography, and zero-knowledge proofs.",
    url="https://github.com/sangeet01/matp",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
        "liboqs-python>=0.14.0",
    ],
    keywords="cryptography steganography encryption messaging security invisible matp",
)
