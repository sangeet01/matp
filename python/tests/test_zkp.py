#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test Zero-Knowledge Proofs."""

import sys
from pathlib import Path

# Add parent directory to path to find matp package
sys.path.insert(0, str(Path(__file__).parent.parent))

from matp.zkp import SigmaProtocol, InnocenceProofZKP, generate_innocence_proof, verify_innocence_proof


def test_sigma_protocol():
    """Test basic Sigma protocol."""
    print("Testing Sigma Protocol ZKP...")
    
    sigma = SigmaProtocol()
    
    # Generate keypair
    secret, public_key = sigma.generate_keypair()
    print(f"[+] Generated keypair")
    
    # Create proof
    message = b"Test message for ZKP"
    proof = sigma.prove(secret, message)
    print(f"[+] Generated proof")
    
    # Verify proof
    valid = sigma.verify(proof, public_key, message)
    assert valid, "Proof should be valid"
    print(f"[+] Proof verified successfully")
    
    # Test with wrong message
    wrong_message = b"Different message"
    invalid = sigma.verify(proof, public_key, wrong_message)
    assert not invalid, "Proof should be invalid for wrong message"
    print(f"[+] Invalid proof rejected")
    
    print("[SUCCESS] Sigma Protocol test PASSED\n")


def test_innocence_proof():
    """Test innocence proof with cover traffic."""
    print("Testing Innocence Proof ZKP...")
    
    zkp = InnocenceProofZKP()
    
    # Create cover traffic
    cover_data = {
        "status": "success",
        "data": {
            "user_id": 12345,
            "session_token": "encrypted_payload_here",
            "timestamp": 1234567890
        }
    }
    
    # Generate proof
    proof = zkp.generate_proof(cover_data)
    assert proof['type'] == 'sigma_protocol'
    print(f"[+] Generated innocence proof")
    
    # Verify proof
    valid = zkp.verify_proof(proof, cover_data)
    assert valid, "Innocence proof should be valid"
    print(f"[+] Innocence proof verified")
    
    # Test with modified cover data
    modified_cover = cover_data.copy()
    modified_cover['data']['user_id'] = 99999
    invalid = zkp.verify_proof(proof, modified_cover)
    assert not invalid, "Proof should be invalid for modified data"
    print(f"[+] Invalid proof rejected for modified data")
    
    print("[SUCCESS] Innocence Proof test PASSED\n")


def test_api_functions():
    """Test simplified API."""
    print("Testing Simplified API...")
    
    cover_data = {
        "status": "success",
        "data": {"user_id": 54321, "action": "fetch"}
    }
    
    # Generate
    proof = generate_innocence_proof(cover_data)
    print(f"[+] Generated proof via API")
    
    # Verify
    valid = verify_innocence_proof(proof, cover_data)
    assert valid, "API proof should be valid"
    print(f"[+] Verified proof via API")
    
    print("[SUCCESS] API test PASSED\n")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("ZERO-KNOWLEDGE PROOF TEST SUITE")
    print("="*60 + "\n")
    
    test_sigma_protocol()
    test_innocence_proof()
    test_api_functions()
    
    print("="*60)
    print("[SUCCESS] ALL ZKP TESTS PASSED")
    print("="*60)
    print("\nReal zero-knowledge proofs implemented!")
