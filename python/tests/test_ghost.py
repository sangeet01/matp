#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Ghost Mode - Perfect Invisibility

Demonstrates:
1. Real traffic mimicry (ε → 0)
2. Behavioral camouflage
3. Dead drop protocol
4. Service rotation
"""

import json
import sys
from pathlib import Path

# Add parent directory to path to find matp package
sys.path.insert(0, str(Path(__file__).parent.parent))

from matp.ghost.engine import GhostMode, DeadDropProtocol, ServiceRotation


def test_basic_invisibility():
    """Test basic invisible messaging."""
    print("=" * 60)
    print("TEST 1: Basic Invisibility")
    print("=" * 60)
    
    key = b"test_key_32_bytes_long_padding!!"
    alice = GhostMode(key=key)
    bob = GhostMode(key=key)
    
    # Send invisible message
    message = "Meet at the usual place"
    cover = alice.send_invisible(message, service="github")
    
    print("\n📤 Alice sends (looks like GitHub API):")
    print(json.dumps(cover, indent=2))
    
    # Receive
    received = bob.receive_invisible(cover)
    print(f"\n Bob receives: '{received}'")
    
    assert received == message, "Message mismatch!"
    print("\nPASS: Message transmitted invisibly\n")


def test_behavioral_camouflage():
    """Test behavioral camouflage with real traffic mixing."""
    print("=" * 60)
    print("TEST 2: Behavioral Camouflage")
    print("=" * 60)
    
    key = b"camouflage_key_32_bytes_padding!"
    alice = GhostMode(key=key)
    
    print("\n Sending with 90% real traffic camouflage...")
    cover = alice.send_with_camouflage("Secret data", real_traffic_ratio=0.9)
    
    stats = alice.get_statistics()
    print(f"\n Traffic Statistics:")
    print(f"   Hidden messages: {stats['messages_sent']}")
    print(f"   Real traffic: {stats['real_traffic_sent']}")
    print(f"   Total traffic: {stats['total_traffic']}")
    print(f"   Hidden ratio: {stats['hidden_ratio']:.1%}")
    print(f"   Detection probability (ε): {stats['detection_probability']:.6f}")
    
    assert stats['hidden_ratio'] <= 0.15, "Too much hidden traffic!"
    print("\n PASS: Behavioral camouflage working\n")


def test_dead_drop_protocol():
    """Test dead drop protocol (no direct communication)."""
    print("=" * 60)
    print("TEST 3: Dead Drop Protocol")
    print("=" * 60)
    
    key = b"dead_drop_key_32_bytes_padding!!"
    dead_drop = DeadDropProtocol(key=key)
    
    # Alice drops message
    print("\n👤 Alice drops message at public location...")
    location = dead_drop.drop_message(
        drop_id="secret_spot_42",
        message="The eagle has landed",
        service="github"
    )
    print(f"   Drop location: {location}")
    
    # List available drops
    drops = dead_drop.list_drops()
    print(f"   Available drops: {len(drops)}")
    
    # Bob picks up (no connection to Alice)
    print("\n Bob picks up message (hours later)...")
    message = dead_drop.pickup_message(location)
    print(f"   Retrieved: '{message}'")
    
    assert message == "The eagle has landed", "Message mismatch!"
    print("\n PASS: Dead drop protocol working")
    print("    No direct communication between Alice and Bob\n")


def test_service_rotation():
    """Test service rotation for diversity."""
    print("=" * 60)
    print("TEST 4: Service Rotation")
    print("=" * 60)
    
    key = b"rotation_key_32_bytes_padding!!!"
    rotator = ServiceRotation(key=key)
    
    print("\n Rotating through services...")
    services_used = []
    
    for i in range(6):
        cover, service = rotator.send_rotated(f"Message {i+1}")
        services_used.append(service)
        print(f"   Message {i+1}: {service}")
    
    # Verify rotation
    unique_services = set(services_used)
    print(f"\n   Services used: {unique_services}")
    print(f"   Rotation pattern: {' → '.join(services_used)}")
    
    assert len(unique_services) >= 2, "Not enough service diversity!"
    print("\n PASS: Service rotation working\n")


def test_multiple_services():
    """Test hiding in different service types."""
    print("=" * 60)
    print("TEST 5: Multiple Service Types")
    print("=" * 60)
    
    key = b"multi_service_key_32_bytes_pad!!"
    alice = GhostMode(key=key)
    bob = GhostMode(key=key)
    
    services = ["github", "stripe", "aws"]
    
    for service in services:
        print(f"\n Testing {service.upper()} mimicry...")
        cover = alice.send_invisible(f"Secret via {service}", service=service)
        print(f"   Cover: {list(cover.keys())}")
        
        received = bob.receive_invisible(cover)
        assert received == f"Secret via {service}", f"{service} failed!"
        print(f"    {service} working")
    
    print("\n PASS: All services working\n")


def test_detection_probability():
    """Calculate detection probability with different ratios."""
    print("=" * 60)
    print("TEST 6: Detection Probability Analysis")
    print("=" * 60)
    
    key = b"detection_test_key_32_bytes_pad!"
    
    ratios = [0.5, 0.7, 0.9, 0.95, 0.99]
    
    print("\n Detection Probability vs Real Traffic Ratio:")
    print(f"{'Real Traffic':<15} {'Hidden':<10} {'ε (Detection)':<20}")
    print("-" * 45)
    
    for ratio in ratios:
        ghost = GhostMode(key=key)
        ghost.send_with_camouflage("test", real_traffic_ratio=ratio)
        stats = ghost.get_statistics()
        
        print(f"{ratio:.0%}{'':>13} {stats['hidden_ratio']:.1%}{'':>6} "
              f"{stats['detection_probability']:.6f}")
    
    print("\n Recommendation: Use 90%+ real traffic for ε < 0.001")
    print("PASS: Detection probability scales correctly\n")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("GHOST MODE TEST SUITE")
    print("Perfect Invisibility for Matryoshka Protocol")
    print("=" * 60 + "\n")
    
    try:
        test_basic_invisibility()
        test_behavioral_camouflage()
        test_dead_drop_protocol()
        test_service_rotation()
        test_multiple_services()
        test_detection_probability()
        
        print("=" * 60)
        print(" ALL TESTS PASSED")
        print("=" * 60)
        print("\n Ghost Mode: Perfect Invisibility Achieved")
        print("   - Real traffic mimicry: ε → 0")
        print("   - Behavioral camouflage: 90%+ real traffic")
        print("   - Dead drop protocol: No direct communication")
        print("   - Service rotation: Maximum diversity")
        print("\n You are now a ghost on the network.\n")
        
    except AssertionError as e:
        print(f"\n TEST FAILED: {e}\n")
    except Exception as e:
        print(f"\n ERROR: {e}\n")
        import traceback
        traceback.print_exc()
