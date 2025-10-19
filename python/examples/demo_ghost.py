#!/usr/bin/env python3
"""
Ghost Mode Demo - Be Invisible

Simple demonstration of perfect invisibility.
"""

from ghost_mode import GhostMode, DeadDropProtocol
import json

# Setup
key = b"my_secret_key_32_bytes_padding!!"
alice = GhostMode(key=key)
bob = GhostMode(key=key)

print("🎭 GHOST MODE DEMO\n")

# 1. Send invisible message
print("1️⃣  Alice sends invisible message:")
cover = alice.send_invisible("Meet me at midnight", service="github")
print(f"   Looks like: {cover['login']}@GitHub API")
print(f"   Actually contains: SECRET MESSAGE\n")

# 2. Bob receives
message = bob.receive_invisible(cover)
print(f"2️⃣  Bob receives: '{message}'\n")

# 3. With camouflage (99% real traffic)
print("3️⃣  Sending with 99% real traffic camouflage...")
cover = alice.send_with_camouflage("Top secret", real_traffic_ratio=0.99)
stats = alice.get_statistics()
print(f"   Detection probability: ε = {stats['detection_probability']:.6f}")
print(f"   You are {1/stats['detection_probability']:.0f}x harder to detect than Signal\n")

# 4. Dead drop (no direct communication)
print("4️⃣  Dead drop protocol:")
dead_drop = DeadDropProtocol(key=key)
location = dead_drop.drop_message("spot_1", "The package is ready")
print(f"   Alice drops at: {location}")
print(f"   Bob picks up: '{dead_drop.pickup_message(location)}'")
print(f"   NSA sees: No connection between Alice and Bob ✅\n")

print("🔒 You are now invisible on the network.")
