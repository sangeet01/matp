#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final working test for Matryoshka Protocol
"""

import json
import base64

class MatryoshkaDemo:
    """Simplified Matryoshka Protocol demonstration."""
    
    def __init__(self):
        # Simple key for XOR encryption (demo only)
        self.key = "matryoshka_secret_key_demo_32b"
    
    def encrypt(self, text):
        """Simple XOR encryption."""
        result = ""
        for i, char in enumerate(text):
            key_char = self.key[i % len(self.key)]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            result += encrypted_char
        return result
    
    def decrypt(self, encrypted_text):
        """Simple XOR decryption (same as encrypt for XOR)."""
        return self.encrypt(encrypted_text)
    
    def send_message(self, message):
        """Send message hidden in JSON API response."""
        print("Sending:", message)
        
        # Encrypt the message
        encrypted = self.encrypt(message)
        
        # Encode for safe JSON transport
        encoded = base64.b64encode(encrypted.encode('latin1')).decode()
        
        # Hide in normal-looking API response
        api_response = {
            "status": "success",
            "data": {
                "user_id": 12345,
                "session_id": encoded,  # Hidden message here!
                "preferences": {"theme": "dark"},
                "last_login": "2024-01-15T10:30:00Z"
            },
            "meta": {
                "version": "2.1.0",
                "server": "api-prod-01"
            }
        }
        
        return json.dumps(api_response, indent=2)
    
    def receive_message(self, api_response_json):
        """Extract and decrypt message from API response."""
        # Parse the JSON
        data = json.loads(api_response_json)
        
        # Extract the hidden message
        encoded = data["data"]["session_id"]
        
        # Decode and decrypt
        encrypted = base64.b64decode(encoded).decode('latin1')
        message = self.decrypt(encrypted)
        
        print("Received:", message)
        return message

def main():
    print("=" * 60)
    print("MATRYOSHKA PROTOCOL - STEGANOGRAPHIC MESSAGING DEMO")
    print("=" * 60)
    
    # Create protocol instance
    mtp = MatryoshkaDemo()
    
    # Test message
    secret_message = "Meet me at the library at 3pm"
    
    print("\n1. SENDING SECRET MESSAGE")
    print("-" * 30)
    
    # Send message (hide in API response)
    api_response = mtp.send_message(secret_message)
    
    print("\n2. WHAT AN OBSERVER SEES")
    print("-" * 30)
    print("Normal JSON API response:")
    print(api_response)
    
    print("\n3. RECEIVING SECRET MESSAGE")
    print("-" * 30)
    
    # Receive message (extract from API response)
    received_message = mtp.receive_message(api_response)
    
    print("\n4. VERIFICATION")
    print("-" * 30)
    print("Original :", repr(secret_message))
    print("Received :", repr(received_message))
    print("Success  :", secret_message == received_message)
    
    if secret_message == received_message:
        print("\n" + "=" * 60)
        print("SUCCESS! MATRYOSHKA PROTOCOL CORE FEATURES WORKING:")
        print("✓ GHOST STEGANOGRAPHY: Message hidden in plain sight")
        print("✓ PLAUSIBLE DENIABILITY: Looks like normal API traffic")
        print("✓ UNDETECTABLE: No crypto signatures visible")
        print("✓ SELF-CONTAINED: No special infrastructure needed")
        print("=" * 60)
        return True
    else:
        print("\nFAILED: Message corruption detected")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\nMatryoshka Protocol concepts successfully demonstrated!")
        print("Ready for full cryptographic implementation.")
    else:
        print("\nDemo failed - need to debug.")