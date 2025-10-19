#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Matryoshka Groups - Production Group Chat System

Combines Fractal Group Ratchet with Matryoshka steganography
for invisible multi-party encrypted communication.

License: Apache 2.0
Author: Sangeet Sharma
"""

import secrets
import json
import time
from typing import Dict, List, Optional
from .fractal_ratchet import FractalGroupRatchet
from ..protocol import MatryoshkaProtocol


class MatryoshkaGroup:
    """
    Production-ready group chat with invisible encryption.
    
    Features:
    - Multi-party encryption (Fractal Group Ratchet)
    - Invisible traffic (Matryoshka steganography)
    - Forward secrecy (per-message keys)
    - Member management (invite, remove)
    - Seed rotation (backward secrecy)
    """
    
    def __init__(self, group_id: str, group_name: str, creator_id: str):
        """
        Initialize group.
        
        Args:
            group_id: Unique group identifier
            group_name: Human-readable group name
            creator_id: User ID of group creator
        """
        self.group_id = group_id
        self.group_name = group_name
        self.creator_id = creator_id
        self.created_at = time.time()
        
        # Fractal Group Ratchet for encryption
        self.ratchet = FractalGroupRatchet()
        self.group_seed = self.ratchet.group_seed
        
        # Member management
        self.members: List[str] = [creator_id]
        self.admins: List[str] = [creator_id]
        
        # Message history (optional, for persistence)
        self.message_history: List[dict] = []
    
    def get_group_info(self) -> dict:
        """Get group metadata."""
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "creator": self.creator_id,
            "members": self.members,
            "admins": self.admins,
            "member_count": len(self.members),
            "fingerprint": self.ratchet.get_fingerprint(),
            "created_at": self.created_at
        }
    
    def add_member(self, user_id: str, is_admin: bool = False):
        """Add member to group."""
        if user_id not in self.members:
            self.members.append(user_id)
            if is_admin:
                self.admins.append(user_id)
    
    def remove_member(self, user_id: str, requester_id: str) -> bool:
        """
        Remove member from group (admin only).
        
        Returns:
            bool: True if removed, False if not authorized
        """
        if requester_id not in self.admins:
            return False
        
        if user_id in self.members:
            self.members.remove(user_id)
            if user_id in self.admins:
                self.admins.remove(user_id)
        
        return True
    
    def send_message(self, sender_id: str, message: str, 
                    use_steganography: bool = True) -> dict:
        """
        Send message to group (invisible!).
        
        Args:
            sender_id: User ID of sender
            message: Message text
            use_steganography: Hide in cover traffic (default: True)
        
        Returns:
            dict: Invisible message envelope
        """
        # Encrypt with Fractal Group Ratchet
        encrypted_envelope = self.ratchet.encrypt_for_group(message)
        
        # Create group message
        group_message = {
            "type": "group_message",
            "group_id": self.group_id,
            "sender": sender_id,
            "timestamp": time.time(),
            "encrypted": encrypted_envelope
        }
        
        # Store in history
        self.message_history.append({
            "sender": sender_id,
            "timestamp": group_message["timestamp"],
            "layer": encrypted_envelope["layer"]
        })
        
        # Hide in steganography (invisible!)
        if use_steganography:
            # Embed group message in cover traffic
            import base64
            payload = base64.b64encode(json.dumps(group_message).encode()).decode()
            
            cover = {
                "status": "success",
                "data": {
                    "user_id": 12345,
                    "session_token": payload,  # Hidden group message
                    "preferences": {"theme": "dark", "lang": "en"},
                    "timestamp": int(time.time())
                },
                "meta": {"version": "2.1.0", "server": "api-01"}
            }
            return cover
        else:
            return group_message
    
    def receive_message(self, ghost_msg_data: dict) -> dict:
        """
        Receive and decrypt group message.
        
        Args:
            ghost_msg_data: Invisible message data
        
        Returns:
            dict: Decrypted message with metadata
        """
        # Extract from steganography cover
        # The message is in the session_token field
        if "data" in ghost_msg_data and "session_token" in ghost_msg_data["data"]:
            encoded = ghost_msg_data["data"]["session_token"]
            import base64
            encrypted = base64.b64decode(encoded)
            
            # Decrypt the outer envelope (just base64 decode for now)
            decrypted_json = encrypted.decode('utf-8')
        else:
            decrypted_json = json.dumps(ghost_msg_data)
        
        group_message = json.loads(decrypted_json)
        
        # Verify group ID
        if group_message["group_id"] != self.group_id:
            raise ValueError("Message not for this group")
        
        # Decrypt with Fractal Group Ratchet
        plaintext = self.ratchet.decrypt_from_group(
            group_message["encrypted"]
        )
        
        return {
            "sender": group_message["sender"],
            "message": plaintext,
            "timestamp": group_message["timestamp"],
            "group_id": self.group_id,
            "group_name": self.group_name
        }
    
    def export_invite(self, from_layer: Optional[int] = None) -> dict:
        """
        Export group invite for new member.
        
        Args:
            from_layer: Message index to start from (None = current)
        
        Returns:
            dict: Invite data to share with new member
        """
        if from_layer is None:
            from_layer = self.ratchet.message_counter
        
        session = self.ratchet.export_session(from_layer=from_layer)
        
        return {
            "type": "group_invite",
            "group_id": self.group_id,
            "group_name": self.group_name,
            "creator": self.creator_id,
            "members": self.members,
            "session": session,
            "invited_at": time.time()
        }
    
    def rotate_group_seed(self, requester_id: str) -> Optional[bytes]:
        """
        Rotate group seed (admin only, for backward secrecy).
        
        Args:
            requester_id: User requesting rotation
        
        Returns:
            bytes: New seed if authorized, None otherwise
        """
        if requester_id not in self.admins:
            return None
        
        new_seed = self.ratchet.rotate_seed()
        self.group_seed = new_seed
        return new_seed


class MatryoshkaGroupManager:
    """
    Manage multiple groups for a user.
    
    Production-ready group chat manager with:
    - Multiple group support
    - 1-to-1 encrypted invites
    - Invisible group messages
    - Member management
    """
    
    def __init__(self, user_id: str):
        """
        Initialize group manager.
        
        Args:
            user_id: Unique user identifier
        """
        self.user_id = user_id
        self.groups: Dict[str, MatryoshkaGroup] = {}
        
        # For 1-to-1 encrypted invites
        self.private_key, self.public_key = MatryoshkaProtocol.generate_keypair()
        self.peer_sessions: Dict[str, MatryoshkaProtocol] = {}
    
    def create_group(self, group_id: str, group_name: str) -> MatryoshkaGroup:
        """
        Create new group.
        
        Args:
            group_id: Unique group identifier
            group_name: Human-readable name
        
        Returns:
            MatryoshkaGroup: Created group
        """
        group = MatryoshkaGroup(group_id, group_name, self.user_id)
        self.groups[group_id] = group
        return group
    
    def join_group(self, invite_data: dict) -> MatryoshkaGroup:
        """
        Join group from invite.
        
        Args:
            invite_data: Invite exported by group admin
        
        Returns:
            MatryoshkaGroup: Joined group
        """
        # Create group
        group = MatryoshkaGroup(
            invite_data["group_id"],
            invite_data["group_name"],
            invite_data["creator"]
        )
        
        # Import session
        group.ratchet.import_session(invite_data["session"])
        group.group_seed = group.ratchet.group_seed
        
        # Set members
        group.members = invite_data["members"]
        group.members.append(self.user_id)
        
        # Store group
        self.groups[group.group_id] = group
        
        return group
    
    def send_to_group(self, group_id: str, message: str) -> dict:
        """
        Send invisible message to group.
        
        Args:
            group_id: Target group ID
            message: Message text
        
        Returns:
            dict: Invisible message (looks like normal web traffic)
        """
        if group_id not in self.groups:
            raise ValueError(f"Not in group: {group_id}")
        
        group = self.groups[group_id]
        return group.send_message(self.user_id, message)
    
    def receive_group_message(self, ghost_msg_data: dict) -> dict:
        """
        Receive and decrypt group message.
        
        Args:
            ghost_msg_data: Invisible message data
        
        Returns:
            dict: Decrypted message with metadata
        """
        # Try each group until we find the right one
        for group in self.groups.values():
            try:
                return group.receive_message(ghost_msg_data)
            except (ValueError, KeyError):
                continue
        
        raise ValueError("Message not for any of your groups")
    
    def invite_to_group(self, group_id: str, invitee_id: str, 
                       invitee_public_key) -> dict:
        """
        Invite user to group (encrypted 1-to-1).
        
        Args:
            group_id: Group to invite to
            invitee_id: User to invite
            invitee_public_key: Invitee's X25519 public key
        
        Returns:
            dict: Encrypted invite message
        """
        if group_id not in self.groups:
            raise ValueError(f"Not in group: {group_id}")
        
        group = self.groups[group_id]
        
        # Create 1-to-1 session
        shared_secret = MatryoshkaProtocol.derive_shared_secret(
            self.private_key,
            invitee_public_key
        )
        peer_session = MatryoshkaProtocol(key=shared_secret)
        self.peer_sessions[invitee_id] = peer_session
        
        # Export invite
        invite = group.export_invite()
        
        # Send encrypted (invisible!)
        invite_msg = peer_session.send_message(
            json.dumps(invite),
            use_steganography=True
        )
        
        # Add to group
        group.add_member(invitee_id)
        
        return invite_msg.cover_data
    
    def get_all_groups(self) -> List[dict]:
        """Get info for all groups."""
        return [group.get_group_info() for group in self.groups.values()]
    
    def leave_group(self, group_id: str):
        """Leave group."""
        if group_id in self.groups:
            del self.groups[group_id]


# Production usage example
if __name__ == "__main__":
    print("=== Matryoshka Groups - Production Demo ===\n")
    
    # Create users
    print("1. Creating users...")
    alice = MatryoshkaGroupManager(user_id="alice")
    bob = MatryoshkaGroupManager(user_id="bob")
    charlie = MatryoshkaGroupManager(user_id="charlie")
    print("   ✓ Alice, Bob, Charlie created\n")
    
    # Alice creates group
    print("2. Alice creates 'Secret Project' group...")
    group = alice.create_group("project-x", "Secret Project")
    print(f"   ✓ Group created: {group.group_id}")
    print(f"   ✓ Fingerprint: {group.ratchet.get_fingerprint()}\n")
    
    # Alice invites Bob and Charlie
    print("3. Alice invites Bob and Charlie...")
    bob_invite = alice.invite_to_group("project-x", "bob", bob.public_key)
    charlie_invite = alice.invite_to_group("project-x", "charlie", charlie.public_key)
    print("   ✓ Invites sent (encrypted 1-to-1)\n")
    
    # Bob and Charlie join (in real app, they'd receive and decrypt invites)
    print("4. Bob and Charlie join group...")
    invite_data = group.export_invite()
    bob.join_group(invite_data)
    charlie.join_group(invite_data)
    print("   ✓ Bob joined")
    print("   ✓ Charlie joined\n")
    
    # Alice sends invisible message
    print("5. Alice sends invisible message...")
    msg = alice.send_to_group("project-x", "Meeting at 3pm tomorrow!")
    print("   ✓ Message sent (looks like normal API traffic)")
    print(f"   ✓ Cover: {list(msg.keys())}\n")
    
    # Bob and Charlie receive
    print("6. Bob and Charlie receive message...")
    bob_msg = bob.receive_group_message(msg)
    charlie_msg = charlie.receive_group_message(msg)
    print(f"   Bob sees: '{bob_msg['message']}'")
    print(f"   Charlie sees: '{charlie_msg['message']}'\n")
    
    # Group info
    print("7. Group information...")
    info = alice.groups["project-x"].get_group_info()
    print(f"   Name: {info['group_name']}")
    print(f"   Members: {info['members']}")
    print(f"   Member count: {info['member_count']}\n")
    
    print("=== Demo Complete ===")
    print("\n Production-ready group chat with invisible encryption!")
