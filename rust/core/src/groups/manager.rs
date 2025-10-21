//! # Matryoshka Groups - Production Group Chat System
//!
//! Combines Fractal Group Ratchet with Matryoshka steganography
//! for invisible multi-party encrypted communication.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose, Engine as _};

use super::{FractalGroupRatchet, GroupError};
use super::fractal_ratchet::{GroupEnvelope, SessionExport};

/// Production-ready group chat with invisible encryption
pub struct MatryoshkaGroup {
    group_id: String,
    group_name: String,
    creator_id: String,
    created_at: f64,
    
    ratchet: FractalGroupRatchet,
    
    members: Vec<String>,
    admins: Vec<String>,
    
    message_history: Vec<MessageRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MessageRecord {
    sender: String,
    timestamp: f64,
    layer: u32,
}

impl MatryoshkaGroup {
    /// Create new group
    pub fn new(group_id: String, group_name: String, creator_id: String) -> Self {
        Self {
            group_id,
            group_name,
            creator_id: creator_id.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            ratchet: FractalGroupRatchet::new(None),
            members: vec![creator_id.clone()],
            admins: vec![creator_id],
            message_history: Vec::new(),
        }
    }
    
    /// Get group metadata
    pub fn get_group_info(&self) -> GroupInfo {
        GroupInfo {
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
            creator: self.creator_id.clone(),
            members: self.members.clone(),
            admins: self.admins.clone(),
            member_count: self.members.len(),
            fingerprint: self.ratchet.get_fingerprint().to_string(),
            created_at: self.created_at,
        }
    }
    
    /// Add member to group
    pub fn add_member(&mut self, user_id: String, is_admin: bool) {
        if !self.members.contains(&user_id) {
            self.members.push(user_id.clone());
            if is_admin {
                self.admins.push(user_id);
            }
        }
    }
    
    /// Remove member from group (admin only)
    pub fn remove_member(&mut self, user_id: &str, requester_id: &str) -> Result<(), GroupError> {
        if !self.admins.contains(&requester_id.to_string()) {
            return Err(GroupError::PermissionDenied("Not an admin".to_string()));
        }
        
        self.members.retain(|m| m != user_id);
        self.admins.retain(|a| a != user_id);
        
        Ok(())
    }
    
    /// Send message to group (invisible!)
    pub fn send_message(&mut self, sender_id: &str, message: &str, use_steganography: bool) 
        -> Result<Vec<u8>, GroupError> 
    {
        let encrypted_envelope = self.ratchet.encrypt_for_group(message)?;
        
        let group_message = GroupMessage {
            msg_type: "group_message".to_string(),
            group_id: self.group_id.clone(),
            sender: sender_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            encrypted: encrypted_envelope.clone(),
        };
        
        // Store in history
        self.message_history.push(MessageRecord {
            sender: sender_id.to_string(),
            timestamp: group_message.timestamp,
            layer: encrypted_envelope.layer,
        });
        
        if use_steganography {
            // Embed in cover traffic
            let payload = serde_json::to_string(&group_message)
                .map_err(|e| GroupError::EncryptionError(e.to_string()))?;
            let encoded = general_purpose::STANDARD.encode(payload);
            
            let cover = serde_json::json!({
                "status": "success",
                "data": {
                    "user_id": 12345,
                    "session_token": encoded,
                    "preferences": {"theme": "dark", "lang": "en"},
                    "timestamp": group_message.timestamp as u64
                },
                "meta": {"version": "2.1.0", "server": "api-01"}
            });
            
            serde_json::to_vec(&cover)
                .map_err(|e| GroupError::EncryptionError(e.to_string()))
        } else {
            serde_json::to_vec(&group_message)
                .map_err(|e| GroupError::EncryptionError(e.to_string()))
        }
    }
    
    /// Receive and decrypt group message
    pub fn receive_message(&mut self, ghost_data: &[u8]) -> Result<ReceivedMessage, GroupError> {
        // Try to parse as JSON
        let json_data: serde_json::Value = serde_json::from_slice(ghost_data)
            .map_err(|e| GroupError::DecryptionError(e.to_string()))?;
        
        // Extract from steganography if present
        let group_message: GroupMessage = if let Some(data) = json_data.get("data") {
            if let Some(token) = data.get("session_token") {
                let encoded = token.as_str()
                    .ok_or_else(|| GroupError::DecryptionError("Invalid token".to_string()))?;
                let decoded = general_purpose::STANDARD.decode(encoded)
                    .map_err(|e| GroupError::DecryptionError(e.to_string()))?;
                serde_json::from_slice(&decoded)
                    .map_err(|e| GroupError::DecryptionError(e.to_string()))?
            } else {
                serde_json::from_value(json_data)
                    .map_err(|e| GroupError::DecryptionError(e.to_string()))?
            }
        } else {
            serde_json::from_value(json_data)
                .map_err(|e| GroupError::DecryptionError(e.to_string()))?
        };
        
        // Verify group ID
        if group_message.group_id != self.group_id {
            return Err(GroupError::DecryptionError("Message not for this group".to_string()));
        }
        
        // Decrypt with ratchet
        let plaintext = self.ratchet.decrypt_from_group(&group_message.encrypted)?;
        
        Ok(ReceivedMessage {
            sender: group_message.sender,
            message: plaintext,
            timestamp: group_message.timestamp,
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
        })
    }
    
    /// Export invite for new member
    pub fn export_invite(&self, from_layer: Option<u32>) -> GroupInvite {
        let layer = from_layer.unwrap_or(self.ratchet.message_counter);
        let session = self.ratchet.export_session(layer);
        
        GroupInvite {
            invite_type: "group_invite".to_string(),
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
            creator: self.creator_id.clone(),
            members: self.members.clone(),
            session,
            invited_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        }
    }
    
    /// Rotate group seed (admin only)
    pub fn rotate_group_seed(&mut self, requester_id: &str) -> Result<[u8; 32], GroupError> {
        if !self.admins.contains(&requester_id.to_string()) {
            return Err(GroupError::PermissionDenied("Not an admin".to_string()));
        }
        
        Ok(self.ratchet.rotate_seed())
    }
}

/// Group metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: String,
    pub group_name: String,
    pub creator: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub member_count: usize,
    pub fingerprint: String,
    pub created_at: f64,
}

/// Group message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupMessage {
    #[serde(rename = "type")]
    msg_type: String,
    group_id: String,
    sender: String,
    timestamp: f64,
    encrypted: GroupEnvelope,
}

/// Received message
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub sender: String,
    pub message: String,
    pub timestamp: f64,
    pub group_id: String,
    pub group_name: String,
}

/// Group invite
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInvite {
    #[serde(rename = "type")]
    invite_type: String,
    pub group_id: String,
    pub group_name: String,
    pub creator: String,
    pub members: Vec<String>,
    pub session: SessionExport,
    pub invited_at: f64,
}

/// Manage multiple groups for a user
pub struct MatryoshkaGroupManager {
    user_id: String,
    groups: HashMap<String, MatryoshkaGroup>,
}

impl MatryoshkaGroupManager {
    /// Create new group manager
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            groups: HashMap::new(),
        }
    }
    
    /// Create new group
    pub fn create_group(&mut self, group_id: String, group_name: String) -> &mut MatryoshkaGroup {
        let group = MatryoshkaGroup::new(group_id.clone(), group_name, self.user_id.clone());
        self.groups.insert(group_id.clone(), group);
        self.groups.get_mut(&group_id).unwrap()
    }
    
    /// Join group from invite
    pub fn join_group(&mut self, invite: &GroupInvite) -> Result<(), GroupError> {
        let mut group = MatryoshkaGroup::new(
            invite.group_id.clone(),
            invite.group_name.clone(),
            invite.creator.clone(),
        );
        
        group.ratchet.import_session(&invite.session)?;
        group.members = invite.members.clone();
        group.members.push(self.user_id.clone());
        
        self.groups.insert(invite.group_id.clone(), group);
        Ok(())
    }
    
    /// Send message to group
    pub fn send_to_group(&mut self, group_id: &str, message: &str) -> Result<Vec<u8>, GroupError> {
        let group = self.groups.get_mut(group_id)
            .ok_or_else(|| GroupError::GroupNotFound(group_id.to_string()))?;
        
        group.send_message(&self.user_id, message, true)
    }
    
    /// Receive group message
    pub fn receive_group_message(&mut self, ghost_data: &[u8]) -> Result<ReceivedMessage, GroupError> {
        for group in self.groups.values_mut() {
            if let Ok(msg) = group.receive_message(ghost_data) {
                return Ok(msg);
            }
        }
        
        Err(GroupError::DecryptionError("Message not for any group".to_string()))
    }
    
    /// Get all groups
    pub fn get_all_groups(&self) -> Vec<GroupInfo> {
        self.groups.values().map(|g| g.get_group_info()).collect()
    }
    
    /// Leave group
    pub fn leave_group(&mut self, group_id: &str) {
        self.groups.remove(group_id);
    }
    
    /// Get specific group
    pub fn get_group(&self, group_id: &str) -> Option<&MatryoshkaGroup> {
        self.groups.get(group_id)
    }
    
    /// Get mutable group reference
    pub fn get_group_mut(&mut self, group_id: &str) -> Option<&mut MatryoshkaGroup> {
        self.groups.get_mut(group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_group_creation() {
        let mut alice = MatryoshkaGroupManager::new("alice".to_string());
        let group = alice.create_group("project-x".to_string(), "Secret Project".to_string());
        
        let info = group.get_group_info();
        assert_eq!(info.group_id, "project-x");
        assert_eq!(info.members.len(), 1);
    }
    
    #[test]
    fn test_group_messaging() {
        let mut alice = MatryoshkaGroupManager::new("alice".to_string());
        let mut bob = MatryoshkaGroupManager::new("bob".to_string());
        
        // Alice creates group
        alice.create_group("test-group".to_string(), "Test".to_string());
        
        // Export invite
        let invite = alice.get_group("test-group").unwrap().export_invite(None);
        
        // Bob joins
        bob.join_group(&invite).unwrap();
        
        // Alice sends message
        let msg = alice.send_to_group("test-group", "Hello Bob!").unwrap();
        
        // Bob receives
        let received = bob.receive_group_message(&msg).unwrap();
        assert_eq!(received.message, "Hello Bob!");
        assert_eq!(received.sender, "alice");
    }
}
