#!/usr/bin/env python3
"""
JSON API Embedding Strategy

Embeds encrypted messages in JSON API responses.
"""

import json
import base64
from typing import Dict, Any


class JSONAPIEmbedding:
    """Embed messages in JSON API responses."""
    
    @staticmethod
    def embed(encrypted_payload: bytes, template: str = "github") -> Dict[str, Any]:
        """
        Embed encrypted payload in JSON API response.
        
        Args:
            encrypted_payload: Encrypted message
            template: API template (github, stripe, aws)
        
        Returns:
            JSON API response with embedded payload
        """
        encoded = base64.b64encode(encrypted_payload).decode()
        
        templates = {
            "github": {
                "id": 123456,
                "login": "user",
                "bio": encoded,
                "public_repos": 42,
                "followers": 100
            },
            "stripe": {
                "id": "ch_1234567890",
                "object": "charge",
                "amount": 1000,
                "description": encoded,
                "status": "succeeded"
            },
            "aws": {
                "ResponseMetadata": {
                    "RequestId": "abc-123",
                    "HTTPStatusCode": 200
                },
                "Data": encoded
            }
        }
        
        return templates.get(template, templates["github"])
    
    @staticmethod
    def extract(api_response: Dict[str, Any], template: str = "github") -> bytes:
        """
        Extract encrypted payload from JSON API response.
        
        Args:
            api_response: JSON API response
            template: API template used
        
        Returns:
            Encrypted payload
        """
        field_map = {
            "github": "bio",
            "stripe": "description",
            "aws": "Data"
        }
        
        field = field_map.get(template, "bio")
        
        if template == "aws":
            encoded = api_response.get("Data", "")
        else:
            encoded = api_response.get(field, "")
        
        return base64.b64decode(encoded)


__all__ = ["JSONAPIEmbedding"]
