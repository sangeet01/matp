#!/usr/bin/env python3
"""
EXIF Image Embedding Strategy

Embeds encrypted messages in image EXIF metadata.
"""

import base64
from typing import Dict, Any


class EXIFEmbedding:
    """Embed messages in image EXIF metadata."""
    
    @staticmethod
    def embed(encrypted_payload: bytes, image_data: bytes = None) -> Dict[str, Any]:
        """
        Embed encrypted payload in EXIF metadata.
        
        Args:
            encrypted_payload: Encrypted message
            image_data: Optional image bytes
        
        Returns:
            Image metadata with embedded payload
        """
        encoded = base64.b64encode(encrypted_payload).decode()
        
        exif_data = {
            "ImageDescription": encoded,
            "Make": "Canon",
            "Model": "EOS 5D Mark IV",
            "Software": "Adobe Photoshop CC 2021",
            "DateTime": "2024:01:15 14:30:00",
            "Artist": "Photographer",
            "Copyright": "Copyright 2024"
        }
        
        return {
            "exif": exif_data,
            "image": image_data if image_data else b"fake_image_data"
        }
    
    @staticmethod
    def extract(image_metadata: Dict[str, Any]) -> bytes:
        """
        Extract encrypted payload from EXIF metadata.
        
        Args:
            image_metadata: Image metadata dict
        
        Returns:
            Encrypted payload
        """
        exif = image_metadata.get("exif", {})
        encoded = exif.get("ImageDescription", "")
        
        return base64.b64decode(encoded)


__all__ = ["EXIFEmbedding"]
