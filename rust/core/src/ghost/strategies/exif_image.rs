//! # EXIF Image Steganography Strategy
//!
//! Hides data within the UserComment field of a JPEG image's EXIF metadata.
//! Enhanced version matching Python implementation with realistic image generation.

use image::{ImageBuffer, Rgb, ImageOutputFormat};
use exif::{In, Tag, Value};
use exif::experimental::Writer;
use std::io::Cursor;
use rand::{Rng, thread_rng};

use crate::ghost::{engine::EmbeddingStrategy, GhostError};

pub struct ExifImageStrategy {
    image_width: u32,
    image_height: u32,
    jpeg_quality: u8,
}

impl ExifImageStrategy {
    pub fn new() -> Self {
        Self {
            image_width: 800,
            image_height: 600,
            jpeg_quality: 85,
        }
    }
    
    /// Create with custom dimensions
    pub fn with_dimensions(width: u32, height: u32) -> Self {
        Self {
            image_width: width,
            image_height: height,
            jpeg_quality: 85,
        }
    }
    
    /// Generate realistic-looking image with noise pattern
    fn generate_realistic_image(&self) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        let mut img = ImageBuffer::new(self.image_width, self.image_height);
        let mut rng = thread_rng();
        
        // Generate gradient with noise for realistic appearance
        for y in 0..self.image_height {
            for x in 0..self.image_width {
                let base_r = ((x as f32 / self.image_width as f32) * 255.0) as u8;
                let base_g = ((y as f32 / self.image_height as f32) * 255.0) as u8;
                let base_b = 128u8;
                
                // Add noise
                let noise = rng.gen_range(-20..20);
                let r = (base_r as i16 + noise).clamp(0, 255) as u8;
                let g = (base_g as i16 + noise).clamp(0, 255) as u8;
                let b = (base_b as i16 + noise).clamp(0, 255) as u8;
                
                img.put_pixel(x, y, Rgb([r, g, b]));
            }
        }
        
        img
    }
    
    /// Create EXIF metadata with realistic fields
    fn create_realistic_exif(&self, payload: &str) -> Vec<exif::Field> {
        let mut fields = Vec::new();
        
        // UserComment with payload (base64 encoded for reliability)
        use base64::{Engine as _, engine::general_purpose};
        let encoded = general_purpose::STANDARD.encode(payload.as_bytes());
        let exif_payload = [b"ASCII\0\0\0", encoded.as_bytes()].concat();
        fields.push(exif::Field {
            tag: Tag::UserComment,
            ifd_num: In::PRIMARY,
            value: Value::Undefined(exif_payload, 0),
        });
        
        // Add realistic metadata
        fields.push(exif::Field {
            tag: Tag::Make,
            ifd_num: In::PRIMARY,
            value: Value::Ascii(vec![b"Canon".to_vec()]),
        });
        
        fields.push(exif::Field {
            tag: Tag::Model,
            ifd_num: In::PRIMARY,
            value: Value::Ascii(vec![b"EOS 5D Mark IV".to_vec()]),
        });
        
        fields.push(exif::Field {
            tag: Tag::Software,
            ifd_num: In::PRIMARY,
            value: Value::Ascii(vec![b"Adobe Photoshop CC 2021".to_vec()]),
        });
        
        fields
    }
}

impl EmbeddingStrategy for ExifImageStrategy {
    fn embed(&self, payload: &str) -> Result<Vec<u8>, GhostError> {
        use base64::{Engine as _, engine::general_purpose};
        
        // Validate payload size
        if payload.len() > 65000 {
            return Err(GhostError::EmbeddingError(
                "Payload too large for EXIF embedding".to_string()
            ));
        }
        
        // Base64 encode payload
        let encoded = general_purpose::STANDARD.encode(payload.as_bytes());
        
        // Generate realistic image
        let img = self.generate_realistic_image();

        // Encode image to JPEG
        let mut img_buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut img_buf);
            img.write_to(&mut cursor, ImageOutputFormat::Jpeg(self.jpeg_quality))
                .map_err(|e| GhostError::EmbeddingError(format!("Image encoding failed: {}", e)))?;
        }

        // Create EXIF with payload in UserComment
        let exif_payload = [b"ASCII\0\0\0", encoded.as_bytes()].concat();
        let mut fields = Vec::new();
        fields.push(exif::Field {
            tag: Tag::UserComment,
            ifd_num: In::PRIMARY,
            value: Value::Undefined(exif_payload, 0),
        });
        
        let mut writer = Writer::new();
        for field in &fields {
            writer.push_field(field);
        }
        
        // Write EXIF to buffer
        let mut exif_buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut exif_buf);
            writer.write(&mut cursor, false)
                .map_err(|e| GhostError::EmbeddingError(format!("EXIF writing failed: {}", e)))?;
        }
        
        // Inject EXIF into JPEG with proper APP1 marker
        let mut final_output = Vec::new();
        
        if img_buf.len() >= 2 && img_buf[0] == 0xFF && img_buf[1] == 0xD8 {
            final_output.extend_from_slice(&[0xFF, 0xD8]); // SOI
            final_output.extend_from_slice(&[0xFF, 0xE1]); // APP1
            
            // EXIF marker + size
            let marker = b"Exif\0\0";
            let total_size = (marker.len() + exif_buf.len() + 2) as u16;
            final_output.extend_from_slice(&total_size.to_be_bytes());
            final_output.extend_from_slice(marker);
            final_output.extend_from_slice(&exif_buf);
            
            // Rest of JPEG
            final_output.extend_from_slice(&img_buf[2..]);
        } else {
            final_output.extend_from_slice(&img_buf);
        }
        
        Ok(final_output)
    }

    fn extract(&self, data: &[u8]) -> Option<String> {
        use base64::{Engine as _, engine::general_purpose};
        
        // Validate input
        if data.len() < 100 {
            return None;
        }
        
        // Try to parse EXIF from JPEG
        let mut cursor = Cursor::new(data);
        let exif_reader = exif::Reader::new();
        
        if let Ok(exif) = exif_reader.read_from_container(&mut cursor) {
            // Find UserComment field
            for field in exif.fields() {
                if field.tag == Tag::UserComment {
                    if let Value::Undefined(bytes, _) = &field.value {
                        // Strip "ASCII\0\0\0" prefix (8 bytes) and decode base64
                        if bytes.len() > 8 {
                            if let Ok(encoded) = String::from_utf8(bytes[8..].to_vec()) {
                                if let Ok(decoded) = general_purpose::STANDARD.decode(encoded.trim()) {
                                    if let Ok(s) = String::from_utf8(decoded) {
                                        return Some(s);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
}

impl Default for ExifImageStrategy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_exif_embed_extract() {
        let strategy = ExifImageStrategy::new();
        let payload = "secret_message_12345";
        
        let embedded = strategy.embed(payload).unwrap();
        assert!(embedded.len() > 1000); // Should be a real JPEG
        
        let extracted = strategy.extract(&embedded);
        assert!(extracted.is_some(), "Failed to extract payload from embedded image");
        assert_eq!(extracted.unwrap(), payload);
    }
    
    #[test]
    fn test_exif_large_payload() {
        let strategy = ExifImageStrategy::new();
        let payload = "x".repeat(70000);
        
        assert!(strategy.embed(&payload).is_err());
    }
    
    #[test]
    fn test_exif_custom_dimensions() {
        let strategy = ExifImageStrategy::with_dimensions(1024, 768);
        let payload = "test";
        
        let embedded = strategy.embed(payload).unwrap();
        let extracted = strategy.extract(&embedded);
        assert!(extracted.is_some(), "Failed to extract payload from custom dimension image");
        assert_eq!(extracted.unwrap(), payload);
    }
}
