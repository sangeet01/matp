//! # EXIF Image Steganography Strategy
//!
//! Hides data within the UserComment field of a JPEG image's EXIF metadata.

use image::{ImageBuffer, Rgb, ImageOutputFormat};
use exif::{In, Tag, Value};
use exif::experimental::Writer;
use std::io::Cursor;

use crate::ghost::{engine::EmbeddingStrategy, GhostError};

pub struct ExifImageStrategy;

impl ExifImageStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl EmbeddingStrategy for ExifImageStrategy {
    fn embed(&self, payload: &str) -> Result<Vec<u8>, GhostError> {
        // Create a dummy image buffer
        let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(600, 400);
        img.fill(rand::random());

        // Encode image to JPEG
        let mut img_buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut img_buf);
            img.write_to(&mut cursor, ImageOutputFormat::Jpeg(80))
                .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        }

        // Prepare EXIF data with UserComment
        let exif_payload = [b"ASCII\0\0\0", payload.as_bytes()].concat();
        let field = exif::Field {
            tag: Tag::UserComment,
            ifd_num: In::PRIMARY,
            value: Value::Undefined(exif_payload, 0),
        };
        
        let mut writer = Writer::new();
        writer.push_field(&field);
        
        // Write EXIF to buffer
        let mut exif_buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut exif_buf);
            writer.write(&mut cursor, false)
                .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        }
        
        // Combine JPEG with EXIF
        let mut final_output = img_buf;
        final_output.extend_from_slice(&exif_buf);
        
        Ok(final_output)
    }

    fn extract(&self, data: &[u8]) -> Option<String> {
        let mut cursor = Cursor::new(data);
        let exif_reader = exif::Reader::new();
        let exif_data = exif_reader.read_from_container(&mut cursor).ok()?;
        
        // Find UserComment field
        for field in exif_data.fields() {
            if field.tag == Tag::UserComment {
                if let Value::Undefined(bytes, _) = &field.value {
                    // Strip "ASCII\0\0\0" prefix
                    return bytes.get(8..).and_then(|s| String::from_utf8(s.to_vec()).ok());
                }
            }
        }
        None
    }
}
