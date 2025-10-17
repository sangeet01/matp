//! # EXIF Image Steganography Strategy
//!
//! Hides data within the UserComment field of a JPEG image's EXIF metadata.

use image::{ImageBuffer, Rgb, ImageOutputFormat};
use kamadak_exif as exif;
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
        // 1. Create a dummy image buffer.
        let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(600, 400);
        // In a real app, this could be a user-provided image or a more realistic generated one.
        img.fill(rand::random());

        // 2. Encode image to JPEG first
        let mut img_buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut img_buf);
            img.write_to(&mut cursor, ImageOutputFormat::Jpeg(80))
                .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        }

        // 3. Prepare the EXIF data with UserComment containing payload
        let exif_payload = [b"ASCII\0\0\0", payload.as_bytes()].concat();
        
        let mut exif_data = exif::Exif::new();
        let user_comment = exif::Field {
            tag: exif::Tag::UserComment,
            ifd_num: exif::In::PRIMARY,
            value: exif::Value::Undefined(exif_payload, 0),
        };
        exif_data.push_field(user_comment);

        // 4. Write EXIF data into JPEG
        let mut output = Vec::new();
        {
            let mut writer = exif::Writer::new();
            let mut cursor = Cursor::new(&mut output);
            writer.write(&mut cursor, &exif_data)
                .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        }
        
        // 5. Combine JPEG with EXIF
        let mut final_output = img_buf;
        final_output.extend_from_slice(&output);
        
        Ok(final_output)
    }

    fn extract(&self, data: &[u8]) -> Option<String> {
        let mut cursor = Cursor::new(data);
        let exif_reader = exif::Reader::new();
        let exif_data = exif_reader.read_from_container(&mut cursor).ok()?;
        
        // Try to find UserComment field
        for field in exif_data.fields() {
            if field.tag == exif::Tag::UserComment {
                if let exif::Value::Undefined(bytes, _) = &field.value {
                    // Strip the "ASCII\0\0\0" prefix and convert to string
                    return bytes.get(8..).and_then(|s| String::from_utf8(s.to_vec()).ok());
                }
            }
        }
        None
    }
}
