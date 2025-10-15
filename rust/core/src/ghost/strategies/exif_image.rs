//! # EXIF Image Steganography Strategy
//!
//! Hides data within the UserComment field of a JPEG image's EXIF metadata.

use std::io::Cursor;
use image::{ImageBuffer, Rgb};
use piexif;

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

        // 2. Prepare the EXIF data.
        let mut exif_writer = piexif::ExifWriter::new();
        // The payload must be prefixed with the correct character encoding for the standard.
        let exif_payload = [b"ASCII\0\0\0", payload.as_bytes()].concat();
        let field = piexif::Field {
            tag: piexif::Tag::UserComment,
            ifd_num: piexif::Ifd::Exif,
            value: piexif::Value::Undefined(exif_payload),
        };
        exif_writer.push_field(&field);

        // 3. Write the image with the new EXIF data to a byte buffer.
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageOutputFormat::Jpeg(80))
            .map_err(|e| GhostError::EmbeddingError(e.to_string()))?;
        
        Ok(buf.into_inner())
    }

    fn extract(&self, data: &[u8]) -> Option<String> {
        let exif_reader = piexif::ExifReader::read_from(data).ok()?;
        let user_comment_field = exif_reader.get_field(piexif::Tag::UserComment, piexif::Ifd::Exif)?;
        let comment_bytes = user_comment_field.value.get_undefined()?;
        
        // Strip the "ASCII\0\0\0" prefix and convert to string.
        comment_bytes.get(8..).and_then(|s| String::from_utf8(s.to_vec()).ok())
    }
}