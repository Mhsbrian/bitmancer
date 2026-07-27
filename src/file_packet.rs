// src/file_packet.rs
//
// Payload of MessageType::FileTransfer (0x22) — how pictures, voice notes and
// files travel over the mesh itself, as opposed to being linked.
//
// TLV, ported from bitchat/Protocols/BitchatFilePacket.swift:
//
//   0x01 fileName  u16 length + UTF-8
//   0x02 fileSize  u16 length (always 4) + u32 big-endian
//   0x03 mimeType  u16 length + UTF-8
//   0x04 content   u32 length + bytes
//
// `content` is the one field with a 4-byte length; older senders wrote 2, so the
// decoder tries the canonical width first and falls back.

/// Upstream's `FileTransferLimits.maxPayloadBytes`.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

const TLV_FILE_NAME: u8 = 0x01;
const TLV_FILE_SIZE: u8 = 0x02;
const TLV_MIME_TYPE: u8 = 0x03;
const TLV_CONTENT: u8 = 0x04;

#[derive(Debug, Clone, PartialEq)]
pub struct FilePacket {
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub mime_type: Option<String>,
    pub content: Vec<u8>,
}

impl FilePacket {
    /// True when this is something we can display.
    pub fn is_image(&self) -> bool {
        match &self.mime_type {
            Some(mime) => mime.to_lowercase().starts_with("image/"),
            // No mime tag: fall back to the extension, which is all an older
            // sender may give us.
            None => self
                .file_name
                .as_deref()
                .map(|name| {
                    let lowered = name.to_lowercase();
                    ["png", "jpg", "jpeg", "gif", "webp", "bmp"]
                        .iter()
                        .any(|extension| lowered.ends_with(&format!(".{extension}")))
                })
                .unwrap_or(false),
        }
    }

    /// Name to show, falling back to something honest rather than blank.
    pub fn display_name(&self) -> String {
        self.file_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| match &self.mime_type {
                Some(mime) => format!("untitled ({mime})"),
                None => "untitled".to_string(),
            })
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.content.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        let mut out = Vec::with_capacity(self.content.len() + 32);

        if let Some(name) = &self.file_name {
            let bytes = name.as_bytes();
            if bytes.len() <= u16::MAX as usize {
                out.push(TLV_FILE_NAME);
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }

        let size = self.file_size.unwrap_or(self.content.len() as u64);
        if size > u32::MAX as u64 {
            return None;
        }
        out.push(TLV_FILE_SIZE);
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&(size as u32).to_be_bytes());

        if let Some(mime) = &self.mime_type {
            let bytes = mime.as_bytes();
            if bytes.len() <= u16::MAX as usize {
                out.push(TLV_MIME_TYPE);
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }

        out.push(TLV_CONTENT);
        out.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.content);
        Some(out)
    }

    pub fn decode(data: &[u8]) -> Option<FilePacket> {
        let mut cursor = 0usize;
        let mut file_name = None;
        let mut file_size = None;
        let mut mime_type = None;
        let mut content = Vec::new();

        while cursor < data.len() {
            let tlv_type = data[cursor];
            cursor += 1;

            let length = if tlv_type == TLV_CONTENT {
                // Canonical width is 4; older senders used 2. Accept the wide
                // form only when it actually fits the remaining bytes.
                let wide = read_be(data, cursor, 4);
                match wide {
                    Some(value) if value <= data.len().saturating_sub(cursor + 4) => {
                        cursor += 4;
                        Some(value)
                    }
                    _ => {
                        let narrow = read_be(data, cursor, 2)?;
                        cursor += 2;
                        Some(narrow)
                    }
                }
            } else {
                let value = read_be(data, cursor, 2)?;
                cursor += 2;
                Some(value)
            }?;

            let end = cursor.checked_add(length)?;
            if end > data.len() {
                return None;
            }
            let value = &data[cursor..end];
            cursor = end;

            match tlv_type {
                TLV_FILE_NAME => file_name = String::from_utf8(value.to_vec()).ok(),
                TLV_FILE_SIZE => file_size = read_be(value, 0, value.len()).map(|v| v as u64),
                TLV_MIME_TYPE => mime_type = String::from_utf8(value.to_vec()).ok(),
                TLV_CONTENT => {
                    if value.len() > MAX_PAYLOAD_BYTES {
                        return None;
                    }
                    content = value.to_vec();
                }
                // Unknown tags are skipped, so a newer sender does not break us.
                _ => {}
            }
        }

        // A file packet with no bytes is not a file.
        if content.is_empty() {
            return None;
        }
        Some(FilePacket {
            file_name,
            file_size,
            mime_type,
            content,
        })
    }
}

fn read_be(data: &[u8], offset: usize, width: usize) -> Option<usize> {
    if width == 0 || width > 8 || offset + width > data.len() {
        return None;
    }
    let mut value: u64 = 0;
    for byte in &data[offset..offset + width] {
        value = (value << 8) | *byte as u64;
    }
    usize::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FilePacket {
        FilePacket {
            file_name: Some("cat.png".into()),
            file_size: Some(4),
            mime_type: Some("image/png".into()),
            content: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn round_trips() {
        let encoded = sample().encode().expect("encodes");
        assert_eq!(FilePacket::decode(&encoded), Some(sample()));
    }

    #[test]
    fn content_uses_a_four_byte_length() {
        let encoded = sample().encode().unwrap();
        // Find the content tag and check the width that follows it.
        let position = encoded
            .windows(5)
            .position(|window| window[0] == TLV_CONTENT && window[1..5] == [0, 0, 0, 4])
            .expect("canonical 4-byte content length");
        assert!(position > 0);
    }

    #[test]
    fn accepts_the_legacy_two_byte_content_length() {
        // An older sender writes the content length in two bytes.
        let mut legacy = Vec::new();
        legacy.push(TLV_MIME_TYPE);
        legacy.extend_from_slice(&9u16.to_be_bytes());
        legacy.extend_from_slice(b"image/png");
        legacy.push(TLV_CONTENT);
        legacy.extend_from_slice(&4u16.to_be_bytes());
        legacy.extend_from_slice(&[9, 8, 7, 6]);

        let decoded = FilePacket::decode(&legacy).expect("legacy form decodes");
        assert_eq!(decoded.content, vec![9, 8, 7, 6]);
        assert_eq!(decoded.mime_type.as_deref(), Some("image/png"));
    }

    #[test]
    fn unknown_tags_are_skipped() {
        let mut data = sample().encode().unwrap();
        // A tag from a future version, inserted at the front.
        let mut extended = vec![0x7F];
        extended.extend_from_slice(&3u16.to_be_bytes());
        extended.extend_from_slice(b"new");
        extended.append(&mut data);
        assert_eq!(FilePacket::decode(&extended), Some(sample()));
    }

    #[test]
    fn rejects_truncated_and_empty_payloads() {
        let encoded = sample().encode().unwrap();
        for cut in 1..encoded.len() {
            // Must never panic; may reject.
            let _ = FilePacket::decode(&encoded[..cut]);
        }
        assert!(FilePacket::decode(&[]).is_none());
        // Metadata but no content is not a file.
        let mut only_name = vec![TLV_FILE_NAME];
        only_name.extend_from_slice(&3u16.to_be_bytes());
        only_name.extend_from_slice(b"abc");
        assert!(FilePacket::decode(&only_name).is_none());
    }

    #[test]
    fn rejects_a_declared_length_beyond_the_buffer() {
        // The classic overflow: claim 60000 bytes, provide four.
        let mut hostile = vec![TLV_CONTENT];
        hostile.extend_from_slice(&60000u32.to_be_bytes());
        hostile.extend_from_slice(&[1, 2, 3, 4]);
        assert!(FilePacket::decode(&hostile).is_none());
    }

    #[test]
    fn refuses_to_encode_beyond_the_payload_cap() {
        let oversized = FilePacket {
            file_name: None,
            file_size: None,
            mime_type: None,
            content: vec![0u8; MAX_PAYLOAD_BYTES + 1],
        };
        assert!(oversized.encode().is_none());
    }

    #[test]
    fn identifies_images_by_mime_then_extension() {
        assert!(sample().is_image());

        let by_extension = FilePacket {
            mime_type: None,
            file_name: Some("photo.JPEG".into()),
            ..sample()
        };
        assert!(by_extension.is_image());

        let not_an_image = FilePacket {
            mime_type: Some("audio/mp4".into()),
            file_name: Some("note.m4a".into()),
            ..sample()
        };
        assert!(!not_an_image.is_image());

        let unknowable = FilePacket {
            mime_type: None,
            file_name: None,
            ..sample()
        };
        assert!(!unknowable.is_image());
    }

    #[test]
    fn display_name_is_never_blank() {
        assert_eq!(sample().display_name(), "cat.png");
        let unnamed = FilePacket {
            file_name: Some("   ".into()),
            ..sample()
        };
        assert_eq!(unnamed.display_name(), "untitled (image/png)");
        let bare = FilePacket {
            file_name: None,
            mime_type: None,
            ..sample()
        };
        assert_eq!(bare.display_name(), "untitled");
    }
}
