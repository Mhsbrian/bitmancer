// src/protocol.rs
//
// Wire format for the current bitchat protocol, ported from
// localPackages/BitFoundation/Sources/BitFoundation/{BinaryProtocol,MessageType,
// MessagePadding}.swift in permissionlesstech/bitchat.
//
// Frame layout:
//   v1 header (14 bytes): version(1) type(1) ttl(1) timestamp(8, BE ms) flags(1) payloadLen(2, BE)
//   v2 header (16 bytes): same but payloadLen is 4 bytes, and a route section may follow
//   then: senderID(8) [recipientID(8)] [routeCount(1) + hops(8 each)] payload [signature(64)]
//
// When the compressed flag is set, `payloadLen` covers a length-field-sized
// original-size preamble *plus* the compressed bytes.

use crate::compression;

pub const V1_HEADER_SIZE: usize = 14;
pub const V2_HEADER_SIZE: usize = 16;
pub const SENDER_ID_SIZE: usize = 8;
pub const RECIPIENT_ID_SIZE: usize = 8;
pub const SIGNATURE_SIZE: usize = 64;

// Swift caps a framed payload at FileTransferLimits.maxFramedFileBytes; we only
// need a sane upper bound to reject absurd lengths before allocating.
const MAX_FRAMED_PAYLOAD: usize = 8 * 1024 * 1024;

pub const BROADCAST_RECIPIENT: [u8; 8] = [0xFF; 8];

pub mod flags {
    pub const HAS_RECIPIENT: u8 = 0x01;
    pub const HAS_SIGNATURE: u8 = 0x02;
    pub const IS_COMPRESSED: u8 = 0x04;
    pub const HAS_ROUTE: u8 = 0x08;
    pub const IS_RSR: u8 = 0x10;
}

/// Outer packet type byte. Values must track MessageType.swift exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Announce = 0x01,
    Message = 0x02,
    Leave = 0x03,
    CourierEnvelope = 0x04,
    NoiseHandshake = 0x10,
    NoiseEncrypted = 0x11,
    Fragment = 0x20,
    RequestSync = 0x21,
    FileTransfer = 0x22,
    BoardPost = 0x23,
    PrekeyBundle = 0x24,
    GroupMessage = 0x25,
    Ping = 0x26,
    Pong = 0x27,
    NostrCarrier = 0x28,
    VoiceFrame = 0x29,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        use MessageType::*;
        Some(match value {
            0x01 => Announce,
            0x02 => Message,
            0x03 => Leave,
            0x04 => CourierEnvelope,
            0x10 => NoiseHandshake,
            0x11 => NoiseEncrypted,
            0x20 => Fragment,
            0x21 => RequestSync,
            0x22 => FileTransfer,
            0x23 => BoardPost,
            0x24 => PrekeyBundle,
            0x25 => GroupMessage,
            0x26 => Ping,
            0x27 => Pong,
            0x28 => NostrCarrier,
            0x29 => VoiceFrame,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub version: u8,
    pub msg_type: u8,
    pub ttl: u8,
    pub timestamp: u64,
    pub sender_id: [u8; 8],
    pub recipient_id: Option<[u8; 8]>,
    pub payload: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub route: Option<Vec<[u8; 8]>>,
    pub is_rsr: bool,
}

impl Packet {
    pub fn new(msg_type: MessageType, sender_id: [u8; 8], payload: Vec<u8>, ttl: u8) -> Self {
        Self {
            version: 1,
            msg_type: msg_type as u8,
            ttl,
            timestamp: now_millis(),
            sender_id,
            recipient_id: None,
            payload,
            signature: None,
            route: None,
            is_rsr: false,
        }
    }

    pub fn with_recipient(mut self, recipient: [u8; 8]) -> Self {
        self.recipient_id = Some(recipient);
        self
    }

    pub fn parsed_type(&self) -> Option<MessageType> {
        MessageType::from_u8(self.msg_type)
    }

    pub fn sender_hex(&self) -> String {
        hex::encode(self.sender_id)
    }

    pub fn recipient_hex(&self) -> Option<String> {
        self.recipient_id.map(hex::encode)
    }

    pub fn is_broadcast(&self) -> bool {
        match self.recipient_id {
            None => true,
            Some(id) => id == BROADCAST_RECIPIENT,
        }
    }

    /// Canonical bytes covered by the Ed25519 packet signature: the packet
    /// re-encoded with no signature, TTL forced to 0 (it mutates on relay) and
    /// the RSR flag cleared. Swift signs the *padded* encoding, so we do too.
    pub fn signing_bytes(&self) -> Option<Vec<u8>> {
        let unsigned = Packet {
            signature: None,
            ttl: 0,
            is_rsr: false,
            ..self.clone()
        };
        unsigned.encode_with_padding(true)
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        self.encode_with_padding(true)
    }

    /// Encodes the frame. We never set the compressed flag on outbound packets:
    /// signature verification on the peer re-encodes our payload with Apple's
    /// DEFLATE, which would not be byte-identical to ours, and uncompressed
    /// frames are always accepted. Inbound compressed frames are still decoded.
    pub fn encode_with_padding(&self, padding: bool) -> Option<Vec<u8>> {
        if self.version != 1 && self.version != 2 {
            return None;
        }
        let length_field_bytes = if self.version == 2 { 4 } else { 2 };

        let route: Vec<[u8; 8]> = if self.version >= 2 {
            self.route.clone().unwrap_or_default()
        } else {
            Vec::new()
        };
        if route.len() > 255 {
            return None;
        }
        let has_route = !route.is_empty();

        let payload_data_size = self.payload.len();
        if self.version == 1 && payload_data_size > u16::MAX as usize {
            return None;
        }

        let mut data = Vec::with_capacity(V2_HEADER_SIZE + 16 + payload_data_size + 320);
        data.push(self.version);
        data.push(self.msg_type);
        data.push(self.ttl);
        data.extend_from_slice(&self.timestamp.to_be_bytes());

        let mut flag_byte: u8 = 0;
        if self.recipient_id.is_some() {
            flag_byte |= flags::HAS_RECIPIENT;
        }
        if self.signature.is_some() {
            flag_byte |= flags::HAS_SIGNATURE;
        }
        if has_route && self.version >= 2 {
            flag_byte |= flags::HAS_ROUTE;
        }
        if self.is_rsr {
            flag_byte |= flags::IS_RSR;
        }
        data.push(flag_byte);

        if self.version == 2 {
            data.extend_from_slice(&(payload_data_size as u32).to_be_bytes());
        } else {
            data.extend_from_slice(&(payload_data_size as u16).to_be_bytes());
        }
        let _ = length_field_bytes;

        data.extend_from_slice(&self.sender_id);
        if let Some(recipient) = &self.recipient_id {
            data.extend_from_slice(recipient);
        }

        if has_route {
            data.push(route.len() as u8);
            for hop in &route {
                data.extend_from_slice(hop);
            }
        }

        data.extend_from_slice(&self.payload);

        if let Some(signature) = &self.signature {
            data.extend_from_slice(&signature[..SIGNATURE_SIZE.min(signature.len())]);
        }

        if padding {
            let target = optimal_block_size(data.len());
            return Some(pad(data, target));
        }
        Some(data)
    }

    /// Mirrors Swift's `BinaryProtocol.decode`: try the bytes as-is first, then
    /// retry after stripping PKCS#7 padding.
    pub fn decode(data: &[u8]) -> Option<Packet> {
        if let Some(packet) = decode_core(data) {
            return Some(packet);
        }
        let unpadded = unpad(data);
        if unpadded.len() == data.len() {
            return None;
        }
        decode_core(&unpadded)
    }
}

fn decode_core(raw: &[u8]) -> Option<Packet> {
    if raw.len() < V1_HEADER_SIZE + SENDER_ID_SIZE {
        return None;
    }
    let mut offset = 0usize;

    let read_u8 = |offset: &mut usize| -> Option<u8> {
        let value = *raw.get(*offset)?;
        *offset += 1;
        Some(value)
    };
    let read_slice = |offset: &mut usize, n: usize| -> Option<Vec<u8>> {
        let end = offset.checked_add(n)?;
        let slice = raw.get(*offset..end)?.to_vec();
        *offset = end;
        Some(slice)
    };

    let version = read_u8(&mut offset)?;
    if version != 1 && version != 2 {
        return None;
    }
    let length_field_bytes = if version == 2 { 4 } else { 2 };
    let header_size = if version == 2 {
        V2_HEADER_SIZE
    } else {
        V1_HEADER_SIZE
    };
    if raw.len() < header_size + SENDER_ID_SIZE {
        return None;
    }

    let msg_type = read_u8(&mut offset)?;
    let ttl = read_u8(&mut offset)?;

    let timestamp_bytes = read_slice(&mut offset, 8)?;
    let timestamp = u64::from_be_bytes(timestamp_bytes.try_into().ok()?);

    let flag_byte = read_u8(&mut offset)?;
    let has_recipient = flag_byte & flags::HAS_RECIPIENT != 0;
    let has_signature = flag_byte & flags::HAS_SIGNATURE != 0;
    let is_compressed = flag_byte & flags::IS_COMPRESSED != 0;
    let has_route = version >= 2 && flag_byte & flags::HAS_ROUTE != 0;
    let is_rsr = flag_byte & flags::IS_RSR != 0;

    let payload_length = if version == 2 {
        u32::from_be_bytes(read_slice(&mut offset, 4)?.try_into().ok()?) as usize
    } else {
        u16::from_be_bytes(read_slice(&mut offset, 2)?.try_into().ok()?) as usize
    };
    if payload_length > MAX_FRAMED_PAYLOAD {
        return None;
    }

    let sender_id: [u8; 8] = read_slice(&mut offset, SENDER_ID_SIZE)?.try_into().ok()?;

    let recipient_id: Option<[u8; 8]> = if has_recipient {
        Some(read_slice(&mut offset, RECIPIENT_ID_SIZE)?.try_into().ok()?)
    } else {
        None
    };

    // Route bytes sit outside payload_length (v2 only).
    let route = if has_route {
        let hop_count = read_u8(&mut offset)? as usize;
        if hop_count == 0 {
            None
        } else {
            let mut hops = Vec::with_capacity(hop_count);
            for _ in 0..hop_count {
                hops.push(read_slice(&mut offset, SENDER_ID_SIZE)?.try_into().ok()?);
            }
            Some(hops)
        }
    } else {
        None
    };

    let payload = if is_compressed {
        if payload_length < length_field_bytes {
            return None;
        }
        let original_size = if version == 2 {
            u32::from_be_bytes(read_slice(&mut offset, 4)?.try_into().ok()?) as usize
        } else {
            u16::from_be_bytes(read_slice(&mut offset, 2)?.try_into().ok()?) as usize
        };
        if original_size > MAX_FRAMED_PAYLOAD {
            return None;
        }
        let compressed_size = payload_length - length_field_bytes;
        if compressed_size == 0 {
            return None;
        }
        let compressed = read_slice(&mut offset, compressed_size)?;
        // Reject decompression bombs the same way Swift does.
        if original_size as f64 / compressed_size as f64 > 50_000.0 {
            return None;
        }
        let decompressed = compression::decompress(&compressed, original_size).ok()?;
        if decompressed.len() != original_size {
            return None;
        }
        decompressed
    } else {
        read_slice(&mut offset, payload_length)?
    };

    let signature = if has_signature {
        Some(read_slice(&mut offset, SIGNATURE_SIZE)?)
    } else {
        None
    };

    Some(Packet {
        version,
        msg_type,
        ttl,
        timestamp,
        sender_id,
        recipient_id,
        payload,
        signature,
        route,
        is_rsr,
    })
}

// MARK: - Padding (MessagePadding.swift)

const BLOCK_SIZES: [usize; 4] = [256, 512, 1024, 2048];

pub fn optimal_block_size(data_size: usize) -> usize {
    // Swift accounts for a ~16 byte AEAD tag before bucketing.
    let total = data_size + 16;
    for size in BLOCK_SIZES {
        if total <= size {
            return size;
        }
    }
    data_size
}

/// PKCS#7: every pad byte equals the pad length. Swift's `unpad` verifies this,
/// so the random padding the old client emitted was never actually stripped.
pub fn pad(data: Vec<u8>, target_size: usize) -> Vec<u8> {
    if data.len() >= target_size {
        return data;
    }
    let padding_needed = target_size - data.len();
    if padding_needed == 0 || padding_needed > 255 {
        return data;
    }
    let mut padded = data;
    padded.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
    padded
}

pub fn unpad(data: &[u8]) -> Vec<u8> {
    let Some(&last) = data.last() else {
        return data.to_vec();
    };
    let padding_length = last as usize;
    if padding_length == 0 || padding_length > data.len() {
        return data.to_vec();
    }
    let start = data.len() - padding_length;
    if data[start..].iter().any(|&b| b != last) {
        return data.to_vec();
    }
    data[..start].to_vec()
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Converts a 16-hex peer ID into the 8 raw bytes carried in the frame.
pub fn peer_id_to_bytes(peer_id: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    if let Ok(decoded) = hex::decode(peer_id) {
        let n = decoded.len().min(8);
        out[..n].copy_from_slice(&decoded[..n]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_broadcast_v1_packet() {
        let packet = Packet::new(MessageType::Message, [1, 2, 3, 4, 5, 6, 7, 8], b"hello".to_vec(), 7);
        let encoded = packet.encode().unwrap();
        // 14 byte header + 8 sender + 5 payload = 27, padded up to the 256 bucket.
        assert_eq!(encoded.len(), 256);
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.msg_type, MessageType::Message as u8);
        assert_eq!(decoded.ttl, 7);
        assert_eq!(decoded.sender_id, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(decoded.payload, b"hello");
        assert!(decoded.recipient_id.is_none());
        assert!(decoded.signature.is_none());
    }

    #[test]
    fn round_trips_recipient_and_signature() {
        let mut packet = Packet::new(MessageType::NoiseEncrypted, [9; 8], vec![0xAB; 40], 3)
            .with_recipient([7; 8]);
        packet.signature = Some(vec![0x5A; SIGNATURE_SIZE]);
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.recipient_id, Some([7; 8]));
        assert_eq!(decoded.signature.unwrap().len(), SIGNATURE_SIZE);
        assert_eq!(decoded.payload, vec![0xAB; 40]);
    }

    #[test]
    fn header_layout_matches_swift() {
        let packet = Packet::new(MessageType::Announce, [0xAA; 8], vec![0x01], 7);
        let raw = packet.encode_with_padding(false).unwrap();
        assert_eq!(raw[0], 1, "version");
        assert_eq!(raw[1], 0x01, "type");
        assert_eq!(raw[2], 7, "ttl");
        // Flags live at offset 11, after version+type+ttl+timestamp(8).
        assert_eq!(raw[11], 0, "no flags set for an unsigned broadcast");
        assert_eq!(u16::from_be_bytes([raw[12], raw[13]]), 1, "payload length");
        assert_eq!(&raw[14..22], &[0xAA; 8], "sender id");
        assert_eq!(raw.len(), V1_HEADER_SIZE + 8 + 1);
    }

    #[test]
    fn signing_bytes_zero_the_ttl_and_drop_the_signature() {
        let mut packet = Packet::new(MessageType::Announce, [3; 8], b"payload".to_vec(), 7);
        let before = packet.signing_bytes().unwrap();
        packet.signature = Some(vec![0x11; SIGNATURE_SIZE]);
        packet.ttl = 2;
        let after = packet.signing_bytes().unwrap();
        assert_eq!(before, after, "signature and ttl must not affect signed bytes");
        assert_eq!(before[2], 0, "ttl is forced to 0");
        assert_eq!(before[11] & flags::HAS_SIGNATURE, 0);
    }

    #[test]
    fn pkcs7_padding_round_trips() {
        let padded = pad(vec![1, 2, 3], 8);
        assert_eq!(padded, vec![1, 2, 3, 5, 5, 5, 5, 5]);
        assert_eq!(unpad(&padded), vec![1, 2, 3]);
        // Non-conforming trailer is left untouched, matching Swift.
        assert_eq!(unpad(&[1, 2, 3, 9, 5]), vec![1, 2, 3, 9, 5]);
    }

    #[test]
    fn optimal_block_sizes_match_swift_buckets() {
        assert_eq!(optimal_block_size(10), 256);
        assert_eq!(optimal_block_size(240), 256);
        assert_eq!(optimal_block_size(241), 512);
        assert_eq!(optimal_block_size(5000), 5000);
    }

    #[test]
    fn decodes_v2_header_with_route() {
        // Hand-built v2 frame: 16 byte header, 4 byte length, one route hop.
        let mut raw = vec![2u8, MessageType::Message as u8, 5u8];
        raw.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
        raw.push(flags::HAS_ROUTE);
        raw.extend_from_slice(&3u32.to_be_bytes());
        raw.extend_from_slice(&[0xC1; 8]);
        raw.push(1);
        raw.extend_from_slice(&[0xD2; 8]);
        raw.extend_from_slice(b"abc");

        let decoded = Packet::decode(&raw).expect("v2 frame should decode");
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.payload, b"abc");
        assert_eq!(decoded.route, Some(vec![[0xD2; 8]]));
        assert_eq!(decoded.sender_id, [0xC1; 8]);
    }

    // The three cases below are ported from upstream's
    // BinaryProtocolTests.swift "Bounds Checking Tests (Crash Prevention)",
    // which exist because these frames used to crash the Swift decoder.

    #[test]
    fn rejects_a_payload_length_longer_than_the_frame() {
        let mut raw = vec![1u8, 1, 10];
        raw.extend_from_slice(&[0u8; 8]);
        raw.push(0);
        raw.extend_from_slice(&[0x00, 0xC1]); // claims 193 payload bytes
        raw.extend_from_slice(&[0x01; 8]);
        raw.extend_from_slice(&[0x02; 8]); // only 8 provided
        assert_eq!(raw.len(), 30);
        assert!(Packet::decode(&raw).is_none());
    }

    #[test]
    fn rejects_a_compressed_frame_too_short_for_its_size_preamble() {
        let mut raw = vec![1u8, 1, 10];
        raw.extend_from_slice(&[0u8; 8]);
        raw.push(flags::IS_COMPRESSED);
        raw.extend_from_slice(&[0x00, 0x01]); // 1 byte, less than the 2 byte preamble
        raw.extend_from_slice(&[0x01; 8]);
        raw.push(0x99);
        assert!(Packet::decode(&raw).is_none());
    }

    #[test]
    fn survives_truncation_at_every_offset() {
        let mut packet = Packet::new(MessageType::Message, [4; 8], b"payload bytes".to_vec(), 7)
            .with_recipient([6; 8]);
        packet.signature = Some(vec![0x33; SIGNATURE_SIZE]);
        let encoded = packet.encode_with_padding(false).unwrap();
        for end in 0..encoded.len() {
            // Must not panic; a short frame either decodes or is rejected.
            let _ = Packet::decode(&encoded[..end]);
        }
        assert!(Packet::decode(&encoded).is_some());
    }

    #[test]
    fn rejects_unknown_versions() {
        let mut raw = vec![3u8, 0x02, 1];
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.push(0);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&[0; 8]);
        assert!(Packet::decode(&raw).is_none());
    }
}
