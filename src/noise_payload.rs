// src/noise_payload.rs
//
// What rides inside an encrypted frame.
//
// A Noise session hands back a byte string, not a message. Upstream puts a
// single type byte in front of the plaintext so one encrypted channel can carry
// chat, receipts, verification and file transfer without standing up a separate
// handshake for each.
//
// Two things here were verified against upstream source rather than inferred,
// because both were wrong when guessed at:
//
//   * The type byte has eleven values, not three. Decoding only the chat types
//     silently discards voice, private files, verification challenges and the
//     group payloads.
//   * A private message is not raw text. It is a TLV record carrying a message
//     ID alongside the content, and the ID is what a read receipt refers back
//     to. Sending raw text talks only to other clients making the same mistake.
//
// Reference: bitchat/Protocols/BitchatProtocol.swift (NoisePayloadType) and
// bitchat/Protocols/Packets.swift (PrivateMessagePacket).

/// The kinds of payload an encrypted 0x11 frame can carry.
///
/// Values are taken verbatim from upstream's `NoisePayloadType`. The gaps in
/// the numbering are upstream's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePayloadType {
    PrivateMessage = 0x01,
    ReadReceipt = 0x02,
    Delivered = 0x03,
    GroupInvite = 0x06,
    GroupKeyUpdate = 0x07,
    VoiceFrame = 0x08,
    VerifyChallenge = 0x10,
    VerifyResponse = 0x11,
    Vouch = 0x12,
    PrivateFile = 0x20,
    AuthenticatedPeerState = 0x21,
}

impl NoisePayloadType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::PrivateMessage),
            0x02 => Some(Self::ReadReceipt),
            0x03 => Some(Self::Delivered),
            0x06 => Some(Self::GroupInvite),
            0x07 => Some(Self::GroupKeyUpdate),
            0x08 => Some(Self::VoiceFrame),
            0x10 => Some(Self::VerifyChallenge),
            0x11 => Some(Self::VerifyResponse),
            0x12 => Some(Self::Vouch),
            0x20 => Some(Self::PrivateFile),
            0x21 => Some(Self::AuthenticatedPeerState),
            _ => None,
        }
    }

    /// What to call this in a trace. Payload kinds we decode but do not act on
    /// should still be nameable, or `/debug` reports a number.
    pub fn label(self) -> &'static str {
        match self {
            Self::PrivateMessage => "private message",
            Self::ReadReceipt => "read receipt",
            Self::Delivered => "delivery ack",
            Self::GroupInvite => "group invite",
            Self::GroupKeyUpdate => "group key update",
            Self::VoiceFrame => "voice frame",
            Self::VerifyChallenge => "verify challenge",
            Self::VerifyResponse => "verify response",
            Self::Vouch => "vouch",
            Self::PrivateFile => "private file",
            Self::AuthenticatedPeerState => "peer state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoisePayload {
    pub kind: NoisePayloadType,
    pub body: Vec<u8>,
}

impl NoisePayload {
    pub fn new(kind: NoisePayloadType, body: Vec<u8>) -> Self {
        Self { kind, body }
    }

    /// A receipt naming the message it is about.
    ///
    /// Over the mesh a receipt body is just the message ID as UTF-8 — not the
    /// richer `ReadReceipt` record with reader ID and timestamp, which is a
    /// different form used elsewhere. Verified against upstream's
    /// `BLENoisePayloadFactory.readReceipt`, whose whole body is
    /// `Data(originalMessageID.utf8)`, and against the decoder, which reads it
    /// straight back with `String(data:encoding:.utf8)`.
    pub fn receipt(kind: NoisePayloadType, message_id: &str) -> Self {
        Self {
            kind,
            body: message_id.as_bytes().to_vec(),
        }
    }

    /// The body as a message ID, when it is one.
    pub fn message_id(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.body.len());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (first, rest) = bytes.split_first()?;
        Some(Self {
            kind: NoisePayloadType::from_byte(*first)?,
            body: rest.to_vec(),
        })
    }
}

/// The largest a TLV value can be: the length prefix is a single byte.
pub const MAX_TLV_VALUE: usize = 255;

const TLV_MESSAGE_ID: u8 = 0x00;
const TLV_CONTENT: u8 = 0x01;

/// The body of a `PrivateMessage` payload.
///
/// `[type u8][length u8][value]`, the same TLV shape the announce uses. Both
/// fields are mandatory — upstream's decoder returns nil when either is absent,
/// so a record missing one is not a partial message, it is not a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateMessagePacket {
    pub message_id: String,
    pub content: String,
}

impl PrivateMessagePacket {
    /// A new message with a fresh identifier. The ID is what a read receipt or
    /// delivery acknowledgement points back at, so it has to be generated by
    /// the sender and carried on the wire.
    pub fn new(content: &str) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            content: content.to_string(),
        }
    }

    /// Encodes, or `None` when either field exceeds what a one-byte length can
    /// describe. Truncating silently would deliver a different message than the
    /// user typed.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let id = self.message_id.as_bytes();
        let content = self.content.as_bytes();
        if id.len() > MAX_TLV_VALUE || content.len() > MAX_TLV_VALUE {
            return None;
        }
        let mut data = Vec::with_capacity(4 + id.len() + content.len());
        push_tlv(&mut data, TLV_MESSAGE_ID, id);
        push_tlv(&mut data, TLV_CONTENT, content);
        Some(data)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut offset = 0usize;
        let mut message_id: Option<String> = None;
        let mut content: Option<String> = None;

        while offset + 2 <= bytes.len() {
            let tlv_type = bytes[offset];
            let length = bytes[offset + 1] as usize;
            offset += 2;
            if offset + length > bytes.len() {
                return None;
            }
            let value = &bytes[offset..offset + length];
            offset += length;

            match tlv_type {
                TLV_MESSAGE_ID => message_id = Some(String::from_utf8(value.to_vec()).ok()?),
                TLV_CONTENT => content = Some(String::from_utf8(value.to_vec()).ok()?),
                // Upstream aborts the whole decode on a type it does not know
                // rather than skipping the field. Matching that matters: a
                // record we half-understand is one we would render wrongly.
                _ => return None,
            }
        }

        Some(Self {
            message_id: message_id?,
            content: content?,
        })
    }
}

fn push_tlv(data: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
    data.push(tlv_type);
    data.push(value.len() as u8);
    data.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_upstream_payload_type_round_trips() {
        // The eleven values are upstream's, gaps included. Decoding only the
        // three chat types silently discarded the other eight.
        for (byte, kind) in [
            (0x01, NoisePayloadType::PrivateMessage),
            (0x02, NoisePayloadType::ReadReceipt),
            (0x03, NoisePayloadType::Delivered),
            (0x06, NoisePayloadType::GroupInvite),
            (0x07, NoisePayloadType::GroupKeyUpdate),
            (0x08, NoisePayloadType::VoiceFrame),
            (0x10, NoisePayloadType::VerifyChallenge),
            (0x11, NoisePayloadType::VerifyResponse),
            (0x12, NoisePayloadType::Vouch),
            (0x20, NoisePayloadType::PrivateFile),
            (0x21, NoisePayloadType::AuthenticatedPeerState),
        ] {
            assert_eq!(NoisePayloadType::from_byte(byte), Some(kind));
            assert_eq!(kind as u8, byte);
        }
    }

    #[test]
    fn the_gaps_in_the_numbering_stay_unknown() {
        for byte in [0x00, 0x04, 0x05, 0x09, 0x0f, 0x13, 0x1f, 0x22, 0xff] {
            assert!(
                NoisePayloadType::from_byte(byte).is_none(),
                "0x{byte:02x} is not an upstream type"
            );
        }
    }

    #[test]
    fn the_type_byte_leads_the_payload() {
        let payload = NoisePayload::new(NoisePayloadType::Delivered, b"abc".to_vec());
        assert_eq!(payload.encode()[0], 0x03);
        assert_eq!(NoisePayload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn a_private_message_is_tlv_not_raw_text() {
        // The bug this module was rewritten for: raw text on the wire is
        // readable only by another client making the same mistake.
        let packet = PrivateMessagePacket::new("meet at the docks");
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded[0], TLV_MESSAGE_ID);
        assert_eq!(encoded[1] as usize, packet.message_id.len());
        let decoded = PrivateMessagePacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet);
        assert_eq!(decoded.content, "meet at the docks");
    }

    #[test]
    fn each_message_carries_its_own_identifier() {
        // A receipt names the message it acknowledges, so two messages sharing
        // an ID would tick the wrong line.
        let first = PrivateMessagePacket::new("one");
        let second = PrivateMessagePacket::new("two");
        assert_ne!(first.message_id, second.message_id);
        assert!(!first.message_id.is_empty());
    }

    #[test]
    fn a_record_missing_either_field_is_not_a_message() {
        // Upstream's decoder returns nil rather than a partial record.
        let mut only_id = Vec::new();
        push_tlv(&mut only_id, TLV_MESSAGE_ID, b"abc");
        assert!(PrivateMessagePacket::decode(&only_id).is_none());

        let mut only_content = Vec::new();
        push_tlv(&mut only_content, TLV_CONTENT, b"hello");
        assert!(PrivateMessagePacket::decode(&only_content).is_none());
    }

    #[test]
    fn an_unknown_tlv_type_fails_the_whole_record() {
        // Upstream aborts instead of skipping. Skipping would render a record
        // we only half understand.
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_MESSAGE_ID, b"abc");
        push_tlv(&mut data, TLV_CONTENT, b"hello");
        push_tlv(&mut data, 0x7f, b"future");
        assert!(PrivateMessagePacket::decode(&data).is_none());
    }

    #[test]
    fn a_truncated_value_is_refused() {
        // Length says ten bytes, three follow.
        assert!(PrivateMessagePacket::decode(&[TLV_CONTENT, 10, b'a', b'b', b'c']).is_none());
    }

    #[test]
    fn content_too_long_for_a_one_byte_length_is_refused_not_truncated() {
        let packet = PrivateMessagePacket {
            message_id: "id".to_string(),
            content: "x".repeat(MAX_TLV_VALUE + 1),
        };
        assert!(
            packet.encode().is_none(),
            "truncating would send different words than the user typed"
        );
    }

    #[test]
    fn content_at_the_limit_still_encodes() {
        let packet = PrivateMessagePacket {
            message_id: "id".to_string(),
            content: "x".repeat(MAX_TLV_VALUE),
        };
        let encoded = packet.encode().unwrap();
        assert_eq!(PrivateMessagePacket::decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn an_empty_frame_is_not_a_payload() {
        assert!(NoisePayload::decode(&[]).is_none());
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn a_mesh_receipt_body_is_the_bare_message_id() {
        // Upstream's BLENoisePayloadFactory sends Data(messageID.utf8) and
        // nothing else. The 49-byte ReadReceipt record is a different form; if
        // we sent that here the peer would read it as a nonsense id.
        let id = "3F2504E0-4F89-11D3-9A0C-0305E82C3301";
        let payload = NoisePayload::receipt(NoisePayloadType::ReadReceipt, id);
        assert_eq!(payload.body, id.as_bytes());
        assert_eq!(payload.encode()[0], 0x02);
        assert_eq!(payload.encode().len(), 1 + id.len());
    }

    #[test]
    fn a_receipt_round_trips_through_the_type_byte() {
        for kind in [NoisePayloadType::ReadReceipt, NoisePayloadType::Delivered] {
            let payload = NoisePayload::receipt(kind, "abc-123");
            let decoded = NoisePayload::decode(&payload.encode()).unwrap();
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.message_id().unwrap(), "abc-123");
        }
    }

    #[test]
    fn a_non_utf8_receipt_body_is_not_an_id() {
        let payload = NoisePayload::new(NoisePayloadType::Delivered, vec![0xff, 0xfe]);
        assert!(payload.message_id().is_none());
    }
}
