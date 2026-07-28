// src/noise_payload.rs
//
// What rides inside an encrypted frame.
//
// A Noise session hands back a byte string, not a message. Upstream puts a
// single type byte in front of the plaintext so one encrypted channel can carry
// chat, read receipts and delivery acknowledgements without standing up a
// second handshake for each.
//
// The byte matters more than it looks: decode it wrong and a delivery
// acknowledgement is rendered to the user as an empty chat line from someone
// they were talking to. Unknown types are dropped rather than guessed at,
// because a type we do not recognise is a type whose body we cannot parse.

/// The kinds of payload an encrypted 0x11 frame can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePayloadType {
    PrivateMessage = 0x01,
    ReadReceipt = 0x02,
    Delivered = 0x03,
}

impl NoisePayloadType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::PrivateMessage),
            0x02 => Some(Self::ReadReceipt),
            0x03 => Some(Self::Delivered),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoisePayload {
    pub kind: NoisePayloadType,
    pub body: Vec<u8>,
}

impl NoisePayload {
    pub fn private_message(text: &str) -> Self {
        Self {
            kind: NoisePayloadType::PrivateMessage,
            body: text.as_bytes().to_vec(),
        }
    }

    /// A receipt names the message it is about, so the sender can tick the
    /// right line rather than the most recent one.
    pub fn receipt(kind: NoisePayloadType, message_id: &str) -> Self {
        Self {
            kind,
            body: message_id.as_bytes().to_vec(),
        }
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

    /// The body as text, when it is text at all. A peer sending invalid UTF-8
    /// is a peer we cannot render, not one we should panic over.
    pub fn text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_message_survives_the_round_trip() {
        let payload = NoisePayload::private_message("meet at the docks");
        let decoded = NoisePayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.text().unwrap(), "meet at the docks");
    }

    #[test]
    fn the_type_byte_leads() {
        // The wire order is what the other implementation reads; a body-first
        // encoding would decode as whatever the first character happens to be.
        assert_eq!(NoisePayload::private_message("hi").encode()[0], 0x01);
        assert_eq!(
            NoisePayload::receipt(NoisePayloadType::Delivered, "abc").encode()[0],
            0x03
        );
    }

    #[test]
    fn every_known_type_decodes_to_itself() {
        for kind in [
            NoisePayloadType::PrivateMessage,
            NoisePayloadType::ReadReceipt,
            NoisePayloadType::Delivered,
        ] {
            assert_eq!(NoisePayloadType::from_byte(kind as u8), Some(kind));
        }
    }

    #[test]
    fn an_unknown_type_is_dropped_rather_than_guessed() {
        // A future payload type whose body we cannot parse must not be shown
        // to the user as if it were chat.
        assert!(NoisePayload::decode(&[0x7f, b'h', b'i']).is_none());
        assert!(NoisePayloadType::from_byte(0x00).is_none());
    }

    #[test]
    fn an_empty_frame_is_not_a_payload() {
        assert!(NoisePayload::decode(&[]).is_none());
    }

    #[test]
    fn a_type_byte_alone_is_a_valid_empty_payload() {
        // A read receipt carrying no id is malformed but decodable; the layer
        // above decides what to do with it.
        let decoded = NoisePayload::decode(&[0x02]).unwrap();
        assert_eq!(decoded.kind, NoisePayloadType::ReadReceipt);
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn invalid_utf8_reports_as_untextual_instead_of_panicking() {
        let payload = NoisePayload {
            kind: NoisePayloadType::PrivateMessage,
            body: vec![0xff, 0xfe],
        };
        assert!(payload.text().is_none());
    }
}
