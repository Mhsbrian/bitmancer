// src/nostr/carrier.rs
//
// A whole signed Nostr event, ferried over Bluetooth.
//
// This is the wire format between a mesh-only peer and a gateway. A peer with no
// data signs its geohash event locally and hands the finished event to a gateway
// to publish; the gateway hands back what the relays send it. The event travels
// as JSON because that is exactly what a relay wants and what a signature covers
// — re-encoding it any other way would mean rebuilding it byte-identically at the
// far end, and getting that wrong invalidates the signature silently.
//
// Two things here differ from every other TLV in this codebase and both are easy
// to get wrong:
//
//   - lengths are **2 bytes, big-endian**, because an event JSON blob does not
//     fit in the one-byte length the smaller packets use;
//   - unknown TLV types are **skipped**, not fatal, unlike `PrivateMessagePacket`
//     where an unrecognised record aborts the whole thing.
//
// Verified against `NostrCarrierPacket.swift`.

/// Which way an event is travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A mesh-only peer asking us to publish. Rides a *directed* packet.
    ToGateway = 0x01,
    /// A gateway handing the mesh what the relays sent. Rides a *broadcast*.
    FromGateway = 0x02,
    /// The same pair for island-to-island bridging, which we do not do. Decoded
    /// so bridge traffic is recognised and ignored rather than mistaken for
    /// something addressed to us.
    ToBridge = 0x03,
    FromBridge = 0x04,
}

impl Direction {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::ToGateway),
            0x02 => Some(Self::FromGateway),
            0x03 => Some(Self::ToBridge),
            0x04 => Some(Self::FromBridge),
            _ => None,
        }
    }
}

/// Airtime ceiling for one carried event, matching upstream.
pub const MAX_EVENT_JSON_BYTES: usize = 16 * 1024;
pub const MAX_GEOHASH_LENGTH: usize = 12;

const TLV_DIRECTION: u8 = 0x01;
const TLV_GEOHASH: u8 = 0x02;
const TLV_EVENT_JSON: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub direction: Direction,
    pub geohash: String,
    /// The complete signed event, as the relay would see it. Kept as text
    /// rather than parsed so the bytes the signature covers survive the trip.
    pub event_json: String,
}

impl Carrier {
    /// Builds a carrier, or `None` when it could never be delivered.
    pub fn new(direction: Direction, geohash: &str, event_json: &str) -> Option<Self> {
        if geohash.is_empty()
            || geohash.len() > MAX_GEOHASH_LENGTH
            || event_json.is_empty()
            || event_json.len() > MAX_EVENT_JSON_BYTES
        {
            return None;
        }
        Some(Self {
            direction,
            geohash: geohash.to_string(),
            event_json: event_json.to_string(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.event_json.len() + self.geohash.len() + 12);
        push_tlv(&mut data, TLV_DIRECTION, &[self.direction as u8]);
        push_tlv(&mut data, TLV_GEOHASH, self.geohash.as_bytes());
        push_tlv(&mut data, TLV_EVENT_JSON, self.event_json.as_bytes());
        data
    }

    /// Reads a carrier. All three fields are required, and trailing bytes are
    /// refused: a record that does not account for every byte it was given is
    /// one we have misunderstood.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0usize;
        let mut direction = None;
        let mut geohash: Option<String> = None;
        let mut event_json: Option<String> = None;

        while offset + 3 <= data.len() {
            let tag = data[offset];
            // Two bytes, big-endian — the one place in this codebase that is so.
            let length = ((data[offset + 1] as usize) << 8) | data[offset + 2] as usize;
            offset += 3;
            let end = offset.checked_add(length)?;
            if end > data.len() {
                return None;
            }
            let value = &data[offset..end];
            offset = end;

            match tag {
                TLV_DIRECTION => {
                    if value.len() != 1 {
                        return None;
                    }
                    direction = Some(Direction::from_byte(value[0])?);
                }
                TLV_GEOHASH => geohash = Some(String::from_utf8(value.to_vec()).ok()?),
                TLV_EVENT_JSON => event_json = Some(String::from_utf8(value.to_vec()).ok()?),
                // Skipped rather than fatal, so a future field does not make the
                // whole carrier unreadable.
                _ => {}
            }
        }

        if offset != data.len() {
            return None;
        }
        Self::new(direction?, &geohash?, &event_json?)
    }

    /// The event inside, parsed but *not* trusted. Every caller must check the
    /// signature before publishing or displaying it: the whole reason a gateway
    /// is safe to use is that it cannot alter what it carries undetected, and
    /// that only holds if the far end actually looks.
    pub fn event(&self) -> Option<crate::nostr::event::Event> {
        serde_json::from_str(&self.event_json).ok()
    }
}

fn push_tlv(data: &mut Vec<u8>, tag: u8, value: &[u8]) {
    data.push(tag);
    data.push((value.len() >> 8) as u8);
    data.push((value.len() & 0xFF) as u8);
    data.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey, SECP256K1};

    fn signed_event() -> crate::nostr::event::Event {
        let secret = SecretKey::from_byte_array([7u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        crate::nostr::event::Event::signed(
            &keypair,
            1_700_000_000,
            crate::nostr::event::KIND_EPHEMERAL,
            crate::nostr::event::geohash_tags("9q", Some("phone"), false),
            "sent from a phone with no data".into(),
        )
    }

    #[test]
    fn a_carried_event_survives_with_its_signature_intact() {
        // The point of the whole exercise. If the JSON does not come back
        // byte-identical the signature stops verifying, and it fails at the
        // relay rather than here.
        let event = signed_event();
        let json = serde_json::to_string(&event).unwrap();
        let carrier = Carrier::new(Direction::ToGateway, "9q", &json).unwrap();

        let read = Carrier::decode(&carrier.encode()).expect("our own carrier parses");
        assert_eq!(read, carrier);
        let arrived = read.event().expect("the event parses");
        assert_eq!(arrived, event);
        assert!(arrived.verify(), "and still verifies after the trip");
    }

    #[test]
    fn lengths_are_two_bytes_big_endian() {
        // Every other TLV in this codebase uses one byte, and the bit encoding
        // next door is little-endian. Pinning this as literal bytes is the only
        // way the difference stays deliberate.
        let carrier = Carrier::new(Direction::FromGateway, "9q", "x").unwrap();
        let bytes = carrier.encode();
        assert_eq!(&bytes[0..4], &[TLV_DIRECTION, 0x00, 0x01, 0x02]);
        assert_eq!(&bytes[4..7], &[TLV_GEOHASH, 0x00, 0x02]);
    }

    #[test]
    fn a_payload_longer_than_one_byte_can_describe_round_trips() {
        // The reason the lengths are two bytes at all: a real event JSON is
        // several hundred bytes and a one-byte length would truncate it.
        let long = "y".repeat(4096);
        let json = format!("{{\"content\":\"{long}\"}}");
        assert!(json.len() > 255);
        let carrier = Carrier::new(Direction::FromGateway, "9q8yy", &json).unwrap();
        let read = Carrier::decode(&carrier.encode()).unwrap();
        assert_eq!(read.event_json, json);
    }

    #[test]
    fn every_direction_round_trips() {
        for direction in [
            Direction::ToGateway,
            Direction::FromGateway,
            Direction::ToBridge,
            Direction::FromBridge,
        ] {
            let carrier = Carrier::new(direction, "9q", "{}").unwrap();
            assert_eq!(Carrier::decode(&carrier.encode()).unwrap().direction, direction);
        }
    }

    #[test]
    fn an_unknown_direction_is_refused() {
        let mut bytes = Carrier::new(Direction::ToGateway, "9q", "{}").unwrap().encode();
        bytes[3] = 0x7F;
        assert!(Carrier::decode(&bytes).is_none());
    }

    #[test]
    fn an_unknown_field_is_skipped_not_fatal() {
        // Unlike PrivateMessagePacket, where an unrecognised record aborts the
        // whole thing. Upstream is tolerant here for forward compatibility, and
        // being stricter would make us unable to read a future client at all.
        let carrier = Carrier::new(Direction::ToGateway, "9q", "{}").unwrap();
        let mut bytes = carrier.encode();
        push_tlv(&mut bytes, 0x7E, b"something we have never heard of");
        let read = Carrier::decode(&bytes).expect("still readable");
        assert_eq!(read.geohash, "9q");
        assert_eq!(read.direction, Direction::ToGateway);
    }

    #[test]
    fn a_missing_field_is_refused() {
        let mut only_direction = Vec::new();
        push_tlv(&mut only_direction, TLV_DIRECTION, &[0x01]);
        assert!(Carrier::decode(&only_direction).is_none());

        let mut no_event = Vec::new();
        push_tlv(&mut no_event, TLV_DIRECTION, &[0x01]);
        push_tlv(&mut no_event, TLV_GEOHASH, b"9q");
        assert!(Carrier::decode(&no_event).is_none());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // A record that does not account for every byte it was handed is one we
        // have misunderstood, and guessing is how a parser gets used as a way in.
        let mut bytes = Carrier::new(Direction::ToGateway, "9q", "{}").unwrap().encode();
        bytes.push(0x00);
        assert!(Carrier::decode(&bytes).is_none());
    }

    #[test]
    fn a_truncated_length_is_refused() {
        let bytes = Carrier::new(Direction::ToGateway, "9q", "{}").unwrap().encode();
        for cut in 1..bytes.len() {
            // Cutting anywhere leaves either a short value or a missing field.
            assert!(
                Carrier::decode(&bytes[..cut]).is_none(),
                "truncating to {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn nothing_undeliverable_is_built() {
        assert!(Carrier::new(Direction::ToGateway, "", "{}").is_none());
        assert!(Carrier::new(Direction::ToGateway, "9q", "").is_none());
        assert!(
            Carrier::new(Direction::ToGateway, &"9".repeat(MAX_GEOHASH_LENGTH + 1), "{}").is_none()
        );
        assert!(Carrier::new(
            Direction::ToGateway,
            "9q",
            &"x".repeat(MAX_EVENT_JSON_BYTES + 1)
        )
        .is_none());
    }

    #[test]
    fn rubbish_does_not_panic() {
        for bytes in [
            vec![],
            vec![0x01],
            vec![0x01, 0x00],
            vec![0x01, 0xFF, 0xFF],
            vec![0xFF; 32],
        ] {
            let _ = Carrier::decode(&bytes);
        }
    }
}
