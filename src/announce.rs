// src/announce.rs
//
// Port of `AnnouncementPacket` from bitchat/Protocols/Packets.swift.
//
// An announce payload is a TLV blob and the enclosing packet is Ed25519-signed.
// The receiving side (BLEAnnounceHandler) requires all of: a decodable TLV set
// with nickname + noise key + signing key, a sender ID equal to the peer ID
// derived from the announced noise key, and a valid signature. Anything else is
// dropped with "no backward compatibility".

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::protocol::Packet;

const TLV_NICKNAME: u8 = 0x01;
const TLV_NOISE_PUBLIC_KEY: u8 = 0x02;
const TLV_SIGNING_PUBLIC_KEY: u8 = 0x03;
const TLV_DIRECT_NEIGHBORS: u8 = 0x04;
const TLV_CAPABILITIES: u8 = 0x05;
const TLV_BRIDGE_GEOHASH: u8 = 0x06;

/// Keeping the announce payload under the 100-byte compression threshold means
/// neither side ever compresses it, so our canonical signing bytes and the
/// peer's re-encoded verification bytes are guaranteed to be identical. The
/// three mandatory TLVs cost 70 bytes, so the nickname gets the rest.
///
/// The entropy half of `should_compress` does not protect us here: an announce
/// is mostly two random public keys, so it comfortably passes the
/// low-entropy test and *would* be compressed the moment it reached 100 bytes.
/// Length is the only guard, which is why there is a test on it.
pub const MAX_NICKNAME_BYTES: usize = 24;

/// Feature bits a peer advertises about itself.
///
/// Encoded little-endian and minimally — the low byte first, trailing zero
/// bytes dropped — so the common case of one or two interesting bits costs one
/// byte on an announce that has very little room to spare. Always at least one
/// byte, because upstream distinguishes "advertises nothing" from "does not
/// speak capabilities at all", and those mean different things: the first is a
/// current client with everything off, the second is an old one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities(u64);

impl Capabilities {
    // Named in full because the wire assignments are a contract: a bit we
    // cannot act on still has to be decodable, and must never be reused for
    // something else. Only the ones with behaviour behind them are advertised.
    #[allow(dead_code)]
    pub const PREKEYS: u64 = 1 << 0;
    #[allow(dead_code)]
    pub const WIFI_BULK: u64 = 1 << 1;
    /// Shares its internet with the mesh: publishes geohash events deposited by
    /// mesh-only peers and rebroadcasts inbound relay events to them.
    pub const GATEWAY: u64 = 1 << 2;
    #[allow(dead_code)]
    pub const GROUPS: u64 = 1 << 3;
    #[allow(dead_code)]
    pub const BOARD: u64 = 1 << 4;
    #[allow(dead_code)]
    pub const VOUCH: u64 = 1 << 5;
    #[allow(dead_code)]
    pub const MESH_DIAGNOSTICS: u64 = 1 << 6;
    /// Bridges one mesh island to another through a geohash rendezvous cell.
    /// Advertised alongside `bridge_geohash`.
    #[allow(dead_code)]
    pub const BRIDGE: u64 = 1 << 7;
    #[allow(dead_code)]
    pub const PRIVATE_MEDIA: u64 = 1 << 8;
    #[allow(dead_code)]
    pub const PRIVATE_MEDIA_RECEIPTS: u64 = 1 << 9;
    /// Reserved: briefly advertised by test builds. Kept decodable so the wire
    /// assignment is never reused, and deliberately never set.
    #[allow(dead_code)]
    pub const RESERVED_NOISE_REPLACEMENT: u64 = 1 << 10;

    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[allow(dead_code)]
    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn has(&self, bit: u64) -> bool {
        self.0 & bit == bit
    }

    pub fn with(self, bit: u64) -> Self {
        Self(self.0 | bit)
    }

    /// Minimal little-endian bytes, never empty.
    pub fn encode(&self) -> Vec<u8> {
        let mut value = self.0;
        let mut bytes = Vec::new();
        loop {
            bytes.push((value & 0xFF) as u8);
            value >>= 8;
            if value == 0 {
                break;
            }
        }
        bytes
    }

    /// Reads any length. Bytes past the low 64 bits are ignored rather than
    /// rejected, so a future client advertising a bit we have never heard of
    /// still parses as the peer it is.
    pub fn decode(bytes: &[u8]) -> Self {
        let mut value = 0u64;
        for (index, byte) in bytes.iter().take(8).enumerate() {
            value |= (*byte as u64) << (index * 8);
        }
        Self(value)
    }

    /// Names for the bits we understand, for display. Bits we do not know are
    /// deliberately unnamed rather than shown as numbers: a peer advertising
    /// something we cannot act on is not information the user can use.
    pub fn labels(&self) -> Vec<&'static str> {
        [
            (Self::GATEWAY, "gateway"),
            (Self::BRIDGE, "bridge"),
            (Self::GROUPS, "groups"),
            (Self::BOARD, "board"),
            (Self::VOUCH, "vouch"),
            (Self::PREKEYS, "prekeys"),
            (Self::WIFI_BULK, "wifi-bulk"),
            (Self::MESH_DIAGNOSTICS, "diagnostics"),
            (Self::PRIVATE_MEDIA, "private-media"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.has(*bit))
        .map(|(_, name)| name)
        .collect()
    }
}

/// Everything this client is willing to claim about itself.
///
/// Advertising a bit is a promise to act on it, so this is deliberately not
/// "every bit we can name": a peer that sees `groups` and sends us a group
/// message we silently drop is worse served than one that never tried. It grows
/// only when the behaviour behind a bit actually exists.
///
/// `gateway` is conditional and therefore not here — it is added at announce
/// time only while we genuinely have relays to offer.
pub const ADVERTISED: u64 = 0;

#[derive(Debug, Clone)]
pub struct Announcement {
    pub nickname: String,
    pub noise_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub direct_neighbors: Option<Vec<[u8; 8]>>,
    pub capabilities: Option<Vec<u8>>,
    pub bridge_geohash: Option<String>,
}

impl Announcement {
    pub fn new(nickname: &str, noise_public_key: Vec<u8>, signing_public_key: Vec<u8>) -> Self {
        Self {
            nickname: truncate_nickname(nickname),
            noise_public_key,
            signing_public_key,
            direct_neighbors: None,
            capabilities: None,
            bridge_geohash: None,
        }
    }

    /// Sets the bits we advertise about ourselves.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = Some(capabilities.encode());
        self
    }

    /// What the peer advertised, or `None` when the TLV was absent entirely —
    /// which means an older client rather than a current one with nothing on.
    pub fn advertised(&self) -> Option<Capabilities> {
        self.capabilities
            .as_deref()
            .map(Capabilities::decode)
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        let nickname_bytes = self.nickname.as_bytes();
        if nickname_bytes.len() > 255
            || self.noise_public_key.len() > 255
            || self.signing_public_key.len() > 255
        {
            return None;
        }

        let mut data = Vec::with_capacity(6 + nickname_bytes.len() + 64);
        push_tlv(&mut data, TLV_NICKNAME, nickname_bytes);
        push_tlv(&mut data, TLV_NOISE_PUBLIC_KEY, &self.noise_public_key);
        push_tlv(&mut data, TLV_SIGNING_PUBLIC_KEY, &self.signing_public_key);

        // Optional TLVs are best-effort, and deliberately so. A peer that
        // cannot read our capabilities is degraded but working; an announce
        // that reaches the compression threshold is re-encoded compressed by
        // the verifier, stops matching our signed bytes, and is rejected as
        // forged by *everyone* — with nothing failing on this side. So an
        // optional field that will not fit is dropped rather than allowed to
        // break the whole announce. The three mandatory TLVs always fit.
        let fits = |data: &[u8], value_len: usize| {
            data.len() + 2 + value_len < crate::compression::COMPRESSION_THRESHOLD
        };

        if let Some(neighbors) = &self.direct_neighbors {
            let flat: Vec<u8> = neighbors.iter().take(10).flatten().copied().collect();
            if !flat.is_empty()
                && flat.len().is_multiple_of(8)
                && flat.len() <= 255
                && fits(&data, flat.len())
            {
                push_tlv(&mut data, TLV_DIRECT_NEIGHBORS, &flat);
            }
        }
        if let Some(capabilities) = &self.capabilities {
            if capabilities.len() <= 255 && fits(&data, capabilities.len()) {
                push_tlv(&mut data, TLV_CAPABILITIES, capabilities);
            }
        }
        if let Some(cell) = &self.bridge_geohash {
            let bytes = cell.as_bytes();
            if !bytes.is_empty() && bytes.len() <= 12 && fits(&data, bytes.len()) {
                push_tlv(&mut data, TLV_BRIDGE_GEOHASH, bytes);
            }
        }
        Some(data)
    }

    /// Tolerant decoder: unknown TLVs are skipped for forward compatibility,
    /// but the three mandatory fields must be present.
    pub fn decode(data: &[u8]) -> Option<Announcement> {
        let mut offset = 0usize;
        let mut nickname = None;
        let mut noise_public_key = None;
        let mut signing_public_key = None;
        let mut direct_neighbors = None;
        let mut capabilities = None;
        let mut bridge_geohash = None;

        while offset + 2 <= data.len() {
            let tlv_type = data[offset];
            let length = data[offset + 1] as usize;
            offset += 2;
            let end = offset.checked_add(length)?;
            if end > data.len() {
                return None;
            }
            let value = &data[offset..end];
            offset = end;

            match tlv_type {
                TLV_NICKNAME => nickname = String::from_utf8(value.to_vec()).ok(),
                TLV_NOISE_PUBLIC_KEY => noise_public_key = Some(value.to_vec()),
                TLV_SIGNING_PUBLIC_KEY => signing_public_key = Some(value.to_vec()),
                TLV_DIRECT_NEIGHBORS => {
                    if length > 0 && length.is_multiple_of(8) {
                        direct_neighbors = Some(
                            value
                                .chunks_exact(8)
                                .filter_map(|c| <[u8; 8]>::try_from(c).ok())
                                .collect(),
                        );
                    }
                }
                TLV_CAPABILITIES => capabilities = Some(value.to_vec()),
                TLV_BRIDGE_GEOHASH
                    if length <= 12 => {
                        bridge_geohash = String::from_utf8(value.to_vec()).ok();
                    }
                _ => {}
            }
        }

        Some(Announcement {
            nickname: nickname?,
            noise_public_key: noise_public_key?,
            signing_public_key: signing_public_key?,
            direct_neighbors,
            capabilities,
            bridge_geohash,
        })
    }
}

fn push_tlv(data: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
    data.push(tlv_type);
    data.push(value.len() as u8);
    data.extend_from_slice(value);
}

/// Trims on a char boundary so a multi-byte nickname never breaks the encoding.
pub fn truncate_nickname(nickname: &str) -> String {
    if nickname.len() <= MAX_NICKNAME_BYTES {
        return nickname.to_string();
    }
    let mut end = MAX_NICKNAME_BYTES;
    while end > 0 && !nickname.is_char_boundary(end) {
        end -= 1;
    }
    nickname[..end].to_string()
}

/// Signs the packet over its canonical bytes (no signature, TTL 0).
pub fn sign_packet(packet: &mut Packet, signing_key: &SigningKey) -> bool {
    let Some(bytes) = packet.signing_bytes() else {
        return false;
    };
    packet.signature = Some(signing_key.sign(&bytes).to_bytes().to_vec());
    true
}

/// Verifies a packet signature against an announced Ed25519 public key.
pub fn verify_packet(packet: &Packet, signing_public_key: &[u8]) -> bool {
    let Some(signature_bytes) = &packet.signature else {
        return false;
    };
    let Ok(signature_array) = <[u8; 64]>::try_from(signature_bytes.as_slice()) else {
        return false;
    };
    let Ok(key_array) = <[u8; 32]>::try_from(signing_public_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_array) else {
        return false;
    };
    let Some(bytes) = packet.signing_bytes() else {
        return false;
    };
    verifying_key
        .verify(&bytes, &Signature::from_bytes(&signature_array))
        .is_ok()
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn the_gateway_bit_is_a_single_byte() {
        // Minimal little-endian. Worth pinning as a literal: the announce has
        // three bytes of headroom, and this is the value that goes on the wire.
        assert_eq!(Capabilities::default().with(Capabilities::GATEWAY).encode(), vec![0x04]);
    }

    #[test]
    fn an_empty_set_is_still_a_byte() {
        // Upstream distinguishes "advertises nothing" from "does not speak
        // capabilities": the first is a current client with everything off, the
        // second an old one. An empty encoding would collapse them.
        assert_eq!(Capabilities::default().encode(), vec![0x00]);
    }

    #[test]
    fn every_bit_round_trips() {
        for bit in [
            Capabilities::PREKEYS,
            Capabilities::WIFI_BULK,
            Capabilities::GATEWAY,
            Capabilities::GROUPS,
            Capabilities::BOARD,
            Capabilities::VOUCH,
            Capabilities::MESH_DIAGNOSTICS,
            Capabilities::BRIDGE,
            Capabilities::PRIVATE_MEDIA,
            Capabilities::PRIVATE_MEDIA_RECEIPTS,
            Capabilities::RESERVED_NOISE_REPLACEMENT,
        ] {
            let set = Capabilities::default().with(bit);
            let read = Capabilities::decode(&set.encode());
            assert_eq!(read, set, "bit {bit:#x} did not survive");
            assert!(read.has(bit));
        }
    }

    #[test]
    fn the_encoding_is_little_endian() {
        // The carrier packet uses big-endian lengths and this uses
        // little-endian bits. Getting them the same way round would produce a
        // capability set no phone recognises.
        let high = Capabilities::default().with(Capabilities::PRIVATE_MEDIA); // 1 << 8
        assert_eq!(high.encode(), vec![0x00, 0x01], "low byte first");
    }

    #[test]
    fn a_bit_we_have_never_heard_of_does_not_break_the_peer() {
        // Forward compatibility: a future client advertising bit 40 must still
        // parse as the peer it is, with the bits we do understand intact.
        let future = Capabilities::from_bits(Capabilities::GATEWAY | (1 << 40));
        let read = Capabilities::decode(&future.encode());
        assert!(read.has(Capabilities::GATEWAY));
        assert_eq!(read.labels(), vec!["gateway"]);
    }

    #[test]
    fn trailing_bytes_beyond_sixty_four_bits_are_ignored() {
        let mut padded = Capabilities::default().with(Capabilities::GATEWAY).encode();
        padded.extend_from_slice(&[0xFF; 12]);
        assert!(Capabilities::decode(&padded).has(Capabilities::GATEWAY));
    }

    #[test]
    fn an_absent_tlv_is_not_an_empty_set() {
        let (signing_key, noise_public_key) = super::tests::test_keys();
        let bare = Announcement::new("bob", noise_public_key.clone(), signing_key.verifying_key().to_bytes().to_vec());
        assert_eq!(bare.advertised(), None, "an old client says nothing at all");

        let current = bare.clone().with_capabilities(Capabilities::default());
        assert_eq!(
            current.advertised(),
            Some(Capabilities::default()),
            "a current client with nothing on still says so"
        );
    }

    #[test]
    fn capabilities_survive_the_wire() {
        let (signing_key, noise_public_key) = super::tests::test_keys();
        let announced = Announcement::new(
            "bob",
            noise_public_key,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        .with_capabilities(Capabilities::default().with(Capabilities::GATEWAY));

        let decoded = Announcement::decode(&announced.encode().unwrap()).unwrap();
        let advertised = decoded.advertised().expect("the TLV is present");
        assert!(advertised.has(Capabilities::GATEWAY));
        assert!(!advertised.has(Capabilities::BRIDGE));
    }

    #[test]
    fn advertising_capabilities_keeps_the_announce_uncompressible() {
        // The one that matters for interop, and the one that fails silently.
        // If an announce reaches 100 bytes the peer's verification re-encode
        // compresses it, the bytes stop matching ours, and every announce we
        // send is rejected as forged — with nothing failing on this side.
        //
        // An announce is mostly two random public keys, so the entropy half of
        // `should_compress` passes easily: length is the only thing standing
        // between us and that.
        let (signing_key, noise_public_key) = super::tests::test_keys();
        let worst = Announcement::new(
            &"n".repeat(MAX_NICKNAME_BYTES),
            noise_public_key,
            signing_key.verifying_key().to_bytes().to_vec(),
        );
        // Everything we claim, plus the conditional bit — which together is the
        // largest capability set that will ever leave this client.
        let claimed = ADVERTISED | Capabilities::GATEWAY;
        let worst = worst.with_capabilities(Capabilities::from_bits(claimed));

        let payload = worst.encode().expect("encodes");
        assert!(
            payload.len() < crate::compression::COMPRESSION_THRESHOLD,
            "worst-case announce is {} bytes, threshold is {}",
            payload.len(),
            crate::compression::COMPRESSION_THRESHOLD
        );
        assert!(
            !crate::compression::should_compress(&payload),
            "neither side may compress an announce"
        );
        assert!(
            Announcement::decode(&payload)
                .and_then(|read| read.advertised())
                .is_some_and(|read| read.bits() == claimed),
            "and everything we advertise actually survived"
        );
    }

    #[test]
    fn an_optional_field_that_will_not_fit_is_dropped_not_fatal() {
        // The failure this guards against is total and silent: an announce at
        // or past the threshold is re-encoded compressed by the verifier, stops
        // matching our signed bytes, and is rejected as forged by every peer.
        // Losing an optional field instead costs one feature.
        let (signing_key, noise_public_key) = super::tests::test_keys();
        let overweight = Announcement::new(
            &"n".repeat(MAX_NICKNAME_BYTES),
            noise_public_key,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        // Far more than could ever fit alongside a full-length nickname.
        .with_capabilities(Capabilities::from_bits(u64::MAX));

        let payload = overweight.encode().expect("still encodes");
        assert!(
            payload.len() < crate::compression::COMPRESSION_THRESHOLD,
            "{} bytes",
            payload.len()
        );
        let read = Announcement::decode(&payload).expect("and still decodes");
        assert_eq!(read.nickname.len(), MAX_NICKNAME_BYTES, "the mandatory part is intact");
        assert_eq!(read.advertised(), None, "the optional part was dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_id::derive_peer_id;
    use crate::protocol::{peer_id_to_bytes, MessageType, Packet};

    pub(super) fn test_keys() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let noise_public_key = vec![0x5Au8; 32];
        (signing_key, noise_public_key)
    }

    #[test]
    fn tlv_round_trips() {
        let (signing_key, noise_pub) = test_keys();
        let announcement = Announcement::new(
            "tui-user",
            noise_pub.clone(),
            signing_key.verifying_key().to_bytes().to_vec(),
        );
        let encoded = announcement.encode().unwrap();
        let decoded = Announcement::decode(&encoded).unwrap();
        assert_eq!(decoded.nickname, "tui-user");
        assert_eq!(decoded.noise_public_key, noise_pub);
        assert_eq!(decoded.signing_public_key, signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn announce_payload_stays_under_the_compression_threshold() {
        let (signing_key, noise_pub) = test_keys();
        let announcement = Announcement::new(
            &"n".repeat(64),
            noise_pub,
            signing_key.verifying_key().to_bytes().to_vec(),
        );
        let encoded = announcement.encode().unwrap();
        assert!(
            encoded.len() < crate::compression::COMPRESSION_THRESHOLD,
            "announce must never be compressed, got {} bytes",
            encoded.len()
        );
        assert!(!crate::compression::should_compress(&encoded));
    }

    #[test]
    fn decode_requires_the_three_mandatory_tlvs() {
        let mut only_nickname = Vec::new();
        push_tlv(&mut only_nickname, TLV_NICKNAME, b"solo");
        assert!(Announcement::decode(&only_nickname).is_none());
    }

    #[test]
    fn decode_skips_unknown_tlvs() {
        let (signing_key, noise_pub) = test_keys();
        let mut data = Announcement::new("bob", noise_pub, signing_key.verifying_key().to_bytes().to_vec())
            .encode()
            .unwrap();
        push_tlv(&mut data, 0x7F, b"future field");
        assert_eq!(Announcement::decode(&data).unwrap().nickname, "bob");
    }

    #[test]
    fn sign_then_verify_a_full_announce_packet() {
        let (signing_key, noise_pub) = test_keys();
        let peer_id = derive_peer_id(&noise_pub);
        let payload = Announcement::new(
            "tui-user",
            noise_pub.clone(),
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        .encode()
        .unwrap();

        let mut packet = Packet::new(
            MessageType::Announce,
            peer_id_to_bytes(&peer_id),
            payload,
            7,
        );
        assert!(sign_packet(&mut packet, &signing_key));

        // Survives a wire round trip, and the sender ID matches the derived ID.
        let wire = packet.encode().unwrap();
        let decoded = Packet::decode(&wire).unwrap();
        let announcement = Announcement::decode(&decoded.payload).unwrap();
        assert_eq!(derive_peer_id(&announcement.noise_public_key), decoded.sender_hex());
        assert!(verify_packet(&decoded, &announcement.signing_public_key));
    }

    #[test]
    fn verification_fails_when_the_payload_is_tampered_with() {
        let (signing_key, noise_pub) = test_keys();
        let payload = Announcement::new("tui-user", noise_pub, signing_key.verifying_key().to_bytes().to_vec())
            .encode()
            .unwrap();
        let mut packet = Packet::new(MessageType::Announce, [1; 8], payload, 7);
        sign_packet(&mut packet, &signing_key);
        packet.payload[3] ^= 0xFF;
        let signing_public_key = signing_key.verifying_key().to_bytes();
        assert!(!verify_packet(&packet, &signing_public_key));
    }

    #[test]
    fn relaying_does_not_break_the_signature() {
        let (signing_key, noise_pub) = test_keys();
        let payload = Announcement::new("tui-user", noise_pub, signing_key.verifying_key().to_bytes().to_vec())
            .encode()
            .unwrap();
        let mut packet = Packet::new(MessageType::Announce, [1; 8], payload, 7);
        sign_packet(&mut packet, &signing_key);
        // A relay decrements TTL; signing bytes pin it to 0 so this must verify.
        packet.ttl = 4;
        let signing_public_key = signing_key.verifying_key().to_bytes();
        assert!(verify_packet(&packet, &signing_public_key));
    }
}
