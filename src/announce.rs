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
pub const MAX_NICKNAME_BYTES: usize = 24;

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

        if let Some(neighbors) = &self.direct_neighbors {
            let flat: Vec<u8> = neighbors.iter().take(10).flatten().copied().collect();
            if !flat.is_empty() && flat.len().is_multiple_of(8) && flat.len() <= 255 {
                push_tlv(&mut data, TLV_DIRECT_NEIGHBORS, &flat);
            }
        }
        if let Some(capabilities) = &self.capabilities {
            if capabilities.len() <= 255 {
                push_tlv(&mut data, TLV_CAPABILITIES, capabilities);
            }
        }
        if let Some(cell) = &self.bridge_geohash {
            let bytes = cell.as_bytes();
            if !bytes.is_empty() && bytes.len() <= 12 {
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
mod tests {
    use super::*;
    use crate::peer_id::derive_peer_id;
    use crate::protocol::{peer_id_to_bytes, MessageType, Packet};

    fn test_keys() -> (SigningKey, Vec<u8>) {
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
