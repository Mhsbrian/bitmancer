// src/peer_id.rs
//
// Peer IDs are no longer random. Current bitchat derives them from the Noise
// static public key (PeerID.swift): the first 16 hex characters of the key's
// SHA-256 fingerprint. The announce handler rejects any announce whose derived
// ID does not match the frame's sender ID, so a random ID can never join.

use sha2::{Digest, Sha256};

/// Full SHA-256 fingerprint of a public key, lowercase hex (64 chars).
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// Stable 16-hex peer ID derived from a Noise static public key.
pub fn derive_peer_id(noise_public_key: &[u8]) -> String {
    fingerprint(noise_public_key)[..16].to_string()
}

/// Short display form used in the UI when a nickname is not known yet.
pub fn short_display(peer_id: &str) -> String {
    peer_id.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_sixteen_hex_chars_from_the_fingerprint() {
        let key = [0x42u8; 32];
        let fp = fingerprint(&key);
        let peer_id = derive_peer_id(&key);
        assert_eq!(peer_id.len(), 16);
        assert_eq!(peer_id, &fp[..16]);
        assert!(peer_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn matches_a_known_sha256_vector() {
        // SHA-256 of 32 zero bytes.
        let expected = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        assert_eq!(fingerprint(&[0u8; 32]), expected);
        assert_eq!(derive_peer_id(&[0u8; 32]), &expected[..16]);
    }

    #[test]
    fn peer_id_round_trips_through_the_wire_encoding() {
        let peer_id = derive_peer_id(&[7u8; 32]);
        let bytes = crate::protocol::peer_id_to_bytes(&peer_id);
        assert_eq!(hex::encode(bytes), peer_id);
    }
}
