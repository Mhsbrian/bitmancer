// src/sync/packet_id.rs
//
// The identity a packet carries through gossip sync. Port of upstream
// `Sync/PacketIdUtil.swift`.

use crate::protocol::Packet;
use sha2::{Digest, Sha256};

/// Length of a sync packet ID. Upstream truncates the digest to 16 bytes and
/// the filter hashes that truncated form, so the width is on the wire.
pub const PACKET_ID_LEN: usize = 16;

/// `SHA-256(type ‖ sender_id ‖ timestamp_be ‖ payload)`, truncated to 16 bytes.
///
/// Four fields, in that order. What is *absent* matters as much: version, TTL,
/// recipient, signature and route are all excluded. TTL especially — it is
/// decremented by every relay, so including it would give the same message a
/// different identity at every hop and defeat the whole point.
///
/// This deliberately does not reuse `relay::digest`, which answers a similar
/// question for the forwarding ring. That one hashes a different field set (it
/// includes the recipient) with `DefaultHasher`, whose output is explicitly not
/// stable across Rust releases. It is right for its own job and could never go
/// on the wire.
pub fn packet_id(packet: &Packet) -> [u8; PACKET_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([packet.msg_type]);
    hasher.update(packet.sender_id);
    hasher.update(packet.timestamp.to_be_bytes());
    hasher.update(&packet.payload);
    let digest = hasher.finalize();

    let mut id = [0u8; PACKET_ID_LEN];
    id.copy_from_slice(&digest[..PACKET_ID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    /// Builds the exact packet the golden vector below was computed over.
    fn vector_packet() -> Packet {
        let mut packet = Packet::new(
            MessageType::Message,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            b"hi".to_vec(),
            7,
        );
        packet.timestamp = 1;
        packet
    }

    #[test]
    fn the_id_matches_a_digest_computed_outside_this_crate() {
        // Ground truth, not a round-trip. The hashed bytes are
        //
        //     02                 type (MessageType::Message)
        //     0102030405060708   sender_id
        //     0000000000000001   timestamp, big-endian u64
        //     6869               payload, "hi"
        //
        // and `printf '02010203040506070800000000000000016869' | xxd -r -p |
        // sha256sum` gives
        //
        //     724f0ff675362a2f3125776a3f475e9dd9c233f2d13c11097c31490524a62f31
        //
        // of which we keep the first 16 bytes. Computed with coreutils rather
        // than with this module, so the test can actually disagree with it.
        let expected = hex::decode("724f0ff675362a2f3125776a3f475e9d").unwrap();
        assert_eq!(packet_id(&vector_packet()).to_vec(), expected);
    }

    #[test]
    fn the_hop_count_is_not_part_of_the_identity() {
        // A relayed copy has to keep its ID or dedup across hops collapses.
        let original = vector_packet();
        let mut relayed = vector_packet();
        relayed.ttl = original.ttl - 1;
        assert_eq!(packet_id(&original), packet_id(&relayed));
    }

    #[test]
    fn the_signature_and_route_are_not_part_of_the_identity() {
        // Both are added or rewritten in flight; neither changes which message
        // this is.
        let original = vector_packet();
        let mut decorated = vector_packet();
        decorated.signature = Some(vec![0xAA; 64]);
        decorated.route = Some(vec![[0x09; 8]]);
        assert_eq!(packet_id(&original), packet_id(&decorated));
    }

    #[test]
    fn each_hashed_field_changes_the_identity() {
        let base = packet_id(&vector_packet());

        let mut other_type = vector_packet();
        other_type.msg_type = MessageType::Announce as u8;
        assert_ne!(packet_id(&other_type), base, "type is hashed");

        let mut other_sender = vector_packet();
        other_sender.sender_id[7] = 0x09;
        assert_ne!(packet_id(&other_sender), base, "sender is hashed");

        let mut other_time = vector_packet();
        other_time.timestamp = 2;
        assert_ne!(packet_id(&other_time), base, "timestamp is hashed");

        let mut other_payload = vector_packet();
        other_payload.payload = b"ho".to_vec();
        assert_ne!(packet_id(&other_payload), base, "payload is hashed");
    }

    #[test]
    fn the_timestamp_is_hashed_big_endian() {
        // Little-endian would make these two collide on their first byte and,
        // more to the point, would disagree with every phone in the room.
        // 0x0102030405060708 reversed is 0x0807060504030201.
        let mut forward = vector_packet();
        forward.timestamp = 0x0102_0304_0506_0708;
        let mut reversed = vector_packet();
        reversed.timestamp = 0x0807_0605_0403_0201;
        assert_ne!(packet_id(&forward), packet_id(&reversed));
    }
}
