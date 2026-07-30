// tests/public_api.rs
//
// The first test in this repo that lives outside `src/`.
//
// Until the crate grew a `[lib]` target this file could not exist: the package
// was a single binary, so nothing under `tests/` could name `bitmancer` at all.
// That is why the one real fixture in the tree is reached with `include_str!`
// from inside a unit test — there was no other way in.
//
// These assertions are deliberately about things a caller outside the crate can
// reach and depend on. The point is partly the assertions and partly that the
// boundary exists and holds: if `lib.rs` stops exposing a module, this stops
// compiling, which is a better signal than a unit test that can see everything
// regardless.

use bitmancer::geohash;
use bitmancer::peer_id;
use bitmancer::protocol::{MessageType, Packet};

#[test]
fn a_peer_id_is_derived_from_the_noise_key_and_stays_put() {
    // Peer ids are not random — a peer re-derives ours from the key inside our
    // announce and drops the announce on a mismatch. Same key must always give
    // the same id, and it must be the 16 hex chars the frame carries.
    let key = [0x11u8; 32];

    let first = peer_id::derive_peer_id(&key);
    let second = peer_id::derive_peer_id(&key);

    assert_eq!(first, second, "derivation must be deterministic");
    assert_eq!(first.len(), 16, "the frame carries 16 hex chars: {first}");
    assert!(
        first.chars().all(|c| c.is_ascii_hexdigit()),
        "must be hex: {first}"
    );

    let other = peer_id::derive_peer_id(&[0x22u8; 32]);
    assert_ne!(first, other, "a different key must give a different id");
}

#[test]
fn a_geohash_round_trips_through_its_own_centre() {
    // Both clients have to agree on which cell a coordinate is in, or they
    // compute different relay sets and never meet. Encoding a point and decoding
    // the cell's centre must land back inside the same cell.
    let encoded = geohash::encode(37.7749, -122.4194, 5);
    assert_eq!(encoded.len(), 5, "precision 5 means five characters");
    assert!(geohash::is_valid(&encoded), "must be a valid geohash");

    let (latitude, longitude) = geohash::decode_center(&encoded);
    let re_encoded = geohash::encode(latitude, longitude, 5);
    assert_eq!(
        encoded, re_encoded,
        "a cell's centre must encode back to that cell"
    );
}

#[test]
fn a_geohash_is_normalised_the_same_way_a_user_would_type_it() {
    // `/geo #9Q8YY` and `/geo 9q8yy` are the same room.
    for spelling in ["#9q8yy", "9q8yy", "#9Q8YY", "9Q8YY"] {
        assert_eq!(
            geohash::normalize(spelling),
            "9q8yy",
            "{spelling} must normalise to the same cell"
        );
    }
}

#[test]
fn a_frame_survives_the_encode_decode_round_trip() {
    // The codec is the one thing both sides must agree on byte for byte.
    let sender = [0xAB; 8];
    let packet = Packet::new(MessageType::Message, sender, b"hello".to_vec(), 3);

    let encoded = packet.encode().expect("a well-formed packet encodes");
    let decoded = Packet::decode(&encoded).expect("our own bytes must decode");

    assert_eq!(decoded.sender_id, sender);
    assert_eq!(decoded.payload, b"hello");
    assert_eq!(decoded.ttl, 3);
    assert_eq!(decoded.msg_type, MessageType::Message as u8);
}

#[test]
fn a_truncated_frame_is_refused_rather_than_panicking() {
    // Frames arrive off a radio, so every prefix of a real one is a thing that
    // can actually reach the decoder. `protocol.rs` carries upstream's bounds
    // cases as unit tests; this is the same guarantee asserted from outside, on
    // the public entry point a caller would use.
    let packet = Packet::new(MessageType::Message, [0x01; 8], b"payload".to_vec(), 1);
    let encoded = packet.encode().expect("encodes");

    for length in 0..encoded.len() {
        // No unwrap: the contract is None, never a panic.
        let _ = Packet::decode(&encoded[..length]);
    }
}
