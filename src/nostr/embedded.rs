// src/nostr/embedded.rs
//
// BitChat inside a Nostr rumor.
//
// The sealed layers underneath carry an opaque string, and it would have been
// reasonable for that string to be the message. It is not. Upstream puts a
// whole mesh packet in there, base64url-encoded behind a `bitchat1:` prefix,
// and a client that sends plain text is not sending a private message — it is
// sending something the other side logs and drops. Verified against
// `NostrEmbeddedBitChat.encodePMForNostr` and the `content.hasPrefix` branch in
// `NostrInboundPipeline`, which ignores anything without the prefix.
//
// The packet is typed `noiseEncrypted`, which is a lie of convenience: nothing
// here is Noise-encrypted, because the envelope already did that and doing it
// twice would require a mesh session with someone who is by definition out of
// radio range. The type is reused so the payload lands in the same dispatch
// that handles a mesh DM, and the receiving side reads `[type byte] || body`
// exactly as it would off the radio. One format, two carriers.
//
// That reuse is the reason this file is thin. Private messages, delivery acks
// and read receipts already have wire formats; this only addresses and frames
// them.

use crate::noise_payload::{NoisePayload, NoisePayloadType, PrivateMessagePacket};
use crate::protocol::{peer_id_to_bytes, MessageType, Packet};

/// Marks rumor content as a framed mesh packet rather than text.
pub const PREFIX: &str = "bitchat1:";

/// Same TTL upstream stamps on an embedded packet. It is decorative here —
/// nothing relays a packet that arrived over the internet — but it is part of
/// the bytes the other side parses.
const EMBEDDED_TTL: u8 = 7;

/// Ceiling on a decoded packet.
///
/// Deliberately far below upstream's, which reuses the file-transfer limit of
/// roughly a mebibyte. Files do not come this way: the inbound switch upstream
/// ignores `privateFile` outright, and the only payloads that can legitimately
/// arrive are a private message — whose content is capped at 255 bytes by its
/// own one-byte TLV length — and a receipt, which is a bare message id. Those
/// fit in a few hundred bytes with padding. Sixty-four kibibytes is two orders
/// of magnitude of headroom and still refuses to allocate a megabyte because a
/// relay served a long string.
const MAX_PACKET_BYTES: usize = 64 * 1024;

/// Frames a packet as rumor content.
///
/// Padded, like every other packet this client emits. Here the padding earns
/// something extra: the envelope does not pad its plaintext, so without this
/// the ciphertext length would track the message length and a relay could read
/// the size of everything it carries for us.
pub fn encode(packet: &Packet) -> Option<String> {
    let bytes = packet.encode()?;
    Some(format!(
        "{PREFIX}{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    ))
}

/// A private message addressed to a peer.
///
/// The id is supplied rather than generated, because it is what a receipt
/// points back at. A message sent over the internet and acknowledged over the
/// radio has to be recognisable as the same message.
///
/// Not yet called: sending this way needs a recipient address, and a peer's
/// address arrives as bech32 `npub` from upstream, which nothing here decodes
/// yet. Receiving is wired, so this is the half that answers.
#[allow(dead_code)]
pub fn private_message(
    message_id: &str,
    content: &str,
    sender_peer_id: &str,
    recipient_peer_id: &str,
) -> Option<String> {
    let record = PrivateMessagePacket {
        message_id: message_id.to_string(),
        content: content.to_string(),
    };
    let payload = NoisePayload::new(NoisePayloadType::PrivateMessage, record.encode()?);
    encode(&frame(payload, sender_peer_id, recipient_peer_id))
}

/// A delivery or read acknowledgement.
///
/// Returns `None` for any other payload type: an acknowledgement is a bare
/// message id, and encoding something else under that shape would produce a
/// record the other side reads as a receipt for a message that does not exist.
pub fn receipt(
    kind: NoisePayloadType,
    message_id: &str,
    sender_peer_id: &str,
    recipient_peer_id: &str,
) -> Option<String> {
    if !matches!(
        kind,
        NoisePayloadType::Delivered | NoisePayloadType::ReadReceipt
    ) {
        return None;
    }
    let payload = NoisePayload::receipt(kind, message_id);
    encode(&frame(payload, sender_peer_id, recipient_peer_id))
}

fn frame(payload: NoisePayload, sender_peer_id: &str, recipient_peer_id: &str) -> Packet {
    Packet::new(
        MessageType::NoiseEncrypted,
        peer_id_to_bytes(sender_peer_id),
        payload.encode(),
        EMBEDDED_TTL,
    )
    .with_recipient(peer_id_to_bytes(recipient_peer_id))
}

/// Reads rumor content back into a packet, or `None` if it is not one.
///
/// The length of the *encoded* string is checked before decoding it, so a
/// hostile relay cannot make us allocate the decoded size of something we were
/// always going to reject. Upstream orders the same two checks the same way.
pub fn decode(content: &str) -> Option<Packet> {
    let encoded = content.strip_prefix(PREFIX)?;
    // Four base64 characters per three bytes, rounded up.
    let max_encoded = MAX_PACKET_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        return None;
    }
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        encoded,
    )
    .ok()?;
    if bytes.len() > MAX_PACKET_BYTES {
        return None;
    }
    Packet::decode(&bytes)
}

/// The payload of an embedded packet, if it carries one we act on.
///
/// Group state, voice and files are mesh-only upstream and are refused here for
/// the same reasons: a group key update that arrived without a Noise session is
/// unauthenticated, and voice over a store-and-forward relay is meaningless.
pub fn payload_of(packet: &Packet) -> Option<NoisePayload> {
    if packet.parsed_type() != Some(MessageType::NoiseEncrypted) {
        return None;
    }
    let payload = NoisePayload::decode(&packet.payload)?;
    matches!(
        payload.kind,
        NoisePayloadType::PrivateMessage
            | NoisePayloadType::Delivered
            | NoisePayloadType::ReadReceipt
    )
    .then_some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "1122334455667788";
    const THEM: &str = "99aabbccddeeff00";

    #[test]
    fn a_private_message_round_trips_through_the_framing() {
        let content = private_message("msg-1", "meet at the usual place", ME, THEM).unwrap();
        assert!(content.starts_with(PREFIX), "{content}");

        let packet = decode(&content).expect("our own framing must parse");
        assert_eq!(packet.parsed_type(), Some(MessageType::NoiseEncrypted));
        assert_eq!(packet.sender_hex(), ME);
        assert_eq!(packet.recipient_hex().as_deref(), Some(THEM));

        let payload = payload_of(&packet).expect("a private message is acted on");
        assert_eq!(payload.kind, NoisePayloadType::PrivateMessage);
        let record = PrivateMessagePacket::decode(&payload.body).unwrap();
        assert_eq!(record.message_id, "msg-1");
        assert_eq!(record.content, "meet at the usual place");
    }

    #[test]
    fn a_receipt_carries_a_bare_message_id() {
        for kind in [NoisePayloadType::Delivered, NoisePayloadType::ReadReceipt] {
            let content = receipt(kind, "msg-1", ME, THEM).unwrap();
            let packet = decode(&content).unwrap();
            let payload = payload_of(&packet).unwrap();
            assert_eq!(payload.kind, kind);
            assert_eq!(payload.message_id().as_deref(), Some("msg-1"));
        }
    }

    #[test]
    fn only_receipts_can_be_encoded_as_receipts() {
        // A private message under a receipt's shape would be read as an
        // acknowledgement of a message that was never sent.
        assert!(receipt(NoisePayloadType::PrivateMessage, "msg-1", ME, THEM).is_none());
        assert!(receipt(NoisePayloadType::Vouch, "msg-1", ME, THEM).is_none());
    }

    #[test]
    fn plain_text_is_not_an_embedded_packet() {
        // The case that matters: a client sending bare text over this transport
        // is silently ignored by upstream, so we must never mistake the reverse
        // for a message either.
        for content in ["hello", "", "bitchat:hello", "bitchat1", "verify:abc"] {
            assert!(decode(content).is_none(), "{content:?} is not a packet");
        }
    }

    #[test]
    fn the_prefix_is_exact() {
        let framed = private_message("m", "hi", ME, THEM).unwrap();
        assert!(decode(&framed).is_some());
        // Same bytes, wrong marker.
        let mangled = framed.replacen(PREFIX, "bitchat2:", 1);
        assert!(decode(&mangled).is_none());
    }

    #[test]
    fn an_oversized_string_is_refused_before_it_is_decoded() {
        let huge = format!("{PREFIX}{}", "A".repeat(MAX_PACKET_BYTES * 2));
        assert!(decode(&huge).is_none());
    }

    #[test]
    fn rubbish_after_the_prefix_is_not_fatal() {
        for tail in ["!!!!", "AAAA", "not base64url +/=", "A"] {
            let _ = decode(&format!("{PREFIX}{tail}"));
        }
    }

    #[test]
    fn payloads_that_belong_to_the_mesh_are_refused() {
        // Voice over a store-and-forward relay is meaningless, and a group key
        // update that arrived without a Noise session is unauthenticated.
        for kind in [
            NoisePayloadType::VoiceFrame,
            NoisePayloadType::GroupKeyUpdate,
            NoisePayloadType::PrivateFile,
            NoisePayloadType::VerifyChallenge,
        ] {
            let packet = frame(NoisePayload::new(kind, vec![1, 2, 3]), ME, THEM);
            assert!(
                payload_of(&packet).is_none(),
                "{kind:?} must not be acted on over Nostr"
            );
        }
    }

    #[test]
    fn a_packet_of_another_type_is_not_a_private_payload() {
        let packet = Packet::new(
            MessageType::Message,
            peer_id_to_bytes(ME),
            b"public chatter".to_vec(),
            EMBEDDED_TTL,
        );
        assert!(payload_of(&packet).is_none());
    }

    #[test]
    fn a_message_survives_every_layer_between_two_clients() {
        // The layers are each tested alone; this is the one that matters,
        // because a private message crosses all of them and a mistake at any
        // seam looks identical from either side — a wrap that opens to
        // something the other end quietly ignores.
        use crate::nostr::envelope;
        use secp256k1::{Keypair, SecretKey, SECP256K1};

        let key = |byte: u8| Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array([byte; 32]).unwrap());
        let (sender, recipient, ephemeral) = (key(1), key(2), key(3));
        let (recipient_pubkey, _) = recipient.x_only_public_key();

        // Sender: frame the message, then seal it.
        let content = private_message("msg-7", "out of range, still here", ME, THEM).unwrap();
        let wrap = envelope::seal_message(
            &content,
            &recipient_pubkey,
            &sender,
            &ephemeral,
            1_700_000_000,
            envelope::published_timestamp(1_700_000_000, 42),
            [[7u8; 24], [8u8; 24]],
        )
        .expect("sealing a framed message");

        // Recipient: open it, then unframe.
        let opened = envelope::open_message(&wrap, &recipient.secret_key(), &recipient_pubkey)
            .expect("the recipient can open their own mail");
        assert_eq!(
            opened.sender,
            hex::encode(sender.x_only_public_key().0.serialize()),
            "the proved sender is the one who sealed it"
        );
        assert_eq!(
            opened.created_at, 1_700_000_000,
            "the true send time rides inside, not on the jittered wrap"
        );

        let packet = decode(&opened.content).expect("the rumor carries a framed packet");
        let payload = payload_of(&packet).expect("carrying a private message");
        let record = PrivateMessagePacket::decode(&payload.body).unwrap();
        assert_eq!(record.content, "out of range, still here");
        assert_eq!(
            record.message_id, "msg-7",
            "the id has to survive, or no receipt can point back at it"
        );
    }

    #[test]
    fn framing_hides_the_length_of_short_messages() {
        // The envelope does not pad its plaintext, so if the packet did not pad
        // either, a relay could read the length of every message it carries.
        let short = decode(&private_message("m", "hi", ME, THEM).unwrap()).unwrap();
        let longer = decode(&private_message("m", &"x".repeat(80), ME, THEM).unwrap()).unwrap();
        let short_wire = private_message("m", "hi", ME, THEM).unwrap().len();
        let longer_wire = private_message("m", &"x".repeat(80), ME, THEM).unwrap().len();
        assert_eq!(
            short_wire, longer_wire,
            "two messages of very different lengths must look the same on the wire"
        );
        // And both still carry what was written.
        assert_eq!(
            PrivateMessagePacket::decode(&payload_of(&short).unwrap().body)
                .unwrap()
                .content,
            "hi"
        );
        assert_eq!(
            PrivateMessagePacket::decode(&payload_of(&longer).unwrap().body)
                .unwrap()
                .content
                .len(),
            80
        );
    }
}
