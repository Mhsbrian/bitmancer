// src/sync/responder.rs
//
// Answering a REQUEST_SYNC. Port of upstream
// `GossipSyncManager._handleRequestSync`.
//
// Kept as a pure function over the archive so the diff logic can be tested with
// constructed packets rather than a live mesh. The mesh layer supplies the
// archive and puts the results on the air.

use crate::protocol::{MessageType, Packet};

use super::archive::{Archive, Kind};
use super::gcs;
use super::packet_id::packet_id;
use super::request::{decode_fragment_id_filter, RequestSync};
use super::type_flags::SyncTypeFlags;

/// Builds the packets this request is missing.
///
/// Each is a copy of what we hold with the hop count zeroed and the RSR flag
/// set: a solicited reply is for the peer that asked, and must not be relayed
/// onward by anyone it passes.
pub fn respond(archive: &Archive, request: &RequestSync, now_ms: u64) -> Vec<Packet> {
    let types = request.requested_types();
    let known = gcs::decode_to_sorted_set(request.p, request.m, &request.data);

    // A filter the peer sent that we cannot read decodes to nothing, which
    // reads as "they hold none of it" and makes us send everything. That is the
    // safe direction: a wasted round rather than a message nobody ever sees.
    let missing = |packet: &Packet| -> bool {
        !gcs::contains(&known, gcs::bucket(&packet_id(packet), request.m))
    };

    let mut out = Vec::new();

    // Announces are exempt from the since-cursor. They carry the signing keys
    // needed to verify everything else, and there is at most one per peer, so
    // the cost of re-sending is bounded and a peer that just arrived has to be
    // able to learn about announces older than its own arrival.
    if types.contains(MessageType::Announce) {
        for packet in archive.fresh_announces(now_ms) {
            if missing(packet) {
                out.push(as_reply(packet));
            }
        }
    }

    if types.contains(MessageType::Message) {
        for packet in archive.fresh(Kind::Message, now_ms) {
            if before_cursor(packet, request.since_timestamp) {
                continue;
            }
            if missing(packet) {
                out.push(as_reply(packet));
            }
        }
    }

    if types.contains(MessageType::Fragment) {
        // A fragment-ID filter narrows the answer to exactly the streams whose
        // reassembly has stalled, and bypasses the cursor for them — the whole
        // point is recovering pieces older than the requester's coverage. The
        // GCS filter still excludes the pieces they already hold.
        let wanted = decode_fragment_id_filter(request.fragment_id_filter.as_deref());
        for packet in archive.fresh(Kind::Fragment, now_ms) {
            match &wanted {
                Some(streams) => {
                    // A fragment payload opens with its 8-byte stream ID.
                    let Some(stream) = packet.payload.get(..8) else {
                        continue;
                    };
                    if !streams.iter().any(|id| id == stream) {
                        continue;
                    }
                }
                None => {
                    if before_cursor(packet, request.since_timestamp) {
                        continue;
                    }
                }
            }
            if missing(packet) {
                out.push(as_reply(packet));
            }
        }
    }

    if types.contains(MessageType::FileTransfer) {
        for packet in archive.fresh(Kind::File, now_ms) {
            if before_cursor(packet, request.since_timestamp) {
                continue;
            }
            if missing(packet) {
                out.push(as_reply(packet));
            }
        }
    }

    out
}

/// Whether a packet sits before the coverage the requester claimed.
///
/// Without this every round re-sends everything older than the filter: those
/// packets are outside what the filter describes, so they always look absent.
fn before_cursor(packet: &Packet, since: Option<u64>) -> bool {
    match since {
        Some(since) => packet.timestamp < since,
        None => false,
    }
}

/// A copy addressed at the requester rather than the room.
fn as_reply(packet: &Packet) -> Packet {
    let mut reply = packet.clone();
    // Zero, not one: this is a direct answer to the peer on the other end of
    // the link and nobody else should carry it. `relay::plan` refuses anything
    // at or below one hop, so this is also what keeps our own relay from
    // amplifying a reply that arrives at somebody else.
    reply.ttl = 0;
    reply.is_rsr = true;
    reply
}

/// The types this client can actually answer for.
///
/// Board posts, prekey bundles and group messages are in upstream's table and
/// we do not implement those opcodes, so a request naming them gets the types
/// we do hold and silence for the rest — which is exactly what an older peer
/// looks like to a newer one.
pub fn answerable_types() -> SyncTypeFlags {
    SyncTypeFlags::from_types(&[
        MessageType::Announce,
        MessageType::Message,
        MessageType::Fragment,
        MessageType::FileTransfer,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::gcs::build_filter;
    use crate::sync::packet_id::PACKET_ID_LEN;

    const NOW: u64 = 1_785_000_000_000;

    fn packet_at(message_type: MessageType, sender: u8, timestamp: u64, body: &[u8]) -> Packet {
        let mut packet = Packet::new(message_type, [sender; 8], body.to_vec(), 7);
        packet.timestamp = timestamp;
        packet
    }

    /// A request whose filter claims to hold exactly `held`.
    fn request_holding(held: &[&Packet], types: Option<SyncTypeFlags>) -> RequestSync {
        let ids: Vec<[u8; PACKET_ID_LEN]> = held.iter().map(|p| packet_id(p)).collect();
        let params = build_filter(&ids, 400, 0.01);
        RequestSync {
            p: params.p,
            m: params.m,
            data: params.data,
            types,
            since_timestamp: None,
            fragment_id_filter: None,
        }
    }

    fn bodies(packets: &[Packet]) -> Vec<Vec<u8>> {
        packets.iter().map(|p| p.payload.clone()).collect()
    }

    #[test]
    fn a_peer_holding_nothing_is_sent_everything_we_have() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"one"), NOW);
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"two"), NOW);

        let request = request_holding(&[], None);
        let sent = respond(&archive, &request, NOW);
        assert_eq!(bodies(&sent), vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn a_packet_the_filter_claims_is_not_sent_again() {
        let mut archive = Archive::new();
        let held = packet_at(MessageType::Message, 1, NOW, b"they have this");
        let fresh = packet_at(MessageType::Message, 1, NOW, b"they do not");
        archive.record(&held, NOW);
        archive.record(&fresh, NOW);

        let request = request_holding(&[&held], None);
        let sent = respond(&archive, &request, NOW);
        assert_eq!(bodies(&sent), vec![b"they do not".to_vec()]);
    }

    #[test]
    fn a_second_round_with_nothing_new_sends_nothing() {
        // The property that stops this flooding the mesh every fifteen seconds.
        let mut archive = Archive::new();
        let a = packet_at(MessageType::Message, 1, NOW, b"a");
        let b = packet_at(MessageType::Message, 1, NOW, b"b");
        archive.record(&a, NOW);
        archive.record(&b, NOW);

        let request = request_holding(&[&a, &b], None);
        assert!(respond(&archive, &request, NOW).is_empty());
    }

    #[test]
    fn a_reply_is_marked_solicited_and_will_not_be_relayed() {
        let mut archive = Archive::new();
        let original = packet_at(MessageType::Message, 1, NOW, b"body");
        archive.record(&original, NOW);
        assert!(original.ttl > 1, "the stored copy is relayable");

        let sent = respond(&archive, &request_holding(&[], None), NOW);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ttl, 0, "a reply must not travel past its requester");
        assert!(sent[0].is_rsr, "and must be marked as solicited");
        // Everything that identifies the message is untouched.
        assert_eq!(sent[0].payload, original.payload);
        assert_eq!(sent[0].timestamp, original.timestamp);
        assert_eq!(packet_id(&sent[0]), packet_id(&original));
    }

    #[test]
    fn only_the_types_asked_for_come_back() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"msg"), NOW);
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, &[7u8; 16]), NOW);
        archive.record(&packet_at(MessageType::FileTransfer, 1, NOW, b"file"), NOW);

        let only_messages = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[MessageType::Message])),
        );
        assert_eq!(bodies(&respond(&archive, &only_messages, NOW)), vec![b"msg".to_vec()]);

        let only_files = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[MessageType::FileTransfer])),
        );
        assert_eq!(bodies(&respond(&archive, &only_files, NOW)), vec![b"file".to_vec()]);
    }

    #[test]
    fn a_request_naming_no_types_gets_public_messages() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Announce, 1, NOW, b"who"), NOW);
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"what"), NOW);
        archive.record(&packet_at(MessageType::FileTransfer, 1, NOW, b"file"), NOW);

        let sent = respond(&archive, &request_holding(&[], None), NOW);
        // announce + message, and not the file.
        assert_eq!(bodies(&sent), vec![b"who".to_vec(), b"what".to_vec()]);
    }

    #[test]
    fn a_request_naming_types_we_cannot_serve_gets_the_ones_we_can() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"msg"), NOW);
        let request = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[
                MessageType::Message,
                MessageType::BoardPost,
                MessageType::GroupMessage,
            ])),
        );
        assert_eq!(bodies(&respond(&archive, &request, NOW)), vec![b"msg".to_vec()]);
    }

    #[test]
    fn the_cursor_holds_back_packets_the_filter_never_covered() {
        // Without this, everything older than the filter's coverage looks
        // absent and is re-sent on every round forever.
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW - 10_000, b"old"), NOW);
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"new"), NOW);

        let mut request = request_holding(&[], None);
        request.since_timestamp = Some(NOW - 5_000);
        assert_eq!(bodies(&respond(&archive, &request, NOW)), vec![b"new".to_vec()]);
    }

    #[test]
    fn the_cursor_does_not_hold_back_announces() {
        // A peer that just arrived must be able to learn a signing key older
        // than its own arrival, or it cannot verify anything else we send.
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Announce, 1, NOW - 10_000, b"old key"), NOW);

        let mut request = request_holding(&[], None);
        request.since_timestamp = Some(NOW - 5_000);
        assert_eq!(bodies(&respond(&archive, &request, NOW)), vec![b"old key".to_vec()]);
    }

    #[test]
    fn a_packet_past_the_freshness_window_is_never_offered() {
        let mut archive = Archive::new();
        archive.record(&packet_at(
            MessageType::Message,
            1,
            NOW - crate::sync::archive::MAX_AGE_MS - 1,
            b"ancient",
        ), NOW);
        assert!(respond(&archive, &request_holding(&[], None), NOW).is_empty());
    }

    #[test]
    fn a_fragment_filter_narrows_to_the_stalled_streams() {
        let mut archive = Archive::new();
        let mut wanted = vec![0x01u8; 8];
        wanted.extend_from_slice(b"piece of the wanted stream");
        let mut other = vec![0x02u8; 8];
        other.extend_from_slice(b"piece of another stream");
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, &wanted), NOW);
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, &other), NOW);

        let mut request = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[MessageType::Fragment])),
        );
        request.fragment_id_filter = Some("0101010101010101".to_string());

        let sent = respond(&archive, &request, NOW);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, wanted);
    }

    #[test]
    fn a_fragment_filter_reaches_past_the_cursor() {
        // Targeted recovery exists to fetch pieces older than the coverage the
        // requester could describe, so the cursor must not veto it.
        let mut archive = Archive::new();
        let mut old_piece = vec![0x01u8; 8];
        old_piece.extend_from_slice(b"stalled long ago");
        archive.record(&packet_at(MessageType::Fragment, 1, NOW - 10_000, &old_piece), NOW);

        let mut request = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[MessageType::Fragment])),
        );
        request.since_timestamp = Some(NOW - 5_000);
        request.fragment_id_filter = Some("0101010101010101".to_string());

        assert_eq!(respond(&archive, &request, NOW).len(), 1);
    }

    #[test]
    fn a_fragment_shorter_than_its_stream_id_is_skipped_not_panicked_on() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, &[0x01, 0x02]), NOW);

        let mut request = request_holding(
            &[],
            Some(SyncTypeFlags::from_types(&[MessageType::Fragment])),
        );
        request.fragment_id_filter = Some("0101010101010101".to_string());
        assert!(respond(&archive, &request, NOW).is_empty());
    }

    #[test]
    fn an_unreadable_filter_makes_us_send_everything_rather_than_nothing() {
        // decode refuses out-of-range parameters, and the safe reading of "we
        // learned nothing about what they hold" is to offer it all.
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"body"), NOW);

        let request = RequestSync {
            p: 7,
            m: 1, // m <= 1 makes the decoder refuse
            data: vec![0xFF; 8],
            types: None,
            since_timestamp: None,
            fragment_id_filter: None,
        };
        assert_eq!(respond(&archive, &request, NOW).len(), 1);
    }

    #[test]
    fn nothing_held_means_nothing_sent() {
        let archive = Archive::new();
        assert!(respond(&archive, &request_holding(&[], None), NOW).is_empty());
    }
}
