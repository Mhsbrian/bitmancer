// src/relay.rs
//
// Whether to pass a mesh packet along.
//
// A flooded mesh works because every node rebroadcasts what it hears, minus a
// hop of TTL. The rule that makes it terminate — and the one that matters most
// here — is that a packet is never sent back out the link it arrived on.
//
// With a single link every rebroadcast would go back to the peer that just
// spoke, which is an echo rather than a relay, so this was written as a policy
// that yields `Suppress` in that case rather than as a rebroadcast that happened
// to be harmful. The transport now holds several links and the same policy
// forwards, unchanged.
//
// TTL alone would eventually stop a flood, but not before the same packet went
// round several times: a node with three links hands a copy to two neighbours,
// who hand it back to each other. So a packet is also only ever forwarded once,
// keyed on everything about it *except* the TTL — which mutates on every hop and
// is precisely what must not distinguish two copies of one message.

use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};

use crate::protocol::{MessageType, Packet};

/// Upstream's `messageTTLDefault`, and the ceiling we accept from a peer.
pub const MAX_TTL: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relay {
    /// Send it on with this TTL, to every link except the one named.
    Forward { ttl: u8, except_link: String },
    Suppress(&'static str),
}

/// Decides what to do with a packet we just received.
///
/// `links` is every link we could send on; `ingress` is the one it came from.
pub fn plan(packet: &Packet, links: &[String], ingress: &str, local_peer_id: &str) -> Relay {
    // Our own traffic coming back to us is the flood working, not something to
    // amplify.
    if packet.sender_hex() == local_peer_id {
        return Relay::Suppress("our own packet");
    }

    // TTL 1 means "last hop"; 0 means it has already been consumed.
    if packet.ttl <= 1 {
        return Relay::Suppress("time to live exhausted");
    }
    if packet.ttl > MAX_TTL {
        // A peer inflating TTL would otherwise buy unbounded amplification.
        return Relay::Suppress("time to live above the protocol maximum");
    }

    // Anything addressed to us specifically has arrived; forwarding it would
    // leak a private exchange back onto the air.
    if !packet.is_broadcast() && packet.recipient_hex().as_deref() == Some(local_peer_id) {
        return Relay::Suppress("addressed to us");
    }

    match packet.parsed_type() {
        // Presence is per-link state, not something to carry onward: upstream
        // rebuilds it from each peer's own announce.
        Some(MessageType::Announce) | Some(MessageType::Leave) => {
            return Relay::Suppress("presence is not relayed")
        }
        // An unknown type might carry rules we do not understand.
        None => return Relay::Suppress("unknown packet type"),
        _ => {}
    }

    let onward: Vec<&String> = links.iter().filter(|link| *link != ingress).collect();
    if onward.is_empty() {
        return Relay::Suppress("no link other than the one it came from");
    }

    Relay::Forward {
        ttl: packet.ttl - 1,
        except_link: ingress.to_string(),
    }
}

/// How many forwarded packets to remember. A flood arrives within a second or
/// two of being sent, so this only has to outlive the burst, not the session.
const FORWARDED_LIMIT: usize = 1024;

/// Packets already passed on, so a copy arriving from another link is not sent
/// round a second time.
#[derive(Default)]
pub struct Forwarded {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}

impl Forwarded {
    /// Records a packet, reporting whether this is the first sighting.
    ///
    /// Stored as a 64-bit digest rather than the packet: the set only has to
    /// answer "have I seen this", and keeping a thousand full payloads to
    /// answer it would cost more than the flood does. A collision drops one
    /// relay, which the flood routes around; at this size it is not a risk
    /// worth carrying whole packets to avoid.
    pub fn accept(&mut self, packet: &Packet) -> bool {
        let digest = digest(packet);
        if !self.seen.insert(digest) {
            return false;
        }
        self.order.push_back(digest);
        if self.order.len() > FORWARDED_LIMIT {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

/// Identity of a packet across hops.
///
/// TTL is excluded deliberately — it is decremented by every relay, so
/// including it would make each hop look like a different message and defeat
/// the whole purpose. The signature is excluded for the same reason it is not
/// recomputed: it does not cover the TTL, so it is identical on every copy and
/// adds nothing.
fn digest(packet: &Packet) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    packet.sender_id.hash(&mut hasher);
    packet.recipient_id.hash(&mut hasher);
    packet.timestamp.hash(&mut hasher);
    packet.msg_type.hash(&mut hasher);
    packet.payload.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "aaaaaaaaaaaaaaaa";

    fn packet(ttl: u8) -> Packet {
        Packet::new(MessageType::Message, [0xBB; 8], b"hello".to_vec(), ttl)
    }

    #[test]
    fn a_forwarded_copy_still_carries_a_valid_signature() {
        // Forwarding rebuilds the frame with one less TTL rather than resending
        // the bytes verbatim, which is only safe because the signature excludes
        // the TTL — the one field a relay is expected to change. If that ever
        // stopped holding, every relayed packet would be rejected as forged by
        // the peer it reached, and nothing local would fail.
        let mut original = packet(7);
        original.signature = Some(vec![0x11; crate::protocol::SIGNATURE_SIZE]);
        let signed_over = original.signing_bytes().expect("a signable packet");

        let wire = original.encode().expect("encodes");
        let mut received = Packet::decode(&wire).expect("decodes");
        received.ttl -= 1;
        let onward = received.encode().expect("re-encodes for the next hop");
        let arrived = Packet::decode(&onward).expect("the far end decodes it");

        assert_eq!(arrived.ttl, 6, "one hop consumed");
        assert_eq!(
            arrived.signature, original.signature,
            "the signature travels unchanged"
        );
        assert_eq!(
            arrived.signing_bytes().expect("still signable"),
            signed_over,
            "and still covers exactly the bytes that were signed"
        );
    }

    #[test]
    fn a_packet_is_only_forwarded_once() {
        // Three links means two neighbours get a copy, and they hand it to each
        // other. TTL would stop that eventually; this stops it immediately.
        let mut forwarded = Forwarded::default();
        assert!(forwarded.accept(&packet(7)), "the first sighting relays");
        assert!(!forwarded.accept(&packet(7)), "the copy does not");
    }

    #[test]
    fn a_copy_that_has_been_relayed_is_recognised_at_any_ttl() {
        // The whole point. Every hop decrements the TTL, so including it in the
        // identity would make each copy look like a new message and the dedup
        // would never fire.
        let mut forwarded = Forwarded::default();
        let original = packet(7);
        assert!(forwarded.accept(&original));
        for ttl in [6, 5, 4, 1] {
            let mut hop = original.clone();
            hop.ttl = ttl;
            assert!(
                !forwarded.accept(&hop),
                "ttl {ttl} is the same message one hop along"
            );
        }
    }

    #[test]
    fn different_messages_are_told_apart() {
        let mut forwarded = Forwarded::default();
        let first = packet(7);
        let mut second = packet(7);
        second.payload = b"different".to_vec();
        let mut third = packet(7);
        third.timestamp = first.timestamp.wrapping_add(1);
        let mut fourth = packet(7);
        fourth.sender_id = [0xCC; 8];

        assert!(forwarded.accept(&first));
        assert!(forwarded.accept(&second), "different content");
        assert!(forwarded.accept(&third), "different send time");
        assert!(forwarded.accept(&fourth), "different sender");
    }

    #[test]
    fn a_private_packet_is_not_confused_with_a_broadcast() {
        // Same bytes, different addressee. Collapsing them would drop one.
        let mut forwarded = Forwarded::default();
        let broadcast = packet(7);
        let addressed = packet(7).with_recipient([0x11; 8]);
        assert!(forwarded.accept(&broadcast));
        assert!(forwarded.accept(&addressed));
    }

    #[test]
    fn the_memory_is_bounded_and_forgets_the_oldest() {
        let mut forwarded = Forwarded::default();
        for index in 0..(FORWARDED_LIMIT + 10) {
            let mut unique = packet(7);
            unique.timestamp = index as u64;
            assert!(forwarded.accept(&unique));
        }
        assert_eq!(forwarded.seen.len(), FORWARDED_LIMIT);
        let mut oldest = packet(7);
        oldest.timestamp = 0;
        assert!(
            forwarded.accept(&oldest),
            "past the window it is treated as new, which costs one extra relay"
        );
    }

    #[test]
    fn a_single_link_never_relays() {
        // The whole reason this module is a policy and not a rebroadcast: with
        // one link, forwarding sends the packet back to its author.
        let links = vec!["link-a".to_string()];
        assert_eq!(
            plan(&packet(7), &links, "link-a", ME),
            Relay::Suppress("no link other than the one it came from")
        );
    }

    #[test]
    fn a_second_link_makes_forwarding_correct() {
        let links = vec!["link-a".to_string(), "link-b".to_string()];
        assert_eq!(
            plan(&packet(7), &links, "link-a", ME),
            Relay::Forward {
                ttl: 6,
                except_link: "link-a".to_string()
            }
        );
    }

    #[test]
    fn the_hop_count_decreases_so_the_flood_terminates() {
        let links = vec!["a".to_string(), "b".to_string()];
        for ttl in 2..=MAX_TTL {
            match plan(&packet(ttl), &links, "a", ME) {
                Relay::Forward { ttl: onward, .. } => assert_eq!(onward, ttl - 1),
                other => panic!("ttl {ttl} should forward, got {other:?}"),
            }
        }
        assert!(matches!(plan(&packet(1), &links, "a", ME), Relay::Suppress(_)));
        assert!(matches!(plan(&packet(0), &links, "a", ME), Relay::Suppress(_)));
    }

    #[test]
    fn an_inflated_hop_count_is_refused() {
        let links = vec!["a".to_string(), "b".to_string()];
        assert_eq!(
            plan(&packet(MAX_TTL + 1), &links, "a", ME),
            Relay::Suppress("time to live above the protocol maximum")
        );
        assert_eq!(
            plan(&packet(255), &links, "a", ME),
            Relay::Suppress("time to live above the protocol maximum")
        );
    }

    #[test]
    fn our_own_echo_is_not_amplified() {
        let links = vec!["a".to_string(), "b".to_string()];
        let mut mine = packet(7);
        mine.sender_id = crate::protocol::peer_id_to_bytes(ME);
        assert_eq!(
            plan(&mine, &links, "a", ME),
            Relay::Suppress("our own packet")
        );
    }

    #[test]
    fn a_packet_addressed_to_us_stops_here() {
        let links = vec!["a".to_string(), "b".to_string()];
        let directed = packet(7).with_recipient(crate::protocol::peer_id_to_bytes(ME));
        assert_eq!(
            plan(&directed, &links, "a", ME),
            Relay::Suppress("addressed to us")
        );
    }

    #[test]
    fn a_packet_addressed_to_someone_else_is_carried() {
        let links = vec!["a".to_string(), "b".to_string()];
        let directed = packet(7).with_recipient([0xCC; 8]);
        assert!(matches!(
            plan(&directed, &links, "a", ME),
            Relay::Forward { .. }
        ));
    }

    #[test]
    fn presence_is_not_relayed() {
        let links = vec!["a".to_string(), "b".to_string()];
        for kind in [MessageType::Announce, MessageType::Leave] {
            let presence = Packet::new(kind, [0xBB; 8], Vec::new(), 7);
            assert_eq!(
                plan(&presence, &links, "a", ME),
                Relay::Suppress("presence is not relayed")
            );
        }
    }

    #[test]
    fn unknown_types_are_not_carried_blindly() {
        let links = vec!["a".to_string(), "b".to_string()];
        let mut strange = packet(7);
        strange.msg_type = 0x77;
        assert_eq!(
            plan(&strange, &links, "a", ME),
            Relay::Suppress("unknown packet type")
        );
    }

    #[test]
    fn fragments_and_files_are_carried() {
        let links = vec!["a".to_string(), "b".to_string()];
        for kind in [
            MessageType::Fragment,
            MessageType::FileTransfer,
            MessageType::NoiseEncrypted,
        ] {
            let carried = Packet::new(kind, [0xBB; 8], vec![0u8; 16], 7);
            assert!(
                matches!(plan(&carried, &links, "a", ME), Relay::Forward { .. }),
                "{kind:?} should be relayed"
            );
        }
    }
}
