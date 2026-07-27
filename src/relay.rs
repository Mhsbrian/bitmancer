// src/relay.rs
//
// Whether to pass a mesh packet along.
//
// A flooded mesh works because every node rebroadcasts what it hears, minus a
// hop of TTL. The rule that makes it terminate — and the one that matters most
// here — is that a packet is never sent back out the link it arrived on.
//
// This client currently holds exactly one BLE link, so *every* rebroadcast would
// go back to the peer that just spoke, which is an echo rather than a relay.
// The decision is therefore written as a policy that yields `Suppress` in that
// situation, rather than as a rebroadcast that happens to be harmful today: when
// multi-link support arrives, forwarding becomes correct by construction instead
// of needing to be remembered.

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

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "aaaaaaaaaaaaaaaa";

    fn packet(ttl: u8) -> Packet {
        Packet::new(MessageType::Message, [0xBB; 8], b"hello".to_vec(), ttl)
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
