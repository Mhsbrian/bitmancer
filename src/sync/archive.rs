// src/sync/archive.rs
//
// What we hold on behalf of the room. Port of the storage half of upstream
// `Sync/GossipSyncManager.swift` — its `PacketStore`, its capacities, and its
// freshness rules.
//
// This is a record of what was said near us, so it is memory-only and `/wipe`
// clears it. Upstream persists an equivalent archive to disk; that is a separate
// decision with its own privacy argument and is deliberately not made here.

use std::collections::HashMap;

use crate::protocol::{MessageType, Packet};

use super::packet_id::{packet_id, PACKET_ID_LEN};

/// Public messages held for re-offering. Upstream's `seenCapacity`.
pub const MESSAGE_CAPACITY: usize = 1000;
/// Upstream's `fragmentCapacity`.
pub const FRAGMENT_CAPACITY: usize = 600;
/// Upstream's `fileTransferCapacity`.
pub const FILE_CAPACITY: usize = 200;

/// How long a packet stays syncable, in milliseconds.
///
/// Upstream's `maxMessageAgeSeconds` and `publicMessageMaxAgeSeconds` are both
/// 900. Worth stating because two things in the upstream tree disagree with the
/// constant: `WHITEPAPER.md` section 6.3 says public history is retained for six
/// hours, and the comment directly above `publicMessageMaxAgeSeconds` says
/// public messages stay syncable "much longer". The shipped value is 900 for
/// both, and 900 is what interoperates. Holding six hours would mean re-offering
/// packets every phone in the room dropped long ago, on every round, forever.
pub const MAX_AGE_MS: u64 = 900 * 1000;

/// How recent an announce must be to be *filed*, in milliseconds.
///
/// Upstream gates announces twice on the way in: `isPacketFresh` at 900s like
/// everything else, and then `isAnnouncementFresh` at `stalePeerTimeoutSeconds`
/// = 60, which also forgets the peer when it fails. Only the tighter gate has
/// any effect, so that is what this is.
///
/// It matters because an announce is a claim about who is *here*. Without it a
/// peer could replay a fourteen-minute-old announce and have us re-serve it to
/// the room as current presence. Our own `ANNOUNCE_INTERVAL` is 10s, so a
/// genuine announce clears this by a wide margin.
///
/// Announces already filed stay servable for the full `MAX_AGE_MS`, matching
/// upstream: the responder checks the loose window, not this one.
pub const ANNOUNCE_RECORD_MAX_AGE_MS: u64 = 60 * 1000;

/// Which store a packet belongs in.
///
/// Only the types this client actually speaks. Upstream also syncs board posts,
/// prekey bundles and group messages; we do not implement those opcodes at all,
/// so there would never be one to hold and a store for them would be an empty
/// promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Message,
    Fragment,
    File,
}

impl Kind {
    pub fn of(message_type: MessageType) -> Option<Self> {
        Some(match message_type {
            MessageType::Message => Self::Message,
            MessageType::Fragment => Self::Fragment,
            MessageType::FileTransfer => Self::File,
            _ => return None,
        })
    }

    fn capacity(self) -> usize {
        match self {
            Self::Message => MESSAGE_CAPACITY,
            Self::Fragment => FRAGMENT_CAPACITY,
            Self::File => FILE_CAPACITY,
        }
    }
}

/// An insertion-ordered, capacity-bounded set of packets.
///
/// The order is what makes eviction "oldest first" without consulting the clock,
/// and what lets the responder walk the store in a stable order.
#[derive(Default)]
struct PacketStore {
    packets: HashMap<[u8; PACKET_ID_LEN], Packet>,
    order: Vec<[u8; PACKET_ID_LEN]>,
}

impl PacketStore {
    /// Records a packet, evicting the oldest once over capacity.
    ///
    /// Re-inserting a packet we already hold replaces the value and leaves its
    /// position alone. A relayed copy of an old message must not be able to
    /// push itself to the front of the queue and evict something newer.
    fn insert(&mut self, id: [u8; PACKET_ID_LEN], packet: Packet, capacity: usize) {
        if capacity == 0 {
            return;
        }
        if self.packets.insert(id, packet).is_some() {
            return;
        }
        self.order.push(id);
        while self.order.len() > capacity {
            let victim = self.order.remove(0);
            self.packets.remove(&victim);
        }
    }

    fn fresh(&self, now_ms: u64) -> Vec<&Packet> {
        self.order
            .iter()
            .filter_map(|id| self.packets.get(id))
            .filter(|packet| is_fresh(packet, now_ms))
            .collect()
    }

    fn drop_stale(&mut self, now_ms: u64) {
        let packets = &mut self.packets;
        self.order.retain(|id| match packets.get(id) {
            Some(packet) if is_fresh(packet, now_ms) => true,
            _ => {
                packets.remove(id);
                false
            }
        });
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Whether a packet is still inside the sync window.
///
/// A timestamp in the future is treated as fresh rather than clamped. It is a
/// remote value and this client has been bitten by trusting one before, but the
/// consequence here is bounded: the worst a peer can do by lying forward is keep
/// its own packet in our store until the capacity evicts it.
fn is_fresh(packet: &Packet, now_ms: u64) -> bool {
    now_ms.saturating_sub(packet.timestamp) <= MAX_AGE_MS
}

/// The public history this client holds on behalf of the room.
#[derive(Default)]
pub struct Archive {
    messages: PacketStore,
    fragments: PacketStore,
    files: PacketStore,
    /// The latest announce from each peer, keyed by sender.
    ///
    /// A map rather than a store because there is only ever one worth holding
    /// per peer — a newer announce completely replaces an older one, and the
    /// responder sends every fresh announce it has regardless of the request's
    /// since-cursor.
    announces: HashMap<[u8; 8], Packet>,
}

impl Archive {
    pub fn new() -> Self {
        Self::default()
    }

    /// Files a packet if it is a type gossip sync carries.
    ///
    /// Returns whether it was kept, which is only used by tests and logging —
    /// callers hand everything past and let the archive decide.
    pub fn record(&mut self, packet: &Packet, now_ms: u64) -> bool {
        // Only broadcast traffic is public history. A packet addressed to
        // someone is a private exchange and re-offering it to the room would be
        // the worst bug in this file.
        if !packet.is_broadcast() {
            return false;
        }
        let Some(message_type) = packet.parsed_type() else {
            return false;
        };
        if !is_fresh(packet, now_ms) {
            return false;
        }

        if message_type == MessageType::Announce {
            // An announce that has aged past the presence window is not
            // evidence anyone is here. Upstream also drops what it knew about
            // that peer at this point rather than leaving a stale claim behind.
            if now_ms.saturating_sub(packet.timestamp) > ANNOUNCE_RECORD_MAX_AGE_MS {
                self.announces.remove(&packet.sender_id);
                return false;
            }
            self.announces.insert(packet.sender_id, packet.clone());
            return true;
        }

        let Some(kind) = Kind::of(message_type) else {
            return false;
        };
        let id = packet_id(packet);
        self.store_mut(kind).insert(id, packet.clone(), kind.capacity());
        true
    }

    fn store_mut(&mut self, kind: Kind) -> &mut PacketStore {
        match kind {
            Kind::Message => &mut self.messages,
            Kind::Fragment => &mut self.fragments,
            Kind::File => &mut self.files,
        }
    }

    fn store(&self, kind: Kind) -> &PacketStore {
        match kind {
            Kind::Message => &self.messages,
            Kind::Fragment => &self.fragments,
            Kind::File => &self.files,
        }
    }

    /// Packets of one kind still inside the window, oldest first.
    pub fn fresh(&self, kind: Kind, now_ms: u64) -> Vec<&Packet> {
        self.store(kind).fresh(now_ms)
    }

    /// Every peer's latest announce that is still inside the window.
    pub fn fresh_announces(&self, now_ms: u64) -> Vec<&Packet> {
        let mut fresh: Vec<&Packet> = self
            .announces
            .values()
            .filter(|packet| is_fresh(packet, now_ms))
            .collect();
        // A HashMap iterates in an unspecified order, which would make the
        // responder's output vary run to run. Sorting by sender keeps a reply
        // reproducible, which is what makes it testable.
        fresh.sort_by_key(|packet| packet.sender_id);
        fresh
    }

    /// Drops everything outside the window. Cheap enough to call per tick.
    pub fn drop_stale(&mut self, now_ms: u64) {
        self.messages.drop_stale(now_ms);
        self.fragments.drop_stale(now_ms);
        self.files.drop_stale(now_ms);
        self.announces
            .retain(|_, packet| is_fresh(packet, now_ms));
    }

    /// Forgets a peer's announce, for when they leave.
    pub fn forget_peer(&mut self, sender_id: &[u8; 8]) {
        self.announces.remove(sender_id);
    }

    /// Forgets everything.
    ///
    /// This is a log of what the room said near us, so it belongs in `/wipe`
    /// for the same reason `nostr/processed.rs` does: a list of what we heard is
    /// a record of who was there.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.fragments.clear();
        self.files.clear();
        self.announces.clear();
    }

    #[cfg(test)]
    pub fn len(&self, kind: Kind) -> usize {
        self.store(kind).len()
    }

    #[cfg(test)]
    pub fn announce_count(&self) -> usize {
        self.announces.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.messages.len() == 0
            && self.fragments.len() == 0
            && self.files.len() == 0
            && self.announces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_785_000_000_000;

    fn packet_at(message_type: MessageType, sender: u8, timestamp: u64, body: &[u8]) -> Packet {
        let mut packet = Packet::new(message_type, [sender; 8], body.to_vec(), 7);
        packet.timestamp = timestamp;
        packet
    }

    fn message_at(sender: u8, timestamp: u64, body: &[u8]) -> Packet {
        packet_at(MessageType::Message, sender, timestamp, body)
    }

    #[test]
    fn a_broadcast_message_is_kept_and_can_be_read_back() {
        let mut archive = Archive::new();
        assert!(archive.record(&message_at(1, NOW, b"hello"), NOW));
        let held = archive.fresh(Kind::Message, NOW);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].payload, b"hello");
    }

    #[test]
    fn a_packet_addressed_to_someone_is_never_public_history() {
        // The worst bug this file could have: re-offering a private exchange to
        // the room.
        let mut archive = Archive::new();
        let mut private = message_at(1, NOW, b"for you only");
        private.recipient_id = Some([2u8; 8]);
        assert!(!private.is_broadcast());
        assert!(!archive.record(&private, NOW));
        assert!(archive.is_empty());
    }

    #[test]
    fn the_types_gossip_does_not_carry_are_not_stored() {
        let mut archive = Archive::new();
        for message_type in [
            MessageType::CourierEnvelope,
            MessageType::NoiseHandshake,
            MessageType::NoiseEncrypted,
            MessageType::NostrCarrier,
            MessageType::VoiceFrame,
            MessageType::Leave,
        ] {
            assert!(
                !archive.record(&packet_at(message_type, 1, NOW, b"x"), NOW),
                "{message_type:?} must not be archived"
            );
        }
        assert!(archive.is_empty());
    }

    #[test]
    fn each_kind_lands_in_its_own_store() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Message, 1, NOW, b"m"), NOW);
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, b"f"), NOW);
        archive.record(&packet_at(MessageType::FileTransfer, 1, NOW, b"t"), NOW);
        assert_eq!(archive.len(Kind::Message), 1);
        assert_eq!(archive.len(Kind::Fragment), 1);
        assert_eq!(archive.len(Kind::File), 1);
    }

    #[test]
    fn a_relayed_copy_is_recognised_rather_than_stored_twice() {
        let mut archive = Archive::new();
        let original = message_at(1, NOW, b"once");
        let mut relayed = original.clone();
        relayed.ttl = original.ttl - 1;
        archive.record(&original, NOW);
        archive.record(&relayed, NOW);
        // The id excludes the hop count, so both are the same message.
        assert_eq!(archive.len(Kind::Message), 1);
    }

    #[test]
    fn a_repeat_does_not_move_a_packet_to_the_front_of_the_queue() {
        // Otherwise a peer could keep re-sending one old message and evict
        // everything newer out from under the room.
        let mut archive = Archive::new();
        for i in 0..MESSAGE_CAPACITY {
            archive.record(&message_at(1, NOW, format!("m{i}").as_bytes()), NOW);
        }
        // Re-record the oldest, then push one more in.
        archive.record(&message_at(1, NOW, b"m0"), NOW);
        archive.record(&message_at(1, NOW, b"newest"), NOW);

        let held = archive.fresh(Kind::Message, NOW);
        assert_eq!(held.len(), MESSAGE_CAPACITY);
        let bodies: Vec<&[u8]> = held.iter().map(|p| p.payload.as_slice()).collect();
        assert!(
            !bodies.contains(&b"m0".as_slice()),
            "the re-sent oldest packet should still have been the one evicted"
        );
        assert!(bodies.contains(&b"newest".as_slice()));
    }

    #[test]
    fn each_store_is_bounded_by_its_own_capacity() {
        let mut archive = Archive::new();
        for i in 0..(MESSAGE_CAPACITY + 50) {
            archive.record(&message_at(1, NOW, format!("m{i}").as_bytes()), NOW);
        }
        for i in 0..(FILE_CAPACITY + 50) {
            archive.record(
                    &packet_at(MessageType::FileTransfer, 1, NOW, format!("f{i}").as_bytes()),
                    NOW,
                );
        }
        assert_eq!(archive.len(Kind::Message), MESSAGE_CAPACITY);
        assert_eq!(archive.len(Kind::File), FILE_CAPACITY);

        // And the survivors are the newest, not the first arrivals.
        let held = archive.fresh(Kind::Message, NOW);
        assert_eq!(held[0].payload, b"m50");
    }

    #[test]
    fn a_packet_past_the_window_is_refused_at_the_door() {
        // Upstream guards on freshness before filing, not only before serving,
        // so a peer replaying something ancient cannot take up a slot at all.
        let mut archive = Archive::new();
        assert!(!archive.record(&message_at(1, NOW - MAX_AGE_MS - 1, b"stale"), NOW));
        assert!(archive.record(&message_at(1, NOW - MAX_AGE_MS, b"just inside"), NOW));

        let held = archive.fresh(Kind::Message, NOW);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].payload, b"just inside");
        assert_eq!(archive.len(Kind::Message), 1, "the stale one never landed");
    }

    #[test]
    fn a_packet_that_ages_out_while_held_stops_being_offered() {
        // The other half: something filed while fresh must drop out of the
        // answer once the window passes it, without waiting for a sweep.
        let mut archive = Archive::new();
        assert!(archive.record(&message_at(1, NOW, b"fresh now"), NOW));
        assert_eq!(archive.fresh(Kind::Message, NOW).len(), 1);
        assert!(archive.fresh(Kind::Message, NOW + MAX_AGE_MS + 1).is_empty());
        assert_eq!(archive.len(Kind::Message), 1, "held until swept");
    }

    #[test]
    fn an_announce_replayed_from_long_ago_is_not_treated_as_presence() {
        // An announce is a claim that somebody is here now. Upstream gates it
        // on a 60s window rather than the 900s one, and forgets the peer when
        // it fails, so a replayed announce cannot resurrect a departed peer.
        let mut archive = Archive::new();
        assert!(archive.record(
            &packet_at(MessageType::Announce, 1, NOW, b"here now"),
            NOW
        ));
        assert_eq!(archive.announce_count(), 1);

        let replayed = packet_at(
            MessageType::Announce,
            1,
            NOW - ANNOUNCE_RECORD_MAX_AGE_MS - 1,
            b"here ages ago",
        );
        assert!(!archive.record(&replayed, NOW));
        assert_eq!(
            archive.announce_count(),
            0,
            "and what we knew about that peer goes with it"
        );

        // Just inside the window is still presence.
        assert!(archive.record(
            &packet_at(
                MessageType::Announce,
                2,
                NOW - ANNOUNCE_RECORD_MAX_AGE_MS,
                b"only just"
            ),
            NOW
        ));
        assert_eq!(archive.announce_count(), 1);
    }

    #[test]
    fn an_announce_already_filed_stays_servable_past_the_presence_window() {
        // Recording is gated at 60s; serving is gated at 900s. Upstream splits
        // them this way so a peer that has gone quiet is still introduced to a
        // newcomer who needs its signing key.
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Announce, 1, NOW, b"key"), NOW);
        let later = NOW + ANNOUNCE_RECORD_MAX_AGE_MS + 1;
        assert_eq!(archive.fresh_announces(later).len(), 1);
    }

    #[test]
    fn sweeping_reclaims_the_stale_entries() {
        let mut archive = Archive::new();
        archive.record(&message_at(1, NOW - MAX_AGE_MS - 1, b"stale"), NOW);
        archive.record(&message_at(1, NOW, b"fresh"), NOW);
        archive.drop_stale(NOW);
        assert_eq!(archive.len(Kind::Message), 1);
        assert_eq!(archive.fresh(Kind::Message, NOW)[0].payload, b"fresh");
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_hide_everything() {
        // saturating_sub, so a `now` behind the packet's stamp reads as age
        // zero rather than wrapping to a colossal age and sweeping the store.
        let mut archive = Archive::new();
        archive.record(&message_at(1, NOW, b"from the future"), NOW);
        assert_eq!(archive.fresh(Kind::Message, NOW - 60_000).len(), 1);
        archive.drop_stale(NOW - 60_000);
        assert_eq!(archive.len(Kind::Message), 1);
    }

    #[test]
    fn only_the_latest_announce_from_a_peer_is_kept() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Announce, 1, NOW - 1000, b"old name"), NOW);
        archive.record(&packet_at(MessageType::Announce, 1, NOW, b"new name"), NOW);
        archive.record(&packet_at(MessageType::Announce, 2, NOW, b"someone else"), NOW);
        assert_eq!(archive.announce_count(), 2);
        let held = archive.fresh_announces(NOW);
        assert_eq!(held[0].payload, b"new name");
        assert_eq!(held[1].payload, b"someone else");
    }

    #[test]
    fn announces_are_listed_in_a_stable_order() {
        // A HashMap would hand them back differently run to run, which makes a
        // responder's reply unreproducible and its test flaky.
        let mut archive = Archive::new();
        for sender in [9u8, 3, 7, 1] {
            archive.record(&packet_at(MessageType::Announce, sender, NOW, b"a"), NOW);
        }
        let senders: Vec<u8> = archive
            .fresh_announces(NOW)
            .iter()
            .map(|p| p.sender_id[0])
            .collect();
        assert_eq!(senders, vec![1, 3, 7, 9]);
    }

    #[test]
    fn a_stale_announce_is_neither_offered_nor_kept() {
        let mut archive = Archive::new();
        archive.record(&packet_at(
            MessageType::Announce,
            1,
            NOW - MAX_AGE_MS - 1,
            b"gone",
        ), NOW);
        assert!(archive.fresh_announces(NOW).is_empty());
        archive.drop_stale(NOW);
        assert_eq!(archive.announce_count(), 0);
    }

    #[test]
    fn a_departed_peer_can_be_forgotten() {
        let mut archive = Archive::new();
        archive.record(&packet_at(MessageType::Announce, 1, NOW, b"here"), NOW);
        archive.forget_peer(&[1u8; 8]);
        assert_eq!(archive.announce_count(), 0);
    }

    #[test]
    fn a_wipe_leaves_nothing_behind() {
        // The archive is a record of what the room said near us. `/wipe` has to
        // reach it for the same reason it reaches the opened-envelope list.
        let mut archive = Archive::new();
        archive.record(&message_at(1, NOW, b"said"), NOW);
        archive.record(&packet_at(MessageType::Fragment, 1, NOW, b"frag"), NOW);
        archive.record(&packet_at(MessageType::FileTransfer, 1, NOW, b"file"), NOW);
        archive.record(&packet_at(MessageType::Announce, 1, NOW, b"who"), NOW);
        assert!(!archive.is_empty());

        archive.clear();

        assert!(archive.is_empty());
        assert_eq!(archive.len(Kind::Message), 0);
        assert_eq!(archive.len(Kind::Fragment), 0);
        assert_eq!(archive.len(Kind::File), 0);
        assert_eq!(archive.announce_count(), 0);
        assert!(archive.fresh_announces(NOW).is_empty());
    }
}
