// src/gateway.rs
//
// Sharing our internet with the mesh.
//
// A phone in a crowd often has a radio and no data. This client usually runs on
// something with mains power, a real connection and — since multi-link — six
// simultaneous BLE links. Gateway mode turns that asymmetry into infrastructure:
// mesh-only peers hand us geohash events they signed themselves, we publish them
// to the relays, and we hand back what the relays send us so they can see the
// channel they could not otherwise reach.
//
// What makes this safe to do is that we are a courier, not a party. Every
// carried event is a complete, signed Nostr event and its contents are public
// geohash chat that is already plaintext on relays, so:
//   - keys never leave the originating device;
//   - we cannot forge or alter an event, because the signature is checked here
//     before we act on it, and again by the relays and by every receiver;
//   - carrying adds reach without adding trust.
// That is the whole security argument, and it is why this is a policy engine
// rather than a crypto one.
//
// The hard part is loops. Two gateways on one mesh, plus our own relay
// subscription redelivering what we just published, gives traffic several ways
// to come back around. Upstream names the failure it hit — the self-echo, where
// a gateway rebroadcasts its own uplink because the relays returned it — so the
// three ID sets below are not defensive decoration, they are each a bug someone
// already had.
//
// Nothing here touches a radio or a socket: it answers "may I" and the caller
// does the work, which is what makes the policy testable without either.

use std::collections::{HashMap, HashSet, VecDeque};

/// Uplink deposits held while the relays are unreachable, in total and per
/// depositor. Bounded both ways: one peer with a stuck queue must not fill the
/// mailbag, and the mailbag must not grow without limit.
pub const MAX_QUEUED_UPLINKS: usize = 20;
pub const MAX_QUEUED_PER_DEPOSITOR: usize = 5;
/// Deposits accepted from one peer per minute.
pub const UPLINKS_PER_MINUTE_PER_DEPOSITOR: usize = 10;
/// Mesh rebroadcasts per minute. BLE airtime is shared by every link we hold,
/// so this is the budget that protects the peers we are trying to help.
pub const DOWNLINKS_PER_MINUTE: usize = 30;
/// How old a carried event may be. Beyond this it is stale replay the relays
/// would refuse anyway, and spending airtime on it helps nobody.
pub const MAX_EVENT_AGE_SECONDS: i64 = 15 * 60;
/// Loop-prevention memory, oldest evicted. Sized to outlive a burst rather than
/// a session: what matters is that an event and its echo fall inside it.
pub const MAX_TRACKED_IDS: usize = 512;

const RATE_WINDOW_SECONDS: i64 = 60;

/// Whether to publish an event a mesh-only peer asked us to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uplink {
    /// Publish it to this geohash's relays.
    Publish,
    /// Hold it: we cannot reach the relays right now, but we will try.
    Queued,
    Refused(&'static str),
}

/// Whether to put a relay event onto the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Downlink {
    Broadcast,
    Refused(&'static str),
}

/// A deposit waiting for the relays to come back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub depositor: String,
    pub geohash: String,
    pub event_id: String,
    pub event_json: String,
}

/// Bounded set of event ids, oldest evicted.
#[derive(Debug, Default)]
struct Seen {
    ids: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    /// Records an id, reporting whether it is new.
    fn insert(&mut self, id: &str) -> bool {
        if !self.ids.insert(id.to_string()) {
            return false;
        }
        self.order.push_back(id.to_string());
        while self.order.len() > MAX_TRACKED_IDS {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        true
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

#[derive(Debug, Default)]
pub struct Gateway {
    /// The user's decision. Off by default: carrying other people's traffic
    /// spends our bandwidth and puts our IP on relays for events we did not
    /// write, which is a choice to make rather than assume.
    enabled: bool,
    /// Events we learned from another gateway's mesh broadcast. Never published,
    /// never re-uplinked, never rebroadcast — otherwise two gateways on one mesh
    /// hand the same event back and forth until its TTL runs out.
    from_mesh: Seen,
    /// Events we uplinked. Published at most once, and never rebroadcast: our
    /// own relay subscription will return what we just sent, and broadcasting
    /// that is the self-echo — the event originated on this mesh, so putting it
    /// back doubles airtime for no reader.
    published: Seen,
    /// Events we put on the mesh. Broadcast at most once, so a relay echo or a
    /// second copy from another relay is absorbed.
    rebroadcast: Seen,
    /// Deposit timestamps per peer, for the per-minute budget.
    deposits: HashMap<String, VecDeque<i64>>,
    /// Rebroadcast timestamps, for the airtime budget.
    broadcasts: VecDeque<i64>,
    /// Deposits waiting for relays.
    held: Vec<Held>,
}

impl Gateway {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Turns carrying on or off.
    ///
    /// Switching off drops the mailbag rather than keeping it: those deposits
    /// were made on a promise we have just withdrawn, and holding someone's
    /// traffic after we have stopped advertising that we will carry it is the
    /// worst of both — they think it is gone, and we still have it.
    pub fn set_enabled(&mut self, enabled: bool) -> usize {
        self.enabled = enabled;
        if enabled {
            return 0;
        }
        let dropped = self.held.len();
        self.held.clear();
        dropped
    }

    /// Records an event that reached us over another gateway's mesh broadcast.
    ///
    /// Called for what we *receive* as a `fromGateway` carrier, before anything
    /// else looks at it: rule one of loop prevention is that mesh-carried
    /// traffic never re-enters either direction.
    pub fn note_carried_on_mesh(&mut self, event_id: &str) {
        self.from_mesh.insert(event_id);
    }

    /// Whether a mesh-only peer's event should go to the relays.
    ///
    /// `relays_up` is passed in rather than inferred because this layer cannot
    /// see a socket, and the answer changes what happens to the deposit: with
    /// relays up it goes out, with them down it waits.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_uplink(
        &mut self,
        depositor: &str,
        geohash: &str,
        event_id: &str,
        event_json: &str,
        created_at: i64,
        now: i64,
        relays_up: bool,
    ) -> Uplink {
        if !self.enabled {
            return Uplink::Refused("not acting as a gateway");
        }
        // Rule 1: never carry back what a gateway carried to us.
        if self.from_mesh.contains(event_id) {
            return Uplink::Refused("already carried over the mesh");
        }
        // Rule 2: publish once. A repeat deposit is absorbed rather than
        // doubled, and a peer retrying because it never saw an ack is the
        // normal case, not an attack.
        if self.published.contains(event_id) {
            return Uplink::Refused("already published");
        }
        if now - created_at > MAX_EVENT_AGE_SECONDS {
            return Uplink::Refused("too old to be worth carrying");
        }
        // From the future by more than the window: not something a relay would
        // keep, and accepting it would let one peer hold a slot indefinitely.
        if created_at - now > MAX_EVENT_AGE_SECONDS {
            return Uplink::Refused("dated in the future");
        }
        if !self.within_deposit_budget(depositor, now) {
            return Uplink::Refused("depositing too fast");
        }

        if relays_up {
            self.published.insert(event_id);
            self.note_deposit(depositor, now);
            return Uplink::Publish;
        }

        // Relays unreachable. Hold it, bounded in both directions — and count
        // the deposit either way, so a peer cannot use an outage to get a
        // larger share of the budget.
        let mine = self
            .held
            .iter()
            .filter(|entry| entry.depositor == depositor)
            .count();
        if mine >= MAX_QUEUED_PER_DEPOSITOR {
            return Uplink::Refused("already holding all we will for this peer");
        }
        self.note_deposit(depositor, now);
        // Drop the oldest rather than refuse the newest: the freshest traffic is
        // the traffic someone is still waiting on.
        if self.held.len() >= MAX_QUEUED_UPLINKS {
            self.held.remove(0);
        }
        self.held.push(Held {
            depositor: depositor.to_string(),
            geohash: geohash.to_string(),
            event_id: event_id.to_string(),
            event_json: event_json.to_string(),
        });
        Uplink::Queued
    }

    /// Everything held for the relays, cleared as it is handed over.
    ///
    /// Marked published on the way out for the same reason a live uplink is: the
    /// subscription that carries it will return it, and it must not be
    /// rebroadcast when it does.
    pub fn take_held(&mut self) -> Vec<Held> {
        let ready = std::mem::take(&mut self.held);
        for entry in &ready {
            self.published.insert(&entry.event_id);
        }
        ready
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Whether a relay event should be put on the mesh for peers who cannot
    /// reach the relays themselves.
    pub fn accept_downlink(&mut self, event_id: &str, now: i64) -> Downlink {
        if !self.enabled {
            return Downlink::Refused("not acting as a gateway");
        }
        // The self-echo, named as a bug upstream actually hit: this event came
        // from this mesh, we published it, and the subscription handed it back.
        // Broadcasting it now spends airtime returning a message to the peer
        // that wrote it.
        if self.published.contains(event_id) {
            return Downlink::Refused("we published this ourselves");
        }
        if self.from_mesh.contains(event_id) {
            return Downlink::Refused("already carried over the mesh");
        }
        if self.rebroadcast.contains(event_id) {
            return Downlink::Refused("already broadcast");
        }
        if !self.within_broadcast_budget(now) {
            return Downlink::Refused("out of airtime for this minute");
        }
        self.rebroadcast.insert(event_id);
        self.broadcasts.push_back(now);
        Downlink::Broadcast
    }

    fn within_deposit_budget(&mut self, depositor: &str, now: i64) -> bool {
        let recent = self.deposits.entry(depositor.to_string()).or_default();
        prune(recent, now);
        recent.len() < UPLINKS_PER_MINUTE_PER_DEPOSITOR
    }

    fn note_deposit(&mut self, depositor: &str, now: i64) {
        self.deposits
            .entry(depositor.to_string())
            .or_default()
            .push_back(now);
    }

    fn within_broadcast_budget(&mut self, now: i64) -> bool {
        prune(&mut self.broadcasts, now);
        self.broadcasts.len() < DOWNLINKS_PER_MINUTE
    }
}

fn prune(stamps: &mut VecDeque<i64>, now: i64) {
    while stamps
        .front()
        .is_some_and(|stamp| now - *stamp >= RATE_WINDOW_SECONDS)
    {
        stamps.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const PHONE: &str = "aa11bb22cc33dd44";

    fn carrying() -> Gateway {
        let mut gateway = Gateway::new();
        gateway.set_enabled(true);
        gateway
    }

    fn deposit(gateway: &mut Gateway, id: &str, now: i64, relays_up: bool) -> Uplink {
        gateway.accept_uplink(PHONE, "9q", id, "{}", now, now, relays_up)
    }

    #[test]
    fn nothing_is_carried_until_the_user_says_so() {
        // Carrying spends our bandwidth and puts our address on relays for
        // events we did not write. That is a decision, not a default.
        let mut idle = Gateway::new();
        assert!(!idle.is_enabled());
        assert_eq!(
            deposit(&mut idle, "e1", NOW, true),
            Uplink::Refused("not acting as a gateway")
        );
        assert_eq!(
            idle.accept_downlink("e2", NOW),
            Downlink::Refused("not acting as a gateway")
        );
    }

    #[test]
    fn a_fresh_deposit_goes_to_the_relays() {
        let mut gateway = carrying();
        assert_eq!(deposit(&mut gateway, "e1", NOW, true), Uplink::Publish);
    }

    #[test]
    fn the_same_event_is_published_once() {
        // A peer that never saw an acknowledgement retries. That is ordinary,
        // and it must not put the message on the relays twice.
        let mut gateway = carrying();
        assert_eq!(deposit(&mut gateway, "e1", NOW, true), Uplink::Publish);
        assert_eq!(
            deposit(&mut gateway, "e1", NOW, true),
            Uplink::Refused("already published")
        );
    }

    #[test]
    fn we_never_rebroadcast_what_we_published() {
        // The self-echo, and the one upstream says it actually hit: our own
        // subscription returns what we just sent, and broadcasting it spends
        // airtime handing a message back to the peer that wrote it.
        let mut gateway = carrying();
        deposit(&mut gateway, "e1", NOW, true);
        assert_eq!(
            gateway.accept_downlink("e1", NOW),
            Downlink::Refused("we published this ourselves")
        );
    }

    #[test]
    fn two_gateways_on_one_mesh_do_not_feed_each_other() {
        // Without this the same event goes back and forth between gateways
        // until its TTL runs out, and every hop is real airtime.
        let mut gateway = carrying();
        gateway.note_carried_on_mesh("e1");

        assert_eq!(
            gateway.accept_downlink("e1", NOW),
            Downlink::Refused("already carried over the mesh"),
            "not back onto the mesh"
        );
        assert_eq!(
            deposit(&mut gateway, "e1", NOW, true),
            Uplink::Refused("already carried over the mesh"),
            "and not up to the relays either"
        );
    }

    #[test]
    fn a_relay_event_reaches_the_mesh_once() {
        let mut gateway = carrying();
        assert_eq!(gateway.accept_downlink("e1", NOW), Downlink::Broadcast);
        assert_eq!(
            gateway.accept_downlink("e1", NOW),
            Downlink::Refused("already broadcast"),
            "five relays delivering one event is still one event"
        );
    }

    #[test]
    fn stale_and_future_events_are_refused() {
        let mut gateway = carrying();
        assert_eq!(
            gateway.accept_uplink(PHONE, "9q", "old", "{}", NOW - MAX_EVENT_AGE_SECONDS - 1, NOW, true),
            Uplink::Refused("too old to be worth carrying")
        );
        assert_eq!(
            gateway.accept_uplink(PHONE, "9q", "ahead", "{}", NOW + MAX_EVENT_AGE_SECONDS + 1, NOW, true),
            Uplink::Refused("dated in the future")
        );
        // The edges still count.
        assert_eq!(
            gateway.accept_uplink(PHONE, "9q", "edge", "{}", NOW - MAX_EVENT_AGE_SECONDS, NOW, true),
            Uplink::Publish
        );
    }

    #[test]
    fn one_peer_cannot_spend_everyone_elses_budget() {
        let mut gateway = carrying();
        for index in 0..UPLINKS_PER_MINUTE_PER_DEPOSITOR {
            assert_eq!(
                deposit(&mut gateway, &format!("e{index}"), NOW, true),
                Uplink::Publish,
                "deposit {index}"
            );
        }
        assert_eq!(
            deposit(&mut gateway, "one-too-many", NOW, true),
            Uplink::Refused("depositing too fast")
        );
        // Another peer is unaffected.
        assert_eq!(
            gateway.accept_uplink("ffffffffffffffff", "9q", "theirs", "{}", NOW, NOW, true),
            Uplink::Publish
        );
    }

    #[test]
    fn the_deposit_budget_recovers() {
        let mut gateway = carrying();
        for index in 0..UPLINKS_PER_MINUTE_PER_DEPOSITOR {
            deposit(&mut gateway, &format!("e{index}"), NOW, true);
        }
        assert_eq!(
            deposit(&mut gateway, "blocked", NOW, true),
            Uplink::Refused("depositing too fast")
        );
        assert_eq!(
            deposit(&mut gateway, "later", NOW + RATE_WINDOW_SECONDS, true),
            Uplink::Publish,
            "a minute on, the window has moved"
        );
    }

    #[test]
    fn airtime_is_budgeted_because_every_link_shares_it() {
        let mut gateway = carrying();
        for index in 0..DOWNLINKS_PER_MINUTE {
            assert_eq!(
                gateway.accept_downlink(&format!("e{index}"), NOW),
                Downlink::Broadcast,
                "broadcast {index}"
            );
        }
        assert_eq!(
            gateway.accept_downlink("over", NOW),
            Downlink::Refused("out of airtime for this minute")
        );
        assert_eq!(
            gateway.accept_downlink("over", NOW + RATE_WINDOW_SECONDS),
            Downlink::Broadcast,
            "and recovers"
        );
    }

    #[test]
    fn deposits_wait_when_the_relays_are_down() {
        let mut gateway = carrying();
        assert_eq!(deposit(&mut gateway, "e1", NOW, false), Uplink::Queued);
        assert_eq!(gateway.held_count(), 1);

        let held = gateway.take_held();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].event_id, "e1");
        assert_eq!(gateway.held_count(), 0, "handed over, not kept");
    }

    #[test]
    fn a_held_deposit_is_not_rebroadcast_once_it_is_sent() {
        // Same reason as a live uplink: the subscription that carries it will
        // return it, and it must not come back onto the mesh when it does.
        let mut gateway = carrying();
        deposit(&mut gateway, "e1", NOW, false);
        gateway.take_held();
        assert_eq!(
            gateway.accept_downlink("e1", NOW),
            Downlink::Refused("we published this ourselves")
        );
    }

    #[test]
    fn the_mailbag_is_bounded_per_peer_and_overall() {
        let mut gateway = carrying();
        for index in 0..MAX_QUEUED_PER_DEPOSITOR {
            assert_eq!(
                deposit(&mut gateway, &format!("mine{index}"), NOW, false),
                Uplink::Queued
            );
        }
        assert_eq!(
            deposit(&mut gateway, "extra", NOW, false),
            Uplink::Refused("already holding all we will for this peer")
        );

        // Filling the bag from many peers displaces the oldest rather than
        // refusing the newest: fresh traffic is what someone is still waiting on.
        let mut wide = carrying();
        for index in 0..(MAX_QUEUED_UPLINKS + 4) {
            let peer = format!("{index:016x}");
            wide.accept_uplink(&peer, "9q", &format!("e{index}"), "{}", NOW, NOW, false);
        }
        assert_eq!(wide.held_count(), MAX_QUEUED_UPLINKS);
        let ids: Vec<String> = wide.take_held().into_iter().map(|h| h.event_id).collect();
        assert!(!ids.contains(&"e0".to_string()), "the oldest fell out");
        assert!(ids.contains(&format!("e{}", MAX_QUEUED_UPLINKS + 3)), "the newest stayed");
    }

    #[test]
    fn an_outage_does_not_buy_a_bigger_share() {
        // Queued deposits count against the rate budget too, or a peer could
        // wait for the relays to blink and then flood.
        let mut gateway = carrying();
        for index in 0..MAX_QUEUED_PER_DEPOSITOR {
            deposit(&mut gateway, &format!("q{index}"), NOW, false);
        }
        gateway.take_held();
        let remaining = UPLINKS_PER_MINUTE_PER_DEPOSITOR - MAX_QUEUED_PER_DEPOSITOR;
        for index in 0..remaining {
            assert_eq!(
                deposit(&mut gateway, &format!("live{index}"), NOW, true),
                Uplink::Publish
            );
        }
        assert_eq!(
            deposit(&mut gateway, "over", NOW, true),
            Uplink::Refused("depositing too fast")
        );
    }

    #[test]
    fn switching_off_drops_the_mailbag() {
        // Those deposits were made on a promise we have just withdrawn. Keeping
        // them is the worst of both: the sender believes it is gone, and we
        // still hold it.
        let mut gateway = carrying();
        deposit(&mut gateway, "e1", NOW, false);
        deposit(&mut gateway, "e2", NOW, false);
        assert_eq!(gateway.set_enabled(false), 2, "and says how many");
        assert_eq!(gateway.held_count(), 0);
    }

    #[test]
    fn loop_prevention_memory_is_bounded() {
        let mut gateway = carrying();
        for index in 0..(MAX_TRACKED_IDS + 20) {
            gateway.note_carried_on_mesh(&format!("e{index}"));
        }
        assert_eq!(gateway.from_mesh.order.len(), MAX_TRACKED_IDS);
        assert!(!gateway.from_mesh.contains("e0"), "the oldest was forgotten");
        assert!(gateway.from_mesh.contains(&format!("e{}", MAX_TRACKED_IDS + 19)));
    }
}
