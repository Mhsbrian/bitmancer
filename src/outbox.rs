// src/outbox.rs
//
// Which way a private message goes, and what happens to it when no way exists.
//
// Two transports carry the same conversation. The mesh is preferred whenever it
// can be used: it is lower latency, it works with no internet at all, and it
// tells no relay that the two of us are talking. Nostr is the fallback for a
// peer who has walked out of Bluetooth range but has handed us an address.
// Neither being available is not a failure — it is the ordinary case for a mesh
// client, and the message waits.
//
// What waits here is the *content*, not a sealed frame. Each transport encodes
// differently, the route can change between the attempt that failed and the one
// that succeeds, and every sealing draws a fresh nonce — so holding ciphertext
// would mean holding something that can only be sent one way, and sending it
// twice would reuse a nonce.
//
// Retention is bounded in both directions. Upstream keeps a copy until an
// acknowledgement clears it, which is right, but "until acknowledged" with no
// ceiling means a client that never meets its peer again holds their message
// forever — plaintext, in memory, on a client whose whole premise is leaving
// nothing behind. So there is a cap per peer and an age at which a message is
// given up on and said to be given up on.

// Not yet called by the client: this is the decision layer, landing ahead of
// the relay plumbing that will act on it. Routing and retention are worth
// getting right on their own, and both are fully exercised by the tests below.
#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Messages held for any single peer.
///
/// Small on purpose: a queue this long already means the peer has been
/// unreachable for a while, and the honest response is to say so rather than to
/// accumulate.
pub const MAX_PER_PEER: usize = 32;

/// How long an unacknowledged message is kept before it is abandoned.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Wait before the first retry, doubling per attempt up to [`MAX_BACKOFF`].
pub const BASE_BACKOFF: Duration = Duration::from_secs(30);
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Where a private message should be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// An encrypted mesh session is up. Preferred whenever available: no
    /// relay learns that this conversation exists.
    Mesh,
    /// No mesh session, but we hold the peer's Nostr address.
    Nostr,
    /// No way to reach them right now.
    Hold,
}

/// Chooses a transport.
///
/// Mesh first, and not only for latency: a message that never leaves the local
/// radio tells no third party anything, while the Nostr path necessarily
/// reveals to a relay that *someone* addressed this recipient, even though the
/// envelope hides who and what.
pub fn route(mesh_session: bool, nostr_address: Option<&str>) -> Route {
    match (mesh_session, nostr_address) {
        (true, _) => Route::Mesh,
        (false, Some(address)) if !address.is_empty() => Route::Nostr,
        _ => Route::Hold,
    }
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub message_id: String,
    pub content: String,
    pub queued_at: Instant,
    pub attempts: u32,
    pub last_attempt: Option<Instant>,
}

impl Pending {
    /// Whether this is worth trying again yet.
    ///
    /// Backoff is per message rather than per peer so one long-queued message
    /// cannot hold up a fresh one behind it.
    fn due(&self, now: Instant) -> bool {
        match self.last_attempt {
            None => true,
            Some(last) => now.duration_since(last) >= self.backoff(),
        }
    }

    fn backoff(&self) -> Duration {
        // The first retry waits the base interval, not twice it: `attempts` is
        // a count of sends already made, so the exponent is one less.
        let exponent = self.attempts.saturating_sub(1).min(16);
        BASE_BACKOFF
            .checked_mul(1u32 << exponent)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF)
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.queued_at) >= MAX_AGE
    }
}

/// Why a message left the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Departure {
    /// The peer acknowledged it.
    Acknowledged,
    /// It was held past [`MAX_AGE`] without ever being acknowledged.
    Abandoned,
    /// Displaced by newer messages once the per-peer cap was reached.
    Displaced,
}

#[derive(Debug, Default)]
pub struct Outbox {
    by_peer: HashMap<String, Vec<Pending>>,
}

impl Outbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds a message for a peer, keyed by fingerprint.
    ///
    /// Re-holding an id already queued is a no-op rather than a duplicate: a
    /// retry that races an enqueue must not double the message, since the
    /// receiver deduplicates by this same id and would simply drop the copy
    /// after we had paid to send it.
    ///
    /// Returns what had to be dropped to make room, if anything.
    pub fn hold(
        &mut self,
        fingerprint: &str,
        message_id: &str,
        content: &str,
        now: Instant,
    ) -> Option<(String, Departure)> {
        let queue = self.by_peer.entry(fingerprint.to_string()).or_default();
        if queue.iter().any(|held| held.message_id == message_id) {
            return None;
        }
        queue.push(Pending {
            message_id: message_id.to_string(),
            content: content.to_string(),
            queued_at: now,
            attempts: 0,
            last_attempt: None,
        });

        // Drop the oldest rather than refusing the newest: what someone just
        // typed matters more than what they typed yesterday to a peer who has
        // not appeared since.
        if queue.len() > MAX_PER_PEER {
            let evicted = queue.remove(0);
            return Some((evicted.message_id, Departure::Displaced));
        }
        None
    }

    /// Records that a message has just been sent, so it backs off before the
    /// next attempt. It stays queued until acknowledged: a send is not a
    /// delivery.
    pub fn mark_attempted(&mut self, message_id: &str, now: Instant) {
        for queue in self.by_peer.values_mut() {
            if let Some(held) = queue.iter_mut().find(|held| held.message_id == message_id) {
                held.attempts = held.attempts.saturating_add(1);
                held.last_attempt = Some(now);
                return;
            }
        }
    }

    /// Clears a message the peer has acknowledged.
    ///
    /// Both a delivery and a read acknowledgement clear it — read implies
    /// delivered, and the two can arrive in either order.
    pub fn acknowledge(&mut self, message_id: &str) -> bool {
        for queue in self.by_peer.values_mut() {
            if let Some(index) = queue.iter().position(|held| held.message_id == message_id) {
                queue.remove(index);
                return true;
            }
        }
        false
    }

    /// Messages worth another attempt now, oldest first per peer.
    pub fn due(&self, now: Instant) -> Vec<(String, Pending)> {
        let mut ready: Vec<(String, Pending)> = self
            .by_peer
            .iter()
            .flat_map(|(fingerprint, queue)| {
                queue
                    .iter()
                    .filter(|held| held.due(now) && !held.expired(now))
                    .map(move |held| (fingerprint.clone(), held.clone()))
            })
            .collect();
        // Stable order so retries do not depend on hash iteration.
        ready.sort_by(|a, b| a.1.queued_at.cmp(&b.1.queued_at).then(a.0.cmp(&b.0)));
        ready
    }

    /// Drops anything held past [`MAX_AGE`], reporting it so the user can be
    /// told rather than left believing a message is still on its way.
    pub fn expire(&mut self, now: Instant) -> Vec<(String, String)> {
        let mut abandoned = Vec::new();
        for (fingerprint, queue) in self.by_peer.iter_mut() {
            queue.retain(|held| {
                if held.expired(now) {
                    abandoned.push((fingerprint.clone(), held.message_id.clone()));
                    false
                } else {
                    true
                }
            });
        }
        self.by_peer.retain(|_, queue| !queue.is_empty());
        abandoned
    }

    pub fn waiting_for(&self, fingerprint: &str) -> usize {
        self.by_peer.get(fingerprint).map_or(0, Vec::len)
    }

    pub fn total(&self) -> usize {
        self.by_peer.values().map(Vec::len).sum()
    }

    /// Forgets everything. Held messages are plaintext a wipe must not leave.
    pub fn clear(&mut self) {
        self.by_peer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "aa11bb22";

    fn at(base: Instant, seconds: u64) -> Instant {
        base + Duration::from_secs(seconds)
    }

    #[test]
    fn the_mesh_is_preferred_whenever_it_is_available() {
        // Not only for speed: a message that stays on the local radio tells no
        // relay the conversation exists.
        assert_eq!(route(true, None), Route::Mesh);
        assert_eq!(route(true, Some("npub1peer")), Route::Mesh);
    }

    #[test]
    fn nostr_carries_a_peer_who_has_left_radio_range() {
        assert_eq!(route(false, Some("npub1peer")), Route::Nostr);
    }

    #[test]
    fn without_a_session_or_an_address_the_message_waits() {
        assert_eq!(route(false, None), Route::Hold);
        // An empty address is not an address; treating it as one would send a
        // message nowhere and report success.
        assert_eq!(route(false, Some("")), Route::Hold);
    }

    #[test]
    fn an_acknowledgement_clears_the_copy_we_kept() {
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        assert_eq!(outbox.waiting_for(PEER), 1);

        assert!(outbox.acknowledge("id-1"));
        assert_eq!(outbox.waiting_for(PEER), 0);
        assert!(!outbox.acknowledge("id-1"), "clearing twice is not a clear");
    }

    #[test]
    fn a_send_is_not_a_delivery() {
        // The copy is kept after sending, because a frame put on the air is
        // not a frame that arrived.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        outbox.mark_attempted("id-1", now);
        assert_eq!(outbox.waiting_for(PEER), 1);
    }

    #[test]
    fn holding_the_same_id_twice_does_not_double_it() {
        // The receiver deduplicates by id, so a duplicate costs airtime and
        // buys nothing.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        outbox.hold(PEER, "id-1", "hello", now);
        assert_eq!(outbox.waiting_for(PEER), 1);
    }

    #[test]
    fn a_fresh_message_is_due_at_once_and_then_backs_off() {
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        assert_eq!(outbox.due(now).len(), 1, "never tried, so try now");

        outbox.mark_attempted("id-1", now);
        assert!(outbox.due(now).is_empty(), "just tried");
        assert!(
            outbox.due(at(now, BASE_BACKOFF.as_secs() + 1)).len() == 1,
            "due again once the wait has passed"
        );
    }

    #[test]
    fn backoff_grows_but_is_capped() {
        // Unbounded doubling would silently stop retrying; a cap keeps a
        // long-queued message checking in.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        for _ in 0..20 {
            outbox.mark_attempted("id-1", now);
        }
        let held = outbox.due(at(now, MAX_BACKOFF.as_secs() + 1));
        assert_eq!(held.len(), 1, "the cap must keep it retryable");
    }

    #[test]
    fn backoff_is_per_message_not_per_peer() {
        // Otherwise one old message blocks a fresh one behind it.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "old", "first", now);
        outbox.mark_attempted("old", now);
        outbox.hold(PEER, "new", "second", now);

        let due = outbox.due(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.message_id, "new");
    }

    #[test]
    fn a_message_is_eventually_abandoned_rather_than_held_forever() {
        // Plaintext kept indefinitely for a peer who never returns is exactly
        // what this client exists not to do.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);

        assert!(outbox.expire(at(now, 60)).is_empty(), "still fresh");
        let abandoned = outbox.expire(at(now, MAX_AGE.as_secs() + 1));
        assert_eq!(abandoned, vec![(PEER.to_string(), "id-1".to_string())]);
        assert_eq!(outbox.total(), 0);
    }

    #[test]
    fn an_expired_message_is_never_offered_for_retry() {
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "hello", now);
        assert!(outbox.due(at(now, MAX_AGE.as_secs() + 1)).is_empty());
    }

    #[test]
    fn the_oldest_is_displaced_when_a_peer_queue_fills() {
        // What someone just typed matters more than what they typed yesterday
        // to a peer who has not appeared since.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        for index in 0..MAX_PER_PEER {
            assert!(outbox
                .hold(PEER, &format!("id-{index}"), "text", now)
                .is_none());
        }
        let displaced = outbox.hold(PEER, "newest", "text", now);
        assert_eq!(
            displaced,
            Some(("id-0".to_string(), Departure::Displaced)),
            "the oldest gives way"
        );
        assert_eq!(outbox.waiting_for(PEER), MAX_PER_PEER);
    }

    #[test]
    fn peers_do_not_share_a_queue() {
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold("peer-a", "id-1", "one", now);
        outbox.hold("peer-b", "id-2", "two", now);
        assert_eq!(outbox.waiting_for("peer-a"), 1);
        assert_eq!(outbox.waiting_for("peer-b"), 1);
        outbox.acknowledge("id-1");
        assert_eq!(outbox.waiting_for("peer-a"), 0);
        assert_eq!(outbox.waiting_for("peer-b"), 1);
    }

    #[test]
    fn retry_order_does_not_depend_on_hash_iteration() {
        // A queue that reorders itself between runs makes a delivery bug
        // impossible to reproduce.
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold("peer-z", "first", "1", now);
        outbox.hold("peer-a", "second", "2", at(now, 1));
        let ids: Vec<String> = outbox
            .due(at(now, 2))
            .into_iter()
            .map(|(_, held)| held.message_id)
            .collect();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[test]
    fn clearing_leaves_nothing() {
        let now = Instant::now();
        let mut outbox = Outbox::new();
        outbox.hold(PEER, "id-1", "sensitive", now);
        outbox.clear();
        assert_eq!(outbox.total(), 0);
    }
}
