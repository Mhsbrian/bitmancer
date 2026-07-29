// src/nostr/health.rs
//
// Which relays are down, and what the user has already been told.
//
// The relay pool reports facts: every connection attempt that fails produces an
// event, because the pool cannot know which of those facts is worth repeating.
// Deciding that is this file's job, and it is not a detail — a relay that stops
// answering is retried forever on a backoff, so a pool reporting honestly and a
// client repeating everything it hears produces a line every minute, per dead
// relay, per subscription, for as long as the session lasts.
//
// Three things make that worse than it sounds. The geo relay directory is a
// static snapshot with no liveness signal, so a channel whose nearest relays
// have since died picks them again on every join. A host that is down is down
// for every subscription at once, so the same dead relay is reported by the
// joined channel and by the map sampler independently. And some hosts are not
// down but *degraded* — they accept a connection, drop it, and refuse the next
// one, over and over.
//
// So the state is keyed by host, not by (channel, host): the fact being
// reported is "this relay is not answering", which has nothing to do with which
// subscription happened to notice. It is a set rather than a last-seen string,
// because the failure that made this necessary was two relays failing with
// *different* reasons — consecutive messages never matched, so a single-slot
// filter suppressed nothing at all. And a relay that keeps changing its mind is
// eventually muted, because reporting every transition honestly is still a line
// every few seconds when the host is flapping.

use std::collections::HashMap;

/// How many times a relay may go down before it stops being worth reporting.
///
/// Observed on `nostr-01.yakihonne.com`, which connected and 502'd three times
/// in a minute. Reporting each transition is accurate and useless: the user
/// cannot act on it, and the one thing they need to know — this relay is not
/// dependable — is said better once than forty times.
const FLAP_LIMIT: u32 = 3;

/// What, if anything, to tell the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// Nothing new.
    Silent,
    /// This relay has stopped answering.
    Down,
    /// It has failed once too often to keep reporting; say so and go quiet.
    Unstable,
    /// It is answering again, after we said it was not.
    BackUp,
}

#[derive(Debug, Default, Clone)]
struct Record {
    /// Whether the user was last told this relay was down.
    reported_down: bool,
    /// How many separate times it has gone down.
    falls: u32,
    /// Whether we have given up reporting on it.
    muted: bool,
}

/// What the user has been told about each relay.
#[derive(Debug, Default)]
pub struct RelayHealth {
    relays: HashMap<String, Record>,
}

impl RelayHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a relay is not answering.
    pub fn fell_over(&mut self, relay: &str) -> Notice {
        let record = self.relays.entry(relay.to_string()).or_default();
        if record.reported_down {
            // Already down as far as the user knows; the pool is just retrying.
            return Notice::Silent;
        }
        record.reported_down = true;
        record.falls += 1;
        if record.muted {
            return Notice::Silent;
        }
        if record.falls > FLAP_LIMIT {
            record.muted = true;
            return Notice::Unstable;
        }
        Notice::Down
    }

    /// Records that a relay answered.
    ///
    /// Silent for an ordinary first connection: announcing every relay that
    /// connects would put five lines on screen for a healthy join. A recovery
    /// is worth saying precisely because a failure was said earlier.
    pub fn recovered(&mut self, relay: &str) -> Notice {
        match self.relays.get_mut(relay) {
            Some(record) if record.reported_down => {
                record.reported_down = false;
                if record.muted {
                    Notice::Silent
                } else {
                    Notice::BackUp
                }
            }
            _ => Notice::Silent,
        }
    }

    /// How many relays are currently believed down. Asked only by the tests;
    /// the client acts on the transitions, not on the total.
    #[cfg(test)]
    pub fn down_count(&self) -> usize {
        self.relays
            .values()
            .filter(|record| record.reported_down)
            .count()
    }

    /// Forgets everything, for a wipe or a fresh set of subscriptions.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.relays.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEAD: &str = "wss://relay0.gfcom.info";
    const ALSO_DEAD: &str = "wss://relay1.gfcom.info";
    const FLAPPY: &str = "wss://nostr-01.yakihonne.com";

    #[test]
    fn a_relay_going_down_is_said_once() {
        let mut health = RelayHealth::new();
        assert_eq!(health.fell_over(DEAD), Notice::Down, "the first failure is news");
        for _ in 0..100 {
            assert_eq!(
                health.fell_over(DEAD),
                Notice::Silent,
                "every retry after it is not"
            );
        }
    }

    #[test]
    fn two_relays_failing_differently_are_both_reported() {
        // The exact bug. A single-slot "was this the last message" filter
        // suppressed nothing here, because the two relays fail with different
        // reasons and so never produce two identical lines in a row.
        let mut health = RelayHealth::new();
        assert_eq!(health.fell_over(DEAD), Notice::Down);
        assert_eq!(health.fell_over(ALSO_DEAD), Notice::Down);
        for _ in 0..50 {
            assert_eq!(health.fell_over(DEAD), Notice::Silent);
            assert_eq!(health.fell_over(ALSO_DEAD), Notice::Silent);
        }
        assert_eq!(health.down_count(), 2);
    }

    #[test]
    fn one_host_is_one_report_however_many_subscriptions_notice() {
        // A joined channel and the map sampler dial the same hosts. The fact
        // is about the host, so noticing it twice is still one fact.
        let mut health = RelayHealth::new();
        assert_eq!(health.fell_over(DEAD), Notice::Down, "the channel noticed");
        assert_eq!(
            health.fell_over(DEAD),
            Notice::Silent,
            "the sampler noticed the same thing"
        );
        assert_eq!(health.down_count(), 1);
    }

    #[test]
    fn recovery_is_announced_only_after_a_failure_was() {
        let mut health = RelayHealth::new();
        assert_eq!(
            health.recovered(DEAD),
            Notice::Silent,
            "an ordinary first connection is not worth a line"
        );

        health.fell_over(DEAD);
        assert_eq!(health.recovered(DEAD), Notice::BackUp);
        assert_eq!(health.recovered(DEAD), Notice::Silent, "and is not repeated");
        assert_eq!(health.down_count(), 0);
    }

    #[test]
    fn a_flapping_relay_is_given_up_on() {
        // Observed live: connect, 502, connect, 502. Reporting every honest
        // transition is a line every few seconds for the rest of the session.
        let mut health = RelayHealth::new();
        for round in 0..FLAP_LIMIT {
            assert_eq!(health.fell_over(FLAPPY), Notice::Down, "round {round}");
            assert_eq!(health.recovered(FLAPPY), Notice::BackUp, "round {round}");
        }

        assert_eq!(
            health.fell_over(FLAPPY),
            Notice::Unstable,
            "once too often: say so, once"
        );
        // And then nothing further, whichever way it goes.
        for _ in 0..100 {
            assert_eq!(health.recovered(FLAPPY), Notice::Silent);
            assert_eq!(health.fell_over(FLAPPY), Notice::Silent);
        }
    }

    #[test]
    fn a_steadily_dead_relay_is_never_called_unstable() {
        // It fell over once and stayed there. "Unstable" would be a different
        // and wrong claim, and the count must not creep up on retries.
        let mut health = RelayHealth::new();
        assert_eq!(health.fell_over(DEAD), Notice::Down);
        for _ in 0..1000 {
            assert_eq!(health.fell_over(DEAD), Notice::Silent);
        }
    }

    #[test]
    fn a_relay_that_recovers_for_good_is_still_reported_next_time() {
        // Muting is for hosts that cannot make up their mind, not for any host
        // that has ever failed. One bad afternoon must not silence it forever.
        let mut health = RelayHealth::new();
        health.fell_over(DEAD);
        health.recovered(DEAD);
        assert_eq!(
            health.fell_over(DEAD),
            Notice::Down,
            "a second, separate outage is still worth saying"
        );
    }

    #[test]
    fn relays_are_tracked_independently() {
        let mut health = RelayHealth::new();
        health.fell_over(DEAD);
        health.fell_over(ALSO_DEAD);
        assert_eq!(health.recovered(DEAD), Notice::BackUp);
        assert_eq!(
            health.down_count(),
            1,
            "one recovering says nothing about the other"
        );
        assert_eq!(health.recovered(ALSO_DEAD), Notice::BackUp);
        assert_eq!(health.down_count(), 0);
    }

    #[test]
    fn muting_one_relay_does_not_quieten_another() {
        let mut health = RelayHealth::new();
        for _ in 0..=FLAP_LIMIT {
            health.fell_over(FLAPPY);
            health.recovered(FLAPPY);
        }
        assert_eq!(health.fell_over(DEAD), Notice::Down);
    }
}
