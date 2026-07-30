// src/sync/rate_limit.rs
//
// Port of upstream `Sync/SyncResponseRateLimiter.swift`.

use std::collections::HashMap;

/// Responses one peer may draw per window. Upstream's
/// `responseRateLimitMaxResponses`.
pub const MAX_RESPONSES: usize = 8;

/// The sliding window, in milliseconds. Upstream's
/// `responseRateLimitWindowSeconds`.
pub const WINDOW_MS: u64 = 30 * 1000;

/// Bounds how often one peer can make us replay the store.
///
/// A single response can put our whole archive on the air, so a peer asking in
/// a tight loop would otherwise drain the airtime and battery of everyone in
/// range — including peers with no interest in either of us. A legitimate peer
/// sends a handful per window: one per type schedule, plus the initial sync.
pub struct ResponseRateLimiter {
    max_responses: usize,
    window_ms: u64,
    history: HashMap<[u8; 8], Vec<u64>>,
}

impl Default for ResponseRateLimiter {
    fn default() -> Self {
        Self::new(MAX_RESPONSES, WINDOW_MS)
    }
}

impl ResponseRateLimiter {
    pub fn new(max_responses: usize, window_ms: u64) -> Self {
        Self {
            max_responses: max_responses.max(1),
            window_ms,
            history: HashMap::new(),
        }
    }

    /// Whether this peer is still under budget, recording the response if so.
    ///
    /// Asking is what spends the budget, so a caller must not call this and
    /// then decide not to answer — the refusal is the answer.
    pub fn should_respond(&mut self, peer: [u8; 8], now_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let recent = self.history.entry(peer).or_default();
        recent.retain(|&at| at >= cutoff);
        if recent.len() >= self.max_responses {
            return false;
        }
        recent.push(now_ms);
        true
    }

    /// Drops history outside the window so peers that have gone do not
    /// accumulate. Safe to call on any tick.
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.history.retain(|_, times| {
            times.retain(|&at| at >= cutoff);
            !times.is_empty()
        });
    }

    pub fn tracked_peers(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_785_000_000_000;
    const PEER: [u8; 8] = [1; 8];
    const OTHER: [u8; 8] = [2; 8];

    #[test]
    fn a_peer_gets_its_budget_and_no_more() {
        let mut limiter = ResponseRateLimiter::default();
        for i in 0..MAX_RESPONSES {
            assert!(limiter.should_respond(PEER, NOW), "response {i} is in budget");
        }
        assert!(!limiter.should_respond(PEER, NOW), "one past the budget");
    }

    #[test]
    fn the_window_slides_rather_than_resetting() {
        // Spend the budget one millisecond apart, so the entries expire one at
        // a time and the sliding is actually observable. Spending it all in a
        // single instant would expire it all in a single instant too, which
        // proves nothing about sliding.
        let mut limiter = ResponseRateLimiter::default();
        for i in 0..MAX_RESPONSES as u64 {
            assert!(limiter.should_respond(PEER, NOW + i));
        }
        let last = NOW + MAX_RESPONSES as u64 - 1;
        assert!(!limiter.should_respond(PEER, last), "budget spent");

        // The cutoff is `now - window` and an entry is kept when it is at or
        // after it, so the first response is still inside the window at exactly
        // NOW + WINDOW_MS and falls out one millisecond later.
        assert!(!limiter.should_respond(PEER, NOW + WINDOW_MS));

        // Now exactly one slot has opened — the seven later responses are still
        // inside the window.
        assert!(limiter.should_respond(PEER, NOW + WINDOW_MS + 1));
        assert!(!limiter.should_respond(PEER, NOW + WINDOW_MS + 1));
    }

    #[test]
    fn one_peer_cannot_spend_anothers_budget() {
        // The point of the limiter: a peer in a tight loop must not be able to
        // silence us towards everybody else.
        let mut limiter = ResponseRateLimiter::default();
        for _ in 0..(MAX_RESPONSES * 3) {
            limiter.should_respond(PEER, NOW);
        }
        assert!(limiter.should_respond(OTHER, NOW));
    }

    #[test]
    fn a_refusal_does_not_extend_the_ban() {
        // Refused attempts must not be recorded, or a peer that keeps asking
        // would push its own window forward forever and never recover.
        let mut limiter = ResponseRateLimiter::default();
        for _ in 0..MAX_RESPONSES {
            limiter.should_respond(PEER, NOW);
        }
        for offset in 0..=WINDOW_MS {
            assert!(!limiter.should_respond(PEER, NOW + offset), "still refused");
        }
        assert!(limiter.should_respond(PEER, NOW + WINDOW_MS + 1));
    }

    #[test]
    fn pruning_forgets_peers_that_stopped_asking() {
        let mut limiter = ResponseRateLimiter::default();
        limiter.should_respond(PEER, NOW);
        assert_eq!(limiter.tracked_peers(), 1);
        limiter.prune(NOW + WINDOW_MS - 1);
        assert_eq!(limiter.tracked_peers(), 1, "still inside the window");
        limiter.prune(NOW + WINDOW_MS + 1);
        assert_eq!(limiter.tracked_peers(), 0);
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_open_the_gate() {
        let mut limiter = ResponseRateLimiter::default();
        for _ in 0..MAX_RESPONSES {
            limiter.should_respond(PEER, NOW);
        }
        // saturating_sub keeps the cutoff at 0 rather than wrapping to a
        // colossal value, which would drop the whole history and refill the
        // budget.
        assert!(!limiter.should_respond(PEER, 1));
    }
}
