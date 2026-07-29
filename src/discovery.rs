// src/discovery.rs
//
// Choosing which advertiser to connect to.
//
// This is separate from the radio code because the rule is subtle and worth
// testing on its own. BlueZ hands back every device it has *ever* seen this
// session, not the ones advertising now, and BitChat phones use resolvable
// private addresses that rotate every few minutes. So the peripheral list fills
// up with ghosts: entries whose cached properties still advertise the BitChat
// service UUID but whose address died twenty minutes ago.
//
// Connecting to a ghost does not fail quickly. It hangs, which is why picking
// the right candidate matters more than any timeout.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a failed address is skipped, so a dead entry cannot be retried
/// forever while a live peer sits next to it in the list.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub address: String,
    /// Present when the adapter has heard this device recently. A cached ghost
    /// usually has none, which is the strongest freshness signal available
    /// without keeping our own scan-time bookkeeping.
    pub rssi: Option<i16>,
    pub name: Option<String>,
}

impl Candidate {
    pub fn label(&self) -> String {
        let name = self.name.clone().unwrap_or_else(|| "unnamed".to_string());
        match self.rssi {
            Some(rssi) => format!("{name} [{}] {rssi} dBm", self.address),
            None => format!("{name} [{}] no signal", self.address),
        }
    }
}

/// Remembers which addresses just failed, so the next pass tries something else.
#[derive(Default)]
pub struct FailureLog {
    failures: HashMap<String, Instant>,
}

impl FailureLog {
    pub fn record(&mut self, address: &str) {
        self.failures.insert(address.to_string(), Instant::now());
    }

    pub fn is_cooling(&self, address: &str) -> bool {
        self.failures
            .get(address)
            .is_some_and(|at| at.elapsed() < FAILURE_COOLDOWN)
    }

    pub fn forget(&mut self, address: &str) {
        self.failures.remove(address);
    }

    pub fn prune(&mut self) {
        self.failures
            .retain(|_, at| at.elapsed() < FAILURE_COOLDOWN);
    }
}

/// Every candidate worth trying, best first.
///
/// Holding several links at once means dialling several peers, so the
/// second-best entry is a target in its own right rather than a fallback for
/// when the first fails.
///
/// One total order rather than a preferred list with a fallback pass. A
/// recently-failed address sorts *below* everything else instead of being
/// filtered out and reconsidered: the two express the same preference — try
/// anything else first, but a bad peer beats no peer — and as an ordering it
/// also says what to do with the fifth-best when the first four are taken.
pub fn rank(candidates: &[Candidate], failures: &FailureLog) -> Vec<Candidate> {
    let mut viable: Vec<Candidate> = candidates.to_vec();
    viable.sort_by(|a, b| {
        // `false` sorts before `true`, so not-cooling comes first.
        failures
            .is_cooling(&a.address)
            .cmp(&failures.is_cooling(&b.address))
            // Heard-recently beats never-heard: a cached ghost usually has no
            // RSSI, and connecting to one hangs rather than failing.
            .then(b.rssi.is_some().cmp(&a.rssi.is_some()))
            .then(b.rssi.unwrap_or(i16::MIN).cmp(&a.rssi.unwrap_or(i16::MIN)))
            // Stable when two peers are equally loud.
            .then(a.address.cmp(&b.address))
    });
    viable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The head of the ranking. The client works down the whole list now, but
    /// "which peer would be tried first" is still the clearest way to state
    /// most of these expectations.
    fn best(candidates: &[Candidate], failures: &FailureLog) -> Option<Candidate> {
        rank(candidates, failures).into_iter().next()
    }

    fn live(address: &str, rssi: i16) -> Candidate {
        Candidate {
            address: address.to_string(),
            rssi: Some(rssi),
            name: Some("Pixel".to_string()),
        }
    }

    fn ghost(address: &str) -> Candidate {
        Candidate {
            address: address.to_string(),
            rssi: None,
            name: None,
        }
    }

    #[test]
    fn a_live_peer_beats_a_ghost_however_they_are_ordered() {
        // The real bug: BlueZ returned the ghost first and we connected to it.
        let candidates = vec![ghost("AA:AA"), live("BB:BB", -70), ghost("CC:CC")];
        assert_eq!(
            best(&candidates, &FailureLog::default()).unwrap().address,
            "BB:BB"
        );
    }

    #[test]
    fn the_strongest_signal_wins() {
        let candidates = vec![live("AA:AA", -88), live("BB:BB", -52), live("CC:CC", -70)];
        assert_eq!(
            best(&candidates, &FailureLog::default()).unwrap().address,
            "BB:BB"
        );
    }

    #[test]
    fn ties_break_stably() {
        let candidates = vec![live("CC:CC", -60), live("AA:AA", -60)];
        let first = best(&candidates, &FailureLog::default()).unwrap();
        let again = best(&candidates, &FailureLog::default()).unwrap();
        assert_eq!(first, again, "the same input must give the same choice");
        assert_eq!(first.address, "AA:AA");
    }

    #[test]
    fn a_recent_failure_is_skipped_in_favour_of_anything_else() {
        let mut failures = FailureLog::default();
        failures.record("BB:BB");
        // BB is louder, but it just failed, so try the other one.
        let candidates = vec![live("AA:AA", -85), live("BB:BB", -40)];
        assert_eq!(best(&candidates, &failures).unwrap().address, "AA:AA");
    }

    #[test]
    fn a_failed_peer_is_still_tried_when_it_is_the_only_one() {
        // Never connecting at all is worse than retrying the one that failed.
        let mut failures = FailureLog::default();
        failures.record("BB:BB");
        let candidates = vec![live("BB:BB", -40)];
        assert_eq!(best(&candidates, &failures).unwrap().address, "BB:BB");
    }

    #[test]
    fn success_clears_the_cooldown() {
        let mut failures = FailureLog::default();
        failures.record("BB:BB");
        assert!(failures.is_cooling("BB:BB"));
        failures.forget("BB:BB");
        assert!(!failures.is_cooling("BB:BB"));
    }

    #[test]
    fn ghosts_alone_are_still_attempted() {
        // Some stacks never report RSSI. Refusing to connect at all there would
        // be worse than trying.
        let candidates = vec![ghost("AA:AA")];
        assert_eq!(
            best(&candidates, &FailureLog::default()).unwrap().address,
            "AA:AA"
        );
    }

    #[test]
    fn nothing_to_choose_from_is_not_a_choice() {
        assert!(best(&[], &FailureLog::default()).is_none());
        assert!(rank(&[], &FailureLog::default()).is_empty());
    }

    fn addresses(ranked: &[Candidate]) -> Vec<&str> {
        ranked.iter().map(|c| c.address.as_str()).collect()
    }

    #[test]
    fn ranking_orders_every_candidate_not_just_the_best() {
        // Holding several links means the second and third entries are targets,
        // so the whole list has to be ordered rather than only its head.
        let candidates = vec![
            ghost("DD:DD"),
            live("AA:AA", -80),
            live("BB:BB", -40),
            ghost("CC:CC"),
        ];
        let ranked = rank(&candidates, &FailureLog::default());
        assert_eq!(addresses(&ranked), vec!["BB:BB", "AA:AA", "CC:CC", "DD:DD"]);
    }

    #[test]
    fn a_cooling_peer_sorts_last_but_is_still_offered() {
        // It must be reachable when the peers above it are already held: with
        // six links to fill, "skip it entirely" would leave a slot empty for a
        // peer that is merely suspect.
        let mut failures = FailureLog::default();
        failures.record("BB:BB");
        let candidates = vec![live("BB:BB", -40), live("AA:AA", -85), ghost("CC:CC")];
        let ranked = rank(&candidates, &failures);
        assert_eq!(
            addresses(&ranked),
            vec!["AA:AA", "CC:CC", "BB:BB"],
            "the loudest peer sorts last because it just failed"
        );
    }

    #[test]
    fn ranking_agrees_with_choosing() {
        let mut failures = FailureLog::default();
        failures.record("BB:BB");
        let candidates = vec![live("BB:BB", -40), live("AA:AA", -85), ghost("CC:CC")];
        assert_eq!(
            best(&candidates, &failures).as_ref(),
            rank(&candidates, &failures).first(),
            "one is defined as the head of the other; they cannot disagree"
        );
    }

    #[test]
    fn ranking_is_stable_across_runs() {
        // The dialler works down this list. An order that shuffled between
        // passes would make a connection problem impossible to reproduce.
        let candidates = vec![live("CC:CC", -60), live("AA:AA", -60), ghost("BB:BB")];
        let failures = FailureLog::default();
        assert_eq!(
            addresses(&rank(&candidates, &failures)),
            addresses(&rank(&candidates, &failures))
        );
    }

    #[test]
    fn the_label_says_why_a_peer_was_picked() {
        assert_eq!(live("AA:BB", -61).label(), "Pixel [AA:BB] -61 dBm");
        assert_eq!(ghost("CC:DD").label(), "unnamed [CC:DD] no signal");
    }
}
