// src/nostr/processed.rs
//
// Which private envelopes we have already opened.
//
// A gift wrap is stored mail: the relay holds it so it can be handed over when
// the recipient reappears, and hands it over again on the next reconnect, and
// the one after that. The DM subscription asks for a day of history precisely
// so nothing sent while we were offline is missed — which means every launch is
// handed the same day of history again.
//
// A session-lifetime cache is not enough for that. Restart the client and every
// message from the last 24 hours arrives as though it were new: old
// conversations replayed into the log, delivery receipts re-fired at peers who
// acknowledged them yesterday, read receipts sent a second time for messages
// read once. The record has to outlive the process, so it lives on disk.
//
// What it holds is not secret — every id here is public on the relays that
// served it — but it is a record that we received mail and roughly when, so the
// wipe path clears it with everything else.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

/// How many ids to keep.
///
/// The floor that matters is how many distinct wraps the subscription window
/// can deliver: a day of history, `DM_LIMIT` per relay, across the relay set.
/// Evicting an id that is still inside that window would let the event it
/// describes be processed again on the next reconnect, which is the exact
/// failure this file exists to prevent — so the cap sits an order of magnitude
/// above the worst case rather than close to it.
const CAPACITY: usize = 4096;

/// Ids of private envelopes already handled, remembered across launches.
pub struct ProcessedEvents {
    /// `None` when no home directory could be resolved. The client still runs;
    /// it simply cannot remember across launches, and says so once rather than
    /// failing to start.
    path: Option<PathBuf>,
    seen: HashSet<String>,
    /// Insertion order, so the cap evicts the ids recorded longest ago.
    order: VecDeque<String>,
}

impl ProcessedEvents {
    /// Loads the record beside the identity file.
    pub fn open() -> Self {
        Self::open_at(default_path())
    }

    pub fn open_at(path: Option<PathBuf>) -> Self {
        let stored: Vec<String> = path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();

        let mut store = Self {
            path,
            seen: HashSet::with_capacity(stored.len()),
            order: VecDeque::with_capacity(stored.len()),
        };
        // Through the same door as a live id, so a hand-edited or duplicated
        // file cannot leave `seen` and `order` disagreeing about the contents.
        for id in stored {
            store.insert(id);
        }
        store
    }

    /// Records an id, reporting whether it is one we had not already handled.
    ///
    /// Writes through on every new id. That is a syscall per message, which
    /// would be indefensible for chat volume and is not for this: private mail
    /// arrives a few times a day, and the cost of losing the write is replaying
    /// a day of it. Cheap insurance against a crash, a kill, or a laptop lid.
    pub fn remember(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return false;
        }
        self.insert(id.to_string());
        self.save();
        true
    }

    /// Inspection used by the tests. The client only ever asks `remember`,
    /// which answers the one question it has.
    #[cfg(test)]
    pub fn contains(&self, id: &str) -> bool {
        self.seen.contains(id)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Paired with `len` so the public surface reads consistently. Both are
    /// test-only; the record's real question is `contains`.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Forgets everything, on disk as well as in memory.
    pub fn wipe(&mut self) {
        self.seen.clear();
        self.order.clear();
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }

    fn insert(&mut self, id: String) {
        if !self.seen.insert(id.clone()) {
            return;
        }
        self.order.push_back(id);
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    /// Writes to a sibling temp file and renames over the original, so an
    /// interrupted write leaves the previous record intact rather than a
    /// half-written one that parses as empty.
    fn save(&self) {
        let Some(path) = &self.path else { return };
        let ids: Vec<&String> = self.order.iter().collect();
        let Ok(encoded) = serde_json::to_string(&ids) else {
            return;
        };
        let temporary = path.with_extension("json.tmp");
        if fs::write(&temporary, encoded).is_ok() && fs::rename(&temporary, path).is_err() {
            let _ = fs::remove_file(&temporary);
        }
    }
}

fn default_path() -> Option<PathBuf> {
    let state = crate::persistence::get_state_file_path();
    let directory: &Path = state.parent()?;
    Some(directory.join("nostr-seen.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitmancer-processed-{name}-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn an_id_is_new_once() {
        let mut store = ProcessedEvents::open_at(Some(scratch("once")));
        assert!(store.remember("abc"), "first sighting is new");
        assert!(!store.remember("abc"), "second sighting is not");
        assert!(store.remember("def"));
    }

    #[test]
    fn the_record_survives_a_restart() {
        // The whole point: relays redeliver a day of mail on every reconnect,
        // so a store that forgets on exit replays every message and re-fires
        // every receipt at peers who acknowledged them yesterday.
        let path = scratch("restart");
        {
            let mut first = ProcessedEvents::open_at(Some(path.clone()));
            first.remember("wrap-1");
            first.remember("wrap-2");
        }
        let mut second = ProcessedEvents::open_at(Some(path.clone()));
        assert!(!second.remember("wrap-1"), "must be remembered across launches");
        assert!(!second.remember("wrap-2"));
        assert!(second.remember("wrap-3"), "and still accept genuinely new mail");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_record_is_bounded_and_evicts_the_oldest() {
        let path = scratch("bounded");
        let mut store = ProcessedEvents::open_at(Some(path.clone()));
        for index in 0..(CAPACITY + 10) {
            store.remember(&format!("id-{index}"));
        }
        assert_eq!(store.len(), CAPACITY);
        assert!(!store.contains("id-0"), "the oldest fell out");
        assert!(store.contains(&format!("id-{}", CAPACITY + 9)), "the newest stayed");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_wipe_leaves_nothing_on_disk() {
        let path = scratch("wipe");
        let mut store = ProcessedEvents::open_at(Some(path.clone()));
        store.remember("wrap-1");
        assert!(path.exists());
        store.wipe();
        assert!(!path.exists(), "the file must go, not just the memory");
        assert!(
            ProcessedEvents::open_at(Some(path.clone())).remember("wrap-1"),
            "and a fresh store must not recover it"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_file_is_not_fatal() {
        // Losing the record costs a replay. Refusing to start costs the client.
        let path = scratch("corrupt");
        fs::write(&path, "{not json at all").unwrap();
        let mut store = ProcessedEvents::open_at(Some(path.clone()));
        assert_eq!(store.len(), 0);
        assert!(store.remember("wrap-1"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_duplicated_file_loads_once() {
        let path = scratch("dupes");
        fs::write(&path, r#"["a","a","b"]"#).unwrap();
        let store = ProcessedEvents::open_at(Some(path.clone()));
        assert_eq!(store.len(), 2, "seen and order must agree on the contents");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn no_home_directory_is_survivable() {
        let mut store = ProcessedEvents::open_at(None);
        assert!(store.remember("wrap-1"), "still deduplicates within the session");
        assert!(!store.remember("wrap-1"));
    }
}
