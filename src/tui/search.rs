// src/tui/search.rs

//! Finding a line in the scrollback.
//!
//! The log is the only part of this client that keeps everything. A channel can
//! run for hours and the wheel only moves three lines a notch, so "who said the
//! thing about the relay" is a question the UI could not answer at all.
//!
//! Two states rather than one, because they take the keyboard differently. While
//! the prompt is open every keystroke is query text — that is what stops `i`
//! opening the image viewer mid-word, which is the bug this shape exists to
//! prevent. Once committed the prompt closes, the matches stay, and `n`/`N` walk
//! them. Esc from either state puts the log back exactly where it was, because a
//! search that loses your place costs more than it found.

use crate::tui::app::Message;

/// Matching is on the sender as well as the body.
///
/// Looking for a person is at least as common as looking for a word, and a
/// nickname is rarely a substring of anything else in the line.
fn matches(message: &Message, needle_lowercase: &str) -> bool {
    message.content.to_lowercase().contains(needle_lowercase)
        || message.sender.to_lowercase().contains(needle_lowercase)
}

#[derive(Default)]
pub struct Search {
    /// Whether the prompt is taking keystrokes.
    pub prompt_open: bool,
    /// What has been typed. Kept when the prompt closes so the status line can
    /// still say what is being walked.
    pub query: String,
    /// Indices into the current conversation's messages, oldest first.
    hits: Vec<usize>,
    /// Which of `hits` is selected.
    selected: usize,
    /// Where the log sat before the prompt opened, to restore on cancel.
    scroll_before: usize,
}

impl Search {
    /// Opens the prompt, remembering where the log was.
    pub fn open(&mut self, current_scroll: usize) {
        self.prompt_open = true;
        self.query.clear();
        self.hits.clear();
        self.selected = 0;
        self.scroll_before = current_scroll;
    }

    /// Closes everything and reports the scroll position to go back to.
    ///
    /// Used for Esc. Committing a search does not come through here — that
    /// keeps the hits so `n` has something to walk.
    pub fn cancel(&mut self) -> usize {
        self.prompt_open = false;
        self.query.clear();
        self.hits.clear();
        self.selected = 0;
        self.scroll_before
    }

    /// Drops the hits without moving the log. For when the conversation changes
    /// underneath a finished search and the indices stop meaning anything.
    pub fn forget(&mut self) {
        self.prompt_open = false;
        self.query.clear();
        self.hits.clear();
        self.selected = 0;
    }

    pub fn push(&mut self, character: char) {
        self.query.push(character);
    }

    pub fn backspace(&mut self) {
        self.query.pop();
    }

    /// Recomputes the hits against a conversation.
    ///
    /// Selects the *newest* match, not the oldest. The interesting line in a
    /// chat log is nearly always the most recent one that matches, and starting
    /// at the top would mean walking the whole history to reach it.
    pub fn run(&mut self, messages: &[Message]) {
        self.hits.clear();
        self.selected = 0;
        if self.query.is_empty() {
            return;
        }
        let needle = self.query.to_lowercase();
        self.hits = messages
            .iter()
            .enumerate()
            .filter(|(_, message)| matches(message, &needle))
            .map(|(index, _)| index)
            .collect();
        self.selected = self.hits.len().saturating_sub(1);
    }

    /// Commits the query: the prompt closes, the hits stay.
    pub fn commit(&mut self) {
        self.prompt_open = false;
    }

    /// Steps towards older matches, wrapping to the newest.
    pub fn previous(&mut self) {
        if self.hits.is_empty() {
            return;
        }
        self.selected = match self.selected.checked_sub(1) {
            Some(previous) => previous,
            None => self.hits.len() - 1,
        };
    }

    /// Steps towards newer matches, wrapping to the oldest.
    pub fn next(&mut self) {
        if self.hits.is_empty() {
            return;
        }
        self.selected = if self.selected + 1 >= self.hits.len() {
            0
        } else {
            self.selected + 1
        };
    }

    /// The message index currently selected, if any.
    pub fn current(&self) -> Option<usize> {
        self.hits.get(self.selected).copied()
    }

    /// Whether `n`/`N` should be taken as navigation rather than as text.
    pub fn is_walking(&self) -> bool {
        !self.prompt_open && !self.hits.is_empty()
    }

    pub fn hit_count(&self) -> usize {
        self.hits.len()
    }

    /// What to draw beside the query. Ordinal is oldest-first so it counts the
    /// way the log reads, even though the selection starts at the newest.
    pub fn status(&self) -> String {
        if self.query.is_empty() {
            return String::new();
        }
        if self.hits.is_empty() {
            return "no matches".to_string();
        }
        format!("{} of {}", self.selected + 1, self.hits.len())
    }
}

/// The scroll offset that brings `message_index` into view.
///
/// `msg_scroll` counts backwards from the newest message, so this is the
/// distance from the end. The match lands on the last visible row, which needs
/// no viewport height to compute and puts the found line where the eye already
/// is after a jump.
///
/// Clamping to `max_scroll` is what keeps the oldest matches on screen: at the
/// top of the log there is nothing behind them to scroll to, so they sit high in
/// the viewport instead of at its foot. The unit tests check the match is
/// visible on both sides of that boundary, since an off-by-one here scrolls to
/// a line next to the one you asked for and looks like a search bug.
pub fn scroll_for(message_index: usize, total_messages: usize, viewport_height: usize) -> usize {
    let max_scroll = total_messages.saturating_sub(viewport_height);
    total_messages
        .saturating_sub(message_index + 1)
        .min(max_scroll)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(sender: &str, content: &str) -> Message {
        Message {
            sender: sender.to_string(),
            timestamp: "00:00".to_string(),
            content: content.to_string(),
            is_self: false,
            epoch: 0,
            message_id: None,
            delivery: None,
            arrived: None,
        }
    }

    fn log() -> Vec<Message> {
        vec![
            message("alice", "the relay is down"),
            message("bob", "which relay"),
            message("alice", "damus"),
            message("carol", "unrelated chatter"),
            message("bob", "RELAY is back"),
        ]
    }

    #[test]
    fn a_search_finds_every_line_that_contains_the_word() {
        let mut search = Search::default();
        search.open(0);
        for character in "relay".chars() {
            search.push(character);
        }
        search.run(&log());
        assert_eq!(search.hit_count(), 3, "two lowercase and one uppercase");
    }

    #[test]
    fn matching_ignores_case_in_both_directions() {
        // The uppercase line must be found by a lowercase query and the reverse,
        // or searching becomes a guess about how someone typed.
        let mut lower = Search::default();
        lower.open(0);
        "RELAY".chars().for_each(|c| lower.push(c));
        lower.run(&log());
        assert_eq!(lower.hit_count(), 3);
    }

    #[test]
    fn a_sender_is_searchable_as_well_as_a_body() {
        let mut search = Search::default();
        search.open(0);
        "carol".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.hit_count(), 1, "found by who said it");
        assert_eq!(search.current(), Some(3));
    }

    #[test]
    fn the_newest_match_is_selected_first() {
        // Not the oldest. In a log the recent one is nearly always the one being
        // looked for, and starting at the top means walking the whole history.
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.current(), Some(4), "the last matching line");
    }

    #[test]
    fn stepping_back_and_forward_walks_the_matches_and_wraps() {
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());

        assert_eq!(search.current(), Some(4));
        search.previous();
        assert_eq!(search.current(), Some(1), "older");
        search.previous();
        assert_eq!(search.current(), Some(0), "older still");
        search.previous();
        assert_eq!(search.current(), Some(4), "wrapped to the newest");
        search.next();
        assert_eq!(search.current(), Some(0), "and forward wraps the other way");
    }

    #[test]
    fn a_query_matching_nothing_leaves_nothing_to_walk() {
        let mut search = Search::default();
        search.open(0);
        "nonesuch".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.current(), None);
        assert_eq!(search.status(), "no matches");
        // Stepping must not panic or wrap onto a stale index.
        search.next();
        search.previous();
        assert_eq!(search.current(), None);
    }

    #[test]
    fn an_empty_query_matches_nothing_rather_than_everything() {
        // `"".contains("")` is true for every string, so the obvious
        // implementation selects the whole log and calls it a result.
        let mut search = Search::default();
        search.open(0);
        search.run(&log());
        assert_eq!(search.hit_count(), 0);
        assert_eq!(search.status(), "");
    }

    #[test]
    fn backspacing_to_empty_clears_the_matches() {
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.hit_count(), 3);

        for _ in 0..5 {
            search.backspace();
        }
        search.run(&log());
        assert_eq!(search.hit_count(), 0, "no query, no hits");
        assert_eq!(search.current(), None);
    }

    #[test]
    fn cancelling_reports_the_scroll_the_log_started_at() {
        let mut search = Search::default();
        search.open(42);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.cancel(), 42, "Esc puts the log back where it was");
        assert!(!search.prompt_open);
        assert_eq!(search.current(), None, "and leaves nothing to walk");
    }

    #[test]
    fn committing_closes_the_prompt_and_keeps_the_matches() {
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        search.commit();
        assert!(!search.prompt_open, "the prompt is done taking keys");
        assert!(search.is_walking(), "but n and N have somewhere to go");
        assert_eq!(search.current(), Some(4));
    }

    #[test]
    fn a_committed_search_with_no_matches_does_not_capture_n() {
        // Otherwise `n` is silently swallowed after a failed search, which reads
        // as a wedged keyboard.
        let mut search = Search::default();
        search.open(0);
        "nonesuch".chars().for_each(|c| search.push(c));
        search.run(&log());
        search.commit();
        assert!(!search.is_walking());
    }

    #[test]
    fn the_status_counts_from_the_oldest_match() {
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        assert_eq!(search.status(), "3 of 3", "newest selected, counted in order");
        search.previous();
        assert_eq!(search.status(), "2 of 3");
    }

    #[test]
    fn forgetting_drops_the_search_without_claiming_a_scroll() {
        let mut search = Search::default();
        search.open(7);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&log());
        search.forget();
        assert!(!search.is_walking());
        assert_eq!(search.current(), None);
    }

    #[test]
    fn a_match_in_the_middle_lands_on_the_last_visible_row() {
        // 100 messages, a viewport of 20, match at index 50. The row after the
        // match is the end of the slice, so the distance from the newest is 49.
        assert_eq!(scroll_for(50, 100, 20), 49);
    }

    #[test]
    fn the_newest_message_needs_no_scrolling() {
        assert_eq!(scroll_for(99, 100, 20), 0);
    }

    #[test]
    fn an_old_match_is_clamped_and_still_on_screen() {
        // Index 0 of 100 would want a scroll of 99, but the log stops at 80.
        // Clamped, the slice is [0, 20) and the match sits at the top rather
        // than the foot — visible either way, which is the property that counts.
        assert_eq!(scroll_for(0, 100, 20), 80);
    }

    #[test]
    fn every_match_is_visible_at_the_scroll_chosen_for_it() {
        // The property behind the three cases above, over the whole range and
        // across the clamp boundary. `start..end` is exactly how the log slices
        // itself, so this fails if the arithmetic drifts from the renderer's.
        let total = 100;
        for viewport in [1, 7, 20, 99, 100, 140] {
            for index in 0..total {
                let scroll = scroll_for(index, total, viewport);
                let end = total - scroll;
                let start = end.saturating_sub(viewport);
                assert!(
                    (start..end).contains(&index),
                    "index {index} not visible in {start}..{end} at viewport {viewport}"
                );
            }
        }
    }

    #[test]
    fn a_viewport_taller_than_the_log_never_scrolls() {
        for index in 0..5 {
            assert_eq!(scroll_for(index, 5, 40), 0, "nothing to scroll past");
        }
    }

    #[test]
    fn searching_an_empty_log_is_harmless() {
        let mut search = Search::default();
        search.open(0);
        "relay".chars().for_each(|c| search.push(c));
        search.run(&[]);
        assert_eq!(search.current(), None);
        assert_eq!(scroll_for(0, 0, 20), 0);
    }
}
