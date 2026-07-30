// src/tui/emoji.rs
//
// Typing an emoji without leaving the keyboard.
//
// A terminal has no emoji picker and no way to reach one without taking your
// hands off the keys, which for a client whose entire interaction model is
// typing is the wrong trade. So emoji are typed the way they are typed
// everywhere people are already used to: `:fire:` becomes 🔥.
//
// Two paths through the same mechanism, deliberately:
//
//   - If you know the name, type it and the closing colon and it is simply
//     there. No interaction, no strip, nothing to dismiss.
//   - If you do not, the matches appear as you type and Tab takes one.
//
// The first path is the one that gets used once someone knows three shortcodes,
// so it must not require the second. A picker that always demands a selection is
// slower than the thing it replaced.
//
// The table is curated rather than exhaustive. The full Unicode set is some
// thousands of characters and most of them are never sent in conversation;
// carrying all of them would trade a large data blob for entries nobody reaches
// past the first screen of matches. Names follow the shared GitHub/Slack
// vocabulary, because a shortcode nobody else uses is a shortcode nobody knows.

/// One emoji and the names that reach it.
///
/// Aliases exist because people reach for different words for the same thing —
/// someone typing `:thumbsup:` and someone typing `:+1:` want the same
/// character, and making one of them wrong is a worse outcome than a slightly
/// larger table.
pub struct Emoji {
    pub glyph: &'static str,
    pub names: &'static [&'static str],
}

/// How many matches to offer at once.
///
/// A short list is the point. Anyone scrolling a long one has already lost to
/// simply typing the name, and the strip has to fit above the input without
/// pushing the conversation off screen.
pub const MAX_SUGGESTIONS: usize = 7;

/// The longest a shortcode query can get before it is obviously not one.
///
/// Guards the common false positive: a colon in ordinary prose. "here's the
/// thing: it was raining" should not spend the rest of the sentence looking like
/// an unfinished emoji.
const MAX_QUERY: usize = 24;

macro_rules! emoji {
    ($($glyph:literal => [$($name:literal),+ $(,)?]),* $(,)?) => {
        &[$(Emoji { glyph: $glyph, names: &[$($name),+] }),*]
    };
}

/// The set, in the order matches are offered.
///
/// Ordered by how often each is actually sent rather than alphabetically, so the
/// first match for a short prefix is usually the one wanted: `:s` should reach
/// 😄 before 🛰. Within that, related things sit together so browsing the strip
/// reads sensibly.
pub const TABLE: &[Emoji] = emoji! {
    // Faces — the overwhelming majority of what anyone sends.
    "😄" => ["smile", "happy"],
    "😂" => ["joy", "lol", "laughing"],
    "🙂" => ["slight_smile", "smiley"],
    "😉" => ["wink"],
    "😅" => ["sweat_smile", "phew"],
    "🙃" => ["upside_down"],
    "😐" => ["neutral", "straight_face"],
    "😑" => ["expressionless"],
    "🤔" => ["thinking", "hmm"],
    "😕" => ["confused"],
    "🙁" => ["frown", "sad"],
    "😞" => ["disappointed"],
    "😭" => ["sob", "crying"],
    "😱" => ["scream"],
    "😳" => ["flushed"],
    "😬" => ["grimace", "yikes"],
    "🤨" => ["raised_eyebrow", "suspicious"],
    "😴" => ["sleeping", "tired"],
    "🥲" => ["tear"],
    "😎" => ["sunglasses", "cool"],
    "🤯" => ["mind_blown", "exploding_head"],
    "🫠" => ["melting"],
    "😤" => ["triumph", "determined"],
    "🤷" => ["shrug"],
    "🫡" => ["salute"],
    "🙏" => ["pray", "thanks", "please"],

    // Hands and gestures.
    "👍" => ["+1", "thumbsup", "yes"],
    "👎" => ["-1", "thumbsdown", "no"],
    "👋" => ["wave", "hello", "bye"],
    "👌" => ["ok_hand"],
    "🤙" => ["call_me", "shaka"],
    "✌️" => ["v", "peace"],
    "🤝" => ["handshake", "deal"],
    "👏" => ["clap", "applause"],
    "💪" => ["muscle", "strong"],
    "🫶" => ["heart_hands"],
    "🖖" => ["vulcan", "live_long"],

    // Approval, celebration, emphasis.
    "🔥" => ["fire", "lit"],
    "🎉" => ["tada", "party", "celebrate"],
    "✨" => ["sparkles", "shiny"],
    "💯" => ["100", "hundred"],
    "⚡" => ["zap", "lightning", "fast"],
    "💥" => ["boom", "collision"],
    "🚀" => ["rocket", "ship", "launch"],
    "🏆" => ["trophy", "win"],
    "🥳" => ["partying"],
    "👀" => ["eyes", "looking"],

    // Hearts and warmth.
    "❤️" => ["heart", "love"],
    "🧡" => ["orange_heart"],
    "💚" => ["green_heart"],
    "💙" => ["blue_heart"],
    "💜" => ["purple_heart"],
    "🖤" => ["black_heart"],
    "💔" => ["broken_heart"],
    "🫂" => ["hug", "hugging"],

    // Marks and status — the ones a terminal person reaches for constantly.
    "✅" => ["white_check_mark", "check", "done"],
    "❌" => ["x", "cross", "fail"],
    "⚠️" => ["warning", "caution"],
    "❓" => ["question"],
    "❗" => ["exclamation"],
    "🚫" => ["no_entry", "blocked"],
    "🔒" => ["lock", "locked", "secure"],
    "🔓" => ["unlock", "unlocked"],
    "🔑" => ["key"],
    "🛡️" => ["shield"],
    "👁️" => ["eye", "watching"],

    // Machines, signal, the subject matter of this client.
    "📡" => ["satellite", "antenna", "relay"],
    "📶" => ["signal", "bars"],
    "🔋" => ["battery"],
    "🪫" => ["low_battery"],
    "🔌" => ["plug"],
    "💻" => ["computer", "laptop"],
    "🖥️" => ["desktop"],
    "📱" => ["phone", "mobile"],
    "🤖" => ["robot", "bot"],
    "🛰️" => ["satellite_orbital"],
    "🌐" => ["globe", "internet", "web"],
    "📻" => ["radio"],
    "🔗" => ["link", "chain"],
    "📦" => ["package", "box", "mail"],
    "✉️" => ["envelope", "letter"],
    "📍" => ["pin", "location", "here"],
    "🗺️" => ["map"],
    "🧭" => ["compass"],
    "🔍" => ["magnifying_glass", "search", "find"],
    "🐛" => ["bug"],
    "🔧" => ["wrench", "fix"],
    "🛠️" => ["tools"],
    "⚙️" => ["gear", "settings"],
    "🧪" => ["test_tube", "experiment"],
    "💾" => ["floppy", "save"],
    "📊" => ["chart", "stats"],
    "🕐" => ["clock", "time"],
    "⏳" => ["hourglass", "waiting"],
    "🔔" => ["bell", "notify"],
    "🔕" => ["mute", "silent"],

    // Weather, world, and a few things worth saying.
    "☀️" => ["sun", "sunny"],
    "🌙" => ["moon", "night"],
    "⭐" => ["star"],
    "🌧️" => ["rain"],
    "❄️" => ["snow", "cold"],
    "🌊" => ["wave_water", "ocean"],
    "🌲" => ["tree", "forest"],
    "🏔️" => ["mountain"],
    "🌍" => ["earth"],
    "☕" => ["coffee"],
    "🍺" => ["beer"],
    "🍕" => ["pizza"],
    "🎵" => ["music", "note"],
    "🎧" => ["headphones"],
    "📷" => ["camera", "photo"],
    "🎮" => ["game", "controller"],
    "🚲" => ["bike"],
    "🚗" => ["car"],
    "✈️" => ["plane", "flight"],
    "🏠" => ["house", "home"],
    "🐈" => ["cat"],
    "🐕" => ["dog"],
    "🦀" => ["crab", "rust"],
    "🐧" => ["penguin", "linux"],
    "👻" => ["ghost"],
    "💀" => ["skull", "dead"],
    "🧠" => ["brain"],
    "🌀" => ["cyclone", "spiral"],
    "🪄" => ["magic_wand"],
};

/// The `:query` sitting immediately before the cursor, if there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Character index of the opening colon.
    pub start: usize,
    /// Character index just past the query, which is where the cursor is.
    pub end: usize,
    /// What was typed after the colon, lowercased.
    pub text: String,
}

/// Finds the shortcode being typed at the cursor.
///
/// Scans back from the cursor to an opening colon, refusing at the first thing
/// that says this is not a shortcode: whitespace, a second colon, or simply
/// going on too long. Without those, every colon in ordinary prose would open a
/// picker and keep it open — and a colon is far more often punctuation than the
/// start of an emoji.
pub fn query_at(value: &str, cursor: usize) -> Option<Query> {
    let chars: Vec<char> = value.chars().collect();
    let cursor = cursor.min(chars.len());

    let mut index = cursor;
    while index > 0 {
        let candidate = chars[index - 1];
        if candidate == ':' {
            let text: String = chars[index..cursor].iter().collect();
            // A bare `:` with nothing after it offers the whole table, which is
            // how someone who does not know any shortcode finds the first one.
            return Some(Query {
                start: index - 1,
                end: cursor,
                text: text.to_lowercase(),
            });
        }
        // A shortcode is one word. Anything that ends a word ends the query.
        if candidate.is_whitespace() || cursor - index >= MAX_QUERY {
            return None;
        }
        index -= 1;
    }
    None
}

/// The emoji whose name is exactly this, for the type-it-and-go path.
pub fn exact(name: &str) -> Option<&'static Emoji> {
    let name = name.to_lowercase();
    TABLE
        .iter()
        .find(|emoji| emoji.names.iter().any(|alias| *alias == name))
}

/// Matches for a partial name, best first.
///
/// Names that *start* with the query come before names that merely contain it,
/// so `:fire` reaches 🔥 rather than a campfire, and table order breaks ties —
/// which is why the table is ordered by how often things are actually sent. A
/// list that reshuffled as you typed would be unusable at speed.
pub fn suggestions(query: &str) -> Vec<&'static Emoji> {
    let query = query.to_lowercase();
    if query.is_empty() {
        return TABLE.iter().take(MAX_SUGGESTIONS).collect();
    }

    let mut prefix = Vec::new();
    let mut contains = Vec::new();
    for emoji in TABLE {
        if emoji.names.iter().any(|name| name.starts_with(&query)) {
            prefix.push(emoji);
        } else if emoji.names.iter().any(|name| name.contains(&query)) {
            contains.push(emoji);
        }
    }
    prefix.extend(contains);
    prefix.truncate(MAX_SUGGESTIONS);
    prefix
}

/// The name to show for a match, preferring one the query actually explains.
///
/// Showing `:+1:` to someone who typed `thumb` would look like the wrong result
/// even though it is the right character.
pub fn label_for(emoji: &Emoji, query: &str) -> &'static str {
    let query = query.to_lowercase();
    emoji
        .names
        .iter()
        .find(|name| name.starts_with(&query))
        .or_else(|| emoji.names.iter().find(|name| name.contains(&query)))
        .copied()
        .unwrap_or(emoji.names[0])
}

/// Replaces the query with the emoji, returning the new text and cursor.
///
/// Adds no trailing space. Emoji are frequently sent in runs — 🎉🎉🎉 — and a
/// space after each would have to be deleted every time.
pub fn apply(value: &str, query: &Query, glyph: &str) -> (String, usize) {
    let chars: Vec<char> = value.chars().collect();
    let before: String = chars[..query.start].iter().collect();
    let after: String = chars[query.end.min(chars.len())..].iter().collect();
    let cursor = query.start + glyph.chars().count();
    (format!("{before}{glyph}{after}"), cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_name_reaches_exactly_one_emoji() {
        // A duplicated name makes one of the two unreachable, and which one
        // depends on table order — a bug that looks like a missing emoji.
        let mut seen: HashSet<&str> = HashSet::new();
        for emoji in TABLE {
            for name in emoji.names {
                assert!(seen.insert(name), "{name:?} names more than one emoji");
            }
        }
    }

    #[test]
    fn every_entry_has_a_glyph_and_a_name() {
        for emoji in TABLE {
            assert!(!emoji.glyph.is_empty());
            assert!(!emoji.names.is_empty());
            for name in emoji.names {
                assert!(!name.is_empty());
                assert!(
                    !name.contains(':') && !name.contains(' '),
                    "{name:?} cannot be typed as a shortcode"
                );
                assert_eq!(*name, name.to_lowercase(), "{name:?} must be lowercase");
            }
        }
    }

    #[test]
    fn the_shortcodes_people_already_know_work() {
        // The shared GitHub/Slack vocabulary. A shortcode nobody else uses is a
        // shortcode nobody knows.
        for (name, glyph) in [
            ("fire", "🔥"),
            ("tada", "🎉"),
            ("+1", "👍"),
            ("-1", "👎"),
            ("heart", "❤️"),
            ("joy", "😂"),
            ("rocket", "🚀"),
            ("eyes", "👀"),
            ("100", "💯"),
            ("white_check_mark", "✅"),
        ] {
            assert_eq!(exact(name).map(|e| e.glyph), Some(glyph), "{name}");
        }
    }

    #[test]
    fn aliases_reach_the_same_character() {
        assert_eq!(exact("+1").map(|e| e.glyph), exact("thumbsup").map(|e| e.glyph));
        assert_eq!(exact("lol").map(|e| e.glyph), exact("joy").map(|e| e.glyph));
    }

    #[test]
    fn a_name_is_found_whatever_case_it_is_typed() {
        assert_eq!(exact("FIRE").map(|e| e.glyph), Some("🔥"));
        assert_eq!(exact("Tada").map(|e| e.glyph), Some("🎉"));
    }

    #[test]
    fn a_prefix_beats_a_mere_substring() {
        // `:fire` must reach 🔥 and not something that merely contains "fire".
        let matches = suggestions("fire");
        assert_eq!(matches.first().map(|e| e.glyph), Some("🔥"));
    }

    #[test]
    fn suggestions_are_capped_and_stable() {
        // A list that reshuffled as you typed would be unusable at speed.
        let first = suggestions("s");
        assert!(first.len() <= MAX_SUGGESTIONS);
        let again = suggestions("s");
        assert_eq!(
            first.iter().map(|e| e.glyph).collect::<Vec<_>>(),
            again.iter().map(|e| e.glyph).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_bare_colon_offers_somewhere_to_start() {
        // How someone who knows no shortcodes finds their first one.
        let matches = suggestions("");
        assert_eq!(matches.len(), MAX_SUGGESTIONS);
    }

    #[test]
    fn nonsense_matches_nothing() {
        assert!(suggestions("zzzzqqq").is_empty());
        assert!(exact("zzzzqqq").is_none());
    }

    #[test]
    fn the_label_explains_the_match() {
        // Showing `:+1:` to someone who typed "thumb" looks like the wrong
        // result even when the character is right.
        let thumbs = exact("thumbsup").unwrap();
        assert_eq!(label_for(thumbs, "thumb"), "thumbsup");
        assert_eq!(label_for(thumbs, "+"), "+1");
        assert_eq!(label_for(thumbs, ""), "+1", "falls back to the first name");
    }

    // MARK: - Finding the query under the cursor

    #[test]
    fn a_shortcode_being_typed_is_found() {
        let found = query_at("hey :fi", 7).expect("mid-shortcode");
        assert_eq!(found.text, "fi");
        assert_eq!(found.start, 4);
        assert_eq!(found.end, 7);
    }

    #[test]
    fn a_bare_colon_is_a_query() {
        let found = query_at("hey :", 5).expect("just opened");
        assert_eq!(found.text, "");
    }

    #[test]
    fn a_colon_in_prose_does_not_open_a_picker() {
        // The false positive that would make this feature unbearable: a colon is
        // far more often punctuation than the start of an emoji.
        assert!(query_at("the thing: it was raining", 25).is_none());
        assert!(query_at("note: see below", 15).is_none());
    }

    #[test]
    fn a_query_gives_up_after_a_sensible_length() {
        let long = format!(":{}", "z".repeat(MAX_QUERY + 5));
        assert!(
            query_at(&long, long.chars().count()).is_none(),
            "past a point it is plainly not a shortcode"
        );
    }

    #[test]
    fn only_the_text_before_the_cursor_counts() {
        // Someone editing earlier in the line is not typing an emoji at the end.
        let found = query_at("hey :fire there", 7).expect("cursor inside the shortcode");
        assert_eq!(found.text, "fi");
        assert_eq!(found.end, 7, "the query stops at the cursor, not the word");
    }

    #[test]
    fn a_shortcode_at_the_very_start_is_found() {
        let found = query_at(":ro", 3).unwrap();
        assert_eq!(found.text, "ro");
        assert_eq!(found.start, 0);
    }

    #[test]
    fn nothing_is_found_where_there_is_no_colon() {
        assert!(query_at("plain words", 11).is_none());
        assert!(query_at("", 0).is_none());
    }

    #[test]
    fn a_cursor_past_the_end_does_not_panic() {
        let _ = query_at("hey", 99);
        let _ = query_at("", 5);
    }

    // MARK: - Applying a choice

    #[test]
    fn accepting_replaces_the_shortcode_in_place() {
        let query = query_at("hey :fi", 7).unwrap();
        let (text, cursor) = apply("hey :fi", &query, "🔥");
        assert_eq!(text, "hey 🔥");
        assert_eq!(cursor, 5, "just past the emoji");
    }

    #[test]
    fn accepting_keeps_what_follows_the_cursor() {
        // Someone who went back to fix a shortcode mid-sentence must not lose
        // the rest of the sentence.
        let query = query_at("say :fi soon", 7).unwrap();
        let (text, cursor) = apply("say :fi soon", &query, "🔥");
        assert_eq!(text, "say 🔥 soon");
        assert_eq!(cursor, 5);
    }

    #[test]
    fn no_space_is_added_after_an_emoji() {
        // Emoji are sent in runs, and a space after each would have to be
        // deleted every time.
        let query = query_at(":tada", 5).unwrap();
        let (text, _) = apply(":tada", &query, "🎉");
        assert_eq!(text, "🎉");
    }

    #[test]
    fn emoji_can_be_typed_back_to_back() {
        let (text, cursor) = apply(":tada", &query_at(":tada", 5).unwrap(), "🎉");
        assert_eq!(text, "🎉");
        let next = format!("{text}:tada");
        let query = query_at(&next, next.chars().count()).unwrap();
        let (text, _) = apply(&next, &query, "🎉");
        assert_eq!(text, "🎉🎉");
        assert_eq!(cursor, 1);
    }

    #[test]
    fn a_multi_codepoint_emoji_leaves_the_cursor_past_all_of_it() {
        // ❤️ is a heart plus a variation selector. A cursor placed by codepoint
        // count has to account for both or the next keystroke lands inside it.
        let query = query_at(":heart", 6).unwrap();
        let (text, cursor) = apply(":heart", &query, "❤️");
        assert_eq!(text, "❤️");
        assert_eq!(cursor, "❤️".chars().count());
    }
}
