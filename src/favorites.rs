// src/favorites.rs
//
// Who we can reach when Bluetooth cannot reach them.
//
// A favourite is not a bookmark. Marking someone hands them our long-lived
// Nostr address, and being marked by them hands us theirs — and that exchange
// is the only way either side learns where to send a private message once the
// peer walks out of radio range. Everything about internet-carried DMs rests on
// this table.
//
// The relationship has two independent halves. We can favourite someone who has
// not favourited us, and vice versa; only when both hold is there a two-way
// route. Collapsing them into one flag would make an unanswered favourite look
// like a working address.
//
// Keyed by SHA-256 fingerprint, matching the block list and `state.json`'s
// `bitchat.favorites`. A nickname is claimed rather than owned, and a peer ID
// follows the key, so neither can anchor a stored address.

use std::collections::HashMap;

/// The marker a favourite notification carries, ahead of the sender's address.
///
/// Upstream sends this as the *content of an ordinary private message* rather
/// than as its own packet type — `"[FAVORITED]:" + npub` — and intercepts it on
/// arrival before it can reach the chat log. Verified against
/// `BLEService.sendFavoriteNotification` and
/// `ChatPrivateConversationCoordinator.handleFavoriteNotification`.
pub const FAVORITED: &str = "[FAVORITED]";
pub const UNFAVORITED: &str = "[UNFAVORITED]";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relationship {
    /// We handed them our address.
    pub we_favorited: bool,
    /// They handed us theirs.
    pub they_favorited: bool,
    /// Their long-lived Nostr address, once they have sent it.
    pub their_nostr_key: Option<String>,
    /// Last nickname seen, so a favourite list can be read by a human after
    /// the peer has gone out of range.
    pub nickname: String,
    /// Their announced Noise static key.
    ///
    /// Kept because a fingerprint is one-way and a courier envelope is addressed
    /// by a tag derived from the *key*. Without this we can name an absent
    /// favourite and still have no way to write to them — which is precisely the
    /// person store-and-forward exists for. The key is public; what is new is
    /// that it now outlives the peer being in range.
    pub noise_public_key: Option<Vec<u8>>,
}

impl Relationship {
    /// Whether a message could be carried to them over the internet.
    ///
    /// Requires their address, which only arrives with their favourite. Our own
    /// half does not matter for reachability: someone who favourited us can be
    /// answered whether or not we favourited them back.
    pub fn reachable_over_nostr(&self) -> bool {
        self.their_nostr_key.is_some()
    }

    pub fn mutual(&self) -> bool {
        self.we_favorited && self.they_favorited
    }
}

#[derive(Debug, Clone, Default)]
pub struct Favorites {
    by_fingerprint: HashMap<String, Relationship>,
}

/// What an inbound favourite marker turned out to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FavoriteNotice {
    pub is_favorite: bool,
    pub their_nostr_key: Option<String>,
}

impl Favorites {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a favourite marker, or `None` when the text is ordinary chat.
    ///
    /// The address is optional: upstream omits it when the sender has no Nostr
    /// identity yet, and an unfavourite carries one too. Splitting on the first
    /// colon only, because a key is opaque and must not be cut in half by one.
    pub fn parse_notice(content: &str) -> Option<FavoriteNotice> {
        let (marker, rest) = match content.split_once(':') {
            Some((marker, rest)) => (marker, Some(rest)),
            None => (content, None),
        };
        let is_favorite = match marker {
            FAVORITED => true,
            UNFAVORITED => false,
            _ => return None,
        };
        Some(FavoriteNotice {
            is_favorite,
            their_nostr_key: rest
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(str::to_string),
        })
    }

    /// The text of a notification announcing our own address.
    pub fn notice_text(is_favorite: bool, our_nostr_key: &str) -> String {
        let marker = if is_favorite { FAVORITED } else { UNFAVORITED };
        format!("{marker}:{our_nostr_key}")
    }

    /// Remembers a peer's announced key, if we have any relationship with them.
    ///
    /// Deliberately does not create an entry: caching a key for every stranger
    /// who announces would turn the favourites table into a log of everyone ever
    /// seen, which is a different thing with different consequences.
    pub fn note_key(&mut self, fingerprint: &str, noise_public_key: &[u8]) {
        if let Some(entry) = self.by_fingerprint.get_mut(&fingerprint.to_lowercase()) {
            entry.noise_public_key = Some(noise_public_key.to_vec());
        }
    }

    /// Records that we favourited, or stopped favouriting, a peer.
    pub fn set_ours(&mut self, fingerprint: &str, nickname: &str, favorited: bool) {
        let entry = self.entry(fingerprint);
        entry.we_favorited = favorited;
        if !nickname.is_empty() {
            entry.nickname = nickname.to_string();
        }
    }

    /// Applies an inbound notification.
    ///
    /// An address already held is kept when a notice arrives without one: an
    /// unfavourite is a statement about the relationship, not a retraction of
    /// the address, and dropping it would strand any message still queued.
    pub fn apply_notice(&mut self, fingerprint: &str, nickname: &str, notice: &FavoriteNotice) {
        let entry = self.entry(fingerprint);
        entry.they_favorited = notice.is_favorite;
        if !nickname.is_empty() {
            entry.nickname = nickname.to_string();
        }
        if let Some(key) = &notice.their_nostr_key {
            entry.their_nostr_key = Some(key.clone());
        }
    }

    /// Lookups the client does not call yet. They are the surface an internet
    /// transport needs — resolve an address to a peer, a peer to an address —
    /// and exist now because the table that answers them does.
    #[allow(dead_code)]
    pub fn get(&self, fingerprint: &str) -> Option<&Relationship> {
        self.by_fingerprint.get(fingerprint)
    }

    /// Their Nostr address, if we have one.
    #[allow(dead_code)]
    pub fn nostr_key_for(&self, fingerprint: &str) -> Option<&str> {
        self.by_fingerprint
            .get(fingerprint)
            .and_then(|entry| entry.their_nostr_key.as_deref())
    }

    /// Finds a relationship from a peer ID or a full fingerprint.
    ///
    /// The table is keyed by fingerprint but the client addresses peers by peer
    /// ID, which is the fingerprint's first 16 hex characters. Matching on that
    /// prefix reuses the protocol's own assumption that 64 bits of hash name a
    /// peer — the same one peer IDs already rest on — rather than inventing a
    /// weaker one, and it is how `is_blocked` answers the same question.
    pub fn resolve(&self, peer_id_or_fingerprint: &str) -> Option<(&str, &Relationship)> {
        let needle = peer_id_or_fingerprint.to_lowercase();
        self.by_fingerprint
            .iter()
            .find(|(fingerprint, _)| {
                fingerprint.starts_with(&needle) || needle.starts_with(*fingerprint)
            })
            .map(|(fingerprint, entry)| (fingerprint.as_str(), entry))
    }

    /// Everyone we could reach over the internet, by nickname.
    ///
    /// Used to address someone who has walked out of radio range: the peer list
    /// has forgotten them, but this table keeps the nickname and the address.
    pub fn by_nickname(&self, nickname: &str) -> Vec<(&str, &Relationship)> {
        let mut found: Vec<(&str, &Relationship)> = self
            .by_fingerprint
            .iter()
            .filter(|(_, entry)| entry.nickname.eq_ignore_ascii_case(nickname))
            .map(|(fingerprint, entry)| (fingerprint.as_str(), entry))
            .collect();
        // Stable order, so a name shared by two people reports the same pair
        // every run rather than whichever the hash iterated to first.
        found.sort_by_key(|(fingerprint, _)| *fingerprint);
        found
    }

    /// Fingerprint behind a Nostr address, for routing an inbound DM back to a
    /// mesh identity.
    #[allow(dead_code)]
    pub fn fingerprint_for_nostr_key(&self, nostr_key: &str) -> Option<&str> {
        self.by_fingerprint
            .iter()
            .find(|(_, entry)| entry.their_nostr_key.as_deref() == Some(nostr_key))
            .map(|(fingerprint, _)| fingerprint.as_str())
    }

    /// Everyone we have favourited, for the list command and for persistence.
    pub fn ours(&self) -> Vec<(&str, &Relationship)> {
        let mut listed: Vec<(&str, &Relationship)> = self
            .by_fingerprint
            .iter()
            .filter(|(_, entry)| entry.we_favorited)
            .map(|(fingerprint, entry)| (fingerprint.as_str(), entry))
            .collect();
        listed.sort_by(|a, b| a.1.nickname.cmp(&b.1.nickname));
        listed
    }

    pub fn all(&self) -> impl Iterator<Item = (&String, &Relationship)> {
        self.by_fingerprint.iter()
    }

    pub fn load(&mut self, entries: HashMap<String, Relationship>) {
        self.by_fingerprint = entries;
    }

    pub fn clear(&mut self) {
        self.by_fingerprint.clear();
    }

    fn entry(&mut self, fingerprint: &str) -> &mut Relationship {
        self.by_fingerprint
            .entry(fingerprint.to_lowercase())
            .or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "aa11bb22";

    #[test]
    fn a_favourite_marker_carries_an_address() {
        let notice = Favorites::parse_notice("[FAVORITED]:npub1abc").unwrap();
        assert!(notice.is_favorite);
        assert_eq!(notice.their_nostr_key.as_deref(), Some("npub1abc"));
    }

    #[test]
    fn an_unfavourite_is_recognised_too() {
        let notice = Favorites::parse_notice("[UNFAVORITED]:npub1abc").unwrap();
        assert!(!notice.is_favorite);
    }

    #[test]
    fn a_marker_without_an_address_is_still_a_marker() {
        // Upstream omits the key when the sender has no Nostr identity yet.
        let notice = Favorites::parse_notice("[FAVORITED]").unwrap();
        assert!(notice.is_favorite);
        assert!(notice.their_nostr_key.is_none());
    }

    #[test]
    fn ordinary_chat_is_not_a_marker() {
        // The interception must be exact: a message that merely mentions the
        // word must still reach the log.
        for text in [
            "hello",
            "I [FAVORITED] your post",
            "[FAV]:npub1",
            "",
            ":npub1abc",
        ] {
            assert!(
                Favorites::parse_notice(text).is_none(),
                "{text:?} must not be read as a favourite"
            );
        }
    }

    #[test]
    fn only_the_first_colon_separates_the_address() {
        // A key is opaque. Splitting on every colon would truncate one that
        // happened to contain another.
        let notice = Favorites::parse_notice("[FAVORITED]:npub1:with:colons").unwrap();
        assert_eq!(
            notice.their_nostr_key.as_deref(),
            Some("npub1:with:colons")
        );
    }

    #[test]
    fn the_text_we_send_is_the_text_we_parse() {
        let sent = Favorites::notice_text(true, "npub1mine");
        let parsed = Favorites::parse_notice(&sent).unwrap();
        assert!(parsed.is_favorite);
        assert_eq!(parsed.their_nostr_key.as_deref(), Some("npub1mine"));
    }

    #[test]
    fn the_two_halves_are_independent() {
        // Favouriting someone does not make them reachable; only their address
        // does. Collapsing the halves would make an unanswered favourite look
        // like a working route.
        let mut favorites = Favorites::new();
        favorites.set_ours(FP, "bob", true);
        let entry = favorites.get(FP).unwrap();
        assert!(entry.we_favorited);
        assert!(!entry.they_favorited);
        assert!(!entry.reachable_over_nostr());
        assert!(!entry.mutual());

        favorites.apply_notice(
            FP,
            "bob",
            &FavoriteNotice {
                is_favorite: true,
                their_nostr_key: Some("npub1bob".into()),
            },
        );
        let entry = favorites.get(FP).unwrap();
        assert!(entry.mutual());
        assert!(entry.reachable_over_nostr());
    }

    #[test]
    fn being_unfavourited_does_not_forget_the_address() {
        // An unfavourite is a statement about the relationship, not a
        // retraction of the address; dropping it would strand queued mail.
        let mut favorites = Favorites::new();
        favorites.apply_notice(
            FP,
            "bob",
            &FavoriteNotice {
                is_favorite: true,
                their_nostr_key: Some("npub1bob".into()),
            },
        );
        favorites.apply_notice(
            FP,
            "bob",
            &FavoriteNotice {
                is_favorite: false,
                their_nostr_key: None,
            },
        );
        let entry = favorites.get(FP).unwrap();
        assert!(!entry.they_favorited);
        assert_eq!(entry.their_nostr_key.as_deref(), Some("npub1bob"));
    }

    #[test]
    fn an_address_maps_back_to_its_peer() {
        // Inbound internet mail arrives addressed to a Nostr key and has to be
        // resolved to the mesh identity it belongs to.
        let mut favorites = Favorites::new();
        favorites.apply_notice(
            FP,
            "bob",
            &FavoriteNotice {
                is_favorite: true,
                their_nostr_key: Some("npub1bob".into()),
            },
        );
        assert_eq!(favorites.fingerprint_for_nostr_key("npub1bob"), Some(FP));
        assert!(favorites.fingerprint_for_nostr_key("npub1nobody").is_none());
    }

    #[test]
    fn a_peer_id_finds_the_fingerprint_it_prefixes() {
        // The client addresses peers by the 16-character peer ID; this table is
        // keyed by the full fingerprint it is a prefix of.
        let full = "aa11bb22cc33dd44ee55ff66";
        let peer_id = "aa11bb22cc33dd44";
        let mut favorites = Favorites::new();
        favorites.apply_notice(
            full,
            "bob",
            &FavoriteNotice {
                is_favorite: true,
                their_nostr_key: Some("npub1bob".into()),
            },
        );

        let (found, entry) = favorites.resolve(peer_id).expect("a peer ID resolves");
        assert_eq!(found, full);
        assert_eq!(entry.their_nostr_key.as_deref(), Some("npub1bob"));
        // And the whole thing still works.
        assert!(favorites.resolve(full).is_some());
        assert!(favorites.resolve("ffffffffffffffff").is_none());
    }

    #[test]
    fn a_favourite_is_reachable_by_name_after_they_leave() {
        // The peer list forgets someone who walked out of range. This table is
        // the only thing that still knows the name, which is the entire point:
        // otherwise the internet transport can never be addressed.
        let mut favorites = Favorites::new();
        favorites.set_ours("aa11", "bob", true);
        let found = favorites.by_nickname("BOB");
        assert_eq!(found.len(), 1, "the lookup ignores case");
        assert_eq!(found[0].0, "aa11");
        assert!(favorites.by_nickname("nobody").is_empty());
    }

    #[test]
    fn a_shared_nickname_reports_every_holder_in_a_stable_order() {
        // A nickname is claimed, not owned. Returning one arbitrary match would
        // send a private message to whichever the hash happened to iterate to.
        let mut favorites = Favorites::new();
        favorites.set_ours("bb22", "sam", true);
        favorites.set_ours("aa11", "sam", true);
        let names: Vec<&str> = favorites.by_nickname("sam").iter().map(|(f, _)| *f).collect();
        assert_eq!(names, vec!["aa11", "bb22"]);
    }

    #[test]
    fn our_list_holds_only_the_ones_we_marked() {
        let mut favorites = Favorites::new();
        favorites.set_ours("aa", "alice", true);
        favorites.set_ours("bb", "bob", false);
        favorites.apply_notice(
            "cc",
            "carol",
            &FavoriteNotice {
                is_favorite: true,
                their_nostr_key: None,
            },
        );
        let ours: Vec<&str> = favorites.ours().iter().map(|(f, _)| *f).collect();
        assert_eq!(ours, vec!["aa"], "only our own marks belong in our list");
    }
}
