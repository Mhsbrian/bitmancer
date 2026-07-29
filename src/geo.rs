// src/geo.rs
//
// Geohash location channels: the Nostr-side counterpart to `mesh.rs`.
//
// Each channel has its own derived identity, its own relay set, and its own
// participant list. Nothing here knows about Bluetooth, and `mesh.rs` knows
// nothing about this.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::geohash;
use crate::nostr::event::{geohash_tags, Event, KIND_EPHEMERAL, KIND_PRESENCE};
use crate::nostr::identity::IdentityStore;
use crate::nostr::pow;

/// Relays per channel, matching upstream's `closestRelays(count: 5)`.
const RELAYS_PER_CHANNEL: usize = 5;

/// Upstream broadcasts presence on a 40-80s randomised loop.
const PRESENCE_MIN: Duration = Duration::from_secs(40);
const PRESENCE_MAX: Duration = Duration::from_secs(80);

/// A participant is listed until this long after their last beacon or message.
const PARTICIPANT_TTL: Duration = Duration::from_secs(300);

/// Presence is only announced at coarse precisions. Beaconing at building or
/// block level would broadcast the user's exact location, which is why
/// upstream restricts it to region/province/city.
const PRESENCE_PRECISIONS: [usize; 3] = [2, 4, 5];

#[derive(Debug, Clone)]
pub struct Participant {
    pub pubkey: String,
    pub nickname: Option<String>,
    pub last_seen: Instant,
}

impl Participant {
    pub fn display_name(&self) -> String {
        self.nickname
            .clone()
            .unwrap_or_else(|| format!("anon{}", &self.pubkey[..4.min(self.pubkey.len())]))
    }
}

struct Channel {
    geohash: String,
    relays: Vec<String>,
    participants: HashMap<String, Participant>,
    next_presence: Instant,
}

pub struct GeoService {
    identities: IdentityStore,
    channels: HashMap<String, Channel>,
    pub nickname: String,
    /// Counter used to vary the presence interval without pulling in an RNG on
    /// the hot path; upstream randomises within the same window.
    presence_tick: u64,
}

impl GeoService {
    pub fn new(device_seed: [u8; 32], nickname: &str) -> Self {
        Self {
            identities: IdentityStore::new(device_seed),
            channels: HashMap::new(),
            nickname: nickname.to_string(),
            presence_tick: 0,
        }
    }

    /// Our long-lived Nostr address, the one a favourite hands out.
    ///
    /// Distinct from the per-geohash identities this service otherwise deals
    /// in: those exist to be unlinkable, this one exists to be findable.
    pub fn main_nostr_pubkey(&mut self) -> String {
        self.identities.main_pubkey_hex()
    }

    /// The same address in the spelling other clients hand out.
    ///
    /// Upstream appends `npub` to a favourite notification, and while its
    /// reader also accepts raw hex, an address is a thing people copy and
    /// compare. Sending the form everything else in the ecosystem prints keeps
    /// ours recognisable as the same key.
    pub fn main_nostr_npub(&mut self) -> String {
        let hex = self.identities.main_pubkey_hex();
        crate::nostr::npub::to_bytes(&hex)
            .and_then(|bytes| crate::nostr::npub::from_bytes(&bytes))
            .unwrap_or(hex)
    }

    /// The secret half of that address, for opening private mail and signing
    /// the seal inside it.
    ///
    /// Handed out rather than used here because this service knows about
    /// location channels and nothing about private messages, and giving it the
    /// envelope format as well would make it the place where both live.
    pub fn main_nostr_keypair(&mut self) -> secp256k1::Keypair {
        self.identities.main_keypair()
    }

    pub fn set_nickname(&mut self, nickname: &str) {
        self.nickname = nickname.to_string();
    }

    /// Membership check kept beside `joined()`; the UI asks for the list.
    #[allow(dead_code)]
    pub fn is_joined(&self, geohash: &str) -> bool {
        self.channels.contains_key(geohash)
    }

    pub fn joined(&self) -> Vec<String> {
        let mut names: Vec<String> = self.channels.keys().cloned().collect();
        names.sort();
        names
    }

    /// Registers a channel and returns the relays to subscribe to, or None if
    /// already joined.
    pub fn join(&mut self, geohash: &str) -> Option<Vec<String>> {
        if self.channels.contains_key(geohash) {
            return None;
        }
        let relays = geohash::closest_relays(geohash, RELAYS_PER_CHANNEL);
        self.channels.insert(
            geohash.to_string(),
            Channel {
                geohash: geohash.to_string(),
                relays: relays.clone(),
                participants: HashMap::new(),
                // Beacon shortly after joining so others see us promptly.
                next_presence: Instant::now(),
            },
        );
        Some(relays)
    }

    pub fn leave(&mut self, geohash: &str) -> bool {
        self.channels.remove(geohash).is_some()
    }

    pub fn relays_for(&self, geohash: &str) -> Vec<String> {
        self.channels
            .get(geohash)
            .map(|channel| channel.relays.clone())
            .unwrap_or_default()
    }

    /// Our identity in this channel. Different in every channel by design.
    pub fn pubkey_for(&mut self, geohash: &str) -> String {
        self.identities.pubkey_hex(geohash)
    }

    /// Builds a signed kind-20000 chat event, mining a NIP-13 nonce first.
    pub fn message_event(&mut self, geohash: &str, content: &str) -> Event {
        let keypair = self.identities.keypair_for(geohash);
        let pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        let created_at = now_seconds();
        let base_tags = geohash_tags(geohash, Some(&self.nickname), false);

        // The nonce commits to the whole serialized event, so mine before
        // signing and sign exactly what was mined.
        let tags = pow::mine(
            &pubkey,
            created_at,
            KIND_EPHEMERAL,
            &base_tags,
            content,
            pow::TARGET_BITS,
        );
        Event::signed(&keypair, created_at, KIND_EPHEMERAL, tags, content.to_string())
    }

    /// Kind-20001 heartbeat: empty content and no nickname tag, per upstream.
    fn presence_event(&mut self, geohash: &str) -> Event {
        let keypair = self.identities.keypair_for(geohash);
        Event::signed(
            &keypair,
            now_seconds(),
            KIND_PRESENCE,
            vec![vec!["g".to_string(), geohash.to_string()]],
            String::new(),
        )
    }

    /// Presence beacons that are due, paired with their channel.
    pub fn due_presence(&mut self) -> Vec<(String, Event)> {
        let now = Instant::now();
        let due: Vec<String> = self
            .channels
            .values()
            .filter(|channel| {
                now >= channel.next_presence
                    && PRESENCE_PRECISIONS.contains(&channel.geohash.chars().count())
            })
            .map(|channel| channel.geohash.clone())
            .collect();

        due.into_iter()
            .map(|geohash| {
                self.presence_tick = self.presence_tick.wrapping_add(1);
                let spread = PRESENCE_MAX.as_secs() - PRESENCE_MIN.as_secs();
                let jitter = Duration::from_secs(self.presence_tick % (spread + 1));
                if let Some(channel) = self.channels.get_mut(&geohash) {
                    channel.next_presence = Instant::now() + PRESENCE_MIN + jitter;
                }
                let event = self.presence_event(&geohash);
                (geohash, event)
            })
            .collect()
    }

    /// Records that a pubkey is active in a channel. Returns the display name.
    pub fn note_activity(
        &mut self,
        geohash: &str,
        pubkey: &str,
        nickname: Option<String>,
    ) -> String {
        let Some(channel) = self.channels.get_mut(geohash) else {
            return nickname.unwrap_or_else(|| short_pubkey(pubkey));
        };

        let participant = channel
            .participants
            .entry(pubkey.to_string())
            .or_insert_with(|| Participant {
                pubkey: pubkey.to_string(),
                nickname: None,
                last_seen: Instant::now(),
            });
        // A chat event carries the nickname; presence beacons never do, so keep
        // the last name we were told.
        if nickname.is_some() {
            participant.nickname = nickname;
        }
        participant.last_seen = Instant::now();
        participant.display_name()
    }

    pub fn participants(&self, geohash: &str) -> Vec<Participant> {
        let mut people: Vec<Participant> = self
            .channels
            .get(geohash)
            .map(|channel| channel.participants.values().cloned().collect())
            .unwrap_or_default();
        people.sort_by_key(|participant| participant.display_name());
        people
    }

    pub fn participant_count(&self, geohash: &str) -> usize {
        self.channels
            .get(geohash)
            .map(|channel| channel.participants.len())
            .unwrap_or(0)
    }

    /// Forgets participants who have gone quiet.
    pub fn prune_participants(&mut self) {
        for channel in self.channels.values_mut() {
            channel
                .participants
                .retain(|_, participant| participant.last_seen.elapsed() < PARTICIPANT_TTL);
        }
    }
}

fn short_pubkey(pubkey: &str) -> String {
    format!("anon{}", &pubkey[..4.min(pubkey.len())])
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Channel names are shown as "#<geohash>" in the UI, matching the phone app.
pub fn channel_name(geohash: &str) -> String {
    format!("#{geohash}")
}

/// Extracts the geohash from a "#<geohash>" channel name.
pub fn geohash_from_channel(channel: &str) -> Option<String> {
    let candidate = geohash::normalize(channel);
    if candidate == "public" || candidate.is_empty() {
        return None;
    }
    geohash::is_valid(&candidate).then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> GeoService {
        GeoService::new([0x33; 32], "tui")
    }

    #[test]
    fn joining_returns_five_relays_and_is_idempotent() {
        let mut geo = service();
        let relays = geo.join("9q8yy").expect("first join subscribes");
        assert_eq!(relays.len(), 5);
        assert!(geo.is_joined("9q8yy"));
        assert!(geo.join("9q8yy").is_none(), "second join is a no-op");
    }

    #[test]
    fn leaving_forgets_the_channel() {
        let mut geo = service();
        geo.join("9q8yy");
        assert!(geo.leave("9q8yy"));
        assert!(!geo.is_joined("9q8yy"));
        assert!(!geo.leave("9q8yy"));
    }

    #[test]
    fn each_channel_uses_a_different_identity() {
        let mut geo = service();
        assert_ne!(geo.pubkey_for("9q8yy"), geo.pubkey_for("dr5r"));
    }

    #[test]
    fn message_events_are_valid_signed_kind_20000() {
        let mut geo = service();
        geo.join("9q8yy");
        let event = geo.message_event("9q8yy", "hello from the terminal");

        assert_eq!(event.kind, KIND_EPHEMERAL);
        assert_eq!(event.geohash(), Some("9q8yy"));
        assert_eq!(event.nickname(), Some("tui"));
        assert_eq!(event.content, "hello from the terminal");
        assert!(event.verify(), "relays reject anything that does not verify");
        assert_eq!(event.pubkey, geo.pubkey_for("9q8yy"));
    }

    #[test]
    fn mined_messages_still_verify() {
        // The PoW nonce is part of the signed tag list; signing must happen
        // after mining or the id no longer matches.
        let mut geo = service();
        let event = geo.message_event("9q8yy", "mined");
        let nonce = event
            .tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("nonce"));
        assert!(nonce.is_some(), "expected a nonce tag");
        assert!(event.verify());
    }

    #[test]
    fn presence_events_carry_no_nickname() {
        let mut geo = service();
        geo.join("9q");
        let event = geo.presence_event("9q");
        assert_eq!(event.kind, KIND_PRESENCE);
        assert_eq!(event.content, "");
        assert_eq!(event.nickname(), None, "presence must not leak a nickname");
        assert_eq!(event.tags, vec![vec!["g".to_string(), "9q".to_string()]]);
        assert!(event.verify());
    }

    #[test]
    fn presence_is_withheld_at_fine_precisions() {
        // Beaconing at building level would broadcast an exact location.
        let mut geo = service();
        geo.join("9q8yyk8n"); // 8 chars: building
        assert!(geo.due_presence().is_empty());

        let mut coarse = service();
        coarse.join("9q8yy"); // 5 chars: city
        assert_eq!(coarse.due_presence().len(), 1);
    }

    #[test]
    fn presence_reschedules_after_firing() {
        let mut geo = service();
        geo.join("9q");
        assert_eq!(geo.due_presence().len(), 1);
        assert!(geo.due_presence().is_empty(), "not due again immediately");
    }

    #[test]
    fn participants_are_tracked_and_named() {
        let mut geo = service();
        geo.join("9q8yy");

        let name = geo.note_activity("9q8yy", &"ab".repeat(32), Some("alice".into()));
        assert_eq!(name, "alice");
        assert_eq!(geo.participant_count("9q8yy"), 1);

        // A presence beacon has no nickname and must not erase the known one.
        let name = geo.note_activity("9q8yy", &"ab".repeat(32), None);
        assert_eq!(name, "alice");
        assert_eq!(geo.participant_count("9q8yy"), 1);

        // Someone we have only seen beaconing gets an anon handle.
        let name = geo.note_activity("9q8yy", &"cd".repeat(32), None);
        assert_eq!(name, "anoncdcd");
        assert_eq!(geo.participants("9q8yy").len(), 2);
    }

    #[test]
    fn activity_in_an_unjoined_channel_is_ignored() {
        let mut geo = service();
        let name = geo.note_activity("9q8yy", &"ef".repeat(32), Some("bob".into()));
        assert_eq!(name, "bob");
        assert_eq!(geo.participant_count("9q8yy"), 0);
    }

    #[test]
    fn channel_names_round_trip() {
        assert_eq!(channel_name("9q8yy"), "#9q8yy");
        assert_eq!(geohash_from_channel("#9q8yy"), Some("9q8yy".to_string()));
        assert_eq!(geohash_from_channel("9Q8YY"), Some("9q8yy".to_string()));
        assert_eq!(geohash_from_channel("#public"), None);
        assert_eq!(geohash_from_channel("#not-a-geohash"), None);
    }
}
