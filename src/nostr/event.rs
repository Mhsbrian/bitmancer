// src/nostr/event.rs
//
// NIP-01 events. Ported from bitchat/Nostr/NostrProtocol.swift.
//
// The event id is sha256 over the canonical JSON array
//   [0, pubkey, created_at, kind, tags, content]
// serialized with slashes left unescaped, and the signature is BIP-340 Schnorr
// over that 32-byte hash. Both sides of a geohash channel must agree on this
// byte for byte or every event is rejected as forged.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Geohash public chat.
pub const KIND_EPHEMERAL: u32 = 20000;
/// Geohash presence heartbeat: empty content, no nickname tag.
pub const KIND_PRESENCE: u32 = 20001;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Canonical serialization the id is computed over.
    pub fn serialize_for_id(
        pubkey: &str,
        created_at: i64,
        kind: u32,
        tags: &[Vec<String>],
        content: &str,
    ) -> String {
        // serde_json does not escape forward slashes, matching Swift's
        // .withoutEscapingSlashes, and escapes control characters the same way.
        let value = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
        value.to_string()
    }

    pub fn compute_id(
        pubkey: &str,
        created_at: i64,
        kind: u32,
        tags: &[Vec<String>],
        content: &str,
    ) -> [u8; 32] {
        let serialized = Self::serialize_for_id(pubkey, created_at, kind, tags, content);
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hasher.finalize().into()
    }

    /// Builds and signs an event with the given keypair.
    pub fn signed(
        keypair: &Keypair,
        created_at: i64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Event {
        let (xonly, _parity) = keypair.x_only_public_key();
        let pubkey = hex::encode(xonly.serialize());
        let id = Self::compute_id(&pubkey, created_at, kind, &tags, &content);
        let signature = SECP256K1.sign_schnorr(&id, keypair);

        Event {
            id: hex::encode(id),
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(signature.serialize()),
        }
    }

    /// Recomputes the id and checks the Schnorr signature. Relays are
    /// untrusted, so nothing inbound is displayed without passing this.
    pub fn verify(&self) -> bool {
        let expected_id = Self::compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if hex::encode(expected_id) != self.id {
            return false;
        }
        let (Ok(pubkey_bytes), Ok(sig_bytes)) = (hex::decode(&self.pubkey), hex::decode(&self.sig))
        else {
            return false;
        };
        let (Ok(pubkey), Ok(signature)) = (
            XOnlyPublicKey::from_slice(&pubkey_bytes),
            Signature::from_slice(&sig_bytes),
        ) else {
            return false;
        };
        SECP256K1
            .verify_schnorr(&signature, &expected_id, &pubkey)
            .is_ok()
    }

    /// First value of the first tag with this name.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some(name))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }

    pub fn geohash(&self) -> Option<&str> {
        self.tag_value("g")
    }

    pub fn nickname(&self) -> Option<&str> {
        self.tag_value("n")
    }

    pub fn is_teleported(&self) -> bool {
        self.tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("t") && tag.get(1).map(String::as_str) == Some("teleport"))
    }
}

/// Tags for a kind-20000 geohash message (NostrProtocol.ephemeralGeohashTags).
pub fn geohash_tags(geohash: &str, nickname: Option<&str>, teleported: bool) -> Vec<Vec<String>> {
    let mut tags = vec![vec!["g".to_string(), geohash.to_string()]];
    if let Some(nickname) = nickname.map(str::trim).filter(|n| !n.is_empty()) {
        tags.push(vec!["n".to_string(), nickname.to_string()]);
    }
    if teleported {
        tags.push(vec!["t".to_string(), "teleport".to_string()]);
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_slice(&[seed.max(1); 32]).unwrap();
        Keypair::from_secret_key(SECP256K1, &secret)
    }

    #[test]
    fn canonical_serialization_matches_nip01() {
        let serialized = Event::serialize_for_id(
            "abc123",
            1700000000,
            20000,
            &[vec!["g".into(), "9q8yy".into()]],
            "hello",
        );
        assert_eq!(
            serialized,
            r#"[0,"abc123",1700000000,20000,[["g","9q8yy"]],"hello"]"#
        );
    }

    #[test]
    fn slashes_are_not_escaped() {
        // Swift uses .withoutEscapingSlashes; a URL in the content must not
        // become \/ or the id will not match other clients'.
        let serialized =
            Event::serialize_for_id("abc", 1, 20000, &[], "see https://example.com/x");
        assert!(serialized.contains("https://example.com/x"), "{serialized}");
        assert!(!serialized.contains("\\/"));
    }

    #[test]
    fn control_characters_and_unicode_survive_round_trip() {
        let content = "line1\nline2\t\"quoted\" — emoji 🛰";
        let event = Event::signed(&keypair(7), 1700000000, KIND_EPHEMERAL, vec![], content.into());
        assert!(event.verify());
        let json = serde_json::to_string(&event).unwrap();
        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.content, content);
        assert!(parsed.verify(), "must still verify after a JSON round trip");
    }

    #[test]
    fn signed_events_verify() {
        let event = Event::signed(
            &keypair(3),
            1700000000,
            KIND_EPHEMERAL,
            geohash_tags("9q8yy", Some("tui"), false),
            "hello mesh".into(),
        );
        assert_eq!(event.id.len(), 64);
        assert_eq!(event.sig.len(), 128);
        assert_eq!(event.pubkey.len(), 64, "x-only pubkey is 32 bytes");
        assert!(event.verify());
    }

    #[test]
    fn tampering_breaks_verification() {
        let base = Event::signed(&keypair(4), 1700000000, KIND_EPHEMERAL, vec![], "real".into());

        let mut edited_content = base.clone();
        edited_content.content = "forged".into();
        assert!(!edited_content.verify(), "content change must fail");

        let mut edited_id = base.clone();
        edited_id.id = hex::encode([0u8; 32]);
        assert!(!edited_id.verify(), "id must be recomputed, not trusted");

        let mut edited_sig = base.clone();
        edited_sig.sig = hex::encode([0u8; 64]);
        assert!(!edited_sig.verify());

        // An event whose id matches its contents but was signed by someone else.
        let other = Event::signed(&keypair(5), 1700000000, KIND_EPHEMERAL, vec![], "real".into());
        let mut swapped = base.clone();
        swapped.sig = other.sig;
        assert!(!swapped.verify(), "signature must bind to the pubkey");
    }

    #[test]
    fn rejects_malformed_hex_without_panicking() {
        let mut event = Event::signed(&keypair(6), 1, KIND_EPHEMERAL, vec![], "x".into());
        event.pubkey = "nothex".into();
        assert!(!event.verify());
    }

    #[test]
    fn geohash_tags_match_upstream_shape() {
        assert_eq!(geohash_tags("9q8yy", None, false), vec![vec!["g", "9q8yy"]]);
        assert_eq!(
            geohash_tags("9q8yy", Some("tui"), true),
            vec![
                vec!["g", "9q8yy"],
                vec!["n", "tui"],
                vec!["t", "teleport"],
            ]
        );
        // Blank nicknames are dropped, like trimmedOrNilIfEmpty.
        assert_eq!(geohash_tags("9q8yy", Some("   "), false), vec![vec!["g", "9q8yy"]]);
    }

    #[test]
    fn accessors_read_tags() {
        let event = Event::signed(
            &keypair(8),
            1,
            KIND_EPHEMERAL,
            geohash_tags("u4pruy", Some("bob"), true),
            "hi".into(),
        );
        assert_eq!(event.geohash(), Some("u4pruy"));
        assert_eq!(event.nickname(), Some("bob"));
        assert!(event.is_teleported());
    }
}
