// src/nostr/identity.rs
//
// Per-geohash Nostr identities, ported from NostrIdentityBridge.swift.
//
// Each geohash channel gets its own secp256k1 key derived from one device seed,
// so activity in one location channel cannot be linked to another — and none of
// them link back to the mesh Noise identity.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Derives and caches per-geohash keypairs from a stable device seed.
pub struct IdentityStore {
    device_seed: [u8; 32],
    cache: HashMap<String, Keypair>,
}

/// Label the long-lived identity is derived under. Not a geohash, and chosen
/// so it cannot collide with one: geohashes are base32 and never contain a
/// hyphen.
const MAIN_IDENTITY_LABEL: &str = "bitmancer-main-identity";

impl IdentityStore {
    pub fn new(device_seed: [u8; 32]) -> Self {
        Self {
            device_seed,
            cache: HashMap::new(),
        }
    }

    /// `HMAC-SHA256(seed, utf8(geohash) || u32be(iteration))`, retried until the
    /// output is a valid secp256k1 scalar, with a seed+geohash hash as the last
    /// resort. Same construction as upstream, so the same device would derive
    /// the same channel identity on either client.
    pub fn keypair_for(&mut self, geohash: &str) -> Keypair {
        if let Some(cached) = self.cache.get(geohash) {
            return *cached;
        }

        let keypair = Self::derive(&self.device_seed, geohash);
        self.cache.insert(geohash.to_string(), keypair);
        keypair
    }

    /// The one long-lived Nostr identity, distinct from the per-geohash ones.
    ///
    /// Location-channel identities are deliberately unlinkable from each other.
    /// This one is the opposite: it is the address a favourite hands out so we
    /// can be reached when Bluetooth cannot carry the message, so it has to be
    /// stable across sessions and the same in every channel.
    ///
    /// The derivation label is ours and need not match another client's. A peer
    /// never re-derives this key — it is exchanged explicitly in a favourite
    /// notification — so the only requirement is that it stays the same for the
    /// same device seed.
    /// Only the public half is needed to hand out an address; the secret half
    /// is what will sign internet-carried DMs.
    #[allow(dead_code)]
    pub fn main_keypair(&mut self) -> Keypair {
        self.keypair_for(MAIN_IDENTITY_LABEL)
    }

    pub fn main_pubkey_hex(&mut self) -> String {
        self.pubkey_hex(MAIN_IDENTITY_LABEL)
    }

    fn derive(seed: &[u8; 32], geohash: &str) -> Keypair {
        for iteration in 0u32..10 {
            let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
            mac.update(geohash.as_bytes());
            mac.update(&iteration.to_be_bytes());
            let candidate = mac.finalize().into_bytes();

            if let Ok(secret) = SecretKey::from_byte_array(candidate.into()) {
                return Keypair::from_secret_key(SECP256K1, &secret);
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(geohash.as_bytes());
        let fallback = hasher.finalize();
        let secret = SecretKey::from_byte_array(fallback.into())
            .expect("sha256 of seed+geohash is a valid scalar with overwhelming probability");
        Keypair::from_secret_key(SECP256K1, &secret)
    }

    /// Hex x-only public key used as the Nostr identity in events.
    pub fn pubkey_hex(&mut self, geohash: &str) -> String {
        let keypair = self.keypair_for(geohash);
        hex::encode(keypair.x_only_public_key().0.serialize())
    }

    /// Forgets cached keys; used when the device seed is rotated.
    /// Drops every derived per-geohash identity. Kept for the wipe path to
    /// call once geo identities are held across a session.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x11; 32];

    #[test]
    fn derivation_is_deterministic() {
        let mut a = IdentityStore::new(SEED);
        let mut b = IdentityStore::new(SEED);
        assert_eq!(a.pubkey_hex("9q8yy"), b.pubkey_hex("9q8yy"));
    }

    #[test]
    fn each_geohash_gets_an_unlinkable_key() {
        let mut store = IdentityStore::new(SEED);
        let first = store.pubkey_hex("9q8yy");
        let second = store.pubkey_hex("u4pruy");
        assert_ne!(first, second, "channels must not share an identity");
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn a_different_device_seed_yields_a_different_identity() {
        let mut mine = IdentityStore::new(SEED);
        let mut theirs = IdentityStore::new([0x22; 32]);
        assert_ne!(mine.pubkey_hex("9q8yy"), theirs.pubkey_hex("9q8yy"));
    }

    #[test]
    fn matches_the_upstream_hmac_construction() {
        // Independently recompute HMAC-SHA256(seed, "9q8yy" || 0u32be) and
        // check the store derived its key from exactly those bytes.
        let mut mac = HmacSha256::new_from_slice(&SEED).unwrap();
        mac.update(b"9q8yy");
        mac.update(&0u32.to_be_bytes());
        let expected_secret = mac.finalize().into_bytes();

        let secret = SecretKey::from_byte_array(expected_secret.into()).expect("valid scalar for this seed");
        let expected = Keypair::from_secret_key(SECP256K1, &secret);

        let mut store = IdentityStore::new(SEED);
        assert_eq!(
            store.pubkey_hex("9q8yy"),
            hex::encode(expected.x_only_public_key().0.serialize())
        );
    }

    #[test]
    fn caching_returns_the_same_key() {
        let mut store = IdentityStore::new(SEED);
        let first = store.keypair_for("9q8yy");
        let second = store.keypair_for("9q8yy");
        assert_eq!(first.secret_bytes(), second.secret_bytes());
        store.clear();
        assert_eq!(store.keypair_for("9q8yy").secret_bytes(), first.secret_bytes());
    }
}

#[cfg(test)]
mod main_identity_tests {
    use super::*;

    #[test]
    fn the_main_identity_is_stable_for_a_seed() {
        // A favourite hands this out as our address; if it moved between
        // sessions every peer's stored copy would go stale.
        let mut first = IdentityStore::new([7; 32]);
        let mut second = IdentityStore::new([7; 32]);
        assert_eq!(first.main_pubkey_hex(), second.main_pubkey_hex());
    }

    #[test]
    fn a_different_seed_is_a_different_identity() {
        let mut a = IdentityStore::new([7; 32]);
        let mut b = IdentityStore::new([8; 32]);
        assert_ne!(a.main_pubkey_hex(), b.main_pubkey_hex());
    }

    #[test]
    fn the_main_identity_is_not_any_channel_identity() {
        // Location-channel identities exist to be unlinkable. If the main one
        // collided with a cell's, joining that cell would publish the address
        // our favourites know us by.
        let mut store = IdentityStore::new([7; 32]);
        let main = store.main_pubkey_hex();
        for cell in ["9q", "u4pruy", "gbsuv", "bitmancer", "main"] {
            assert_ne!(store.pubkey_hex(cell), main, "collided with {cell}");
        }
    }
}
