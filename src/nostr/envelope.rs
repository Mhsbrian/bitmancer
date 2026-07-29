// src/nostr/envelope.rs
//
// The sealed envelope a private message travels in over relays.
//
// This looks like NIP-17 and is not NIP-17. Upstream says so in as many words:
// the construction "is deliberately BitChat-specific and is not NIP-17, NIP-44,
// or NIP-59 compatible, even though it historically reuses those NIPs' kind
// numbers (1059/13/14) and a `v2:` content prefix." Implementing the standard
// here would produce something no BitChat client can open, so every parameter
// below is taken from upstream's `NostrProtocol.swift` rather than from a spec.
//
// Three layers, outermost last:
//
//   rumor     kind 14, unsigned      the message itself
//   seal      kind 13, signed        rumor encrypted to the recipient, signed
//                                    with the sender's real key so the reader
//                                    can tell who wrote it
//   gift wrap kind 1059, signed      seal encrypted under a throwaway key, so
//                                    relays never learn the sender
//
// The cipher is XChaCha20-Poly1305 over `v2:` + base64url(nonce24 ‖ ct ‖ tag).
// The key is HKDF-SHA256 of the ECDH shared secret with an empty salt and the
// info string "nip44-v2" — which is borrowed wording, not borrowed behaviour.
//
// One detail is easy to get wrong and silently fatal: the ECDH input is the
// *compressed point*, 33 bytes of parity prefix and x, not the SHA-256 of it
// that libsecp256k1 hands back by default. Get that wrong and everything still
// encrypts, produces plausible base64, and cannot be read by anybody.

// Nothing calls this yet. The cryptography landed first and on its own, so it
// could be checked against a real envelope from another implementation before
// anything was built on top of it — a sealing layer that is subtly wrong is
// indistinguishable from a correct one until a stranger tries to read it.
#![allow(dead_code)]

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

/// Ceiling on either encrypted layer before it is decoded.
///
/// Real envelopes run to a few KiB. Without a bound, an addressed relay event
/// drives whatever allocation it likes.
pub const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;

const CONTENT_PREFIX: &str = "v2:";
const HKDF_INFO: &[u8] = b"nip44-v2";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    BadKey,
    BadFraming,
    TooLarge,
    Undecryptable,
    /// Structurally an envelope, but nothing proves who sent it.
    Unauthenticated,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadKey => "malformed key",
            Self::BadFraming => "not a v2 envelope",
            Self::TooLarge => "envelope larger than we will decode",
            Self::Undecryptable => "could not decrypt",
            Self::Unauthenticated => "envelope is not authenticated",
        })
    }
}

/// The two shared secrets this protocol could mean.
///
/// The secret is the 33-byte compressed point, not the SHA-256 of it that
/// libsecp256k1 returns by default. Because the point's parity byte is part of
/// the key material, and a Nostr key is x-only, the result depends on a bit
/// that was never transmitted: the sender used their own secret as stored,
/// whose parity the receiver cannot recover from an x-only public key.
///
/// So there are two candidates and the receiver has to try both. This is not a
/// workaround for a bug of ours — it is a property of pairing a
/// parity-sensitive key derivation with parity-free identities, and the
/// upstream fixture demonstrates both cases occurring in real traffic: its
/// gift-wrap layer wants one and its seal layer the other. NIP-44 sidesteps
/// this by hashing only the x coordinate; this construction does not.
fn shared_secrets(secret: &SecretKey, public: &XOnlyPublicKey) -> [[u8; 33]; 2] {
    [secp256k1::Parity::Even, secp256k1::Parity::Odd].map(|parity| {
        let full = PublicKey::from_x_only_public_key(*public, parity);
        let point = secp256k1::ecdh::shared_secret_point(&full, secret);
        let mut compressed = [0u8; 33];
        compressed[0] = if point[63] & 1 == 0 { 0x02 } else { 0x03 };
        compressed[1..].copy_from_slice(&point[..32]);
        compressed
    })
}

/// The secret to seal with.
///
/// Sealing has to pick one, and picks the same one upstream does: the secret
/// exactly as stored, with the peer's key lifted to even. A reader who lands on
/// the other candidate will find it on their second attempt.
fn sealing_secret(secret: &SecretKey, public: &XOnlyPublicKey) -> [u8; 33] {
    shared_secrets(secret, public)[0]
}

fn symmetric_key(shared: &[u8; 33]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    // Length is fixed and the algorithm is fixed, so this cannot fail.
    hkdf.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Seals plaintext to a recipient, returning the `v2:` content string.
pub fn encrypt(
    plaintext: &str,
    recipient: &XOnlyPublicKey,
    sender_secret: &SecretKey,
    nonce24: [u8; NONCE_BYTES],
) -> Result<String, EnvelopeError> {
    let key = symmetric_key(&sealing_secret(sender_secret, recipient));
    let cipher = XChaCha20Poly1305::new((&key).into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce24),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &[],
            },
        )
        .map_err(|_| EnvelopeError::Undecryptable)?;

    let mut combined = Vec::with_capacity(NONCE_BYTES + sealed.len());
    combined.extend_from_slice(&nonce24);
    combined.extend_from_slice(&sealed);
    Ok(format!(
        "{CONTENT_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined)
    ))
}

/// Opens a `v2:` content string addressed to us.
pub fn decrypt(
    content: &str,
    recipient_secret: &SecretKey,
    sender: &XOnlyPublicKey,
) -> Result<String, EnvelopeError> {
    // Bound the work before decoding, not after: the point is to refuse a
    // hostile allocation, and by then it has already happened.
    if content.len() > MAX_CIPHERTEXT_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    let body = content
        .strip_prefix(CONTENT_PREFIX)
        .ok_or(EnvelopeError::BadFraming)?;
    let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| EnvelopeError::BadFraming)?;
    if combined.len() < NONCE_BYTES + TAG_BYTES {
        return Err(EnvelopeError::BadFraming);
    }

    let (nonce24, sealed) = combined.split_at(NONCE_BYTES);
    // Both candidates, because the sender's parity is not on the wire. The
    // authentication tag decides which one was meant: a wrong key fails to
    // authenticate rather than producing plausible plaintext, so this cannot
    // pick the wrong one, only spend one extra AEAD when the first misses.
    for shared in shared_secrets(recipient_secret, sender) {
        let key = symmetric_key(&shared);
        let cipher = XChaCha20Poly1305::new((&key).into());
        if let Ok(plaintext) = cipher.decrypt(
            XNonce::from_slice(nonce24),
            Payload {
                msg: sealed,
                aad: &[],
            },
        ) {
            return String::from_utf8(plaintext).map_err(|_| EnvelopeError::Undecryptable);
        }
    }
    Err(EnvelopeError::Undecryptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};

    /// Deterministic keys: a test that fails only on some runs is worse than
    /// no test, and nothing here needs entropy.
    fn keypair(seed: u8) -> Keypair {
        Keypair::from_secret_key(SECP256K1, &secret_from(seed))
    }

    fn secret_from(seed: u8) -> SecretKey {
        let mut bytes = [seed.max(1); 32];
        bytes[31] = seed.max(1);
        SecretKey::from_byte_array(bytes).unwrap()
    }

    /// A real envelope produced by BitChat release 733098bb, carried over from
    /// upstream's own fixtures. Decrypting it proves this implementation talks
    /// to *another* implementation — self-consistency would prove nothing,
    /// since two wrong implementations agree with each other perfectly.
    const FIXTURE: &str = include_str!("../../tests/fixtures/legacy_private_envelope.json");
    const RECIPIENT_SECRET: &str =
        "8355a5c110cdfef2e644f4ad5d51c39f253b2c2c80ebb6856379fb16531dc1fa";
    /// The gift wrap's throwaway key, which is what the outer layer is sealed
    /// to us from.
    const WRAPPER_PUBKEY: &str =
        "960e391e314a7fb00bbdd85eccb0a93c17e981b6fed38487cf891f1ed6b66aeb";

    fn fixture_content() -> String {
        let value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        value["content"].as_str().unwrap().to_string()
    }

    fn secret(hex_str: &str) -> SecretKey {
        SecretKey::from_byte_array(
            <[u8; 32]>::try_from(hex::decode(hex_str).unwrap().as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn xonly(hex_str: &str) -> XOnlyPublicKey {
        XOnlyPublicKey::from_byte_array(
            <[u8; 32]>::try_from(hex::decode(hex_str).unwrap().as_slice()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_outer_layer_of_a_real_envelope_opens() {
        // The decisive test for the whole module. If the ECDH point format,
        // the HKDF parameters, the cipher or the framing are wrong in any
        // detail, this fails and everything built on top would have been
        // talking to nobody.
        let opened = decrypt(
            &fixture_content(),
            &secret(RECIPIENT_SECRET),
            &xonly(WRAPPER_PUBKEY),
        );
        assert!(
            opened.is_ok(),
            "a real BitChat envelope must open: {:?}",
            opened.err()
        );
        // The gift wrap contains the seal, which is itself a Nostr event.
        let inner = opened.unwrap();
        assert!(
            inner.contains("\"kind\":13") || inner.contains("\"kind\": 13"),
            "the wrap should hold a kind-13 seal, got: {}",
            inner.chars().take(120).collect::<String>()
        );
    }

    #[test]
    fn what_we_seal_we_can_open() {
        let sender = keypair(11);
        let recipient = keypair(12);

        let sealed = encrypt(
            "meet at the docks",
            &recipient.x_only_public_key().0,
            &sender.secret_key(),
            [7u8; NONCE_BYTES],
        )
        .unwrap();
        assert!(sealed.starts_with(CONTENT_PREFIX));

        let opened = decrypt(
            &sealed,
            &recipient.secret_key(),
            &sender.x_only_public_key().0,
        )
        .unwrap();
        assert_eq!(opened, "meet at the docks");
    }

    #[test]
    fn the_secret_a_sender_used_is_always_one_of_the_two_a_reader_tries() {
        // The reader cannot know which, so the guarantee that matters is that
        // the sealing choice is always among the candidates.
        let a = keypair(13);
        let b = keypair(14);
        let sealed_with = sealing_secret(&a.secret_key(), &b.x_only_public_key().0);
        let candidates = shared_secrets(&b.secret_key(), &a.x_only_public_key().0);
        assert!(
            candidates.contains(&sealed_with),
            "a reader would never find the key this was sealed with"
        );
    }

    #[test]
    fn a_stranger_cannot_open_it() {
        let sender = keypair(15);
        let recipient = keypair(16);
        let stranger = keypair(17);

        let sealed = encrypt(
            "private",
            &recipient.x_only_public_key().0,
            &sender.secret_key(),
            [9u8; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(
            decrypt(&sealed, &stranger.secret_key(), &sender.x_only_public_key().0),
            Err(EnvelopeError::Undecryptable)
        );
    }

    #[test]
    fn a_tampered_envelope_is_refused_rather_than_half_read() {
        // Poly1305 is what makes this an authenticated envelope; a flipped bit
        // must fail, not decrypt to something else.
        let sender = keypair(18);
        let recipient = keypair(19);
        let sealed = encrypt(
            "original",
            &recipient.x_only_public_key().0,
            &sender.secret_key(),
            [3u8; NONCE_BYTES],
        )
        .unwrap();

        let body = sealed.strip_prefix(CONTENT_PREFIX).unwrap();
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!(
            "{CONTENT_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw)
        );

        assert_eq!(
            decrypt(&tampered, &recipient.secret_key(), &sender.x_only_public_key().0),
            Err(EnvelopeError::Undecryptable)
        );
    }

    #[test]
    fn framing_is_checked_before_anything_else() {
        let recipient = keypair(20);
        let sender = keypair(21);
        let sender_pub = sender.x_only_public_key().0;

        for (label, content, expected) in [
            ("no prefix", "AAAA".to_string(), EnvelopeError::BadFraming),
            ("not base64", "v2:!!!!".to_string(), EnvelopeError::BadFraming),
            ("too short", format!("{CONTENT_PREFIX}AAAA"), EnvelopeError::BadFraming),
            (
                "oversized",
                format!("{CONTENT_PREFIX}{}", "A".repeat(MAX_CIPHERTEXT_BYTES)),
                EnvelopeError::TooLarge,
            ),
        ] {
            assert_eq!(
                decrypt(&content, &recipient.secret_key(), &sender_pub),
                Err(expected),
                "{label}"
            );
        }
    }

    #[test]
    fn a_fresh_nonce_changes_the_ciphertext() {
        // Nonce reuse under one key breaks XChaCha20-Poly1305 outright, so the
        // nonce is a parameter here only to keep the tests deterministic - the
        // caller must draw it randomly.
        let sender = keypair(22);
        let recipient = keypair(23);
        let to = recipient.x_only_public_key().0;
        let first = encrypt("same text", &to, &sender.secret_key(), [1u8; NONCE_BYTES]).unwrap();
        let second = encrypt("same text", &to, &sender.secret_key(), [2u8; NONCE_BYTES]).unwrap();
        assert_ne!(first, second);
    }
}

#[cfg(test)]
mod real_envelope {
    use super::tests_support::*;

    /// Upstream's own expectations for this fixture.
    const EXPECTED_PLAINTEXT: &str = "legacy fixture from 733098bb";
    const EXPECTED_SENDER: &str =
        "2e3d79df7047204f02b726c574e256f8de1dd80510f7dcb8b0d12df13acb87e6";

    #[test]
    fn both_layers_of_a_real_envelope_open_to_the_expected_message() {
        // End to end against traffic produced by a different implementation.
        // The two layers of this very fixture disagree about key parity, which
        // is exactly why the reader tries both — a single-candidate reader
        // opens the wrap and then fails on the seal.
        let seal_json = open_wrap();
        let seal: serde_json::Value = serde_json::from_str(&seal_json).unwrap();
        assert_eq!(seal["kind"], 13, "the wrap must hold a seal");
        assert_eq!(
            seal["tags"].as_array().unwrap().len(),
            0,
            "a BitChat seal is tagless, and the reader binds to that shape"
        );
        assert_eq!(seal["pubkey"], EXPECTED_SENDER);

        let rumor_json = open_seal(&seal_json);
        let rumor: serde_json::Value = serde_json::from_str(&rumor_json).unwrap();
        assert_eq!(rumor["kind"], 14, "the seal must hold a rumor");
        assert_eq!(rumor["content"], EXPECTED_PLAINTEXT);
        assert_eq!(
            rumor["pubkey"], EXPECTED_SENDER,
            "the rumor's claimed author must be the key that signed the seal"
        );
        assert!(
            rumor.get("sig").is_none() || rumor["sig"].is_null(),
            "the rumor is unsigned; authentication comes from the seal"
        );
    }
}

#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub const FIXTURE: &str = include_str!("../../tests/fixtures/legacy_private_envelope.json");
    const RECIPIENT_SECRET: &str =
        "8355a5c110cdfef2e644f4ad5d51c39f253b2c2c80ebb6856379fb16531dc1fa";

    pub fn recipient() -> SecretKey {
        SecretKey::from_byte_array(
            <[u8; 32]>::try_from(hex::decode(RECIPIENT_SECRET).unwrap().as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn xonly_of(hex_str: &str) -> XOnlyPublicKey {
        XOnlyPublicKey::from_byte_array(
            <[u8; 32]>::try_from(hex::decode(hex_str).unwrap().as_slice()).unwrap(),
        )
        .unwrap()
    }

    pub fn open_wrap() -> String {
        let wrap: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        decrypt(
            wrap["content"].as_str().unwrap(),
            &recipient(),
            &xonly_of(wrap["pubkey"].as_str().unwrap()),
        )
        .unwrap()
    }

    pub fn open_seal(seal_json: &str) -> String {
        let seal: serde_json::Value = serde_json::from_str(seal_json).unwrap();
        decrypt(
            seal["content"].as_str().unwrap(),
            &recipient(),
            &xonly_of(seal["pubkey"].as_str().unwrap()),
        )
        .unwrap()
    }
}

// MARK: - Layers

use crate::nostr::event::Event;
use serde::{Deserialize, Serialize};

pub const KIND_RUMOR: u32 = 14;
pub const KIND_SEAL: u32 = 13;
pub const KIND_GIFT_WRAP: u32 = 1059;

/// How far a published timestamp is moved from the truth.
///
/// The outer layers are visible to relays, so their timestamps are jittered by
/// up to a quarter hour either way; the real send time rides inside the
/// encrypted rumor, where only the recipient can read it. Without this, two
/// relays comparing arrival times can correlate a conversation they cannot
/// decrypt.
pub const TIMESTAMP_JITTER_SECS: i64 = 900;

/// A timestamp fit to publish: the real one, displaced by up to a quarter hour.
///
/// Takes the displacement rather than drawing it, so the jitter is testable and
/// the caller owns the randomness. Any input maps into the window, because a
/// caller passing an unbounded random number should get a valid timestamp
/// rather than one a relay will reject as far-future.
pub fn published_timestamp(now: i64, jitter: i64) -> i64 {
    let span = 2 * TIMESTAMP_JITTER_SECS + 1;
    now + jitter.rem_euclid(span) - TIMESTAMP_JITTER_SECS
}

/// The innermost layer: the message, unsigned.
///
/// The shape is taken from a real envelope rather than from the struct that
/// produces it, because two fields are surprising. `id` is present and *empty*
/// rather than omitted, and `sig` is absent entirely rather than null — a
/// reader that insists on a signature here rejects every genuine message, and
/// one that emits `"sig": null` is sending a document upstream did not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rumor {
    pub kind: u32,
    pub created_at: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub pubkey: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// A private message, opened and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub content: String,
    /// The key that signed the seal — not the one the rumor claims. They are
    /// checked to match, and this is the one that was actually proved.
    pub sender: String,
    /// Send time from inside the envelope, not the jittered outer one.
    pub created_at: i64,
}

/// Builds the gift wrap that carries `content` to `recipient`.
///
/// `ephemeral` is passed in rather than generated here so a caller can be
/// deterministic; in use it must be a fresh key per message, since reusing one
/// links every message sealed under it.
pub fn seal_message(
    content: &str,
    recipient: &XOnlyPublicKey,
    sender: &secp256k1::Keypair,
    ephemeral: &secp256k1::Keypair,
    sent_at: i64,
    published_at: i64,
    nonces: [[u8; NONCE_BYTES]; 2],
) -> Result<Event, EnvelopeError> {
    let sender_pubkey = hex::encode(sender.x_only_public_key().0.serialize());

    let rumor = Rumor {
        kind: KIND_RUMOR,
        created_at: sent_at,
        tags: Vec::new(),
        content: content.to_string(),
        pubkey: sender_pubkey,
        id: String::new(),
        sig: None,
    };
    let rumor_json = serde_json::to_string(&rumor).map_err(|_| EnvelopeError::BadFraming)?;

    // The seal is signed with the sender's real key: that signature is the only
    // thing that makes the sender name mean anything, since the wrap outside it
    // is signed by a throwaway.
    let seal = Event::signed(
        sender,
        published_at,
        KIND_SEAL,
        Vec::new(),
        encrypt(&rumor_json, recipient, &sender.secret_key(), nonces[0])?,
    );
    let seal_json = serde_json::to_string(&seal).map_err(|_| EnvelopeError::BadFraming)?;

    Ok(Event::signed(
        ephemeral,
        published_at,
        KIND_GIFT_WRAP,
        vec![vec!["p".to_string(), hex::encode(recipient.serialize())]],
        encrypt(&seal_json, recipient, &ephemeral.secret_key(), nonces[1])?,
    ))
}

/// Opens a gift wrap addressed to us, or explains why it is not one.
///
/// Every check here is load-bearing. Without the seal's signature a private
/// message is forgeable by anyone who knows the recipient's public key, and
/// without binding the rumor's claimed author to the seal's signer the sender
/// name is decoration.
pub fn open_message(
    wrap: &Event,
    our_secret: &SecretKey,
    our_pubkey: &XOnlyPublicKey,
) -> Result<Opened, EnvelopeError> {
    let ours = hex::encode(our_pubkey.serialize());
    if wrap.kind != KIND_GIFT_WRAP
        || wrap.tags != vec![vec!["p".to_string(), ours.clone()]]
        || !wrap.verify()
    {
        return Err(EnvelopeError::BadFraming);
    }

    let seal: Event = serde_json::from_str(&decrypt(
        &wrap.content,
        our_secret,
        &parse_xonly(&wrap.pubkey)?,
    )?)
    .map_err(|_| EnvelopeError::BadFraming)?;

    // A BitChat seal is tagless. Binding to that exact shape leaves nothing for
    // a forger to smuggle in beside the signature.
    if seal.kind != KIND_SEAL || !seal.tags.is_empty() || !seal.verify() {
        return Err(EnvelopeError::Unauthenticated);
    }

    let rumor: Rumor = serde_json::from_str(&decrypt(
        &seal.content,
        our_secret,
        &parse_xonly(&seal.pubkey)?,
    )?)
    .map_err(|_| EnvelopeError::BadFraming)?;

    if rumor.kind != KIND_RUMOR || rumor.sig.is_some() || rumor.pubkey != seal.pubkey {
        return Err(EnvelopeError::Unauthenticated);
    }
    // Released iOS envelopes carry no inner tags; current Android ones carry
    // exactly the recipient's own `p` tag. Anything else — another recipient,
    // duplicates, extras — is not a shape any client emits.
    let inner_tags_ok =
        rumor.tags.is_empty() || rumor.tags == vec![vec!["p".to_string(), ours]];
    if !inner_tags_ok {
        return Err(EnvelopeError::Unauthenticated);
    }

    Ok(Opened {
        content: rumor.content,
        sender: seal.pubkey,
        created_at: rumor.created_at,
    })
}

fn parse_xonly(hex_str: &str) -> Result<XOnlyPublicKey, EnvelopeError> {
    let bytes = hex::decode(hex_str).map_err(|_| EnvelopeError::BadKey)?;
    let array = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| EnvelopeError::BadKey)?;
    XOnlyPublicKey::from_byte_array(array).map_err(|_| EnvelopeError::BadKey)
}

#[cfg(test)]
mod layer_tests {
    use super::tests_support::*;
    use super::*;
    use secp256k1::{Keypair, SECP256K1};

    fn key(seed: u8) -> Keypair {
        let mut bytes = [seed.max(1); 32];
        bytes[31] = seed.max(1);
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(bytes).unwrap())
    }

    fn sealed_to(recipient: &Keypair, sender: &Keypair, content: &str) -> Event {
        seal_message(
            content,
            &recipient.x_only_public_key().0,
            sender,
            &key(99),
            1_700_000_000,
            1_700_000_500,
            [[5u8; NONCE_BYTES], [6u8; NONCE_BYTES]],
        )
        .unwrap()
    }

    #[test]
    fn a_real_envelope_opens_through_the_full_stack() {
        // The whole point: this was produced by another implementation, so
        // every layer, check and key decision has to match theirs.
        let wrap: Event = serde_json::from_str(FIXTURE).unwrap();
        let opened = open_message(
            &wrap,
            &recipient(),
            &recipient().x_only_public_key(SECP256K1).0,
        )
        .expect("a genuine envelope must open");

        assert_eq!(opened.content, "legacy fixture from 733098bb");
        assert_eq!(
            opened.sender,
            "2e3d79df7047204f02b726c574e256f8de1dd80510f7dcb8b0d12df13acb87e6"
        );
    }

    #[test]
    fn what_we_seal_another_reader_opens() {
        let sender = key(21);
        let recipient = key(22);
        let wrap = sealed_to(&recipient, &sender, "meet at the docks");

        assert_eq!(wrap.kind, KIND_GIFT_WRAP);
        assert!(wrap.verify(), "the wrap must be signed by its throwaway key");
        assert_eq!(
            wrap.tags,
            vec![vec![
                "p".to_string(),
                hex::encode(recipient.x_only_public_key().0.serialize())
            ]]
        );

        let opened = open_message(
            &wrap,
            &recipient.secret_key(),
            &recipient.x_only_public_key().0,
        )
        .unwrap();
        assert_eq!(opened.content, "meet at the docks");
        assert_eq!(
            opened.sender,
            hex::encode(sender.x_only_public_key().0.serialize())
        );
        assert_eq!(opened.created_at, 1_700_000_000, "the true send time");
    }

    #[test]
    fn the_outer_layers_never_carry_the_sender_or_the_real_time() {
        // What a relay can see must not identify the conversation.
        let sender = key(23);
        let recipient = key(24);
        let wrap = sealed_to(&recipient, &sender, "private");

        let sender_hex = hex::encode(sender.x_only_public_key().0.serialize());
        assert_ne!(wrap.pubkey, sender_hex, "the wrap is signed by a throwaway");
        assert!(
            !serde_json::to_string(&wrap).unwrap().contains(&sender_hex),
            "the sender must not appear anywhere a relay can read"
        );
        assert_ne!(
            wrap.created_at, 1_700_000_000,
            "the published time is jittered, not the send time"
        );
    }

    #[test]
    fn an_envelope_addressed_to_someone_else_is_refused() {
        let wrap = sealed_to(&key(26), &key(25), "not for you");
        let bystander = key(27);
        assert_eq!(
            open_message(
                &wrap,
                &bystander.secret_key(),
                &bystander.x_only_public_key().0
            ),
            Err(EnvelopeError::BadFraming)
        );
    }

    #[test]
    fn a_seal_signed_by_the_wrong_key_is_rejected() {
        // The forgery this check exists for: anyone knowing the recipient's
        // public key can build a well-formed wrap. Only the seal's signature
        // says who wrote what is inside.
        let recipient = key(31);
        let impostor = key(32);
        let claimed = key(33);

        // A seal that claims `claimed` but is signed by `impostor`.
        let rumor = Rumor {
            kind: KIND_RUMOR,
            created_at: 1_700_000_000,
            tags: Vec::new(),
            content: "transfer the funds".to_string(),
            pubkey: hex::encode(claimed.x_only_public_key().0.serialize()),
            id: String::new(),
            sig: None,
        };
        let sealed = Event::signed(
            &impostor,
            1_700_000_500,
            KIND_SEAL,
            Vec::new(),
            encrypt(
                &serde_json::to_string(&rumor).unwrap(),
                &recipient.x_only_public_key().0,
                &impostor.secret_key(),
                [1u8; NONCE_BYTES],
            )
            .unwrap(),
        );
        let ephemeral = key(34);
        let wrap = Event::signed(
            &ephemeral,
            1_700_000_500,
            KIND_GIFT_WRAP,
            vec![vec![
                "p".to_string(),
                hex::encode(recipient.x_only_public_key().0.serialize()),
            ]],
            encrypt(
                &serde_json::to_string(&sealed).unwrap(),
                &recipient.x_only_public_key().0,
                &ephemeral.secret_key(),
                [2u8; NONCE_BYTES],
            )
            .unwrap(),
        );

        assert_eq!(
            open_message(
                &wrap,
                &recipient.secret_key(),
                &recipient.x_only_public_key().0
            ),
            Err(EnvelopeError::Unauthenticated),
            "a rumor claiming an author the seal's signer is not must be refused"
        );
    }

    #[test]
    fn a_signed_rumor_is_refused() {
        // The rumor is unsigned by design; a signature there would be an
        // unchecked second opinion about authorship.
        let recipient = key(41);
        let sender = key(42);
        let mut rumor = Rumor {
            kind: KIND_RUMOR,
            created_at: 1_700_000_000,
            tags: Vec::new(),
            content: "hello".to_string(),
            pubkey: hex::encode(sender.x_only_public_key().0.serialize()),
            id: String::new(),
            sig: None,
        };
        rumor.sig = Some("00".repeat(64));

        let sealed = Event::signed(
            &sender,
            1_700_000_500,
            KIND_SEAL,
            Vec::new(),
            encrypt(
                &serde_json::to_string(&rumor).unwrap(),
                &recipient.x_only_public_key().0,
                &sender.secret_key(),
                [3u8; NONCE_BYTES],
            )
            .unwrap(),
        );
        let ephemeral = key(43);
        let wrap = Event::signed(
            &ephemeral,
            1_700_000_500,
            KIND_GIFT_WRAP,
            vec![vec![
                "p".to_string(),
                hex::encode(recipient.x_only_public_key().0.serialize()),
            ]],
            encrypt(
                &serde_json::to_string(&sealed).unwrap(),
                &recipient.x_only_public_key().0,
                &ephemeral.secret_key(),
                [4u8; NONCE_BYTES],
            )
            .unwrap(),
        );

        assert_eq!(
            open_message(
                &wrap,
                &recipient.secret_key(),
                &recipient.x_only_public_key().0
            ),
            Err(EnvelopeError::Unauthenticated)
        );
    }

    #[test]
    fn a_rumor_serialises_to_the_shape_a_real_one_has() {
        // Verified against the fixture: `id` is empty rather than absent, and
        // `sig` is absent rather than null.
        let json = serde_json::to_string(&Rumor {
            kind: KIND_RUMOR,
            created_at: 1,
            tags: Vec::new(),
            content: "x".to_string(),
            pubkey: "ab".to_string(),
            id: String::new(),
            sig: None,
        })
        .unwrap();
        assert!(json.contains(r#""id":"""#), "id must be present and empty: {json}");
        assert!(!json.contains("sig"), "sig must be absent entirely: {json}");
    }

    #[test]
    fn the_wrong_kind_at_any_layer_is_refused() {
        let recipient = key(51);
        let ephemeral = key(52);
        let wrap = Event::signed(
            &ephemeral,
            1_700_000_500,
            KIND_RUMOR, // not a gift wrap
            vec![vec![
                "p".to_string(),
                hex::encode(recipient.x_only_public_key().0.serialize()),
            ]],
            "v2:AAAA".to_string(),
        );
        assert_eq!(
            open_message(
                &wrap,
                &recipient.secret_key(),
                &recipient.x_only_public_key().0
            ),
            Err(EnvelopeError::BadFraming)
        );
    }
}

#[cfg(test)]
mod jitter_tests {
    use super::*;

    #[test]
    fn any_displacement_lands_inside_the_window() {
        // A caller handing over a raw random number must still get a timestamp
        // a relay will accept, not one years in the future.
        for jitter in [0, 1, -1, 900, -900, 901, -901, i64::MAX, i64::MIN + 1] {
            let published = published_timestamp(1_700_000_000, jitter);
            let drift = published - 1_700_000_000;
            assert!(
                (-TIMESTAMP_JITTER_SECS..=TIMESTAMP_JITTER_SECS).contains(&drift),
                "jitter {jitter} drifted {drift}s"
            );
        }
    }

    #[test]
    fn the_window_reaches_both_ways() {
        // A one-sided jitter would still let a relay bound the true send time.
        let published: Vec<i64> = (0..2000)
            .map(|j| published_timestamp(1_700_000_000, j) - 1_700_000_000)
            .collect();
        assert!(published.iter().any(|drift| *drift < 0), "must reach earlier");
        assert!(published.iter().any(|drift| *drift > 0), "must reach later");
    }
}
