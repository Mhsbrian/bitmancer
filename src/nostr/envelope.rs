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
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadKey => "malformed key",
            Self::BadFraming => "not a v2 envelope",
            Self::TooLarge => "envelope larger than we will decode",
            Self::Undecryptable => "could not decrypt",
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
