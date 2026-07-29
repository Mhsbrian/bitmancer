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

/// The ECDH shared secret, as this protocol wants it.
///
/// `secp256k1`'s own `SharedSecret` hashes the point; upstream uses the raw
/// compressed serialisation instead, so the point is rebuilt here by hand. The
/// parity byte comes from the y coordinate, which is why the full point is
/// needed rather than just x.
fn shared_secret(secret: &SecretKey, public: &XOnlyPublicKey) -> [u8; 33] {
    // A Nostr key is x-only, so the peer's point is lifted to the even one.
    // Our own secret has to be normalised the same way or the two sides do not
    // agree: lifting their key to even while ours corresponds to an odd point
    // makes each side compute the negation of the other's result. Same x,
    // opposite parity byte, different HKDF output, and a ciphertext nobody can
    // open. This is BIP-340's rule, applied to key agreement rather than
    // signing.
    let normalised = if secret.x_only_public_key(secp256k1::SECP256K1).1 == secp256k1::Parity::Odd
    {
        secret.negate()
    } else {
        *secret
    };
    let full = PublicKey::from_x_only_public_key(*public, secp256k1::Parity::Even);
    let point = secp256k1::ecdh::shared_secret_point(&full, &normalised);

    let mut compressed = [0u8; 33];
    compressed[0] = if point[63] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(&point[..32]);
    compressed
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
    let key = symmetric_key(&shared_secret(sender_secret, recipient));
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
    let key = symmetric_key(&shared_secret(recipient_secret, sender));
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce24),
            Payload {
                msg: sealed,
                aad: &[],
            },
        )
        .map_err(|_| EnvelopeError::Undecryptable)?;

    String::from_utf8(plaintext).map_err(|_| EnvelopeError::Undecryptable)
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
    fn both_ends_derive_the_same_key() {
        // ECDH is symmetric; if our point reconstruction broke that, sealing
        // would work and opening would not.
        let a = keypair(13);
        let b = keypair(14);
        assert_eq!(
            shared_secret(&a.secret_key(), &b.x_only_public_key().0),
            shared_secret(&b.secret_key(), &a.x_only_public_key().0)
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
