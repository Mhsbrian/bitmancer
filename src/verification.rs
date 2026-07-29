// src/verification.rs
//
// Proving that a peer is who you think they are.
//
// Everything else in this client trusts a fingerprint because it was derived
// from a key that arrived over the air. That is enough to know the same party is
// still on the other end of a conversation, and not enough to know who they are:
// an attacker in the middle can hand each side its own key and both fingerprints
// will look perfectly stable forever. The only cure is comparing keys over a
// channel the attacker does not control, which in practice means standing next
// to someone.
//
// So this is deliberately out of band. A verification card carries the two
// public keys, is signed by the signing half, and is exchanged by being *shown*
// — as a QR on a phone, as a URL between desktops. Reading it tells you which
// keys the person in front of you claims. The challenge/response that follows
// proves they still hold the signing key right now, over the mesh, so a card
// captured and replayed by someone else does not verify them.
//
// Formats are upstream's, checked against `VerificationService.swift` rather
// than inferred: a verification scheme that only interoperates with itself
// verifies nothing useful.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Signed into every card, so a signature made for some other purpose can never
/// be replayed as one of these.
const CARD_CONTEXT: &str = "bitchat-verify-v1";
/// The equivalent for a challenge response.
const RESPONSE_CONTEXT: &str = "bitchat-verify-resp-v1";

/// How long a card stays good. Upstream's `verificationQRMaxAgeSeconds`.
///
/// Short on purpose: the card says "these are my keys, now". A stale one proves
/// only that the holder was near the owner at some point, which is exactly the
/// claim an attacker who copied it would like to make.
pub const MAX_AGE_SECONDS: i64 = 5 * 60;

/// Length of the nonce a card carries, before base64.
pub const NONCE_BYTES: usize = 16;

/// Field length that fits in the one-byte prefix upstream writes.
const MAX_FIELD: usize = 255;

/// TLV tags inside a challenge and its response.
const TLV_NOISE_KEY: u8 = 0x01;
const TLV_NONCE: u8 = 0x02;
const TLV_SIGNATURE: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Not a `bitchat://verify` URL, or a field is missing.
    Malformed,
    /// Older than [`MAX_AGE_SECONDS`], or dated in the future.
    Stale,
    /// The signature does not match the keys it claims.
    BadSignature,
}

/// What someone shows you to prove which keys are theirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub version: u32,
    /// Noise static public key, hex. The fingerprint is derived from this, so
    /// it is the value the whole exercise exists to pin down.
    pub noise_key_hex: String,
    /// Ed25519 public key, hex. Signs the card and any later challenge.
    pub signing_key_hex: String,
    /// Their long-lived Nostr address, when they have one.
    pub npub: Option<String>,
    pub nickname: String,
    pub timestamp: i64,
    /// base64url, unpadded. Makes two cards from the same identity differ, so
    /// one cannot be mistaken for a replay of the other.
    pub nonce: String,
    pub signature_hex: String,
}

impl Card {
    /// Builds and signs a card for our own identity.
    ///
    /// `now` and `nonce` are passed in rather than taken from the clock and the
    /// RNG so a caller can be deterministic. In use the nonce must be fresh.
    pub fn build(
        signing_key: &SigningKey,
        noise_public_key: &[u8],
        nickname: &str,
        npub: Option<&str>,
        now: i64,
        nonce: [u8; NONCE_BYTES],
    ) -> Self {
        let mut card = Self {
            version: 1,
            noise_key_hex: hex::encode(noise_public_key),
            signing_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            npub: npub.map(str::to_string),
            nickname: nickname.to_string(),
            timestamp: now,
            nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            signature_hex: String::new(),
        };
        let signature = signing_key.sign(&card.canonical_bytes());
        card.signature_hex = hex::encode(signature.to_bytes());
        card
    }

    /// The bytes the signature covers.
    ///
    /// Length-prefixed fields in a fixed order, so the signature commits to
    /// where each one ends: without that, moving a character from the nickname
    /// to the nonce would leave the signed bytes identical.
    ///
    /// Both key fields are lowercased here but not in the URL, so a card whose
    /// hex arrives upper-cased still verifies. A field longer than 255 bytes is
    /// truncated rather than refused — upstream's `prefix(255)`, matched
    /// deliberately, and the reason `nickname` is length-capped before a card is
    /// ever built.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, CARD_CONTEXT);
        push_field(&mut out, &self.version.to_string());
        push_field(&mut out, &self.noise_key_hex.to_lowercase());
        push_field(&mut out, &self.signing_key_hex.to_lowercase());
        push_field(&mut out, self.npub.as_deref().unwrap_or(""));
        push_field(&mut out, &self.nickname);
        push_field(&mut out, &self.timestamp.to_string());
        push_field(&mut out, &self.nonce);
        out
    }

    /// The string that goes on a screen, in a QR or in a message.
    pub fn to_url(&self) -> String {
        let mut url = format!(
            "bitchat://verify?v={}&noise={}&sign={}&nick={}&ts={}&nonce={}&sig={}",
            self.version,
            encode_query(&self.noise_key_hex),
            encode_query(&self.signing_key_hex),
            encode_query(&self.nickname),
            self.timestamp,
            encode_query(&self.nonce),
            encode_query(&self.signature_hex),
        );
        if let Some(npub) = &self.npub {
            url.push_str(&format!("&npub={}", encode_query(npub)));
        }
        url
    }

    /// Reads a card, without checking whether it is any good.
    pub fn from_url(url: &str) -> Result<Self, VerifyError> {
        let query = url
            .trim()
            .strip_prefix("bitchat://verify?")
            .ok_or(VerifyError::Malformed)?;

        let mut fields = std::collections::HashMap::new();
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            // First wins: a duplicated parameter must not let a second copy
            // silently replace a field the signature was computed over.
            fields
                .entry(name)
                .or_insert_with(|| decode_query(value));
        }
        let take = |name: &str| fields.get(name).cloned().ok_or(VerifyError::Malformed);

        Ok(Self {
            version: take("v")?.parse().map_err(|_| VerifyError::Malformed)?,
            noise_key_hex: take("noise")?,
            signing_key_hex: take("sign")?,
            npub: fields.get("npub").cloned().filter(|key| !key.is_empty()),
            nickname: take("nick")?,
            timestamp: take("ts")?.parse().map_err(|_| VerifyError::Malformed)?,
            nonce: take("nonce")?,
            signature_hex: take("sig")?,
        })
    }

    /// Whether this card is currently worth acting on.
    ///
    /// A card from the future is refused as firmly as an expired one. Clock skew
    /// is real, so a small amount of it is tolerated, but a timestamp well ahead
    /// of ours is how a card gets minted once and shown for a week.
    pub fn check(&self, now: i64) -> Result<(), VerifyError> {
        let age = now - self.timestamp;
        if !(-MAX_AGE_SECONDS..=MAX_AGE_SECONDS).contains(&age) {
            return Err(VerifyError::Stale);
        }
        let signing_key = verifying_key(&self.signing_key_hex)?;
        let signature = signature_from_hex(&self.signature_hex)?;
        signing_key
            .verify(&self.canonical_bytes(), &signature)
            .map_err(|_| VerifyError::BadSignature)
    }

    /// The fingerprint this card claims, which is what gets marked verified.
    pub fn fingerprint(&self) -> Result<String, VerifyError> {
        let noise_key = hex::decode(&self.noise_key_hex).map_err(|_| VerifyError::Malformed)?;
        Ok(crate::peer_id::fingerprint(&noise_key))
    }

    /// The peer ID that fingerprint belongs to.
    pub fn peer_id(&self) -> Result<String, VerifyError> {
        Ok(self.fingerprint()?.chars().take(16).collect())
    }
}

// The initiator's half of challenge/response.
//
// Unused by this client, and not by oversight. Issuing a challenge would prove
// that the peer holds the signing key behind a noise key — which the Noise
// session already establishes, since it binds the static key, and a card read
// off a screen supplies the fingerprint to compare it against. There is nothing
// left for us to ask. Upstream marks its own equivalent "scaffold only".
//
// It stays because the responder is wired and has to be testable: proving our
// reply is well-formed means issuing a real challenge and checking a real
// signature against it. A responder tested only against itself is a responder
// tested against nothing.

/// Asks a peer to prove they hold the signing key behind a noise key.
#[allow(dead_code)]
pub fn challenge(noise_key_hex: &str, nonce: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::new();
    push_tlv(&mut tlv, TLV_NOISE_KEY, noise_key_hex.as_bytes());
    push_tlv(&mut tlv, TLV_NONCE, nonce);
    tlv
}

pub fn parse_challenge(body: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut reader = Reader::new(body);
    let noise_key_hex = String::from_utf8(reader.tlv(TLV_NOISE_KEY)?).ok()?;
    let nonce = reader.tlv(TLV_NONCE)?;
    Some((noise_key_hex, nonce))
}

/// The bytes a response signs.
///
/// The noise key is length-prefixed and the nonce is not, because the nonce is
/// the tail. Matching upstream exactly matters more here than elegance: a
/// response signed over different bytes verifies nowhere.
pub fn response_message(noise_key_hex: &str, nonce: &[u8]) -> Vec<u8> {
    let mut message = RESPONSE_CONTEXT.as_bytes().to_vec();
    let key = noise_key_hex.as_bytes();
    let length = key.len().min(MAX_FIELD);
    message.push(length as u8);
    message.extend_from_slice(&key[..length]);
    message.extend_from_slice(nonce);
    message
}

/// Answers a challenge, proving present possession of the signing key.
pub fn response(noise_key_hex: &str, nonce: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(&response_message(noise_key_hex, nonce));
    let mut tlv = Vec::new();
    push_tlv(&mut tlv, TLV_NOISE_KEY, noise_key_hex.as_bytes());
    push_tlv(&mut tlv, TLV_NONCE, nonce);
    push_tlv(&mut tlv, TLV_SIGNATURE, &signature.to_bytes());
    tlv
}

#[allow(dead_code)]
pub fn parse_response(body: &[u8]) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let mut reader = Reader::new(body);
    let noise_key_hex = String::from_utf8(reader.tlv(TLV_NOISE_KEY)?).ok()?;
    let nonce = reader.tlv(TLV_NONCE)?;
    let signature = reader.tlv(TLV_SIGNATURE)?;
    Some((noise_key_hex, nonce, signature))
}

/// Whether a response actually answers the challenge that was sent.
///
/// The nonce is checked against the one we issued, not merely against the one
/// the response echoes: a reply carrying its own nonce and a valid signature
/// over that nonce is a recording of some earlier exchange.
#[allow(dead_code)]
pub fn verify_response(
    noise_key_hex: &str,
    expected_nonce: &[u8],
    echoed_nonce: &[u8],
    signature: &[u8],
    signing_key_hex: &str,
) -> bool {
    if echoed_nonce != expected_nonce {
        return false;
    }
    let (Ok(key), Ok(signature)) = (
        verifying_key(signing_key_hex),
        signature_from_hex(&hex::encode(signature)),
    ) else {
        return false;
    };
    key.verify(&response_message(noise_key_hex, expected_nonce), &signature)
        .is_ok()
}

fn verifying_key(hex_key: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .map_err(|_| VerifyError::Malformed)?
        .try_into()
        .map_err(|_| VerifyError::Malformed)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::Malformed)
}

fn signature_from_hex(hex_signature: &str) -> Result<Signature, VerifyError> {
    let bytes: [u8; 64] = hex::decode(hex_signature)
        .map_err(|_| VerifyError::Malformed)?
        .try_into()
        .map_err(|_| VerifyError::Malformed)?;
    Ok(Signature::from_bytes(&bytes))
}

fn push_field(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = bytes.len().min(MAX_FIELD);
    out.push(length as u8);
    out.extend_from_slice(&bytes[..length]);
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    let length = value.len().min(MAX_FIELD);
    out.push(tag);
    out.push(length as u8);
    out.extend_from_slice(&value[..length]);
}

/// Walks a TLV record, insisting on the tags it expects in the order it expects
/// them — the same shape upstream's parsers take.
struct Reader<'a> {
    body: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, offset: 0 }
    }

    fn tlv(&mut self, expected: u8) -> Option<Vec<u8>> {
        let tag = *self.body.get(self.offset)?;
        if tag != expected {
            return None;
        }
        let length = *self.body.get(self.offset + 1)? as usize;
        let start = self.offset + 2;
        let end = start.checked_add(length)?;
        let value = self.body.get(start..end)?.to_vec();
        self.offset = end;
        Some(value)
    }
}

/// Percent-encodes the characters that would otherwise end a query value.
///
/// Deliberately small: every field here is hex, base64url, or a nickname, and
/// the only characters that can break parsing are the separators themselves.
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn decode_query(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn identity(seed: u8) -> (SigningKey, [u8; 32]) {
        (SigningKey::from_bytes(&[seed; 32]), [seed.wrapping_add(1); 32])
    }

    fn card(now: i64) -> (Card, SigningKey) {
        let (signing_key, noise_key) = identity(7);
        let card = Card::build(
            &signing_key,
            &noise_key,
            "technician",
            Some("npub1abc"),
            now,
            [3u8; NONCE_BYTES],
        );
        (card, signing_key)
    }

    #[test]
    fn a_card_we_built_verifies() {
        let (card, _) = card(NOW);
        assert_eq!(card.check(NOW), Ok(()));
    }

    #[test]
    fn a_card_survives_the_url_it_travels_in() {
        let (card, _) = card(NOW);
        let url = card.to_url();
        assert!(url.starts_with("bitchat://verify?"), "{url}");
        let read = Card::from_url(&url).expect("our own URL parses");
        assert_eq!(read, card);
        assert_eq!(read.check(NOW), Ok(()));
    }

    #[test]
    fn a_card_without_a_nostr_address_is_still_a_card() {
        let (signing_key, noise_key) = identity(9);
        let card = Card::build(&signing_key, &noise_key, "nobody", None, NOW, [1u8; NONCE_BYTES]);
        assert_eq!(card.check(NOW), Ok(()));
        let read = Card::from_url(&card.to_url()).unwrap();
        assert_eq!(read.npub, None);
        assert_eq!(read.check(NOW), Ok(()));
    }

    #[test]
    fn every_signed_field_is_actually_covered() {
        // A signature that did not commit to the noise key would let an
        // attacker swap in their own and leave the card verifying — which is
        // the entire attack this exists to stop.
        let (original, _) = card(NOW);
        for mutate in [
            (|c: &mut Card| c.noise_key_hex = hex::encode([0xEE; 32])) as fn(&mut Card),
            |c: &mut Card| c.signing_key_hex = hex::encode([0xEE; 32]),
            |c: &mut Card| c.nickname = "someone else".into(),
            |c: &mut Card| c.npub = Some("npub1attacker".into()),
            |c: &mut Card| c.timestamp += 1,
            |c: &mut Card| c.nonce = "AAAAAAAAAAAAAAAAAAAAAA".into(),
            |c: &mut Card| c.version = 2,
        ] {
            let mut tampered = original.clone();
            mutate(&mut tampered);
            assert_ne!(
                tampered.check(NOW),
                Ok(()),
                "a change to a signed field must not verify"
            );
        }
    }

    #[test]
    fn a_card_signed_by_someone_else_is_refused() {
        let (mut card, _) = card(NOW);
        let (impostor, _) = identity(11);
        // Claim their key while keeping our signature.
        card.signing_key_hex = hex::encode(impostor.verifying_key().to_bytes());
        assert_eq!(card.check(NOW), Err(VerifyError::BadSignature));
    }

    #[test]
    fn an_expired_card_is_refused() {
        let (card, _) = card(NOW);
        assert_eq!(card.check(NOW + MAX_AGE_SECONDS + 1), Err(VerifyError::Stale));
        assert_eq!(card.check(NOW + MAX_AGE_SECONDS), Ok(()), "the edge still counts");
    }

    #[test]
    fn a_card_from_the_future_is_refused() {
        // Otherwise a card is minted once with a distant timestamp and shown
        // for as long as its owner likes.
        let (card, _) = card(NOW);
        assert_eq!(card.check(NOW - MAX_AGE_SECONDS - 1), Err(VerifyError::Stale));
    }

    #[test]
    fn rubbish_is_not_a_card() {
        for text in [
            "",
            "hello",
            "https://example.com/verify?v=1",
            "bitchat://verify",
            "bitchat://verify?v=1",                    // missing everything else
            "bitchat://verify?v=x&noise=aa&sign=bb&nick=n&ts=1&nonce=c&sig=d", // bad version
        ] {
            assert_eq!(
                Card::from_url(text),
                Err(VerifyError::Malformed),
                "{text:?} must not read as a card"
            );
        }
    }

    #[test]
    fn a_duplicated_parameter_cannot_replace_a_signed_field() {
        let (card, _) = card(NOW);
        let tampered = format!("{}&nick=someone-else", card.to_url());
        let read = Card::from_url(&tampered).expect("still parses");
        assert_eq!(read.nickname, "technician", "the first value stands");
        assert_eq!(read.check(NOW), Ok(()));
    }

    #[test]
    fn a_nickname_with_awkward_characters_round_trips() {
        // Nicknames are user-chosen, so the separators have to survive.
        let (signing_key, noise_key) = identity(5);
        for nickname in ["a b", "a&b=c", "100%", "ünïcødé", "?query"] {
            let card = Card::build(
                &signing_key,
                &noise_key,
                nickname,
                None,
                NOW,
                [2u8; NONCE_BYTES],
            );
            let read = Card::from_url(&card.to_url()).expect("parses");
            assert_eq!(read.nickname, nickname);
            assert_eq!(read.check(NOW), Ok(()), "{nickname:?}");
        }
    }

    #[test]
    fn upper_case_hex_still_verifies() {
        // The signature is computed over lowercase, but the URL carries what it
        // was given; a card retyped in capitals must not silently fail.
        let (mut card, _) = card(NOW);
        card.noise_key_hex = card.noise_key_hex.to_uppercase();
        card.signing_key_hex = card.signing_key_hex.to_uppercase();
        assert_eq!(card.check(NOW), Ok(()));
    }

    #[test]
    fn the_fingerprint_is_the_one_the_rest_of_the_client_uses() {
        let (_, noise_key) = identity(7);
        let (card, _) = card(NOW);
        assert_eq!(card.fingerprint().unwrap(), crate::peer_id::fingerprint(&noise_key));
        assert_eq!(card.peer_id().unwrap(), crate::peer_id::derive_peer_id(&noise_key));
    }

    #[test]
    fn the_signed_bytes_are_laid_out_the_way_upstream_lays_them_out() {
        // Spelled out rather than compared against our own builder, which would
        // only prove we are consistent with ourselves. Field order and framing
        // are what a card verifying on a phone depends on, and getting either
        // wrong fails in exactly one place: someone else's client.
        let (card, _) = card(NOW);

        let mut expected = Vec::new();
        for field in [
            "bitchat-verify-v1",
            "1",
            &card.noise_key_hex.to_lowercase(),
            &card.signing_key_hex.to_lowercase(),
            "npub1abc",
            "technician",
            "1700000000",
            &card.nonce,
        ] {
            expected.push(field.len() as u8);
            expected.extend_from_slice(field.as_bytes());
        }

        assert_eq!(card.canonical_bytes(), expected);
    }

    #[test]
    fn the_response_message_is_laid_out_the_way_upstream_lays_it_out() {
        // The asymmetry is upstream's and is easy to get wrong: the key is
        // length-prefixed, the nonce is not, because the nonce is the tail.
        let key = hex::encode([4u8; 32]);
        let nonce = [0xAB; NONCE_BYTES];

        let mut expected = b"bitchat-verify-resp-v1".to_vec();
        expected.push(key.len() as u8);
        expected.extend_from_slice(key.as_bytes());
        expected.extend_from_slice(&nonce);

        assert_eq!(response_message(&key, &nonce), expected);
    }

    #[test]
    fn an_over_long_field_is_truncated_rather_than_refused() {
        // Upstream's `prefix(255)`, matched deliberately. It is also a hazard
        // worth naming: two nicknames sharing their first 255 bytes produce the
        // same signed bytes, so a nickname is capped long before it gets here.
        let (signing_key, noise_key) = identity(21);
        let long = "n".repeat(300);
        let card = Card::build(&signing_key, &noise_key, &long, None, NOW, [0; NONCE_BYTES]);
        let bytes = card.canonical_bytes();
        // The nickname field is the sixth; find it by its length byte of 255.
        assert!(
            bytes.windows(2).any(|pair| pair[0] == 255 && pair[1] == b'n'),
            "the field is written at its capped length"
        );
    }

    #[test]
    fn a_challenge_round_trips() {
        let nonce = [0xAB; NONCE_BYTES];
        let key = hex::encode([4u8; 32]);
        let (read_key, read_nonce) =
            parse_challenge(&challenge(&key, &nonce)).expect("our own challenge parses");
        assert_eq!(read_key, key);
        assert_eq!(read_nonce, nonce);
    }

    #[test]
    fn a_response_proves_the_signing_key_is_held_now() {
        let (signing_key, noise_key) = identity(13);
        let key_hex = hex::encode(noise_key);
        let nonce = [0x5A; NONCE_BYTES];

        let frame = response(&key_hex, &nonce, &signing_key);
        let (read_key, read_nonce, signature) = parse_response(&frame).expect("parses");
        assert_eq!(read_key, key_hex);
        assert!(verify_response(
            &key_hex,
            &nonce,
            &read_nonce,
            &signature,
            &hex::encode(signing_key.verifying_key().to_bytes())
        ));
    }

    #[test]
    fn a_response_to_a_different_nonce_is_refused() {
        // The replay that matters: a recording of an earlier exchange carries a
        // perfectly valid signature over its own nonce.
        let (signing_key, noise_key) = identity(13);
        let key_hex = hex::encode(noise_key);
        let recorded = [0x11; NONCE_BYTES];
        let frame = response(&key_hex, &recorded, &signing_key);
        let (_, echoed, signature) = parse_response(&frame).unwrap();

        let we_asked = [0x22; NONCE_BYTES];
        assert!(
            !verify_response(
                &key_hex,
                &we_asked,
                &echoed,
                &signature,
                &hex::encode(signing_key.verifying_key().to_bytes())
            ),
            "a reply must answer the question we asked"
        );
    }

    #[test]
    fn a_response_signed_by_the_wrong_key_is_refused() {
        let (signing_key, noise_key) = identity(13);
        let (impostor, _) = identity(17);
        let key_hex = hex::encode(noise_key);
        let nonce = [0x5A; NONCE_BYTES];
        let frame = response(&key_hex, &nonce, &signing_key);
        let (_, echoed, signature) = parse_response(&frame).unwrap();
        assert!(!verify_response(
            &key_hex,
            &nonce,
            &echoed,
            &signature,
            &hex::encode(impostor.verifying_key().to_bytes())
        ));
    }

    #[test]
    fn a_response_about_a_different_noise_key_is_refused() {
        // Signing a challenge for someone else's key would let a verified peer
        // vouch a stranger's fingerprint into place.
        let (signing_key, noise_key) = identity(13);
        let nonce = [0x5A; NONCE_BYTES];
        let frame = response(&hex::encode(noise_key), &nonce, &signing_key);
        let (_, echoed, signature) = parse_response(&frame).unwrap();
        assert!(!verify_response(
            &hex::encode([0xFF; 32]),
            &nonce,
            &echoed,
            &signature,
            &hex::encode(signing_key.verifying_key().to_bytes())
        ));
    }

    #[test]
    fn malformed_records_do_not_panic() {
        for body in [
            vec![],
            vec![0x01],
            vec![0x01, 0xFF],
            vec![0x01, 0x02, 0xAA],
            vec![0x02, 0x01, 0xAA],
            vec![0xFF; 8],
        ] {
            let _ = parse_challenge(&body);
            let _ = parse_response(&body);
        }
    }

    #[test]
    fn the_two_contexts_cannot_be_confused() {
        // A card signature and a response signature must never be
        // interchangeable, or answering a challenge would mint a card.
        assert_ne!(CARD_CONTEXT, RESPONSE_CONTEXT);
        let (card, signing_key) = card(NOW);
        let nonce = [3u8; NONCE_BYTES];
        assert_ne!(
            card.canonical_bytes(),
            response_message(&card.noise_key_hex, &nonce)
        );
        // And a response signature does not verify as a card signature.
        let mut forged = card.clone();
        let signature = signing_key.sign(&response_message(&card.noise_key_hex, &nonce));
        forged.signature_hex = hex::encode(signature.to_bytes());
        assert_eq!(forged.check(NOW), Err(VerifyError::BadSignature));
    }
}
