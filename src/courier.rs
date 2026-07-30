// src/courier.rs
//
// Mail we are holding for somebody who is not here.
//
// This is the one thing in the protocol that needs no infrastructure at all —
// not a relay, not a tower, not the internet. Alice seals a message for Bob and
// hands it to whoever is nearby. That somebody holds it. Bob walks past hours
// later and collects it. The message travelled by being carried and then found.
//
// A courier learns nothing. Not the sender, not the recipient, not a byte of the
// content: the only routing information is a 16-byte tag keyed on the
// recipient's Noise static key and the UTC day, so envelopes for the same person
// on different days do not correlate for anyone who does not already know that
// person's public key. Delivery works because an announce carries a peer's
// static key — when they appear we can compute their tag and check the shelf.
//
// Upstream builds this for phones, which move, and a moving device is a courier.
// This client usually runs on something that does not move, which makes it a
// worse courier and a much better *mailbox*: always on, always in the same
// place, always covering the same neighbourhood. A phone is a postal van; this
// is the box on the corner. That changes what to optimise — spraying copies
// matters less when the recipient probably comes back to where the mail is, and
// simply still being there matters more.
//
// Formats are upstream's `CourierEnvelope`. Two details are load-bearing and
// easy to get wrong: lengths are **2-byte big-endian** (as in the Nostr carrier,
// unlike every 1-byte TLV elsewhere here), and a carry-only envelope must omit
// the `copies` field entirely rather than write 1 — otherwise our envelopes
// deduplicate differently from everyone else's.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length of the rotating recipient hint.
pub const TAG_BYTES: usize = 16;
/// Couriered messages are text-sized. Media is deliberately out of scope: a
/// mailbox that accepts megabytes is a mailbox that fills up.
pub const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
/// Longest an envelope may live, matching upstream's retention.
pub const MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
/// Ceiling on the spray budget a depositor may claim, so one envelope cannot
/// turn a courier network into an amplifier.
pub const MAX_COPIES: u8 = 8;

/// Signed into every tag, so an HMAC computed for some other purpose can never
/// be mistaken for one of these.
const TAG_CONTEXT: &[u8] = b"bitchat-courier-tag-v1";

const TLV_RECIPIENT_TAG: u8 = 0x01;
const TLV_EXPIRY: u8 = 0x02;
const TLV_CIPHERTEXT: u8 = 0x03;
const TLV_COPIES: u8 = 0x04;
const TLV_PREKEY_ID: u8 = 0x05;

/// A sealed message addressed by tag alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `HMAC-SHA256(recipient's noise static key, context ‖ epoch_day)`, first
    /// 16 bytes. Computable only by someone who already knows that key.
    pub recipient_tag: [u8; TAG_BYTES],
    /// Milliseconds since the epoch after which this must be discarded.
    pub expiry_ms: u64,
    /// One-way Noise ciphertext to the recipient. The sender's identity rides
    /// inside it, which is why a courier cannot learn who sent what.
    pub ciphertext: Vec<u8>,
    /// How many further copies the holder may hand to other couriers. 1 means
    /// carry only: deliver to the recipient, never re-spray.
    pub copies: u8,
    /// Present when sealed to a one-time prekey rather than the static key,
    /// which makes the envelope forward secret. We carry either opaquely.
    pub prekey_id: Option<u32>,
}

impl Envelope {
    /// Builds an envelope, clamping the copy budget to what policy allows.
    pub fn new(
        recipient_tag: [u8; TAG_BYTES],
        expiry_ms: u64,
        ciphertext: Vec<u8>,
        copies: u8,
        prekey_id: Option<u32>,
    ) -> Option<Self> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return None;
        }
        Some(Self {
            recipient_tag,
            expiry_ms,
            ciphertext,
            copies: copies.clamp(1, MAX_COPIES),
            prekey_id,
        })
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expiry_ms
    }

    /// How long this envelope still has, in seconds, or zero once it is done.
    pub fn remaining_seconds(&self, now_ms: u64) -> u64 {
        self.expiry_ms.saturating_sub(now_ms) / 1000
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return None;
        }
        let mut data = Vec::with_capacity(9 + TAG_BYTES + 8 + self.ciphertext.len());
        push_tlv(&mut data, TLV_RECIPIENT_TAG, &self.recipient_tag);
        push_tlv(&mut data, TLV_EXPIRY, &self.expiry_ms.to_be_bytes());
        push_tlv(&mut data, TLV_CIPHERTEXT, &self.ciphertext);
        // Omitted at 1, not written as 1. A carry-only envelope has to be
        // byte-identical to one from a client that predates spraying, or the
        // two deduplicate the same message differently and it is carried twice.
        if self.copies > 1 {
            push_tlv(&mut data, TLV_COPIES, &[self.copies]);
        }
        // Omitted for a statically sealed envelope, for the same reason.
        if let Some(prekey_id) = self.prekey_id {
            push_tlv(&mut data, TLV_PREKEY_ID, &prekey_id.to_be_bytes());
        }
        Some(data)
    }

    /// Reads an envelope. Unknown fields are skipped, so a client that adds one
    /// is still carried rather than refused — the point of a courier is to move
    /// things it does not understand.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0usize;
        let mut recipient_tag: Option<[u8; TAG_BYTES]> = None;
        let mut expiry_ms: Option<u64> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        let mut copies = 1u8;
        let mut prekey_id = None;

        while offset < data.len() {
            let tag = data[offset];
            offset += 1;
            if offset + 2 > data.len() {
                return None;
            }
            let length = ((data[offset] as usize) << 8) | data[offset + 1] as usize;
            offset += 2;
            let end = offset.checked_add(length)?;
            if end > data.len() {
                return None;
            }
            let value = &data[offset..end];
            offset = end;

            match tag {
                TLV_RECIPIENT_TAG => recipient_tag = Some(value.try_into().ok()?),
                TLV_EXPIRY => {
                    expiry_ms = Some(u64::from_be_bytes(value.try_into().ok()?));
                }
                TLV_CIPHERTEXT => {
                    if value.is_empty() || value.len() > MAX_CIPHERTEXT_BYTES {
                        return None;
                    }
                    ciphertext = Some(value.to_vec());
                }
                TLV_COPIES => {
                    if value.len() != 1 {
                        return None;
                    }
                    copies = value[0];
                }
                TLV_PREKEY_ID => {
                    prekey_id = Some(u32::from_be_bytes(value.try_into().ok()?));
                }
                _ => {}
            }
        }

        Self::new(recipient_tag?, expiry_ms?, ciphertext?, copies, prekey_id)
    }

    /// A stable identity for this envelope, so the same mail handed over twice
    /// is recognised as one item.
    ///
    /// Deliberately excludes `copies`, which is decremented as an envelope is
    /// passed along: including it would make every hop look like new mail and
    /// the shelf would fill with the same message.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(self.recipient_tag);
        hasher.update(self.expiry_ms.to_be_bytes());
        hasher.update(&self.ciphertext);
        hex::encode(&hasher.finalize()[..16])
    }
}

fn push_tlv(data: &mut Vec<u8>, tag: u8, value: &[u8]) {
    data.push(tag);
    data.extend_from_slice(&(value.len() as u16).to_be_bytes());
    data.extend_from_slice(value);
}

/// Domain separation for courier envelopes.
///
/// Mixed into the transcript before anything else, so a one-way envelope and an
/// interactive handshake can never be confused for one another even though they
/// share a cipher suite. Upstream's `courierPrologue`; a different string here
/// would produce mail nobody else can open.
const SEAL_PROLOGUE: &[u8] = b"bitchat-courier-v1";

/// Seals a payload to a recipient we cannot talk to.
///
/// One-way Noise X: one message, no reply, because the recipient is by
/// definition not present. Our own static key rides *inside* the ciphertext, so
/// the recipient learns who wrote to them and a courier does not.
///
/// The cost, which upstream states and is worth repeating: a one-way message has
/// **no forward secrecy**. A later compromise of the recipient's static key
/// exposes envelopes captured in transit. When a peer is reachable, an
/// established session is the better choice and this is the fallback.
pub fn seal(
    payload: &[u8],
    recipient_static_key: &[u8],
    our_static: &x25519_dalek::StaticSecret,
) -> Option<Vec<u8>> {
    use crate::noise_protocol::{NoiseHandshakeState, NoisePattern, NoiseRole};

    let recipient = NoiseHandshakeState::validate_public_key(recipient_static_key).ok()?;
    let mut handshake = NoiseHandshakeState::with_prologue(
        NoiseRole::Initiator,
        NoisePattern::X,
        Some(our_static.clone()),
        Some(recipient),
        SEAL_PROLOGUE,
    );
    handshake.write_message(payload).ok()
}

/// Opens an envelope addressed to us, returning what it says and who wrote it.
///
/// The sender's key is not a claim in the payload — it is authenticated by the
/// `ss` step of the pattern, which only the holder of that static key could have
/// performed. So a courier cannot alter who mail appears to be from, and neither
/// can anyone who captured it in transit.
pub fn open(
    ciphertext: &[u8],
    our_static: &x25519_dalek::StaticSecret,
) -> Option<(Vec<u8>, Vec<u8>)> {
    use crate::noise_protocol::{NoiseHandshakeState, NoisePattern, NoiseRole};

    let mut handshake = NoiseHandshakeState::with_prologue(
        NoiseRole::Responder,
        NoisePattern::X,
        Some(our_static.clone()),
        None,
        SEAL_PROLOGUE,
    );
    let payload = handshake.read_message(ciphertext).ok()?;
    let sender = handshake.get_remote_static_public_key()?;
    Some((payload, sender.to_bytes().to_vec()))
}

/// Seconds since the epoch. Zero if the clock is somehow before it, which
/// would make every tag wrong but must not make anything panic.
pub fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

/// Milliseconds since the epoch, which is what an expiry is measured in.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or_default()
}

/// UTC day number the tags rotate on.
pub fn epoch_day(now_seconds: u64) -> u32 {
    (now_seconds / 86_400) as u32
}

/// The hint that says "this is for you" to exactly one person.
pub fn recipient_tag(noise_static_key: &[u8], day: u32) -> [u8; TAG_BYTES] {
    // The key is the recipient's *public* key, which is the trick: anyone who
    // knows it can recognise their own mail, and nobody else can tell whose it
    // is. It is a hint rather than an address.
    let mut mac = HmacSha256::new_from_slice(noise_static_key)
        .expect("HMAC accepts a key of any length");
    mac.update(TAG_CONTEXT);
    mac.update(&day.to_be_bytes());
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&mac.finalize().into_bytes()[..TAG_BYTES]);
    tag
}

/// Every tag worth testing when asking whether an envelope is for a peer.
///
/// Yesterday, today and tomorrow. An envelope sealed just before midnight is
/// carried into the next day, and two devices rarely agree on the hour — so
/// checking only today would silently fail to deliver exactly the mail that has
/// been waiting longest.
pub fn candidate_tags(noise_static_key: &[u8], now_seconds: u64) -> [[u8; TAG_BYTES]; 3] {
    let today = epoch_day(now_seconds);
    [
        recipient_tag(noise_static_key, today.saturating_sub(1)),
        recipient_tag(noise_static_key, today),
        recipient_tag(noise_static_key, today.saturating_add(1)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const NOW_MS: u64 = 1_700_000_000_000;
    const NOW_S: u64 = 1_700_000_000;

    fn envelope(copies: u8, prekey_id: Option<u32>) -> Envelope {
        Envelope::new(
            [0xAB; TAG_BYTES],
            NOW_MS + 3_600_000,
            vec![0x42; 128],
            copies,
            prekey_id,
        )
        .unwrap()
    }

    fn identity(seed: u8) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from([seed; 32])
    }

    fn public(secret: &x25519_dalek::StaticSecret) -> Vec<u8> {
        x25519_dalek::PublicKey::from(secret).to_bytes().to_vec()
    }

    #[test]
    fn sealed_mail_opens_for_its_recipient_and_names_its_sender() {
        // The whole point of the pattern: one message, no reply, and the
        // recipient still learns who wrote to them.
        let alice = identity(1);
        let bob = identity(2);

        let sealed = seal(b"meet me where we said", &public(&bob), &alice)
            .expect("sealing to a known key");
        let (payload, sender) = open(&sealed, &bob).expect("bob can open his own mail");

        assert_eq!(payload, b"meet me where we said");
        assert_eq!(
            sender,
            public(&alice),
            "the sender's key is authenticated by the pattern, not claimed in the payload"
        );
    }

    #[test]
    fn nobody_else_can_open_it() {
        let alice = identity(1);
        let bob = identity(2);
        let carol = identity(3);

        let sealed = seal(b"for bob only", &public(&bob), &alice).unwrap();
        assert!(
            open(&sealed, &carol).is_none(),
            "a courier holding this must not be able to read it"
        );
    }

    #[test]
    fn a_tampered_envelope_does_not_open() {
        // A courier cannot alter mail it carries without the recipient noticing,
        // which is what makes handing mail to a stranger reasonable at all.
        let alice = identity(1);
        let bob = identity(2);
        let sealed = seal(b"unaltered", &public(&bob), &alice).unwrap();

        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 0x01;
            assert!(
                open(&altered, &bob).is_none(),
                "flipping byte {index} must break the seal"
            );
        }
    }

    #[test]
    fn the_sender_cannot_be_forged() {
        // Carol seals her own mail but claims Alice's key: the `ss` step can only
        // be performed by whoever holds the static secret, so the substitution
        // cannot survive.
        let alice = identity(1);
        let bob = identity(2);
        let carol = identity(3);

        let hers = seal(b"pretending", &public(&bob), &carol).unwrap();
        let (_, sender) = open(&hers, &bob).unwrap();
        assert_eq!(sender, public(&carol), "it is her key, not the one she wanted");
        assert_ne!(sender, public(&alice));
    }

    #[test]
    fn each_sealing_is_different_even_for_the_same_words() {
        // A fresh ephemeral per envelope. Identical ciphertext for identical text
        // would let a courier see that two people said the same thing.
        let alice = identity(1);
        let bob = identity(2);
        let first = seal(b"same words", &public(&bob), &alice).unwrap();
        let again = seal(b"same words", &public(&bob), &alice).unwrap();
        assert_ne!(first, again);
    }

    #[test]
    fn a_malformed_recipient_key_is_refused_rather_than_used() {
        let alice = identity(1);
        assert!(seal(b"hello", &[0u8; 31], &alice).is_none(), "wrong length");
        assert!(seal(b"hello", &[0u8; 32], &alice).is_none(), "all-zero is not a point");
    }

    #[test]
    fn rubbish_does_not_open_and_does_not_panic() {
        let bob = identity(2);
        for bytes in [vec![], vec![0u8; 1], vec![0u8; 32], vec![0xFF; 128]] {
            assert!(open(&bytes, &bob).is_none());
        }
    }

    #[test]
    fn an_empty_message_still_seals() {
        // A receipt or an acknowledgement has nothing to say and still has to
        // travel.
        let alice = identity(1);
        let bob = identity(2);
        let sealed = seal(b"", &public(&bob), &alice).unwrap();
        let (payload, _) = open(&sealed, &bob).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn a_full_size_message_fits_the_envelope_it_travels_in() {
        // The seal adds an ephemeral key, an encrypted static key and two tags.
        // If that overhead pushed a maximum-length message past the envelope's
        // ciphertext limit, the largest messages would fail at the last step.
        let alice = identity(1);
        let bob = identity(2);
        let long = vec![b'x'; 8 * 1024];
        let sealed = seal(&long, &public(&bob), &alice).unwrap();
        assert!(
            sealed.len() <= MAX_CIPHERTEXT_BYTES,
            "sealed to {} bytes, envelope holds {MAX_CIPHERTEXT_BYTES}",
            sealed.len()
        );
        assert!(Envelope::new([0; TAG_BYTES], NOW_MS, sealed, 1, None).is_some());
    }

    #[test]
    fn an_envelope_survives_the_wire() {
        let original = envelope(1, None);
        let read = Envelope::decode(&original.encode().unwrap()).expect("our own envelope parses");
        assert_eq!(read, original);
    }

    #[test]
    fn a_carry_only_envelope_omits_the_copies_field_entirely() {
        // The interop rule that matters. A client predating spray-and-wait
        // writes no `copies` TLV; if we wrote 1 instead of omitting it, the same
        // message would hash differently on the two clients and be carried
        // twice. Upstream tests this from the other side.
        let carry_only = envelope(1, None);
        let encoded = carry_only.encode().unwrap();
        assert!(
            !encoded.windows(3).any(|w| w[0] == TLV_COPIES && w[1] == 0 && w[2] == 1),
            "a copies TLV must not be written at all"
        );
        assert_eq!(
            Envelope::decode(&encoded).unwrap().copies,
            1,
            "and its absence must read back as carry-only"
        );
    }

    #[test]
    fn a_spray_budget_is_written_when_there_is_one() {
        let sprayable = envelope(4, None);
        let read = Envelope::decode(&sprayable.encode().unwrap()).unwrap();
        assert_eq!(read.copies, 4);
    }

    #[test]
    fn the_copy_budget_is_clamped_rather_than_trusted() {
        // A hostile envelope claiming a thousand copies would turn the courier
        // network into an amplifier.
        assert_eq!(envelope(0, None).copies, 1);
        assert_eq!(envelope(200, None).copies, MAX_COPIES);
    }

    #[test]
    fn the_layout_is_the_one_upstream_writes() {
        // Spelled out rather than round-tripped: field order and 2-byte
        // big-endian lengths are what make an envelope readable by a phone, and
        // a round trip proves only that we agree with ourselves.
        let plain = envelope(1, None);
        let encoded = plain.encode().unwrap();

        let mut expected = Vec::new();
        expected.push(TLV_RECIPIENT_TAG);
        expected.extend_from_slice(&(TAG_BYTES as u16).to_be_bytes());
        expected.extend_from_slice(&[0xAB; TAG_BYTES]);
        expected.push(TLV_EXPIRY);
        expected.extend_from_slice(&8u16.to_be_bytes());
        expected.extend_from_slice(&plain.expiry_ms.to_be_bytes());
        expected.push(TLV_CIPHERTEXT);
        expected.extend_from_slice(&128u16.to_be_bytes());
        expected.extend_from_slice(&[0x42; 128]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn a_prekey_sealed_envelope_is_carried_the_same_way() {
        // We cannot open either kind, so the discriminator is only something to
        // preserve — but preserving it is what lets the recipient open it.
        let forward_secret = envelope(1, Some(0xDEADBEEF));
        let read = Envelope::decode(&forward_secret.encode().unwrap()).unwrap();
        assert_eq!(read.prekey_id, Some(0xDEADBEEF));
    }

    #[test]
    fn an_unknown_field_is_carried_rather_than_refused() {
        // The whole job of a courier is to move things it does not understand.
        let mut encoded = envelope(1, None).encode().unwrap();
        push_tlv(&mut encoded, 0x7E, b"something from a later client");
        let read = Envelope::decode(&encoded).expect("still readable");
        assert_eq!(read.ciphertext.len(), 128);
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        let mut only_tag = Vec::new();
        push_tlv(&mut only_tag, TLV_RECIPIENT_TAG, &[0xAB; TAG_BYTES]);
        assert!(Envelope::decode(&only_tag).is_none());

        let mut no_ciphertext = Vec::new();
        push_tlv(&mut no_ciphertext, TLV_RECIPIENT_TAG, &[0xAB; TAG_BYTES]);
        push_tlv(&mut no_ciphertext, TLV_EXPIRY, &NOW_MS.to_be_bytes());
        assert!(Envelope::decode(&no_ciphertext).is_none());
    }

    #[test]
    fn nothing_oversized_is_accepted() {
        assert!(Envelope::new([0; TAG_BYTES], NOW_MS, Vec::new(), 1, None).is_none());
        assert!(Envelope::new(
            [0; TAG_BYTES],
            NOW_MS,
            vec![0; MAX_CIPHERTEXT_BYTES + 1],
            1,
            None
        )
        .is_none());
        // And an oversized one cannot be smuggled past the decoder either.
        let mut huge = Vec::new();
        push_tlv(&mut huge, TLV_RECIPIENT_TAG, &[0xAB; TAG_BYTES]);
        push_tlv(&mut huge, TLV_EXPIRY, &NOW_MS.to_be_bytes());
        huge.push(TLV_CIPHERTEXT);
        huge.extend_from_slice(&((MAX_CIPHERTEXT_BYTES + 1) as u16).to_be_bytes());
        huge.extend_from_slice(&vec![0u8; MAX_CIPHERTEXT_BYTES + 1]);
        assert!(Envelope::decode(&huge).is_none());
    }

    #[test]
    fn a_truncated_or_rubbish_envelope_does_not_panic() {
        let good = envelope(1, None).encode().unwrap();
        for cut in 0..good.len() {
            let _ = Envelope::decode(&good[..cut]);
        }
        for rubbish in [vec![], vec![0x01], vec![0x01, 0xFF], vec![0xFF; 40]] {
            let _ = Envelope::decode(&rubbish);
        }
    }

    #[test]
    fn expiry_is_a_deadline_not_a_suggestion() {
        let mail = envelope(1, None);
        assert!(!mail.is_expired(mail.expiry_ms - 1));
        assert!(mail.is_expired(mail.expiry_ms), "the moment it arrives, it is over");
        assert!(mail.is_expired(mail.expiry_ms + 1));
        assert_eq!(mail.remaining_seconds(mail.expiry_ms), 0);
        assert_eq!(mail.remaining_seconds(mail.expiry_ms - 5_000), 5);
    }

    #[test]
    fn a_tag_is_only_computable_by_someone_who_knows_the_key() {
        // The property the whole scheme rests on: holding an envelope tells you
        // nothing about who it is for.
        let theirs = recipient_tag(&KEY, epoch_day(NOW_S));
        let stranger = recipient_tag(&[9u8; 32], epoch_day(NOW_S));
        assert_ne!(theirs, stranger);
        assert_eq!(theirs.len(), TAG_BYTES);
    }

    #[test]
    fn a_tag_rotates_daily() {
        // So two envelopes for the same person a week apart cannot be linked by
        // anyone who does not already know that person's key.
        let today = recipient_tag(&KEY, epoch_day(NOW_S));
        let tomorrow = recipient_tag(&KEY, epoch_day(NOW_S) + 1);
        assert_ne!(today, tomorrow);
    }

    #[test]
    fn the_same_day_gives_the_same_tag() {
        // Otherwise mail could never be matched to its recipient at all.
        let morning = NOW_S - (NOW_S % 86_400) + 60;
        let evening = morning + 80_000;
        assert_eq!(epoch_day(morning), epoch_day(evening));
        assert_eq!(
            recipient_tag(&KEY, epoch_day(morning)),
            recipient_tag(&KEY, epoch_day(evening))
        );
    }

    #[test]
    fn delivery_checks_the_days_either_side() {
        // An envelope sealed just before midnight is carried into the next day,
        // and two devices rarely agree on the hour. Checking only today would
        // fail to deliver precisely the mail that has waited longest.
        let sealed_yesterday = recipient_tag(&KEY, epoch_day(NOW_S) - 1);
        let sealed_tomorrow = recipient_tag(&KEY, epoch_day(NOW_S) + 1);
        let candidates = candidate_tags(&KEY, NOW_S);
        assert!(candidates.contains(&sealed_yesterday));
        assert!(candidates.contains(&recipient_tag(&KEY, epoch_day(NOW_S))));
        assert!(candidates.contains(&sealed_tomorrow));
    }

    #[test]
    fn the_epoch_boundary_does_not_underflow() {
        let candidates = candidate_tags(&KEY, 0);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0], recipient_tag(&KEY, 0), "day zero has no yesterday");
    }

    #[test]
    fn the_same_mail_has_the_same_fingerprint_at_any_copy_budget() {
        // `copies` is decremented as an envelope passes along. Including it
        // would make every hop look like new mail and fill the shelf with one
        // message.
        let original = envelope(8, None);
        let passed_along = envelope(4, None);
        let last_hop = envelope(1, None);
        assert_eq!(original.fingerprint(), passed_along.fingerprint());
        assert_eq!(original.fingerprint(), last_hop.fingerprint());
    }

    #[test]
    fn different_mail_has_different_fingerprints() {
        let mail = envelope(1, None);
        let mut other_recipient = mail.clone();
        other_recipient.recipient_tag = [0xCD; TAG_BYTES];
        let mut other_content = mail.clone();
        other_content.ciphertext = vec![0x99; 128];
        let mut other_deadline = mail.clone();
        other_deadline.expiry_ms += 1;

        let mut seen = std::collections::HashSet::new();
        for item in [&mail, &other_recipient, &other_content, &other_deadline] {
            assert!(seen.insert(item.fingerprint()), "fingerprints collided");
        }
    }
}
