// src/nostr/pow.rs
//
// NIP-13 proof of work, ported from bitchat/Nostr/NostrPoW.swift.
//
// The nonce tag commits to a target difficulty and the id must actually meet
// it, so the tag has to be part of the serialization the id is computed over.
// Mining is strictly best effort: if the time cap hits, the committed target
// steps down rather than blocking the send.

use std::time::{Duration, Instant};

use crate::nostr::event::Event;

/// Upstream's default target (NostrPoW.targetBits).
pub const TARGET_BITS: u32 = 8;
const MINING_TIME_CAP: Duration = Duration::from_secs(2);

/// Number of leading zero bits in a hash.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0;
    for &byte in bytes {
        if byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros(); // u8::leading_zeros() is already 0..=8
            break;
        }
    }
    total
}

/// Mines a `["nonce", value, target]` tag, returning the tag list to sign.
///
/// Returns the original tags unchanged if even a zero-bit commitment cannot be
/// produced, which cannot normally happen — a zero target is met by any hash.
pub fn mine(
    pubkey: &str,
    created_at: i64,
    kind: u32,
    base_tags: &[Vec<String>],
    content: &str,
    target_bits: u32,
) -> Vec<Vec<String>> {
    let mut target = target_bits.min(256);
    let deadline = Instant::now() + MINING_TIME_CAP;

    loop {
        if let Some(tags) = mine_attempt(pubkey, created_at, kind, base_tags, content, target, deadline)
        {
            return tags;
        }
        if target == 0 {
            return base_tags.to_vec();
        }
        // Out of time: halve the commitment and take what we can get, so the
        // event still ships with an honest difficulty claim.
        target /= 2;
    }
}

fn mine_attempt(
    pubkey: &str,
    created_at: i64,
    kind: u32,
    base_tags: &[Vec<String>],
    content: &str,
    target_bits: u32,
    deadline: Instant,
) -> Option<Vec<Vec<String>>> {
    let target_string = target_bits.to_string();
    let mut nonce: u64 = 0;

    loop {
        let mut tags = base_tags.to_vec();
        tags.push(vec![
            "nonce".to_string(),
            nonce.to_string(),
            target_string.clone(),
        ]);

        let id = Event::compute_id(pubkey, created_at, kind, &tags, content);
        if leading_zero_bits(&id) >= target_bits {
            return Some(tags);
        }

        nonce += 1;
        // Checking the clock every hash is wasteful; 8 bits averages 256 tries.
        if nonce.is_multiple_of(256) && Instant::now() >= deadline {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x7F]), 1);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn mined_events_meet_the_committed_target() {
        let base = vec![vec!["g".to_string(), "9q8yy".to_string()]];
        let tags = mine("aa".repeat(32).as_str(), 1700000000, 20000, &base, "hi", TARGET_BITS);

        let nonce_tag = tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("nonce"))
            .expect("a nonce tag must be added");
        assert_eq!(nonce_tag.len(), 3);
        let committed: u32 = nonce_tag[2].parse().unwrap();

        // The id computed over the *final* tag list must meet the commitment.
        let id = Event::compute_id(&"aa".repeat(32), 1700000000, 20000, &tags, "hi");
        assert!(
            leading_zero_bits(&id) >= committed,
            "id has {} bits, committed to {committed}",
            leading_zero_bits(&id)
        );
    }

    #[test]
    fn the_original_tags_are_preserved() {
        let base = vec![
            vec!["g".to_string(), "9q8yy".to_string()],
            vec!["n".to_string(), "tui".to_string()],
        ];
        let tags = mine(&"bb".repeat(32), 1, 20000, &base, "x", 4);
        assert_eq!(&tags[..2], &base[..]);
    }

    #[test]
    fn a_zero_target_returns_immediately() {
        let tags = mine(&"cc".repeat(32), 1, 20000, &[], "x", 0);
        assert_eq!(tags.len(), 1, "just the nonce tag");
        assert_eq!(tags[0][2], "0");
    }
}
