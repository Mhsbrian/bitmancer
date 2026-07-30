// src/sync/gcs.rs
//
// Golomb-Coded Set filters. Port of upstream `Sync/GCSFilter.swift`.
//
// A GCS is a Bloom filter's inverse in spirit: instead of a bit array, it sorts
// the hashed members, delta-encodes them, and Golomb-Rice codes the deltas. That
// costs about `P + 2` bits per element, which is what makes a thousand packet
// IDs fit in the few hundred bytes a BLE write can carry.
//
// The direction of the error matters and is worth stating once: this structure
// has false positives and no false negatives. A false positive means the peer
// appears to already hold a packet it does not, so we skip sending it — a missed
// sync that the next round repairs. There is no case where it makes us claim to
// hold something we do not.

use sha2::{Digest, Sha256};

use super::packet_id::PACKET_ID_LEN;

/// Highest Golomb-Rice parameter accepted from the wire.
///
/// `P` maps to a false-positive rate of about `1 / 2^P`. Past 32 the remainder
/// is wider than any real filter and the shifts in `decode` would run off the
/// end into garbage, so upstream refuses rather than decoding nonsense.
pub const MAX_P: u32 = 32;

/// A built filter, plus how much of the input it actually covers.
///
/// `included_count` can be below the number of IDs handed in: when the encoding
/// overflows the byte budget the tail is trimmed. Callers pass IDs **newest
/// first**, so what survives is always a contiguous newest-prefix rather than an
/// arbitrary hash-ordered subset. That is precisely what lets a caller derive an
/// exact since-cursor from the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub p: u32,
    pub m: u32,
    pub data: Vec<u8>,
    pub included_count: usize,
}

/// `P` from a target false-positive rate, `ceil(log2(1/f))`.
///
/// The clamp is upstream's: below 1e-6 the parameter stops being useful and
/// above 0.25 the filter stops being a filter.
pub fn derive_p(target_fpr: f64) -> u32 {
    let f = target_fpr.clamp(0.000_001, 0.25);
    let p = (1.0f64 / f).log2().ceil() as i64;
    p.max(1) as u32
}

/// Roughly how many elements fit in a byte budget at this `P`.
///
/// `P + 2` bits per element is the standard Golomb-Rice estimate: `P` for the
/// remainder plus about two for the unary quotient.
pub fn estimate_max_elements(size_bytes: usize, p: u32) -> usize {
    let bits = (size_bytes * 8).max(8);
    let per = (p as usize + 2).max(3);
    (bits / per).max(1)
}

/// `count * 2^p`, saturating at `u32::MAX`.
///
/// This is the modulus the hashes are folded into. Making it proportional to the
/// element count is what holds the false-positive rate at `1/2^P` regardless of
/// how many elements there are.
fn hash_range(count: usize, p: u32) -> u32 {
    if count == 0 {
        return 1;
    }
    if p >= 64 {
        return u32::MAX;
    }
    let product = (count as u64).saturating_mul(1u64 << p);
    if product == 0 {
        return 1;
    }
    product.min(u64::from(u32::MAX)) as u32
}

/// First 8 bytes of `SHA-256(id)`, big-endian, with the top bit cleared.
///
/// The mask is not decoration. Without it, roughly half of all IDs land on a
/// different bucket than every phone in the room computes for the same packet,
/// and the filter quietly stops agreeing with anyone.
fn h64(id: &[u8; PACKET_ID_LEN]) -> u64 {
    let digest = Sha256::digest(id);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes) & 0x7fff_ffff_ffff_ffff
}

/// Folds a hash into `[1, modulo)`.
///
/// Zero is remapped to one so no delta is ever zero-length: the Golomb-Rice
/// encoding writes `x - 1`, and a zero delta would encode as `x = 0`, whose
/// `x - 1` wraps.
fn map_hash(hash: u64, modulo: u64) -> u64 {
    if modulo <= 1 {
        return 0;
    }
    match hash % modulo {
        0 => 1,
        value => value,
    }
}

/// Clamps into range and drops duplicates, keeping the sequence strictly
/// increasing so every delta is at least 1.
fn normalize_mapped_values(values: &[u64], modulo: u64) -> Vec<u64> {
    if modulo <= 1 {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(values.len());
    let mut last = 0u64;
    for &value in values {
        let normalized = value.min(modulo - 1);
        if normalized > last {
            result.push(normalized);
            last = normalized;
        }
    }
    result
}

/// The bucket a packet ID occupies in a filter with this modulus. Used by the
/// responder to test an ID it holds against a filter the requester sent.
pub fn bucket(id: &[u8; PACKET_ID_LEN], m: u32) -> u64 {
    let modulo = u64::from(m.max(1));
    if modulo <= 1 {
        return 0;
    }
    map_hash(h64(id), modulo)
}

/// Builds a filter over `ids`, which must be ordered **newest first**.
pub fn build_filter(ids: &[[u8; PACKET_ID_LEN]], max_bytes: usize, target_fpr: f64) -> Params {
    let p = derive_p(target_fpr);
    if ids.is_empty() {
        return Params {
            p,
            m: 1,
            data: Vec::new(),
            included_count: 0,
        };
    }

    let cap = estimate_max_elements(max_bytes, p);
    // The modulus is pinned to the *initial* candidate count so it does not
    // move as the tail is trimmed below. A modulus that shifted between
    // attempts would put the same ID in a different bucket each time.
    let range = hash_range(ids.len().min(cap), p).max(1);
    let modulo = u64::from(range);

    let encode_first = |count: usize| -> Vec<u8> {
        let mut mapped: Vec<u64> = ids[..count]
            .iter()
            .map(|id| map_hash(h64(id), modulo))
            .collect();
        mapped.sort_unstable();
        let mapped = normalize_mapped_values(&mapped, modulo);
        if mapped.is_empty() {
            Vec::new()
        } else {
            encode_sorted(&mapped, p)
        }
    };

    let mut count = ids.len().min(cap);
    let mut encoded = encode_first(count);
    while encoded.len() > max_bytes && count > 1 {
        count = (count * 9 / 10).max(1);
        encoded = encode_first(count);
    }
    if encoded.len() > max_bytes {
        // One element that still will not fit cannot be represented at all.
        return Params {
            p,
            m: range,
            data: Vec::new(),
            included_count: 0,
        };
    }

    let included_count = if encoded.is_empty() { 0 } else { count };
    Params {
        p,
        m: range,
        data: encoded,
        included_count,
    }
}

/// Golomb-Rice encodes strictly increasing values as deltas.
///
/// For each delta `x`: `q = (x - 1) >> p` in unary (that many one-bits then a
/// zero), followed by the `p`-bit remainder `r = (x - 1) & (2^p - 1)`.
fn encode_sorted(sorted: &[u64], p: u32) -> Vec<u8> {
    let mut writer = BitWriter::default();
    let mask: u64 = if p >= 64 { u64::MAX } else { (1u64 << p) - 1 };
    let mut prev = 0u64;
    for &value in sorted {
        let x = value.wrapping_sub(prev);
        prev = value;
        // `normalize_mapped_values` makes the input strictly increasing, so a
        // zero delta cannot reach here. It is guarded anyway because the
        // failure mode is not a wrong answer but a hang: `x - 1` wraps to
        // `u64::MAX`, and the unary quotient becomes roughly 2^64 one-bits.
        debug_assert!(x > 0, "encode_sorted needs strictly increasing values");
        if x == 0 {
            continue;
        }
        let q = x.wrapping_sub(1) >> p;
        let r = x.wrapping_sub(1) & mask;
        writer.write_ones(q);
        writer.write_bit(false);
        writer.write_bits(r, p);
    }
    writer.finish()
}

/// Decodes a filter back to its sorted bucket values.
///
/// Out-of-range parameters return empty rather than decoding garbage. Callers
/// read an empty set as "the peer holds nothing" and send everything, which is
/// the safe direction to fail in.
pub fn decode_to_sorted_set(p: u32, m: u32, data: &[u8]) -> Vec<u64> {
    if !(1..=MAX_P).contains(&p) || m <= 1 {
        return Vec::new();
    }
    let mut values = Vec::new();
    let mut reader = BitReader::new(data);
    let mut acc = 0u64;
    while let Some(q) = reader.read_unary() {
        // A quotient with no remainder behind it is a truncated stream, not a
        // value: stop rather than invent one.
        let Some(r) = reader.read_bits(p) else { break };
        // Saturating rather than wrapping: `q` is bounded by the bit length of
        // `data`, so with `p <= 32` this cannot reach the ceiling for any input
        // that fits the 1024-byte TLV cap. Saturating simply means a crafted
        // oversized filter terminates the loop instead of panicking in debug.
        let x = (q << p).saturating_add(r).saturating_add(1);
        acc = acc.wrapping_add(x);
        if acc >= u64::from(m) {
            break;
        }
        values.push(acc);
    }
    values
}

/// Membership test against a decoded filter.
pub fn contains(sorted_values: &[u64], candidate: u64) -> bool {
    sorted_values.binary_search(&candidate).is_ok()
}

/// MSB-first bit writer. The first bit written lands in bit 7 of byte 0.
#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    cur: u8,
    nbits: u32,
}

impl BitWriter {
    fn write_bit(&mut self, bit: bool) {
        self.cur = (self.cur << 1) | u8::from(bit);
        self.nbits += 1;
        if self.nbits == 8 {
            self.buf.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    fn write_ones(&mut self, count: u64) {
        for _ in 0..count {
            self.write_bit(true);
        }
    }

    fn write_bits(&mut self, value: u64, count: u32) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    /// Flushes the partial byte, left-aligned. The padding bits are zero, which
    /// the reader may decode as extra buckets — harmless, since a spurious
    /// bucket only ever costs a skipped send.
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.buf.push(self.cur << (8 - self.nbits));
            self.cur = 0;
            self.nbits = 0;
        }
        self.buf
    }
}

/// MSB-first bit reader, the exact inverse of `BitWriter`.
struct BitReader<'a> {
    data: &'a [u8],
    idx: usize,
    cur: u8,
    left: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let (cur, left) = match data.first() {
            Some(&byte) => (byte, 8),
            None => (0, 0),
        };
        Self {
            data,
            idx: 0,
            cur,
            left,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.idx >= self.data.len() {
            return None;
        }
        let bit = (self.cur >> 7) & 1 == 1;
        self.cur <<= 1;
        self.left -= 1;
        if self.left == 0 {
            self.idx += 1;
            if let Some(&byte) = self.data.get(self.idx) {
                self.cur = byte;
                self.left = 8;
            }
        }
        Some(bit)
    }

    fn read_unary(&mut self) -> Option<u64> {
        let mut q = 0u64;
        while self.read_bit()? {
            q += 1;
        }
        Some(q)
    }

    fn read_bits(&mut self, count: u32) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..count {
            value = (value << 1) | u64::from(self.read_bit()?);
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_of(byte: u8) -> [u8; PACKET_ID_LEN] {
        [byte; PACKET_ID_LEN]
    }

    #[test]
    fn the_bitstream_matches_a_hand_derived_encoding() {
        // The golden vector. Upstream ships no byte-level vectors — every test
        // in GCSFilterTests.swift is a property test — and a round-trip proves
        // nothing here, because a consistently wrong bit order round-trips
        // perfectly. So the expected bytes are derived by hand and the
        // arithmetic is written out to be checked rather than trusted.
        //
        // p = 3, values [1, 3, 6, 10], so deltas are [1, 2, 3, 4].
        // For each delta x: q = (x-1) >> 3, which is 0 for all four; the unary
        // quotient is therefore just the terminating zero bit, and
        // r = (x-1) & 7 is the low three bits of x-1.
        //
        //   x=1  ->  q=0, r=0  ->  0 000
        //   x=2  ->  q=0, r=1  ->  0 001
        //   x=3  ->  q=0, r=2  ->  0 010
        //   x=4  ->  q=0, r=3  ->  0 011
        //
        // Concatenated MSB-first: 0000 0001 0010 0011
        //                         \_______/ \_______/
        //                           0x01      0x23
        //
        // Exactly 16 bits, so there is no padding to reason about. Written
        // LSB-first the first byte would be 0x80, so this vector fails loudly
        // on the bit order rather than round-tripping through it.
        let encoded = encode_sorted(&[1, 3, 6, 10], 3);
        assert_eq!(encoded, vec![0x01, 0x23]);

        // And back, with m = 4 * 2^3 = 32, the modulus build_filter would pick.
        assert_eq!(decode_to_sorted_set(3, 32, &encoded), vec![1, 3, 6, 10]);
    }

    #[test]
    fn the_hash_clears_the_top_bit() {
        // Ground truth from coreutils, not from this module:
        //
        //   printf '01010101010101010101010101010101' | xxd -r -p | sha256sum
        //     -> cc8cd41cef907c4d216069122c4b89936211361f9050a717a1e37ad1862e952f
        //
        // The first eight bytes big-endian are 0xcc8cd41cef907c4d, whose top bit
        // is set. Masking clears it, giving 0x4c8cd41cef907c4d. An
        // implementation that skips the mask returns the 0xcc form and disagrees
        // with every other client on this ID.
        assert_eq!(h64(&id_of(0x01)), 0x4c8c_d41c_ef90_7c4d);

        //   printf 'abababab...' (16 bytes) | xxd -r -p | sha256sum
        //     -> 5a2cfe8ab935918525d44fd6fd87c70fc83b4f29d1a727672e1b48f380473fc1
        //
        // Top bit already clear, so the mask is a no-op here. Both cases are
        // pinned so the mask cannot be "fixed" in the wrong direction.
        assert_eq!(h64(&id_of(0xAB)), 0x5a2c_fe8a_b935_9185);
    }

    #[test]
    fn a_bucket_is_never_zero() {
        // Upstream's own `bucketAvoidsZeroCandidate` uses an id whose hash is
        // odd, so `% 2` is never 0 and the remap it is named after never runs —
        // the assertion holds whether or not the remap exists. `id_of(0x02)`
        // hashes to 0x292afde3b64e6636, which is even, so this is the case that
        // actually reaches the branch: 0 must come back as 1.
        assert_eq!(h64(&id_of(0x02)) % 2, 0, "the premise of this test");
        assert_eq!(bucket(&id_of(0x02), 2), 1);

        // And directly, without depending on any particular digest.
        assert_eq!(map_hash(10, 5), 1, "a multiple of the modulus remaps to 1");
        assert_eq!(map_hash(7, 5), 2, "anything else is left alone");
    }

    #[test]
    fn normalisation_leaves_a_strictly_increasing_sequence() {
        // Load-bearing rather than tidy. A repeated value would give the
        // encoder a zero delta, whose `x - 1` wraps to u64::MAX and turns the
        // unary quotient into an effectively infinite run of one-bits. The
        // encoder guards that too, but this is where it is supposed to be
        // impossible.
        let normalized = normalize_mapped_values(&[1, 1, 1, 4, 4, 9], 32);
        assert_eq!(normalized, vec![1, 4, 9]);
        for pair in normalized.windows(2) {
            assert!(pair[1] > pair[0], "values must strictly increase");
        }

        // Clamping happens before the comparison, so values at or past the
        // modulus collapse into the last usable slot rather than spilling out.
        let clamped = normalize_mapped_values(&[3, 40, 50], 32);
        assert_eq!(clamped, vec![3, 31]);
        assert!(clamped.iter().all(|&v| v < 32));
    }

    #[test]
    fn derive_p_matches_the_rate_it_is_asked_for() {
        // 1% is the rate the sync config actually uses: ceil(log2(100)) = 7.
        assert_eq!(derive_p(0.01), 7);
        assert_eq!(derive_p(0.5), 2, "clamped to 0.25, ceil(log2(4)) = 2");
        assert_eq!(derive_p(0.25), 2);
        assert!(derive_p(0.0) >= 1, "clamped low end still yields a usable p");
        // A nonsense rate must still produce a parameter the wire accepts,
        // because `decode` refuses anything outside 1..=32 and we would be
        // sending a filter nobody will read.
        assert!((1..=MAX_P).contains(&derive_p(f64::NAN)));
        assert!((1..=MAX_P).contains(&derive_p(-1.0)));
    }

    #[test]
    fn an_id_in_the_filter_is_found_by_its_bucket() {
        let ids: Vec<_> = (0..16u8).map(id_of).collect();
        let params = build_filter(&ids, 400, 0.01);
        let decoded = decode_to_sorted_set(params.p, params.m, &params.data);
        for id in &ids {
            assert!(
                contains(&decoded, bucket(id, params.m)),
                "an id that was encoded must test as present"
            );
        }
    }

    #[test]
    fn an_id_outside_the_filter_is_usually_absent() {
        // "Usually" is the honest word: this is a probabilistic structure at a
        // 1% target rate, so the assertion is on the rate, not on any single
        // id. A filter that claimed everything would sync nothing at all, and
        // that is the failure this catches.
        let ids: Vec<_> = (0..64u8).map(id_of).collect();
        let params = build_filter(&ids, 400, 0.01);
        let decoded = decode_to_sorted_set(params.p, params.m, &params.data);

        let strangers: Vec<_> = (100..=255u8).map(id_of).collect();
        let hits = strangers
            .iter()
            .filter(|id| contains(&decoded, bucket(id, params.m)))
            .count();
        assert!(
            hits * 5 < strangers.len(),
            "{hits} of {} strangers matched; the filter is not discriminating",
            strangers.len()
        );
    }

    #[test]
    fn an_empty_input_produces_a_filter_that_claims_nothing() {
        let params = build_filter(&[], 400, 0.01);
        assert_eq!(params.included_count, 0);
        assert!(params.data.is_empty());
        // m = 1 makes decode refuse, which the responder reads as "send it all".
        assert!(decode_to_sorted_set(params.p, params.m, &params.data).is_empty());
    }

    #[test]
    fn a_tight_budget_trims_the_tail_and_says_how_much_it_kept() {
        let ids: Vec<_> = (0..200u8).map(id_of).collect();
        let params = build_filter(&ids, 32, 0.01);
        assert!(params.data.len() <= 32, "the byte budget is a hard cap");
        assert!(params.included_count > 0);
        assert!(
            params.included_count < ids.len(),
            "32 bytes cannot hold 200 ids"
        );
    }

    #[test]
    fn a_generous_budget_covers_every_id() {
        let ids: Vec<_> = (0..8u8).map(id_of).collect();
        let params = build_filter(&ids, 1024, 0.01);
        assert_eq!(params.included_count, ids.len());
    }

    #[test]
    fn the_kept_prefix_is_the_newest_ids_not_an_arbitrary_subset() {
        // The since-cursor is derived from included_count, so trimming has to
        // drop from the tail. If it dropped by hash order instead, the cursor
        // would claim coverage the filter does not have and those packets would
        // never be re-offered.
        let ids: Vec<_> = (0..200u8).map(id_of).collect();
        let params = build_filter(&ids, 32, 0.01);
        let decoded = decode_to_sorted_set(params.p, params.m, &params.data);

        for id in &ids[..params.included_count] {
            assert!(
                contains(&decoded, bucket(id, params.m)),
                "every id inside the reported coverage must be encoded"
            );
        }
    }

    #[test]
    fn duplicate_ids_collapse_to_one_value() {
        // Upstream's `buildFilterWithDuplicateIdsProducesStableEncoding`. The
        // strictly-increasing normalisation is what does this.
        let ids = vec![id_of(0xAB); 64];
        let params = build_filter(&ids, 128, 0.01);
        let decoded = decode_to_sorted_set(params.p, params.m, &params.data);
        assert!(decoded.len() <= 1);
    }

    #[test]
    fn out_of_range_parameters_decode_to_nothing() {
        let junk = vec![0xFF; 64];
        assert!(decode_to_sorted_set(0, 1000, &junk).is_empty());
        assert!(decode_to_sorted_set(MAX_P + 1, 1000, &junk).is_empty());
        assert!(decode_to_sorted_set(255, u32::MAX, &junk).is_empty());
        assert!(decode_to_sorted_set(8, 0, &junk).is_empty());
        assert!(decode_to_sorted_set(8, 1, &junk).is_empty());
    }

    #[test]
    fn a_truncated_filter_invents_nothing() {
        let ids: Vec<_> = (0..32u8).map(id_of).collect();
        let params = build_filter(&ids, 128, 0.01);
        let full = decode_to_sorted_set(params.p, params.m, &params.data);
        let half = &params.data[..params.data.len() / 2];
        let truncated = decode_to_sorted_set(params.p, params.m, half);
        assert!(truncated.len() <= full.len());
        for value in &truncated {
            assert!(full.contains(value), "truncation must not invent buckets");
        }
    }

    #[test]
    fn a_hostile_filter_terminates_instead_of_panicking() {
        // All-ones is the worst input for the unary quotient: it is the shape
        // that runs the accumulator up fastest. Decoding must return, not trap.
        for p in [1u32, 7, MAX_P] {
            let hostile = vec![0xFF; 1024];
            let decoded = decode_to_sorted_set(p, u32::MAX, &hostile);
            assert!(decoded.len() <= 1, "an all-ones stream encodes one huge x");
        }
    }

    #[test]
    fn decoding_stops_at_the_modulus() {
        // The accumulator passing m is the terminator. Without it, the zero
        // padding at the end of a filter would decode as unbounded extra
        // buckets.
        let encoded = encode_sorted(&[1, 3, 6, 10], 3);
        let tight = decode_to_sorted_set(3, 7, &encoded);
        assert_eq!(tight, vec![1, 3, 6], "10 is at or past m = 7");
    }

    #[test]
    fn the_writer_and_reader_agree_on_partial_bytes() {
        // [1, 3, 8] at p = 2 has deltas [1, 2, 5]. The first two cost 3 bits
        // each (a lone terminating zero plus a 2-bit remainder); the third has
        // q = 1, so it costs 4. That is 10 bits, leaving the second byte 6/8
        // padding — the case where an off-by-one in the flush shows up.
        let encoded = encode_sorted(&[1, 3, 8], 2);
        assert_eq!(encoded, vec![0b0000_0110, 0b0000_0000]);
        let decoded = decode_to_sorted_set(2, 12, &encoded);
        assert_eq!(&decoded[..3], &[1, 3, 8]);
    }
}
