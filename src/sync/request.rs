// src/sync/request.rs
//
// The REQUEST_SYNC (0x21) payload. Port of upstream
// `Models/RequestSyncPacket.swift`.
//
// TLV, with a one-byte tag and a **big-endian** two-byte length. Note that the
// type-flags field inside is little-endian while `m` and `since` are big-endian;
// that inconsistency is upstream's and is called out again at each site.

use super::gcs::MAX_P;
use super::type_flags::SyncTypeFlags;

/// Largest value accepted for the filter payload and the fragment filter.
///
/// The two react differently on overflow, which is deliberate upstream: an
/// oversized `0x03` fails the whole decode, because a filter we cannot read
/// makes the request meaningless. An oversized `0x06` is dropped and the rest of
/// the request is honoured, because a missing fragment filter only widens the
/// answer.
pub const MAX_ACCEPT_BYTES: usize = 1024;

/// Most fragment stream IDs one `0x06` filter may carry.
///
/// Each ID is 16 hex characters plus a separator, so 60 of them encode to
/// `60 * 17 - 1 = 1019` bytes and fit inside `MAX_ACCEPT_BYTES`.
pub const MAX_FRAGMENT_ID_FILTER_COUNT: usize = 60;

const TAG_P: u8 = 0x01;
const TAG_M: u8 = 0x02;
const TAG_DATA: u8 = 0x03;
const TAG_TYPES: u8 = 0x04;
const TAG_SINCE: u8 = 0x05;
const TAG_FRAGMENT_FILTER: u8 = 0x06;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSync {
    /// Golomb-Rice parameter.
    pub p: u32,
    /// Hash range the filter folds into.
    pub m: u32,
    /// The Golomb-Rice bitstream.
    pub data: Vec<u8>,
    /// Which packet types this round covers. Absent means public messages.
    pub types: Option<SyncTypeFlags>,
    /// How far back the filter actually covers.
    ///
    /// Packets older than this are outside the filter but *not* missing, so a
    /// responder must skip them. Without the cursor they look absent and get
    /// re-sent on every single round.
    pub since_timestamp: Option<u64>,
    /// Restricts a fragment round to specific stalled streams.
    pub fragment_id_filter: Option<String>,
}

/// Encodes 8-byte fragment stream IDs into the `0x06` filter string, dropping
/// nothing but the overflow past the count cap.
#[allow(dead_code)] // used by targeted fragment recovery, which the requester drives
pub fn encode_fragment_id_filter(fragment_ids: &[[u8; 8]]) -> Option<String> {
    if fragment_ids.is_empty() {
        return None;
    }
    let tokens: Vec<String> = fragment_ids
        .iter()
        .take(MAX_FRAGMENT_ID_FILTER_COUNT)
        .map(hex::encode)
        .collect();
    Some(tokens.join(","))
}

/// Reads the `0x06` filter back, ignoring malformed tokens rather than failing.
pub fn decode_fragment_id_filter(filter: Option<&str>) -> Option<Vec<[u8; 8]>> {
    let filter = filter?;
    let mut ids = Vec::new();
    for token in filter.split(',').take(MAX_FRAGMENT_ID_FILTER_COUNT) {
        if token.len() != 16 {
            continue;
        }
        let Ok(bytes) = hex::decode(token) else {
            continue;
        };
        let Ok(id) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            continue;
        };
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

impl RequestSync {
    #[allow(dead_code)] // the requesting half builds these; tests build them now
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut put = |tag: u8, value: &[u8]| {
            out.push(tag);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        };

        put(TAG_P, &[(self.p & 0xFF) as u8]);
        // Big-endian, unlike the type flags below.
        put(TAG_M, &self.m.to_be_bytes());
        put(TAG_DATA, &self.data);
        if let Some(bytes) = self.types.and_then(SyncTypeFlags::to_bytes) {
            // Little-endian. Yes, next to two big-endian fields.
            put(TAG_TYPES, &bytes);
        }
        if let Some(since) = self.since_timestamp {
            put(TAG_SINCE, &since.to_be_bytes());
        }
        if let Some(filter) = &self.fragment_id_filter {
            put(TAG_FRAGMENT_FILTER, filter.as_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        Self::decode_with_cap(data, MAX_ACCEPT_BYTES)
    }

    pub fn decode_with_cap(data: &[u8], max_accept_bytes: usize) -> Option<Self> {
        let mut off = 0usize;
        let mut p: Option<u32> = None;
        let mut m: Option<u32> = None;
        let mut payload: Option<Vec<u8>> = None;
        let mut types: Option<SyncTypeFlags> = None;
        let mut since_timestamp: Option<u64> = None;
        let mut fragment_id_filter: Option<String> = None;

        // A tag plus its length is three bytes; a tail shorter than that is
        // tolerated and ignored rather than treated as corruption.
        while off + 3 <= data.len() {
            let tag = data[off];
            off += 1;
            let len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
            off += 2;
            // A value that runs past the end is corruption, not a short read.
            if off + len > data.len() {
                return None;
            }
            let value = &data[off..off + len];
            off += len;

            match tag {
                TAG_P if value.len() == 1 => p = Some(u32::from(value[0])),
                TAG_M if value.len() == 4 => {
                    m = Some(u32::from_be_bytes(value.try_into().ok()?));
                }
                TAG_DATA => {
                    // An unreadable filter makes the whole request meaningless.
                    if value.len() > max_accept_bytes {
                        return None;
                    }
                    payload = Some(value.to_vec());
                }
                TAG_TYPES => {
                    if let Some(decoded) = SyncTypeFlags::from_bytes(value) {
                        types = Some(decoded);
                    }
                }
                TAG_SINCE if value.len() == 8 => {
                    since_timestamp = Some(u64::from_be_bytes(value.try_into().ok()?));
                }
                // Oversized here is survivable, unlike TAG_DATA above: falling
                // through drops the narrowing filter and answers the broader
                // question, which is the direction upstream chose.
                TAG_FRAGMENT_FILTER if value.len() <= max_accept_bytes => {
                    if let Ok(text) = std::str::from_utf8(value) {
                        fragment_id_filter = Some(text.to_string());
                    }
                }
                // Unknown tags, and known tags at the wrong width, are skipped
                // so a newer peer can add fields without breaking us.
                _ => {}
            }
        }

        let p = p?;
        let m = m?;
        let data = payload?;
        if !(1..=MAX_P).contains(&p) || m == 0 {
            return None;
        }
        Some(Self {
            p,
            m,
            data,
            types,
            since_timestamp,
            fragment_id_filter,
        })
    }

    /// The types this request covers, applying the documented default.
    pub fn requested_types(&self) -> SyncTypeFlags {
        self.types.unwrap_or_else(SyncTypeFlags::public_messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    fn minimal() -> RequestSync {
        RequestSync {
            p: 8,
            m: 4096,
            data: vec![0x01, 0x02],
            types: None,
            since_timestamp: None,
            fragment_id_filter: None,
        }
    }

    #[test]
    fn the_acceptance_limits_are_the_ones_upstream_ships() {
        assert_eq!(MAX_ACCEPT_BYTES, 1024, "upstream maxAcceptBytes");
        assert_eq!(
            MAX_FRAGMENT_ID_FILTER_COUNT, 60,
            "upstream maxFragmentIdFilterCount"
        );

        // The doc comment on `MAX_FRAGMENT_ID_FILTER_COUNT` justifies 60 with
        // arithmetic against `MAX_ACCEPT_BYTES` — sixteen hex characters plus a
        // separator each, so `60 * 17 - 1 = 1019` fits inside 1024. The two
        // constants can be edited independently, so the claim is checked rather
        // than only written down.
        let widest = MAX_FRAGMENT_ID_FILTER_COUNT * 17 - 1;
        assert_eq!(widest, 1019);
        assert!(
            widest <= MAX_ACCEPT_BYTES,
            "the widest fragment filter must survive its own decoder"
        );

        // And demonstrated, not just computed.
        let ids: Vec<[u8; 8]> = (0..MAX_FRAGMENT_ID_FILTER_COUNT as u64)
            .map(|i| i.to_be_bytes())
            .collect();
        let encoded = encode_fragment_id_filter(&ids).expect("non-empty");
        assert_eq!(encoded.len(), widest);
        assert_eq!(
            decode_fragment_id_filter(Some(&encoded)).unwrap().len(),
            MAX_FRAGMENT_ID_FILTER_COUNT
        );
    }

    #[test]
    fn the_encoding_matches_a_hand_written_tlv() {
        // Golden bytes, laid out field by field so the length prefixes and the
        // endianness of each field are checkable by eye rather than by running
        // the encoder against itself.
        //
        //   01 0001 08                 P = 8
        //   02 0004 00001000           M = 4096, big-endian
        //   03 0002 0102               filter bytes
        let encoded = minimal().encode();
        assert_eq!(
            encoded,
            vec![
                0x01, 0x00, 0x01, 0x08, //
                0x02, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00, //
                0x03, 0x00, 0x02, 0x01, 0x02,
            ]
        );
    }

    #[test]
    fn the_optional_fields_encode_in_tag_order_with_their_own_endianness() {
        let request = RequestSync {
            types: Some(SyncTypeFlags::public_messages()),
            since_timestamp: Some(1),
            ..minimal()
        };
        let encoded = request.encode();
        // After the three mandatory fields:
        //   04 0001 03                 announce|message, little-endian
        //   05 0008 0000000000000001    since = 1, big-endian
        assert_eq!(
            &encoded[16..],
            &[
                0x04, 0x00, 0x01, 0x03, //
                0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]
        );
        assert_eq!(RequestSync::decode(&encoded), Some(request));
    }

    #[test]
    fn a_full_request_round_trips() {
        let request = RequestSync {
            p: 7,
            m: 12_800,
            data: vec![0xAB; 64],
            types: Some(SyncTypeFlags::from_types(&[MessageType::Fragment])),
            since_timestamp: Some(1_785_000_000_000),
            fragment_id_filter: Some("0102030405060708,1112131415161718".to_string()),
        };
        assert_eq!(RequestSync::decode(&request.encode()), Some(request));
    }

    #[test]
    fn the_parameters_the_filter_cannot_use_are_refused() {
        // Mirrors upstream's `requestSyncPacketDecodeRejectsOversizedP`.
        assert!(RequestSync::decode(&minimal().encode()).is_some());

        let oversized = RequestSync { p: 200, ..minimal() };
        assert_eq!(RequestSync::decode(&oversized.encode()), None);

        let zero_p = RequestSync { p: 0, ..minimal() };
        assert_eq!(RequestSync::decode(&zero_p.encode()), None);

        let zero_m = RequestSync { m: 0, ..minimal() };
        assert_eq!(RequestSync::decode(&zero_m.encode()), None);
    }

    #[test]
    fn a_request_missing_a_mandatory_field_is_refused() {
        for drop_tag in [TAG_P, TAG_M, TAG_DATA] {
            let encoded = minimal().encode();
            // Rebuild without that field by decoding tag by tag.
            let mut rebuilt = Vec::new();
            let mut off = 0;
            while off + 3 <= encoded.len() {
                let tag = encoded[off];
                let len = u16::from_be_bytes([encoded[off + 1], encoded[off + 2]]) as usize;
                let end = off + 3 + len;
                if tag != drop_tag {
                    rebuilt.extend_from_slice(&encoded[off..end]);
                }
                off = end;
            }
            assert_eq!(
                RequestSync::decode(&rebuilt),
                None,
                "a request without tag {drop_tag:#04x} cannot be answered"
            );
        }
    }

    #[test]
    fn an_unknown_tag_is_skipped_rather_than_fatal() {
        // Forward compatibility: a newer peer adding a field must not make the
        // whole request unreadable to us.
        let mut encoded = minimal().encode();
        encoded.extend_from_slice(&[0x7F, 0x00, 0x03, 0xDE, 0xAD, 0xBE]);
        assert_eq!(RequestSync::decode(&encoded), Some(minimal()));
    }

    #[test]
    fn a_value_running_past_the_end_is_corruption() {
        // The encoding is 16 bytes:
        //   00..04  01 0001 08          P
        //   04..11  02 0004 00001000    M
        //   11..16  03 0002 0102        data, whose length sits at [12..14]
        // so overstating the data length is the overrun to test.
        let mut encoded = minimal().encode();
        assert_eq!(encoded.len(), 16);
        assert_eq!(encoded[11], TAG_DATA, "the data field starts here");
        encoded[12] = 0x00;
        encoded[13] = 0x40; // claims 64 bytes, only 2 follow
        assert_eq!(RequestSync::decode(&encoded), None);

        // One byte past the end is still corruption, not a short read.
        let mut just_over = minimal().encode();
        just_over[13] = 0x03; // claims 3 bytes, only 2 follow
        assert_eq!(RequestSync::decode(&just_over), None);
    }

    #[test]
    fn an_empty_filter_is_a_peer_that_holds_nothing() {
        // Zero-length 0x03 is legal and means "I have none of these", which the
        // responder answers by sending everything. Distinct from a malformed
        // request, which it must not answer at all.
        let empty = RequestSync {
            data: Vec::new(),
            ..minimal()
        };
        let decoded = RequestSync::decode(&empty.encode()).expect("legal request");
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn a_truncated_tail_shorter_than_a_header_is_ignored() {
        let mut encoded = minimal().encode();
        encoded.extend_from_slice(&[0x09, 0x00]);
        assert_eq!(RequestSync::decode(&encoded), Some(minimal()));
    }

    #[test]
    fn an_oversized_filter_fails_but_an_oversized_fragment_list_only_drops() {
        // The asymmetry is upstream's and it is deliberate, so it gets a test
        // rather than a comment alone.
        let huge_filter = RequestSync {
            data: vec![0u8; MAX_ACCEPT_BYTES + 1],
            ..minimal()
        };
        assert_eq!(RequestSync::decode(&huge_filter.encode()), None);

        let huge_fragments = RequestSync {
            fragment_id_filter: Some("a".repeat(MAX_ACCEPT_BYTES + 1)),
            ..minimal()
        };
        let decoded = RequestSync::decode(&huge_fragments.encode()).expect("still readable");
        assert_eq!(decoded.fragment_id_filter, None);
        assert_eq!(decoded.data, huge_fragments.data);
    }

    #[test]
    fn absent_types_mean_public_messages() {
        let decoded = RequestSync::decode(&minimal().encode()).unwrap();
        assert_eq!(decoded.types, None);
        assert_eq!(decoded.requested_types(), SyncTypeFlags::public_messages());
    }

    #[test]
    fn the_fragment_filter_round_trips_and_caps_its_length() {
        let ids: Vec<[u8; 8]> = (0..3u8).map(|i| [i; 8]).collect();
        let encoded = encode_fragment_id_filter(&ids).expect("non-empty");
        assert_eq!(
            encoded,
            "0000000000000000,0101010101010101,0202020202020202"
        );
        assert_eq!(decode_fragment_id_filter(Some(&encoded)), Some(ids));

        // Past the cap the tail is dropped, and the encoded form still fits the
        // acceptance limit.
        let many: Vec<[u8; 8]> = (0..200u16).map(|i| (i as u64).to_be_bytes()).collect();
        let encoded = encode_fragment_id_filter(&many).expect("non-empty");
        assert!(encoded.len() <= MAX_ACCEPT_BYTES, "{}", encoded.len());
        assert_eq!(
            decode_fragment_id_filter(Some(&encoded)).unwrap().len(),
            MAX_FRAGMENT_ID_FILTER_COUNT
        );
    }

    #[test]
    fn a_malformed_fragment_token_is_skipped_not_fatal() {
        let filter = "0102030405060708,nothex,zz,1112131415161718";
        assert_eq!(
            decode_fragment_id_filter(Some(filter)),
            Some(vec![
                [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            ])
        );
        assert_eq!(decode_fragment_id_filter(Some("")), None);
        assert_eq!(decode_fragment_id_filter(None), None);
        assert_eq!(encode_fragment_id_filter(&[]), None);
    }
}
