// src/fragment.rs
//
// Reassembly of fragmented mesh packets (MessageType::Fragment, 0x20).
//
// A BLE characteristic write is small, so anything larger than a few hundred
// bytes is split. Each fragment payload is:
//
//   [0..8]   fragment id, big-endian u64
//   [8..10]  index,  big-endian u16
//   [10..12] total,  big-endian u16
//   [12]     type of the packet being carried
//   [13..]   this fragment's slice
//
// The reassembled bytes are a *complete encoded packet*, not a bare payload, so
// flags, compression and signatures all survive the trip.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::protocol::Packet;

/// Upstream's `maxFramedFileBytes`: 1 MiB of payload plus TLV and frame
/// overhead. Anything claiming more is dropped rather than buffered.
pub const MAX_ASSEMBLED_BYTES: usize = 1024 * 1024 + 18 + 2 * 65535 + 16 + 8 + 8 + 64;
/// `bleMaxInFlightAssemblies`
const MAX_IN_FLIGHT: usize = 128;
/// `bleFragmentLifetimeSeconds`
const ASSEMBLY_LIFETIME: Duration = Duration::from_secs(30);
/// Upstream's sanity bound on the fragment count.
const MAX_FRAGMENTS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    /// Sender's 8-byte peer ID. Keyed with the id because two peers can pick
    /// the same fragment id without colliding.
    pub sender: [u8; 8],
    pub id: u64,
}

#[derive(Debug, Clone)]
pub struct FragmentHeader {
    pub key: FragmentKey,
    pub index: usize,
    pub total: usize,
    pub original_type: u8,
    pub data: Vec<u8>,
}

/// Parses a fragment packet, rejecting anything malformed or absurd.
/// Bytes of file data per fragment.
///
/// This is a transmission choice, not a protocol constant: the receiver
/// reassembles whatever arrives, keyed by index and total, so any slice size
/// works. It is sized so the finished frame lands in the 256-byte padding
/// bucket, which is the only bucket we have live evidence a phone accepts —
/// announces use it. Larger slices would mean fewer writes and a faster
/// transfer, and are very likely fine, but "very likely" is not evidence.
/// Raise it once the negotiated MTU is actually observable.
///
///   256 bucket - 16 (the AEAD allowance in `optimal_block_size`)
///       - 14 (v1 packet header) - 13 (fragment header) = 213
pub const SLICE_BYTES: usize = 213;

/// Splits an encoded packet into fragment payloads.
///
/// `body` is a whole encoded packet, not a bare payload: reassembly hands the
/// joined bytes straight back to the packet decoder, so what goes in has to be
/// something that decodes on its own.
pub fn split(id: u64, original_type: u8, body: &[u8], slice_bytes: usize) -> Vec<Vec<u8>> {
    if body.is_empty() || slice_bytes == 0 {
        return Vec::new();
    }
    let total = body.len().div_ceil(slice_bytes);
    if total > MAX_FRAGMENTS {
        return Vec::new();
    }

    body.chunks(slice_bytes)
        .enumerate()
        .map(|(index, slice)| {
            let mut payload = Vec::with_capacity(13 + slice.len());
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&(index as u16).to_be_bytes());
            payload.extend_from_slice(&(total as u16).to_be_bytes());
            payload.push(original_type);
            payload.extend_from_slice(slice);
            payload
        })
        .collect()
}

pub fn parse(packet: &Packet) -> Option<FragmentHeader> {
    // 8 id + 2 index + 2 total + 1 type
    if packet.payload.len() < 13 {
        return None;
    }
    let id = u64::from_be_bytes(packet.payload[0..8].try_into().ok()?);
    let index = u16::from_be_bytes(packet.payload[8..10].try_into().ok()?) as usize;
    let total = u16::from_be_bytes(packet.payload[10..12].try_into().ok()?) as usize;

    if total == 0 || total > MAX_FRAGMENTS || index >= total {
        return None;
    }

    Some(FragmentHeader {
        key: FragmentKey {
            sender: packet.sender_id,
            id,
        },
        index,
        total,
        original_type: packet.payload[12],
        data: packet.payload[13..].to_vec(),
    })
}

struct Assembly {
    /// Slices by index; `None` until that fragment arrives.
    pieces: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
    started: Instant,
}

/// Collects fragments until a packet is whole.
pub struct Assembler {
    in_flight: HashMap<FragmentKey, Assembly>,
}

#[derive(Debug, PartialEq)]
pub enum Append {
    /// Stored; more fragments needed.
    Pending { have: usize, total: usize },
    /// All fragments in: the reassembled packet bytes.
    Complete(Vec<u8>),
    /// Rejected — duplicate, oversized, or too many assemblies in flight.
    Rejected(&'static str),
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
        }
    }

    pub fn append(&mut self, header: FragmentHeader) -> Append {
        self.expire();

        let is_new = !self.in_flight.contains_key(&header.key);
        if is_new && self.in_flight.len() >= MAX_IN_FLIGHT {
            // A flood of first-fragments would otherwise pin memory until the
            // lifetime expired; drop the newcomer rather than the ones making
            // progress.
            return Append::Rejected("too many assemblies in flight");
        }

        let assembly = self
            .in_flight
            .entry(header.key.clone())
            .or_insert_with(|| Assembly {
                pieces: vec![None; header.total],
                received: 0,
                bytes: 0,
                started: Instant::now(),
            });

        // A peer that changes its mind about the total mid-transfer is either
        // broken or hostile; either way the buffer is no longer meaningful.
        if assembly.pieces.len() != header.total {
            self.in_flight.remove(&header.key);
            return Append::Rejected("fragment count changed mid-assembly");
        }
        if assembly.pieces[header.index].is_some() {
            return Append::Rejected("duplicate fragment");
        }
        if assembly.bytes + header.data.len() > MAX_ASSEMBLED_BYTES {
            self.in_flight.remove(&header.key);
            return Append::Rejected("assembly exceeds the size limit");
        }

        assembly.bytes += header.data.len();
        assembly.received += 1;
        assembly.pieces[header.index] = Some(header.data);

        if assembly.received < assembly.pieces.len() {
            return Append::Pending {
                have: assembly.received,
                total: assembly.pieces.len(),
            };
        }

        let assembly = self.in_flight.remove(&header.key).expect("just inserted");
        let mut bytes = Vec::with_capacity(assembly.bytes);
        for piece in assembly.pieces.into_iter() {
            bytes.extend_from_slice(&piece.expect("all pieces present"));
        }
        Append::Complete(bytes)
    }

    /// Drops assemblies whose remaining fragments never arrived.
    fn expire(&mut self) {
        self.in_flight
            .retain(|_, assembly| assembly.started.elapsed() < ASSEMBLY_LIFETIME);
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    /// Builds the fragment packets carrying `inner`, as a sender would.
    fn fragments_of(inner: &[u8], sender: [u8; 8], id: u64, piece_size: usize) -> Vec<Packet> {
        let chunks: Vec<&[u8]> = inner.chunks(piece_size).collect();
        let total = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                let mut payload = Vec::new();
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&(index as u16).to_be_bytes());
                payload.extend_from_slice(&(total as u16).to_be_bytes());
                payload.push(MessageType::Message as u8);
                payload.extend_from_slice(chunk);
                Packet::new(MessageType::Fragment, sender, payload, 7)
            })
            .collect()
    }

    #[test]
    fn parses_the_upstream_header_layout() {
        let packets = fragments_of(b"hello world", [1; 8], 0x0102030405060708, 4);
        let header = parse(&packets[1]).expect("valid fragment");
        assert_eq!(header.key.id, 0x0102030405060708);
        assert_eq!(header.key.sender, [1; 8]);
        assert_eq!(header.index, 1);
        assert_eq!(header.total, 3);
        assert_eq!(header.original_type, MessageType::Message as u8);
        assert_eq!(header.data, b"o wo");
    }

    #[test]
    fn rejects_malformed_fragments() {
        // Too short for the header at all.
        let short = Packet::new(MessageType::Fragment, [1; 8], vec![0; 12], 7);
        assert!(parse(&short).is_none());

        // index >= total is nonsense and would panic an unchecked implementation.
        let mut payload = vec![0u8; 13];
        payload[9] = 5; // index 5
        payload[11] = 2; // total 2
        let bad = Packet::new(MessageType::Fragment, [1; 8], payload, 7);
        assert!(parse(&bad).is_none());

        // total = 0
        let zero = Packet::new(MessageType::Fragment, [1; 8], vec![0u8; 13], 7);
        assert!(parse(&zero).is_none());
    }

    #[test]
    fn reassembles_in_order() {
        let inner = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut assembler = Assembler::new();
        let packets = fragments_of(&inner, [2; 8], 42, 7);

        let mut completed = None;
        for packet in &packets {
            match assembler.append(parse(packet).unwrap()) {
                Append::Complete(bytes) => completed = Some(bytes),
                Append::Pending { .. } => {}
                Append::Rejected(reason) => panic!("rejected: {reason}"),
            }
        }
        assert_eq!(completed.unwrap(), inner);
        assert_eq!(assembler.in_flight(), 0, "buffer released on completion");
    }

    #[test]
    fn reassembles_out_of_order() {
        // The mesh does not promise ordering, and a relay may reorder freely.
        let inner = b"0123456789abcdefghij".to_vec();
        let mut assembler = Assembler::new();
        let mut packets = fragments_of(&inner, [3; 8], 7, 3);
        packets.reverse();

        let mut completed = None;
        for packet in &packets {
            if let Append::Complete(bytes) = assembler.append(parse(packet).unwrap()) {
                completed = Some(bytes);
            }
        }
        assert_eq!(completed.unwrap(), inner);
    }

    #[test]
    fn two_senders_do_not_collide_on_the_same_id() {
        // Fragment ids are chosen independently, so the sender is part of the key.
        let mut assembler = Assembler::new();
        let alice = fragments_of(b"aaaaaa", [1; 8], 99, 3);
        let bob = fragments_of(b"bbbbbb", [2; 8], 99, 3);

        assembler.append(parse(&alice[0]).unwrap());
        assembler.append(parse(&bob[0]).unwrap());
        assert_eq!(assembler.in_flight(), 2);

        let a = assembler.append(parse(&alice[1]).unwrap());
        let b = assembler.append(parse(&bob[1]).unwrap());
        assert_eq!(a, Append::Complete(b"aaaaaa".to_vec()));
        assert_eq!(b, Append::Complete(b"bbbbbb".to_vec()));
    }

    #[test]
    fn duplicates_are_rejected_not_double_counted() {
        let mut assembler = Assembler::new();
        let packets = fragments_of(b"abcdef", [4; 8], 1, 3);
        assembler.append(parse(&packets[0]).unwrap());
        assert_eq!(
            assembler.append(parse(&packets[0]).unwrap()),
            Append::Rejected("duplicate fragment")
        );
        // The genuine second fragment still completes it.
        assert_eq!(
            assembler.append(parse(&packets[1]).unwrap()),
            Append::Complete(b"abcdef".to_vec())
        );
    }

    #[test]
    fn a_changed_total_abandons_the_assembly() {
        let mut assembler = Assembler::new();
        let first = fragments_of(b"abcdef", [5; 8], 1, 3);
        assembler.append(parse(&first[0]).unwrap());

        let mut header = parse(&first[1]).unwrap();
        header.total = 9; // same key, different story
        assert_eq!(
            assembler.append(header),
            Append::Rejected("fragment count changed mid-assembly")
        );
        assert_eq!(assembler.in_flight(), 0);
    }

    #[test]
    fn the_in_flight_count_is_capped() {
        let mut assembler = Assembler::new();
        for index in 0..MAX_IN_FLIGHT + 5 {
            let sender = [(index % 251) as u8; 8];
            let packets = fragments_of(b"abcdef", sender, index as u64, 3);
            assembler.append(parse(&packets[0]).unwrap());
        }
        assert!(assembler.in_flight() <= MAX_IN_FLIGHT);
    }

    #[test]
    fn a_reassembled_packet_decodes_with_its_flags_intact() {
        // The bytes on the wire are a whole packet, which is what lets a
        // compressed or signed inner packet survive fragmentation.
        let inner = Packet::new(MessageType::Message, [9; 8], b"payload".to_vec(), 5);
        let encoded = inner.encode().expect("encodes");

        let mut assembler = Assembler::new();
        let mut completed = None;
        for packet in fragments_of(&encoded, [9; 8], 77, 64) {
            if let Append::Complete(bytes) = assembler.append(parse(&packet).unwrap()) {
                completed = Some(bytes);
            }
        }

        let decoded = Packet::decode(&completed.expect("completed")).expect("decodes");
        assert_eq!(decoded.msg_type, MessageType::Message as u8);
        assert_eq!(decoded.payload, b"payload");
        assert_eq!(decoded.sender_id, [9; 8]);
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use crate::protocol::MessageType;

    #[test]
    fn splitting_then_reassembling_returns_the_original() {
        // The pair has to be exact: a fragmenter that disagrees with our own
        // assembler would also disagree with everyone else's.
        let body: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let pieces = split(0xABCD, MessageType::FileTransfer as u8, &body, SLICE_BYTES);
        assert_eq!(pieces.len(), body.len().div_ceil(SLICE_BYTES));

        let mut assembler = Assembler::new();
        let mut finished = None;
        for payload in pieces {
            let packet = Packet::new(MessageType::Fragment, [9; 8], payload, 7);
            let header = parse(&packet).expect("our own fragment must parse");
            if let Append::Complete(data) = assembler.append(header) {
                finished = Some(data);
            }
        }
        assert_eq!(finished.expect("must complete"), body);
    }

    #[test]
    fn the_original_type_survives_the_trip() {
        let pieces = split(1, MessageType::FileTransfer as u8, b"hello", SLICE_BYTES);
        let packet = Packet::new(MessageType::Fragment, [1; 8], pieces[0].clone(), 7);
        assert_eq!(
            parse(&packet).unwrap().original_type,
            MessageType::FileTransfer as u8
        );
    }

    #[test]
    fn every_fragment_fits_the_bucket_we_have_evidence_for() {
        // If a fragment grows past the 256-byte bucket it silently starts
        // relying on an MTU nobody measured.
        let body = vec![7u8; 5000];
        for payload in split(2, 0x22, &body, SLICE_BYTES) {
            let encoded = Packet::new(MessageType::Fragment, [1; 8], payload, 7)
                .encode()
                .unwrap();
            assert!(
                encoded.len() <= 256,
                "fragment frame grew to {} bytes",
                encoded.len()
            );
        }
    }

    #[test]
    fn indices_are_dense_and_totals_agree() {
        let body = vec![3u8; SLICE_BYTES * 4 + 1];
        let pieces = split(3, 0x22, &body, SLICE_BYTES);
        assert_eq!(pieces.len(), 5);
        for (expected, payload) in pieces.iter().enumerate() {
            let packet = Packet::new(MessageType::Fragment, [1; 8], payload.clone(), 7);
            let header = parse(&packet).unwrap();
            assert_eq!(header.index, expected);
            assert_eq!(header.total, 5);
        }
    }

    #[test]
    fn a_body_that_would_need_too_many_fragments_is_refused() {
        // Better to refuse than to emit a run the receiver will reject partway
        // through, having already spent the airtime.
        let body = vec![0u8; MAX_FRAGMENTS + 1];
        assert!(split(4, 0x22, &body, 1).is_empty());
    }

    #[test]
    fn nothing_to_send_produces_nothing() {
        assert!(split(5, 0x22, b"", SLICE_BYTES).is_empty());
    }

    #[test]
    fn a_body_smaller_than_one_slice_is_a_single_fragment() {
        let pieces = split(6, 0x22, b"tiny", SLICE_BYTES);
        assert_eq!(pieces.len(), 1);
    }
}
