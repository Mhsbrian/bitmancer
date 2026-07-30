// src/sync/type_flags.rs
//
// Which message types a sync round covers. Port of upstream
// `Sync/SyncTypeFlags.swift`, whose comments say the bit table matches the
// Android client's, so this is a three-way agreement and not ours to renumber.

use crate::protocol::MessageType;

/// Bitfield of the types a REQUEST_SYNC round asks about.
///
/// Note the encoding is **little-endian** while `M` and `sinceTimestamp` in the
/// same TLV payload are big-endian. That inconsistency is upstream's, and
/// matching it is the whole job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncTypeFlags {
    raw: u64,
}

/// Bit index for each type that gossip sync will carry.
///
/// The types deliberately absent are as load-bearing as the ones present, and
/// upstream gives a reason for each:
///
/// - `CourierEnvelope` — a directed deposit between trusted peers; gossip would
///   spread it to everyone.
/// - `Ping` / `Pong` — ephemeral directed probes; a replayed one is a stale
///   question nobody can answer.
/// - `NostrCarrier` — ephemeral live gateway traffic; replaying extends its
///   lifetime and wastes airtime.
/// - `VoiceFrame` — only useful now. Receivers drop stale audio anyway.
fn bit_index(message_type: MessageType) -> Option<u32> {
    Some(match message_type {
        MessageType::Announce => 0,
        MessageType::Message => 1,
        MessageType::Leave => 2,
        MessageType::NoiseHandshake => 3,
        MessageType::NoiseEncrypted => 4,
        MessageType::Fragment => 5,
        MessageType::RequestSync => 6,
        MessageType::FileTransfer => 7,
        MessageType::BoardPost => 8,
        MessageType::PrekeyBundle => 9,
        MessageType::GroupMessage => 10,
        MessageType::CourierEnvelope
        | MessageType::Ping
        | MessageType::Pong
        | MessageType::NostrCarrier
        | MessageType::VoiceFrame => return None,
    })
}

/// Every type in bit order, so the mask and the reverse lookup stay derived from
/// one table rather than being written twice.
const MAPPED_TYPES: [MessageType; 11] = [
    MessageType::Announce,
    MessageType::Message,
    MessageType::Leave,
    MessageType::NoiseHandshake,
    MessageType::NoiseEncrypted,
    MessageType::Fragment,
    MessageType::RequestSync,
    MessageType::FileTransfer,
    MessageType::BoardPost,
    MessageType::PrekeyBundle,
    MessageType::GroupMessage,
];

impl SyncTypeFlags {
    /// Builds from a raw bitfield, dropping any bit with no type behind it.
    ///
    /// Masking at construction is upstream's design and worth keeping: an
    /// unmasked phantom bit would survive `to_bytes`, re-serialise onto the
    /// wire, and match nothing — an "accepted but does nothing" state that is
    /// invisible until someone wonders why a round returned empty. A newer peer
    /// advertising a type we do not know lands here too, and is simply ignored.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            raw: raw & Self::known_mask(),
        }
    }

    fn known_mask() -> u64 {
        MAPPED_TYPES.iter().fold(0u64, |mask, &message_type| {
            match bit_index(message_type) {
                Some(bit) => mask | (1u64 << bit),
                None => mask,
            }
        })
    }

    pub fn from_types(types: &[MessageType]) -> Self {
        let raw = types.iter().fold(0u64, |raw, &message_type| {
            match bit_index(message_type) {
                Some(bit) => raw | (1u64 << bit),
                None => raw,
            }
        });
        Self::from_raw(raw)
    }

    /// The default set when a request carries no `0x04` TLV, matching upstream's
    /// `publicMessages`.
    pub fn public_messages() -> Self {
        Self::from_types(&[MessageType::Announce, MessageType::Message])
    }

    pub fn contains(self, message_type: MessageType) -> bool {
        match bit_index(message_type) {
            Some(bit) => self.raw & (1u64 << bit) != 0,
            None => false,
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(self) -> bool {
        self.raw == 0
    }

    #[allow(dead_code)]
    pub fn raw(self) -> u64 {
        self.raw
    }

    /// Wire form: little-endian, trailing zero bytes trimmed, 1–8 bytes.
    ///
    /// An empty set encodes as `None` rather than an empty field — upstream
    /// omits the TLV entirely, and a zero-length `0x04` would be read by the
    /// far side as "no types named", which then defaults to public messages.
    /// Those are not the same request.
    #[allow(dead_code)] // written by the requester; read by us
    pub fn to_bytes(self) -> Option<Vec<u8>> {
        if self.raw == 0 {
            return None;
        }
        let mut bytes = self.raw.to_le_bytes().to_vec();
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        // `raw != 0` guarantees at least one byte survives.
        debug_assert!(!bytes.is_empty());
        Some(bytes)
    }

    /// Reads the wire form. Accepts 1–8 bytes; anything else is malformed.
    ///
    /// Widening is deliberately backward compatible: bit 8 (`BoardPost`) is the
    /// first that needs a second byte, and an older peer decoding two bytes
    /// simply finds a bit it has no type for and ignores that type.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > 8 {
            return None;
        }
        let raw = bytes
            .iter()
            .enumerate()
            .fold(0u64, |raw, (index, &byte)| raw | (u64::from(byte) << (index * 8)));
        Some(Self::from_raw(raw))
    }

    pub fn to_types(self) -> Vec<MessageType> {
        MAPPED_TYPES
            .iter()
            .copied()
            .filter(|&message_type| self.contains(message_type))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bit_table_matches_the_one_upstream_publishes() {
        // Pinned individually rather than as a set, because an off-by-one in
        // the middle of the table still produces a plausible-looking set.
        let expected = [
            (MessageType::Announce, 0u32),
            (MessageType::Message, 1),
            (MessageType::Leave, 2),
            (MessageType::NoiseHandshake, 3),
            (MessageType::NoiseEncrypted, 4),
            (MessageType::Fragment, 5),
            (MessageType::RequestSync, 6),
            (MessageType::FileTransfer, 7),
            (MessageType::BoardPost, 8),
            (MessageType::PrekeyBundle, 9),
            (MessageType::GroupMessage, 10),
        ];
        for (message_type, bit) in expected {
            assert_eq!(
                bit_index(message_type),
                Some(bit),
                "{message_type:?} must sit on bit {bit}"
            );
        }
    }

    #[test]
    fn the_types_gossip_must_never_carry_have_no_bit() {
        for message_type in [
            MessageType::CourierEnvelope,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::NostrCarrier,
            MessageType::VoiceFrame,
        ] {
            assert_eq!(bit_index(message_type), None, "{message_type:?}");
            // And asking for them can never be satisfied by accident.
            assert!(!SyncTypeFlags::from_raw(u64::MAX).contains(message_type));
        }
    }

    #[test]
    fn the_wire_form_is_little_endian() {
        // Bit 8 is the first that needs a second byte, and it is the case that
        // catches a big-endian writer: little-endian puts the low byte first,
        // so announce+board is [0x01, 0x01] and never [0x01, 0x01] reversed
        // into a single byte or [0x00, 0x01].
        let flags = SyncTypeFlags::from_types(&[MessageType::Announce, MessageType::BoardPost]);
        assert_eq!(flags.to_bytes(), Some(vec![0x01, 0x01]));

        // A single low bit stays one byte.
        let announce = SyncTypeFlags::from_types(&[MessageType::Announce]);
        assert_eq!(announce.to_bytes(), Some(vec![0x01]));

        // Bit 7 is the last that fits in one byte; bit 8 forces the second.
        let files = SyncTypeFlags::from_types(&[MessageType::FileTransfer]);
        assert_eq!(files.to_bytes(), Some(vec![0x80]));
        let board = SyncTypeFlags::from_types(&[MessageType::BoardPost]);
        assert_eq!(board.to_bytes(), Some(vec![0x00, 0x01]));
    }

    #[test]
    fn public_messages_is_announce_and_message() {
        let flags = SyncTypeFlags::public_messages();
        assert!(flags.contains(MessageType::Announce));
        assert!(flags.contains(MessageType::Message));
        assert!(!flags.contains(MessageType::Fragment));
        assert_eq!(flags.to_bytes(), Some(vec![0b0000_0011]));
    }

    #[test]
    fn an_empty_set_is_absent_rather_than_a_zero_byte() {
        // A zero-length or zero-valued 0x04 would be read as "no types named",
        // which the responder turns back into public messages — a different
        // request from the one that was made.
        assert_eq!(SyncTypeFlags::default().to_bytes(), None);
        assert_eq!(SyncTypeFlags::from_raw(0).to_bytes(), None);
    }

    #[test]
    fn a_bit_with_no_type_behind_it_is_dropped_on_the_way_in() {
        // Bit 11 is unassigned today. A newer peer setting it must not leave a
        // phantom in the set that re-serialises and matches nothing.
        let with_phantom = SyncTypeFlags::from_raw((1 << 11) | 1);
        assert_eq!(with_phantom.raw(), 1);
        assert_eq!(with_phantom.to_bytes(), Some(vec![0x01]));
        assert!(with_phantom.contains(MessageType::Announce));
    }

    #[test]
    fn the_wire_form_round_trips_at_every_accepted_width() {
        for flags in [
            SyncTypeFlags::from_types(&[MessageType::Announce]),
            SyncTypeFlags::public_messages(),
            SyncTypeFlags::from_types(&[MessageType::BoardPost]),
            SyncTypeFlags::from_types(&[MessageType::GroupMessage]),
            SyncTypeFlags::from_raw(u64::MAX),
        ] {
            let bytes = flags.to_bytes().expect("non-empty");
            assert!((1..=8).contains(&bytes.len()));
            assert_eq!(SyncTypeFlags::from_bytes(&bytes), Some(flags));
        }
    }

    #[test]
    fn a_field_outside_one_to_eight_bytes_is_refused() {
        assert_eq!(SyncTypeFlags::from_bytes(&[]), None);
        assert_eq!(SyncTypeFlags::from_bytes(&[0u8; 9]), None);
        assert!(SyncTypeFlags::from_bytes(&[0u8; 8]).is_some());
    }

    #[test]
    fn an_old_peer_reading_a_wider_field_keeps_the_bits_it_knows() {
        // Two bytes carrying announce (bit 0) and a type from the future
        // (bit 11): the known bit survives, the unknown one does not.
        let decoded = SyncTypeFlags::from_bytes(&[0x01, 0x08]).expect("valid width");
        assert!(decoded.contains(MessageType::Announce));
        assert_eq!(decoded.raw(), 1);
    }

    #[test]
    fn to_types_lists_in_bit_order() {
        let flags = SyncTypeFlags::from_types(&[
            MessageType::GroupMessage,
            MessageType::Announce,
            MessageType::Fragment,
        ]);
        assert_eq!(
            flags.to_types(),
            vec![
                MessageType::Announce,
                MessageType::Fragment,
                MessageType::GroupMessage
            ]
        );
    }
}
