// src/mesh.rs
//
// The mesh session: local identity, the peer registry, and the inbound packet
// dispatch. Everything the BLE loop in main.rs needs to behave like a real
// bitchat peer lives here, so the transport layer stays dumb.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::announce::{self, Announcement};
use crate::compression;
use crate::peer_id::{derive_peer_id, fingerprint, short_display};
use crate::protocol::{peer_id_to_bytes, MessageType, Packet};

/// Broadcast TTL. Matches the whitepaper's maximum-reach default.
const MESSAGE_TTL: u8 = 7;

/// How often we re-announce. Peers drop a silent link's peer entry after
/// `blePeerInactivityTimeoutSeconds` (8s), and re-announce on a 15-30s cadence
/// themselves; 10s keeps us comfortably fresh without spamming the mesh.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(10);

/// Mirrors `bleReachabilityRetentionUnverifiedSeconds` / `...VerifiedSeconds`.
const PEER_RETENTION: Duration = Duration::from_secs(60);

/// Bound on the replay-dedup set.
const SEEN_LIMIT: usize = 512;

#[derive(Debug, Clone)]
pub enum MeshEvent {
    PeerAppeared { peer_id: String, nickname: String },
    PeerRenamed { peer_id: String, nickname: String },
    PeerLeft { peer_id: String, nickname: String },
    PublicMessage {
        peer_id: String,
        sender: String,
        content: String,
        timestamp_ms: u64,
    },
    /// Human-readable diagnostic destined for the message pane.
    Notice(String),
    /// Per-frame protocol trace, only emitted while `/debug` is on. Unlike a
    /// Notice these are never deduplicated.
    Trace(String),
}

#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub peer_id: String,
    pub nickname: String,
    pub noise_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub fingerprint: String,
    pub verified: bool,
    pub last_seen: Instant,
}

pub struct MeshService {
    pub my_peer_id: String,
    pub nickname: String,
    pub peers: HashMap<String, MeshPeer>,
    /// Retained for the Noise DM work; the handshake needs the static secret.
    #[allow(dead_code)]
    pub noise_static_key: StaticSecret,
    pub noise_public_key: [u8; 32],
    signing_key: SigningKey,
    seen_message_ids: HashSet<String>,
    seen_order: VecDeque<String>,
    last_announce: Option<Instant>,
    /// When on, every inbound frame is reported to the UI. Interop bugs are
    /// otherwise invisible: unknown packet types are silently ignored.
    pub debug: bool,
}

impl MeshService {
    pub fn new(identity_key: [u8; 32], noise_static_key: [u8; 32], nickname: &str) -> Self {
        let signing_key = SigningKey::from_bytes(&identity_key);
        let noise_static_key = StaticSecret::from(noise_static_key);
        let noise_public_key = PublicKey::from(&noise_static_key).to_bytes();
        let my_peer_id = derive_peer_id(&noise_public_key);

        Self {
            my_peer_id,
            nickname: announce::truncate_nickname(nickname),
            peers: HashMap::new(),
            noise_static_key,
            noise_public_key,
            signing_key,
            seen_message_ids: HashSet::new(),
            seen_order: VecDeque::new(),
            last_announce: None,
            debug: false,
        }
    }

    pub fn my_fingerprint(&self) -> String {
        fingerprint(&self.noise_public_key)
    }

    pub fn set_nickname(&mut self, nickname: &str) {
        self.nickname = announce::truncate_nickname(nickname);
    }

    fn sender_bytes(&self) -> [u8; 8] {
        peer_id_to_bytes(&self.my_peer_id)
    }

    // MARK: - Outbound

    /// Signed TLV announce. This is what makes us a peer: without it we are an
    /// anonymous subscribed central that nobody lists or addresses.
    pub fn announce_frame(&mut self) -> Option<Vec<u8>> {
        let payload = Announcement::new(
            &self.nickname,
            self.noise_public_key.to_vec(),
            self.signing_key.verifying_key().to_bytes().to_vec(),
        )
        .encode()?;

        let mut packet = Packet::new(
            MessageType::Announce,
            self.sender_bytes(),
            payload,
            MESSAGE_TTL,
        );
        if !announce::sign_packet(&mut packet, &self.signing_key) {
            return None;
        }
        self.last_announce = Some(Instant::now());
        packet.encode()
    }

    pub fn announce_due(&self) -> bool {
        match self.last_announce {
            None => true,
            Some(at) => at.elapsed() >= ANNOUNCE_INTERVAL,
        }
    }

    /// Signed, empty-payload leave notice (BLEService.stopServices).
    pub fn leave_frame(&self) -> Option<Vec<u8>> {
        let mut packet = Packet::new(
            MessageType::Leave,
            self.sender_bytes(),
            Vec::new(),
            MESSAGE_TTL,
        );
        announce::sign_packet(&mut packet, &self.signing_key);
        packet.encode()
    }

    /// Public mesh message: type 0x02 whose payload is the raw UTF-8 text.
    ///
    /// The receiver *requires* a valid signature ("Dropping public message with
    /// missing/invalid signature"), and it verifies by re-encoding the packet
    /// canonically. That re-encode compresses any payload of 100 bytes or more
    /// with Apple's DEFLATE, which we cannot reproduce byte-for-byte, so long
    /// text is split into chunks that stay below the threshold. Each chunk is
    /// its own signed packet.
    pub fn public_message_frames(&mut self, content: &str) -> Vec<Vec<u8>> {
        split_for_signing(content)
            .into_iter()
            .filter_map(|chunk| {
                let mut packet = Packet::new(
                    MessageType::Message,
                    self.sender_bytes(),
                    chunk.as_bytes().to_vec(),
                    MESSAGE_TTL,
                );
                if !announce::sign_packet(&mut packet, &self.signing_key) {
                    return None;
                }
                self.remember_packet(&packet, &chunk);
                packet.encode()
            })
            .collect()
    }

    // MARK: - Inbound

    pub fn handle_frame(&mut self, raw: &[u8]) -> Vec<MeshEvent> {
        let Some(packet) = Packet::decode(raw) else {
            return vec![MeshEvent::Notice(format!(
                "dropped an undecodable {} byte frame",
                raw.len()
            ))];
        };

        let sender = packet.sender_hex();

        let mut events = Vec::new();
        if self.debug {
            events.push(MeshEvent::Trace(format!(
                "rx type={} v{} ttl={} {}B payload from {}{}",
                packet
                    .parsed_type()
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| format!("0x{:02X}?", packet.msg_type)),
                packet.version,
                packet.ttl,
                packet.payload.len(),
                short_display(&sender),
                if packet.signature.is_some() {
                    " signed"
                } else {
                    " UNSIGNED"
                }
            )));
        }

        if sender == self.my_peer_id {
            return events;
        }

        events.extend(match packet.parsed_type() {
            Some(MessageType::Announce) => self.handle_announce(&packet),
            Some(MessageType::Message) => self.handle_public_message(&packet),
            Some(MessageType::Leave) => self.handle_leave(&sender),
            Some(MessageType::NoiseHandshake) | Some(MessageType::NoiseEncrypted) => {
                // Stage 2: private messaging over Noise.
                vec![MeshEvent::Notice(format!(
                    "ignoring encrypted traffic from {} (DMs not wired up yet)",
                    short_display(&sender)
                ))]
            }
            Some(_) => Vec::new(),
            None => Vec::new(),
        });
        events
    }

    fn handle_announce(&mut self, packet: &Packet) -> Vec<MeshEvent> {
        let sender = packet.sender_hex();
        let Some(announcement) = Announcement::decode(&packet.payload) else {
            return vec![MeshEvent::Notice(format!(
                "malformed announce from {}",
                short_display(&sender)
            ))];
        };

        // The peer ID must be the one derived from the announced Noise key.
        let derived = derive_peer_id(&announcement.noise_public_key);
        if derived != sender {
            return vec![MeshEvent::Notice(format!(
                "announce sender mismatch: claimed {}, derived {}",
                short_display(&sender),
                short_display(&derived)
            ))];
        }

        // We can only reproduce the canonical signing bytes when neither side
        // compressed the payload; a compressed announce is accepted but stays
        // unverified rather than being silently trusted.
        let verifiable = !compression::should_compress(&packet.payload);
        let verified = announce::verify_packet(packet, &announcement.signing_public_key);
        if verifiable && !verified {
            return vec![MeshEvent::Notice(format!(
                "rejected announce from {} with a bad signature",
                short_display(&sender)
            ))];
        }

        let nickname = announcement.nickname.clone();
        let fingerprint = fingerprint(&announcement.noise_public_key);
        let now = Instant::now();

        match self.peers.get_mut(&sender) {
            Some(existing) => {
                // A changed Noise key under a live peer ID is impossible by
                // construction, so only the nickname can move.
                let renamed = existing.nickname != nickname;
                existing.nickname = nickname.clone();
                existing.verified = verified;
                existing.last_seen = now;
                if renamed {
                    vec![MeshEvent::PeerRenamed {
                        peer_id: sender,
                        nickname,
                    }]
                } else {
                    Vec::new()
                }
            }
            None => {
                self.peers.insert(
                    sender.clone(),
                    MeshPeer {
                        peer_id: sender.clone(),
                        nickname: nickname.clone(),
                        noise_public_key: announcement.noise_public_key,
                        signing_public_key: announcement.signing_public_key,
                        fingerprint,
                        verified,
                        last_seen: now,
                    },
                );
                vec![MeshEvent::PeerAppeared {
                    peer_id: sender,
                    nickname,
                }]
            }
        }
    }

    /// The payload is the message text itself; the sender's name comes from the
    /// announce registry and the time from the packet header.
    fn handle_public_message(&mut self, packet: &Packet) -> Vec<MeshEvent> {
        let sender = packet.sender_hex();
        let Ok(content) = String::from_utf8(packet.payload.clone()) else {
            return vec![MeshEvent::Notice(format!(
                "non-UTF-8 message payload from {}",
                short_display(&sender)
            ))];
        };

        if !self.remember_packet(packet, &content) {
            return Vec::new(); // relayed copy of something already shown
        }

        // senderID is attacker-controlled, so a registry hit alone proves
        // nothing; upstream requires the signature to match the claimed
        // sender's key and we do the same when we can reproduce the canonical
        // bytes (see public_message_frames for why compression blocks that).
        let known_peer = self.peers.get(&sender).cloned();
        let verifiable = !compression::should_compress(&packet.payload);
        let display_name = match &known_peer {
            Some(peer) => {
                if verifiable && !announce::verify_packet(packet, &peer.signing_public_key) {
                    return vec![MeshEvent::Notice(format!(
                        "dropped a message claiming to be from {} with a bad signature",
                        peer.nickname
                    ))];
                }
                if let Some(peer) = self.peers.get_mut(&sender) {
                    peer.last_seen = Instant::now();
                }
                peer.nickname.clone()
            }
            // No announce seen yet: show it rather than dropping, but do not
            // pretend to know who sent it.
            None => format!("{}?", short_display(&sender)),
        };

        vec![MeshEvent::PublicMessage {
            peer_id: sender,
            sender: display_name,
            content,
            timestamp_ms: packet.timestamp,
        }]
    }

    fn handle_leave(&mut self, sender: &str) -> Vec<MeshEvent> {
        match self.peers.remove(sender) {
            Some(peer) => vec![MeshEvent::PeerLeft {
                peer_id: peer.peer_id,
                nickname: peer.nickname,
            }],
            None => Vec::new(),
        }
    }

    /// Drops peers we have not heard from inside the retention window.
    pub fn prune_peers(&mut self) -> Vec<MeshEvent> {
        let expired: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.last_seen.elapsed() > PEER_RETENTION)
            .map(|(id, _)| id.clone())
            .collect();

        expired
            .into_iter()
            .filter_map(|id| {
                self.peers.remove(&id).map(|peer| MeshEvent::PeerLeft {
                    peer_id: peer.peer_id,
                    nickname: peer.nickname,
                })
            })
            .collect()
    }

    /// Forgets every peer, e.g. after the BLE link drops.
    pub fn clear_peers(&mut self) {
        self.peers.clear();
    }

    pub fn nicknames(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .peers
            .values()
            .map(|peer| {
                if peer.nickname.is_empty() {
                    short_display(&peer.peer_id)
                } else {
                    peer.nickname.clone()
                }
            })
            .collect();
        names.sort();
        names
    }

    pub fn peer_by_nickname(&self, nickname: &str) -> Option<&MeshPeer> {
        self.peers.values().find(|peer| peer.nickname == nickname)
    }

    /// Dedup key for a broadcast. The wire carries no message ID any more, so
    /// upstream derives a stable one from sender + timestamp + content
    /// (MeshMessageIdentity.stableID) and we key on the same triple. TTL is
    /// excluded so a relayed copy collapses onto the original.
    fn remember_packet(&mut self, packet: &Packet, content: &str) -> bool {
        let key = format!("{}:{}:{}", packet.sender_hex(), packet.timestamp, content);
        if !self.seen_message_ids.insert(key.clone()) {
            return false;
        }
        self.seen_order.push_back(key);
        if self.seen_order.len() > SEEN_LIMIT {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_message_ids.remove(&oldest);
            }
        }
        true
    }
}

/// Splits text into pieces that each stay under the 100-byte compression
/// threshold, preferring word boundaries. Anything at or above that size would
/// be compressed inside the peer's signature check with an encoder we cannot
/// match, and the message would be dropped as unsigned.
fn split_for_signing(content: &str) -> Vec<String> {
    const MAX_CHUNK_BYTES: usize = 99;

    if content.is_empty() {
        return Vec::new();
    }
    if content.len() <= MAX_CHUNK_BYTES {
        return vec![content.to_string()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    for word in content.split_whitespace() {
        // A single word longer than the budget has to be hard-split.
        if word.len() > MAX_CHUNK_BYTES {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            let mut rest = word;
            while !rest.is_empty() {
                let mut end = MAX_CHUNK_BYTES.min(rest.len());
                while end > 0 && !rest.is_char_boundary(end) {
                    end -= 1;
                }
                chunks.push(rest[..end].to_string());
                rest = &rest[end..];
            }
            continue;
        }

        let separator = if current.is_empty() { 0 } else { 1 };
        if current.len() + separator + word.len() > MAX_CHUNK_BYTES {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(seed: u8) -> MeshService {
        MeshService::new([seed; 32], [seed.wrapping_add(1); 32], "tui")
    }

    #[test]
    fn peer_id_is_derived_from_the_noise_key() {
        let mesh = service(1);
        assert_eq!(mesh.my_peer_id, derive_peer_id(&mesh.noise_public_key));
        assert_eq!(mesh.my_peer_id.len(), 16);
    }

    #[test]
    fn an_announce_from_a_peer_registers_it() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");

        let frame = bob.announce_frame().unwrap();
        let events = alice.handle_frame(&frame);

        assert_eq!(alice.peers.len(), 1);
        let peer = alice.peers.get(&bob.my_peer_id).unwrap();
        assert_eq!(peer.nickname, "bob");
        assert!(peer.verified, "a self-consistent announce must verify");
        assert!(matches!(
            events.as_slice(),
            [MeshEvent::PeerAppeared { nickname, .. }] if nickname == "bob"
        ));
    }

    #[test]
    fn a_tampered_announce_is_rejected() {
        let mut alice = service(1);
        let mut bob = service(20);
        let frame = bob.announce_frame().unwrap();

        let mut packet = Packet::decode(&frame).unwrap();
        packet.payload[1] = packet.payload[1].wrapping_add(1); // corrupt nickname length
        let tampered = packet.encode().unwrap();

        let events = alice.handle_frame(&tampered);
        assert!(alice.peers.is_empty());
        assert!(matches!(events.as_slice(), [MeshEvent::Notice(_)]));
    }

    #[test]
    fn an_announce_claiming_someone_elses_peer_id_is_rejected() {
        let mut alice = service(1);
        let mut bob = service(20);
        let frame = bob.announce_frame().unwrap();

        let mut packet = Packet::decode(&frame).unwrap();
        packet.sender_id = [0xAB; 8]; // does not match the announced noise key
        let spoofed = packet.encode().unwrap();

        let events = alice.handle_frame(&spoofed);
        assert!(alice.peers.is_empty());
        match events.as_slice() {
            [MeshEvent::Notice(text)] => assert!(text.contains("mismatch"), "{text}"),
            other => panic!("expected a mismatch notice, got {other:?}"),
        }
    }

    #[test]
    fn public_messages_round_trip_between_two_services() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());

        let frames = bob.public_message_frames("hello mesh");
        assert_eq!(frames.len(), 1);
        let events = alice.handle_frame(&frames[0]);

        match events.as_slice() {
            [MeshEvent::PublicMessage { sender, content, .. }] => {
                assert_eq!(sender, "bob");
                assert_eq!(content, "hello mesh");
            }
            other => panic!("expected a public message, got {other:?}"),
        }
    }

    #[test]
    fn the_payload_is_the_raw_text_and_the_packet_is_signed() {
        // Upstream drops public messages with a missing or invalid signature,
        // and reads the payload straight back as UTF-8.
        let mut bob = service(20);
        let frames = bob.public_message_frames("hello mesh");
        let packet = Packet::decode(&frames[0]).unwrap();
        assert_eq!(packet.payload, b"hello mesh");
        assert_eq!(packet.msg_type, MessageType::Message as u8);
        assert!(packet.signature.is_some(), "must be signed or peers drop it");
    }

    #[test]
    fn a_message_with_a_forged_signature_is_dropped() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());

        let frames = bob.public_message_frames("legit");
        let mut packet = Packet::decode(&frames[0]).unwrap();
        packet.payload = b"tampered".to_vec(); // signature no longer matches
        let events = alice.handle_frame(&packet.encode().unwrap());

        match events.as_slice() {
            [MeshEvent::Notice(text)] => assert!(text.contains("bad signature"), "{text}"),
            other => panic!("expected a rejection notice, got {other:?}"),
        }
    }

    #[test]
    fn a_message_from_an_unannounced_peer_is_shown_but_not_attributed() {
        let mut alice = service(1);
        let mut bob = service(20);
        let frames = bob.public_message_frames("who am i");

        match alice.handle_frame(&frames[0]).as_slice() {
            [MeshEvent::PublicMessage { sender, content, .. }] => {
                assert!(sender.ends_with('?'), "unknown sender must be marked: {sender}");
                assert_eq!(content, "who am i");
            }
            other => panic!("expected a public message, got {other:?}"),
        }
    }

    #[test]
    fn relayed_copies_are_shown_once() {
        let mut alice = service(1);
        let mut bob = service(20);
        let frames = bob.public_message_frames("echo");

        assert_eq!(alice.handle_frame(&frames[0]).len(), 1);
        assert!(
            alice.handle_frame(&frames[0]).is_empty(),
            "replay must be dropped"
        );

        // A relay decrements TTL; that must still count as the same message.
        let mut relayed = Packet::decode(&frames[0]).unwrap();
        relayed.ttl -= 1;
        assert!(alice.handle_frame(&relayed.encode().unwrap()).is_empty());
    }

    #[test]
    fn long_messages_split_below_the_compression_threshold() {
        let mut bob = service(20);
        let long = "the mesh carries this sentence a very long way indeed ".repeat(6);
        let frames = bob.public_message_frames(&long);

        assert!(frames.len() > 1, "long text must be split");
        for frame in &frames {
            let packet = Packet::decode(frame).unwrap();
            assert!(
                !crate::compression::should_compress(&packet.payload),
                "chunk of {} bytes would be compressed and fail verification",
                packet.payload.len()
            );
            assert!(packet.signature.is_some());
        }

        // Nothing is lost in the split.
        let rejoined: Vec<String> = frames
            .iter()
            .map(|frame| String::from_utf8(Packet::decode(frame).unwrap().payload).unwrap())
            .collect();
        assert_eq!(
            rejoined.join(" ").split_whitespace().collect::<Vec<_>>(),
            long.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_single_oversized_word_is_hard_split() {
        let mut bob = service(20);
        let frames = bob.public_message_frames(&"z".repeat(250));
        assert_eq!(frames.len(), 3);
        for frame in &frames {
            assert!(Packet::decode(frame).unwrap().payload.len() <= 99);
        }
    }

    #[test]
    fn our_own_traffic_is_ignored() {
        let mut alice = service(1);
        let frame = alice.announce_frame().unwrap();
        assert!(alice.handle_frame(&frame).is_empty());
        assert!(alice.peers.is_empty());
    }

    #[test]
    fn leave_removes_the_peer() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());
        assert_eq!(alice.peers.len(), 1);

        let events = alice.handle_frame(&bob.leave_frame().unwrap());
        assert!(alice.peers.is_empty());
        assert!(matches!(events.as_slice(), [MeshEvent::PeerLeft { .. }]));
    }

    #[test]
    fn a_renamed_peer_updates_in_place() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());

        bob.set_nickname("robert");
        let events = alice.handle_frame(&bob.announce_frame().unwrap());

        assert_eq!(alice.peers.len(), 1);
        assert_eq!(alice.peers[&bob.my_peer_id].nickname, "robert");
        assert!(matches!(
            events.as_slice(),
            [MeshEvent::PeerRenamed { nickname, .. }] if nickname == "robert"
        ));
    }

    #[test]
    fn garbage_frames_do_not_panic() {
        let mut alice = service(1);
        for frame in [vec![], vec![0xFF; 3], vec![0x01; 64], vec![0x02; 300]] {
            let _ = alice.handle_frame(&frame);
        }
        assert!(alice.peers.is_empty());
    }

    #[test]
    fn announce_becomes_due_again_after_the_interval() {
        let mut mesh = service(1);
        assert!(mesh.announce_due(), "first announce is always due");
        mesh.announce_frame().unwrap();
        assert!(!mesh.announce_due());
        mesh.last_announce = Some(Instant::now() - ANNOUNCE_INTERVAL - Duration::from_secs(1));
        assert!(mesh.announce_due());
    }
}
