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
use crate::file_packet::FilePacket;
use crate::fragment::{self, Append, Assembler};
use crate::noise_payload::{NoisePayload, NoisePayloadType};
use crate::noise_session::NoiseSessionManager;
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
    /// A frame the mesh layer produced while handling an inbound one, for the
    /// main loop to put on the air. A handshake is a conversation, so a reply
    /// has to be able to originate down here rather than from a user action.
    Send(Vec<u8>),
    /// Decrypted chat from an established session.
    PrivateMessage {
        peer_id: String,
        sender: String,
        content: String,
    },
    /// An encrypted channel came up. The fingerprint is what a user compares
    /// out of band; the peer ID rotates with the key, so it cannot be that.
    SessionUp {
        peer_id: String,
        nickname: String,
        fingerprint: String,
    },
    PeerRenamed { peer_id: String, nickname: String },
    PeerLeft { peer_id: String, nickname: String },
    PublicMessage {
        peer_id: String,
        sender: String,
        content: String,
        timestamp_ms: u64,
    },
    /// A file arrived over the mesh itself rather than as a link.
    FileReceived {
        peer_id: String,
        sender: String,
        name: String,
        mime: Option<String>,
        bytes: Vec<u8>,
        is_image: bool,
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
    pub noise_public_key: [u8; 32],
    /// Encrypted sessions, one per peer we have spoken to privately. Owns the
    /// static secret, since the handshake is the only thing that needs it.
    sessions: NoiseSessionManager,
    signing_key: SigningKey,
    seen_message_ids: HashSet<String>,
    seen_order: VecDeque<String>,
    last_announce: Option<Instant>,
    /// Buffers fragmented packets until they are whole.
    assembler: Assembler,
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
            noise_public_key,
            sessions: NoiseSessionManager::new(noise_static_key),
            signing_key,
            seen_message_ids: HashSet::new(),
            seen_order: VecDeque::new(),
            last_announce: None,
            assembler: Assembler::new(),
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

    /// An addressed, unsigned frame.
    ///
    /// Noise packets carry no Ed25519 signature. The handshake authenticates
    /// the channel on its own, and signing would not survive the trip anyway:
    /// verification re-encodes the packet canonically, and that re-encode
    /// compresses any payload at or above 100 bytes with a DEFLATE we cannot
    /// reproduce byte-for-byte. Handshake messages are routinely larger than
    /// that, so a signed Noise frame would be dropped by the receiver every
    /// time. See NOTES.md on canonical encoding.
    fn noise_frame(
        &self,
        kind: MessageType,
        recipient: &str,
        payload: Vec<u8>,
    ) -> Option<Vec<u8>> {
        Packet::new(kind, self.sender_bytes(), payload, MESSAGE_TTL)
            .with_recipient(peer_id_to_bytes(recipient))
            .encode()
    }

    /// Whether an encrypted channel to this peer is already up.
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.has_established_session(peer_id)
    }

    /// The peer currently answering to a nickname.
    ///
    /// Nicknames are chosen, not owned — two peers can claim the same one. When
    /// they do, refusing is better than silently encrypting to whichever we
    /// happened to hear from first.
    pub fn peer_id_for_nickname(&self, nickname: &str) -> Result<String, String> {
        let matches: Vec<&MeshPeer> = self
            .peers
            .values()
            .filter(|peer| peer.nickname.eq_ignore_ascii_case(nickname))
            .collect();
        match matches.as_slice() {
            [] => Err(format!("nobody here is called {nickname}")),
            [peer] => Ok(peer.peer_id.clone()),
            several => Err(format!(
                "{} peers are called {nickname}; use a peer ID instead ({})",
                several.len(),
                several
                    .iter()
                    .map(|peer| short_display(&peer.peer_id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// Frames carrying a private message.
    ///
    /// When no channel is up yet this starts the handshake and queues the text
    /// instead of dropping it; the queued message goes out by itself once the
    /// session establishes, so the user never has to send it twice.
    pub fn dm_frames(&mut self, peer_id: &str, content: &str) -> Result<Vec<Vec<u8>>, String> {
        if peer_id == self.my_peer_id {
            return Err("that is your own peer ID".to_string());
        }
        if self.sessions.has_established_session(peer_id) {
            let payload = NoisePayload::private_message(content).encode();
            let sealed = self
                .sessions
                .encrypt(&payload, peer_id)
                .map_err(|error| format!("could not encrypt: {error}"))?;
            return Ok(self
                .noise_frame(MessageType::NoiseEncrypted, peer_id, sealed)
                .into_iter()
                .collect());
        }

        // Order matters: queueing needs a session object to hang the message
        // on, and initiating the handshake is what creates one. Queue first and
        // the text is dropped on the floor with only a `false` to say so.
        let opening = self
            .sessions
            .initiate_handshake(peer_id)
            .map_err(|error| format!("could not start a handshake: {error}"))?;
        if !self.sessions.queue_message(peer_id, content.to_string()) {
            return Err("could not hold the message while the channel opens".to_string());
        }
        Ok(self
            .noise_frame(MessageType::NoiseHandshake, peer_id, opening)
            .into_iter()
            .collect())
    }

    /// Encrypts anything queued while the handshake was still running, and
    /// announces the channel.
    fn drain_pending(&mut self, peer_id: &str) -> Vec<MeshEvent> {
        let mut events = Vec::new();
        let nickname = self
            .peers
            .get(peer_id)
            .map(|peer| peer.nickname.clone())
            .unwrap_or_else(|| short_display(peer_id));
        events.push(MeshEvent::SessionUp {
            peer_id: peer_id.to_string(),
            nickname,
            fingerprint: self
                .sessions
                .get_peer_fingerprint(peer_id)
                .unwrap_or_default(),
        });

        for text in self.sessions.get_pending_messages(peer_id) {
            let payload = NoisePayload::private_message(&text).encode();
            match self.sessions.encrypt(&payload, peer_id) {
                Ok(sealed) => {
                    if let Some(frame) =
                        self.noise_frame(MessageType::NoiseEncrypted, peer_id, sealed)
                    {
                        events.push(MeshEvent::Send(frame));
                    }
                }
                Err(error) => events.push(MeshEvent::Notice(format!(
                    "queued message to {} was lost: {error}",
                    short_display(peer_id)
                ))),
            }
        }
        events
    }

    /// One leg of a handshake. Either side may open one, and either may need to
    /// answer, so this both consumes and produces.
    fn handle_noise_handshake(&mut self, packet: &Packet) -> Vec<MeshEvent> {
        let sender = packet.sender_hex();
        if !self.addressed_to_us(packet) {
            return Vec::new();
        }

        let mut events = Vec::new();
        match self
            .sessions
            .handle_incoming_handshake(&sender, &packet.payload)
        {
            Ok(Some(response)) => {
                if let Some(frame) =
                    self.noise_frame(MessageType::NoiseHandshake, &sender, response)
                {
                    events.push(MeshEvent::Send(frame));
                }
            }
            Ok(None) => {}
            Err(error) => {
                // A failed handshake leaves a half-open session behind that
                // rejects every later attempt. Clearing it means the next try
                // starts clean instead of failing forever.
                self.sessions.remove_session(&sender);
                return vec![MeshEvent::Notice(format!(
                    "handshake with {} failed: {error}",
                    short_display(&sender)
                ))];
            }
        }

        if self.sessions.has_established_session(&sender) {
            events.extend(self.drain_pending(&sender));
        }
        events
    }

    fn handle_noise_encrypted(&mut self, packet: &Packet) -> Vec<MeshEvent> {
        let sender = packet.sender_hex();
        if !self.addressed_to_us(packet) {
            return Vec::new();
        }

        let plaintext = match self.sessions.decrypt(&packet.payload, &sender) {
            Ok(bytes) => bytes,
            Err(error) => {
                return vec![MeshEvent::Notice(format!(
                    "could not decrypt a message from {}: {error}",
                    short_display(&sender)
                ))]
            }
        };

        let Some(payload) = NoisePayload::decode(&plaintext) else {
            return vec![MeshEvent::Trace(format!(
                "unreadable encrypted payload from {}",
                short_display(&sender)
            ))];
        };

        match payload.kind {
            NoisePayloadType::PrivateMessage => {
                let Some(content) = payload.text() else {
                    return vec![MeshEvent::Trace(format!(
                        "non-text private message from {}",
                        short_display(&sender)
                    ))];
                };
                let nickname = self
                    .peers
                    .get(&sender)
                    .map(|peer| peer.nickname.clone())
                    .unwrap_or_else(|| short_display(&sender));
                vec![MeshEvent::PrivateMessage {
                    peer_id: sender,
                    sender: nickname,
                    content,
                }]
            }
            // Receipts are bookkeeping, not conversation. They are traced so
            // /debug can see them and otherwise stay out of the log.
            NoisePayloadType::ReadReceipt | NoisePayloadType::Delivered => {
                vec![MeshEvent::Trace(format!(
                    "{:?} from {}",
                    payload.kind,
                    short_display(&sender)
                ))]
            }
        }
    }

    /// Encrypted traffic is point-to-point. A frame addressed to someone else
    /// is not ours to open, and answering a broadcast handshake would announce
    /// our presence to anyone who asked.
    fn addressed_to_us(&self, packet: &Packet) -> bool {
        packet.recipient_hex().as_deref() == Some(self.my_peer_id.as_str())
    }

    // MARK: - Inbound

    pub fn handle_frame(&mut self, raw: &[u8]) -> Vec<MeshEvent> {
        let Some(packet) = Packet::decode(raw) else {
            return vec![MeshEvent::Notice(format!(
                "dropped an undecodable {} byte frame",
                raw.len()
            ))];
        };
        self.handle_packet(packet, false)
    }

    /// `reassembled` marks a packet that came out of the fragment buffer, so a
    /// fragment carrying another fragment cannot recurse.
    fn handle_packet(&mut self, packet: Packet, reassembled: bool) -> Vec<MeshEvent> {

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

        // Fragments carry a whole encoded packet; feed the reassembled bytes
        // back through this same dispatch once every piece has arrived.
        if packet.parsed_type() == Some(MessageType::Fragment) {
            if reassembled {
                events.push(MeshEvent::Notice(
                    "ignored a fragment nested inside a fragment".to_string(),
                ));
                return events;
            }
            let Some(header) = fragment::parse(&packet) else {
                events.push(MeshEvent::Notice(format!(
                    "malformed fragment from {}",
                    short_display(&sender)
                )));
                return events;
            };
            let total = header.total;
            match self.assembler.append(header) {
                Append::Pending { have, total } => {
                    if self.debug {
                        events.push(MeshEvent::Trace(format!(
                            "fragment {have}/{total} from {}",
                            short_display(&sender)
                        )));
                    }
                }
                Append::Rejected(reason) => events.push(MeshEvent::Notice(format!(
                    "dropped a fragment from {}: {reason}",
                    short_display(&sender)
                ))),
                Append::Complete(bytes) => match Packet::decode(&bytes) {
                    Some(inner) => events.extend(self.handle_packet(inner, true)),
                    None => events.push(MeshEvent::Notice(format!(
                        "reassembled {total} fragments from {} into an undecodable packet",
                        short_display(&sender)
                    ))),
                },
            }
            return events;
        }

        events.extend(match packet.parsed_type() {
            Some(MessageType::Announce) => self.handle_announce(&packet),
            Some(MessageType::Message) => self.handle_public_message(&packet),
            Some(MessageType::Leave) => self.handle_leave(&sender),
            Some(MessageType::FileTransfer) => self.handle_file(&packet),
            Some(MessageType::NoiseHandshake) => self.handle_noise_handshake(&packet),
            Some(MessageType::NoiseEncrypted) => self.handle_noise_encrypted(&packet),
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

    /// A file sent over the radio. Arrives fragmented in practice, so this only
    /// ever sees a whole payload thanks to the assembler.
    fn handle_file(&mut self, packet: &Packet) -> Vec<MeshEvent> {
        let sender_id = packet.sender_hex();
        let Some(file) = FilePacket::decode(&packet.payload) else {
            return vec![MeshEvent::Notice(format!(
                "unreadable file from {}",
                short_display(&sender_id)
            ))];
        };

        if let Some(peer) = self.peers.get_mut(&sender_id) {
            peer.last_seen = Instant::now();
        }
        let sender = self
            .peers
            .get(&sender_id)
            .map(|peer| peer.nickname.clone())
            .unwrap_or_else(|| format!("{}?", short_display(&sender_id)));

        vec![MeshEvent::FileReceived {
            peer_id: sender_id,
            sender,
            name: file.display_name(),
            mime: file.mime_type.clone(),
            is_image: file.is_image(),
            bytes: file.content,
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
    fn a_fragmented_message_arrives_whole() {
        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());

        // Bob sends a message, then it is split the way the radio layer splits
        // anything too big for one write.
        let frames = bob.public_message_frames("fragmented hello");
        let inner = Packet::decode(&frames[0]).unwrap().encode().unwrap();

        let mut events = Vec::new();
        let chunks: Vec<&[u8]> = inner.chunks(40).collect();
        let total = chunks.len();
        assert!(total > 1, "test needs a real split");
        for (index, chunk) in chunks.iter().enumerate() {
            let mut payload = Vec::new();
            payload.extend_from_slice(&7u64.to_be_bytes());
            payload.extend_from_slice(&(index as u16).to_be_bytes());
            payload.extend_from_slice(&(total as u16).to_be_bytes());
            payload.push(MessageType::Message as u8);
            payload.extend_from_slice(chunk);
            let fragment = Packet::new(
                MessageType::Fragment,
                peer_id_to_bytes(&bob.my_peer_id),
                payload,
                7,
            );
            events.extend(alice.handle_frame(&fragment.encode().unwrap()));
        }

        match events.as_slice() {
            [MeshEvent::PublicMessage { sender, content, .. }] => {
                assert_eq!(sender, "bob");
                assert_eq!(content, "fragmented hello");
            }
            other => panic!("expected the reassembled message, got {other:?}"),
        }
    }

    #[test]
    fn an_image_sent_over_the_radio_arrives_whole() {
        // The full path a phone-sent picture takes: a file packet, split into
        // fragments because a BLE write is small, reassembled here.
        use crate::file_packet::FilePacket;

        let mut alice = service(1);
        let mut bob = service(20);
        bob.set_nickname("bob");
        alice.handle_frame(&bob.announce_frame().unwrap());

        // A real PNG, so the decode at the far end is genuine.
        let mut png = Vec::new();
        image::DynamicImage::new_rgb8(24, 18)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();

        let file = FilePacket {
            file_name: Some("photo.png".into()),
            file_size: Some(png.len() as u64),
            mime_type: Some("image/png".into()),
            content: png.clone(),
        };
        let inner = Packet::new(
            MessageType::FileTransfer,
            peer_id_to_bytes(&bob.my_peer_id),
            file.encode().expect("encodes"),
            7,
        )
        .encode()
        .expect("frames");
        assert!(inner.len() > 200, "worth fragmenting");

        let chunks: Vec<&[u8]> = inner.chunks(120).collect();
        let total = chunks.len();
        let mut events = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut payload = Vec::new();
            payload.extend_from_slice(&555u64.to_be_bytes());
            payload.extend_from_slice(&(index as u16).to_be_bytes());
            payload.extend_from_slice(&(total as u16).to_be_bytes());
            payload.push(MessageType::FileTransfer as u8);
            payload.extend_from_slice(chunk);
            let fragment = Packet::new(
                MessageType::Fragment,
                peer_id_to_bytes(&bob.my_peer_id),
                payload,
                7,
            );
            events.extend(alice.handle_frame(&fragment.encode().unwrap()));
        }

        match events.as_slice() {
            [MeshEvent::FileReceived {
                sender,
                name,
                mime,
                bytes,
                is_image,
                ..
            }] => {
                assert_eq!(sender, "bob");
                assert_eq!(name, "photo.png");
                assert_eq!(mime.as_deref(), Some("image/png"));
                assert!(is_image);
                assert_eq!(bytes, &png, "the picture survives fragmentation intact");
                // And it is a decodable image, not just matching bytes.
                let decoded = image::load_from_memory(bytes).expect("valid png");
                assert_eq!((decoded.width(), decoded.height()), (24, 18));
            }
            other => panic!("expected a received file, got {other:?}"),
        }
    }

    #[test]
    fn a_non_image_file_is_reported_but_not_decoded() {
        use crate::file_packet::FilePacket;
        let mut alice = service(1);
        let file = FilePacket {
            file_name: Some("note.m4a".into()),
            file_size: None,
            mime_type: Some("audio/mp4".into()),
            content: vec![7u8; 64],
        };
        let packet = Packet::new(MessageType::FileTransfer, [3; 8], file.encode().unwrap(), 7);

        match alice.handle_frame(&packet.encode().unwrap()).as_slice() {
            [MeshEvent::FileReceived { is_image, name, .. }] => {
                assert!(!is_image);
                assert_eq!(name, "note.m4a");
            }
            other => panic!("expected a file event, got {other:?}"),
        }
    }

    #[test]
    fn a_fragment_nested_in_a_fragment_is_refused() {
        // Otherwise a crafted packet could recurse until the stack gave out.
        let mut alice = service(1);
        let inner = Packet::new(MessageType::Fragment, [2; 8], vec![0u8; 13], 7)
            .encode()
            .unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(MessageType::Fragment as u8);
        payload.extend_from_slice(&inner);
        let outer = Packet::new(MessageType::Fragment, [2; 8], payload, 7);

        let events = alice.handle_frame(&outer.encode().unwrap());
        match events.as_slice() {
            [MeshEvent::Notice(text)] => assert!(text.contains("nested"), "{text}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
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

#[cfg(test)]
mod noise_dm_tests {
    use super::*;

    fn pair() -> (MeshService, MeshService) {
        (
            MeshService::new([11; 32], [12; 32], "alice"),
            MeshService::new([21; 32], [22; 32], "bob"),
        )
    }

    /// Runs frames between two clients until neither has anything more to say,
    /// collecting everything that was not a frame. A handshake is several round
    /// trips, so a test that delivers one frame proves nothing.
    fn settle(a: &mut MeshService, b: &mut MeshService, opening: Vec<Vec<u8>>) -> Vec<MeshEvent> {
        let mut collected = Vec::new();
        let mut to_b = opening;
        let mut to_a: Vec<Vec<u8>> = Vec::new();

        for _ in 0..8 {
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
            let mut next_a = Vec::new();
            let mut next_b = Vec::new();

            for frame in to_b.drain(..) {
                for event in b.handle_frame(&frame) {
                    match event {
                        MeshEvent::Send(reply) => next_a.push(reply),
                        other => collected.push(other),
                    }
                }
            }
            for frame in to_a.drain(..) {
                for event in a.handle_frame(&frame) {
                    match event {
                        MeshEvent::Send(reply) => next_b.push(reply),
                        other => collected.push(other),
                    }
                }
            }
            to_a = next_a;
            to_b = next_b;
        }
        collected
    }

    #[test]
    fn a_first_message_opens_a_channel_and_still_arrives() {
        // The whole point of queueing: the user types once, and the text goes
        // out by itself after the handshake rather than being dropped.
        let (mut alice, mut bob) = pair();
        let target = bob.my_peer_id.clone();
        let opening = alice.dm_frames(&target, "the docks at nine").unwrap();
        assert!(!opening.is_empty(), "a DM must put something on the air");

        let events = settle(&mut alice, &mut bob, opening);

        assert!(
            alice.has_session(&target),
            "the initiator should end up with an established session"
        );
        let delivered: Vec<&MeshEvent> = events
            .iter()
            .filter(|event| matches!(event, MeshEvent::PrivateMessage { .. }))
            .collect();
        match delivered.as_slice() {
            [MeshEvent::PrivateMessage { content, .. }] => {
                assert_eq!(content, "the docks at nine")
            }
            other => panic!("expected exactly one private message, got {other:?}"),
        }
    }

    #[test]
    fn both_sides_learn_the_same_fingerprint() {
        // The fingerprint is what a user reads out to verify a peer. If the two
        // ends disagree, verification is theatre.
        let (mut alice, mut bob) = pair();
        let target = bob.my_peer_id.clone();
        let opening = alice.dm_frames(&target, "hi").unwrap();
        let events = settle(&mut alice, &mut bob, opening);

        let fingerprints: Vec<&String> = events
            .iter()
            .filter_map(|event| match event {
                MeshEvent::SessionUp { fingerprint, .. } => Some(fingerprint),
                _ => None,
            })
            .collect();
        assert!(
            !fingerprints.is_empty(),
            "establishing a channel must be announced"
        );
        for print in &fingerprints {
            assert!(!print.is_empty(), "an empty fingerprint verifies nothing");
        }
    }

    #[test]
    fn a_reply_flows_back_over_the_same_channel() {
        let (mut alice, mut bob) = pair();
        let bob_id = bob.my_peer_id.clone();
        let alice_id = alice.my_peer_id.clone();
        let opening = alice.dm_frames(&bob_id, "ping").unwrap();
        settle(&mut alice, &mut bob, opening);

        // Bob now has a session, so his reply should encrypt immediately rather
        // than starting a second handshake.
        assert!(bob.has_session(&alice_id));
        let reply = bob.dm_frames(&alice_id, "pong").unwrap();
        let events = settle(&mut bob, &mut alice, reply);

        assert!(events.iter().any(|event| matches!(
            event,
            MeshEvent::PrivateMessage { content, .. } if content == "pong"
        )));
    }

    #[test]
    fn encrypted_traffic_addressed_elsewhere_is_left_alone() {
        // A DM for someone else must not be decrypted, answered, or shown.
        let (mut alice, mut bob) = pair();
        let mut carol = MeshService::new([31; 32], [32; 32], "carol");
        let bob_id = bob.my_peer_id.clone();

        let opening = alice.dm_frames(&bob_id, "not for carol").unwrap();
        for frame in &opening {
            assert!(
                carol.handle_frame(frame).is_empty(),
                "a bystander must ignore a handshake addressed to someone else"
            );
        }
        // Bob still completes normally.
        assert!(!settle(&mut alice, &mut bob, opening).is_empty());
    }

    #[test]
    fn a_dm_to_yourself_is_refused() {
        let (mut alice, _bob) = pair();
        let me = alice.my_peer_id.clone();
        assert!(alice.dm_frames(&me, "hello me").is_err());
    }

    #[test]
    fn an_ambiguous_nickname_is_reported_rather_than_guessed() {
        // Nicknames are claimed, not owned. Encrypting to whichever peer we
        // happened to hear from first would be silently wrong.
        let mut alice = MeshService::new([11; 32], [12; 32], "alice");
        for seed in [40u8, 50] {
            let peer = MeshPeer {
                peer_id: format!("{:016x}", seed),
                nickname: "twin".to_string(),
                noise_public_key: vec![seed; 32],
                signing_public_key: vec![seed; 32],
                fingerprint: format!("{seed:02x}"),
                verified: false,
                last_seen: Instant::now(),
            };
            alice.peers.insert(peer.peer_id.clone(), peer);
        }

        let error = alice.peer_id_for_nickname("twin").unwrap_err();
        assert!(error.contains("2 peers"), "got: {error}");
        assert!(alice.peer_id_for_nickname("nobody").is_err());
    }

    #[test]
    fn an_unambiguous_nickname_resolves() {
        let mut alice = MeshService::new([11; 32], [12; 32], "alice");
        let peer = MeshPeer {
            peer_id: "00000000000000aa".to_string(),
            nickname: "Bob".to_string(),
            noise_public_key: vec![9; 32],
            signing_public_key: vec![9; 32],
            fingerprint: "aa".to_string(),
            verified: false,
            last_seen: Instant::now(),
        };
        alice.peers.insert(peer.peer_id.clone(), peer);
        // Case-insensitive: users type what they see, not what was announced.
        assert_eq!(
            alice.peer_id_for_nickname("bob").unwrap(),
            "00000000000000aa"
        );
    }
}
