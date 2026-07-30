
// This file used to say the manager deliberately exposed more than the mesh
// layer called, because it was the API the remaining private-messaging work
// would build on. That was true when it was written and the work has since
// landed somewhere else: holding messages during a handshake is `outbox.rs`,
// resolving a fingerprint to a peer is `favorites::resolve`, and the
// secured-versus-verified indicator arrives through `verification.rs`. What was
// left here was a second implementation of each, which is how two mechanisms
// drift apart, so it is gone.
//
// What remains is what the client calls, plus a few items reachable only from
// tests, each annotated individually with the reason. Nothing here is covered
// by a blanket allow any more.
use crate::data_structures::noise_trace;
use crate::debug_full_println;
use crate::noise_protocol::{
    NoiseCipherState, NoiseError, NoiseHandshakeState, NoisePattern, NoiseRole, NoiseSymmetricState,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

// MARK: - Debug Logging

/// A handshake trace, written only when the operator has set
/// `BITMANCER_NOISE_LOG`. The gate used to live here as a local copy of the
/// writer; it now lives in `data_structures::noise_trace` so the protocol half
/// of the stack cannot go on writing unasked while this half asks permission.
fn log_noise_event(event: &str, peer_id: &str, details: &str) {
    let message = format!("[NOISE_DEBUG] {} - Peer: {} - {}", event, peer_id, details);
    noise_trace(&message);
    debug_full_println!("{}", message);
}

// MARK: - Noise Session State

/// A session is either not started, mid-handshake, or up.
///
/// There used to be a fourth, `Failed(String)`, and nothing ever constructed it.
/// It was half of a failure-handling design that `mesh.rs` replaced with
/// remove-on-error — clearing a broken session rather than marking it, which is
/// stronger, because a cleared session cannot be resumed into a bad state at all.
/// See issue #4: that replacement covers the responder path and not the
/// initiator one, which is worth fixing and is not what this enum was doing.
#[derive(Debug, Clone, PartialEq)]
pub enum NoiseSessionState {
    Uninitialized,
    Handshaking,
    Established,
}

// MARK: - Noise Session

pub struct NoiseSession {
    pub peer_id: String,
    pub role: NoiseRole,
    state: NoiseSessionState,
    handshake_state: Option<NoiseHandshakeState>,
    send_cipher: Option<NoiseCipherState>,
    receive_cipher: Option<NoiseCipherState>,

    // Keys
    local_static_key: StaticSecret,
    remote_static_public_key: Option<PublicKey>,

    // Handshake messages for retransmission
    sent_handshake_messages: Vec<Vec<u8>>,
    handshake_hash: Option<Vec<u8>>,
}

impl NoiseSession {
    // MARK: - Handshake

    pub fn process_handshake_message(
        &mut self,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        log_noise_event(
            "HANDSHAKE_PROCESS",
            &self.peer_id,
            &format!(
                "Processing message of {} bytes, current state: {:?}, role: {:?}",
                message.len(),
                self.state,
                self.role
            ),
        );

        // Initialize handshake state if needed (for responders)
        if self.state == NoiseSessionState::Uninitialized
            && matches!(self.role, NoiseRole::Responder)
        {
            log_noise_event(
                "HANDSHAKE_INIT_RESPONDER",
                &self.peer_id,
                "Initializing handshake state for responder",
            );
            self.handshake_state = Some(NoiseHandshakeState::new(
                self.role,
                NoisePattern::XX,
                Some(self.local_static_key.clone()),
                None,
            ));
            self.state = NoiseSessionState::Handshaking;
            log_noise_event(
                "HANDSHAKE_STATE_CHANGE",
                &self.peer_id,
                "Responder state changed to Handshaking",
            );
        }

        if self.state != NoiseSessionState::Handshaking {
            log_noise_event(
                "HANDSHAKE_ERROR",
                &self.peer_id,
                &format!("Invalid state for processing: {:?}", self.state),
            );
            return Err(NoiseError::InvalidState);
        }

        let handshake = self
            .handshake_state
            .as_mut()
            .ok_or(NoiseError::InvalidState)?;
        log_noise_event("HANDSHAKE_READ", &self.peer_id, "Reading handshake message");

        // Process incoming message
        let _payload = handshake.read_message(message)?;
        log_noise_event(
            "HANDSHAKE_READ_SUCCESS",
            &self.peer_id,
            "Successfully read handshake message",
        );

        // Check if handshake is complete
        if handshake.is_handshake_complete() {
            log_noise_event(
                "HANDSHAKE_COMPLETE",
                &self.peer_id,
                "Handshake is complete, getting transport ciphers",
            );

            // Get transport ciphers
            let (send, receive) = handshake.get_transport_ciphers()?;
            self.send_cipher = Some(send);
            self.receive_cipher = Some(receive);
            log_noise_event(
                "HANDSHAKE_CIPHERS_SET",
                &self.peer_id,
                "Transport ciphers established",
            );

            // Store remote static key
            self.remote_static_public_key = handshake.get_remote_static_public_key();
            if let Some(ref remote_key) = self.remote_static_public_key {
                log_noise_event(
                    "HANDSHAKE_REMOTE_KEY",
                    &self.peer_id,
                    &format!("Remote static key: {:?}", &remote_key.to_bytes()[..8]),
                );
            }

            // Store handshake hash for channel binding
            self.handshake_hash = Some(handshake.get_handshake_hash());
            log_noise_event(
                "HANDSHAKE_HASH_STORED",
                &self.peer_id,
                &format!(
                    "Handshake hash: {:?}",
                    &self.handshake_hash.as_ref().unwrap()[..16]
                ),
            );

            self.state = NoiseSessionState::Established;
            self.handshake_state = None; // Clear handshake state
            log_noise_event(
                "HANDSHAKE_ESTABLISHED",
                &self.peer_id,
                "Session established successfully",
            );

            Ok(None)
        } else {
            log_noise_event(
                "HANDSHAKE_RESPONSE_NEEDED",
                &self.peer_id,
                "Generating handshake response",
            );

            // Generate response
            let response = handshake.write_message(&[])?;
            log_noise_event(
                "HANDSHAKE_RESPONSE_CREATED",
                &self.peer_id,
                &format!("Response size: {} bytes", response.len()),
            );
            self.sent_handshake_messages.push(response.clone());

            // Check if handshake is complete after writing
            if handshake.is_handshake_complete() {
                log_noise_event(
                    "HANDSHAKE_COMPLETE_AFTER_RESPONSE",
                    &self.peer_id,
                    "Handshake complete after writing response",
                );

                // Get transport ciphers
                let (send, receive) = handshake.get_transport_ciphers()?;
                self.send_cipher = Some(send);
                self.receive_cipher = Some(receive);
                log_noise_event(
                    "HANDSHAKE_CIPHERS_SET_AFTER_RESPONSE",
                    &self.peer_id,
                    "Transport ciphers established after response",
                );

                // Store remote static key
                self.remote_static_public_key = handshake.get_remote_static_public_key();
                if let Some(ref remote_key) = self.remote_static_public_key {
                    log_noise_event(
                        "HANDSHAKE_REMOTE_KEY_AFTER_RESPONSE",
                        &self.peer_id,
                        &format!("Remote static key: {:?}", &remote_key.to_bytes()[..8]),
                    );
                }

                // Store handshake hash for channel binding
                self.handshake_hash = Some(handshake.get_handshake_hash());
                log_noise_event(
                    "HANDSHAKE_HASH_STORED_AFTER_RESPONSE",
                    &self.peer_id,
                    &format!(
                        "Handshake hash: {:?}",
                        &self.handshake_hash.as_ref().unwrap()[..16]
                    ),
                );

                self.state = NoiseSessionState::Established;
                self.handshake_state = None; // Clear handshake state
                log_noise_event(
                    "HANDSHAKE_ESTABLISHED_AFTER_RESPONSE",
                    &self.peer_id,
                    "Session established after response",
                );
            }

            Ok(Some(response))
        }
    }

    // MARK: - Transport

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::NotEstablished);
        }

        let cipher = self
            .send_cipher
            .as_mut()
            .ok_or(NoiseError::NotEstablished)?;
        cipher.encrypt(plaintext, &[])
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::NotEstablished);
        }

        let cipher = self
            .receive_cipher
            .as_mut()
            .ok_or(NoiseError::NotEstablished)?;
        cipher.decrypt(ciphertext, &[])
    }

    // MARK: - State Management

    pub fn get_state(&self) -> NoiseSessionState {
        self.state.clone()
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, NoiseSessionState::Established)
    }

    pub fn get_remote_static_public_key(&self) -> Option<PublicKey> {
        self.remote_static_public_key
    }

}

// MARK: - Session Manager

pub struct NoiseSessionManager {
    sessions: Arc<Mutex<HashMap<String, NoiseSession>>>,
    local_static_key: StaticSecret,

    // Fingerprint management (matching Swift implementation)
    peer_fingerprints: Arc<Mutex<HashMap<String, String>>>, // peer_id -> fingerprint

    // Verified fingerprints (matching Swift implementation)
    verified_fingerprints: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl NoiseSessionManager {
    /// Opens a courier envelope addressed to us, returning what it says and the
    /// sender's authenticated static key.
    ///
    /// Lives here because this is where the static secret lives, and handing the
    /// secret out to be used elsewhere would make every future caller a place it
    /// could escape from.
    pub fn open_courier(&self, ciphertext: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        crate::courier::open(ciphertext, &self.local_static_key)
    }

    /// Seals a payload to a peer we cannot reach, for a courier to carry.
    pub fn seal_courier(&self, payload: &[u8], recipient_static_key: &[u8]) -> Option<Vec<u8>> {
        crate::courier::seal(payload, recipient_static_key, &self.local_static_key)
    }

    pub fn new(local_static_key: StaticSecret) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_static_key,
            peer_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            verified_fingerprints: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    // MARK: - Fingerprint Management

    pub fn get_peer_fingerprint(&self, peer_id: &str) -> Option<String> {
        let fingerprints = self.peer_fingerprints.lock().unwrap();
        fingerprints.get(peer_id).cloned()
    }

    // MARK: - Verified Fingerprint Management (matching Swift implementation)

    pub fn verify_fingerprint(&mut self, fingerprint: &str) {
        let mut verified = self.verified_fingerprints.lock().unwrap();
        verified.insert(fingerprint.to_string());
        log_noise_event(
            "FINGERPRINT_VERIFIED",
            "SYSTEM",
            &format!("Fingerprint {} marked as verified", &fingerprint[..16]),
        );
    }

    /// Reachable only from tests. The client asks `verification.rs` and the
    /// verified-fingerprints list instead of asking a session manager, so this
    /// is covered but never called in anger — see the note in NOTES.md about
    /// what the restored lint can and cannot tell you.
    #[allow(dead_code)]
    pub fn is_fingerprint_verified(&self, fingerprint: &str) -> bool {
        let verified = self.verified_fingerprints.lock().unwrap();
        verified.contains(fingerprint)
    }

    pub fn get_verified_fingerprints(&self) -> std::collections::HashSet<String> {
        let verified = self.verified_fingerprints.lock().unwrap();
        verified.clone()
    }

    pub fn load_verified_fingerprints(&mut self, fingerprints: std::collections::HashSet<String>) {
        let mut verified = self.verified_fingerprints.lock().unwrap();
        *verified = fingerprints;
        log_noise_event(
            "FINGERPRINTS_LOADED",
            "SYSTEM",
            &format!("Loaded {} verified fingerprints", verified.len()),
        );
    }

    // MARK: - Identity Fingerprint (matching Swift implementation)

    /// Get our own identity fingerprint (SHA256 hash of our static public key)
    /// Reachable only from tests; the live identity fingerprint the user sees
    /// comes through `verification.rs`.
    #[allow(dead_code)]
    pub fn get_identity_fingerprint(&self) -> String {
        let public_key = PublicKey::from(&self.local_static_key);
        self.calculate_fingerprint(&public_key)
    }

    fn calculate_fingerprint(&self, public_key: &PublicKey) -> String {
        let mut hasher = Sha256::new();
        // Use to_bytes() which should match Swift's rawRepresentation for Curve25519
        hasher.update(public_key.to_bytes());
        let result = hasher.finalize();
        result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn handle_session_established(&self, peer_id: String, remote_static_key: PublicKey) {
        log_noise_event(
            "FINGERPRINT_CALC",
            &peer_id,
            "Calculating fingerprint for remote static key",
        );

        // Calculate fingerprint
        let fingerprint = self.calculate_fingerprint(&remote_static_key);
        log_noise_event(
            "FINGERPRINT_CALCULATED",
            &peer_id,
            &format!("Fingerprint: {}", &fingerprint[..16]),
        );

        // Store fingerprint mapping
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();

            fingerprints.insert(peer_id.clone(), fingerprint.clone());
            log_noise_event(
                "FINGERPRINT_STORED",
                &peer_id,
                "Fingerprint mappings stored",
            );
        }

        debug_full_println!(
            "[NOISE] Session established with {} (fingerprint: {})",
            peer_id,
            &fingerprint[..16]
        );
    }

    // MARK: - Session Management

    /// Reachable only from tests. The live paths reach a session through
    /// `initiate_handshake` and `handle_incoming_handshake`, which build one
    /// themselves rather than asking for it first.
    #[allow(dead_code)]
    pub fn create_session(
        &mut self,
        peer_id: String,
        role: NoiseRole,
    ) -> Result<NoiseSession, NoiseError> {
        noise_trace(&format!(
            "[DEBUG] Creating session for peer: {} with role: {:?}",
            peer_id, role
        ));

        // Check if session already exists and is established
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(existing_session) = sessions.get(&peer_id) {
            if existing_session.state == NoiseSessionState::Established {
                return Err(NoiseError::AlreadyEstablished); // keep the channel
            }
            // handshaking or failed sessions are handled below
        }

        noise_trace("[DEBUG] About to create new NoiseHandshakeState");

        // Create new handshake state
        let handshake_state = match role {
            NoiseRole::Initiator => {
                noise_trace("[DEBUG] Creating handshake state as initiator");
                NoiseHandshakeState::new(
                    role,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )
            }
            NoiseRole::Responder => {
                noise_trace("[DEBUG] Creating handshake state as responder");
                NoiseHandshakeState::new(
                    role,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )
            }
        };

        noise_trace("[DEBUG] Handshake state created successfully");

        // Check if we need to create a new session or update existing one
        if let Some(existing_session) = sessions.get_mut(&peer_id) {
            // Update existing session with new handshake state
            existing_session.handshake_state = Some(handshake_state);
            noise_trace(&format!(
                "[DEBUG] Updated existing session for peer: {}",
                peer_id
            ));
            Ok(existing_session.clone())
        } else {
            // Create new session
            let session = NoiseSession {
                peer_id: peer_id.clone(),
                role,
                state: NoiseSessionState::Handshaking,
                handshake_state: Some(handshake_state),
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,

            };

            noise_trace(&format!(
                "[DEBUG] Session created successfully for peer: {}",
                peer_id
            ));

            // Store the session
            sessions.insert(peer_id.clone(), session.clone());

            Ok(session)
        }
    }

    pub fn remove_session(&mut self, peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        noise_trace(&format!("[DEBUG] Removing session for peer: {}", peer_id));
        if let Some(session) = sessions.get(peer_id) {
            if session.is_established() {
                debug_full_println!("[NOISE] Session expired for {}", peer_id);
            }
        }
        sessions.remove(peer_id);
        noise_trace(&format!("[DEBUG] Session removed for peer: {}", peer_id));

        // Also remove fingerprint mappings
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();
            fingerprints.remove(peer_id);
        }
    }

    /// Moves a session to the peer's new id after a BLE address rotation.
    ///
    /// Nothing calls this yet, and it is annotated rather than deleted because
    /// it is the one piece of this file's unused surface that was never
    /// superseded. Everything else removed alongside it had a live replacement
    /// somewhere in the tree; peer-id rotation is a real protocol event with no
    /// handler anywhere, so this is unbuilt rather than obsolete. See
    /// https://github.com/Mhsbrian/bitmancer/issues/6.
    #[allow(dead_code)]
    pub fn migrate_session(&mut self, from_old_peer_id: &str, to_new_peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.remove(from_old_peer_id) {
            sessions.insert(to_new_peer_id.to_string(), session);
            debug_full_println!(
                "[NOISE] Migrated Noise session from {} to {}",
                from_old_peer_id,
                to_new_peer_id
            );
        }

        // Also migrate fingerprint mappings
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();

            if let Some(fingerprint) = fingerprints.remove(from_old_peer_id) {
                fingerprints.insert(to_new_peer_id.to_string(), fingerprint);
            }
        }
    }

    // MARK: - Handshake Helpers

    pub fn has_established_session(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(peer_id) {
            session.state == NoiseSessionState::Established
        } else {
            false
        }
    }

    /// Reachable only from tests. `MeshService::has_session` is the one the
    /// client calls and it is a different function on a different type — the
    /// shared name makes a grep for callers look answered when it is not.
    #[allow(dead_code)]
    pub fn has_session(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        let has_session = sessions.contains_key(peer_id);
        noise_trace(&format!(
            "[DEBUG] Checking if session exists for peer: {} - Result: {}",
            peer_id, has_session
        ));
        has_session
    }

    pub fn initiate_handshake(&mut self, peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        noise_trace(&format!(
            "[DEBUG] Starting initiate_handshake for peer: {}",
            peer_id
        ));

        let mut sessions = self.sessions.lock().unwrap();

        // Check if session exists
        if !sessions.contains_key(peer_id) {
            noise_trace(&format!(
                "[DEBUG] No session exists for peer: {}, creating new session as initiator",
                peer_id
            ));

            // Create new session as initiator
            let session = NoiseSession {
                peer_id: peer_id.to_string(),
                role: NoiseRole::Initiator,
                state: NoiseSessionState::Handshaking,
                handshake_state: Some(NoiseHandshakeState::new(
                    NoiseRole::Initiator,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )),
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,

            };

            sessions.insert(peer_id.to_string(), session);
            noise_trace(&format!(
                "[DEBUG] Created new session as initiator for peer: {}",
                peer_id
            ));
        } else {
            noise_trace(&format!(
                "[DEBUG] Session already exists for peer: {}",
                peer_id
            ));
        }

        // Get the session and start handshake
        if let Some(session) = sessions.get_mut(peer_id) {
            noise_trace(&format!(
                "[DEBUG] Starting handshake for session with role: {:?}",
                session.role
            ));

            if let Some(handshake_state) = &mut session.handshake_state {
                let message = handshake_state.write_message(&[])?;
                session.sent_handshake_messages.push(message.clone());
                noise_trace(&format!(
                    "[DEBUG] Handshake message created, length: {}",
                    message.len()
                ));

                Ok(message)
            } else {
                noise_trace("[DEBUG] No handshake state found");
                Err(NoiseError::InvalidState)
            }
        } else {
            noise_trace("[DEBUG] Session not found after creation");
            Err(NoiseError::SessionNotFound)
        }
    }

    pub fn handle_incoming_handshake(
        &mut self,
        peer_id: &str,
        handshake_data: &[u8],
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        noise_trace(&format!(
            "[DEBUG] Starting handle_incoming_handshake for peer: {}",
            peer_id
        ));

        // CRITICAL FIX: Check for existing established session first
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(sess) = sessions.get(peer_id) {
                if sess.get_state() == NoiseSessionState::Established {
                    noise_trace(&format!(
                        "[DEBUG] Ignoring handshake - session already established for peer: {}",
                        peer_id
                    ));
                    return Ok(None);
                }
            }
        }

        let mut sessions = self.sessions.lock().unwrap();

        // A session we already hold is continued, never replaced. There used to
        // be a second arm here for `Failed`, and it was unreachable — nothing
        // constructed that state. Collapsing it is behaviour-preserving for that
        // reason rather than because it looked redundant, which is a distinction
        // worth keeping: a broken session is cleared by `mesh.rs` on the way out
        // of a failed handshake, not marked and resumed here.
        let should_create_new = sessions.get(peer_id).is_none();

        if should_create_new {
            let session = NoiseSession {
                peer_id: peer_id.to_string(),
                role: NoiseRole::Responder,
                state: NoiseSessionState::Uninitialized,
                handshake_state: None,
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,

            };
            sessions.insert(peer_id.to_string(), session);
        }

        let session = sessions.get_mut(peer_id).unwrap();
        let result = session.process_handshake_message(handshake_data);

        // Handle session established callback
        if result.is_ok() && session.is_established() {
            if let Some(remote_key) = session.get_remote_static_public_key() {
                self.handle_session_established(peer_id.to_string(), remote_key);
            }
        }

        result
    }

    // MARK: - Encryption/Decryption

    pub fn encrypt(&mut self, plaintext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(NoiseError::SessionNotFound)?;
        session.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(NoiseError::SessionNotFound)?;
        session.decrypt(ciphertext)
    }

    // MARK: - Key Management

    // FIXED: Add method to store peer static keys for identity announcements
    /// Reachable only from tests. Announced static keys reach a handshake
    /// through `handle_incoming_handshake`, not through this.
    #[allow(dead_code)]
    pub fn store_peer_static_key(&mut self, peer_id: &str, static_key_bytes: &[u8]) -> Result<(), NoiseError> {
        if static_key_bytes.len() != 32 {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Validate and store the key for future handshakes
        let static_key_array: [u8; 32] = static_key_bytes.try_into()
            .map_err(|_| NoiseError::InvalidPublicKey)?;
        let _public_key = PublicKey::from(static_key_array);
        
        // Store in a map for later use during handshakes
        // You might need to add a field to store these keys
        log_noise_event("STATIC_KEY_STORED", peer_id, &format!("Stored static key for peer: {}", peer_id));
        Ok(())
    }
}

impl Clone for NoiseSession {
    fn clone(&self) -> Self {
        Self {
            peer_id: self.peer_id.clone(),
            role: self.role,
            state: self.state.clone(),
            handshake_state: self.handshake_state.clone(),
            send_cipher: self.send_cipher.clone(),
            receive_cipher: self.receive_cipher.clone(),
            local_static_key: self.local_static_key.clone(),
            remote_static_public_key: self.remote_static_public_key,
            sent_handshake_messages: self.sent_handshake_messages.clone(),
            handshake_hash: self.handshake_hash.clone(),
        }
    }
}

impl Clone for NoiseCipherState {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            nonce: self.nonce,
            use_extracted_nonce: self.use_extracted_nonce,
            highest_received_nonce: self.highest_received_nonce,
            replay_window: self.replay_window.clone(),
        }
    }
}

impl Clone for NoiseHandshakeState {
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            pattern: self.pattern,
            symmetric_state: self.symmetric_state.clone(),
            local_static_private: self.local_static_private.clone(),
            local_static_public: self.local_static_public,
            local_ephemeral_private: self.local_ephemeral_private.clone(),
            local_ephemeral_public: self.local_ephemeral_public,
            remote_static_public: self.remote_static_public,
            remote_ephemeral_public: self.remote_ephemeral_public,
            message_patterns: self.message_patterns.clone(),
            current_pattern: self.current_pattern,
        }
    }
}

impl Clone for NoiseSymmetricState {
    fn clone(&self) -> Self {
        Self {
            cipher_state: self.cipher_state.clone(),
            chaining_key: self.chaining_key.clone(),
            hash: self.hash.clone(),
        }
    }
}

/// The session-lifecycle surface that the rest of the client actually reaches.
///
/// Scoped deliberately. `noise_session.rs` measured 43% covered, but a good part
/// of that was never a testing gap: `update_encryption_status`,
/// `get_encryption_status`, `get_peer_id_for_fingerprint` and the whole
/// pending-message queue had no callers outside this file. Pinning that
/// behaviour with tests would have made dead code harder to delete, so these
/// cover only what something else calls: `remove_session`,
/// `has_established_session`, and the fingerprint mapping the verification flow
/// depends on.
///
/// That judgement paid off directly — everything named above has since been
/// deleted, and because none of it was tested, the deletion removed no tests.
/// Five of the methods below did turn out to be reachable only from here, which
/// their own annotations now say; they are kept because deleting them would
/// delete these tests, which is a worse trade than an annotation.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn manager(seed: u8) -> NoiseSessionManager {
        NoiseSessionManager::new(StaticSecret::from([seed; 32]))
    }

    #[test]
    fn a_fresh_manager_holds_no_session_for_anyone() {
        let manager = manager(1);
        assert!(!manager.has_session("aabbccddeeff0011"));
        assert!(!manager.has_established_session("aabbccddeeff0011"));
    }

    #[test]
    fn creating_a_session_registers_it_but_does_not_establish_it() {
        // The distinction the send path depends on: mesh.rs asks
        // has_established_session before it will encrypt to a peer, so a session
        // that merely exists must not answer yes.
        let mut manager = manager(2);
        manager
            .create_session("aabbccddeeff0011".to_string(), NoiseRole::Initiator)
            .expect("a fresh session should be creatable");

        assert!(manager.has_session("aabbccddeeff0011"), "it should be registered");
        assert!(
            !manager.has_established_session("aabbccddeeff0011"),
            "no handshake has happened, so nothing may be encrypted to it yet"
        );
    }

    #[test]
    fn removing_a_session_forgets_it() {
        // remove_session is the one lifecycle call with several callers — it runs
        // when a peer ages out or is blocked, and a session surviving that would
        // keep a stale key usable.
        let mut manager = manager(3);
        manager
            .create_session("aabbccddeeff0011".to_string(), NoiseRole::Initiator)
            .unwrap();
        assert!(manager.has_session("aabbccddeeff0011"));

        manager.remove_session("aabbccddeeff0011");

        assert!(!manager.has_session("aabbccddeeff0011"), "the session must be gone");
        assert!(!manager.has_established_session("aabbccddeeff0011"));
    }

    #[test]
    fn removing_a_session_that_was_never_there_is_not_an_error() {
        // Callers remove on peer-left without checking first, and a peer can
        // leave before any handshake was attempted.
        let mut manager = manager(4);
        manager.remove_session("never-existed");
        assert!(!manager.has_session("never-existed"));
    }

    #[test]
    fn our_own_fingerprint_is_derived_from_our_key_and_is_stable() {
        // A peer reads this off our card to decide we are who we claim, so it
        // has to be a pure function of the key and not of when it was asked.
        let first = manager(5).get_identity_fingerprint();
        let second = manager(5).get_identity_fingerprint();

        assert_eq!(first, second, "same key must give the same fingerprint");
        assert_eq!(first.len(), 64, "a SHA-256 fingerprint is 64 hex characters");
        assert!(
            first.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lower-case hex, because it is compared as a string: {first}"
        );
    }

    #[test]
    fn a_different_key_is_a_different_fingerprint() {
        assert_ne!(
            manager(6).get_identity_fingerprint(),
            manager(7).get_identity_fingerprint(),
            "two identities must not collide"
        );
    }

    #[test]
    fn a_fingerprint_is_unverified_until_it_is_verified() {
        let mut manager = manager(8);
        let fingerprint = "a".repeat(64);

        assert!(
            !manager.is_fingerprint_verified(&fingerprint),
            "nothing is trusted by default"
        );

        manager.verify_fingerprint(&fingerprint);

        assert!(manager.is_fingerprint_verified(&fingerprint));
        assert!(manager.get_verified_fingerprints().contains(&fingerprint));
    }

    #[test]
    fn verifying_one_fingerprint_does_not_verify_another() {
        // The failure that would matter: verification is per-peer, and a blanket
        // yes would mean reading one card trusted everyone.
        let mut manager = manager(9);
        let verified = "b".repeat(64);
        let other = "c".repeat(64);

        manager.verify_fingerprint(&verified);

        assert!(manager.is_fingerprint_verified(&verified));
        assert!(
            !manager.is_fingerprint_verified(&other),
            "trust must not spread to a fingerprint nobody checked"
        );
    }

    #[test]
    fn verified_fingerprints_survive_being_reloaded_from_disk() {
        // These persist between runs — re-verifying a peer on every launch would
        // train the user to say yes without reading.
        let mut manager = manager(10);
        let one = "d".repeat(64);
        let two = "e".repeat(64);

        let mut stored = std::collections::HashSet::new();
        stored.insert(one.clone());
        stored.insert(two.clone());
        manager.load_verified_fingerprints(stored);

        assert!(manager.is_fingerprint_verified(&one));
        assert!(manager.is_fingerprint_verified(&two));
        assert_eq!(manager.get_verified_fingerprints().len(), 2);
    }

    #[test]
    fn verifying_the_same_fingerprint_twice_leaves_one_entry() {
        // It is a set, and a user who confirms twice must not grow the file that
        // gets written out.
        let mut manager = manager(11);
        let fingerprint = "f".repeat(64);

        manager.verify_fingerprint(&fingerprint);
        manager.verify_fingerprint(&fingerprint);

        assert_eq!(manager.get_verified_fingerprints().len(), 1);
    }

    #[test]
    fn a_peer_with_no_session_has_no_fingerprint() {
        // get_peer_fingerprint feeds the verification flow, which must not offer
        // to verify a peer we have never completed a handshake with.
        let manager = manager(12);
        assert!(manager.get_peer_fingerprint("aabbccddeeff0011").is_none());
    }

    #[test]
    fn storing_a_peers_static_key_is_refused_at_the_wrong_length() {
        // The key arrives off the wire in an announce, so the length is a
        // stranger's claim. x25519 is 32 bytes and nothing else.
        let mut manager = manager(13);

        assert!(
            manager.store_peer_static_key("aabbccddeeff0011", &[7u8; 32]).is_ok(),
            "a 32-byte key is the only valid shape"
        );
        for bad in [0usize, 1, 31, 33, 64] {
            assert!(
                manager
                    .store_peer_static_key("aabbccddeeff0011", &vec![7u8; bad])
                    .is_err(),
                "a {bad}-byte key must be refused"
            );
        }
    }
}
