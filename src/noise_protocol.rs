
// The unused items are the rest of the Noise specification - handshake patterns
// we do not initiate, replay-window constants, and mixing steps only some
// patterns use. Keeping the suite whole is cheaper than reconstructing it when
// a pattern is needed, and a partial implementation of a cryptographic spec is
// the kind of thing that looks fine until it does not.
#![allow(dead_code)]
use crate::data_structures::noise_trace;
use crate::debug_full_println;
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};
use generic_array::GenericArray;
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

// MARK: - Debug Logging

/// Every event here runs once per encrypt and once per decrypt, so this is the
/// hottest logging path in the client. It writes nothing unless the operator has
/// set `BITMANCER_NOISE_LOG`; see `data_structures::noise_trace` for why that
/// gate exists and what happened without it.
fn log_noise_protocol_event(event: &str, details: &str) {
    let message = format!("[NOISE_PROTOCOL_DEBUG] {} - {}", event, details);
    noise_trace(&message);
    debug_full_println!("{}", message);
}

// MARK: - Constants and Types

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoisePattern {
    XX, // Most versatile, mutual authentication
    IK, // Initiator knows responder's static key
    NK, // Anonymous initiator
    /// One message, no reply: the initiator already knows the responder's
    /// static key and says everything in one go. Exactly IK's first message,
    /// which is why it costs nothing but a table entry here.
    ///
    /// Used for courier envelopes, where the recipient is by definition not
    /// present to complete a handshake. The trade is stated plainly upstream and
    /// worth repeating: a one-way message has **no forward secrecy** — a later
    /// compromise of the recipient's static key exposes envelopes captured in
    /// transit. An established session is better whenever the peer is reachable.
    X,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseMessagePattern {
    E,  // Ephemeral key
    S,  // Static key
    EE, // DH(ephemeral, ephemeral)
    ES, // DH(ephemeral, static)
    SE, // DH(static, ephemeral)
    SS, // DH(static, static)
}

// MARK: - Noise Protocol Configuration

pub struct NoiseProtocolName {
    pub pattern: String,
    pub dh: String,
    pub cipher: String,
    pub hash: String,
}

impl NoiseProtocolName {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            dh: "25519".to_string(),
            cipher: "ChaChaPoly".to_string(),
            hash: "SHA256".to_string(),
        }
    }

    pub fn full_name(&self) -> String {
        format!(
            "Noise_{}_{}_{}_{}",
            self.pattern, self.dh, self.cipher, self.hash
        )
    }
}

// MARK: - Errors

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("Uninitialized cipher")]
    UninitializedCipher,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Handshake complete")]
    HandshakeComplete,
    #[error("Handshake not complete")]
    HandshakeNotComplete,
    #[error("Missing local static key")]
    MissingLocalStaticKey,
    #[error("Missing keys")]
    MissingKeys,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Authentication failure")]
    AuthenticationFailure,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Replay detected")]
    ReplayDetected,
    #[error("Nonce exceeded")]
    NonceExceeded,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid state")]
    InvalidState,
    #[error("Not established")]
    NotEstablished,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Already established")]
    AlreadyEstablished,
}

// MARK: - Cipher State

// Constants for replay protection
const NONCE_SIZE_BYTES: usize = 4;
const REPLAY_WINDOW_SIZE: usize = 1024;
const REPLAY_WINDOW_BYTES: usize = REPLAY_WINDOW_SIZE / 8; // 128 bytes
const HIGH_NONCE_WARNING_THRESHOLD: u64 = 1_000_000_000;

/// Manages symmetric encryption state for Noise protocol sessions.
/// Handles ChaCha20-Poly1305 AEAD encryption with automatic nonce management
/// and replay protection using a sliding window algorithm.
pub struct NoiseCipherState {
    pub key: Option<ChaChaKey>,
    pub nonce: u64,
    pub use_extracted_nonce: bool,
    pub replay_window: std::collections::HashSet<u64>,
    pub highest_received_nonce: u64,
}

impl Default for NoiseCipherState {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseCipherState {
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
            use_extracted_nonce: false,
            replay_window: std::collections::HashSet::new(),
            highest_received_nonce: 0,
        }
    }

    pub fn new_with_key(key: ChaChaKey, use_extracted_nonce: bool) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
            use_extracted_nonce,
            replay_window: std::collections::HashSet::new(),
            highest_received_nonce: 0,
        }
    }

    pub fn initialize_key(&mut self, key: ChaChaKey) {
        self.key = Some(key);
        self.nonce = 0;
        self.replay_window.clear();
        self.highest_received_nonce = 0;
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    // MARK: - Sliding Window Replay Protection

    /// Check if nonce is valid for replay protection
    fn is_valid_nonce(&self, received_nonce: u64) -> bool {
        if received_nonce + REPLAY_WINDOW_SIZE as u64 <= self.highest_received_nonce {
            return false; // Too old, outside window
        }

        if received_nonce > self.highest_received_nonce {
            return true; // Always accept newer nonces
        }

        // For nonces within the window, they're valid if NOT already seen
        !self.replay_window.contains(&received_nonce)
    }

    /// Mark nonce as seen in replay window
    fn mark_nonce_as_seen(&mut self, received_nonce: u64) {
        if received_nonce > self.highest_received_nonce {
            // Slide the window forward
            let shift = received_nonce - self.highest_received_nonce;

            if shift >= REPLAY_WINDOW_SIZE as u64 {
                // Clear entire window - shift is too large
                self.replay_window.clear();
            } else {
                // Remove nonces that are now too old
                self.replay_window
                    .retain(|&nonce| nonce + REPLAY_WINDOW_SIZE as u64 > received_nonce);
            }

            self.highest_received_nonce = received_nonce;
        }

        // Mark this nonce as seen
        self.replay_window.insert(received_nonce);
    }

    /// Extract nonce from combined payload <nonce><ciphertext>
    /// Returns tuple of (nonce, ciphertext) or None if invalid
    fn extract_nonce_from_ciphertext_payload(
        &self,
        combined_payload: &[u8],
    ) -> Option<(u64, Vec<u8>)> {
        if combined_payload.len() < NONCE_SIZE_BYTES {
            return None;
        }

        // Extract 4-byte nonce (little-endian to match Swift)
        let nonce_data = &combined_payload[..NONCE_SIZE_BYTES];
        let mut extracted_nonce: u64 = 0;
        for (i, &byte) in nonce_data.iter().enumerate() {
            extracted_nonce |= (byte as u64) << (i * 8);
        }

        // Extract ciphertext (remaining bytes)
        let ciphertext = combined_payload[NONCE_SIZE_BYTES..].to_vec();

        Some((extracted_nonce, ciphertext))
    }

    /// Convert nonce to 4-byte array (little-endian to match Swift)
    fn nonce_to_bytes(&self, nonce: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; NONCE_SIZE_BYTES];
        let nonce_le = nonce.to_le_bytes();
        // Copy only the first 4 bytes from the 8-byte u64
        bytes.copy_from_slice(&nonce_le[..NONCE_SIZE_BYTES]);
        bytes
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.key {
            log_noise_protocol_event(
                "CIPHER_ENCRYPT",
                &format!("Encrypting with key, plaintext length: {}", plaintext.len()),
            );
            log_noise_protocol_event("CIPHER_ENCRYPT_KEY", &format!("Key length: {}", key.len()));
            log_noise_protocol_event(
                "CIPHER_ENCRYPT_NONCE",
                &format!("Current nonce: {}", self.nonce),
            );
            log_noise_protocol_event(
                "CIPHER_ENCRYPT_ASSOCIATED_DATA",
                &format!("Associated data length: {}", associated_data.len()),
            );

            let current_nonce = self.nonce;

            // Create 12-byte nonce with counter in bytes 4-12 (little-endian like Swift)
            let mut nonce_bytes = [0u8; 12];
            let nonce_le_bytes = current_nonce.to_le_bytes();
            nonce_bytes[4..12].copy_from_slice(&nonce_le_bytes);
            let nonce_array = GenericArray::clone_from_slice(&nonce_bytes);

            // Create cipher
            let cipher = ChaCha20Poly1305::new(key);

            // Create payload with associated data
            let payload = Payload {
                msg: plaintext,
                aad: associated_data,
            };

            // Encrypt using the payload
            match cipher.encrypt(&nonce_array, payload) {
                Ok(ciphertext) => {
                    log_noise_protocol_event(
                        "CIPHER_ENCRYPT_SUCCESS",
                        &format!(
                            "Encryption successful, ciphertext length: {}",
                            ciphertext.len()
                        ),
                    );

                    // For transport messages with extracted nonce, prepend nonce to ciphertext
                    let result = if self.use_extracted_nonce {
                        let mut result = self.nonce_to_bytes(self.nonce);
                        result.extend_from_slice(&ciphertext);
                        log_noise_protocol_event(
                            "CIPHER_ENCRYPT_TRANSPORT",
                            &format!(
                                "Transport message with nonce prefix, total length: {}",
                                result.len()
                            ),
                        );
                        result
                    } else {
                        ciphertext
                    };

                    self.nonce += 1;
                    Ok(result)
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "CIPHER_ENCRYPT_ERROR",
                        &format!("Encryption failed: {:?}", e),
                    );
                    Err(NoiseError::EncryptionFailed)
                }
            }
        } else {
            Err(NoiseError::UninitializedCipher)
        }
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.key {
            log_noise_protocol_event(
                "CIPHER_DECRYPT",
                &format!(
                    "Decrypting with key, ciphertext length: {}",
                    ciphertext.len()
                ),
            );

            let (nonce, encrypted_payload): (u64, Vec<u8>) = if self.use_extracted_nonce {
                match self.extract_nonce_from_ciphertext_payload(ciphertext) {
                    Some((n, payload)) => {
                        // Nonce 0 is checked like every other nonce. It used to be
                        // exempt, which meant the first transport message of every
                        // session — the counter starts at 0 and increments after
                        // use — could be captured and replayed forever: the AEAD tag
                        // is genuine, so it decrypts every time, and the window
                        // never recorded it. Nothing downstream would have caught
                        // it; mesh dedup only covers public broadcasts.
                        if !self.is_valid_nonce(n) {
                            log_noise_protocol_event(
                                "CIPHER_DECRYPT_REPLAY_DETECTED",
                                &format!("Replay attack detected: nonce {} rejected", n),
                            );
                            return Err(NoiseError::ReplayDetected);
                        }
                        (n, payload)
                    }
                    None => return Err(NoiseError::InvalidCiphertext),
                }
            } else {
                (self.nonce, ciphertext.to_vec())
            };

            // Create 12-byte nonce with counter in bytes 4-12 (little-endian)
            let mut nonce_bytes = [0u8; 12];
            let nonce_le_bytes = nonce.to_le_bytes();
            nonce_bytes[4..12].copy_from_slice(&nonce_le_bytes);
            let nonce_array = GenericArray::clone_from_slice(&nonce_bytes);

            // Create cipher and decrypt
            let cipher = ChaCha20Poly1305::new(key);
            let payload = Payload {
                msg: &encrypted_payload,
                aad: associated_data,
            };

            match cipher.decrypt(&nonce_array, payload) {
                Ok(plaintext) => {
                    log_noise_protocol_event(
                        "CIPHER_DECRYPT_SUCCESS",
                        &format!(
                            "Decryption successful, plaintext length: {}",
                            plaintext.len()
                        ),
                    );

                    // Record the nonce only once the tag has verified, so a
                    // forged frame cannot burn a slot in the window. Nonce 0 is
                    // recorded like any other: exempting it here would leave the
                    // check above unable to reject the second copy, so the two
                    // exemptions had to be removed together.
                    if self.use_extracted_nonce {
                        self.mark_nonce_as_seen(nonce);
                    } else {
                        self.nonce += 1;
                    }
                    Ok(plaintext)
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "CIPHER_DECRYPT_ERROR",
                        &format!("Decryption failed: {:?}", e),
                    );
                    Err(NoiseError::DecryptionFailed)
                }
            }
        } else {
            Err(NoiseError::UninitializedCipher)
        }
    }
}

// MARK: - Symmetric State

/// Manages the symmetric cryptographic state during Noise handshakes.
/// Responsible for key derivation, protocol name hashing, and maintaining
/// the chaining key that provides key separation between handshake messages.
pub struct NoiseSymmetricState {
    pub cipher_state: NoiseCipherState,
    pub chaining_key: Vec<u8>,
    pub hash: Vec<u8>,
}

impl NoiseSymmetricState {
    pub fn new(protocol_name: &str) -> Self {
        let mut hash = vec![0u8; 32];
        let name_data = protocol_name.as_bytes();

        if name_data.len() <= 32 {
            hash[..name_data.len()].copy_from_slice(name_data);
        } else {
            let mut hasher = Sha256::new();
            hasher.update(name_data);
            hash.copy_from_slice(&hasher.finalize());
        }

        Self {
            cipher_state: NoiseCipherState::new(),
            chaining_key: hash.clone(),
            hash,
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let output = self.hkdf(&self.chaining_key, input_key_material, 2);
        self.chaining_key = output[0].clone();
        let temp_key = ChaChaKey::clone_from_slice(&output[1]);
        // During handshake, use internal nonce counter (not extracted nonce)
        self.cipher_state.initialize_key(temp_key);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().to_vec();
    }

    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let output = self.hkdf(&self.chaining_key, input_key_material, 3);
        self.chaining_key = output[0].clone();
        self.mix_hash(&output[1]);
        let temp_key = ChaChaKey::clone_from_slice(&output[2]);
        // During handshake, use internal nonce counter (not extracted nonce)
        self.cipher_state.initialize_key(temp_key);
    }

    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub fn has_cipher_key(&self) -> bool {
        self.cipher_state.has_key()
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.cipher_state.has_key() {
            let ciphertext = self.cipher_state.encrypt(plaintext, &self.hash)?;
            self.mix_hash(&ciphertext);
            Ok(ciphertext)
        } else {
            self.mix_hash(plaintext);
            Ok(plaintext.to_vec())
        }
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.cipher_state.has_key() {
            log_noise_protocol_event(
                "DECRYPT_AND_HASH",
                &format!(
                    "Decrypting with cipher key, ciphertext length: {}",
                    ciphertext.len()
                ),
            );
            log_noise_protocol_event(
                "DECRYPT_AND_HASH_HASH",
                &format!("Current hash length: {}", self.hash.len()),
            );
            log_noise_protocol_event(
                "DECRYPT_AND_HASH_HASH_BYTES",
                &format!("Hash bytes: {:?}", &self.hash[..8]),
            );

            // Handle empty ciphertext (matching Swift behavior)
            if ciphertext.is_empty() {
                log_noise_protocol_event(
                    "DECRYPT_AND_HASH_EMPTY",
                    "Empty ciphertext, returning empty plaintext",
                );
                self.mix_hash(ciphertext);
                return Ok(vec![]);
            }

            let plaintext = match self.cipher_state.decrypt(ciphertext, &self.hash) {
                Ok(pt) => {
                    log_noise_protocol_event(
                        "DECRYPT_AND_HASH_SUCCESS",
                        &format!("Decryption successful, plaintext length: {}", pt.len()),
                    );
                    pt
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "DECRYPT_AND_HASH_ERROR",
                        &format!("Decryption failed: {:?}", e),
                    );
                    return Err(e);
                }
            };

            // Only mix hash if decryption succeeded (matching Swift behavior)
            self.mix_hash(ciphertext);
            log_noise_protocol_event("DECRYPT_AND_HASH_HASH_MIXED", "Hash mixed with ciphertext");
            Ok(plaintext)
        } else {
            log_noise_protocol_event(
                "DECRYPT_AND_HASH",
                &format!(
                    "No cipher key, treating as plaintext, length: {}",
                    ciphertext.len()
                ),
            );
            self.mix_hash(ciphertext);
            log_noise_protocol_event("DECRYPT_AND_HASH_PLAINTEXT", "Hash mixed with plaintext");
            Ok(ciphertext.to_vec())
        }
    }

    pub fn split(&self) -> (NoiseCipherState, NoiseCipherState) {
        let output = self.hkdf(&self.chaining_key, &[], 2);
        let temp_key1 = ChaChaKey::clone_from_slice(&output[0]);
        let temp_key2 = ChaChaKey::clone_from_slice(&output[1]);

        // Transport ciphers MUST use extracted nonce and start fresh
        let mut c1 = NoiseCipherState::new_with_key(temp_key1, true);
        let mut c2 = NoiseCipherState::new_with_key(temp_key2, true);

        // Reset nonce counters and replay windows for transport mode
        c1.nonce = 0;
        c1.replay_window.clear();
        c1.highest_received_nonce = 0;

        c2.nonce = 0;
        c2.replay_window.clear();
        c2.highest_received_nonce = 0;

        (c1, c2)
    }

    // HKDF implementation matching Swift version
    fn hkdf(
        &self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        num_outputs: usize,
    ) -> Vec<Vec<u8>> {
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(chaining_key).unwrap();
        HmacMac::update(&mut mac, input_key_material);
        let temp_key = mac.finalize().into_bytes();

        let mut outputs = Vec::new();
        let mut current_output = Vec::new();

        for i in 1..=num_outputs {
            let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&temp_key).unwrap();
            HmacMac::update(&mut mac, &current_output);
            HmacMac::update(&mut mac, &[i as u8]);
            current_output = mac.finalize().into_bytes().to_vec();
            outputs.push(current_output.clone());
        }

        outputs
    }
}

// MARK: - Handshake State

/// Orchestrates the complete Noise handshake process.
/// This is the main interface for establishing encrypted sessions between peers.
/// Manages the handshake state machine, message patterns, and key derivation.
pub struct NoiseHandshakeState {
    pub role: NoiseRole,
    pub pattern: NoisePattern,
    pub symmetric_state: NoiseSymmetricState,

    // Keys
    pub local_static_private: Option<StaticSecret>,
    pub local_static_public: Option<PublicKey>,
    pub local_ephemeral_private: Option<StaticSecret>,
    pub local_ephemeral_public: Option<PublicKey>,

    pub remote_static_public: Option<PublicKey>,
    pub remote_ephemeral_public: Option<PublicKey>,

    // Message patterns
    pub message_patterns: Vec<Vec<NoiseMessagePattern>>,
    pub current_pattern: usize,
}

impl NoiseHandshakeState {
    pub fn new(
        role: NoiseRole,
        pattern: NoisePattern,
        local_static_key: Option<StaticSecret>,
        remote_static_key: Option<PublicKey>,
    ) -> Self {
        Self::with_prologue(role, pattern, local_static_key, remote_static_key, &[])
    }

    /// The same, with a prologue mixed into the transcript before anything else.
    ///
    /// Domain separation, and load-bearing: it is what stops a one-way courier
    /// envelope and an interactive handshake transcript from ever being
    /// confused for one another.
    pub fn with_prologue(
        role: NoiseRole,
        pattern: NoisePattern,
        local_static_key: Option<StaticSecret>,
        remote_static_key: Option<PublicKey>,
        prologue: &[u8],
    ) -> Self {
        // Initialize protocol name
        let protocol_name = NoiseProtocolName::new(pattern.pattern_name());
        let full_name = protocol_name.full_name();
        log_noise_protocol_event("HANDSHAKE_INIT", &format!("Protocol name: {}", full_name));
        let symmetric_state = NoiseSymmetricState::new(&full_name);
        log_noise_protocol_event(
            "HANDSHAKE_INIT",
            &format!("Initial hash: {:?}", &symmetric_state.hash[..8]),
        );
        log_noise_protocol_event(
            "HANDSHAKE_INIT",
            &format!(
                "Initial chaining key: {:?}",
                &symmetric_state.chaining_key[..8]
            ),
        );

        // Initialize message patterns
        let message_patterns = pattern.message_patterns();

        let mut handshake = Self {
            role,
            pattern,
            symmetric_state,
            local_static_private: local_static_key.clone(),
            local_static_public: local_static_key.as_ref().map(PublicKey::from),
            local_ephemeral_private: None,
            local_ephemeral_public: None,
            remote_static_public: remote_static_key,
            remote_ephemeral_public: None,
            message_patterns,
            current_pattern: 0,
        };

        // Mix pre-message keys according to pattern
        handshake.mix_pre_message_keys(prologue);
        handshake
    }

    fn mix_pre_message_keys(&mut self, prologue: &[u8]) {
        self.symmetric_state.mix_hash(prologue);
        match self.pattern {
            NoisePattern::XX => {
                // Nothing is known in advance, so there is no pre-message.
            }
            // `<- s`: the responder's static key is known to the initiator
            // before the handshake starts, so both sides mix it into the
            // transcript. **Both** — the initiator mixes the key it was given
            // and the responder mixes its own. Mixing on one side only leaves
            // the two transcripts different and nothing decrypts, which stayed
            // invisible while only XX was in use.
            NoisePattern::IK | NoisePattern::NK | NoisePattern::X => {
                let responder_static = if matches!(self.role, NoiseRole::Initiator) {
                    self.remote_static_public.map(|key| key.to_bytes())
                } else {
                    self.local_static_public.map(|key| key.to_bytes())
                };
                if let Some(key) = responder_static {
                    self.symmetric_state.mix_hash(&key);
                }
            }
        }
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        log_noise_protocol_event(
            "WRITE_MESSAGE_START",
            &format!(
                "Pattern: {:?}, Current: {}/{}",
                self.pattern,
                self.current_pattern,
                self.message_patterns.len()
            ),
        );

        if self.current_pattern >= self.message_patterns.len() {
            log_noise_protocol_event(
                "WRITE_MESSAGE_ERROR",
                "Handshake complete, cannot write more messages",
            );
            return Err(NoiseError::HandshakeComplete);
        }

        let mut message_buffer = Vec::new();
        let patterns = &self.message_patterns[self.current_pattern];
        log_noise_protocol_event(
            "WRITE_MESSAGE_PATTERNS",
            &format!("Processing patterns: {:?}", patterns),
        );

        for pattern in patterns {
            log_noise_protocol_event(
                "WRITE_MESSAGE_PATTERN",
                &format!("Processing pattern: {:?}", pattern),
            );

            match pattern {
                NoiseMessagePattern::E => {
                    log_noise_protocol_event("WRITE_MESSAGE_E", "Generating ephemeral key");
                    // Generate ephemeral key
                    self.local_ephemeral_private =
                        Some(StaticSecret::random_from_rng(rand::thread_rng()));
                    self.local_ephemeral_public = Some(PublicKey::from(
                        self.local_ephemeral_private.as_ref().unwrap(),
                    ));
                    message_buffer.extend_from_slice(
                        &self.local_ephemeral_public.as_ref().unwrap().to_bytes(),
                    );
                    self.symmetric_state
                        .mix_hash(&self.local_ephemeral_public.as_ref().unwrap().to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_E_DONE",
                        &format!(
                            "Ephemeral key generated, buffer size: {}",
                            message_buffer.len()
                        ),
                    );
                }

                NoiseMessagePattern::S => {
                    log_noise_protocol_event("WRITE_MESSAGE_S", "Sending static key");
                    // Send static key (encrypted if cipher is initialized)
                    let static_public = self
                        .local_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingLocalStaticKey)?;
                    let encrypted = self
                        .symmetric_state
                        .encrypt_and_hash(&static_public.to_bytes())?;
                    message_buffer.extend_from_slice(&encrypted);
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_S_DONE",
                        &format!(
                            "Static key encrypted and sent, buffer size: {}",
                            message_buffer.len()
                        ),
                    );
                }

                NoiseMessagePattern::EE => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_EE",
                        "Performing DH(ephemeral, ephemeral)",
                    );
                    // DH(local ephemeral, remote ephemeral)
                    let local_ephemeral = self
                        .local_ephemeral_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self
                        .remote_ephemeral_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_EE_DONE",
                        "DH(ephemeral, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::ES => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_ES",
                        &format!("Performing DH(ephemeral, static), role: {:?}", self.role),
                    );
                    // DH(ephemeral, static) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_ephemeral = self
                                .local_ephemeral_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self
                                .remote_static_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_ES_DONE",
                                "DH(ephemeral, static) completed for initiator",
                            );
                        }
                        NoiseRole::Responder => {
                            let local_static = self
                                .local_static_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self
                                .remote_ephemeral_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_ES_DONE",
                                "DH(ephemeral, static) completed for responder",
                            );
                        }
                    }
                }

                NoiseMessagePattern::SE => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_SE",
                        &format!("Performing DH(static, ephemeral), role: {:?}", self.role),
                    );
                    // DH(static, ephemeral) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_static = self
                                .local_static_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self
                                .remote_ephemeral_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_SE_DONE",
                                "DH(static, ephemeral) completed for initiator",
                            );
                        }
                        NoiseRole::Responder => {
                            let local_ephemeral = self
                                .local_ephemeral_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self
                                .remote_static_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_SE_DONE",
                                "DH(static, ephemeral) completed for responder",
                            );
                        }
                    }
                }

                NoiseMessagePattern::SS => {
                    log_noise_protocol_event("WRITE_MESSAGE_SS", "Performing DH(static, static)");
                    // DH(static, static)
                    let local_static = self
                        .local_static_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self
                        .remote_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_SS_DONE",
                        "DH(static, static) completed",
                    );
                }
            }
        }

        // Encrypt payload
        log_noise_protocol_event(
            "WRITE_MESSAGE_ENCRYPT",
            &format!("Encrypting payload of {} bytes", payload.len()),
        );
        let encrypted_payload = self.symmetric_state.encrypt_and_hash(payload)?;
        message_buffer.extend_from_slice(&encrypted_payload);
        log_noise_protocol_event(
            "WRITE_MESSAGE_ENCRYPT_DONE",
            &format!(
                "Payload encrypted, total buffer size: {}",
                message_buffer.len()
            ),
        );

        self.current_pattern += 1;
        log_noise_protocol_event(
            "WRITE_MESSAGE_COMPLETE",
            &format!(
                "Message written, pattern {} complete",
                self.current_pattern - 1
            ),
        );
        Ok(message_buffer)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        log_noise_protocol_event(
            "READ_MESSAGE_START",
            &format!(
                "Pattern: {:?}, Current: {}/{}",
                self.pattern,
                self.current_pattern,
                self.message_patterns.len()
            ),
        );
        log_noise_protocol_event(
            "READ_MESSAGE_HASH_BEFORE",
            &format!("Hash before read: {:?}", &self.symmetric_state.hash[..8]),
        );

        if self.current_pattern >= self.message_patterns.len() {
            log_noise_protocol_event("READ_MESSAGE_ERROR", "Handshake complete");
            return Err(NoiseError::HandshakeComplete);
        }

        let patterns = &self.message_patterns[self.current_pattern];
        log_noise_protocol_event(
            "READ_MESSAGE_PATTERNS",
            &format!("Processing patterns: {:?}", patterns),
        );

        let mut offset = 0;

        for pattern in patterns {
            log_noise_protocol_event(
                "READ_MESSAGE_PATTERN",
                &format!("Processing pattern: {:?}", pattern),
            );
            log_noise_protocol_event(
                "READ_MESSAGE_HASH_BEFORE_PATTERN",
                &format!("Hash before pattern: {:?}", &self.symmetric_state.hash[..8]),
            );

            match pattern {
                NoiseMessagePattern::E => {
                    log_noise_protocol_event("READ_MESSAGE_E", "Reading ephemeral key");

                    if offset + 32 > message.len() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_E_ERROR",
                            "Message too short for ephemeral key",
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let ephemeral_bytes = &message[offset..offset + 32];
                    offset += 32;

                    log_noise_protocol_event(
                        "READ_MESSAGE_E_BYTES",
                        &format!("Ephemeral key bytes: {:?}", &ephemeral_bytes[..8]),
                    );

                    // Checked like the static key below, and for the same reason.
                    // This was the larger half of the gap: the static key was
                    // validated and the ephemeral was not, so a peer could send a
                    // low-order point here and drive `ee` — and every later
                    // mixing that uses it — to a shared secret of all zeroes.
                    // Refusing before `mix_hash` matters: once these bytes are in
                    // the transcript hash the handshake has already committed to
                    // them.
                    let ephemeral_key = Self::validate_public_key(ephemeral_bytes).inspect_err(|_| {
                        log_noise_protocol_event(
                            "READ_MESSAGE_E_ERROR",
                            "Ephemeral key validation failed",
                        );
                    })?;
                    self.remote_ephemeral_public = Some(ephemeral_key);
                    self.symmetric_state.mix_hash(ephemeral_bytes);

                    log_noise_protocol_event(
                        "READ_MESSAGE_E_DONE",
                        &format!("Ephemeral key read, offset: {}", offset),
                    );
                }

                NoiseMessagePattern::S => {
                    log_noise_protocol_event("READ_MESSAGE_S", "Reading static key");

                    // Read static key (may be encrypted)
                    // Swift sends unencrypted static key (32 bytes) before establishing cipher key
                    let key_length = if self.symmetric_state.has_cipher_key() {
                        48
                    } else {
                        32
                    }; // 32 + 16 byte tag if encrypted

                    log_noise_protocol_event(
                        "READ_MESSAGE_S_CHECK",
                        &format!(
                            "Checking static key length: need {} bytes, available {} bytes, has_cipher_key: {}",
                            key_length,
                            message.len() - offset,
                            self.symmetric_state.has_cipher_key()
                        ),
                    );

                    if offset + key_length > message.len() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            &format!(
                                "Message too short for static key, need {} bytes, have {} bytes",
                                key_length,
                                message.len() - offset
                            ),
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let static_data = &message[offset..offset + key_length];
                    offset += key_length;

                    log_noise_protocol_event(
                        "READ_MESSAGE_S_DATA",
                        &format!(
                            "Static key data length: {}, has_cipher_key: {}",
                            key_length,
                            self.symmetric_state.has_cipher_key()
                        ),
                    );

                    let decrypted_static = self.symmetric_state.decrypt_and_hash(static_data)?;

                    if decrypted_static.len() != 32 {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            &format!(
                                "Invalid decrypted static key length: {}",
                                decrypted_static.len()
                            ),
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let static_key =
                        PublicKey::from(<[u8; 32]>::try_from(&decrypted_static[..32]).unwrap());

                    if Self::validate_public_key(&static_key.to_bytes()).is_err() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            "Static key validation failed",
                        );
                        return Err(NoiseError::AuthenticationFailure);
                    }

                    self.remote_static_public = Some(static_key);
                    log_noise_protocol_event(
                        "READ_MESSAGE_S_DONE",
                        "Static key read and validated successfully",
                    );
                }

                NoiseMessagePattern::EE => {
                    log_noise_protocol_event(
                        "READ_MESSAGE_EE",
                        "Performing DH(ephemeral, ephemeral)",
                    );

                    let local_ephemeral = self
                        .local_ephemeral_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self
                        .remote_ephemeral_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;

                    let shared_secret = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared_secret.to_bytes());

                    log_noise_protocol_event(
                        "READ_MESSAGE_EE_DONE",
                        "DH(ephemeral, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::ES => {
                    log_noise_protocol_event("READ_MESSAGE_ES", "Performing DH(ephemeral, static)");

                    if self.role == NoiseRole::Initiator {
                        let local_ephemeral = self
                            .local_ephemeral_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_static = self
                            .remote_static_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_ephemeral.diffie_hellman(remote_static);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    } else {
                        let local_static = self
                            .local_static_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_ephemeral = self
                            .remote_ephemeral_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_static.diffie_hellman(remote_ephemeral);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    }

                    log_noise_protocol_event(
                        "READ_MESSAGE_ES_DONE",
                        "DH(ephemeral, static) completed",
                    );
                }

                NoiseMessagePattern::SE => {
                    log_noise_protocol_event("READ_MESSAGE_SE", "Performing DH(static, ephemeral)");

                    if self.role == NoiseRole::Initiator {
                        let local_static = self
                            .local_static_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_ephemeral = self
                            .remote_ephemeral_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_static.diffie_hellman(remote_ephemeral);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    } else {
                        let local_ephemeral = self
                            .local_ephemeral_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_static = self
                            .remote_static_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_ephemeral.diffie_hellman(remote_static);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    }

                    log_noise_protocol_event(
                        "READ_MESSAGE_SE_DONE",
                        "DH(static, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::SS => {
                    log_noise_protocol_event("READ_MESSAGE_SS", "Performing DH(static, static)");

                    let local_static = self
                        .local_static_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self
                        .remote_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;

                    let shared_secret = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared_secret.to_bytes());

                    log_noise_protocol_event(
                        "READ_MESSAGE_SS_DONE",
                        "DH(static, static) completed",
                    );
                }
            }

            log_noise_protocol_event(
                "READ_MESSAGE_HASH_AFTER_PATTERN",
                &format!(
                    "Hash after pattern {:?}: {:?}",
                    pattern,
                    &self.symmetric_state.hash[..8]
                ),
            );
        }

        // Decrypt payload
        let payload = &message[offset..];
        log_noise_protocol_event(
            "READ_MESSAGE_PAYLOAD",
            &format!("Decrypting payload, length: {}", payload.len()),
        );

        // A payload that does not authenticate fails the handshake. It used to
        // be swallowed and returned as an empty payload "for debugging", which
        // is an integrity hole rather than a leniency: the tag check is the only
        // thing standing between a reader and modified plaintext, and treating
        // its failure as "no message" means anyone in the path can silently
        // blank a message while the *sender* still authenticates — the static
        // key decrypts a step earlier. The recipient then sees an empty message
        // that is provably from someone who never sent it.
        //
        // Latent while every handshake payload we sent was empty. Not latent for
        // courier envelopes, where the payload is the message.
        let decrypted_payload = self.symmetric_state.decrypt_and_hash(payload).map_err(|e| {
            log_noise_protocol_event(
                "READ_MESSAGE_PAYLOAD_ERROR",
                &format!("Payload failed to authenticate: {e:?}"),
            );
            e
        })?;
        log_noise_protocol_event(
            "READ_MESSAGE_PAYLOAD_SUCCESS",
            &format!(
                "Payload decrypted successfully, length: {}",
                decrypted_payload.len()
            ),
        );

        self.current_pattern += 1;
        log_noise_protocol_event(
            "READ_MESSAGE_COMPLETE",
            &format!(
                "Message read successfully, new pattern: {}/{}",
                self.current_pattern,
                self.message_patterns.len()
            ),
        );
        log_noise_protocol_event(
            "READ_MESSAGE_HASH_AFTER",
            &format!("Hash after read: {:?}", &self.symmetric_state.hash[..8]),
        );
        Ok(decrypted_payload)
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.current_pattern >= self.message_patterns.len()
    }

    pub fn get_transport_ciphers(
        &self,
    ) -> Result<(NoiseCipherState, NoiseCipherState), NoiseError> {
        if !self.is_handshake_complete() {
            return Err(NoiseError::HandshakeNotComplete);
        }

        let (c1, c2) = self.symmetric_state.split();

        // FIXED: Correct cipher assignment - initiator uses c1 for send, c2 for receive
        // Responder uses c2 for send, c1 for receive
        Ok(match self.role {
            NoiseRole::Initiator => (c1, c2), // send_cipher, receive_cipher
            NoiseRole::Responder => (c2, c1), // send_cipher, receive_cipher  
        })
    }

    pub fn get_remote_static_public_key(&self) -> Option<PublicKey> {
        self.remote_static_public
    }

    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.symmetric_state.get_handshake_hash()
    }
}

// MARK: - Pattern Extensions

impl NoisePattern {
    pub fn pattern_name(&self) -> &'static str {
        match self {
            NoisePattern::XX => "XX",
            NoisePattern::IK => "IK",
            NoisePattern::NK => "NK",
            NoisePattern::X => "X",
        }
    }

    pub fn message_patterns(&self) -> Vec<Vec<NoiseMessagePattern>> {
        match self {
            NoisePattern::XX => {
                vec![
                    vec![NoiseMessagePattern::E], // -> e
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::EE,
                        NoiseMessagePattern::S,
                        NoiseMessagePattern::ES,
                    ], // <- e, ee, s, es
                    vec![NoiseMessagePattern::S, NoiseMessagePattern::SE], // -> s, se
                ]
            }
            NoisePattern::IK => {
                vec![
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::ES,
                        NoiseMessagePattern::S,
                        NoiseMessagePattern::SS,
                    ], // -> e, es, s, ss
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::EE,
                        NoiseMessagePattern::SE,
                    ], // <- e, ee, se
                ]
            }
            NoisePattern::NK => {
                vec![
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::ES], // -> e, es
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::EE], // <- e, ee
                ]
            }
            // IK's first message and nothing after it. The `ss` is what binds
            // the sender's identity to the ciphertext, so a recipient learns who
            // wrote to them without either side exchanging a second packet.
            NoisePattern::X => {
                vec![vec![
                    NoiseMessagePattern::E,
                    NoiseMessagePattern::ES,
                    NoiseMessagePattern::S,
                    NoiseMessagePattern::SS,
                ]] // -> e, es, s, ss
            }
        }
    }
}

// MARK: - Key Validation

/// The seven low-order points of Curve25519, as little-endian u-coordinates
/// with bit 255 masked off.
///
/// A peer offering one of these forces the shared secret to a value known in
/// advance — the small-subgroup attack `validate_public_key` exists to refuse.
/// No honest peer sends one: an X25519 public key comes from a random scalar,
/// so producing a low-order point by accident does not happen, and refusing
/// them cannot cost an interoperable handshake.
///
/// The list this replaces was trying to be these and was not. One entry was 31
/// bytes long, so it could never equal a key already length-checked to 32.
/// Another was byte-reversed — big-endian one where the encoding is
/// little-endian. Three more were `ff`-filled where p-1, p and p+1 end in `7f`.
///
/// Then a second layer underneath that one: even spelled correctly, comparing
/// raw bytes catches only one of the *two* encodings each point has, because
/// RFC 7748 masks bit 255. `validate_public_key` masks before comparing, which
/// is what lets this table be exactly seven entries instead of fourteen.
///
/// Lives at module scope so the tests can audit it directly. Two do:
/// `low_order_table_entries_are_actually_low_order` drives each entry through a
/// real Diffie-Hellman and requires an all-zero secret, and
/// `every_table_entry_is_reachable_by_the_check` requires the check to reject
/// it. Between them, an entry that is wrong and an entry that is unreachable
/// both fail, which is the pair of mistakes this table has already made once.
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    // 0 — order 1. Also caught by the all-zero check; kept so this is the
    // complete list rather than the complete list minus one.
    [0x00; 32],
    // 1 — order 4.
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // order 8.
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 8. Published ending `d7`; stored masked, hence `57`.
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p.
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1.
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl NoiseHandshakeState {
    /// Validate a Curve25519 public key
    /// Checks for weak/invalid keys that could compromise security
    pub fn validate_public_key(key_data: &[u8]) -> Result<PublicKey, NoiseError> {
        // Check key length
        if key_data.len() != 32 {
            return Err(NoiseError::InvalidPublicKey);
        }

        let received: [u8; 32] = key_data
            .try_into()
            .map_err(|_| NoiseError::InvalidPublicKey)?;

        // Compare on the masked form, never on the bytes as they arrived.
        //
        // RFC 7748 has the receiver ignore bit 255 of a u-coordinate, and
        // x25519-dalek duly masks it before doing anything with the point. So
        // every point on this curve has *two* legal encodings that differ only
        // in that bit, and they are the same point: the Diffie-Hellman output
        // is identical for both.
        //
        // A table compared against raw bytes therefore catches at most half of
        // what it lists. That is not hypothetical — with the table below
        // compared raw, all seven low-order points sailed through in their
        // high-bit-set form, including zero, which also walks past an all-zero
        // check that runs on the unmasked bytes. Masking first collapses the
        // two encodings into one and makes the table complete by construction
        // rather than by remembering to list every spelling.
        let mut canonical = received;
        canonical[31] &= 0x7f;

        // Check for all-zero key (point at infinity)
        if canonical.iter().all(|&b| b == 0) {
            return Err(NoiseError::InvalidPublicKey);
        }

        if LOW_ORDER_POINTS.contains(&canonical) {
            debug_full_println!("[NOISE] Low-order point detected");
            return Err(NoiseError::InvalidPublicKey);
        }

        // The key is built from the bytes as they arrived, not from the masked
        // copy. Masking is how the point is *recognised*; the transcript has to
        // keep what the peer actually sent, because the peer mixed those same
        // bytes into its own handshake hash. For an honest key the two are
        // identical anyway — a real u-coordinate is below p, so bit 255 is
        // already clear and the mask is a no-op.
        Ok(PublicKey::from(received))
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    /// Two transport ciphers over one key, which is the shape `split()` hands
    /// out: one end encrypts, the other receives. Same key both sides so a
    /// frame written by the first opens on the second.
    fn transport_pair() -> (NoiseCipherState, NoiseCipherState) {
        let material = [7u8; 32];
        (
            NoiseCipherState::new_with_key(ChaChaKey::clone_from_slice(&material), true),
            NoiseCipherState::new_with_key(ChaChaKey::clone_from_slice(&material), true),
        )
    }

    #[test]
    fn the_first_frame_of_a_session_cannot_be_replayed() {
        // The defect this module exists for. The send counter starts at 0 and
        // increments after use, so every session's opening frame is nonce 0 —
        // and nonce 0 used to skip both the replay check and the window update.
        // Its tag is genuine, so it decrypted every time it was rewritten to the
        // link, and no mesh-layer dedup covers private messages.
        let (mut sender, mut receiver) = transport_pair();
        let frame = sender.encrypt(b"first words", b"").unwrap();

        assert_eq!(
            &frame[..NONCE_SIZE_BYTES],
            &[0, 0, 0, 0],
            "the opening frame must be the one carrying nonce 0"
        );
        assert_eq!(receiver.decrypt(&frame, b"").unwrap(), b"first words");
        assert!(
            matches!(receiver.decrypt(&frame, b""), Err(NoiseError::ReplayDetected)),
            "a captured opening frame must not open a second time"
        );
    }

    #[test]
    fn a_later_frame_cannot_be_replayed_either() {
        // The path that always worked. Kept so removing the nonce-0 exemption
        // cannot quietly cost us the protection that was already there.
        let (mut sender, mut receiver) = transport_pair();
        let first = sender.encrypt(b"one", b"").unwrap();
        let second = sender.encrypt(b"two", b"").unwrap();

        receiver.decrypt(&first, b"").unwrap();
        receiver.decrypt(&second, b"").unwrap();

        assert!(
            matches!(
                receiver.decrypt(&second, b""),
                Err(NoiseError::ReplayDetected)
            ),
            "a nonce already in the window must be refused"
        );
    }

    #[test]
    fn a_frame_arriving_out_of_order_inside_the_window_still_opens() {
        // BLE reorders. The window exists so a late frame is still accepted;
        // rejecting anything below the high-water mark would drop real traffic.
        let (mut sender, mut receiver) = transport_pair();
        let first = sender.encrypt(b"one", b"").unwrap();
        let second = sender.encrypt(b"two", b"").unwrap();

        receiver.decrypt(&second, b"").unwrap();
        assert_eq!(
            receiver.decrypt(&first, b"").unwrap(),
            b"one",
            "the earlier frame must still open after the later one"
        );
    }

    #[test]
    fn a_frame_older_than_the_window_is_refused() {
        // Past REPLAY_WINDOW_SIZE the window can no longer prove a nonce is
        // unseen, so the only safe answer is no. Accepting it would reopen the
        // replay hole for anything the attacker held on to for long enough.
        let (mut sender, mut receiver) = transport_pair();
        let oldest = sender.encrypt(b"oldest", b"").unwrap();

        for _ in 0..=REPLAY_WINDOW_SIZE {
            let frame = sender.encrypt(b"filler", b"").unwrap();
            receiver.decrypt(&frame, b"").unwrap();
        }

        assert!(
            matches!(
                receiver.decrypt(&oldest, b""),
                Err(NoiseError::ReplayDetected)
            ),
            "a nonce that has fallen out of the window must not be treated as new"
        );
    }

    #[test]
    fn a_forged_frame_does_not_consume_a_window_slot() {
        // The window is updated after the tag verifies, not before. If it were
        // the other way round, anyone in the path could burn the genuine
        // sender's nonce by flipping a byte, and the real frame would then be
        // rejected as a replay of the forgery.
        let (mut sender, mut receiver) = transport_pair();
        let mut frame = sender.encrypt(b"genuine", b"").unwrap();
        let last = frame.len() - 1;

        frame[last] ^= 0x01;
        assert!(
            receiver.decrypt(&frame, b"").is_err(),
            "a tampered tag must not open"
        );

        frame[last] ^= 0x01;
        assert_eq!(
            receiver.decrypt(&frame, b"").unwrap(),
            b"genuine",
            "the forged attempt must not have spent nonce 0"
        );
    }

    #[test]
    fn a_rekey_admits_nonce_zero_again() {
        // The interop case, and the reason this fix is a deletion rather than a
        // `zero_seen` flag. `split()` builds fresh transport ciphers and clears
        // the window, so a legitimate first frame after a re-handshake is nonce
        // 0 on an empty window and must still open.
        //
        // If a peer ever resets its send counter *without* re-handshaking, its
        // next frame arrives as nonce 0 against a window that already holds 0
        // and we refuse it. The answer to that is to tear down and re-handshake,
        // not to exempt the nonce again.
        let (mut sender, mut receiver) = transport_pair();
        let frame = sender.encrypt(b"before", b"").unwrap();
        receiver.decrypt(&frame, b"").unwrap();
        assert!(
            matches!(receiver.decrypt(&frame, b""), Err(NoiseError::ReplayDetected)),
            "the window must be holding nonce 0 before the rekey"
        );

        receiver.initialize_key(ChaChaKey::clone_from_slice(&[7u8; 32]));

        assert_eq!(
            receiver.decrypt(&frame, b"").unwrap(),
            b"before",
            "a rekey restarts the nonce space, so nonce 0 is legitimate again"
        );
    }
}

/// The adversarial half of this file: what happens when the bytes are hostile
/// rather than merely malformed.
///
/// `replay_tests` above covers the nonce window. These cover the other three
/// places a peer's input reaches the cryptography — the public keys it offers,
/// the ciphertext it sends, and the handshake messages it truncates.
#[cfg(test)]
mod adversarial_tests {
    use super::*;

    /// The seven low-order points of Curve25519 as little-endian u-coordinates.
    /// Written out here independently of the table in `validate_public_key`, so
    /// this is a check against the published values rather than against the
    /// implementation restating itself.
    const CANONICAL_LOW_ORDER: [(&str, &str); 7] = [
        ("order 1", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("order 4", "0100000000000000000000000000000000000000000000000000000000000000"),
        ("order 8 a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        // Ends d7, which is how this point is published. The table it is
        // checked against stores 57 — the same value with bit 255 masked off —
        // and that is correct now only because the check masks before
        // comparing. Written the published way on purpose: a constant that
        // matches the implementation's spelling cannot catch the
        // implementation's spelling being wrong.
        ("order 8 b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"),
        ("p-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];

    fn hex32(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        bytes.try_into().expect("32 bytes")
    }

    /// Every low-order point again, with bit 255 set.
    ///
    /// RFC 7748 has the receiver mask that bit, so each of these is the *same
    /// point* as its counterpart above and reaches the same all-zero shared
    /// secret. All seven were accepted while the check compared raw bytes —
    /// including zero, whose high-bit-set form walks past an all-zero test that
    /// runs before masking. Enumerating points cannot fix that, because the
    /// thing being enumerated has two spellings; masking first can, and this is
    /// the test that says so.
    #[test]
    fn the_other_encoding_of_every_low_order_point_is_refused_too() {
        for (name, hex) in CANONICAL_LOW_ORDER {
            let mut point = hex32(hex);
            point[31] |= 0x80;
            assert!(
                NoiseHandshakeState::validate_public_key(&point).is_err(),
                "{name} with bit 255 set is the same point and must be refused"
            );
        }
    }

    /// The table holds what it claims to hold.
    ///
    /// Checked by behaviour rather than by eye: each entry is driven through a
    /// real Diffie-Hellman and has to produce an all-zero shared secret, which
    /// is what makes a point worth refusing. Three entries inherited from the
    /// original list did not survive this — they were `ff`-terminated values
    /// described as "not low-order points, kept because dropping them would
    /// relax a check," and after masking they could not have matched anything
    /// anyway. An entry nobody can reach is indistinguishable from an entry
    /// nobody needs, and this is the test that tells them apart.
    #[test]
    fn low_order_table_entries_are_actually_low_order() {
        let secret = StaticSecret::from([9u8; 32]);
        for (index, entry) in super::LOW_ORDER_POINTS.iter().enumerate() {
            let shared = secret.diffie_hellman(&PublicKey::from(*entry));
            assert!(
                shared.as_bytes().iter().all(|&byte| byte == 0),
                "table entry {index} does not zero the shared secret, so it is \
                 not a low-order point and does not belong in this table"
            );
            assert!(
                !shared.was_contributory(),
                "table entry {index} is contributory, so it is not the hazard \
                 this table exists to refuse"
            );
        }
    }

    /// Nothing in the table is unreachable.
    ///
    /// The defect that started all of this was an entry that could never equal
    /// any input — 31 bytes long, against a key already length-checked to 32.
    /// Every entry must be something `validate_public_key` actually rejects,
    /// or it is decoration.
    #[test]
    fn every_table_entry_is_reachable_by_the_check() {
        for (index, entry) in super::LOW_ORDER_POINTS.iter().enumerate() {
            assert!(
                NoiseHandshakeState::validate_public_key(entry).is_err(),
                "table entry {index} is not refused by the check that lists it"
            );
        }
    }

    #[test]
    fn every_canonical_low_order_point_is_refused() {
        // Four of these used to get through. The table meant to hold them had a
        // 31-byte entry that could never match a length-checked key, a
        // byte-reversed one, and three `ff`-filled values where p-1, p and p+1
        // end in `7f`.
        for (name, hex) in CANONICAL_LOW_ORDER {
            let point = hex32(hex);
            assert!(
                NoiseHandshakeState::validate_public_key(&point).is_err(),
                "{name} is a low-order point and must be refused"
            );
        }
    }

    #[test]
    fn a_low_order_point_would_have_made_the_shared_secret_predictable() {
        // Why the test above matters, stated as an observation rather than an
        // argument: each of these drives the Diffie-Hellman output to all zeroes,
        // which is a value the other side knows before the handshake starts.
        // Nothing in this client checks `was_contributory`, so refusing the point
        // is the whole defence.
        let secret = StaticSecret::from([9u8; 32]);
        for (name, hex) in CANONICAL_LOW_ORDER {
            let shared = secret.diffie_hellman(&PublicKey::from(hex32(hex)));
            assert!(
                shared.as_bytes().iter().all(|byte| *byte == 0),
                "{name} should zero the shared secret, which is the point of refusing it"
            );
        }
    }

    #[test]
    fn an_honest_public_key_is_still_accepted() {
        // The other half of the check above. A validator that refused everything
        // would pass every assertion in this module and break every handshake.
        let honest = PublicKey::from(&StaticSecret::from([3u8; 32]));
        assert!(
            NoiseHandshakeState::validate_public_key(honest.as_bytes()).is_ok(),
            "a key derived from a real scalar must pass"
        );
    }

    #[test]
    fn a_public_key_of_the_wrong_length_is_refused() {
        // The length is a stranger's claim, and the low-order comparison below it
        // is only an equality test because this ran first.
        for length in [0usize, 1, 31, 33, 64] {
            assert!(
                NoiseHandshakeState::validate_public_key(&vec![7u8; length]).is_err(),
                "a {length}-byte key must be refused"
            );
        }
    }

    #[test]
    fn a_handshake_offering_a_low_order_ephemeral_is_refused() {
        // End to end through `read_message`, which is where it would actually
        // arrive. The ephemeral used to reach `mix_hash` with no check at all —
        // the static key was validated and this one was not — so a peer could
        // zero `ee` and everything mixed after it.
        for (name, hex) in CANONICAL_LOW_ORDER {
            let mut responder = NoiseHandshakeState::new(
                NoiseRole::Responder,
                NoisePattern::XX,
                Some(StaticSecret::from([4u8; 32])),
                None,
            );
            // XX message one is exactly the initiator's ephemeral.
            let verdict = responder.read_message(&hex32(hex));
            assert!(
                verdict.is_err(),
                "a handshake opening with the {name} point must be refused"
            );
        }
    }

    #[test]
    fn an_honest_opening_handshake_message_is_still_read() {
        // The negative control for the test above: the same path with a real
        // ephemeral has to keep working, or the validation has simply broken
        // handshaking.
        let mut initiator = NoiseHandshakeState::new(
            NoiseRole::Initiator,
            NoisePattern::XX,
            Some(StaticSecret::from([5u8; 32])),
            None,
        );
        let mut responder = NoiseHandshakeState::new(
            NoiseRole::Responder,
            NoisePattern::XX,
            Some(StaticSecret::from([6u8; 32])),
            None,
        );

        let opening = initiator.write_message(&[]).expect("initiator writes -> e");
        assert!(
            responder.read_message(&opening).is_ok(),
            "an honest opening message must still be read"
        );
    }

    #[test]
    fn a_tampered_tag_does_not_decrypt() {
        // The AEAD is the only thing standing between a rewritten frame and the
        // chat log, so a flipped bit anywhere in the ciphertext must fail rather
        // than yield plaintext.
        let key = ChaChaKey::clone_from_slice(&[11u8; 32]);
        let mut sender = NoiseCipherState::new_with_key(key, true);
        let mut receiver = NoiseCipherState::new_with_key(key, true);

        let frame = sender.encrypt(b"the original words", b"").expect("encrypt");
        assert!(receiver.decrypt(&frame, b"").is_ok(), "the untouched frame opens");

        for index in NONCE_SIZE_BYTES..frame.len() {
            let mut tampered = frame.clone();
            tampered[index] ^= 0x01;
            let mut fresh = NoiseCipherState::new_with_key(key, true);
            assert!(
                fresh.decrypt(&tampered, b"").is_err(),
                "flipping a bit at offset {index} must not still decrypt"
            );
        }
    }

    #[test]
    fn the_wrong_associated_data_does_not_decrypt() {
        // Associated data binds a frame to its context. If it were ignored, a
        // frame lifted from one context would open in another.
        let key = ChaChaKey::clone_from_slice(&[12u8; 32]);
        let mut sender = NoiseCipherState::new_with_key(key, true);
        let frame = sender.encrypt(b"bound to a context", b"context-one").expect("encrypt");

        let mut receiver = NoiseCipherState::new_with_key(key, true);
        assert!(
            receiver.decrypt(&frame, b"context-two").is_err(),
            "different associated data must not open the frame"
        );

        let mut correct = NoiseCipherState::new_with_key(key, true);
        assert!(
            correct.decrypt(&frame, b"context-one").is_ok(),
            "and the right associated data still must"
        );
    }

    #[test]
    fn a_ciphertext_shorter_than_its_nonce_is_refused() {
        // The nonce is read off the front before anything else looks at the
        // buffer, so a frame shorter than that prefix has to be refused rather
        // than sliced.
        let key = ChaChaKey::clone_from_slice(&[13u8; 32]);
        for length in 0..NONCE_SIZE_BYTES {
            let mut receiver = NoiseCipherState::new_with_key(key, true);
            assert!(
                receiver.decrypt(&vec![0u8; length], b"").is_err(),
                "a {length}-byte frame is shorter than the nonce and must be refused"
            );
        }
    }

    #[test]
    fn a_handshake_message_truncated_anywhere_is_refused_rather_than_panicking() {
        // `protocol.rs` carries upstream's malformed-frame cases for the outer
        // frame; this is the same idea for the handshake reader, which does its
        // own offset arithmetic over a message a stranger sent. The requirement
        // is an error, never a panic and never a partial read that advances the
        // state machine.
        let mut initiator = NoiseHandshakeState::new(
            NoiseRole::Initiator,
            NoisePattern::XX,
            Some(StaticSecret::from([7u8; 32])),
            None,
        );
        let opening = initiator.write_message(&[]).expect("initiator writes -> e");

        for cut in 0..opening.len() {
            let mut responder = NoiseHandshakeState::new(
                NoiseRole::Responder,
                NoisePattern::XX,
                Some(StaticSecret::from([8u8; 32])),
                None,
            );
            assert!(
                responder.read_message(&opening[..cut]).is_err(),
                "an opening message truncated to {cut} bytes must be refused"
            );
        }
    }

    #[test]
    fn the_two_ends_of_a_handshake_agree_which_cipher_is_which() {
        // The direction is the interop-critical half of `split()`. Both sides
        // deriving the same pair but assigning it the same way round would pass
        // any test that drives two of *these* against each other, and fail
        // against the phone — so this asserts the mirror rather than a
        // round trip: what the initiator sends with is what the responder
        // receives with, and the reverse.
        let mut initiator = NoiseHandshakeState::new(
            NoiseRole::Initiator,
            NoisePattern::XX,
            Some(StaticSecret::from([21u8; 32])),
            None,
        );
        let mut responder = NoiseHandshakeState::new(
            NoiseRole::Responder,
            NoisePattern::XX,
            Some(StaticSecret::from([22u8; 32])),
            None,
        );

        // XX: -> e, <- e ee s es, -> s se
        let one = initiator.write_message(&[]).expect("-> e");
        responder.read_message(&one).expect("read -> e");
        let two = responder.write_message(&[]).expect("<- e ee s es");
        initiator.read_message(&two).expect("read <- e ee s es");
        let three = initiator.write_message(&[]).expect("-> s se");
        responder.read_message(&three).expect("read -> s se");

        assert!(initiator.is_handshake_complete(), "initiator should be done");
        assert!(responder.is_handshake_complete(), "responder should be done");

        let (initiator_send, initiator_receive) =
            initiator.get_transport_ciphers().expect("initiator ciphers");
        let (responder_send, responder_receive) =
            responder.get_transport_ciphers().expect("responder ciphers");

        assert_eq!(
            initiator_send.key.expect("initiator send key"),
            responder_receive.key.expect("responder receive key"),
            "what the initiator sends with must be what the responder receives with"
        );
        assert_eq!(
            responder_send.key.expect("responder send key"),
            initiator_receive.key.expect("initiator receive key"),
            "and the other direction likewise"
        );
        assert_ne!(
            initiator_send.key.expect("initiator send key"),
            responder_send.key.expect("responder send key"),
            "the two directions must not share one key"
        );
    }

    #[test]
    fn transport_ciphers_are_refused_before_the_handshake_finishes() {
        // Asking early must be an error rather than half a key.
        let handshake = NoiseHandshakeState::new(
            NoiseRole::Initiator,
            NoisePattern::XX,
            Some(StaticSecret::from([23u8; 32])),
            None,
        );
        assert!(!handshake.is_handshake_complete());
        assert!(handshake.get_transport_ciphers().is_err());
    }
}
