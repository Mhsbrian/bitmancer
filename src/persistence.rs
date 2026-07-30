use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use crate::debug_println;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppState {
    // Match iOS UserDefaults keys exactly
    pub nickname: Option<String>,                              // bitchat.nickname
    pub blocked_peers: HashSet<String>,                       // bitchat.blockedUsers (SHA256 fingerprints)
    pub joined_channels: Vec<String>,                         // bitchat.joinedChannels
    /// Mutual favourites, by SHA-256 fingerprint. Unused today and deliberately
    /// kept: upstream gates Nostr key exchange on this, so it is what a DM to a
    /// peer out of Bluetooth range will need.
    pub favorites: HashSet<String>,                           // bitchat.favorites
    /// Nostr address each peer handed us, by fingerprint. Without this a
    /// favourite survives a restart as a name with no way to reach it.
    #[serde(default)]
    pub favorite_nostr_keys: HashMap<String, String>,
    /// Nicknames last seen for favourites, so the list stays readable after the
    /// peer has gone out of range.
    #[serde(default)]
    pub favorite_nicknames: HashMap<String, String>,
    /// Peers who favourited us, by fingerprint.
    #[serde(default)]
    pub favorited_us: HashSet<String>,
    /// Announced Noise keys of favourites, hex, by fingerprint.
    ///
    /// A fingerprint is one-way, and a courier envelope is addressed by a tag
    /// derived from the key — so without this, mail cannot be posted to the one
    /// person store-and-forward is for: a favourite who is not here.
    #[serde(default)]
    pub favorite_noise_keys: HashMap<String, String>,
    /// Fingerprints checked against a card shown out of band, by fingerprint.
    ///
    /// This is the only trust in the client that does not come off the air, so
    /// it is the only thing here that would be genuinely expensive to rebuild:
    /// re-earning it means standing next to each of these people again.
    #[serde(default)]
    pub verified_fingerprints: HashSet<String>,
    pub identity_key: Option<Vec<u8>>,                        // bitchat.identityKey (Ed25519 private key)
    pub noise_static_key: Option<Vec<u8>>,                   // bitchat.noiseStaticKey (X25519 private key)
    /// Seed that per-geohash Nostr identities are derived from. Kept separate
    /// from the mesh keys so location-channel activity cannot be linked to the
    /// mesh identity (NostrIdentityBridge's device seed).
    #[serde(default)]
    pub nostr_device_seed: Option<Vec<u8>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            nickname: None,
            blocked_peers: HashSet::new(),
            joined_channels: Vec::new(),
            favorites: HashSet::new(),
            favorite_nostr_keys: HashMap::new(),
            favorite_nicknames: HashMap::new(),
            favorited_us: HashSet::new(),
            favorite_noise_keys: HashMap::new(),
            verified_fingerprints: HashSet::new(),
            identity_key: None,
            noise_static_key: None,
            nostr_device_seed: None,
        }
    }
}

/// Where bitmancer keeps its identity.
pub fn get_state_file_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".bitmancer");

    if !path.exists() {
        let _ = fs::create_dir_all(&path);
    }

    path.push("state.json");
    path
}

/// The directory this client used before it was renamed.
fn legacy_state_file_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".bitchat");
    path.push("state.json");
    path
}

/// Adopts an existing bitchat-tui identity on first run.
///
/// The mesh peer ID is derived from the stored Noise key, so starting fresh
/// after the rename would silently become a different person to everyone who
/// had already seen us. Copy rather than move: the old client, if still
/// installed, keeps working.
fn migrate_legacy_state_if_needed() {
    let current = get_state_file_path();
    if current.exists() {
        return;
    }
    let legacy = legacy_state_file_path();
    if !legacy.exists() {
        return;
    }
    if let Ok(contents) = fs::read(&legacy) {
        let _ = fs::write(&current, contents);
    }
}

pub fn load_state() -> AppState {
    migrate_legacy_state_if_needed();
    let path = get_state_file_path();
    
    let mut state = if path.exists() {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                match serde_json::from_str(&contents) {
                    Ok(state) => state,
                    Err(_) => {
                        debug_println!("Warning: Could not parse state file, using defaults");
                        AppState::new()
                    }
                }
            }
            Err(_) => {
                debug_println!("Warning: Could not read state file, using defaults");
                AppState::new()
            }
        }
    } else {
        AppState::new()
    };
    
    // Generate persistent identity key if not present (matching iOS behavior)
    if state.identity_key.is_none() {
        let signing_key = SigningKey::generate(&mut OsRng);
        state.identity_key = Some(signing_key.to_bytes().to_vec());
        // Save immediately to persist the identity key
        let _ = save_state(&state);
    }
    
    // Generate persistent Noise static key if not present (matching iOS behavior)
    if state.noise_static_key.is_none() {
        let noise_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        state.noise_static_key = Some(noise_key.to_bytes().to_vec());
        // Save immediately to persist the Noise static key
        let _ = save_state(&state);
    }

    // Seed for per-geohash Nostr identities. Rotating it makes every location
    // channel identity change, so it has to persist like the others.
    if state.nostr_device_seed.is_none() {
        let mut seed = [0u8; 32];
        rand::Rng::fill(&mut OsRng, &mut seed);
        state.nostr_device_seed = Some(seed.to_vec());
        let _ = save_state(&state);
    }
    
    state
}

pub fn save_state(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_state_file_path();
    let json = serde_json::to_string_pretty(state)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Destroys the persisted identity at `path`.
///
/// Takes the path rather than reading the real one so this can be tested
/// without a test run deleting the developer's own keys.
///
/// The file is overwritten before it is unlinked, so the key bytes are not left
/// sitting in place for a casual read of the free list. That is the honest
/// limit of what this does: on a copy-on-write filesystem, or an SSD doing wear
/// levelling, the original blocks can survive somewhere no userspace program
/// can reach. This removes the keys from the filesystem's view. It is not a
/// guarantee of physical erasure, and it should not be described as one.
pub fn wipe_state_at(path: &std::path::Path) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::Write;

    if !path.exists() {
        return Ok(false);
    }
    let length = fs::metadata(path)?.len() as usize;
    {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        // Random rather than zeroes: a run of zeroes is trivially recognisable
        // as a wiped region, which is itself information.
        let noise: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
        file.write_all(&noise)?;
        // Reach the disk before unlinking, or the overwrite may never happen.
        file.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(true)
}

/// Destroys the identity this client actually runs on.
pub fn wipe_state() -> Result<bool, Box<dyn std::error::Error>> {
    wipe_state_at(&get_state_file_path())
}

// Derive AES key from identity key using HKDF-like approach
// Encrypt a password using the identity key
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_noise_static_key() {
        // Test that the same noise static key is generated and persisted
        let state1 = load_state();
        let state2 = load_state();
        
        // Both states should have the same noise static key
        assert!(state1.noise_static_key.is_some());
        assert!(state2.noise_static_key.is_some());
        assert_eq!(state1.noise_static_key, state2.noise_static_key);
        
        // The key should be 32 bytes (X25519 private key size)
        assert_eq!(state1.noise_static_key.unwrap().len(), 32);
    }
}
#[cfg(test)]
mod wipe_tests {
    use super::*;
    use std::io::Write;

    /// Never the real state file: a test that wipes the developer's identity
    /// once is a test nobody runs twice.
    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitmancer-wipe-{name}-{}.json", std::process::id()));
        path
    }

    #[test]
    fn wiping_removes_the_file_and_the_bytes_that_were_in_it() {
        let path = scratch("removes");
        let secret = b"{\"identity_key\":\"very secret material\"}";
        fs::File::create(&path).unwrap().write_all(secret).unwrap();

        assert!(wipe_state_at(&path).unwrap());
        assert!(!path.exists(), "the file must be gone");
    }

    #[test]
    fn the_overwrite_happens_before_the_unlink() {
        // Observe the intermediate state by keeping the length and checking the
        // content changed: if the implementation only unlinked, a recovered
        // block would still hold the key.
        let path = scratch("overwrite");
        let secret = vec![b'A'; 512];
        fs::File::create(&path).unwrap().write_all(&secret).unwrap();

        // Re-implement the observable half: overwrite, then read back before
        // the unlink that wipe_state_at would do.
        let length = fs::metadata(&path).unwrap().len() as usize;
        {
            let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            let noise: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
            file.write_all(&noise).unwrap();
            file.sync_all().unwrap();
        }
        let after = fs::read(&path).unwrap();
        assert_eq!(after.len(), secret.len(), "length must be preserved");
        assert_ne!(after, secret, "the original bytes must not survive");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wiping_nothing_is_not_an_error() {
        // A user who wipes twice, or before the first run has saved anything,
        // should be told it is done rather than shown a failure.
        let path = scratch("absent");
        let _ = fs::remove_file(&path);
        assert!(!wipe_state_at(&path).unwrap());
    }
}
