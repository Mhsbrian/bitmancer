// src/nostr/mod.rs
//
// A minimal Nostr client, just enough for bitchat's geohash location channels:
// NIP-01 events, per-geohash identities, NIP-13 proof of work, and a relay
// pool. Nothing here touches the BLE mesh — geohash channels ride the internet.

pub mod client;
pub mod event;
pub mod identity;
pub mod pow;
pub mod relay;

/// rustls 0.23 refuses to pick a crypto backend for you when more than one
/// could be linked, and panics deep inside the TLS handshake if none was
/// installed. Do it once, before any relay connection is attempted.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
