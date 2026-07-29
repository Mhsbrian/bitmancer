// src/nostr/npub.rs
//
// The two spellings of a Nostr public key.
//
// A key is 32 bytes. Nostr events carry it as 64 hex characters; people, and
// upstream's favourite notification, carry it as bech32 with an `npub` prefix.
// They are the same key, and a client that understands only one of them cannot
// address the other's users.
//
// This matters here for one specific reason: `sendFavoriteNotification` appends
// `":" + myNostrIdentity.npub`, so every address a peer hands us arrives in the
// bech32 spelling while everything downstream — the seal, the `#p` filter, the
// ECDH — needs the bytes. Verified against `BLEService.sendFavoriteNotification`
// and `Bech32.swift`.

/// Human-readable part of a Nostr public key.
pub const HRP: &str = "npub";

/// Decodes either spelling into 32 bytes.
///
/// Accepts hex as well as bech32 because both appear in practice: upstream
/// sends `npub`, this client has sent hex, and a stored address may be either
/// depending on which client wrote it and when.
pub fn to_bytes(address: &str) -> Option<[u8; 32]> {
    let address = address.trim();
    if let Some(bytes) = from_hex(address) {
        return Some(bytes);
    }
    from_npub(address)
}

/// The bech32 spelling, for handing our address to a peer.
pub fn from_bytes(key: &[u8; 32]) -> Option<String> {
    let hrp = bech32::Hrp::parse(HRP).ok()?;
    bech32::encode::<bech32::Bech32>(hrp, key).ok()
}

fn from_hex(address: &str) -> Option<[u8; 32]> {
    if address.len() != 64 {
        return None;
    }
    hex::decode(address).ok()?.try_into().ok()
}

fn from_npub(address: &str) -> Option<[u8; 32]> {
    let (hrp, data) = bech32::decode(address).ok()?;
    // The prefix is not decoration: `nsec` is a *secret* key in the same
    // encoding, and treating one as a public key would seal a message to a
    // point derived from someone's private half.
    if hrp.as_str() != HRP {
        return None;
    }
    data.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A published npub, with the hex confirmed by running the BIP-173
    // reference decoder over it independently. A round-trip test alone would
    // pass just as happily against a consistently wrong implementation.
    const NPUB: &str = "npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9";
    const HEX: &str = "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240";

    #[test]
    fn the_spec_vector_decodes_to_its_hex() {
        let bytes = to_bytes(NPUB).expect("a valid npub");
        assert_eq!(hex::encode(bytes), HEX);
    }

    #[test]
    fn the_spec_vector_encodes_from_its_hex() {
        let bytes = to_bytes(HEX).expect("a valid hex key");
        assert_eq!(from_bytes(&bytes).as_deref(), Some(NPUB));
    }

    #[test]
    fn both_spellings_are_the_same_key() {
        assert_eq!(to_bytes(NPUB), to_bytes(HEX));
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        // The address arrives inside a colon-separated notification and is
        // written by another implementation; a stray space must not cost
        // someone their only route to a peer.
        assert_eq!(to_bytes(&format!("  {NPUB}  ")), to_bytes(NPUB));
        assert_eq!(to_bytes(&format!("{HEX}\n")), to_bytes(HEX));
    }

    #[test]
    fn a_secret_key_is_not_accepted_as_a_public_one() {
        // Same encoding, different prefix. Sealing to a point derived from
        // this would be a silent, unrecoverable mistake.
        let hrp = bech32::Hrp::parse("nsec").unwrap();
        let nsec = bech32::encode::<bech32::Bech32>(hrp, &[7u8; 32]).unwrap();
        assert!(to_bytes(&nsec).is_none(), "{nsec} must be refused");
    }

    #[test]
    fn rubbish_is_refused_rather_than_guessed() {
        for address in [
            "",
            "npub1",
            "not an address",
            &HEX[..63],                       // one hex character short
            &format!("{HEX}ff"),              // two too many
            &NPUB.replace("sn0w", "sn1w"),    // checksum no longer matches
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", // wrong length
        ] {
            assert!(to_bytes(address).is_none(), "{address:?} must be refused");
        }
    }

    #[test]
    fn every_key_round_trips() {
        for byte in [0u8, 1, 0x7f, 0xff] {
            let key = [byte; 32];
            let address = from_bytes(&key).expect("any 32 bytes encode");
            assert_eq!(to_bytes(&address), Some(key));
        }
    }
}
