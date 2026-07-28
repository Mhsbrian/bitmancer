// src/nostr/relay.rs
//
// One websocket connection to one relay, speaking the NIP-01 client protocol:
//   ["REQ", <sub_id>, <filter>]  subscribe
//   ["EVENT", <event>]           publish
//   ["CLOSE", <sub_id>]          unsubscribe
// and reading back ["EVENT", <sub_id>, <event>], ["EOSE", <sub_id>],
// ["OK", ...], ["NOTICE", ...].

use serde::Serialize;
use serde_json::Value;

use crate::nostr::event::Event;

/// A NIP-01 subscription filter. Tag filters are encoded with a `#` prefix.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(rename = "#g", skip_serializing_if = "Option::is_none")]
    pub geohashes: Option<Vec<String>>,
}

impl Filter {
    /// Upstream's `NostrFilter.geohashEphemeral`: chat plus presence for one
    /// geohash.
    /// Filter for a single cell's ephemeral events. The client subscribes by
    /// batch; this is the single-cell form the sampler tests use.
    #[allow(dead_code)]
    pub fn geohash_ephemeral(geohash: &str, since: Option<i64>, limit: usize) -> Self {
        Self::geohashes(&[geohash.to_string()], since, limit)
    }

    /// Seconds-since-epoch cutoff `lookback` seconds ago. Kinds 20000+ are
    /// ephemeral and relays are not supposed to store them at all, but plenty
    /// do — without a cutoff a fresh subscription replays hours of dead
    /// conversation as though it just arrived.
    pub fn since_lookback(lookback_seconds: i64) -> Option<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;
        Some(now - lookback_seconds)
    }

    /// The same filter across many cells at once. NIP-01 tag filters take an
    /// array, so the map can watch a whole grid over one subscription instead
    /// of opening 32 of them.
    pub fn geohashes(cells: &[String], since: Option<i64>, limit: usize) -> Self {
        Self {
            kinds: Some(vec![
                crate::nostr::event::KIND_EPHEMERAL,
                crate::nostr::event::KIND_PRESENCE,
            ]),
            since,
            limit: Some(limit),
            geohashes: Some(cells.to_vec()),
        }
    }
}

/// Client-to-relay messages.
pub fn req_message(subscription_id: &str, filter: &Filter) -> String {
    serde_json::json!(["REQ", subscription_id, filter]).to_string()
}

pub fn event_message(event: &Event) -> String {
    serde_json::json!(["EVENT", event]).to_string()
}

pub fn close_message(subscription_id: &str) -> String {
    serde_json::json!(["CLOSE", subscription_id]).to_string()
}

/// Relay-to-client messages we care about.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    Event {
        subscription_id: String,
        event: Box<Event>,
    },
    EndOfStoredEvents(String),
    /// Publish acknowledgement: (event id, accepted, message)
    Ok(String, bool, String),
    Notice(String),
    /// Anything we do not model; kept so callers can log it.
    Other(String),
}

pub fn parse_relay_message(text: &str) -> Option<RelayMessage> {
    let value: Value = serde_json::from_str(text).ok()?;
    let array = value.as_array()?;
    match array.first()?.as_str()? {
        "EVENT" => {
            let subscription_id = array.get(1)?.as_str()?.to_string();
            let event: Event = serde_json::from_value(array.get(2)?.clone()).ok()?;
            Some(RelayMessage::Event {
                subscription_id,
                event: Box::new(event),
            })
        }
        "EOSE" => Some(RelayMessage::EndOfStoredEvents(
            array.get(1)?.as_str()?.to_string(),
        )),
        "OK" => Some(RelayMessage::Ok(
            array.get(1)?.as_str().unwrap_or_default().to_string(),
            array.get(2)?.as_bool().unwrap_or(false),
            array
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )),
        "NOTICE" => Some(RelayMessage::Notice(
            array.get(1)?.as_str().unwrap_or_default().to_string(),
        )),
        _ => Some(RelayMessage::Other(text.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey, SECP256K1};

    fn sample_event() -> Event {
        let secret = SecretKey::from_byte_array([9u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        Event::signed(
            &keypair,
            1700000000,
            crate::nostr::event::KIND_EPHEMERAL,
            crate::nostr::event::geohash_tags("9q8yy", Some("tui"), false),
            "hello".into(),
        )
    }

    #[test]
    fn filter_encodes_tag_filters_with_a_hash_prefix() {
        let filter = Filter::geohash_ephemeral("9q8yy", Some(1700000000), 1000);
        let json = serde_json::to_string(&filter).unwrap();
        assert!(json.contains(r##""#g":["9q8yy"]"##), "{json}");
        assert!(json.contains(r#""kinds":[20000,20001]"#), "{json}");
        assert!(json.contains(r#""limit":1000"#), "{json}");
    }

    #[test]
    fn filter_omits_absent_fields() {
        let filter = Filter::geohash_ephemeral("9q8yy", None, 10);
        let json = serde_json::to_string(&filter).unwrap();
        assert!(!json.contains("since"), "{json}");
    }

    #[test]
    fn builds_req_and_close_frames() {
        let filter = Filter::geohash_ephemeral("9q8yy", None, 500);
        let req = req_message("sub1", &filter);
        assert!(req.starts_with(r#"["REQ","sub1",{"#), "{req}");
        assert_eq!(close_message("sub1"), r#"["CLOSE","sub1"]"#);
    }

    #[test]
    fn event_frame_round_trips_through_the_parser() {
        let event = sample_event();
        let frame = event_message(&event);
        assert!(frame.starts_with(r#"["EVENT",{"#), "{frame}");

        // Relays echo it back wrapped in a subscription id.
        let echoed = serde_json::json!(["EVENT", "sub1", event]).to_string();
        match parse_relay_message(&echoed) {
            Some(RelayMessage::Event {
                subscription_id,
                event: parsed,
            }) => {
                assert_eq!(subscription_id, "sub1");
                assert_eq!(*parsed, event);
                assert!(parsed.verify(), "signature must survive the round trip");
            }
            other => panic!("expected an event, got {other:?}"),
        }
    }

    #[test]
    fn parses_the_other_relay_messages() {
        assert_eq!(
            parse_relay_message(r#"["EOSE","sub1"]"#),
            Some(RelayMessage::EndOfStoredEvents("sub1".into()))
        );
        assert_eq!(
            parse_relay_message(r#"["OK","abc",true,""]"#),
            Some(RelayMessage::Ok("abc".into(), true, String::new()))
        );
        assert_eq!(
            parse_relay_message(r#"["OK","abc",false,"pow: difficulty too low"]"#),
            Some(RelayMessage::Ok(
                "abc".into(),
                false,
                "pow: difficulty too low".into()
            ))
        );
        assert_eq!(
            parse_relay_message(r#"["NOTICE","rate limited"]"#),
            Some(RelayMessage::Notice("rate limited".into()))
        );
    }

    #[test]
    fn malformed_frames_do_not_panic() {
        for frame in ["", "{}", "[]", "[1,2,3]", r#"["EVENT"]"#, r#"["EVENT","s",{}]"#] {
            let _ = parse_relay_message(frame);
        }
    }
}
