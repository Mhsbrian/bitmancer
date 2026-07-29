// src/nostr/client.rs
//
// The relay pool. One task per (geohash, relay) pair owns its websocket,
// re-subscribes after a drop, and publishes on request. Structured like
// `transport.rs`: the UI never blocks on the network, it just drains events.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::nostr::event::{Event, KIND_EPHEMERAL, KIND_PRESENCE};
use crate::nostr::relay::{
    close_message, event_message, parse_relay_message, req_message, Filter, RelayMessage,
};

const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(2);
/// Five minutes, reached after about eight consecutive failures.
///
/// The directory is a static snapshot and some of the hosts in it are simply
/// gone, so this is not a transient case to ride out — it is the steady state
/// for a channel whose nearest relays have died. A minute between attempts
/// meant well over a thousand connections a day to a host that will never
/// answer, which is wasted traffic and looks like probing from the other end.
/// The curve still recovers a genuinely flapping relay quickly: the cap is only
/// reached after several minutes of continuous failure.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(300);
/// How long a connection must last before it counts as having worked.
///
/// The backoff used to reset the moment a socket opened, which is the wrong
/// signal: a relay that accepts a connection and drops it immediately would be
/// redialled every two seconds forever, since each attempt "succeeded". Seen on
/// a host that accepted, died, and returned 502 three times in a minute.
/// Resetting only after a connection has held for a while means a degraded host
/// backs off like a dead one, while a genuine reconnection still clears it.
const STABLE_CONNECTION: Duration = Duration::from_secs(30);
/// Joined channel: one hour of recent history, matching upstream's
/// nostrGeohashInitialLookbackSeconds / nostrGeohashInitialLimit.
const CHANNEL_LOOKBACK_SECONDS: i64 = 3600;
const CHANNEL_LIMIT: usize = 200;
/// Map sampler: only wants to know who is around *now*, so it looks back five
/// minutes (nostrGeohashSampleLookbackSeconds) and stays cheap.
const SAMPLE_LOOKBACK_SECONDS: i64 = 300;
const SAMPLE_LIMIT: usize = 100;
/// Private mail: a full day of stored history, matching upstream's
/// nostrDMSubscribeLookbackSeconds / nostrRelayDefaultFetchLimit. Long on
/// purpose — a gift wrap is mail held for someone who was not there, so the
/// window has to cover being away, not just being briefly disconnected.
const DM_LOOKBACK_SECONDS: i64 = 86400;
const DM_LIMIT: usize = 100;
/// Bound on the id set used to collapse copies arriving from several relays.
/// Only chat consumes it — see `remember_chat`.
const SEEN_LIMIT: usize = 4096;

#[derive(Debug, Clone)]
pub enum GeoEvent {
    RelayConnected {
        /// Which cell the event arrived from. The subscription already knows,
        /// but an event without its channel cannot be routed by a later caller.
        #[allow(dead_code)]
        geohash: String,
        relay: String,
    },
    /// Carries no channel, deliberately. A host that is not answering is not
    /// answering anyone, and tagging the failure with whichever subscription
    /// noticed invites reporting one fact once per channel.
    RelayFailed { relay: String, reason: String },
    Message {
        geohash: String,
        pubkey: String,
        nickname: Option<String>,
        content: String,
        created_at: i64,
        teleported: bool,
    },
    Presence {
        geohash: String,
        pubkey: String,
        /// Send time, kept beside the content so ordering does not depend on arrival.
        #[allow(dead_code)]
        created_at: i64,
    },
    /// The relays have finished replaying stored history for this channel;
    /// everything after this point arrived live. We know the exact boundary
    /// because the backlog is buffered until every relay sends EOSE, so the UI
    /// can mark it instead of letting hour-old lines pass for conversation.
    HistoryEnd { geohash: String },
    /// Traffic seen by the map sampler in a cell that is only being watched,
    /// not joined.
    Activity {
        geohash: String,
        pubkey: String,
        is_message: bool,
    },
    /// A verified relay event, still in the exact JSON the relay served, for a
    /// gateway to put on the mesh.
    ///
    /// Emitted only while carrying is switched on. The signature is what makes a
    /// gateway safe to trust, and it only survives if the bytes do — so this
    /// carries the original text rather than anything re-encoded from the parsed
    /// event. Kept off the normal path because a client that is not carrying has
    /// no use for it and would pay for the clone on every message.
    Carryable { geohash: String, event_json: String },
    /// A gift wrap addressed to us, still sealed.
    ///
    /// It arrives unopened because this task holds no keys: it speaks the relay
    /// protocol and nothing else, and a private message should not be decrypted
    /// by the component whose whole job is talking to strangers.
    PrivateEnvelope { wrap: Box<Event> },
}

enum Command {
    Subscribe { geohash: String, relays: Vec<String> },
    Unsubscribe { geohash: String },
    Publish { geohash: String, event: Box<Event> },
    /// Watch many cells over one subscription, for the map's heat display.
    Sample { cells: Vec<String>, relays: Vec<String> },
    StopSampling,
    /// Listen for private mail addressed to one identity.
    SubscribeDirect { pubkey: String, relays: Vec<String> },
    /// Whether to hand verified channel events back in their original JSON, so
    /// a gateway can put them on the mesh.
    SetCarrying(bool),
}

/// Reserved subscription keys, for the two subscriptions that are not a joined
/// channel. Neither is a valid geohash — geohashes are base32 — so neither can
/// collide with one.
const SAMPLER_KEY: &str = "\u{1}sampler";
const DM_KEY: &str = "\u{1}dm";

/// Where private mail is posted and collected.
///
/// Deliberately not the geohash directory: those relays are chosen by distance
/// to a location, and a DM has no location. Reusing them would also mean the
/// set of relays we ask for mail on changes with where we are standing, which
/// is a movement signal handed to anyone watching, and would leave mail sitting
/// on a relay we no longer query.
///
/// These are upstream's four built-ins, so mail posted by either client reaches
/// the other. Four clearnet hostnames is a real chokepoint — upstream says as
/// much in `NostrRelaySettings` and offers user-added relays as the escape
/// hatch. We do not have that yet; it is the natural next thing here.
const DM_RELAYS: [&str; 4] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://offchain.pub",
];

/// The relay set private mail uses.
pub fn dm_relays() -> Vec<String> {
    DM_RELAYS.iter().map(|relay| relay.to_string()).collect()
}

/// What one socket is watching. These three used to be separate parameters on
/// `relay_task`; they are one decision, and a DM subscription differs from a
/// channel in all of them at once.
#[derive(Debug, Clone)]
enum Watch {
    /// One or more geohash cells: a joined channel, or the map's sample set.
    Cells {
        cells: Vec<String>,
        lookback_seconds: i64,
        limit: usize,
    },
    /// Gift wraps addressed to one public key.
    DirectMessages { pubkey: String },
}

impl Watch {
    /// Rebuilt on every reconnect, so `since` stays relative to now rather than
    /// asking for an ever-older window as the session runs on.
    fn filter(&self) -> Filter {
        match self {
            Watch::Cells {
                cells,
                lookback_seconds,
                limit,
            } => Filter::geohashes(cells, Filter::since_lookback(*lookback_seconds), *limit),
            Watch::DirectMessages { pubkey } => {
                Filter::gift_wraps(pubkey, Filter::since_lookback(DM_LOOKBACK_SECONDS), DM_LIMIT)
            }
        }
    }

    fn subscription_prefix(&self) -> &'static str {
        match self {
            Watch::Cells { .. } => "geo",
            Watch::DirectMessages { .. } => "dm",
        }
    }
}

pub struct NostrClient {
    pub events: mpsc::Receiver<GeoEvent>,
    commands: mpsc::Sender<Command>,
}

impl NostrClient {
    pub fn spawn() -> Self {
        crate::nostr::install_crypto_provider();
        let (event_tx, event_rx) = mpsc::channel(512);
        let (command_tx, command_rx) = mpsc::channel(64);
        tokio::spawn(supervisor(command_rx, event_tx));
        Self {
            events: event_rx,
            commands: command_tx,
        }
    }

    pub async fn subscribe(&self, geohash: &str, relays: Vec<String>) {
        let _ = self
            .commands
            .send(Command::Subscribe {
                geohash: geohash.to_string(),
                relays,
            })
            .await;
    }

    pub async fn unsubscribe(&self, geohash: &str) {
        let _ = self
            .commands
            .send(Command::Unsubscribe {
                geohash: geohash.to_string(),
            })
            .await;
    }

    /// Points the map sampler at a set of cells, replacing any previous one.
    pub async fn sample(&self, cells: Vec<String>, relays: Vec<String>) {
        let _ = self.commands.send(Command::Sample { cells, relays }).await;
    }

    pub async fn stop_sampling(&self) {
        let _ = self.commands.send(Command::StopSampling).await;
    }

    pub async fn publish(&self, geohash: &str, event: Event) {
        let _ = self
            .commands
            .send(Command::Publish {
                geohash: geohash.to_string(),
                event: Box::new(event),
            })
            .await;
    }

    /// Starts collecting private mail for one identity, replacing any previous
    /// subscription. One at a time: this is the long-lived address a favourite
    /// was given, and there is only ever one of those.
    pub async fn subscribe_direct(&self, pubkey: &str, relays: Vec<String>) {
        let _ = self
            .commands
            .send(Command::SubscribeDirect {
                pubkey: pubkey.to_string(),
                relays,
            })
            .await;
    }

    /// Starts or stops handing back the original JSON of verified channel
    /// events. Off by default: only a gateway has any use for it.
    pub async fn set_carrying(&self, carrying: bool) {
        let _ = self.commands.send(Command::SetCarrying(carrying)).await;
    }

    /// Posts a gift wrap to the DM relays.
    ///
    /// Silently does nothing until `subscribe_direct` has run, because it
    /// borrows that subscription's sockets. That ordering is not a constraint
    /// worth working around — a client that can send private mail but is not
    /// listening for the reply is not a client anyone wants.
    pub async fn publish_direct(&self, event: Event) {
        let _ = self
            .commands
            .send(Command::Publish {
                geohash: DM_KEY.to_string(),
                event: Box::new(event),
            })
            .await;
    }
}

/// Stored events arrive newest-first, so a fresh subscription's backlog is
/// buffered and replayed in chronological order. The window closes on the first
/// EOSE or when the deadline passes, whichever comes first.
const BACKLOG_WINDOW: Duration = Duration::from_secs(3);

struct Backlog {
    buffered: Vec<(i64, GeoEvent)>,
    deadline: tokio::time::Instant,
    /// Relays that have not finished replaying stored events yet. Each relay
    /// sends its own backlog newest-first, so closing on the first EOSE would
    /// let the others' history through unsorted.
    pending_relays: HashSet<String>,
}

/// Owns the set of live subscriptions and fans publishes out to their relays.
async fn supervisor(mut commands: mpsc::Receiver<Command>, events: mpsc::Sender<GeoEvent>) {
    // geohash -> per-relay outbound senders. Dropping a sender ends its task.
    let mut subscriptions: HashMap<String, Vec<mpsc::Sender<String>>> = HashMap::new();
    let (raw_tx, mut raw_rx) = mpsc::channel::<(String, String, RelayMessage)>(512);

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut seen_order: VecDeque<String> = VecDeque::new();
    let mut backlogs: HashMap<String, Backlog> = HashMap::new();
    // Cells the map is currently watching, if any.
    let mut sampler_cells: HashSet<String> = HashSet::new();
    // Whether a gateway downstream wants the raw JSON of what we verify.
    let mut carrying = false;

    let mut ticker = tokio::time::interval(Duration::from_millis(250));

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    None => return,
                    Some(Command::Subscribe { geohash, relays }) => {
                        subscriptions.remove(&geohash); // drop old sockets first
                        backlogs.insert(geohash.clone(), Backlog {
                            buffered: Vec::new(),
                            deadline: tokio::time::Instant::now() + BACKLOG_WINDOW,
                            pending_relays: relays.iter().cloned().collect(),
                        });
                        let mut senders = Vec::new();
                        for relay in relays {
                            let (outbound_tx, outbound_rx) = mpsc::channel::<String>(32);
                            tokio::spawn(relay_task(
                                relay,
                                geohash.clone(),
                                Watch::Cells {
                                    cells: vec![geohash.clone()],
                                    lookback_seconds: CHANNEL_LOOKBACK_SECONDS,
                                    limit: CHANNEL_LIMIT,
                                },
                                outbound_rx,
                                raw_tx.clone(),
                                events.clone(),
                            ));
                            senders.push(outbound_tx);
                        }
                        subscriptions.insert(geohash, senders);
                    }
                    Some(Command::Unsubscribe { geohash }) => {
                        subscriptions.remove(&geohash);
                        backlogs.remove(&geohash);
                    }
                    Some(Command::Sample { cells, relays }) => {
                        subscriptions.remove(SAMPLER_KEY);
                        backlogs.remove(SAMPLER_KEY);
                        sampler_cells = cells.iter().cloned().collect();
                        let mut senders = Vec::new();
                        for relay in relays {
                            let (outbound_tx, outbound_rx) = mpsc::channel::<String>(32);
                            tokio::spawn(relay_task(
                                relay,
                                SAMPLER_KEY.to_string(),
                                Watch::Cells {
                                    cells: cells.clone(),
                                    lookback_seconds: SAMPLE_LOOKBACK_SECONDS,
                                    limit: SAMPLE_LIMIT,
                                },
                                outbound_rx,
                                raw_tx.clone(),
                                events.clone(),
                            ));
                            senders.push(outbound_tx);
                        }
                        subscriptions.insert(SAMPLER_KEY.to_string(), senders);
                    }
                    Some(Command::SubscribeDirect { pubkey, relays }) => {
                        subscriptions.remove(DM_KEY);
                        // No backlog entry, deliberately. The channel backlog
                        // exists to sort replayed history by send time, and a
                        // gift wrap's `created_at` is randomised by a quarter
                        // of an hour either way to blur exactly that. Sorting
                        // on it would order the day's mail by noise. The real
                        // time is inside the sealed rumor, so ordering belongs
                        // downstream of decryption, not here.
                        let mut senders = Vec::new();
                        for relay in relays {
                            let (outbound_tx, outbound_rx) = mpsc::channel::<String>(32);
                            tokio::spawn(relay_task(
                                relay,
                                DM_KEY.to_string(),
                                Watch::DirectMessages {
                                    pubkey: pubkey.clone(),
                                },
                                outbound_rx,
                                raw_tx.clone(),
                                events.clone(),
                            ));
                            senders.push(outbound_tx);
                        }
                        subscriptions.insert(DM_KEY.to_string(), senders);
                    }
                    Some(Command::SetCarrying(wanted)) => carrying = wanted,
                    Some(Command::StopSampling) => {
                        subscriptions.remove(SAMPLER_KEY);
                        backlogs.remove(SAMPLER_KEY);
                        sampler_cells.clear();
                    }
                    Some(Command::Publish { geohash, event }) => {
                        if let Some(senders) = subscriptions.get(&geohash) {
                            let frame = event_message(&event);
                            for sender in senders {
                                let _ = sender.try_send(frame.clone());
                            }
                        }
                    }
                }
            }
            inbound = raw_rx.recv() => {
                let Some((key, relay, message)) = inbound else { continue };
                let geohash = key.clone();

                // This relay finished replaying stored events. Once every relay
                // in the pool has, the backlog is complete and can be sorted.
                if matches!(message, RelayMessage::EndOfStoredEvents(_)) {
                    let complete = match backlogs.get_mut(&geohash) {
                        Some(backlog) => {
                            backlog.pending_relays.remove(&relay);
                            backlog.pending_relays.is_empty()
                        }
                        None => false,
                    };
                    if complete && flush_backlog(&mut backlogs, &geohash, &events).await.is_err() {
                        return;
                    }
                    continue;
                }

                let RelayMessage::Event { event, .. } = message else { continue };

                // Relays are untrusted: check the signature, then collapse the
                // copies the other relays in the pool will also deliver.
                if !event.verify() {
                    continue;
                }

                // Private mail leaves here before anything geographic is asked
                // of it: a gift wrap carries no `#g` tag, and should not — the
                // cell someone is standing in is not part of an address.
                if key == DM_KEY {
                    if event.kind != crate::nostr::envelope::KIND_GIFT_WRAP {
                        continue;
                    }
                    // Four relays each hand over the same wrap. Collapsing them
                    // here saves three decryptions; the durable record that
                    // survives a restart is kept by the caller, which is the
                    // one that knows what it already acted on.
                    if !remember(&mut seen_ids, &mut seen_order, &event.id) {
                        continue;
                    }
                    if events
                        .send(GeoEvent::PrivateEnvelope { wrap: event })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }

                let Some(cell) = event.geohash().map(str::to_string) else { continue };
                let is_sampler = key == SAMPLER_KEY;
                if is_sampler {
                    if !sampler_cells.contains(&cell) {
                        continue;
                    }
                } else if cell != geohash {
                    continue;
                }
                // Only chat is deduplicated, and only once globally.
                //
                // Presence is idempotent downstream (it lands in a set of
                // pubkeys), so spending cache on it is pure waste — and it is
                // ~99% of the traffic: a couple of dozen idle people in a cell
                // emit thousands of beacons a minute, which used to churn the
                // whole ring in seconds and let genuinely-seen chat be
                // redelivered as new after any reconnect.
                if event.kind == KIND_EPHEMERAL {
                    // Two keys, as upstream does: the event id, plus a content
                    // key that still catches a re-serve after the id was
                    // evicted, or the same text republished under a new id.
                    let content_key = format!(
                        "{}|{}|{}",
                        event.pubkey,
                        event.created_at,
                        event.content
                    );
                    let fresh_id = remember(&mut seen_ids, &mut seen_order, &event.id);
                    let fresh_content = remember(&mut seen_ids, &mut seen_order, &content_key);
                    if !fresh_id || !fresh_content {
                        continue;
                    }
                }

                let created_at = event.created_at;
                if is_sampler {
                    let out = GeoEvent::Activity {
                        geohash: cell,
                        pubkey: event.pubkey.clone(),
                        is_message: event.kind == KIND_EPHEMERAL,
                    };
                    if events.send(out).await.is_err() {
                        return;
                    }
                    continue;
                }
                // Offered to a gateway before the backlog buffers anything:
                // carrying is about getting live traffic onto the mesh, and a
                // replayed hour of history is not worth the airtime. Sent
                // outside the backlog for the same reason — it must not be held
                // back and released in a burst.
                if carrying && event.kind == KIND_EPHEMERAL && !backlogs.contains_key(&geohash) {
                    if let Ok(event_json) = serde_json::to_string(&event) {
                        let offer = GeoEvent::Carryable {
                            geohash: geohash.clone(),
                            event_json,
                        };
                        if events.send(offer).await.is_err() {
                            return;
                        }
                    }
                }

                let out = match event.kind {
                    KIND_EPHEMERAL => GeoEvent::Message {
                        geohash: geohash.clone(),
                        pubkey: event.pubkey.clone(),
                        nickname: event.nickname().map(str::to_string),
                        content: event.content.clone(),
                        created_at,
                        teleported: event.is_teleported(),
                    },
                    KIND_PRESENCE => GeoEvent::Presence {
                        geohash: geohash.clone(),
                        pubkey: event.pubkey.clone(),
                        created_at,
                    },
                    _ => continue,
                };

                match backlogs.get_mut(&geohash) {
                    Some(backlog) => backlog.buffered.push((created_at, out)),
                    None if events.send(out).await.is_err() => return,
                    None => {}
                }
            }
            _ = ticker.tick() => {
                let expired: Vec<String> = backlogs
                    .iter()
                    .filter(|(_, backlog)| tokio::time::Instant::now() >= backlog.deadline)
                    .map(|(geohash, _)| geohash.clone())
                    .collect();
                for geohash in expired {
                    if flush_backlog(&mut backlogs, &geohash, &events).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Replays a channel's buffered backlog oldest-first, then switches it to live.
async fn flush_backlog(
    backlogs: &mut HashMap<String, Backlog>,
    geohash: &str,
    events: &mpsc::Sender<GeoEvent>,
) -> Result<(), ()> {
    let Some(mut backlog) = backlogs.remove(geohash) else {
        return Ok(());
    };
    backlog.buffered.sort_by_key(|(created_at, _)| *created_at);
    let replayed_chat = backlog
        .buffered
        .iter()
        .any(|(_, event)| matches!(event, GeoEvent::Message { .. }));
    for (_, event) in backlog.buffered {
        if events.send(event).await.is_err() {
            return Err(());
        }
    }
    // Only worth a divider if there was actually history to divide from.
    if replayed_chat
        && geohash != SAMPLER_KEY
        && events
            .send(GeoEvent::HistoryEnd {
                geohash: geohash.to_string(),
            })
            .await
            .is_err()
    {
        return Err(());
    }
    Ok(())
}

/// Subscription ids go on the wire, so keep them printable.
fn sanitize_subscription_id(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn remember(seen: &mut HashSet<String>, order: &mut VecDeque<String>, id: &str) -> bool {
    if !seen.insert(id.to_string()) {
        return false;
    }
    order.push_back(id.to_string());
    if order.len() > SEEN_LIMIT {
        if let Some(oldest) = order.pop_front() {
            seen.remove(&oldest);
        }
    }
    true
}

/// Holds one relay socket open for one subscription.
async fn relay_task(
    url: String,
    key: String,
    watch: Watch,
    mut outbound: mpsc::Receiver<String>,
    inbound: mpsc::Sender<(String, String, RelayMessage)>,
    events: mpsc::Sender<GeoEvent>,
) {
    let subscription_id = format!(
        "{}-{}",
        watch.subscription_prefix(),
        sanitize_subscription_id(&key)
    );
    let mut backoff = RECONNECT_BACKOFF_START;

    loop {
        match connect_async(&url).await {
            Ok((mut socket, _response)) => {
                // Not yet a reason to reset the backoff — see below.
                let opened_at = tokio::time::Instant::now();
                let _ = events
                    .send(GeoEvent::RelayConnected {
                        geohash: key.clone(),
                        relay: url.clone(),
                    })
                    .await;

                // Recomputed on every (re)connect so a long-lived session does
                // not keep asking for an ever-older window.
                let filter = watch.filter();
                if socket
                    .send(WsMessage::Text(req_message(&subscription_id, &filter).into()))
                    .await
                    .is_err()
                {
                    continue;
                }

                loop {
                    tokio::select! {
                        incoming = socket.next() => {
                            match incoming {
                                Some(Ok(WsMessage::Text(text))) => {
                                    if let Some(message) = parse_relay_message(&text) {
                                        if inbound
                                            .send((key.clone(), url.clone(), message))
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                                Some(Ok(WsMessage::Ping(payload))) => {
                                    let _ = socket.send(WsMessage::Pong(payload)).await;
                                }
                                Some(Ok(_)) => {}
                                // Socket closed or errored: fall through to reconnect.
                                Some(Err(_)) | None => break,
                            }
                        }
                        frame = outbound.recv() => {
                            match frame {
                                // The supervisor dropped us: close cleanly.
                                None => {
                                    let _ = socket
                                        .send(WsMessage::Text(close_message(&subscription_id).into()))
                                        .await;
                                    let _ = socket.close(None).await;
                                    return;
                                }
                                Some(frame) => {
                                    if socket.send(WsMessage::Text(frame.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // The socket is gone. Only a connection that lasted counts as
                // one that worked: a host that accepts and drops immediately
                // would otherwise reset the backoff on every attempt and be
                // redialled every two seconds for the rest of the session.
                if opened_at.elapsed() >= STABLE_CONNECTION {
                    backoff = RECONNECT_BACKOFF_START;
                } else if !outbound.is_closed() {
                    // Not when we are the ones going away: a socket closing
                    // because the channel was left, or the client is quitting,
                    // is not the relay failing.
                    let _ = events
                        .send(GeoEvent::RelayFailed {
                            relay: url.clone(),
                            reason: "dropped the connection".to_string(),
                        })
                        .await;
                }
            }
            Err(error) => {
                let _ = events
                    .send(GeoEvent::RelayFailed {
                        relay: url.clone(),
                        reason: error.to_string(),
                    })
                    .await;
            }
        }

        // Reconnect unless we have been dropped in the meantime.
        if outbound.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// `--geo-doctor`: connect to the relays a geohash resolves to and report what
/// arrives. Subscribe-only on purpose — publishing a test message would put
/// junk into a real location channel that real people are reading.
pub async fn doctor(geohash: &str, seconds: u64) -> i32 {
    use std::collections::HashMap;

    let relays = crate::geohash::closest_relays(geohash, 5);
    println!("bitmancer geohash doctor\n");
    println!("  channel:  #{geohash}");
    let (lat, lon) = crate::geohash::decode_center(geohash);
    println!("  centre:   {lat:.4}, {lon:.4}");
    println!("  relays:   {} selected by distance", relays.len());
    for relay in &relays {
        println!("            {relay}");
    }
    if relays.is_empty() {
        println!("\n  [FAIL] No relays in the directory.");
        return 1;
    }

    let client = NostrClient::spawn();
    client.subscribe(geohash, relays.clone()).await;
    println!("\n  Listening {seconds}s...\n");

    let mut connected: HashMap<String, bool> = HashMap::new();
    let mut messages = 0usize;
    let mut presence = 0usize;
    let mut speakers: HashMap<String, String> = HashMap::new();
    let mut client = client;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client.events.recv()).await {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(event)) => match event {
                // On change, not on first sight: a relay that drops and comes
                // back counts as live in the summary, so suppressing the
                // recovery line makes the two disagree.
                GeoEvent::RelayConnected { relay, .. } => {
                    if connected.insert(relay.clone(), true) != Some(true) {
                        println!("  [ok]   connected  {relay}");
                    }
                }
                GeoEvent::RelayFailed { relay, reason, .. } => {
                    if connected.insert(relay.clone(), false) != Some(false) {
                        println!("  [FAIL] {relay}: {reason}");
                    }
                }
                GeoEvent::Message {
                    pubkey,
                    nickname,
                    content,
                    ..
                } => {
                    messages += 1;
                    let name = nickname.unwrap_or_else(|| pubkey[..8].to_string());
                    speakers.insert(pubkey.clone(), name.clone());
                    let preview: String = content.chars().take(60).collect();
                    println!("  msg    <{name}> {preview}");
                }
                GeoEvent::Presence { pubkey, .. } => {
                    presence += 1;
                    speakers.entry(pubkey.clone()).or_insert_with(|| pubkey[..8].to_string());
                }
                // The doctor starts neither the map sampler nor a DM
                // subscription, and never carries, so none of these arrive.
                GeoEvent::Activity { .. }
                | GeoEvent::HistoryEnd { .. }
                | GeoEvent::Carryable { .. }
                | GeoEvent::PrivateEnvelope { .. } => {}
            },
        }
    }

    let live = connected.values().filter(|ok| **ok).count();
    println!("\n  {live}/{} relays connected", connected.len().max(relays.len()));
    println!("  {messages} message(s), {presence} presence beacon(s), {} distinct participant(s)", speakers.len());

    if live == 0 {
        println!("\n  [FAIL] No relay accepted a connection. Check internet access.");
        return 1;
    }
    println!("\n  [ok]   Relay transport works. Every event shown above passed");
    println!("         signature verification, so our NIP-01 id and Schnorr");
    println!("         checks agree with the wider Nostr network.");
    if messages == 0 && presence == 0 {
        println!("\n  Note: this channel was silent. That is normal for an empty");
        println!("        geohash - try a dense city cell, or a shorter geohash.");
    }
    0
}

/// `--dm-doctor`: check that private mail can actually be collected.
///
/// The geohash doctor cannot answer this — DMs use a different relay set, a
/// different filter and a stored-event window rather than an ephemeral one, and
/// every one of those is a way for the transport to be quietly broken while
/// location channels work perfectly.
///
/// Prints our address, because a DM cannot be tested alone: someone has to send
/// one, and this is the string they need. Subscribe-only, like the others.
pub async fn dm_doctor(pubkey: &str, seconds: u64) -> i32 {
    let relays = dm_relays();
    println!("bitmancer private mail doctor\n");
    println!("  address:  {pubkey}");
    if let Some(bytes) = crate::nostr::npub::to_bytes(pubkey) {
        if let Some(npub) = crate::nostr::npub::from_bytes(&bytes) {
            println!("            {npub}");
        }
    }
    println!("  relays:   {} built in", relays.len());
    for relay in &relays {
        println!("            {relay}");
    }
    println!("  window:   {}h of stored mail, {DM_LIMIT} per relay", DM_LOOKBACK_SECONDS / 3600);

    let mut client = NostrClient::spawn();
    client.subscribe_direct(pubkey, relays.clone()).await;
    println!("\n  Listening {seconds}s...\n");

    let mut connected: HashMap<String, bool> = HashMap::new();
    let mut wraps = 0usize;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client.events.recv()).await {
            Err(_) | Ok(None) => break,
            // Reported on change rather than on first sight. A relay that
            // fails and then reconnects is counted as live below, so printing
            // only its first event would show three [ok] lines above a summary
            // claiming four.
            Ok(Some(GeoEvent::RelayConnected { relay, .. })) => {
                if connected.insert(relay.clone(), true) != Some(true) {
                    println!("  [ok]   connected  {relay}");
                }
            }
            Ok(Some(GeoEvent::RelayFailed { relay, reason, .. })) => {
                if connected.insert(relay.clone(), false) != Some(false) {
                    println!("  [FAIL] {relay}: {reason}");
                }
            }
            Ok(Some(GeoEvent::PrivateEnvelope { wrap })) => {
                wraps += 1;
                // Not opened. This process holds no keys, and printing who
                // wrote to you is not a diagnostic.
                println!("  wrap   {} ({} bytes sealed)", &wrap.id[..16], wrap.content.len());
            }
            Ok(Some(_)) => {}
        }
    }

    let live = connected.values().filter(|ok| **ok).count();
    println!("\n  {live}/{} relays connected", relays.len());
    println!("  {wraps} envelope(s) addressed to you");

    if live == 0 {
        println!("\n  [FAIL] No relay accepted a connection. Check internet access.");
        return 1;
    }
    println!("\n  [ok]   The filter was accepted and the subscription is live.");
    if wraps == 0 {
        println!("\n  Note: an empty mailbox is the normal result. To prove the");
        println!("        whole path, have someone favourite you and send a DM,");
        println!("        then run this again — anything they sent in the last");
        println!("        {}h will still be waiting on these relays.", DM_LOOKBACK_SECONDS / 3600);
    }
    0
}

/// `--geo-sample`: exercise the map's data path headlessly. Subscribes to every
/// channel-level cell beneath `prefix` in one filter and reports which ones have
/// life in them — the same query the map uses to draw its heat.
pub async fn sample_doctor(prefix: &str, seconds: u64) -> i32 {
    use std::collections::BTreeMap;

    let precision = prefix.chars().count() + 1;
    let cells: Vec<String> = if crate::geohash::level_name(precision).is_some() {
        crate::geohash::children(prefix)
    } else {
        crate::geohash::children(prefix)
            .iter()
            .flat_map(|child| crate::geohash::children(child))
            .collect()
    };

    let label = if prefix.is_empty() {
        "world".to_string()
    } else {
        format!("#{prefix}")
    };
    println!("bitmancer geohash sampler\n");
    println!("  view:     {label} (cells of {} chars)", precision);
    println!("  watching: {} cells in one subscription", cells.len());

    let (lat, lon) = if prefix.is_empty() {
        (0.0, 0.0)
    } else {
        crate::geohash::decode_center(prefix)
    };
    let relays = crate::geohash::closest_relays_to(lat, lon, 5);
    println!("  relays:   {}\n", relays.len());

    let mut client = NostrClient::spawn();
    client.sample(cells.clone(), relays).await;

    let mut heat: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut connected = 0usize;
    let mut rejected = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client.events.recv()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(GeoEvent::RelayConnected { .. })) => connected += 1,
            Ok(Some(GeoEvent::RelayFailed { relay, reason, .. })) => {
                rejected.push(format!("{relay}: {reason}"))
            }
            Ok(Some(GeoEvent::Activity {
                geohash,
                is_message,
                ..
            })) => {
                let entry = heat.entry(geohash).or_insert((0, 0));
                entry.0 += 1;
                if is_message {
                    entry.1 += 1;
                }
            }
            Ok(Some(_)) => {}
        }
    }

    for failure in &rejected {
        println!("  [FAIL] {failure}");
    }

    let mut ranked: Vec<(&String, &(usize, usize))> = heat.iter().collect();
    ranked.sort_by_key(|(_, (voices, _))| std::cmp::Reverse(*voices));
    for (cell, (voices, messages)) in ranked.iter().take(20) {
        println!("  #{cell:<10} {voices:>5} events  {messages:>4} msg");
    }

    println!(
        "\n  {connected} relay connection(s), {} cell(s) alive, {} event(s) total",
        heat.len(),
        heat.values().map(|(v, _)| v).sum::<usize>()
    );
    if heat.is_empty() {
        println!("\n  [FAIL] Nothing came back. Either the filter was rejected for");
        println!("         having too many values, or these cells are all empty.");
        return 1;
    }
    println!("\n  [ok]   The map's sampling query works at this scale.");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_the_first_copy_only() {
        let mut seen = HashSet::new();
        let mut order = VecDeque::new();
        assert!(remember(&mut seen, &mut order, "abc"));
        assert!(!remember(&mut seen, &mut order, "abc"));
        assert!(remember(&mut seen, &mut order, "def"));
    }

    fn chat(created_at: i64, content: &str) -> (i64, GeoEvent) {
        (
            created_at,
            GeoEvent::Message {
                geohash: "9q".into(),
                pubkey: "aa".repeat(32),
                nickname: None,
                content: content.into(),
                created_at,
                teleported: false,
            },
        )
    }

    fn beacon(created_at: i64) -> (i64, GeoEvent) {
        (
            created_at,
            GeoEvent::Presence {
                geohash: "9q".into(),
                pubkey: "bb".repeat(32),
                created_at,
            },
        )
    }

    async fn flush(buffered: Vec<(i64, GeoEvent)>, key: &str) -> Vec<GeoEvent> {
        let (tx, mut rx) = mpsc::channel(32);
        let mut backlogs = HashMap::new();
        backlogs.insert(
            key.to_string(),
            Backlog {
                buffered,
                deadline: tokio::time::Instant::now(),
                pending_relays: HashSet::new(),
            },
        );
        flush_backlog(&mut backlogs, key, &tx).await.unwrap();
        drop(tx);
        let mut out = Vec::new();
        while let Some(event) = rx.recv().await {
            out.push(event);
        }
        out
    }

    #[tokio::test]
    async fn replayed_history_is_ordered_and_then_marked_live() {
        // Relays deliver stored events newest-first and each at its own pace.
        let out = flush(
            vec![chat(300, "third"), chat(100, "first"), chat(200, "second")],
            "9q",
        )
        .await;

        let contents: Vec<String> = out
            .iter()
            .filter_map(|event| match event {
                GeoEvent::Message { content, .. } => Some(content.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(contents, ["first", "second", "third"]);
        assert!(
            matches!(out.last(), Some(GeoEvent::HistoryEnd { .. })),
            "the boundary marker must come after the history"
        );
    }

    #[tokio::test]
    async fn a_presence_only_backlog_needs_no_divider() {
        let out = flush(vec![beacon(100), beacon(200)], "9q").await;
        assert_eq!(out.len(), 2);
        assert!(!out
            .iter()
            .any(|event| matches!(event, GeoEvent::HistoryEnd { .. })));
    }

    #[tokio::test]
    async fn the_map_sampler_never_emits_a_divider() {
        let out = flush(vec![chat(100, "history")], SAMPLER_KEY).await;
        assert!(!out
            .iter()
            .any(|event| matches!(event, GeoEvent::HistoryEnd { .. })));
    }

    #[test]
    fn subscription_windows_match_upstream() {
        // A missing `since` is what made relays replay hours of dead chat as
        // though it had just arrived.
        assert_eq!(CHANNEL_LOOKBACK_SECONDS, 3600);
        assert_eq!(CHANNEL_LIMIT, 200);
        assert_eq!(SAMPLE_LOOKBACK_SECONDS, 300);
        assert_eq!(SAMPLE_LIMIT, 100);

        let filter = Filter::geohashes(
            &["9q".to_string()],
            Filter::since_lookback(CHANNEL_LOOKBACK_SECONDS),
            CHANNEL_LIMIT,
        );
        let since = filter.since.expect("a window is always set");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            (now - since - CHANNEL_LOOKBACK_SECONDS).abs() <= 2,
            "since should be roughly an hour ago"
        );
    }

    #[test]
    fn presence_volume_cannot_evict_chat() {
        // Reproduces the bug: a couple of dozen idle people emit thousands of
        // beacons a minute. If presence shared the cache, a chat id recorded
        // before the flood would be gone after it and the message would be
        // shown again on the next reconnect.
        let mut seen = HashSet::new();
        let mut order = VecDeque::new();

        assert!(remember(&mut seen, &mut order, "chat-event-id"));
        // Simulate the flood *not* touching the cache, which is what the
        // KIND_EPHEMERAL guard in the supervisor achieves.
        for _ in 0..10_000 {
            // presence: deliberately not recorded
        }
        assert!(
            !remember(&mut seen, &mut order, "chat-event-id"),
            "the chat id must still be remembered after a presence flood"
        );
    }

    #[test]
    fn dedup_set_is_bounded() {
        let mut seen = HashSet::new();
        let mut order = VecDeque::new();
        for i in 0..(SEEN_LIMIT + 50) {
            remember(&mut seen, &mut order, &i.to_string());
        }
        assert_eq!(seen.len(), SEEN_LIMIT);
        assert_eq!(order.len(), SEEN_LIMIT);
        // The oldest ids fell out, so they would be accepted again.
        assert!(remember(&mut seen, &mut order, "0"));
    }
}
