// src/transport.rs
//
// BLE transport. Runs as its own task so the UI loop never blocks on radio work
// and so a dropped link can be re-established without user action: the old
// client connected to the first advertiser it saw, once, and silently froze if
// that link went away.
//
// It holds several links at once, which is what makes this client a mesh node
// rather than a leaf. A flooded mesh works because every node repeats what it
// hears out of every link except the one it arrived on — with a single link
// there is no "except", so every possible rebroadcast is an echo back to the
// peer that just spoke, and `relay.rs` correctly refuses all of them. Holding a
// second link is the difference between carrying other people's traffic and
// only ever carrying our own.
//
// The shape is: one dialler that finds peers and brings links up, one pump task
// per live link, and a router that fans outbound frames across them. Connection
// attempts stay in the dialler and are made one at a time — BLE stacks handle
// parallel connects badly, and serialising them also gives the rate limit
// somewhere honest to live.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::stream::StreamExt;
use tokio::sync::mpsc;
use tokio::time;

use crate::data_structures::{BITCHAT_CHARACTERISTIC_UUID, BITCHAT_SERVICE_UUID};
use crate::discovery::{self, Candidate, FailureLog};

/// How many peers to hold at once, matching upstream's `bleMaxCentralLinks`.
///
/// The ceiling is the radio's, not ours: a BLE central multiplexes every link
/// over the same antenna, so each additional peer costs airtime for all of
/// them. Six is where upstream settled and there is no reason to differ.
pub const MAX_LINKS: usize = 6;
/// How long every link may be gone before the client calls itself offline.
///
/// A phone rotates its BLE address every few minutes, so the last link dropping
/// and another replacing it seconds later is routine. Declaring an outage
/// immediately covered the screen with a popup, cleared the peer list and made
/// everyone re-announce — turning a blip into the churn it looked like.
///
/// Lives here rather than in the UI loop because every timing it has to stay
/// longer than is in this file, and so is the test pinning that relationship.
/// It used to sit in `main.rs` and be reached from those tests as
/// `crate::OFFLINE_GRACE`, which only compiled while the crate was one binary
/// with no library — a leak from a library module up into the executable that
/// splitting the two made visible.
pub const OFFLINE_GRACE: Duration = Duration::from_secs(12);
/// Minimum gap between connection attempts, matching upstream's
/// `bleConnectRateLimitInterval`. Dialling several peers back to back tends to
/// make BlueZ fail all of them.
const CONNECT_RATE_LIMIT: Duration = Duration::from_millis(500);
/// How long to wait before looking for more peers when links are already held,
/// and how far that backs off when looking turns nothing up.
///
/// Scanning is emphatically not free. Active BLE discovery shares one radio with
/// every link we hold, and BlueZ interleaves it badly: a 15-second scan every 45
/// seconds put the adapter in discovery a third of the time and made traffic
/// between two connected peers crawl. Once the peers nearby are known and
/// linked, looking again is speculative, so the interval grows until something
/// actually changes.
const RESCAN_WITH_LINKS: Duration = Duration::from_secs(45);
const RESCAN_MAX: Duration = Duration::from_secs(300);
/// Scan window while we already hold links.
///
/// Short because the job is different: with nobody, a scan has to work through
/// the grace period a stack needs before it attaches signal strengths, and
/// finding *someone* is the whole point. With a link already up we are only
/// looking for extras, and a peer worth adding is one advertising loudly enough
/// to be seen in a glance.
const SCAN_TIMEOUT_LINKED: Duration = Duration::from_secs(4);
/// Poll interval when every slot is full: nothing to do but notice a departure.
const IDLE_POLL: Duration = Duration::from_secs(5);
/// Connection attempts per scan pass.
///
/// A failed attempt costs the whole `CONNECT_TIMEOUT`, so an unbounded walk down
/// a list of stale addresses spends minutes hanging while a live peer's signal
/// goes unread. Three is enough to get past a couple of ghosts to a real peer,
/// and short enough that the next pass sees current signal strengths.
const MAX_ATTEMPTS_PER_PASS: usize = 3;

/// How long one scan pass looks for an advertiser before reporting back.
const SCAN_TIMEOUT: Duration = Duration::from_secs(15);
/// Backoff between reconnect attempts, capped.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(20);
/// Connecting to an address that no longer exists does not fail — it hangs.
/// Every step of bringing a link up is bounded so a dead peer costs seconds
/// rather than the whole session.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const SETUP_TIMEOUT: Duration = Duration::from_secs(6);
/// A BLE link can stay open after the peer's app is gone: the radio holds the
/// connection while nothing is left to talk to it. A live BitChat node
/// re-announces continuously, so silence this long means the link is a corpse
/// and reconnecting beats waiting on it. Kept far above the announce interval
/// so an idle-but-healthy peer is never dropped.
const LINK_SILENCE_TIMEOUT: Duration = Duration::from_secs(120);
/// BlueZ frequently refuses an immediate reconnect to a device it just
/// dropped, so let the stack settle first.
const SETTLE_AFTER_LINK_LOSS: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum TransportEvent {
    /// Progress text for the connection popup.
    Status(String),
    /// A link came up. `held` is how many we have now, so the UI can tell the
    /// first one — which means we are on the mesh — from the rest.
    LinkUp {
        link: String,
        label: String,
        held: usize,
    },
    /// A link ended. `held` is how many remain; zero means we are off the mesh.
    LinkDown {
        link: String,
        reason: String,
        held: usize,
    },
    /// A frame, and which link it arrived on. The link is what makes relaying
    /// possible: the one rule that stops a flood looping forever is never
    /// sending a packet back the way it came.
    Frame { link: String, data: Vec<u8> },
    /// The adapter itself is unusable; retrying will not help.
    Fatal(String),
}

/// Where an outbound frame should go.
#[derive(Debug)]
pub enum Outbound {
    /// Every link. Our own traffic floods outwards in all directions.
    All(Vec<u8>),
    /// Every link but one — a packet being passed along, kept off the link it
    /// arrived on so it cannot echo back to whoever sent it.
    Except { link: String, data: Vec<u8> },
    /// One link and no other — an answer to the peer that asked.
    ///
    /// A gossip sync reply can be the whole archive, so putting it on every
    /// link would spend one peer's question on everyone else's airtime.
    Only { link: String, data: Vec<u8> },
}

pub struct Transport {
    pub events: mpsc::Receiver<TransportEvent>,
    pub outbound: mpsc::Sender<Outbound>,
}

/// The live links, shared between the router that writes to them and the
/// dialler that opens them.
///
/// A plain mutex rather than a channel because both sides only ever ask small
/// synchronous questions of it — how many, which addresses, give me the senders
/// — and nothing is awaited while it is held.
#[derive(Clone, Default)]
struct LinkSet {
    inner: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
}

impl LinkSet {
    fn count(&self) -> usize {
        self.inner.lock().map(|links| links.len()).unwrap_or(0)
    }

    fn addresses(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|links| links.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn insert(&self, address: &str, sender: mpsc::Sender<Vec<u8>>) {
        if let Ok(mut links) = self.inner.lock() {
            links.insert(address.to_string(), sender);
        }
    }

    fn remove(&self, address: &str) {
        if let Ok(mut links) = self.inner.lock() {
            links.remove(address);
        }
    }

    /// The senders to write a frame to. Cloned out so the lock is released
    /// before anything is awaited.
    fn senders_except(&self, except: Option<&str>) -> Vec<mpsc::Sender<Vec<u8>>> {
        self.inner
            .lock()
            .map(|links| {
                links
                    .iter()
                    .filter(|(address, _)| Some(address.as_str()) != except)
                    .map(|(_, sender)| sender.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The one sender for a link, or none if it has since dropped.
    ///
    /// A link can go away between a frame arriving on it and the answer being
    /// written back, which is why this returns an option rather than assuming.
    fn sender_for(&self, address: &str) -> Vec<mpsc::Sender<Vec<u8>>> {
        self.inner
            .lock()
            .map(|links| links.get(address).cloned().into_iter().collect())
            .unwrap_or_default()
    }
}

pub fn spawn() -> Transport {
    let (event_tx, event_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    tokio::spawn(run(event_tx, outbound_rx));
    Transport {
        events: event_rx,
        outbound: outbound_tx,
    }
}

/// Routes outbound frames across the live links.
///
/// This is all `run` does once started: the dialler and the per-link pumps do
/// the radio work, so a slow write on one link cannot hold up the UI or the
/// other links.
async fn run(events: mpsc::Sender<TransportEvent>, mut outbound: mpsc::Receiver<Outbound>) {
    let adapter = match first_adapter().await {
        Ok(adapter) => adapter,
        Err(message) => {
            let _ = events.send(TransportEvent::Fatal(message)).await;
            return;
        }
    };

    let links = LinkSet::default();
    tokio::spawn(dialler(adapter, links.clone(), events.clone()));

    while let Some(frame) = outbound.recv().await {
        let (targets, data) = match frame {
            Outbound::All(data) => (links.senders_except(None), data),
            Outbound::Except { link, data } => (links.senders_except(Some(&link)), data),
            Outbound::Only { link, data } => (links.sender_for(&link), data),
        };
        for sender in targets {
            // A link whose pump has died or fallen behind must not stall the
            // others; its queue draining is that link's problem.
            let _ = sender.try_send(data.clone());
        }
    }
}

/// Finds peers and brings links up, one connection attempt at a time.
async fn dialler(adapter: Adapter, links: LinkSet, events: mpsc::Sender<TransportEvent>) {
    let mut failures = FailureLog::default();
    let mut announced_empty = false;
    let mut rescan = RESCAN_WITH_LINKS;

    loop {
        failures.prune();
        let held_before = links.count();

        if links.count() >= MAX_LINKS {
            time::sleep(IDLE_POLL).await;
            continue;
        }

        // Only worth saying while we have nobody; once a link is up this is
        // background housekeeping and belongs in no one's log.
        if links.count() == 0 && !announced_empty {
            announced_empty = true;
            let _ = events
                .send(TransportEvent::Status(
                    "» Scanning for bitchat service...".to_string(),
                ))
                .await;
        }

        // A glance when we have someone, a proper look when we do not.
        let window = if links.count() > 0 {
            SCAN_TIMEOUT_LINKED
        } else {
            SCAN_TIMEOUT
        };
        let found = match scan_for_peers(&adapter, window).await {
            Ok(found) => found,
            Err(error) => {
                if links.count() == 0 {
                    let _ = events
                        .send(TransportEvent::Status(format!(
                            "» Scan failed: {error}. Another Bluetooth program may be using the adapter."
                        )))
                        .await;
                }
                time::sleep(RECONNECT_BACKOFF_MAX).await;
                continue;
            }
        };

        let held = links.addresses();
        let candidates: Vec<Candidate> = found
            .iter()
            .map(|(_, candidate)| candidate.clone())
            .filter(|candidate| !held.contains(&candidate.address))
            .collect();

        let mut attempted = 0usize;
        for candidate in discovery::rank(&candidates, &failures) {
            if links.count() >= MAX_LINKS {
                break;
            }
            // Stop and rescan rather than grind through a stale list. Every
            // failed attempt costs the full connect timeout, and the addresses
            // at the bottom of a long list are the least likely to answer — so
            // a fresh scan with current signal strengths beats persisting.
            if attempted >= MAX_ATTEMPTS_PER_PASS {
                break;
            }
            if !discovery::worth_dialling(&candidate, links.count()) {
                continue;
            }
            let Some((peripheral, _)) = found
                .iter()
                .find(|(_, found)| found.address == candidate.address)
            else {
                continue;
            };
            attempted += 1;

            // Dialling several peers at once tends to make BlueZ fail all of
            // them, so attempts are spaced whether or not the last succeeded.
            time::sleep(CONNECT_RATE_LIMIT).await;

            if links.count() == 0 {
                let _ = events
                    .send(TransportEvent::Status(format!(
                        "» Connecting to {}",
                        candidate.label()
                    )))
                    .await;
            }

            match establish(peripheral).await {
                Ok(link) => {
                    failures.forget(&candidate.address);
                    announced_empty = false;
                    let (inbox_tx, inbox_rx) = mpsc::channel::<Vec<u8>>(64);
                    links.insert(&candidate.address, inbox_tx);
                    let _ = events
                        .send(TransportEvent::LinkUp {
                            link: candidate.address.clone(),
                            label: candidate.label(),
                            held: links.count(),
                        })
                        .await;
                    tokio::spawn(pump(
                        peripheral.clone(),
                        candidate.address.clone(),
                        link,
                        inbox_rx,
                        links.clone(),
                        events.clone(),
                    ));
                }
                Err(error) => {
                    // Remember the address so the next pass prefers a different
                    // one rather than hammering a device that is not there.
                    failures.record(&candidate.address);
                    let _ = peripheral.disconnect().await;
                    if links.count() == 0 {
                        let _ = events
                            .send(TransportEvent::Status(format!(
                                "» {} failed: {error}. Trying another peer...",
                                candidate.address
                            )))
                            .await;
                    }
                }
            }
        }

        // With nobody, keep looking briskly — that is the whole job. With links
        // held, looking is speculative, so a pass that gained nothing doubles
        // the wait. The radio goes back to carrying traffic instead of hunting
        // for peers that are not there.
        if links.count() == 0 {
            rescan = RESCAN_WITH_LINKS;
            time::sleep(RECONNECT_BACKOFF_START).await;
            continue;
        }
        if links.count() > held_before {
            // Something changed, so the neighbourhood is worth watching again.
            rescan = RESCAN_WITH_LINKS;
        } else {
            rescan = (rescan * 2).min(RESCAN_MAX);
        }
        time::sleep(rescan).await;
    }
}

/// `--doctor`: prove the BLE path works on this machine without needing a peer.
/// Prints every advertiser the adapter can see and flags BitChat nodes, so a
/// silent scan timeout can be told apart from a broken Bluetooth stack.
pub async fn doctor(scan_seconds: u64) -> i32 {
    println!("bitmancer doctor\n");

    let manager = match Manager::new().await {
        Ok(manager) => manager,
        Err(error) => {
            println!("  [FAIL] Bluetooth stack unreachable: {error}");
            print_linux_hints();
            return 1;
        }
    };

    let adapters = match manager.adapters().await {
        Ok(adapters) => adapters,
        Err(error) => {
            println!("  [FAIL] Could not list adapters: {error}");
            print_linux_hints();
            return 1;
        }
    };

    if adapters.is_empty() {
        println!("  [FAIL] No Bluetooth adapter found.");
        print_linux_hints();
        return 1;
    }

    for adapter in &adapters {
        let info = adapter
            .adapter_info()
            .await
            .unwrap_or_else(|_| "unknown adapter".to_string());
        println!("  [ok]   adapter: {info}");
    }

    let adapter = &adapters[0];
    println!("\n  Scanning {scan_seconds}s for BLE advertisers...\n");

    if let Err(error) = adapter.start_scan(ScanFilter::default()).await {
        println!("  [FAIL] Scan could not start: {error}");
        print_linux_hints();
        return 1;
    }

    // Sample while discovery is live: BlueZ drops RSSI from the D-Bus object
    // once scanning stops, so reading only at the end reports "?" for everyone.
    let mut found: std::collections::BTreeMap<String, (String, Option<i16>, bool)> =
        std::collections::BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(scan_seconds);
    while tokio::time::Instant::now() < deadline {
        for peripheral in adapter.peripherals().await.unwrap_or_default() {
            let Ok(Some(properties)) = peripheral.properties().await else {
                continue;
            };
            let address = properties.address.to_string();
            let is_bitchat = properties.services.contains(&BITCHAT_SERVICE_UUID);
            let name = properties.local_name.unwrap_or_default();
            let entry = found
                .entry(address)
                .or_insert_with(|| (String::new(), None, false));
            if !name.is_empty() {
                entry.0 = name;
            }
            // Keep the strongest reading we saw.
            if let Some(rssi) = properties.rssi {
                entry.1 = Some(entry.1.map_or(rssi, |best: i16| best.max(rssi)));
            }
            entry.2 |= is_bitchat;
        }
        time::sleep(Duration::from_millis(750)).await;
    }
    let _ = adapter.stop_scan().await;

    let seen = found.len();
    let mut bitchat_peers = 0usize;
    for (address, (name, rssi, is_bitchat)) in &found {
        if *is_bitchat {
            bitchat_peers += 1;
        }
        let display_name = if name.is_empty() { "(no name)" } else { name };
        let rssi = rssi
            .map(|value| format!("{value} dBm"))
            .unwrap_or_else(|| "?".to_string());
        println!(
            "  {} {}  {:>8}  {}{}",
            if *is_bitchat { "BITCHAT" } else { "       " },
            address,
            rssi,
            display_name,
            if *is_bitchat {
                "  <-- a BitChat peer"
            } else {
                ""
            }
        );
    }

    println!("\n  {seen} advertiser(s) seen, {bitchat_peers} running BitChat.");

    if seen == 0 {
        println!("\n  [FAIL] The adapter scanned but saw nothing at all.");
        print_linux_hints();
        return 1;
    }
    if bitchat_peers == 0 {
        println!(
            "\n  [ok]   Bluetooth works here - scanning and discovery are fine.\n\
             \x20        No BitChat peer was in range, which is why the client sits at\n\
             \x20        \"Scanning for bitchat service\". Start BitChat on a phone nearby\n\
             \x20        and run this again; it should appear flagged above."
        );
        return 0;
    }
    println!("\n  [ok]   A BitChat peer is reachable. `bitmancer` should connect.");
    0
}

fn print_linux_hints() {
    println!(
        "\n  On Arch, check in this order:\n\
         \x20   systemctl status bluetooth      # bluetoothd must be running\n\
         \x20   rfkill list bluetooth           # must not be soft/hard blocked\n\
         \x20   bluetoothctl show               # adapter must report Powered: yes\n\
         \x20   groups | grep -w lp             # BlueZ D-Bus access on some setups\n\
         \x20 A running `bluetoothctl scan on` elsewhere can also starve this scan."
    );
}

async fn first_adapter() -> Result<Adapter, String> {
    let manager = Manager::new()
        .await
        .map_err(|e| format!("Bluetooth unavailable: {e}"))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| format!("Could not list Bluetooth adapters: {e}"))?;
    adapters.into_iter().next().ok_or_else(|| {
        "No Bluetooth adapter found.\n\
         • Check the device has Bluetooth hardware\n\
         • Check Bluetooth is enabled\n\
         • Check you have permission to use it"
            .to_string()
    })
}

/// One scan pass. Returns `Ok(None)` when the window elapses with no peer,
/// which is a normal outcome rather than an error.
/// BlueZ reports "operation already in progress" when something else already
/// has discovery running — another BLE tool, or a second copy of this client.
/// That is the state we wanted, not a failure, and treating it as fatal used to
/// wedge the transport permanently once it happened.
fn is_already_in_progress(error: &btleplug::Error) -> bool {
    let text = error.to_string().to_lowercase();
    text.contains("already in progress") || text.contains("inprogress")
}

/// One scan pass, returning everything that claims to speak BitChat.
///
/// Returns the whole list rather than a pick, because with several links to
/// fill the ranking is the caller's to work down. An empty result is a normal
/// outcome, not an error.
async fn scan_for_peers(
    adapter: &Adapter,
    window: Duration,
) -> Result<Vec<(Peripheral, Candidate)>, btleplug::Error> {
    if let Err(error) = adapter.start_scan(ScanFilter::default()).await {
        if !is_already_in_progress(&error) {
            return Err(error);
        }
        // Someone else is scanning; enumerate what they turn up.
    }
    let deadline = tokio::time::Instant::now() + window;

    // Every exit from here stops the scan. Returning early with one running
    // makes the *next* start_scan fail, which used to strand the client.
    let outcome = async {
        loop {
            let found = bitchat_peers(adapter).await?;
            // Give the adapter a moment to attach signal strength before
            // committing: an entry with no RSSI is usually a cached ghost, and
            // the first sweep after start_scan often has none at all.
            let heard_any = found.iter().any(|(_, candidate)| candidate.rssi.is_some());
            let past_grace =
                tokio::time::Instant::now() + window - deadline > Duration::from_millis(1500);

            if !found.is_empty() && (heard_any || past_grace) {
                return Ok(found);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(found);
            }
            time::sleep(Duration::from_millis(500)).await;
        }
    }
    .await;

    let _ = adapter.stop_scan().await;
    outcome
}

/// Everything currently claiming to speak BitChat, ghosts included — the
/// filtering is `discovery::choose`'s job.
async fn bitchat_peers(
    adapter: &Adapter,
) -> Result<Vec<(Peripheral, Candidate)>, btleplug::Error> {
    let mut found = Vec::new();
    for peripheral in adapter.peripherals().await? {
        let Ok(Some(properties)) = peripheral.properties().await else {
            continue;
        };
        if !properties.services.contains(&BITCHAT_SERVICE_UUID) {
            continue;
        }
        let candidate = Candidate {
            address: properties.address.to_string(),
            rssi: properties.rssi,
            name: properties.local_name.clone(),
        };
        found.push((peripheral, candidate));
    }
    Ok(found)
}

/// Polls until the peripheral reports connected, for callers that have to let
/// an in-flight attempt from the stack finish.
async fn await_connection(peripheral: &Peripheral, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if peripheral.is_connected().await.unwrap_or(false) {
            return true;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
    false
}

fn format_duration(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    }
}

/// A link that is up: the characteristic to write to, and the stream to read.
struct Link {
    characteristic: Characteristic,
    notifications: std::pin::Pin<
        Box<dyn futures::Stream<Item = btleplug::api::ValueNotification> + Send>,
    >,
}

/// Brings one link up: connect, discover, subscribe.
///
/// Separate from pumping it so the dialler can keep connection attempts
/// serialised and rate-limited while every live link runs concurrently.
async fn establish(peripheral: &Peripheral) -> Result<Link, String> {
    // A connect to an address that has rotated away never returns, so it is
    // bounded rather than trusted.
    if !peripheral.is_connected().await.unwrap_or(false) {
        match time::timeout(CONNECT_TIMEOUT, peripheral.connect()).await {
            Err(_) => return Err(format!("no answer in {}s", CONNECT_TIMEOUT.as_secs())),
            Ok(Ok(())) => {}
            Ok(Err(error)) if is_already_in_progress(&error) => {
                // BlueZ is already dialling this device. Wait for it rather
                // than racing it with a second attempt.
                if !await_connection(peripheral, CONNECT_TIMEOUT).await {
                    return Err("a connection attempt was already running and did not finish"
                        .to_string());
                }
            }
            Ok(Err(error)) => return Err(format!("connection refused ({error})")),
        }
    }

    match time::timeout(SETUP_TIMEOUT, peripheral.discover_services()).await {
        Err(_) => return Err("service discovery timed out".to_string()),
        Ok(Err(error)) => return Err(format!("service discovery failed ({error})")),
        Ok(Ok(())) => {}
    }

    let characteristic: Characteristic = peripheral
        .characteristics()
        .into_iter()
        .find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID)
        .ok_or_else(|| "Peer is not a BitChat node (characteristic missing)".to_string())?;

    match time::timeout(SETUP_TIMEOUT, peripheral.subscribe(&characteristic)).await {
        Err(_) => return Err("subscribe timed out".to_string()),
        Ok(Err(error)) => return Err(format!("could not subscribe ({error})")),
        Ok(Ok(())) => {}
    }

    let notifications = peripheral
        .notifications()
        .await
        .map_err(|e| format!("Could not open the notification stream: {e}"))?;

    Ok(Link {
        characteristic,
        notifications,
    })
}

/// Pumps one live link until it ends, then takes itself out of the set.
///
/// Every frame it reports is tagged with this link's address, which is what
/// lets the mesh layer decide where a relayed copy may go.
async fn pump(
    peripheral: Peripheral,
    address: String,
    link: Link,
    mut inbox: mpsc::Receiver<Vec<u8>>,
    links: LinkSet,
    events: mpsc::Sender<TransportEvent>,
) {
    let Link {
        characteristic,
        mut notifications,
    } = link;
    let started = std::time::Instant::now();
    let mut liveness = time::interval(Duration::from_secs(2));
    liveness.tick().await;
    let mut last_heard = tokio::time::Instant::now();

    let ending = loop {
        tokio::select! {
            notification = notifications.next() => {
                match notification {
                    Some(notification) => {
                        last_heard = tokio::time::Instant::now();
                        let frame = TransportEvent::Frame {
                            link: address.clone(),
                            data: notification.value,
                        };
                        if events.send(frame).await.is_err() {
                            break "the client is shutting down".to_string();
                        }
                    }
                    // Stream end means the peripheral went away.
                    None => break "link lost".to_string(),
                }
            }
            frame = inbox.recv() => {
                match frame {
                    Some(frame) => {
                        if let Err(error) = peripheral
                            .write(&characteristic, &frame, WriteType::WithoutResponse)
                            .await
                        {
                            break format!("write failed ({error})");
                        }
                    }
                    None => break "the client is shutting down".to_string(),
                }
            }
            _ = liveness.tick() => {
                // btleplug does not surface disconnects on every platform, so
                // poll rather than trust the stream to end.
                if !peripheral.is_connected().await.unwrap_or(false) {
                    break "link lost".to_string();
                }
                // A BLE link can stay open after the peer's app is gone: the
                // radio holds the connection while nothing is left to talk to
                // it. A live node re-announces continuously, so silence this
                // long means the link is a corpse.
                if last_heard.elapsed() >= LINK_SILENCE_TIMEOUT {
                    break format!("silent for {}s", LINK_SILENCE_TIMEOUT.as_secs());
                }
            }
        }
    };

    // Out of the set before the event, so a UI reading `held` never sees a
    // count that still includes this link.
    links.remove(&address);
    let _ = peripheral.disconnect().await;
    let _ = events
        .send(TransportEvent::LinkDown {
            link: address,
            reason: format!("{ending} after {}", format_duration(started.elapsed())),
            held: links.count(),
        })
        .await;
    // BlueZ frequently refuses an immediate reconnect to a device it just
    // dropped, so hold the address out of reach until the stack settles.
    time::sleep(SETTLE_AFTER_LINK_LOSS).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_is_judged_well_above_the_announce_rate() {
        // Lowering this into announce range would drop healthy idle peers, which
        // is the churn this timeout exists to avoid causing.
        assert!(
            LINK_SILENCE_TIMEOUT >= crate::mesh::ANNOUNCE_INTERVAL * 6,
            "a quiet-but-live peer must get several announces' grace"
        );
    }

    #[test]
    fn a_reconnect_has_time_to_land_before_we_declare_an_outage() {
        // A phone rotates its BLE address every few minutes, so the last link
        // dropping and another replacing it is routine. The grace window has to
        // cover an actual reconnect — the settle after a loss, plus one connect
        // attempt — or the client announces an outage it is already recovering
        // from, covering the screen and clearing the peer list on a blip.
        let fastest_reconnect = SETTLE_AFTER_LINK_LOSS + CONNECT_TIMEOUT;
        assert!(
            OFFLINE_GRACE > fastest_reconnect,
            "grace is {:?}, a reconnect needs at least {fastest_reconnect:?}",
            OFFLINE_GRACE
        );
    }

    #[test]
    fn a_pass_of_failures_cannot_outlast_the_grace_window() {
        // Otherwise the dialler is still working through stale addresses when
        // the client gives up and says it is offline — which is how the two
        // halves of this end up disagreeing about what is happening.
        let worst_pass = CONNECT_TIMEOUT * MAX_ATTEMPTS_PER_PASS as u32;
        assert!(
            worst_pass <= OFFLINE_GRACE * 3,
            "a failing pass takes {worst_pass:?}, which is far past the {:?} grace",
            OFFLINE_GRACE
        );
    }

    #[test]
    fn formats_link_durations_the_way_an_operator_reads_them() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m00s");
        assert_eq!(format_duration(Duration::from_secs(3725)), "62m05s");
    }
}
