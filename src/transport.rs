// src/transport.rs
//
// BLE transport. Runs as its own task so the UI loop never blocks on radio work
// and so a dropped link can be re-established without user action: the old
// client connected to the first advertiser it saw, once, and silently froze if
// that link went away.

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
    Connected,
    Frame(Vec<u8>),
    Disconnected(String),
    /// The adapter itself is unusable; retrying will not help.
    Fatal(String),
}

pub struct Transport {
    pub events: mpsc::Receiver<TransportEvent>,
    pub outbound: mpsc::Sender<Vec<u8>>,
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

async fn run(events: mpsc::Sender<TransportEvent>, mut outbound: mpsc::Receiver<Vec<u8>>) {
    let adapter = match first_adapter().await {
        Ok(adapter) => adapter,
        Err(message) => {
            let _ = events.send(TransportEvent::Fatal(message)).await;
            return;
        }
    };

    let mut backoff = RECONNECT_BACKOFF_START;
    let mut failures = FailureLog::default();
    loop {
        failures.prune();
        let _ = events
            .send(TransportEvent::Status(
                "» Scanning for bitchat service...".to_string(),
            ))
            .await;

        let (peripheral, candidate) = match scan_for_peer(&adapter, &failures).await {
            Ok(Some(found)) => found,
            Ok(None) => {
                let _ = events
                    .send(TransportEvent::Disconnected(format!(
                        "No BitChat peer in range (scan timed out after {}s). Retrying...",
                        SCAN_TIMEOUT.as_secs()
                    )))
                    .await;
                time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                continue;
            }
            Err(error) => {
                let _ = events
                    .send(TransportEvent::Disconnected(format!(
                        "Scan failed: {error}. Another Bluetooth program may be using the adapter."
                    )))
                    .await;
                time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                continue;
            }
        };

        // Name the peer being tried. When several ghosts are in the list this
        // is the difference between "it is stuck" and "it is working through
        // stale entries".
        let _ = events
            .send(TransportEvent::Status(format!(
                "» Connecting to {}",
                candidate.label()
            )))
            .await;

        let started = std::time::Instant::now();
        match session(&peripheral, &events, &mut outbound).await {
            Ok(ending) => {
                failures.forget(&candidate.address);
                let reason = match ending {
                    LinkEnd::PeerGone => "Link lost".to_string(),
                    LinkEnd::WentQuiet => format!(
                        "Peer went silent for {}s",
                        LINK_SILENCE_TIMEOUT.as_secs()
                    ),
                };
                let _ = events
                    .send(TransportEvent::Disconnected(format!(
                        "{reason} after {}. Reconnecting...",
                        format_duration(started.elapsed())
                    )))
                    .await;
                backoff = RECONNECT_BACKOFF_START;
                let _ = peripheral.disconnect().await;
                time::sleep(SETTLE_AFTER_LINK_LOSS).await;
                continue;
            }
            Err(error) => {
                // Remember the address so the next pass prefers a different
                // one rather than hammering a device that is not there.
                failures.record(&candidate.address);
                let _ = events
                    .send(TransportEvent::Disconnected(format!(
                        "{} failed: {error}. Trying another peer...",
                        candidate.address
                    )))
                    .await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
            }
        }

        let _ = peripheral.disconnect().await;
        time::sleep(backoff).await;
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

async fn scan_for_peer(
    adapter: &Adapter,
    failures: &FailureLog,
) -> Result<Option<(Peripheral, Candidate)>, btleplug::Error> {
    if let Err(error) = adapter.start_scan(ScanFilter::default()).await {
        if !is_already_in_progress(&error) {
            return Err(error);
        }
        // Someone else is scanning; enumerate what they turn up.
    }
    let deadline = tokio::time::Instant::now() + SCAN_TIMEOUT;

    // Every exit from here stops the scan. Returning early with one running
    // makes the *next* start_scan fail, which used to strand the client.
    let outcome = async {
        loop {
            let found = bitchat_peers(adapter).await?;
            // Give the adapter a moment to attach signal strength before
            // committing: an entry with no RSSI is usually a cached ghost, and
            // the first sweep after start_scan often has none at all.
            let heard_any = found.iter().any(|(_, candidate)| candidate.rssi.is_some());
            let past_grace = tokio::time::Instant::now() + SCAN_TIMEOUT - deadline
                > Duration::from_millis(1500);

            if !found.is_empty() && (heard_any || past_grace) {
                let candidates: Vec<Candidate> =
                    found.iter().map(|(_, candidate)| candidate.clone()).collect();
                if let Some(chosen) = discovery::choose(&candidates, failures) {
                    if let Some((peripheral, candidate)) = found
                        .into_iter()
                        .find(|(_, candidate)| candidate.address == chosen.address)
                    {
                        return Ok(Some((peripheral, candidate)));
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
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

/// Holds one connection open, pumping frames both ways until it drops.
/// How a link that was working ended. Neither case says the peer's address is
/// bad, so neither is held against it when choosing the next candidate.
enum LinkEnd {
    /// The radio reported the peer gone, or the notification stream ended.
    PeerGone,
    /// The link stayed open but nothing arrived for [`LINK_SILENCE_TIMEOUT`].
    WentQuiet,
}

async fn session(
    peripheral: &Peripheral,
    events: &mpsc::Sender<TransportEvent>,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<LinkEnd, String> {
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

    let mut notifications = peripheral
        .notifications()
        .await
        .map_err(|e| format!("Could not open the notification stream: {e}"))?;

    events
        .send(TransportEvent::Connected)
        .await
        .map_err(|_| "UI channel closed".to_string())?;

    let mut liveness = time::interval(Duration::from_secs(2));
    liveness.tick().await;
    let mut last_heard = tokio::time::Instant::now();

    loop {
        tokio::select! {
            notification = notifications.next() => {
                match notification {
                    Some(notification) => {
                        last_heard = tokio::time::Instant::now();
                        if events.send(TransportEvent::Frame(notification.value)).await.is_err() {
                            return Ok(LinkEnd::PeerGone);
                        }
                    }
                    // Stream end means the peripheral went away.
                    None => return Ok(LinkEnd::PeerGone),
                }
            }
            frame = outbound.recv() => {
                match frame {
                    Some(frame) => {
                        if let Err(error) = peripheral
                            .write(&characteristic, &frame, WriteType::WithoutResponse)
                            .await
                        {
                            return Err(format!("Write failed: {error}"));
                        }
                    }
                    None => return Ok(LinkEnd::PeerGone),
                }
            }
            _ = liveness.tick() => {
                // btleplug does not surface disconnects on every platform, so
                // poll rather than trust the stream to end.
                if !peripheral.is_connected().await.unwrap_or(false) {
                    return Ok(LinkEnd::PeerGone);
                }
                if last_heard.elapsed() >= LINK_SILENCE_TIMEOUT {
                    return Ok(LinkEnd::WentQuiet);
                }
            }
        }
    }
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
    fn formats_link_durations_the_way_an_operator_reads_them() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m00s");
        assert_eq!(format_duration(Duration::from_secs(3725)), "62m05s");
    }
}
