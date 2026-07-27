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

/// How long one scan pass looks for an advertiser before reporting back.
const SCAN_TIMEOUT: Duration = Duration::from_secs(15);
/// Backoff between reconnect attempts, capped.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(20);

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
    loop {
        let _ = events
            .send(TransportEvent::Status(
                "» Scanning for bitchat service...".to_string(),
            ))
            .await;

        let peripheral = match scan_for_peer(&adapter).await {
            Ok(Some(peripheral)) => peripheral,
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
                    .send(TransportEvent::Disconnected(format!("Scan failed: {error}")))
                    .await;
                time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                continue;
            }
        };

        let _ = events
            .send(TransportEvent::Status(
                "» Found bitchat service! Connecting...".to_string(),
            ))
            .await;

        match session(&peripheral, &events, &mut outbound).await {
            Ok(()) => {
                let _ = events
                    .send(TransportEvent::Disconnected(
                        "Link lost. Reconnecting...".to_string(),
                    ))
                    .await;
                backoff = RECONNECT_BACKOFF_START;
            }
            Err(error) => {
                let _ = events
                    .send(TransportEvent::Disconnected(format!(
                        "{error}\nRetrying automatically..."
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
async fn scan_for_peer(adapter: &Adapter) -> Result<Option<Peripheral>, btleplug::Error> {
    adapter.start_scan(ScanFilter::default()).await?;
    let deadline = tokio::time::Instant::now() + SCAN_TIMEOUT;

    let found = loop {
        if let Some(peripheral) = advertising_peer(adapter).await? {
            break Some(peripheral);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        time::sleep(Duration::from_millis(500)).await;
    };

    let _ = adapter.stop_scan().await;
    Ok(found)
}

async fn advertising_peer(adapter: &Adapter) -> Result<Option<Peripheral>, btleplug::Error> {
    for peripheral in adapter.peripherals().await? {
        if let Ok(Some(properties)) = peripheral.properties().await {
            if properties.services.contains(&BITCHAT_SERVICE_UUID) {
                return Ok(Some(peripheral));
            }
        }
    }
    Ok(None)
}

/// Holds one connection open, pumping frames both ways until it drops.
async fn session(
    peripheral: &Peripheral,
    events: &mpsc::Sender<TransportEvent>,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), String> {
    peripheral
        .connect()
        .await
        .map_err(|e| format!("Connection failed: {e}"))?;

    peripheral
        .discover_services()
        .await
        .map_err(|e| format!("Service discovery failed: {e}"))?;

    let characteristic: Characteristic = peripheral
        .characteristics()
        .into_iter()
        .find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID)
        .ok_or_else(|| "Peer is not a BitChat node (characteristic missing)".to_string())?;

    peripheral
        .subscribe(&characteristic)
        .await
        .map_err(|e| format!("Could not subscribe to the BitChat characteristic: {e}"))?;

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

    loop {
        tokio::select! {
            notification = notifications.next() => {
                match notification {
                    Some(notification) => {
                        if events.send(TransportEvent::Frame(notification.value)).await.is_err() {
                            return Ok(());
                        }
                    }
                    // Stream end means the peripheral went away.
                    None => return Ok(()),
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
                    None => return Ok(()),
                }
            }
            _ = liveness.tick() => {
                // btleplug does not surface disconnects on every platform, so
                // poll rather than trust the stream to end.
                if !peripheral.is_connected().await.unwrap_or(false) {
                    return Ok(());
                }
            }
        }
    }
}
