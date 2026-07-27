// src/main.rs
//
// Transport-agnostic UI loop: the BLE radio lives in `transport`, the protocol
// lives in `mesh`, and this file wires them to the ratatui frontend.

mod announce;
mod commands;
mod compression;
mod data_structures;
mod geo;
mod geohash;
mod media;
mod mesh;
mod noise_protocol;
mod nostr;
mod noise_session;
mod peer_id;
mod persistence;
mod protocol;
mod transport;
mod tui;

use std::time::{Duration, Instant};

use chrono::Local;
use crossterm::event as crossterm_event;
use crossterm::event::Event as CrosstermEvent;
use tokio::sync::mpsc;

use commands::CommandOutcome;
use geo::GeoService;
use mesh::{MeshEvent, MeshService};
use nostr::client::GeoEvent;
use transport::TransportEvent;
use tui::app::{App, TuiPhase};
use tui::event;
use tui::tui as tui_mod;
use tui::ui;

const TICK_RATE: Duration = Duration::from_millis(100);
/// Minimum keyboard poll window. Long enough for crossterm to decide a bare
/// 0x1b is Esc rather than the start of an escape sequence.
const ESC_RESOLVE_WINDOW: Duration = Duration::from_millis(20);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Diagnostics run before the TUI takes over the terminal.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--doctor") => {
            let seconds = args
                .get(1)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(10);
            std::process::exit(transport::doctor(seconds).await);
        }
        Some("--geo-doctor") => {
            let geohash = geohash::normalize(args.get(1).map(String::as_str).unwrap_or("9q8yy"));
            if !geohash::is_valid(&geohash) {
                eprintln!("not a valid geohash: {geohash}");
                std::process::exit(2);
            }
            let seconds = args
                .get(2)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(15);
            std::process::exit(nostr::client::doctor(&geohash, seconds).await);
        }
        Some("--geo-sample") => {
            let prefix = geohash::normalize(args.get(1).map(String::as_str).unwrap_or(""));
            let seconds = args
                .get(2)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(20);
            std::process::exit(nostr::client::sample_doctor(&prefix, seconds).await);
        }
        Some("--version" | "-V") => {
            println!("bitmancer {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            println!(
                "bitmancer - terminal client for BitChat\n\n\
                 Two networks: the Bluetooth mesh (public chat with nearby peers)\n\
                 and geohash location channels carried over Nostr relays.\n\n\
                 USAGE:\n  \
                 bitmancer                        Start the client\n  \
                 bitmancer --doctor [secs]        Check Bluetooth, list nearby BitChat peers\n  \
                 bitmancer --geo-doctor <gh> [s]  Check relays for a geohash channel\n  \
                 bitmancer --version\n\n\
                 In the client, /map opens the world map, /geo #<geohash> joins\n\
                 a location channel, and /help lists everything else.\n"
            );
            return Ok(());
        }
        _ => {}
    }

    let mut state = persistence::load_state();
    let nickname = state
        .nickname
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());

    // Both keys are generated and persisted by load_state on first run. The
    // Noise static key is what our peer ID is derived from, so it has to be
    // stable across restarts or we look like a new peer every launch.
    let identity_key = fixed_key(state.identity_key.as_deref())
        .ok_or("identity key missing or malformed in ~/.bitmancer/state.json")?;
    let noise_static_key = fixed_key(state.noise_static_key.as_deref())
        .ok_or("noise static key missing or malformed in ~/.bitmancer/state.json")?;

    let nostr_device_seed = fixed_key(state.nostr_device_seed.as_deref())
        .ok_or("nostr device seed missing or malformed in ~/.bitmancer/state.json")?;

    let mut mesh = MeshService::new(identity_key, noise_static_key, &nickname);
    let mut geo = GeoService::new(nostr_device_seed, &mesh.nickname);

    let mut terminal = tui_mod::init().expect("Failed to initialize TUI");
    let mut app = App::new_with_nickname(mesh.nickname.clone());
    app.add_popup_message(format!("You are {} ({})", mesh.nickname, mesh.my_peer_id));
    app.add_popup_message("Esc dismisses this; /geo #<geohash> joins a location channel.".into());

    let (input_tx, mut input_rx) = mpsc::channel::<String>(16);
    let mut transport = transport::spawn();
    let mut nostr_client = nostr::client::NostrClient::spawn();

    let mut last_tick = Instant::now();
    let mut last_maintenance = Instant::now();
    let mut last_notice = String::new();
    // Whether the map sampler is currently running, so it can be torn down
    // exactly once when the map closes.
    let mut sampling = false;
    // Image fetches run on blocking threads and report back here.
    let (image_tx, mut image_rx) =
        mpsc::channel::<(String, Result<image::DynamicImage, String>)>(8);
    // URL currently transmitted to the terminal, so redraws only re-place it.
    let mut kitty_shown: Option<String> = None;

    loop {
        // 1. Radio events.
        while let Ok(transport_event) = transport.events.try_recv() {
            match transport_event {
                TransportEvent::Status(text) => {
                    if matches!(app.phase, TuiPhase::Connected) {
                        app.add_log_message(format!("system: {text}"));
                    } else {
                        app.add_popup_message(text);
                    }
                }
                TransportEvent::Connected => {
                    app.transition_to_connected();
                    app.add_log_message("system: Connected to the mesh.".to_string());
                    // Announce immediately so peers can see us.
                    if let Some(frame) = mesh.announce_frame() {
                        let _ = transport.outbound.send(frame).await;
                    }
                }
                TransportEvent::Frame(frame) => {
                    for mesh_event in mesh.handle_frame(&frame) {
                        apply_mesh_event(&mut app, mesh_event, &mut last_notice);
                    }
                }
                TransportEvent::Disconnected(reason) => {
                    mesh.clear_peers();
                    app.people.clear();
                    app.connected = false;
                    app.phase = TuiPhase::Connecting;
                    app.popup_messages.clear();
                    app.add_popup_message(reason);
                }
                TransportEvent::Fatal(reason) => app.transition_to_error(reason),
            }
        }

        // 2. Keyboard.
        //
        // The poll timeout must never reach zero. A lone Esc arrives as a bare
        // 0x1b that could still be the start of an escape sequence, and
        // crossterm only resolves it as Esc once a read times out — with a
        // zero-duration poll it stays buffered until some other key is pressed,
        // so Esc appears to do nothing at all.
        let poll_timeout = TICK_RATE
            .saturating_sub(last_tick.elapsed())
            .max(ESC_RESOLVE_WINDOW);
        if crossterm_event::poll(poll_timeout).unwrap_or(false) {
            if let Ok(CrosstermEvent::Key(key_event)) = crossterm_event::read() {
                event::handle_key_event(&mut app, key_event, &input_tx);
            }
        }
        last_tick = Instant::now();

        // 3. Requests raised by the UI.
        app.pending_channel_switch.take();
        if let Some((target, _)) = app.pending_dm_switch.take() {
            app.add_log_message(format!(
                "system: DMs with {target} are not available yet - the Noise session layer is still being ported."
            ));
        }
        if let Some(new_nickname) = app.pending_nickname_update.take() {
            mesh.set_nickname(&new_nickname);
            geo.set_nickname(&mesh.nickname);
            app.nickname = mesh.nickname.clone();
            state.nickname = Some(mesh.nickname.clone());
            if let Err(error) = persistence::save_state(&state) {
                app.add_log_message(format!("system: Could not save nickname: {error}"));
            }
            if new_nickname != mesh.nickname {
                app.add_log_message(format!(
                    "system: Nickname shortened to {} (announces stay under the compression threshold).",
                    mesh.nickname
                ));
            }
            app.add_log_message(format!("system: You are now {}.", mesh.nickname));
            if app.connected {
                if let Some(frame) = mesh.announce_frame() {
                    let _ = transport.outbound.send(frame).await;
                }
            }
        }
        if app.pending_clear_conversation {
            app.pending_clear_conversation = false;
            app.clear_current_conversation();
        }

        // The viewer asked for an image. Nothing is fetched unless the user
        // opened it, and a cached image never leaves the process.
        if let Some(url) = app.viewer.pending_fetch.take() {
            if app.images.get(&url).is_some() {
                app.viewer.mark_ready();
            } else {
                let sender = image_tx.clone();
                let target = url.clone();
                tokio::task::spawn_blocking(move || {
                    let outcome = media::fetch_image(&target).map_err(|error| error.to_string());
                    let _ = sender.blocking_send((target, outcome));
                });
            }
        }
        while let Ok((url, outcome)) = image_rx.try_recv() {
            match outcome {
                Ok(image) => {
                    app.image_dimensions
                        .insert(url.clone(), (image.width(), image.height()));
                    app.images.insert(url.clone(), image);
                    app.viewer.finish(&url, Ok(()));
                }
                Err(reason) => app.viewer.finish(&url, Err(reason)),
            }
        }
        if app.pending_image_open_external {
            app.pending_image_open_external = false;
            if let Some(url) = app.viewer.current().map(|link| link.url.clone()) {
                // Hand off to the desktop rather than shelling out to a guessed
                // browser; failure is reported instead of being swallowed.
                match std::process::Command::new("xdg-open").arg(&url).spawn() {
                    Ok(_) => app.add_log_message(format!("system: opened {url}")),
                    Err(error) => {
                        app.add_log_message(format!("system: could not open it: {error}"))
                    }
                }
            }
        }

        // The map moved: point the sampler at whatever is on screen now. One
        // subscription covers all 32 cells, on the relays nearest the focus.
        if app.map.view_dirty {
            app.map.view_dirty = false;
            if app.map_open {
                let cells = app.map.sample_targets();
                let (lat, lon) = app.map.viewport().center();
                let relays = geohash::closest_relays_to(lat, lon, 5);
                nostr_client.sample(cells, relays).await;
            }
        }
        if !app.map_open && sampling {
            nostr_client.stop_sampling().await;
        }
        sampling = app.map_open;

        if let Some(target) = app.pending_geohash_join.take() {
            match geo.join(&target) {
                Some(relays) => {
                    nostr_client.subscribe(&target, relays.clone()).await;
                    app.join_channel(geo::channel_name(&target));
                    app.add_log_message(format!(
                        "system: Joined #{target} via {} relays.",
                        relays.len()
                    ));
                }
                None => {
                    app.switch_to_channel(geo::channel_name(&target));
                }
            }
            app.joined_geohashes = geo.joined().into_iter().collect();
        }
        if app.pending_connection_retry {
            app.pending_connection_retry = false;
            app.add_popup_message("Reconnect already in progress...".to_string());
        }

        // 4. Input lines.
        while let Ok(line) = input_rx.try_recv() {
            match commands::handle(&line, &mesh, &geo, app.connected) {
                CommandOutcome::Quit => {
                    app.should_quit = true;
                }
                CommandOutcome::Reply(lines) => {
                    for text in lines {
                        app.add_log_message(format!("system: {text}"));
                    }
                }
                CommandOutcome::SetNickname(name) => app.pending_nickname_update = Some(name),
                CommandOutcome::ClearConversation => app.pending_clear_conversation = true,
                CommandOutcome::OpenMap => app.open_map(),
                CommandOutcome::OpenImage(position) => {
                    let conversation = app.active_conversation();
                    if !app.viewer.open_in(&conversation, position) {
                        app.add_log_message(
                            "system: no image links in this conversation yet.".to_string(),
                        );
                    }
                }
                CommandOutcome::ToggleDebug => {
                    mesh.debug = !mesh.debug;
                    app.add_log_message(format!(
                        "system: packet tracing {}",
                        if mesh.debug { "on" } else { "off" }
                    ));
                }
                CommandOutcome::JoinGeohash(target) => {
                    match geo.join(&target) {
                        Some(relays) => {
                            nostr_client.subscribe(&target, relays.clone()).await;
                            app.join_channel(geo::channel_name(&target));
                            app.add_log_message(format!(
                                "system: Joined #{target} via {} relays. This channel rides Nostr, not Bluetooth.",
                                relays.len()
                            ));
                        }
                        None => {
                            app.switch_to_channel(geo::channel_name(&target));
                            app.add_log_message(format!("system: Already in #{target}."));
                        }
                    }
                    app.joined_geohashes = geo.joined().into_iter().collect();
                }
                CommandOutcome::LeaveGeohash(explicit) => {
                    let target = explicit.or_else(|| {
                        app.current_conv
                            .as_ref()
                            .and_then(|(_, channel)| channel.as_deref())
                            .and_then(geo::geohash_from_channel)
                    });
                    match target {
                        Some(target) if geo.leave(&target) => {
                            nostr_client.unsubscribe(&target).await;
                            app.channels.retain(|name| *name != geo::channel_name(&target));
                            app.switch_to_public();
                            app.joined_geohashes = geo.joined().into_iter().collect();
                            app.add_log_message(format!("system: Left #{target}."));
                        }
                        Some(target) => {
                            app.add_log_message(format!("system: Not in #{target}."));
                        }
                        None => app.add_log_message(
                            "system: No location channel is active. Use /geo #<geohash>."
                                .to_string(),
                        ),
                    }
                }
                CommandOutcome::NotACommand => {
                    // Route to whichever conversation is on screen.
                    let active_geohash = app
                        .current_conv
                        .as_ref()
                        .and_then(|(_, channel)| channel.as_deref())
                        .and_then(geo::geohash_from_channel);

                    match active_geohash {
                        Some(target) => {
                            let event = geo.message_event(&target, &line);
                            nostr_client.publish(&target, event).await;
                        }
                        None if !app.connected => app.add_log_message(
                            "system: Not connected to the mesh - message not sent.".to_string(),
                        ),
                        None => {
                            let frames = mesh.public_message_frames(&line);
                            if frames.is_empty() {
                                app.add_log_message(
                                    "system: Could not encode that message.".to_string(),
                                );
                            } else {
                                if frames.len() > 1 {
                                    app.add_log_message(format!(
                                        "system: Sent in {} parts (each must stay under 100 bytes to be signable).",
                                        frames.len()
                                    ));
                                }
                                for frame in frames {
                                    let _ = transport.outbound.send(frame).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. Location channel traffic.
        while let Ok(geo_event) = nostr_client.events.try_recv() {
            apply_geo_event(&mut app, &mut geo, geo_event, &mut last_notice);
        }

        // 6. Periodic upkeep: re-announce so we do not age out, expire peers,
        //    and beacon presence in the coarse location channels.
        if last_maintenance.elapsed() >= MAINTENANCE_INTERVAL {
            last_maintenance = Instant::now();
            if app.connected && mesh.announce_due() {
                if let Some(frame) = mesh.announce_frame() {
                    let _ = transport.outbound.send(frame).await;
                }
            }
            for mesh_event in mesh.prune_peers() {
                apply_mesh_event(&mut app, mesh_event, &mut last_notice);
            }
            for (target, event) in geo.due_presence() {
                nostr_client.publish(&target, event).await;
            }
            geo.prune_participants();
        }
        sync_people(&mut app, &mesh, &geo);

        // 6. Draw.
        app.tick = app.tick.wrapping_add(1);
        app.pending_image_slot = None;
        terminal.draw(|frame| ui::render(&mut app, frame))?;

        // Kitty graphics are escape sequences, not cells, so they have to be
        // written after ratatui has flushed the frame or they get overdrawn.
        kitty_shown = paint_kitty_image(&mut app, kitty_shown);

        if app.should_quit {
            break;
        }
    }

    // Tell the mesh we are going before tearing the link down.
    if app.connected {
        if let Some(frame) = mesh.leave_frame() {
            let _ = transport.outbound.send(frame).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    tui_mod::restore().expect("Failed to restore terminal");
    Ok(())
}

/// Draws (or clears) the kitty image for this frame.
///
/// Returns the URL currently on the terminal, so the payload is transmitted
/// once per image and later frames only re-place it, and so it is deleted
/// exactly once when the viewer closes.
fn paint_kitty_image(app: &mut App, shown: Option<String>) -> Option<String> {
    use std::io::Write;

    let mut stdout = std::io::stdout();
    let Some(slot) = app.pending_image_slot.take() else {
        if shown.is_some() {
            let _ = write!(stdout, "{}", tui::image_render::kitty_delete());
            let _ = stdout.flush();
        }
        return None;
    };

    let Some(url) = app.viewer.current().map(|link| link.url.clone()) else {
        return shown;
    };

    // Park the cursor at the top-left of the hole; kitty draws from there.
    let _ = crossterm::queue!(stdout, crossterm::cursor::MoveTo(slot.x, slot.y));

    if shown.as_deref() == Some(url.as_str()) {
        let _ = write!(
            stdout,
            "{}",
            tui::image_render::kitty_place(slot.cols, slot.rows)
        );
        let _ = stdout.flush();
        return shown;
    }

    let Some(image) = app.images.get(&url) else {
        return shown;
    };
    let Some(png) = tui::image_render::to_png(image, slot.cols, slot.rows) else {
        return shown;
    };
    let _ = write!(
        stdout,
        "{}",
        tui::image_render::kitty_transmit(&png, slot.cols, slot.rows)
    );
    let _ = stdout.flush();
    Some(url)
}

fn fixed_key(bytes: Option<&[u8]>) -> Option<[u8; 32]> {
    bytes.and_then(|slice| <[u8; 32]>::try_from(slice).ok())
}

fn apply_mesh_event(app: &mut App, mesh_event: MeshEvent, last_notice: &mut String) {
    match mesh_event {
        MeshEvent::PeerAppeared { nickname, .. } => {
            app.add_log_message(format!("system: {nickname} connected"));
        }
        MeshEvent::PeerRenamed { nickname, .. } => {
            app.add_log_message(format!("system: a peer is now known as {nickname}"));
        }
        MeshEvent::PeerLeft { nickname, .. } => {
            app.add_log_message(format!("system: {nickname} disconnected"));
        }
        MeshEvent::PublicMessage {
            sender,
            content,
            timestamp_ms,
            ..
        } => {
            // Send time, not arrival time: a relayed copy can arrive long after
            // the fact, and the UI orders by this value.
            let epoch = (timestamp_ms / 1000) as i64;
            app.add_log_message(format!("__CHANNEL__:#public:{sender}:{epoch}:{content}"));
        }
        MeshEvent::Notice(text) => {
            // Protocol diagnostics repeat a lot; only surface transitions.
            if *last_notice != text {
                *last_notice = text.clone();
                app.add_log_message(format!("system: {text}"));
            }
        }
        MeshEvent::Trace(text) => app.add_log_message(format!("system: {text}")),
    }
}

/// Location channel traffic. Chat lands in the "#<geohash>" conversation; the
/// presence beacons only update the participant list.
fn apply_geo_event(
    app: &mut App,
    geo: &mut GeoService,
    geo_event: GeoEvent,
    last_notice: &mut String,
) {
    match geo_event {
        GeoEvent::RelayConnected { .. } => {}
        GeoEvent::RelayFailed {
            geohash,
            relay,
            reason,
        } => {
            let text = format!("#{geohash}: {relay} unreachable ({reason})");
            if *last_notice != text {
                *last_notice = text.clone();
                app.add_log_message(format!("system: {text}"));
            }
        }
        GeoEvent::Message {
            geohash,
            pubkey,
            nickname,
            content,
            created_at,
            teleported,
        } => {
            // Our own events come back from the relays we published to.
            if pubkey == geo.pubkey_for(&geohash) {
                return;
            }
            let sender = geo.note_activity(&geohash, &pubkey, nickname);
            let sender = if teleported {
                format!("{sender}*") // marked as chatting from elsewhere
            } else {
                sender
            };
            let channel = geo::channel_name(&geohash);
            app.add_log_message(format!("__CHANNEL__:{channel}:{sender}:{created_at}:{content}"));
        }
        GeoEvent::Presence {
            geohash, pubkey, ..
        } => {
            geo.note_activity(&geohash, &pubkey, None);
        }
        GeoEvent::HistoryEnd { geohash } => {
            let channel = geo::channel_name(&geohash);
            let epoch = chrono::Local::now().timestamp();
            app.add_log_message(format!(
                "__CHANNEL__:{channel}:system:{epoch}:─── live ───"
            ));
        }
        // Cells the map is watching but we have not joined.
        GeoEvent::Activity {
            geohash,
            pubkey,
            is_message,
        } => app.map.note_voice(&geohash, &pubkey, is_message),
    }
}

/// Mirrors whoever is present in the *active* conversation into the sidebar,
/// preserving the selected entry.
///
/// The two networks have separate populations: the mesh has Bluetooth peers,
/// and each location channel has its own set of Nostr identities. Showing mesh
/// peers while a geohash channel is open made those channels look deserted even
/// with dozens of people in them.
fn sync_people(app: &mut App, mesh: &MeshService, geo: &GeoService) {
    let active_geohash = app
        .current_conv
        .as_ref()
        .and_then(|(_, channel)| channel.as_deref())
        .and_then(geo::geohash_from_channel);

    let people = match active_geohash {
        Some(geohash) => geo
            .participants(&geohash)
            .iter()
            .map(|participant| participant.display_name())
            .collect(),
        None => mesh.nicknames(),
    };

    if people == app.people {
        return;
    }
    let selected = app
        .sidebar_state
        .people_selected
        .and_then(|index| app.people.get(index).cloned());
    app.people = people;
    app.sidebar_state.people_selected = selected
        .and_then(|name| app.people.iter().position(|candidate| *candidate == name));
    app.update_sidebar_flat_selection();
}
