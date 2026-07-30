// src/main.rs
//
// Transport-agnostic UI loop: the BLE radio lives in `transport`, the protocol
// lives in `mesh`, and this file wires them to the ratatui frontend.
//
// The modules themselves are declared in `lib.rs`, so both this binary and
// anything under `tests/` can reach them. This file is the loop and nothing else.

use std::time::{Duration, Instant};

use crossterm::event as crossterm_event;
use crossterm::event::Event as CrosstermEvent;
use tokio::sync::mpsc;

use bitmancer::commands::{self, CommandOutcome};
use bitmancer::geo::{self, GeoService};
use bitmancer::mesh::{DeliveryStatus, MeshEvent, MeshService};
use bitmancer::noise_payload::{NoisePayloadType, PrivateMessagePacket};
use bitmancer::nostr::{self, client::GeoEvent, health::Notice};
use bitmancer::transport::{self, Outbound, TransportEvent};
use bitmancer::tui::{self, app::App, app::IncomingLine, app::TuiPhase, event, tui as tui_mod, ui};
use bitmancer::{
    courier, favorites, gateway, geohash, mailbox, media, outbox, peer_id, persistence, protocol,
    relay, topology, verification,
};

const TICK_RATE: Duration = Duration::from_millis(100);
/// Frame interval while a line is still arriving. The reveal sweep runs for a
/// quarter of a second, which at the idle rate would be three frames and would
/// read as stepping rather than motion. Only paid for while something moves.
const ANIMATION_TICK: Duration = Duration::from_millis(33);
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
        Some("--dm-doctor") => {
            // Uses the real stored identity: the address a peer was given is
            // the one mail arrives at, so a generated key would test nothing.
            let state = persistence::load_state();
            let Some(seed) = fixed_key(state.nostr_device_seed.as_deref()) else {
                eprintln!("no nostr device seed in ~/.bitmancer/state.json; start the client once first");
                std::process::exit(2);
            };
            let pubkey = nostr::identity::IdentityStore::new(seed).main_pubkey_hex();
            let seconds = args
                .get(1)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(15);
            std::process::exit(nostr::client::dm_doctor(&pubkey, seconds).await);
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
                 bitmancer --dm-doctor [secs]     Check private mail, print your address\n  \
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
    // Restore the block list before the radio starts, so a blocked peer cannot
    // slip a frame in during the window between connecting and loading.
    mesh.load_blocked(state.blocked_peers.clone());
    // The only trust here that was not derived from something off the air, and
    // the only thing in this file that costs a walk across town to rebuild.
    mesh.load_verified(state.verified_fingerprints.clone());
    // Favourites carry the only addresses we have for peers who are not in
    // radio range, so they are restored before anything can need one.
    {
        let mut restored = std::collections::HashMap::new();
        let fingerprints = state
            .favorites
            .iter()
            .chain(state.favorited_us.iter())
            .chain(state.favorite_nostr_keys.keys())
            .cloned()
            .collect::<std::collections::HashSet<String>>();
        for fingerprint in fingerprints {
            restored.insert(
                fingerprint.clone(),
                favorites::Relationship {
                    we_favorited: state.favorites.contains(&fingerprint),
                    they_favorited: state.favorited_us.contains(&fingerprint),
                    their_nostr_key: state.favorite_nostr_keys.get(&fingerprint).cloned(),
                    nickname: state
                        .favorite_nicknames
                        .get(&fingerprint)
                        .cloned()
                        .unwrap_or_default(),
                    noise_public_key: state
                        .favorite_noise_keys
                        .get(&fingerprint)
                        .and_then(|key| hex::decode(key).ok()),
                },
            );
        }
        mesh.favorites.load(restored);
    }
    let mut geo = GeoService::new(nostr_device_seed, &mesh.nickname);

    let mut terminal = tui_mod::init().expect("Failed to initialize TUI");
    // From here to the end of main the terminal is ours. The guard hands it back
    // on every path out — the `?`s below, a panic, or the ordinary quit — so no
    // future early return can strand the user in raw mode.
    let _terminal_guard = tui_mod::TerminalGuard::new();
    let mut app = App::new_with_nickname(mesh.nickname.clone());
    app.short_peer_id = peer_id::short_display(&mesh.my_peer_id);
    app.add_popup_message(format!("You are {} ({})", mesh.nickname, mesh.my_peer_id));
    app.add_popup_message("Esc dismisses this; /geo #<geohash> joins a location channel.".into());

    let (input_tx, mut input_rx) = mpsc::channel::<String>(16);
    let mut transport = transport::spawn();
    let mut nostr_client = nostr::client::NostrClient::spawn();

    // Private mail, collected from the moment the client starts rather than
    // when a channel is joined. The address a favourite was given does not
    // depend on where we are standing, and mail waiting on a relay should not
    // need a location channel to be opened before it is delivered.
    let mut seen_envelopes = nostr::processed::ProcessedEvents::open();
    let our_nostr_key = geo.main_nostr_pubkey();
    nostr_client
        .subscribe_direct(&our_nostr_key, nostr::client::dm_relays())
        .await;

    let mut last_tick = Instant::now();
    let mut last_maintenance = Instant::now();
    let mut last_notice = String::new();
    // Per relay, because two relays failing with different reasons is exactly
    // what defeats a single-slot filter.
    let mut relay_health = nostr::health::RelayHealth::new();
    // Which BLE links are up. The relay policy needs the names, not just the
    // count: a packet may go to every link except the one it arrived on.
    let mut links: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut forwarded = relay::Forwarded::default();
    // Gateway mode: off until asked, and only advertised while the relays are
    // actually answering.
    let mut carrier = gateway::Gateway::new();
    // The shelf. Restored on the way in, minus anything that expired while we
    // were off — a restart must not extend the promise.
    let mut post = mailbox::Mailbox::open(courier::now_millis());
    // Couriered mail arrives as several separately sealed envelopes carrying one
    // letter, so what must not repeat is the letter, not the envelope. Shares the
    // durable store with private envelopes for the same reason: a relaunch that
    // re-showed yesterday's mail would be the same bug twice.
    let mut opened_mail = nostr::processed::ProcessedEvents::open();
    let mut relays_up = false;
    // Relays currently answering. Held as a set rather than a count so a
    // repeated failure from one host cannot take the whole gateway down.
    let mut live_relays: std::collections::HashSet<String> = std::collections::HashSet::new();
    // How much we have carried this session, for the readout.
    let mut carried_out = 0usize;
    // When the last link went, if it has. `None` means we are linked, or have
    // already said we are not.
    let mut offline_since: Option<Instant> = None;
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
                        app.add_notice(text.to_string());
                    } else {
                        app.add_popup_message(text);
                    }
                }
                TransportEvent::LinkUp { link, label, held } => {
                    links.insert(link);
                    // Back before anyone was told we had gone.
                    offline_since = None;
                    if held == 1 {
                        app.transition_to_connected();
                        app.add_notice("Connected to the mesh.".to_string());
                    } else {
                        app.add_notice(format!(
                            "linked to {label} ({held} peers linked)"
                        ));
                    }
                    // Announce down the new link so the peer behind it sees us.
                    // Sent to every link rather than just this one: an announce
                    // is how we stay current with everyone, and re-sending it
                    // costs a frame.
                    if let Some(frame) = mesh.announce_frame() {
                        let _ = transport.outbound.send(Outbound::All(frame)).await;
                    }
                }
                TransportEvent::Frame { link, data } => {
                    // Decide whether to pass it on before handling it. The
                    // packet is moved into the mesh layer, and the relay
                    // decision needs the raw frame and the link it came from.
                    let onward = relay_plan(&mesh, &data, &link, &links, &mut forwarded);
                    for mesh_event in mesh.handle_frame(&data) {
                        match mesh_event {
                            // A handshake reply originates down in the mesh
                            // layer rather than from a user action, so it has
                            // to be put on the air here.
                            MeshEvent::Send(outgoing) => {
                                let _ = transport.outbound.send(Outbound::All(outgoing)).await;
                            }
                            MeshEvent::CarriedEvent {
                                depositor,
                                direction,
                                geohash,
                                event_json,
                            } => {
                                if let Some(event) = uplink(
                                    &mut app,
                                    &mut carrier,
                                    &depositor,
                                    direction,
                                    &geohash,
                                    &event_json,
                                    relays_up,
                                ) {
                                    nostr_client.publish(&geohash, event).await;
                                }
                            }
                            MeshEvent::CourierDeposit {
                                depositor,
                                envelope,
                            } => shelve(&mut app, &mut post, &mesh, &depositor, *envelope),
                            MeshEvent::CourierArrived { courier, envelope } => {
                                // `None` from `open_courier` is not for us after
                                // all, is from someone we block, or is sealed to
                                // a prekey we do not publish. Silent in every
                                // case: a tag collision is rare but not an event,
                                // and the other two are decisions already made.
                                //
                                // Deduplicated on the *inner* message id rather
                                // than the envelope: redundant copies of one
                                // letter are each sealed separately, so they are
                                // different envelopes carrying the same message.
                                if let Some((record, sender_fingerprint)) =
                                    mesh.open_courier(&envelope)
                                        .filter(|(record, _)| {
                                            opened_mail.remember(&record.message_id)
                                        })
                                {
                                    let sender = mesh
                                        .favorites
                                        .resolve(&sender_fingerprint)
                                        .map(|(_, entry)| entry.nickname.clone())
                                        .filter(|name| !name.is_empty())
                                        .unwrap_or_else(|| {
                                            peer_id::short_display(&sender_fingerprint)
                                        });
                                    // A courier's copy carries no send time —
                                    // PrivateMessagePacket is message id and
                                    // content and nothing else — so arrival is
                                    // the only honest value, even though this one
                                    // may have been sealed a day ago. The notice
                                    // below is what says so.
                                    app.add_dm_received(
                                        sender.clone(),
                                        record.message_id.clone(),
                                        record.content.clone(),
                                        chrono::Local::now().timestamp(),
                                    );
                                    app.add_notice(format!(
                                        "that message was carried here by {} while {sender} was away.",
                                        peer_id::short_display(&courier)
                                    ));
                                }
                            }
                            other => apply_mesh_event(&mut app, other, &mut last_notice),
                        }
                    }
                    if let Some(forwarded) = onward {
                        let _ = transport
                            .outbound
                            .send(Outbound::Except {
                                link,
                                data: forwarded,
                            })
                            .await;
                    }
                }
                TransportEvent::LinkDown { link, reason, held } => {
                    links.remove(&link);
                    if held == 0 {
                        // Not declared offline yet. A phone rotates its BLE
                        // address every few minutes, so the last link dropping
                        // and a new one replacing it seconds later is the
                        // ordinary case — and throwing a full-screen popup over
                        // it, clearing the peer list and making everyone
                        // re-announce turns a blip into an outage. The
                        // maintenance tick decides, once the grace period has
                        // had a chance to be wrong.
                        offline_since.get_or_insert_with(Instant::now);
                        app.add_notice(format!("link lost ({reason})"));
                    } else {
                        app.add_notice(format!(
                            "a link ended ({reason}); {held} still up"
                        ));
                    }
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
        let frame_interval = if app.is_animating() {
            ANIMATION_TICK
        } else {
            TICK_RATE
        };
        let poll_timeout = frame_interval
            .saturating_sub(last_tick.elapsed())
            .max(ESC_RESOLVE_WINDOW);
        if crossterm_event::poll(poll_timeout).unwrap_or(false) {
            // Every event kind is dispatched, not only keys. Reading `Key` alone
            // and dropping the rest is what left mouse capture enabled with no
            // wheel behind it, and what turned a pasted newline into a sent
            // half-message. `Resize` needs no arm: the loop redraws every tick
            // and ratatui re-measures from the backend as it goes.
            match crossterm_event::read() {
                Ok(CrosstermEvent::Key(key_event)) => {
                    event::handle_key_event(&mut app, key_event, &input_tx);
                }
                Ok(CrosstermEvent::Mouse(mouse_event)) => {
                    event::handle_mouse_event(&mut app, mouse_event);
                }
                Ok(CrosstermEvent::Paste(pasted)) => {
                    event::handle_paste_event(&mut app, &pasted);
                }
                _ => {}
            }
        }
        last_tick = Instant::now();

        // 3. Requests raised by the UI.
        app.pending_channel_switch.take();
        if let Some((target, _)) = app.pending_dm_switch.take() {
            app.add_notice(format!(
                "DMs with {target} are not available yet - the Noise session layer is still being ported."
            ));
        }
        if let Some(new_nickname) = app.pending_nickname_update.take() {
            mesh.set_nickname(&new_nickname);
            geo.set_nickname(&mesh.nickname);
            app.nickname = mesh.nickname.clone();
            state.nickname = Some(mesh.nickname.clone());
            if let Err(error) = persistence::save_state(&state) {
                app.add_notice(format!("Could not save nickname: {error}"));
            }
            if new_nickname != mesh.nickname {
                app.add_notice(format!(
                    "Nickname shortened to {} (announces stay under the compression threshold).",
                    mesh.nickname
                ));
            }
            app.add_notice(format!("You are now {}.", mesh.nickname));
            if app.connected {
                if let Some(frame) = mesh.announce_frame() {
                    let _ = transport.outbound.send(Outbound::All(frame)).await;
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
                    Ok(_) => app.add_notice(format!("opened {url}")),
                    Err(error) => {
                        app.add_notice(format!("could not open it: {error}"))
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
                    app.add_notice(format!(
                        "Joined #{target} via {} relays.",
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
                        app.add_notice(text.to_string());
                    }
                }
                CommandOutcome::SetFavorite { target, favorite } => {
                    let our_key = geo.main_nostr_npub();
                    match mesh.favorite_frames(&target, favorite, &our_key) {
                        Ok(sent) => {
                            for frame in sent.frames {
                                let _ = transport.outbound.send(Outbound::All(frame)).await;
                            }
                            let who = mesh
                                .peers
                                .get(&target)
                                .map(|peer| peer.nickname.clone())
                                .unwrap_or_else(|| target.clone());
                            let verb = if favorite { "favourited" } else { "unfavourited" };
                            app.add_notice(format!(
                                "{verb} {who}; they now have your Nostr address."
                            ));
                            save_favorites(&mut state, &mesh, &mut app);
                        }
                        Err(reason) => app.add_notice(reason.to_string()),
                    }
                }
                CommandOutcome::SendFile(path) => {
                    match load_outgoing_file(&path) {
                        Ok((name, mime, bytes)) => {
                            let size = bytes.len();
                            match mesh.file_frames(&name, mime, bytes) {
                                Ok(frames) => {
                                    // Say the cost before spending it: a
                                    // megabyte is thousands of BLE writes and
                                    // the pane would otherwise sit silent.
                                    app.add_notice(format!(
                                        "sending {name} ({:.0} KiB) as {} fragments...",
                                        size as f64 / 1024.0,
                                        frames.len()
                                    ));
                                    for frame in frames {
                                        let _ = transport.outbound.send(Outbound::All(frame)).await;
                                    }
                                    app.add_notice(format!("{name} sent."));
                                }
                                Err(reason) => {
                                    app.add_notice(reason.to_string())
                                }
                            }
                        }
                        Err(reason) => app.add_notice(reason.to_string()),
                    }
                }
                CommandOutcome::WipeIdentity => {
                    // Tell the mesh we are going before the keys are gone, so
                    // peers drop us now rather than timing us out.
                    if let Some(frame) = mesh.leave_frame() {
                        let _ = transport.outbound.send(Outbound::All(frame)).await;
                    }
                    match persistence::wipe_state() {
                        Ok(existed) => {
                            mesh.wipe();
                            app.wipe();
                            // A list of envelopes we opened is a record of who
                            // wrote to us and roughly when, in its own file
                            // beside the identity rather than inside it.
                            seen_envelopes.wipe();
                            // Other people's mail must not outlive a wipe.
                            post.wipe();
                            let what = if existed {
                                "Identity destroyed."
                            } else {
                                "Nothing was stored; memory cleared."
                            };
                            app.add_notice(format!("{what} Quitting."));
                        }
                        Err(error) => {
                            // Do not quit on a failed wipe: exiting here would
                            // look identical to success while leaving the keys
                            // on disk.
                            app.add_notice(format!(
                                "could not destroy the stored identity: {error}"
                            ));
                            app.add_notice(
                                "your keys are still on disk. Nothing was cleared."
                                    .to_string(),
                            );
                            continue;
                        }
                    }
                    app.should_quit = true;
                }
                CommandOutcome::BlockPeer(peer_id) => match mesh.block(&peer_id) {
                    Ok(nickname) => {
                        state.blocked_peers = mesh.blocked_fingerprints();
                        if let Err(error) = persistence::save_state(&state) {
                            app.add_notice(format!(
                                "blocked {nickname}, but could not save: {error}"
                            ));
                        } else {
                            app.add_notice(format!(
                                "blocked {nickname}. Their traffic is dropped."
                            ));
                        }
                        app.update_blocked_list(mesh.blocked_labels());
                        sync_people(&mut app, &mesh, &geo);
                    }
                    Err(reason) => app.add_notice(reason.to_string()),
                },
                CommandOutcome::UnblockPeer(needle) => match mesh.unblock(&needle) {
                    Ok(label) => {
                        state.blocked_peers = mesh.blocked_fingerprints();
                        if let Err(error) = persistence::save_state(&state) {
                            app.add_notice(format!(
                                "unblocked {label}, but could not save: {error}"
                            ));
                        } else {
                            app.add_notice(format!("unblocked {label}."));
                        }
                        app.update_blocked_list(mesh.blocked_labels());
                    }
                    Err(reason) => app.add_notice(reason.to_string()),
                },
                CommandOutcome::SendDirectMessage { target, content } => {
                    // Which way to send. A peer we can currently see takes the
                    // radio, and not only because it is faster: a message that
                    // never leaves the local mesh tells no relay the
                    // conversation exists.
                    let present = mesh.peers.contains_key(&target);
                    let address = mesh.nostr_address_for(&target).map(str::to_string);
                    // Neither reachable nor addressable, but somebody nearby
                    // might see them before we do. This is the case with no
                    // infrastructure at all in it, and the only one where a
                    // stranger's radio is the whole delivery mechanism.
                    if !present && address.is_none() {
                        if let Some(sent) = post_to_couriers(&mut app, &mesh, &target, &content) {
                            for frame in sent {
                                let _ = transport.outbound.send(Outbound::All(frame)).await;
                            }
                            continue;
                        }
                    }
                    if matches!(outbox::route(present, address.as_deref()), outbox::Route::Nostr) {
                        let address = address.expect("Route::Nostr means we hold an address");
                        match send_over_nostr(&mut geo, &mesh, &address, &target, &content) {
                            Some((event, message_id)) => {
                                nostr_client.publish_direct(event).await;
                                let who = mesh
                                    .favorites
                                    .resolve(&target)
                                    .map(|(_, entry)| entry.nickname.clone())
                                    .filter(|nickname| !nickname.is_empty())
                                    .unwrap_or_else(|| target.clone());
                                app.add_dm_sent(who.clone(), message_id.clone(), content.clone());
                                app.add_notice(format!(
                                    "{who} is out of range; sent over the internet."
                                ));
                            }
                            None => app.add_notice(
                                "could not address that peer over the internet; their stored address is unreadable.".to_string(),
                            ),
                        }
                        continue;
                    }
                    match mesh.dm_frames(&target, &content) {
                        Ok(sent) => {
                            for frame in sent.frames {
                                let _ = transport.outbound.send(Outbound::All(frame)).await;
                            }
                            // Echo locally straight away. The wire copy is
                            // encrypted to the peer and never comes back to us,
                            // so nothing else would show what we said.
                            let who = mesh
                                .peers
                                .get(&target)
                                .map(|peer| peer.nickname.clone())
                                .unwrap_or_else(|| target.clone());
                            // The id travels with the echo so a receipt
                            // arriving later can tick this exact line.
                            let id = sent.ids.first().cloned().unwrap_or_default();
                            app.add_dm_sent(who.clone(), id.clone(), content.clone());
                            if !mesh.has_session(&target) {
                                app.add_notice(format!(
                                    "opening an encrypted channel with {who}; the message sends once it is up."
                                ));
                            }
                        }
                        Err(reason) => {
                            app.add_notice(reason.to_string());
                        }
                    }
                }
                CommandOutcome::SetMailbox(wanted) => {
                    let dropped = post.set_enabled(wanted);
                    if wanted {
                        app.add_notice(
                            "holding mail for peers who are not here. Anyone nearby can leave sealed messages; they are opaque to you and expire within a day."
                                .to_string(),
                        );
                    } else {
                        app.add_notice("no longer holding mail.".to_string());
                        if dropped > 0 {
                            app.add_notice(format!(
                                "discarded {dropped} item(s) that were waiting. Their senders were never told, so they may try again elsewhere."
                            ));
                        }
                    }
                }
                CommandOutcome::ShowMailbox => {
                    let now = courier::now_millis();
                    let mut lines = vec![
                        format!(
                            "Mailbox: {}",
                            if post.is_enabled() { "holding" } else { "off" }
                        ),
                        format!(
                            "  {} item(s) waiting, {} handed over this session",
                            post.held_count(),
                            post.delivered
                        ),
                    ];
                    let shelf = post.summary(now);
                    if shelf.is_empty() {
                        lines.push("  nothing on the shelf".to_string());
                    } else {
                        lines.push("By depositor:".to_string());
                        lines.extend(shelf);
                    }
                    lines.push(String::new());
                    lines.push(
                        "You cannot read any of it. An envelope names its recipient".to_string(),
                    );
                    lines.push(
                        "only by a tag that rotates daily, and its contents are".to_string(),
                    );
                    lines.push("sealed to them.".to_string());
                    app.add_notice(lines.join("\n"));
                }
                CommandOutcome::SetGateway(wanted) => {
                    let dropped = carrier.set_enabled(wanted);
                    // The relay pool only hands back raw event JSON while we are
                    // carrying, so the toggle reaches it too.
                    nostr_client.set_carrying(wanted).await;
                    // Re-announce immediately: the capability bit is what tells
                    // mesh-only peers they can start depositing, and waiting for
                    // the next scheduled announce would leave the offer unheard
                    // for up to the announce interval.
                    mesh.gateway_ready = wanted && relays_up;
                    if let Some(frame) = mesh.announce_frame() {
                        let _ = transport.outbound.send(Outbound::All(frame)).await;
                    }
                    if wanted {
                        app.add_notice(if relays_up {
                            "carrying mesh traffic to the relays. Nearby peers with no data can now use your connection.".to_string()
                        } else {
                            "gateway mode is on, but no relay is answering yet — the offer is not advertised until one does.".to_string()
                        });
                    } else {
                        app.add_notice("no longer carrying mesh traffic.".to_string());
                        if dropped > 0 {
                            app.add_notice(format!(
                                "dropped {dropped} message(s) that were waiting; their senders were told nothing, so they will retry."
                            ));
                        }
                    }
                }
                CommandOutcome::ShowVerificationCard => {
                    let now = epoch_seconds();
                    let card = mesh.verification_card(
                        Some(&geo.main_nostr_npub()),
                        now,
                        rand::random(),
                    );
                    app.add_notice(format!(
                        "your card, good for {} minutes:",
                        verification::MAX_AGE_SECONDS / 60
                    ));
                    app.add_notice(card.to_url());
                    app.add_notice(
                        "they run /verify <that line>. It is only worth anything if they read it from your screen."
                            .to_string(),
                    );
                }
                CommandOutcome::AcceptVerificationCard(url) => {
                    let now = epoch_seconds();
                    let outcome = verification::Card::from_url(&url)
                        .and_then(|card| card.check(now).map(|()| card));
                    match outcome {
                        Ok(card) => match card.fingerprint() {
                            // Verifying yourself proves nothing and leaves your
                            // own name sitting in a list of people you have
                            // met, which is exactly the list that has to stay
                            // trustworthy at a glance.
                            Ok(fingerprint) if fingerprint == mesh.my_fingerprint() => {
                                app.add_notice(
                                    "that is your own card.".to_string(),
                                );
                            }
                            Ok(fingerprint) => {
                                mesh.mark_verified(&fingerprint);
                                state.verified_fingerprints = mesh.verified_fingerprints();
                                let saved = persistence::save_state(&state).is_ok();
                                app.add_notice(format!(
                                    "verified {} ({})",
                                    card.nickname,
                                    card.peer_id().unwrap_or_default()
                                ));
                                if !saved {
                                    app.add_notice(
                                        "could not write that to disk; it will be forgotten on exit."
                                            .to_string(),
                                    );
                                }
                            }
                            Err(_) => app.add_notice(
                                "that card's key is malformed.".to_string(),
                            ),
                        },
                        Err(verification::VerifyError::Malformed) => app.add_notice(
                            "that is not a verification card. Expected a bitchat://verify line."
                                .to_string(),
                        ),
                        Err(verification::VerifyError::Stale) => app.add_notice(format!(
                            "that card has expired; cards are good for {} minutes. Ask them for a fresh one.",
                            verification::MAX_AGE_SECONDS / 60
                        )),
                        Err(verification::VerifyError::BadSignature) => app.add_notice(
                            "that card's signature does not match its keys. Do not trust it."
                                .to_string(),
                        ),
                    }
                }
                CommandOutcome::SetNickname(name) => app.pending_nickname_update = Some(name),
                CommandOutcome::ClearConversation => app.pending_clear_conversation = true,
                CommandOutcome::OpenMap => app.open_map(),
                CommandOutcome::OpenMeshView => app.mesh_view_open = true,
                CommandOutcome::OpenImage(position) => {
                    let conversation = app.active_conversation();
                    if !app.viewer.open_in(&conversation, position) {
                        app.add_notice(
                            "no image links in this conversation yet.".to_string(),
                        );
                    }
                }
                CommandOutcome::ToggleDebug => {
                    mesh.debug = !mesh.debug;
                    app.add_notice(format!(
                        "packet tracing {}",
                        if mesh.debug { "on" } else { "off" }
                    ));
                }
                CommandOutcome::JoinGeohash(target) => {
                    match geo.join(&target) {
                        Some(relays) => {
                            nostr_client.subscribe(&target, relays.clone()).await;
                            app.join_channel(geo::channel_name(&target));
                            app.add_notice(format!(
                                "Joined #{target} via {} relays. This channel rides Nostr, not Bluetooth.",
                                relays.len()
                            ));
                        }
                        None => {
                            app.switch_to_channel(geo::channel_name(&target));
                            app.add_notice(format!("Already in #{target}."));
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
                            app.add_notice(format!("Left #{target}."));
                        }
                        Some(target) => {
                            app.add_notice(format!("Not in #{target}."));
                        }
                        None => app.add_notice(
                            "No location channel is active. Use /geo #<geohash>."
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
                        None if !app.connected => app.add_notice(
                            "Not connected to the mesh - message not sent.".to_string(),
                        ),
                        None => {
                            let frames = mesh.public_message_frames(&line);
                            if frames.is_empty() {
                                app.add_notice(
                                    "Could not encode that message.".to_string(),
                                );
                            } else {
                                if frames.len() > 1 {
                                    app.add_notice(format!(
                                        "Sent in {} parts (each must stay under 100 bytes to be signable).",
                                        frames.len()
                                    ));
                                }
                                for frame in frames {
                                    let _ = transport.outbound.send(Outbound::All(frame)).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. Location channel traffic, and private mail off the same relays.
        while let Ok(geo_event) = nostr_client.events.try_recv() {
            if let GeoEvent::PrivateEnvelope { wrap } = geo_event {
                if let Some(reply) = open_private_envelope(
                    &mut app,
                    &mut mesh,
                    &mut geo,
                    &mut seen_envelopes,
                    &wrap,
                ) {
                    nostr_client.publish_direct(reply).await;
                }
                continue;
            }
            // A verified channel event, offered for the mesh. Only reaches here
            // while carrying is on.
            if let GeoEvent::Carryable {
                geohash,
                event_json,
            } = &geo_event
            {
                // Built before the policy is consulted, so an event too large
                // for the air is refused by the format rather than counted
                // against the airtime budget and then dropped.
                let carried = nostr::carrier::Carrier::new(
                    nostr::carrier::Direction::FromGateway,
                    geohash,
                    event_json,
                );
                if let Some(carried) = carried {
                    if let Some(event) = carried.event() {
                        if carrier.accept_downlink(&event.id, epoch_seconds())
                            == gateway::Downlink::Broadcast
                        {
                            if let Some(frame) = mesh.carrier_frame(&carried, None) {
                                let _ = transport.outbound.send(Outbound::All(frame)).await;
                                carried_out += 1;
                            }
                        }
                    }
                }
                continue;
            }
            // Relay reachability decides whether we can honestly claim to be a
            // gateway, so it is observed rather than assumed: a client that
            // advertises `gateway` with nothing to publish to has made a promise
            // every mesh-only peer in range will act on.
            match &geo_event {
                GeoEvent::RelayConnected { relay, .. } => {
                    live_relays.insert(relay.clone());
                }
                GeoEvent::RelayFailed { relay, .. } => {
                    live_relays.remove(relay);
                }
                _ => {}
            }
            relays_up = !live_relays.is_empty();
            apply_geo_event(&mut app, &mut geo, geo_event, &mut relay_health);
        }

        // 6. Periodic upkeep: re-announce so we do not age out, expire peers,
        //    and beacon presence in the coarse location channels.
        if last_maintenance.elapsed() >= MAINTENANCE_INTERVAL {
            last_maintenance = Instant::now();
            if app.connected && mesh.announce_due() {
                if let Some(frame) = mesh.announce_frame() {
                    let _ = transport.outbound.send(Outbound::All(frame)).await;
                }
            }
            for mesh_event in mesh.prune_peers() {
                apply_mesh_event(&mut app, mesh_event, &mut last_notice);
            }
            if post.is_enabled() {
                post.prune(courier::now_millis());
                // Every known peer, because an announce is what makes their mail
                // recognisable and we may have been given some since they
                // arrived. Cheap for a handful of peers, and mail that waited
                // hours does not mind waiting one more second.
                let recipients: Vec<String> = mesh.peers.keys().cloned().collect();
                for peer_id in recipients {
                    for frame in hand_over(&mut app, &mut post, &mesh, &peer_id) {
                        let _ = transport.outbound.send(Outbound::All(frame)).await;
                    }
                }
            }

            for (target, event) in geo.due_presence() {
                nostr_client.publish(&target, event).await;
            }

            // A link that has been gone this long is an outage rather than an
            // address rotation, and is worth saying so.
            if offline_since.is_some_and(|since| since.elapsed() >= transport::OFFLINE_GRACE)
                && links.is_empty()
            {
                offline_since = None;
                mesh.clear_peers();
                app.people.clear();
                app.connected = false;
                app.phase = TuiPhase::Connecting;
                app.popup_messages.clear();
                app.add_popup_message(
                    "No BitChat peer in range. Reconnecting...".to_string(),
                );
            }

            // The offer has to track reality: relays come and go, and a claim
            // left standing while they are gone is one a mesh-only peer acts on
            // and nobody keeps.
            let offering = carrier.is_enabled() && relays_up;
            if offering != mesh.gateway_ready {
                mesh.gateway_ready = offering;
                if let Some(frame) = mesh.announce_frame() {
                    let _ = transport.outbound.send(Outbound::All(frame)).await;
                }
                app.add_notice(if offering {
                    "relays are answering; now advertising as a gateway.".to_string()
                } else {
                    "no relay is answering; withdrew the gateway offer.".to_string()
                });
            }
            // Mail held through an outage. Sent now rather than dropped: the
            // depositor was told we would carry it.
            if offering && carrier.held_count() > 0 {
                let waiting = carrier.take_held();
                app.add_notice(format!(
                    "relays are back; sending {} held message(s).",
                    waiting.len()
                ));
                for held in waiting {
                    if let Ok(event) =
                        serde_json::from_str::<nostr::event::Event>(&held.event_json)
                    {
                        nostr_client.publish(&held.geohash, event).await;
                        carried_out += 1;
                    }
                }
            }
            geo.prune_participants();
        }
        sync_people(&mut app, &mesh, &geo);
        // Reflected every frame rather than set at the toggle: the count climbs
        // as traffic is carried, and the band is the only place it shows.
        app.carrying = carrier.is_enabled().then_some(carried_out);
        app.holding = post.is_enabled().then(|| post.held_count());
        if app.mesh_view_open {
            app.topology = topology::Topology::build(
                &mesh.my_peer_id,
                mesh.peers.values().map(|peer| {
                    (
                        peer.peer_id.as_str(),
                        peer.nickname.as_str(),
                        peer.claims_neighbors.as_slice(),
                    )
                }),
            );
        }

        // 6. Draw.
        // Read receipts, sent for whatever the user is actually looking at.
        // Delivered says the radio worked; read says a person saw it, so this
        // is gated on the conversation being on screen rather than on arrival.
        if !app.viewer.open && !app.map_open {
            if let (_, Some(peer), _) = app.get_current_messages() {
                let peer = peer.clone();
                let ids = app.take_unreceipted_from(&peer);
                if !ids.is_empty() {
                    if let Ok(target) = mesh.peer_id_for_nickname(&peer) {
                        for frame in mesh.read_receipt_frames(&target, &ids) {
                            let _ = transport.outbound.send(Outbound::All(frame)).await;
                        }
                    }
                }
            }
        }

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
            let _ = transport.outbound.send(Outbound::All(frame)).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    // No explicit restore: `_terminal_guard` does it as this scope ends, and on
    // every path that never reaches here.
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

/// Reads a file for transmission, refusing early what the mesh cannot carry.
///
/// The type is guessed from the extension rather than sniffed: the receiver
/// only uses it to decide whether to try rendering the bytes as an image, and
/// a wrong guess there costs a failed decode, not a corrupted file.
/// Mirrors the favourite table into the persisted state and saves it.
///
/// A favourite that does not survive a restart is a name with no way to reach
/// it, so the address matters more than the flag.
fn save_favorites(state: &mut persistence::AppState, mesh: &MeshService, app: &mut App) {
    state.favorites.clear();
    state.favorited_us.clear();
    state.favorite_nostr_keys.clear();
    state.favorite_nicknames.clear();
    state.favorite_noise_keys.clear();
    for (fingerprint, entry) in mesh.favorites.all() {
        if entry.we_favorited {
            state.favorites.insert(fingerprint.clone());
        }
        if entry.they_favorited {
            state.favorited_us.insert(fingerprint.clone());
        }
        if let Some(key) = &entry.their_nostr_key {
            state
                .favorite_nostr_keys
                .insert(fingerprint.clone(), key.clone());
        }
        if !entry.nickname.is_empty() {
            state
                .favorite_nicknames
                .insert(fingerprint.clone(), entry.nickname.clone());
        }
        // Their announced key, so mail can still be addressed to them after
        // they walk away — the one case couriering exists for.
        if let Some(key) = &entry.noise_public_key {
            state
                .favorite_noise_keys
                .insert(fingerprint.clone(), hex::encode(key));
        }
    }
    if let Err(error) = persistence::save_state(state) {
        app.add_notice(format!("could not save favourites: {error}"));
    }
}

fn load_outgoing_file(path: &str) -> Result<(String, Option<String>, Vec<u8>), String> {
    let path = std::path::Path::new(path.trim());
    let expanded;
    let path = if let Ok(rest) = path.strip_prefix("~") {
        expanded = dirs::home_dir()
            .ok_or_else(|| "no home directory to expand ~ against".to_string())?
            .join(rest);
        expanded.as_path()
    } else {
        path
    };

    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    if path.is_dir() {
        return Err(format!("{} is a directory", path.display()));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "that filename is not valid text".to_string())?
        .to_string();

    let bytes = std::fs::read(path).map_err(|error| format!("could not read {name}: {error}"))?;
    let mime = match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
        .as_deref()
    {
        Some("png") => Some("image/png"),
        Some("jpg") | Some("jpeg") => Some("image/jpeg"),
        Some("gif") => Some("image/gif"),
        Some("webp") => Some("image/webp"),
        Some("bmp") => Some("image/bmp"),
        Some("txt") | Some("md") => Some("text/plain"),
        _ => None,
    }
    .map(str::to_string);

    Ok((name, mime, bytes))
}

fn fixed_key(bytes: Option<&[u8]>) -> Option<[u8; 32]> {
    bytes.and_then(|slice| <[u8; 32]>::try_from(slice).ok())
}

fn apply_mesh_event(app: &mut App, mesh_event: MeshEvent, last_notice: &mut String) {
    match mesh_event {
        // Handled by the caller, which owns the transport.
        MeshEvent::Send(_) => {}
        MeshEvent::FavoriteUpdate {
            nickname, notice, ..
        } => {
            let what = if notice.is_favorite {
                "favourited you"
            } else {
                "unfavourited you"
            };
            let reach = if notice.their_nostr_key.is_some() {
                " You can now reach them off-mesh."
            } else {
                ""
            };
            app.add_notice(format!("{nickname} {what}.{reach}"));
        }
        MeshEvent::DeliveryUpdate { message_id, status } => {
            app.mark_delivery(&message_id, status);
        }
        MeshEvent::PrivateMessage {
            sender,
            content,
            message_id,
            ..
        } => {
            // Straight off the radio, so arrival is the send time.
            app.add_dm_received(sender, message_id, content, chrono::Local::now().timestamp());
        }
        // Handled in the frame loop, where the gateway policy, the relay pool,
        // the shelf and the toggles are all in scope. Nothing routes one here.
        MeshEvent::CarriedEvent { .. }
        | MeshEvent::CourierDeposit { .. }
        | MeshEvent::CourierArrived { .. } => {}
        MeshEvent::SessionUp {
            nickname,
            fingerprint,
            ..
        } => {
            let short: String = fingerprint.chars().take(16).collect();
            app.add_notice(format!(
                "encrypted channel with {nickname} is up ({short})"
            ));
        }
        MeshEvent::PeerAppeared { nickname, .. } => {
            app.add_notice(format!("{nickname} connected"));
        }
        MeshEvent::PeerRenamed { nickname, .. } => {
            app.add_notice(format!("a peer is now known as {nickname}"));
        }
        MeshEvent::PeerLeft { nickname, .. } => {
            app.add_notice(format!("{nickname} disconnected"));
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
            app.add_channel_line(IncomingLine {
                channel: "#public".to_string(),
                sender,
                epoch,
                content,
            });
        }
        MeshEvent::FileReceived {
            sender,
            name,
            mime: _,
            bytes,
            is_image,
            ..
        } => {
            let size = format!("{:.0} KiB", bytes.len() as f64 / 1024.0);
            if !is_image {
                app.add_notice(format!(
                    "{sender} sent {name} ({size}) over the mesh - only images can be shown."
                ));
                return;
            }
            // Already in hand: decode straight into the cache and offer it in
            // the viewer, with no network request of any kind.
            match image::load_from_memory(&bytes) {
                Ok(decoded) => {
                    let key = media::mesh_key(&sender, &name);
                    app.image_dimensions
                        .insert(key.clone(), (decoded.width(), decoded.height()));
                    app.images.insert(key.clone(), decoded);
                    let conversation = "#public".to_string();
                    app.viewer.remember(media::ImageLink {
                        url: key,
                        sender: sender.clone(),
                        conversation,
                    });
                    app.add_channel_line(IncomingLine {
                        channel: "#public".to_string(),
                        sender: sender.clone(),
                        epoch: chrono::Local::now().timestamp(),
                        content: format!("▣ sent {name} ({size}) - /img to view"),
                    });
                }
                Err(error) => app.add_notice(format!(
                    "{sender} sent {name} but it would not decode: {error}"
                )),
            }
        }
        MeshEvent::Notice(text) => {
            // Protocol diagnostics repeat a lot; only surface transitions.
            if *last_notice != text {
                *last_notice = text.clone();
                app.add_notice(text.to_string());
            }
        }
        MeshEvent::Trace(text) => app.add_notice(text.to_string()),
    }
}

/// Leaves a sealed message with every courier in range.
///
/// The last resort, and the only path with no infrastructure in it: the recipient
/// is not here and we have no address for them, so the message is handed to
/// whoever *is* here in the hope that one of them meets them first. Nothing
/// acknowledges it and nothing can — the recipient is absent by definition, which
/// is why it is offered as a possibility rather than reported as a send.
///
/// Returns `None` when there is nobody to ask, so the caller can fall through to
/// saying the message could not go anywhere.
fn post_to_couriers(
    app: &mut App,
    mesh: &MeshService,
    target: &str,
    content: &str,
) -> Option<Vec<Vec<u8>>> {
    // Their announced key, kept by the favourites table after they walked away.
    // Without it there is no tag to address the envelope with, which is the same
    // constraint as being able to name them at all.
    let (_, relationship) = mesh.favorites.resolve(target)?;
    let recipient_key = relationship.noise_public_key.clone()?;
    let nickname = if relationship.nickname.is_empty() {
        peer_id::short_display(target)
    } else {
        relationship.nickname.clone()
    };

    // Anyone we can currently talk to who is not the recipient. A courier does
    // not need to be trusted — it cannot read what it carries — so the bar is
    // only that we have a link to them.
    let couriers: Vec<String> = mesh
        .peers
        .keys()
        .filter(|peer_id| peer_id.as_str() != target)
        .cloned()
        .collect();
    if couriers.is_empty() {
        return None;
    }

    let now_seconds = courier::now_seconds();
    let expiry_ms = (now_seconds + courier::MAX_LIFETIME_SECONDS) * 1000;
    let (envelope, message_id) =
        mesh.seal_for_courier(&recipient_key, content, expiry_ms, now_seconds)?;

    let frames: Vec<Vec<u8>> = couriers
        .iter()
        .filter_map(|peer_id| mesh.courier_frame(&envelope, peer_id))
        .collect();
    if frames.is_empty() {
        return None;
    }

    app.add_dm_sent(nickname.to_string(), message_id.to_string(), content.to_string());
    app.add_notice(format!(
        "{nickname} is not here and has no internet address. Left with {} nearby peer(s) to carry — it reaches them only if one of them sees them within a day, and nothing will tell you either way.",
        frames.len()
    ));
    Some(frames)
}

/// Takes a deposit onto the shelf, or says why not.
///
/// The tier is decided here rather than in the mesh layer because it rests on
/// favourites, which are a relationship rather than a protocol fact. A peer we
/// have never verified gets nothing: holding mail costs us, and the least we can
/// ask is a signature we checked.
fn shelve(
    app: &mut App,
    post: &mut mailbox::Mailbox,
    mesh: &MeshService,
    depositor: &str,
    envelope: courier::Envelope,
) {
    let mutual = mesh
        .favorites
        .resolve(depositor)
        .is_some_and(|(_, relationship)| relationship.mutual());
    let signed = mesh.peers.get(depositor).is_some_and(|peer| peer.verified);

    let tier = if mutual {
        mailbox::Tier::Favourite
    } else if signed {
        mailbox::Tier::Verified
    } else {
        // No trace line: an unverified announce is already reported, and a
        // second complaint per envelope would be the noisier half of a problem
        // the user cannot act on.
        return;
    };

    match post.accept(envelope, depositor, tier, courier::now_millis()) {
        mailbox::Deposit::Accepted => app.add_notice(format!(
            "holding sealed mail for someone, left by {} ({} on the shelf)",
            peer_id::short_display(depositor),
            post.held_count()
        )),
        // Silent: a depositor retrying because it never saw an acknowledgement
        // is the ordinary case, not an event.
        mailbox::Deposit::AlreadyHeld => {}
        mailbox::Deposit::Refused(why) => app.add_notice(format!(
            "turned away mail from {}: {why}",
            peer_id::short_display(depositor)
        )),
    }
}

/// Hands a peer anything we are holding for them.
///
/// Called when they announce, because an announce carries the static key the tag
/// is derived from — being able to recognise their mail is a consequence of them
/// saying hello, and needs nothing else.
fn hand_over(
    app: &mut App,
    post: &mut mailbox::Mailbox,
    mesh: &MeshService,
    peer_id: &str,
) -> Vec<Vec<u8>> {
    if post.held_count() == 0 {
        return Vec::new();
    }
    let Some(peer) = mesh.peers.get(peer_id) else {
        return Vec::new();
    };
    let tags = courier::candidate_tags(&peer.noise_public_key, courier::now_seconds());
    let theirs = post.collect(&tags);
    if theirs.is_empty() {
        return Vec::new();
    }
    app.add_notice(format!(
        "handed {} waiting message(s) to {}",
        theirs.len(),
        peer.nickname
    ));
    theirs
        .iter()
        .filter_map(|envelope| mesh.courier_frame(envelope, peer_id))
        .collect()
}

/// Seconds since the epoch, or zero if the clock is before it.
fn epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

/// Decides whether to publish an event a peer handed us, and returns it when the
/// answer is yes.
///
/// The signature is checked here, before the policy is even consulted. That
/// check is the entire reason a gateway is safe to use: we are a courier who
/// cannot open or alter the parcel, and a courier who does not look at the seal
/// is just a peer with our bandwidth.
#[allow(clippy::too_many_arguments)]
fn uplink(
    app: &mut App,
    carrier: &mut gateway::Gateway,
    depositor: &str,
    direction: nostr::carrier::Direction,
    geohash: &str,
    event_json: &str,
    relays_up: bool,
) -> Option<nostr::event::Event> {
    let now = epoch_seconds();
    let Ok(event) = serde_json::from_str::<nostr::event::Event>(event_json) else {
        return None;
    };
    if !event.verify() {
        // Worth a line: a neighbour handing us unverifiable events is either
        // broken or trying something, and either way we are the only one who
        // can see it happening.
        app.add_notice(format!(
            "refused an unsigned carried event from {}",
            peer_id::short_display(depositor)
        ));
        return None;
    }

    match direction {
        // Someone else's gateway announcing to the mesh. We only note it, so
        // neither of us hands it back to the other — see gateway.rs. Reading it
        // as *chat* is the mesh-only role, which needs no internet and is not
        // what this client is doing here.
        nostr::carrier::Direction::FromGateway => {
            carrier.note_carried_on_mesh(&event.id);
            None
        }
        nostr::carrier::Direction::ToGateway => {
            match carrier.accept_uplink(
                depositor,
                geohash,
                &event.id,
                event_json,
                event.created_at,
                now,
                relays_up,
            ) {
                gateway::Uplink::Publish => Some(event),
                // Held until the relays answer. Said out loud because the
                // depositor cannot tell the difference between waiting and lost.
                gateway::Uplink::Queued => {
                    app.add_notice(format!(
                        "holding a message for #{geohash} until the relays answer ({} waiting)",
                        carrier.held_count()
                    ));
                    None
                }
                gateway::Uplink::Refused(_) => None,
            }
        }
        // Island bridging, which the mesh layer already declined to hand us.
        _ => None,
    }
}

/// Whether to pass a received frame along, and what to put on the air.
///
/// The forwarded copy is re-encoded with one less TTL rather than resent
/// verbatim. That is safe because the packet signature deliberately excludes the
/// TTL — it is the one field a relay is expected to change — so a rebuilt frame
/// still verifies at the far end.
fn relay_plan(
    mesh: &MeshService,
    data: &[u8],
    ingress: &str,
    links: &std::collections::HashSet<String>,
    forwarded: &mut relay::Forwarded,
) -> Option<Vec<u8>> {
    let packet = protocol::Packet::decode(data)?;
    let names: Vec<String> = links.iter().cloned().collect();
    let relay::Relay::Forward { ttl, .. } = relay::plan(&packet, &names, ingress, &mesh.my_peer_id)
    else {
        return None;
    };
    // Checked only once the policy has said yes, so the set fills with packets
    // we actually relayed rather than every packet that ever arrived.
    if !forwarded.accept(&packet) {
        return None;
    }
    let mut onward = packet;
    onward.ttl = ttl;
    onward.encode()
}

/// Opens a gift wrap and acts on what is inside, returning an acknowledgement
/// to post back when one is owed.
///
/// Everything here is decided on the *envelope's* sender — the key that signed
/// the seal, which the crypto proved — and never on the peer ID written inside
/// the packet. That inner ID is the sender's unverified claim about themselves,
/// and routing a conversation by it would let anyone holding our address drop a
/// message into someone else's thread.
fn open_private_envelope(
    app: &mut App,
    mesh: &mut MeshService,
    geo: &mut GeoService,
    seen: &mut nostr::processed::ProcessedEvents,
    wrap: &nostr::event::Event,
) -> Option<nostr::event::Event> {
    // Recorded before it is opened, not after. A wrap that fails to decrypt
    // will fail again identically on the next reconnect, and the relays offer
    // the same day of mail every time — without recording the failures too,
    // one unreadable envelope becomes an error on a loop forever.
    if !seen.remember(&wrap.id) {
        return None;
    }

    let keypair = geo.main_nostr_keypair();
    let (our_pubkey, _) = keypair.x_only_public_key();
    let opened = match nostr::envelope::open_message(wrap, &keypair.secret_key(), &our_pubkey) {
        Ok(opened) => opened,
        // Not necessarily an attack, and not worth a line in the user's log:
        // relays serve whatever is tagged with our key, including mail sealed
        // by a client we cannot read.
        Err(_) => return None,
    };

    // Plain text is not a private message. Upstream frames a whole mesh packet
    // inside the rumor and ignores content without the marker; a bare string
    // arriving here is from something that does not speak this protocol.
    let packet = nostr::embedded::decode(&opened.content)?;
    let payload = nostr::embedded::payload_of(&packet)?;

    // Who this is, by the only identity the envelope actually proved.
    let fingerprint = mesh
        .favorites
        .fingerprint_for_nostr_key(&opened.sender)
        .map(str::to_string);
    if let Some(fingerprint) = &fingerprint {
        if mesh.is_blocked(fingerprint) {
            return None;
        }
    }
    let (conversation, display) = match &fingerprint {
        Some(fingerprint) => {
            let nickname = mesh
                .favorites
                .get(fingerprint)
                .map(|entry| entry.nickname.clone())
                .filter(|nickname| !nickname.is_empty())
                .unwrap_or_else(|| peer_id::short_display(fingerprint));
            (fingerprint.chars().take(16).collect::<String>(), nickname)
        }
        // Someone we favourited who has not favourited us back can reach us
        // without our ever having been given their address. Their mail is
        // real; we simply have no name for them, so it is filed under the
        // address that sent it rather than dropped.
        None => (
            opened.sender.clone(),
            format!("nostr:{}", &opened.sender[..8.min(opened.sender.len())]),
        ),
    };

    match payload.kind {
        NoisePayloadType::PrivateMessage => {
            let record = PrivateMessagePacket::decode(&payload.body)?;
            // Send time from inside the envelope, not the wrap's own timestamp,
            // which is randomised by up to a quarter of an hour to blur it.
            app.add_dm_received(
                display.clone(),
                record.message_id.clone(),
                record.content.clone(),
                opened.created_at,
            );

            // Acknowledge over the transport it arrived on. The sender is out
            // of radio range by construction — that is why this path exists —
            // so a mesh receipt would go nowhere.
            let our_peer_id = mesh.my_peer_id.clone();
            let content = nostr::embedded::receipt(
                NoisePayloadType::Delivered,
                &record.message_id,
                &our_peer_id,
                &conversation,
            )?;
            seal_for(&content, &opened.sender, &keypair)
        }
        NoisePayloadType::Delivered => {
            app.mark_delivery(&payload.message_id()?, DeliveryStatus::Delivered);
            None
        }
        NoisePayloadType::ReadReceipt => {
            app.mark_delivery(&payload.message_id()?, DeliveryStatus::Read);
            None
        }
        // `payload_of` already refused everything else.
        _ => None,
    }
}

/// Frames and seals a private message for a peer we cannot see.
///
/// Returns the event to post and the id it was sent under, so the local echo
/// can be ticked by a receipt that arrives later — possibly over the radio, if
/// they walk back into range before answering.
fn send_over_nostr(
    geo: &mut GeoService,
    mesh: &MeshService,
    their_address: &str,
    their_peer_id: &str,
    content: &str,
) -> Option<(nostr::event::Event, String)> {
    // Their address arrives as bech32 from upstream and as hex from us.
    let recipient = nostr::npub::to_bytes(their_address)?;
    let message_id = uuid::Uuid::new_v4().to_string();
    let framed = nostr::embedded::private_message(
        &message_id,
        content,
        &mesh.my_peer_id,
        their_peer_id,
    )?;
    let event = seal_for(&framed, &hex::encode(recipient), &geo.main_nostr_keypair())?;
    Some((event, message_id))
}

/// Seals `content` for one recipient, drawing the fresh randomness every
/// envelope needs: a throwaway signing key for the wrap and two nonces that
/// must never repeat under their keys.
fn seal_for(
    content: &str,
    recipient_hex: &str,
    sender: &secp256k1::Keypair,
) -> Option<nostr::event::Event> {
    use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};

    let recipient_bytes: [u8; 32] = hex::decode(recipient_hex).ok()?.try_into().ok()?;
    let recipient = XOnlyPublicKey::from_byte_array(recipient_bytes).ok()?;
    let ephemeral = Keypair::from_secret_key(
        SECP256K1,
        &SecretKey::from_byte_array(rand::random::<[u8; 32]>()).ok()?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    nostr::envelope::seal_message(
        content,
        &recipient,
        sender,
        &ephemeral,
        now,
        nostr::envelope::published_timestamp(now, rand::random::<i64>()),
        [rand::random(), rand::random()],
    )
    .ok()
}

/// Location channel traffic. Chat lands in the "#<geohash>" conversation; the
/// presence beacons only update the participant list.
fn apply_geo_event(
    app: &mut App,
    geo: &mut GeoService,
    geo_event: GeoEvent,
    health: &mut nostr::health::RelayHealth,
) {
    match geo_event {
        // Said only for a relay we had already reported down. Announcing every
        // successful connection would put a line on screen for each of the five
        // relays behind an ordinary join.
        GeoEvent::RelayConnected { relay, .. } => {
            if health.recovered(&relay) == Notice::BackUp {
                app.add_notice(format!("{relay} is answering again."));
            }
        }
        // No channel in the message: the host is down for every subscription at
        // once, so naming the one that happened to notice would report the same
        // fact once per channel and once more for the map sampler.
        GeoEvent::RelayFailed { relay, reason, .. } => match health.fell_over(&relay) {
            Notice::Down => {
                app.add_notice(format!("{relay} unreachable ({reason})"));
            }
            Notice::Unstable => {
                app.add_notice(format!(
                    "{relay} keeps dropping; no longer reporting it."
                ));
            }
            Notice::Silent | Notice::BackUp => {}
        },
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
            app.add_channel_line(IncomingLine {
                channel: channel.clone(),
                sender: sender.clone(),
                epoch: created_at,
                content: content.clone(),
            });
        }
        GeoEvent::Presence {
            geohash, pubkey, ..
        } => {
            geo.note_activity(&geohash, &pubkey, None);
        }
        GeoEvent::HistoryEnd { geohash } => {
            let channel = geo::channel_name(&geohash);
            let epoch = chrono::Local::now().timestamp();
            app.add_channel_line(IncomingLine {
                channel: channel.clone(),
                sender: "system".to_string(),
                epoch,
                content: "─── live ───".to_string(),
            });
        }
        // Cells the map is watching but we have not joined.
        GeoEvent::Activity {
            geohash,
            pubkey,
            is_message,
        } => app.map.note_voice(&geohash, &pubkey, is_message),
        // Both are handled in the loop, where the identity keys, the gateway
        // policy and the radio are in scope. Nothing routes one here.
        GeoEvent::PrivateEnvelope { .. } | GeoEvent::Carryable { .. } => {}
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
