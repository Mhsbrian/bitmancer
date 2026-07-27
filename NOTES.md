# Implementation notes

Things worth knowing before changing the protocol layer. Most of these are
constraints discovered the hard way against the live network, where getting a
detail wrong means the other side silently ignores you rather than erroring.

## Project

`bitmancer` is a single-binary Rust terminal client for BitChat, a serverless
peer-to-peer chat protocol carried over Bluetooth Low Energy, plus its geohash
location channels carried over Nostr. The reference implementation is the Swift
app at `permissionlesstech/bitchat`; this client has to match its wire format
byte for byte to interoperate.

It began as a fork of `vaibhav-mattoo/bitchat-tui`, whose protocol layer
targeted a mid-2025 wire format upstream has since replaced (renumbered opcodes,
key-derived peer IDs, signed TLV announces, no channels). That layer has been
rewritten; the geohash, map and image features are new. See "What is not done".

Identity lives in `~/.bitmancer/state.json`, adopted from `~/.bitchat/state.json`
on first run — the mesh peer ID is derived from the stored Noise key, so a fresh
start would silently make us a different person to everyone who already saw us.

## Commands

```bash
cargo build                       # debug build
cargo build --release
cargo run                         # runs the TUI; needs a real BLE adapter
cargo run -- --doctor 10          # Bluetooth diagnostics, lists nearby BitChat peers
cargo run -- --geo-doctor 9q 15   # relay diagnostics for a geohash channel
cargo run -- --geo-sample "" 20   # headless version of the map's heat query
cargo test
cargo test protocol::             # one module's tests
cargo test round_trips            # single test by substring
cargo check                       # fast type-check; the usual inner-loop command
cd packaging && makepkg -si       # install as an Arch package
```

`--doctor` is the first thing to reach for when the client "does not connect": it
separates a broken Bluetooth stack from simply having no BitChat peer in range,
which the scanning popup cannot distinguish. `--geo-doctor` does the same for
location channels and is subscribe-only on purpose — never publish test traffic
into a real geohash channel; use an empty cell if you need to exercise sending.

Linux builds pull in `dbus` with the `vendored` feature, so a C toolchain and `pkg-config` are needed; the AUR `PKGBUILD` strips `vendored` to link the system libdbus instead. Runtime needs `bluez` and an enabled adapter.

`persistence::tests::test_persistent_noise_static_key` reads and writes the real `~/.bitchat/state.json` — it is not hermetic. Everything else is pure.

## Wire format: the rules that actually bite

All of this is ported from `localPackages/BitFoundation/Sources/BitFoundation/` and `bitchat/Protocols/` upstream. Get any of it wrong and the peer silently ignores you — bitchat's announce handler says "no backward compatibility" and means it.

- **Peer IDs are derived, not random** (`peer_id.rs`). A peer ID is the first 16 hex chars of SHA-256(Noise static public key); the frame carries those 16 hex chars decoded to 8 bytes. The receiver re-derives the ID from the announced key and drops the announce on mismatch, so the ID must stay pinned to the persisted Noise key.
- **Announces are signed TLV** (`announce.rs`). Mandatory TLVs: nickname 0x01, noise public key 0x02, signing public key 0x03. The packet carries an Ed25519 signature over the *canonical* encoding — signature cleared, TTL forced to 0, RSR flag cleared, and padded. Verification re-encodes, so the canonical bytes must be reproducible on both sides.
- **Announce payloads must stay under 100 bytes.** Upstream compresses any payload at or above that threshold before signing, using Apple's DEFLATE, whose output we cannot reproduce byte-for-byte with flate2. Below the threshold neither side compresses and signatures match. This is why `announce::MAX_NICKNAME_BYTES` is 24 — do not raise it without solving the canonical-compression problem.
- **Outbound frames are never compressed** (`protocol.rs`), for the same reason. Inbound compressed frames are decoded normally.
- **Compression is raw DEFLATE, not zlib** (`compression.rs`). Apple's `COMPRESSION_ZLIB` emits RFC 1951 with no wrapper or checksum.
- **Padding is PKCS#7 where every pad byte equals the pad length.** Upstream's `unpad` verifies that, so the random padding the old client emitted was never stripped.
- **Opcodes were renumbered.** `announce 0x01`, `message 0x02`, `leave 0x03`, `noiseHandshake 0x10`, `noiseEncrypted 0x11`, `fragment 0x20`. Notably 0x02 used to be KeyExchange and 0x04 used to be Message — sending the old numbering means sending a public chat message where a key exchange was intended.
- **Frame v2 exists**: 16-byte header, 4-byte payload length, optional source-route section, `hasRoute 0x08` / `isRSR 0x10` flags. We decode v1 and v2 and emit v1.
- **Channels are gone** (deleted upstream July 2025). The message payload's 0x40 flag now means `isBridged`, not `hasChannel`.
- **Liveness is a keepalive**, not a handshake: peers expire a silent link's peer entry after 8s and expire the peer entirely after 45–60s, so `mesh.rs` re-announces every 10s.

## Geohash location channels (Nostr)

The `#<geohash>` channels the phone app shows are **not** mesh channels — they
are Nostr, over the internet, and nothing about them touches BLE. Ported from
`bitchat/Nostr/` and `bitchat/Protocols/Geohash.swift`:

- Chat is Nostr **kind 20000** with tags `["g",<geohash>]`, optional
  `["n",<nickname>]` and `["t","teleport"]`; the content is the plain message.
- Presence is **kind 20001**: empty content, no nickname tag, broadcast on a
  40–80s loop and **only at region/province/city precision (2/4/5)**. Beaconing
  at block or building level would broadcast the user's exact location, which is
  why upstream restricts it and `geo.rs` enforces the same list.
- Event ids are `sha256(json([0,pubkey,created_at,kind,tags,content]))` with
  slashes unescaped, signed BIP-340 Schnorr over that hash.
- Each channel gets its own key: `HMAC-SHA256(device_seed, utf8(geohash) ‖
  u32be(i))`, first valid scalar. Channels are unlinkable from each other and
  from the mesh identity. The seed lives in `state.json` as `nostr_device_seed`.
- **Relay choice is load-bearing**: the 5 closest relays to the geohash centre
  from `assets/online_relays_gps.csv`, ties broken by host. Publishers and
  subscribers only meet because they compute the same set from the same file —
  change the selection and the client goes silent without erroring.
- NIP-13 PoW is mined to 8 bits before signing, since the nonce tag is part of
  the id. Mining is time-capped and steps the committed target down rather than
  blocking a send.

Module layout: `geohash.rs` (encoding, cell geometry, relay directory),
`nostr/event.rs`, `nostr/identity.rs`, `nostr/pow.rs`, `nostr/relay.rs` (framing),
`nostr/client.rs` (relay pool), `geo.rs` (the service, mirroring `mesh.rs`).

### Images

People post pictures as links, in both the mesh and geohash channels. The
client detects them, marks the carrying line with `▣`, and shows them in an
overlay (`/img`, or `i` outside the input box; `←→` steps through the
conversation's images).

**Nothing is ever fetched automatically, and that is a security property, not a
performance one.** A chat line is written by a stranger; requesting the URL in
it hands that stranger your IP address, rough location and a timing signal — on
a network whose whole point is not doing that. Detection is pure text
inspection, so the marker and the index cost no traffic. A request leaves the
machine only when the user opens an image, and the viewer names the host it is
about to contact. Fetches are capped (`MAX_IMAGE_BYTES`, timeout, redirect
limit, content-type check) and cached in a small LRU.

Rendering has two backends (`tui/image_render.rs`). Kitty's graphics protocol
draws real pixels; everywhere else falls back to 24-bit half-blocks (two pixels
per cell), so the feature degrades instead of disappearing.
`BITMANCER_IMAGES=halfblocks|kitty` forces either. Multiplexers never get
graphics — tmux and screen rewrite escapes and would corrupt the display.

Three things about the kitty path are load-bearing: escapes must be written
*after* `terminal.draw` flushes or ratatui overwrites them (hence the panel
returning an `ImageSlot` and `paint_kitty_image` filling it); the payload is
transmitted once by id and later frames only re-place it (a redraw at 10 fps
would otherwise push kilobytes down the pty every frame); and `q=2` is required
on every escape, or the terminal's acknowledgements arrive in the input stream
and are read as junk keystrokes.

Not supported: native mesh file transfer. Upstream carries real image bytes over
BLE (`fileTransfer = 0x22` plus `fragment = 0x20` reassembly); that is a
separate piece of work from links.

### Layout

Panels are divided by hairlines, not boxes. Six rows were going to box drawing
that carried no information; a rule divides just as clearly and gives the rows
to the log. Because there are no borders left to light up, **focus is carried by
the brightness of a section label** (`theme::section`) and by the compose
prompt glyph.

The top band is a readout rather than a header: callsign and short peer ID on
the left, then MESH / GEO / UP / clock in fixed-width fields on the right. The
widths are padded deliberately and there is a test for it — a peer count going
from 9 to 10 must not shift the clock sideways while someone is reading it.

Telemetry appears in the band and nowhere else. It used to be duplicated on the
key strip; saying the same thing twice on one screen trains the eye to ignore
both.

### Visual system

`tui/theme.rs` is the single source of style; no widget defines its own colour.
The rules it encodes, in priority order:

1. **Colour carries meaning, never decoration.** Six roles and no more: chrome
   and faint (structure), text and dim (content), `LIVE` cyan (other people and
   activity), `MINE` mint (your messages, your channels, a healthy link), `ALERT`
   amber (unread, mentions of you), `FAULT` red (offline). `CURSOR` magenta is
   *reserved* — if something is magenta it is where you are pointing, nothing
   else, and a test enforces that no other role shares the value.
2. **No filled selection bars, no emoji, no ASCII art.** Selection is a gutter
   mark (`▌` cursor, `▏` active); panel titles are spaced small-caps; structure
   is thin rules and negative space.
3. **Dim by default.** Brightness is spent only on what changed.
4. **And what changed is a matter of time, not just of role.** A line lands
   lit and cools into the resting palette over 1.5s (`theme::SETTLE`), with a
   short hold at full brightness first so an arrival reads as an entrance
   rather than a flicker. Colours are *lifted toward* a cool white rather than
   replaced, so a speaker's hue and an amber mention both brighten without
   either changing what it is, and no hue has to travel through grey to get
   there. A fading mark in the gutter column carries the cyan.

   Two rules keep that from becoming a strobe, and both are load-bearing:

   - **Newness is a property of the clock, not of position in the log**
     (`LIVE_HORIZON`, 120s). Judging it by "did this land at the end" is the
     obvious rule and it is wrong: a geohash event carries the *sender's*
     `created_at` from before it was mined and relayed, and the `─── live ───`
     divider is stamped with *our* clock at EOSE, so essentially every real
     message sorts in behind something and was silently muted. Two phones in
     one channel rarely agree to the second either. An hour-old backlog is
     nowhere near the horizon, which is the distinction that actually matters.
   - **A flood is not news.** More than `BURST_LIMIT` lines inside
     `BURST_WINDOW` — a relay flushing its backlog, or `/help` printing fifteen
     rows — arrive dark, *including the ones already lit when the flood became
     recognisable*. The count lives in `ArrivalGate` rather than in the
     messages, because clearing a line's arrival stamp is exactly what marks it
     as part of a burst, which also destroys the evidence that it was one:
     counting in the messages restarted the tally every time a group was
     cleared and lit a fresh group every few lines all the way down a backlog.

   A settled line must render *identically* to one that never animated, or the
   log ends up permanently striped; `theme::arriving(colour, 0.0)` returning
   the resting colour exactly is enforced by a test.

5. **A line materialises before it cools.** For the first 260ms
   (`theme::REVEAL`) the body sweeps in left to right behind a bright cyan
   edge (`FRONTIER`), with `RESOLVING_CELLS` cells just behind it flickering
   through block and shade forms before settling into their real characters.
   Three things keep it from being a gimmick:

   - **Only the body sweeps.** The timestamp and the sender column are
     structure and hold their positions, or every arriving line jitters
     sideways as it lands.
   - **Wrapping is computed on the whole message first**, and the sweep is a
     character budget applied across the already-wrapped rows
     (`reveal_spans`), so revealing text never reflows it. Rows the sweep has
     not reached render blank rather than being omitted, so the log does not
     grow row by row.
   - **Double-width glyphs never flicker.** Standing a one-cell block in for a
     two-cell emoji would drag the rest of the row sideways and back again.

   The loop drops to `ANIMATION_TICK` (30fps) while `App::is_animating`, and
   back to the 10fps idle rate afterwards. At the idle rate a 260ms sweep is
   three frames and reads as stepping rather than motion.

Speakers get a stable hue from a deliberately narrow cool palette of six, so a
busy channel stays legible without becoming confetti.

Two layout details worth keeping: the message log uses a fixed, right-aligned
sender column measured in **display columns** (`unicode-width`, because an emoji
handle is two cells and char-counting shifts that row's body), and inbound chat
is inserted by send time rather than appended, since a slow relay can replay an
hour-old backlog after the live conversation.

### The world map

`/map` (or `m` outside the input box) opens a canvas overlay: `tui/map.rs` holds
the state machine, `tui/widgets/map_panel.rs` draws it. Arrows move; `+`/`-` zoom;
Esc, Backspace, Ctrl+H and `-` all zoom out (terminals disagree about Backspace,
and being unable to zoom out is a trap); `q` closes.

**Enter means "go in" the way a user means it**: on a cell at a real channel
level it joins the conversation, and only at the in-between precisions (1 and 3,
where no channel exists to join) does it zoom. The key bar renders which of the
two it will do, so the ambiguity is never felt.

Two ordering hazards live in `tui/event.rs::handle_key_event`, both regressions
once already: the map branch must come *before* the connection-overlay Esc
dismissal, or Esc is swallowed while offline and the map cannot be exited; and
the keyboard poll timeout must never be zero (`ESC_RESOLVE_WINDOW`), because
crossterm only resolves a bare `0x1b` into Esc when a read times out.

**Every subscription must carry a `since`.** Kinds 20000+ are ephemeral and
relays are not supposed to store them, but many do — without a cutoff a fresh
subscription replays hours of dead conversation as though it just arrived.
Upstream's windows, which we match: joined channel `now − 3600s` limit 200
(`nostrGeohashInitialLookback*`), map sampler `now − 300s` limit 100
(`nostrGeohashSampleLookback*`).

**Only chat is deduplicated.** Presence is idempotent downstream (it lands in a
set of pubkeys) and is ~99% of the traffic — a couple of dozen idle people emit
thousands of beacons a minute. Letting presence share the dedup ring churned it
in seconds, so genuinely-seen chat was evicted and redelivered as new after any
reconnect. Chat is keyed twice, as upstream does: by event id, and by
`pubkey|created_at|content` so a re-serve after eviction is still caught.

Two non-obvious pieces:

- **Sampling follows channel levels, not the view.** Events carry an exact
  geohash and channels only exist at precisions 2/4/5/6/7/8, so a view whose
  cells sit at an in-between precision (1 or 3) would match nothing. At those
  levels `sample_targets` drops one level deeper — 1024 cells in a single
  `#g` filter, which relays do accept — and `note_voice` rolls each event back up
  to the visible ancestor by prefix. That is what makes the world view light up.
- **The history boundary is marked.** Because the backlog is buffered until
  every relay EOSEs, we know exactly where replayed history ends, and emit a
  `─── live ───` divider there. Upstream has no equivalent; it is cheap here and
  stops hour-old lines passing for live conversation.
- **The rendering rules are deliberate.** Continuous grid rules cage the map and
  bury the coastlines, so the lattice is drawn as ticks at intersections; and
  active cells are centred nodes rather than outlines, because neighbouring
  outlines share edges and merge back into heavy rules. Palette is coastline
  slate, one cyan ramp for activity, magenta reserved for the cursor alone.

Two details in the relay pool that look optional and are not: stored events
arrive newest-first, so a new subscription buffers until **every** relay sends
EOSE (or a 3s deadline) and replays sorted by `created_at` — flushing on the
first EOSE leaves the other four relays' history interleaved backwards. And
rustls 0.23 will not pick a crypto provider on its own; `install_crypto_provider`
must run before any relay connection or the TLS handshake panics.

## Architecture

Three layers, deliberately not sharing state:

- **`transport.rs`** — owns the BLE radio in its own tokio task. Scans (15s windows), connects, subscribes, then pumps frames both directions over channels until the link drops, reconnecting with capped exponential backoff. It emits `TransportEvent` (`Status`/`Connected`/`Frame`/`Disconnected`/`Fatal`) and consumes raw frames to write. It knows nothing about the protocol.
- **`mesh.rs`** — the protocol session: local identity, peer registry, replay dedup, announce cadence, and inbound dispatch. `handle_frame(&[u8]) -> Vec<MeshEvent>` is the single entry point and is pure enough to unit-test without a radio (most tests drive two `MeshService`s against each other).
- **`main.rs`** — the UI loop. Drains transport events, maps `MeshEvent`s onto the ratatui app, applies the UI's `pending_*` requests, runs the announce/prune timer, and draws. No protocol logic lives here.

Supporting modules: `protocol.rs` (frame codec + padding), `announce.rs` (TLV + signing), `message.rs` (the chat payload inside 0x02), `peer_id.rs`, `compression.rs`, `commands.rs` (slash commands as an outcome enum), `persistence.rs` (`~/.bitchat/state.json`, holds the Ed25519 identity key and the Noise static key).

### UI boundary

The TUI (`src/tui/`) still shares no types with the backend. Backend → UI messages are strings parsed by `App::add_log_message`: `system: <text>` for notices and `__CHANNEL__:#public:<sender>:<HHMM>:<content>` for chat lines. UI → backend requests are `pending_*` fields on `App` that the main loop `take()`s each iteration. Adding a new backend→UI signal means a marker at the emit site *and* a branch in `add_log_message`.

The connection overlay covers the whole UI while disconnected; `Esc` dismisses it so the client stays usable offline (reconnection continues regardless). Keep `App::MAX_POPUP_MESSAGES` small — the popup's message pane is only about four rows.

## Mesh fragments, files and relaying

**Fragments (`0x20`, `fragment.rs`).** A BLE write is small, so larger frames
arrive split: payload is `[id u64][index u16][total u16][original type u8][slice]`
and the reassembled bytes are a *complete encoded packet*, which is what lets a
compressed or signed inner packet survive. Reassembly feeds back through the
same dispatch, with a guard so a fragment carrying a fragment cannot recurse.
Bounds are upstream's: 10,000 fragments max, 128 assemblies in flight, 30s
lifetime, and a cap on assembled size.

**Files (`0x22`, `file_packet.rs`).** TLV: fileName `0x01`, fileSize `0x02`,
mimeType `0x03`, content `0x04`. Only `content` carries a 4-byte length, and
older senders wrote 2, so the decoder tries the canonical width and falls back.
Images are handed to the same viewer as linked ones under a `mesh:` key, so they
are never fetched — the bytes are already in hand.

**Relaying (`relay.rs`) is a policy, not a rebroadcast, and it deliberately never
fires today.** A flood terminates because a packet is never sent back out the
link it arrived on — and this client holds exactly one BLE link, so every
"relay" would be an echo to the peer that just spoke. `plan()` returns
`Suppress("no link other than the one it came from")` in that case. Written this
way, forwarding becomes correct by construction if multi-link support lands,
instead of being a bug someone has to remember. It also refuses inflated TTLs,
packets addressed to us, presence, and unknown types.

## What is not done

- **Noise DMs.** `noise_protocol.rs` and `noise_session.rs` implement `Noise_XX_25519_ChaChaPoly_SHA256`, which is still the right suite, but they are wired for the old three-opcode framing (separate init/response/encrypted types). Current upstream uses unified `noiseHandshake 0x10` (direction inferred from the payload) and `noiseEncrypted 0x11` carrying an inner `NoisePayload` type byte (privateMessage 0x01, readReceipt 0x02, delivered 0x03). Both modules currently compile but are unreferenced. `/dm` and `/reply` report this instead of pretending.
- **Sending** fragments and files. Reassembly and decoding are in; the outbound
  side (splitting our own large frames, uploading a picture) is not.
- **Multi-link.** The transport connects to one peripheral, which is why relaying
  never fires. Upstream holds up to six central links.
- **Everything internet-side** — Nostr transport, geohash channels, groups, media/file transfer, voice, gossip sync — is out of scope for a mesh-only terminal client.

## Verification

There is no second BitChat device in this environment and no loopback mode, so protocol work is verified by unit tests rather than live traffic. Two things help:

- `mesh.rs` tests wire two `MeshService` instances together, which exercises encode → decode → verify end to end.
- `protocol.rs` carries the malformed-frame cases ported from upstream's `BinaryProtocolTests.swift` "Bounds Checking Tests (Crash Prevention)". Keep those passing.

Driving the actual TUI requires a pty (it takes over the terminal). There is no tmux on this machine; a pty + `pyte` driver script works well for screenshots and key injection.

## Arch packaging

`packaging/PKGBUILD` builds this checkout. Two
things about it are load-bearing:

- It lives in `packaging/`, not the repo root, because makepkg uses
  `$startdir/src` as its build directory — at the root that collides with the
  crate's own `src/`, and `makepkg -C` would delete it.
- `prepare()` copies the tree into `$srcdir/build` and patches out the `dbus`
  crate's `vendored` feature there. makepkg exports `LDFLAGS` with
  `--as-needed`, which drops the statically vendored libdbus and leaves every
  `dbus_*` symbol undefined at link time. The system libdbus links fine. The
  copy also keeps packaging from mutating the working tree.

The old `bitchat-tui` package may still be installed from the AUR; it is a
different binary speaking the 2025 protocol and is unrelated to this one.

## Legacy artifacts

The repo root still tracks `debug.log`, `packet_debug.log`, `noise_debug.log`, `noise_handler_debug.log`, and `noise_protocol_debug.log` from the old client. The modules that wrote the first three are deleted; the two `noise_*` ones will only be written again once the Noise work resumes, and those writers still append unconditionally to the current working directory. If you re-enable that path, run the binary from outside the repo or the files show up dirty in `git status`.
