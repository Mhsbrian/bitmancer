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
- **Noise frames are not signed.** `noiseHandshake 0x10` and `noiseEncrypted 0x11` are addressed and unsigned. The handshake authenticates the channel on its own, and a signature would not survive anyway: verification re-encodes canonically, and that re-encode compresses payloads at or above 100 bytes with a DEFLATE we cannot reproduce. Handshake messages routinely exceed 100 bytes, so a signed Noise frame would be dropped every time. Only announces and public messages are signed.
- **Encrypted frames carry a typed payload.** The plaintext inside 0x11 is `[type byte][body]`. There are eleven types, not three: privateMessage 0x01, readReceipt 0x02, delivered 0x03, groupInvite 0x06, groupKeyUpdate 0x07, voiceFrame 0x08, verifyChallenge 0x10, verifyResponse 0x11, vouch 0x12, privateFile 0x20, authenticatedPeerState 0x21 (upstream `BitchatProtocol.swift`). We decode all of them and act on the first; the rest are named in `/debug` rather than reported as corruption.
- **A private message is a TLV record, not raw text.** The body of a privateMessage payload is `[type u8][len u8][value]` with messageID 0x00 and content 0x01, both mandatory, each capped at 255 bytes by the one-byte length (upstream `Packets.swift`, `PrivateMessagePacket`). Sending raw UTF-8 there is readable only by another client making the same mistake — which is what this repo did until the format was checked against the source. Long messages split at 255 bytes; an unknown TLV type aborts the whole record, matching upstream, because a half-understood record renders wrongly.
- **A mesh receipt is the bare message ID, nothing more.** The body of a
  readReceipt or delivered payload is the UUID string as UTF-8 — upstream's
  `BLENoisePayloadFactory` sends `Data(messageID.utf8)` and its decoder reads it
  straight back with `String(data:encoding:.utf8)`. The 49-byte `ReadReceipt`
  record with reader ID, timestamp and nickname is a *different* form used
  elsewhere; sending that over the mesh would be read as a nonsense id. Reading
  the construction site settled this where reading the model struct had
  misled — the model is not always what goes on the wire.
- **Read outranks delivered.** The two can race, and upstream discards a
  delivery acknowledgement for a message already marked read. `DeliveryStatus`
  is ordered so the weaker one cannot walk a line backwards.
- **The message ID is load-bearing.** Each private message carries a UUID that a read receipt or delivery acknowledgement points back at (`ReadReceipt.originalMessageID`). A receipt is itself a binary record — originalMessageID and receiptID as 16-byte UUIDs, an 8-byte reader ID, an 8-byte timestamp and a length-prefixed nickname, 49 bytes minimum — so it cannot be faked from a bare ID string.
- **A queued DM needs a session object first.** `NoiseSessionManager::queue_message` returns `false` and discards the text when no session exists for the peer, and `initiate_handshake` is what creates one. Queue before initiating and the user's first message vanishes with only a bool to say so — `dm_frames` initiates first for exactly this reason.
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
- **The directory is a snapshot with no liveness signal**, so a channel whose
  nearest relays have since died picks them again on every join. `#wd` reaches
  two Bangkok hosts (`relay0`/`relay1.gfcom.info`, lines 16 and 353) that refuse
  and 502 respectively, and a third that flaps. This is survivable — the other
  relays carry the channel — but it is the steady state, not a transient, and
  the client has to behave well in it rather than treat it as an error.
- **Relay failures are reported per host, on transition, with a mute.** Three
  separate defects lived here. The notice filter was a single `last_notice`
  string, which two relays failing with *different* reasons defeat completely,
  because consecutive lines never match. The event carried a channel, so one
  dead host was reported once by the joined channel and again by the map
  sampler. And a host that flaps produces an honest, useless line every few
  seconds — so after `FLAP_LIMIT` separate outages a relay is announced as
  unreliable once and then muted. A steadily dead relay is never called
  unstable; it fell over once and stayed there.
- **The reconnect backoff resets on a connection that lasted, not on one that
  opened.** A relay that accepts and immediately drops was "succeeding" on every
  attempt, so it reset the backoff and was redialled every two seconds for the
  session — roughly 1200 dials an hour at a host that never serves anything.
  Resetting only after `STABLE_CONNECTION` makes a degraded host back off like a
  dead one. A socket closing because we left the channel or are quitting is not
  reported as a failure.
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
- **The hotspot list keeps what the roll-up throws away.** `note_voice` receives
  each event's exact geohash and immediately folds it into whichever square is
  on screen, which is right for heat and wrong for "where should I go": at the
  world view it collapses a thousand channels into thirty-two continents, and a
  continent is not somewhere anyone can join. The same events are therefore also
  kept at the precision they arrived at, which is by construction a real channel
  — the sampler only ever subscribes at channel levels. So the panel beside the
  world map is a live global leaderboard built from traffic the client was
  already receiving and discarding.
  - Ranked by people, matching the grid's heat, with messages breaking ties and
    the geohash breaking those: a list redrawn continuously that reshuffles when
    nothing changed cannot be read, let alone aimed at.
  - Cleared when the view moves, because moving re-points the sampler and a
    leaderboard carried across would be sourced from subscriptions we no longer
    hold — stale numbers shown as live ones.
  - Enter travels rather than joins; the next Enter joins. Joining straight from
    the list would drop someone into a channel they have not looked at.
  - The panel's width is *computed* from its column budget rather than chosen
    alongside it. The first version picked a width by eye and the footer was
    clipped mid-word — which reads as a broken renderer, not a long phrase.

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

**Relaying (`relay.rs`) is a policy, not a rebroadcast.** A flood terminates
because a packet is never sent back out the link it arrived on. While the client
held a single link there was no "except", so every possible rebroadcast was an
echo to the peer that had just spoken and `plan()` returned `Suppress("no link
other than the one it came from")` for all of them. Written as a policy rather
than as a rebroadcast that happened to be harmful, it started forwarding
unchanged the moment the transport held two links. It also refuses inflated
TTLs, packets addressed to us, presence, and unknown types.

Two details that are load-bearing:

- **A forwarded packet is re-encoded with one less TTL, not resent verbatim**,
  and that is only safe because the packet signature deliberately excludes the
  TTL — the one field a relay is expected to change. If that ever stopped
  holding, every relayed packet would be rejected as forged by the peer it
  reached and *nothing local would fail*, so there is a test that carries a
  signed packet through a full hop rather than only checking `signing_bytes`.
- **TTL alone is not enough to stop a flood looping.** A node with three links
  hands a copy to two neighbours who hand it to each other; the packet dies
  eventually but goes round several times first. `Forwarded` keys on everything
  about a packet *except* the TTL — which mutates every hop and is precisely
  what must not distinguish two copies of one message.

**The transport holds up to `MAX_LINKS` peers** (six, upstream's
`bleMaxCentralLinks`). One dialler finds peers and brings links up, one pump task
per live link carries traffic, and a router fans outbound frames across them.
Connection attempts stay in the dialler and are made one at a time with a 500ms
gap, matching upstream's `bleConnectRateLimitInterval`: BLE stacks handle
parallel connects badly, and serialising them gives the rate limit somewhere
honest to live. Scanning backs off hard once any link is held, because it shares
the radio with every link it already has. Losing one link of several does *not*
clear the peer list — peers reachable only through the lost link age out on their
own, while the rest are still there.

## Verifying who a peer actually is

**Two different claims were both called "verified" until this existed.**
`MeshPeer.verified` says an announce carried a signature matching the key inside
it — which an attacker in the middle satisfies trivially, by signing with their
own key. Being on the verified list says a human read a fingerprint off a screen
in front of them. The peer listing now labels the first "unsigned announce" when
it fails, and the second "verified in person".

This is the only trust in the client that does not come off the air, and the
only stored thing that costs a walk across town to rebuild, so it persists in
`state.json` under `verified_fingerprints` and is cleared by `/wipe`.

- **A card is `bitchat://verify?…`**, carrying both public keys, a nickname, an
  optional npub, a timestamp and a nonce, signed by the Ed25519 half. Formats
  are upstream's `VerificationService.swift`: the signed bytes are
  length-prefixed fields in a fixed order behind a `bitchat-verify-v1` context,
  with both key fields lowercased there but not in the URL, so a card retyped in
  capitals still verifies. There is a test asserting that layout explicitly
  rather than round-tripping it — a round trip passes just as happily against a
  consistently wrong implementation, and getting it wrong fails in exactly one
  place: someone else's client.
- **Cards expire after five minutes**, in both directions. A card from the
  future is refused as firmly as an expired one, or a card is minted once with a
  distant timestamp and shown for a week.
- **A card missing a signed field fails safely**, which is not hypothetical:
  copying a card out of a wrapped terminal drops the trailing `&npub=` and the
  signature stops matching. Found by driving the real binary rather than by
  testing — the unit tests round-trip a card that was never truncated.
- **Only the responder half of challenge/response is wired.** Issuing challenges
  would prove the peer holds the signing key behind a noise key, which the Noise
  session already establishes since it binds the static key, and a card supplies
  the fingerprint to compare against. Upstream marks its own equivalent
  "scaffold only". Answering is different and not optional: a phone verifying us
  sends a challenge, and if we cannot answer, verification fails at their end
  with nothing on ours to notice. We refuse to sign a challenge naming a key
  that is not ours — otherwise a peer collects our signature over a claim about
  a third party.

## Typing emoji (`tui/emoji.rs`)

A terminal has no emoji picker and no way to reach one without leaving the
keyboard, which for a client whose whole interaction model is typing is the wrong
trade. So emoji are typed the way people already type them: `:fire:` becomes 🔥.

Two paths through one mechanism, and the first is the one that matters:

- **Know the name and it is simply there.** The closing colon expands it, with no
  strip to read and no key to press. A picker that always demands a selection is
  slower than the thing it replaced.
- **Do not know it and the matches appear** above the prompt as you type. Tab
  takes one, arrows move, Esc puts it away.

- **Enter is never a completion key**, unlike Slack and Discord. Those can afford
  it because a picker only opens deliberately; here a colon is punctuation far
  more often than the start of an emoji, so hijacking Enter would mean "note:
  done" plus Enter silently inserting 😄 instead of sending. Tab accepts, Enter
  always sends, and nothing surprising can happen to a message.
- **The strip needs at least one character after the colon**, so `9:30` and
  `TODO:` stay quiet. A hint that appeared on every colon would be a tax on
  ordinary typing.
- **Prefix matches beat substring matches, and table order breaks ties** — which
  is why the table is ordered by how often things are actually sent rather than
  alphabetically. A list that reshuffled as you typed would be unusable at speed.
- **Key precedence had to be fixed twice, both found by pressing the key rather
  than by testing.** Tab is claimed by the pane cycle and Esc by the connection
  overlay, both of which run *before* dispatch to the input handler — so a
  completion claiming them further down never saw them. Worse, the tests passed:
  they called `handle_input_events` directly, which is not a path any keystroke
  takes. They now go through `handle_key_event`.
- **The compose box measures in grapheme clusters, not characters.** This is
  where inserting an emoji made the cursor drift. Three separate places counted
  characters as one cell each — the wrapper, the box height, and the cursor —
  which is exactly right for ASCII and wrong for everything else. They now share
  one measure (`wrap_rows`), so the drawn text and the drawn cursor cannot
  disagree.
  - The cursor was also handed `visual_cursor()` — a width in *cells* — and then
    used it as a *character* count. Two mistakes that cancelled for ASCII and
    compounded for emoji, at one cell of drift per emoji.
  - The unit has to be the cluster because `unicode-width` can only get emoji
    right when it sees them whole. Measured per character, `❤️` (heart plus an
    invisible selector) comes out 1 instead of 2, and `👨‍👩‍👧‍👦` (seven characters
    joined by ZWJs) comes out **8 instead of 2**. Measured as clusters, both are
    2 — which is what a terminal draws.
  - Rows therefore break between clusters and never inside one, so wrapping
    cannot tear a family emoji into four people and a stray joiner.
- Sending emoji was already safe: `split_into_chunks` respects char boundaries,
  so a 255-byte TLV split cannot cut a codepoint in half. It can still split a ZWJ
  sequence across chunks, which degrades to separate glyphs rather than corruption,
  and needs a single unbroken run of ~10 family emoji to happen at all.

## The mailbox (`/mailbox`)

The one thing in the protocol that needs **no infrastructure at all** — not a
relay, not a tower. Alice seals a message for Bob and hands it to whoever is
nearby. That somebody holds it. Bob walks past hours later and collects it.

A courier learns nothing: the only routing information is a 16-byte tag,
`HMAC-SHA256(recipient's noise static key, "bitchat-courier-tag-v1" ‖ epoch_day)`,
so envelopes for the same person on different days do not correlate for anyone
who does not already know that person's key. Delivery works because an announce
carries that key — recognising someone's mail is a consequence of them saying
hello, and needs nothing else.

- **A deposit and a delivery are the same packet.** `courierEnvelope 0x04` in
  both directions; the tag matching one of *ours* is the only thing that
  distinguishes them, and nothing else needs to. A courier that could tell whose
  mail it holds would defeat the point.
- **Tags are checked for yesterday, today and tomorrow.** They rotate at midnight
  and clocks disagree, so checking only today would fail to deliver precisely the
  mail that has waited longest.
- **A carry-only envelope omits the `copies` field** rather than writing 1, or it
  is not byte-identical to one from a client predating spray-and-wait and the
  same message deduplicates differently on the two ends.
- **A stranger's deposit never displaces a favourite's mail.** When the shelf is
  full of mail from people we know, a verified-but-unfamiliar peer is refused
  rather than served at their cost. Upstream's judgement, worth keeping.
- **It persists**, because a mailbox that forgets on restart is not a mailbox —
  but a restart does not extend the promise: anything past its deadline is
  dropped on the way in, not loaded and then swept.
- **We hold and deliver; we do not spray.** Spraying is how a *moving* courier
  compensates for never meeting the recipient. This client usually does not move,
  so being reliably in one place is what it offers instead. A phone is a postal
  van; this is the box on the corner. The copy budget is preserved and honoured,
  never spent.
- **Posting and reading both work.** `/dm` to a favourite who is neither present
  nor internet-addressable seals the message and leaves a copy with every peer in
  range. Mail carried to us is opened, attributed and shown in the sender's
  thread. Nothing acknowledges a couriered send and nothing can — the recipient is
  absent by definition — so it is offered as a possibility rather than reported as
  a delivery.
- **Noise X is IK's first message and nothing after it.** `-> e, es, s, ss`, so
  adding the pattern cost a table entry rather than new crypto. The prologue is
  `"bitchat-courier-v1"`, which is what keeps a one-way envelope and an
  interactive transcript from ever being confused. The sender's key is
  authenticated by the `ss` step rather than claimed in the payload, so neither
  the courier nor anyone who captured it can change who mail is from.
- **A one-way message has no forward secrecy.** A later compromise of the
  recipient's static key exposes envelopes captured in transit. Upstream says so
  and it bears repeating: when a peer is reachable, a session is better and this
  is the fallback. Upstream's answer is one-time prekeys (the `prekey_id` field);
  we do not publish any, so such an envelope is refused up front rather than
  failed at the decrypt.
- **Two bugs found on the way in**, both latent because only XX was ever used:
  - `mix_pre_message_keys` had the **responder never mixing its own static key**
    for IK/NK. The `<- s` pre-message must be mixed by both sides; on one side
    only, the transcripts differ and nothing decrypts.
  - `read_message` **swallowed a failed payload decrypt** and returned an empty
    payload "for debugging". That is an integrity hole, not a leniency: the static
    key decrypts a step earlier, so anyone in the path could blank a message while
    the *sender* still authenticated — the recipient sees an empty message
    provably from someone who never sent it. Found by flipping every byte of a
    sealed envelope and asking which flips still opened.
- **Retaining a favourite's announced key is required, not incidental.** A
  fingerprint is one-way and an envelope is addressed by a tag derived from the
  key, so without `favorite_noise_keys` we could name an absent favourite and
  still have no way to write to them — exactly the person this feature is for.
  Cached while they are in range, and only for peers we already have a
  relationship with: caching every stranger's key would turn the favourites table
  into a log of everyone ever seen.
- **Deduplicated on the inner message id**, not the envelope. Redundant copies of
  one letter are each sealed separately with a fresh ephemeral, so they are
  different envelopes carrying the same message.
- **The block check happens at the open.** A couriered sender is absent, so there
  is no live session to resolve them through; that open is the only point their
  full static key is in hand.

## Seeing the mesh (`/mesh`)

Three things this client does were invisible: it holds up to six links and showed
one number, it forwards other people's packets and said nothing, and it can carry
a channel to the internet and reported a counter. An evening went on screenshots
and log archaeology because of it. `topology.rs` is the instrument panel.

Two facts make a real graph possible and both were already true:

- **Hearing an announce proves a direct link.** `relay.rs` refuses to forward
  presence, so an announce cannot have been passed along — if we have it, it came
  off that peer's own radio. Every peer we know is a neighbour, with no
  bookkeeping needed to establish it.
- **Peers gossip who they can see.** Upstream fills the announce's
  `directNeighbors` TLV with its connected peer IDs (`BLEService.swift:2906`), up
  to ten. We had always parsed that field and always discarded it.

Because announces are never relayed, claims only ever reach us from peers we can
already hear, so the map has a **hard depth of two** — us, our neighbours, and the
peers they name. That is a property of the protocol, not a simplification.

- **Observed and claimed edges are drawn differently** — solid for our links,
  spaced dots for hearsay. Upstream calls gossiped neighbours advisory, and
  drawing an assertion with the same confidence as a measurement promotes it.
- **Bridge detection is the point.** More than one island among the peers, with
  paths through us excluded, means we are the only thing joining them — the moment
  holding several links stops being a statistic.
- **The view scales to its content.** Fixed at the two-ring extent, the common
  case of two neighbours and nothing beyond drew a small graph in a large box,
  which reads as though something failed to load.
- **We consume `directNeighbors` and cannot fill it.** An announce must stay under
  the 100-byte compression threshold or the verifier re-encodes it compressed and
  every announce we send is rejected as forged. With a full-length nickname there
  are **2 bytes spare and one neighbour costs 10**. It costs this view nothing —
  our own links are known locally — so the only loss is appearing in *other*
  clients' maps. Emitting becomes possible if upstream signs the uncompressed
  form, which is worth reading their source for rather than guessing at.

## The radio is one radio, and scanning is not free

Multi-link introduced a regression that only showed up against a real phone, as
"very serious delays between devices". Three causes, all the same mistake — six
link slots made the dialler behave as though hunting for peers were free:

- **A 15-second active scan every 45 seconds while already linked** put the
  adapter in discovery a third of the time. BlueZ interleaves discovery with
  established GATT traffic badly, and that alone made a connected pair crawl. A
  scan while linked is now 4 seconds — the job is only to spot extras — and the
  interval doubles up to 5 minutes on any pass that gains nothing, resetting when
  the link set changes.
- **Ghost dialling.** A phone rotates its BLE address every few minutes and BlueZ
  keeps the old entries, complete with the friendly name. Connecting to one does
  not fail, it *hangs* for the full 8-second timeout — and the dialler walked the
  whole ranked list trying to fill six slots, so it spent up to 40 seconds per
  pass hanging on dead addresses on the same radio as the live link. Observed
  ending in `Method "WriteValue" ... "org.bluez.GattCharacteristic1" doesn't
  exist` — BlueZ tearing down the connection we were actually using.
  `discovery::worth_dialling` now refuses a signal-less candidate once any link
  is held, and attempts are capped per pass.
- **Ghosts are still dialled when we have nobody**, and that is not a hedge: a
  measured run connected successfully to an entry reporting *no signal*. BlueZ
  had simply not attached RSSI yet. With zero links a hanging attempt costs
  nothing that matters; with a link it costs the link.

Measured after: one scan and two dials in 150 seconds, then silence.

**A dropped last link is not an outage.** Because the address rotates, the last
link dropping and another replacing it seconds later is routine. Declaring it
immediately covered the screen with a popup, cleared the peer list and made every
peer re-announce — manufacturing the churn it appeared to report. `OFFLINE_GRACE`
waits 12 seconds, which is longer than a settle plus one connect attempt, and
there is a test pinning that relationship.

## Gateway mode: sharing this machine's internet with the mesh

A phone in a crowd often has a radio and no data. This client usually runs on
something with mains power, a real connection and six BLE links, so `/gateway on`
turns that asymmetry into infrastructure: mesh-only peers hand us geohash events
they signed themselves, we publish them, and we hand back what the relays send.

**We are a courier, not a party.** Every carried event is a complete signed Nostr
event whose contents are public geohash chat, already plaintext on relays. Keys
never leave the originating device; we cannot forge or alter anything, because
the signature is checked before we act and again by the relays and receivers.
Carrying adds reach without adding trust — which is the whole security argument,
and why `gateway.rs` is a policy engine rather than a crypto one.

- **Three loop-prevention sets, each a bug someone already had.** Traffic learned
  from another gateway's broadcast is never re-published or re-broadcast, or two
  gateways hand it back and forth until the TTL runs out. An event is published
  once. And an event we published is *never* rebroadcast — upstream names this
  one: our own subscription returns what we just sent, and putting it back on the
  air spends airtime returning a message to the peer that wrote it.
- **Direction must agree with addressing.** `toGateway` rides a directed packet
  because it is a request of *us*; accepting a broadcast one would have every
  gateway publish the same event. `fromGateway` rides a broadcast because it is
  for everyone; accepting it directed would let one peer feed us a private
  version of a channel.
- **The offer is advertised only while relays actually answer**, and withdrawn
  when they stop. A standing claim is a promise every mesh-only peer in range
  acts on and nobody keeps.
- **Only conversation is carried, not presence.** Presence is ~99% of geohash
  traffic — hundreds of beacons a minute — and would spend the whole airtime
  budget announcing that people exist. This is worth stating in the UI: a channel
  with twelve people and no chat carries nothing, and a counter reading zero next
  to a busy channel otherwise looks like a fault. Verified against live relays:
  `#ey` served 326 presence beacons and zero messages in 25 seconds.
- **The carrier's TLV lengths are 2-byte big-endian**, the only place in this
  codebase that is so, because an event JSON blob does not fit in one byte. Its
  unknown fields are *skipped*, unlike `PrivateMessagePacket` where an
  unrecognised record aborts the whole thing. The capability bits next door are
  little-endian. All three conventions are deliberate and all three are pinned by
  tests asserting literal bytes.
- **Deposits are held through a relay outage** and sent when it clears, bounded
  per peer and overall, dropping the oldest rather than refusing the newest.
  Queued deposits still count against the rate budget, or a peer could wait for
  the relays to blink and then flood. Switching off drops the mailbag, because
  those deposits were made on a promise just withdrawn.
- **Not done: the mesh-only side.** We can be the gateway; we cannot yet be the
  peer that uses one. That needs relay-reachability detection driving a
  `toGateway` deposit, and consuming `fromGateway` as chat — with dedup against
  our own relay subscription, which currently lives inside the supervisor task.

## What is not done
- **A favourite is an address exchange, not a bookmark** (`favorites.rs`).
  Upstream sends it as the *content of an ordinary private message* —
  `"[FAVORITED]:" + npub` — and intercepts it on arrival, so it needs no packet
  type of its own and must be caught before it reaches the chat log. The two
  halves are independent: favouriting someone does not make them reachable,
  only their address does. An unfavourite does not retract an address already
  held, since that would strand queued mail. Verified against
  `BLEService.sendFavoriteNotification` and
  `ChatPrivateConversationCoordinator.handleFavoriteNotification`.
- **The main Nostr identity is not a channel identity.** Location-channel keys
  exist to be unlinkable from one another; the main one exists to be findable,
  and is what a favourite hands out. Its derivation label is ours and need not
  match another client's — a peer never re-derives it, it is exchanged.
- **The private envelope is not NIP-17** (`nostr/envelope.rs`). Upstream states
  it outright: the construction "is deliberately BitChat-specific and is not
  NIP-17, NIP-44, or NIP-59 compatible, even though it historically reuses those
  NIPs' kind numbers (1059/13/14) and a `v2:` content prefix." Implementing the
  standard would produce something no BitChat client can open. Three layers:
  rumor (kind 14, unsigned), seal (kind 13, encrypted to the recipient and
  signed with the sender's real key), gift wrap (kind 1059, encrypted under a
  throwaway key so relays never learn the sender). Cipher is
  XChaCha20-Poly1305 over `v2:` + base64url(nonce24 ‖ ct ‖ tag); key is
  HKDF-SHA256(ikm = shared secret, salt = empty, info = `"nip44-v2"`).
- **The ECDH input is the compressed point, and the reader must try both
  parities.** The shared secret is the 33-byte compressed serialisation, not
  the SHA-256 of it that libsecp256k1 returns by default — so the point's
  *parity byte is key material*. A Nostr key is x-only, and the sender uses
  their own secret as stored, so the parity that went into their derivation is
  a bit that never reaches the wire. There are therefore two candidate secrets
  and the receiver has to try both; the Poly1305 tag decides, so this cannot
  pick wrongly, it only costs one extra AEAD when the first misses. NIP-44
  avoids the whole problem by hashing only the x coordinate. This construction
  does not, and the upstream fixture proves both cases occur in real traffic:
  its gift-wrap layer wants one candidate and its seal layer the other. A
  single-candidate reader opens the wrap and then fails on the seal, which is
  exactly the bug this repo shipped for an afternoon.
- **The rumor's JSON shape is not guessable.** `id` is present and *empty*
  rather than omitted, and `sig` is absent entirely rather than null. Read off
  a real envelope, not from a struct definition. A reader that requires a
  signature there rejects every genuine message.
- **Outer timestamps are jittered by up to ±900s** (`published_timestamp`).
  The true send time rides inside the encrypted rumor. Without this, two relays
  comparing arrival times correlate a conversation they cannot decrypt.
- **`tests/fixtures/legacy_private_envelope.json`** is a genuine envelope from
  upstream's own suite, produced by BitChat release 733098bb. Opening it is the
  only evidence that separates a correct implementation from two wrong ones
  agreeing with each other. Keep the test.
- **Nostr as a DM transport.** Geohash channels already run over Nostr, so the
  client is no longer mesh-only — but private messages are. Upstream selects a
  transport per DM (Bluetooth preferred, Nostr fallback) and queues when neither
  is up, so a peer out of BLE range is still reachable. Ours are not. The
  unhandled `nostrCarrier 0x28` and the never-populated `TLV_BRIDGE_GEOHASH
  0x06` still belong to this gap. Both directions now work: the client
  subscribes to gift wraps at startup, opens them, files the message and
  acknowledges it; and `/dm` to a peer who is out of range seals the message to
  their stored address and posts it. Untested against another implementation.
- **A rumor does not carry text; it carries a mesh packet.** Upstream puts
  `"bitchat1:" + base64url(BitchatPacket)` in the rumor, and
  `NostrInboundPipeline` ignores content without that prefix outright. A client
  that seals plain text is sending something the other side logs and drops. The
  packet is typed `noiseEncrypted 0x11` even though nothing in it is
  Noise-encrypted — the envelope already did that, and doing it again would need
  a session with someone who is by definition out of radio range. The type is
  reused so the payload lands in the same dispatch as a mesh DM, which is why
  `embedded.rs` is thin: only three payload types travel this way
  (`privateMessage`, `delivered`, `readReceipt`), and group state, voice and
  files are explicitly refused at both ends.
- **The inner packet is padded, and that padding is load-bearing.** The envelope
  does not pad its plaintext, so it is the only thing standing between a relay
  and the length of every message it carries for us.
- **Relays redeliver a day of mail on every reconnect**, which is the point —
  the subscription asks for 24 hours precisely so anything sent while we were
  offline arrives. It also means a session-lifetime dedup cache is not enough:
  every relaunch would replay old conversations and re-fire receipts at peers
  who acknowledged them yesterday. `nostr/processed.rs` keeps the opened-wrap
  ids on disk beside the identity, and `/wipe` clears it — a list of envelopes
  we opened is a record of who wrote to us and roughly when. Upstream reached
  the same conclusion in `NostrProcessedEventStore`.
- **DM relays are a fixed set, not the geohash directory.** Those are chosen by
  distance to a location and a DM has no location; using them would also make
  the relays we collect mail from change with where we are standing, and strand
  mail on relays we stopped querying. Four clearnet hostnames is a real
  chokepoint — upstream says so itself and offers user-added relays as the
  escape hatch. We do not have that yet.
- **A DM subscription gets no backlog buffering.** The channel backlog sorts
  replayed history by send time, and a gift wrap's `created_at` is randomised by
  ±15 minutes to blur exactly that; sorting on it would order the day's mail by
  noise. The true time is inside the sealed rumor, so ordering belongs
  downstream of decryption.
- **Inbound routing uses the envelope's sender, never the peer ID inside the
  packet.** The crypto proves who sealed it; the inner ID is the sender's
  unverified claim about themselves, and routing by it would let anyone holding
  our address drop a message into someone else's conversation. Upstream resolves
  the same way, via favourites with a fallback derived from the Nostr key.
- **Upstream hands out `npub`, not hex.** `sendFavoriteNotification` appends
  `":" + myNostrIdentity.npub`, so a peer's stored address is bech32 while
  everything downstream — the seal, the `#p` filter, the ECDH — needs bytes.
  `nostr/npub.rs` accepts either spelling and we now hand out the bech32 form
  ourselves. It refuses an `nsec`: same encoding, different prefix, and sealing
  to a point derived from someone's secret half would fail silently.
  Cross-checked against the BIP-173 reference decoder rather than only
  round-tripped, because a consistently wrong codec round-trips perfectly.
- **A peer who has left can still be addressed.** `/dm bob` used to resolve only
  against live peers, so it answered "nobody here is called bob" for precisely
  the peer the internet transport exists to reach. Resolution now falls through
  to the favourites table, which keeps the nickname and the address after the
  peer list has forgotten them. A favourite's fingerprint begins with their peer
  ID, so both sources yield the same kind of value.
- **The mesh is preferred over Nostr for every private message**, and not only
  for latency: a message that stays on the local radio tells no third party the
  conversation exists, while the relay path necessarily reveals that *someone*
  addressed this recipient even though the envelope hides who and what.
- **A send is not a delivery.** The outbox keeps its copy until a receipt
  clears it, matching upstream. Unlike upstream it also gives up eventually:
  "until acknowledged" with no ceiling means holding a peer's plaintext forever
  when they never return, which is what this client exists not to do. Held
  content is dropped by `/wipe` along with everything else.
- **The outbox holds content, not sealed frames.** Each transport encodes
  differently, the route can change between a failed attempt and a successful
  one, and every sealing draws a fresh nonce — holding ciphertext would mean
  holding something sendable exactly one way, and resending it would reuse a
  nonce.
- **`courierEnvelope 0x04` is store-and-forward.** Upstream hands a sealed copy
  of an undeliverable message to nearby peers who may physically encounter the
  recipient, addressed by a 16-byte rotating tag — an HMAC of the recipient's
  static key and the UTC day. Not implemented here.
- **Fragment size is a local choice, not a protocol constant.** `SLICE_BYTES`
  is 213 so a finished fragment frame lands in the 256-byte padding bucket —
  the only bucket we have live evidence a phone accepts, since announces use
  it. Larger slices mean fewer BLE writes and are very likely fine; raise it
  once the negotiated MTU is observable, not before.
- **Outbound files are unsigned, necessarily.** A file payload is far past the
  100-byte compression threshold, so a signature could never survive the
  receiver's canonical re-encode. Whether a phone insists on one for
  fileTransfer is untested — if it drops our transfers, look there first.
- **Announce TLVs 0x04/0x05/0x06** (`direct_neighbors`, `capabilities`,
  `bridge_geohash`) encode and decode, but nothing ever populates them.
  `direct_neighbors` is the substrate multi-hop routing needs.
- **No ping/pong upstream.** Our opcode table carries `ping 0x26` and
  `pong 0x27`, but neither `BitchatProtocol.swift` nor `Packets.swift` defines
  them and the whitepaper does not mention them. Do not implement these for
  parity; liveness there comes from announces.
- **Opcodes named but unspecified here:** `courierEnvelope 0x04`,
  `requestSync 0x21`, `boardPost 0x23`, `prekeyBundle 0x24`,
  `groupMessage 0x25`. The names came from reading upstream, but nothing in this
  repo pins down their payloads. Do not implement from the names alone.

## Verification

CI runs build, test and `clippy -D warnings` on every push and pull request
(`.github/workflows/ci.yml`), all with `--all-targets` so the test code is
compiled too. That last flag is not incidental: while getting the tree clean,
the library built without a single warning while the tests did not compile at
all, and `clippy` reported zero warnings because it never got far enough to
find any. A gate that only checks the library is measuring the wrong half.

`cargo fmt` is deliberately not enforced. The tree is not rustfmt-clean and
running it would reflow comment blocks that are laid out by hand.


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
