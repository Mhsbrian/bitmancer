# bitmancer

A terminal client for [BitChat](https://github.com/permissionlesstech/bitchat).

BitChat is chat with no servers and no accounts. Phones nearby talk to each
other directly over Bluetooth Low Energy, and that is the whole network — it
works in a basement, on a plane, or with the internet switched off. The same app
also carries *location channels*: rooms named after a geohash cell, which do go
over the internet, via Nostr relays.

bitmancer speaks both from a terminal.

```
┌ C H A N N E L ──────────────────────────────────────────┐┌ N A V ────────────┐
│#9q  ·  33 here                                          ││ ▾ PUBLIC          │
└─────────────────────────────────────────────────────────┘│   public          │
┌ L O G ──────────────────────────────────────────────────┐│ ▾ CHANNELS        │
│22:26     anon7956   Aint it offline? Or are channels    ││▏  #9q             │
│                     online?                             ││ ▾ PEOPLE          │
│22:27        huh?*   @anon7956 hell yeah                 ││   6ix             │
│22:28         6ix* ▣ look at this                        ││   nerdetta        │
│22:28    nerdetta*   ─── live ───                        ││   huh?            │
└─────────────────────────────────────────────────────────┘│   anon7956        │
┌ → #9q ───────────────────────────────────────────────────┐│                  │
│                                                          ││                  │
└──────────────────────────────────────────────────────────┘└──────────────────┘
 ⏎ send  /map world  /help  tab pane          geo 1  ·  mesh ◈ 4
```

## What it does

The Bluetooth side finds peers in range, announces itself so they can see you,
and carries the public conversation. It reconnects on its own when a link drops,
and keeps announcing so you do not quietly age out of everyone's peer list.

The location-channel side joins any `#geohash` room, shows who is present, and
sends and receives messages there. There is a world map for finding rooms that
have people in them, which is more useful than it sounds: most cells are empty,
and guessing geohashes by hand is miserable.

Pictures that people post as links can be viewed in place — real graphics in
kitty, colour half-blocks everywhere else. Pictures sent over Bluetooth itself
are received and displayed too.

An asterisk after a name means that person is chatting into the cell from
somewhere else. `▣` marks a line carrying an image. On a private message you
sent, `✓` means it reached the other device and `✓✓` means they have it on
screen.

## Requirements

Rust, and for the mesh, BlueZ with a working Bluetooth adapter. Location
channels need only an internet connection, so the client is useful even with the
radio switched off.

Linux only for now. It should port to macOS without much trouble — the
Bluetooth layer goes through btleplug, which supports it — but nobody has tried.

## Installing

On Arch:

```
cd packaging && makepkg -si
```

Anywhere else:

```
cargo install --path .
```

## Using it

```
bitmancer
```

Two diagnostics, both worth knowing about before you start filing bugs:

```
bitmancer --doctor            # is Bluetooth working, and is anyone in range?
bitmancer --geo-doctor 9q     # can we reach the relays a channel lives on?
```

`--doctor` exists because "it says scanning forever" has two completely
different causes — a broken Bluetooth stack, or simply nobody nearby — and the
scanning screen cannot tell you which. It lists every BLE advertiser it can see
and flags the ones running BitChat:

```
  [ok]   adapter: hci0 (usb:v1D6Bp0246d0557)
  Scanning 10s for BLE advertisers...
  BITCHAT 55:C5:BE:E9:65:EB   -72 dBm  Pixel 10 Pro XL  <-- a BitChat peer
          2C:32:6A:D1:01:4A   -56 dBm  AirPods Pro
  22 advertiser(s) seen, 1 running BitChat.
```

### Keys

| | |
|---|---|
| `Tab` | move between the sidebar, the log and the input box |
| wheel | scroll the log, wherever the focus is |
| `m` | world map (also `/map`) |
| `i` | view the newest image in this conversation (also `/img`) |
| `:name:` | becomes an emoji as you close the colon; `Tab` takes a suggestion |
| `Ctrl+C` | quit |
| `Esc` | dismiss the connection overlay; the client works fine offline |

Pasting several lines at once puts all of it in the compose box and sends none of
it — the line breaks become spaces, and nothing goes out until you press `Enter`.

The mouse wheel costs the terminal's own click-drag selection, because a program
cannot both read the wheel and leave the mouse to the terminal. **`Shift`+drag
usually reaches the selection underneath** — that is a terminal feature rather
than something this client controls, and it works in most but not all of them.
The trade is deliberate: on the alternate screen there is no scrollback to select
from anyway, so what selection loses is one visible frame and what the wheel
gains is the whole log.

### Commands

| | |
|---|---|
| `/geo #9q8yy` | join a location channel |
| `/geo list`, `/geo off` | list joined channels, leave the current one |
| `/map` | world map |
| `/img [n]` | view the newest image link, or the nth one back |
| `/dm <nick> <message>` | private message, encrypted end to end |
| `/mesh` | the network around you: links, who forwards, whether you bridge |
| `/fav <nick>`, `/unfav <nick>` | exchange Nostr addresses; `/fav` alone lists |
| `/send <path>` | put a file on the mesh, fragmented |
| `/verify me`, `/verify <url>` | show your card, or read someone else's |
| `/mailbox on\|off\|status` | hold mail for peers who are not here |
| `/gateway on\|off` | share this machine's internet with the mesh |
| `/block <nick>`, `/unblock <nick>` | refuse a peer's traffic; `/block` alone lists |
| `/wipe confirm` | destroy the stored identity and quit |
| `/name <nick>` | change your nickname and re-announce |
| `/online` | who is on the mesh |
| `/status` | link state, peer count, your identity |
| `/debug` | trace every packet received |
| `/help` | the rest |

### The map

`m` opens it on the whole world, with cells lit by how many people are in them.
Arrows move, `+`/`-` zoom, `Esc` or `Backspace` steps back out, `q` closes.
`Enter` does the obvious thing: on a cell that is a real channel it takes you
in, and where no channel can exist it zooms instead. The key bar always says
which of the two it is about to do.

Geohash precision decides how big a room is: 2 characters is a region, 4 a
province, 5 a city, 6 a neighbourhood, 7 a block, 8 a building. Only 2, 4 and 5
tend to have anyone in them.

**Wiping is two steps and honest about its limits.** `/wipe` explains what it
destroys; `/wipe confirm` does it. The state file is overwritten before it is
unlinked, so the keys are not left in the free list for a casual read — but on a
copy-on-write filesystem or an SSD doing wear levelling the original blocks can
survive somewhere no userspace program can reach. It removes the keys from the
filesystem's view. That is worth having and it is not the same as physical
erasure, so it is not described as one.

## Some deliberate choices

**Images are never fetched until you ask for one.** A chat line is written by a
stranger, and quietly requesting the URL in it hands that stranger your IP
address and a timestamp — on a network whose entire point is not doing that.
Finding links costs nothing because it is just text inspection, so lines get
marked and indexed for free; a request only leaves your machine when you open
an image, and the viewer names the host before you commit. Downloads are capped
at 8 MB with a timeout and a content-type check.

**Presence is only announced in large cells.** Location channels go down to
building size, but the client only broadcasts that it is present in region,
province and city cells. Beaconing a building-sized cell every minute would be
publishing your street address. This matches what the phone app does.

**Every location channel gets its own identity.** Channel keys are derived per
geohash from a single device seed, so what you say in one place cannot be linked
to another, and none of it links back to your Bluetooth identity.

**Joining a channel shows an hour of history, and says where it ends.** Relays
are not supposed to store these messages at all, but many do, and without a
cutoff you get handed a wall of dead conversation that looks live. History is
bounded to an hour and separated from the present with a `─── live ───` line.

## What does not work yet

Using someone else's gateway. This client can *be* one — `/gateway on` publishes
geohash events for mesh-only peers nearby and hands back what the relays send —
but it cannot yet be the peer on the other end of that arrangement.

Filling in the neighbour list other clients draw their maps from. We read the
announce TLV that carries it and cannot write our own, because an announce has to
stay under 100 bytes to survive the signature check and a full-length nickname
leaves two bytes spare. Our own view of the mesh is unaffected; the loss is
appearing in other people's.

Private messages to a peer who is out of Bluetooth range go over Nostr, and that
half has never been tested against another implementation.

## Building on it

`cargo test` runs the suite (653 at the time of writing). Most of it is protocol
work that can be checked without a radio: the mesh tests drive two clients
against each other, and the frame codec carries upstream's own malformed-packet
cases.

[NOTES.md](NOTES.md) collects the wire-format details that are easy to get
wrong. Worth a read before touching anything under `src/protocol.rs`,
`src/announce.rs` or `src/nostr/`, because the failure mode for most of them is
that the other side ignores you without an error.

## Credit

The BitChat protocol and its reference implementation are by
[permissionlesstech](https://github.com/permissionlesstech/bitchat), released
into the public domain. Everything bitmancer knows about the wire format was
read out of that source.

This started as a fork of
[vaibhav-mattoo/bitchat-tui](https://github.com/vaibhav-mattoo/bitchat-tui),
whose protocol layer targeted a 2025 version of BitChat that has since been
replaced wholesale. That layer has been rewritten; the location channels, map
and image support are new.

`assets/online_relays_gps.csv` is the relay directory from the upstream project.
Both clients have to pick the same relays for a geohash or they never meet, so
it is vendored rather than reimplemented.

MIT. See [LICENSE](LICENSE).
