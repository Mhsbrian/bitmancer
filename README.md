# bitmancer

A terminal client for [BitChat](https://github.com/permissionlesstech/bitchat) —
the serverless mesh chat that runs over Bluetooth Low Energy, plus its geohash
location channels carried over Nostr.

Two networks, one client:

- **Mesh** — public chat with whoever is in Bluetooth range. No internet, no
  servers, no accounts.
- **Location channels** — `#<geohash>` rooms shared with the phone app, carried
  over Nostr relays, with a world map to find them.

```
┌ C H A N N E L ──────────────────────────────────┐┌ N A V ────────────┐
│#9q  ·  33 here                                  ││ ▾ PUBLIC          │
└─────────────────────────────────────────────────┘│   public          │
┌ L O G ──────────────────────────────────────────┐│ ▾ CHANNELS        │
│04:41     anon5842   hello 6896                  ││▏  #9q             │
│04:44        6ix* ▣ look at this                 ││ ▾ PEOPLE          │
└─────────────────────────────────────────────────┘│   nerdetta        │
┌ → #9q ──────────────────────────────────────────┐│   huh?            │
│                                                 ││                   │
└─────────────────────────────────────────────────┘└───────────────────┘
 ⏎ send  /map world  /help  tab pane    geo 1  ·  mesh ◈ 4
```

## Install

```bash
cd packaging && makepkg -si     # Arch
cargo install --path .          # anywhere else
```

Needs BlueZ and a Bluetooth adapter for the mesh; location channels need only
an internet connection.

## Use

```bash
bitmancer                        # start
bitmancer --doctor               # is Bluetooth working, is anyone in range?
bitmancer --geo-doctor 9q        # can we reach the relays for a channel?
```

Inside:

| | |
|---|---|
| `/map` or `m` | world map of live location channels — arrows move, `⏎` enters, `+`/`-` zoom |
| `/geo #9q8yy` | join a location channel by geohash |
| `/img` or `i` | view an image someone linked (`▣` marks those lines) |
| `/online` | who is on the mesh |
| `/help` | everything else |

## Design notes

**Images are never fetched until you ask.** A chat line is written by a
stranger, and requesting the URL in it hands that stranger your IP address and a
timing signal — on a network whose whole point is not doing that. Links are
detected by inspecting text, which costs nothing; a request leaves the machine
only when you open one, and the viewer names the host first.

**Presence is only broadcast at coarse precision.** Location channels exist at
six sizes, from region down to a single building, but the client only announces
its presence in the region, province and city levels. Beaconing a
building-sized cell would broadcast where you are standing.

**Every location channel has its own identity.** Channel keys are derived per
geohash from one device seed, so activity in one place cannot be linked to
another, and none of it links back to your mesh identity.

## Credits

The BitChat protocol and its reference implementation are by
[permissionlesstech](https://github.com/permissionlesstech/bitchat), released
into the public domain. This client began as a fork of
[vaibhav-mattoo/bitchat-tui](https://github.com/vaibhav-mattoo/bitchat-tui)
(MIT) and has since had its protocol layer rewritten against the current
upstream wire format.

MIT — see [LICENSE](LICENSE).
