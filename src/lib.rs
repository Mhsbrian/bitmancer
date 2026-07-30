// src/lib.rs
//
// Everything except the UI loop, exposed as a library so it can be driven from
// outside the binary.
//
// The crate was a bin and nothing else, which meant `tests/` could not `use
// bitmancer::…` at all: the only integration fixture in the tree is reached with
// `include_str!` from inside a unit test, because there was no other way to get
// at it. Unit tests inside `src/` were the only kind of test possible here, and
// the modules with no test at all were exactly the ones a unit test cannot reach
// comfortably — the terminal setup, the relay pool, the main loop.
//
// The module list is the same list `main.rs` used to declare. Nothing moved; the
// declarations just live somewhere both targets can see them.

pub mod announce;
pub mod commands;
pub mod compression;
pub mod courier;
pub mod data_structures;
pub mod discovery;
pub mod favorites;
pub mod file_packet;
pub mod fragment;
pub mod gateway;
pub mod geo;
pub mod geohash;
pub mod mailbox;
pub mod media;
pub mod mesh;
pub mod noise_payload;
pub mod noise_protocol;
pub mod noise_session;
pub mod nostr;
pub mod outbox;
pub mod peer_id;
pub mod persistence;
pub mod protocol;
pub mod relay;
pub mod topology;
pub mod transport;
pub mod tui;
pub mod verification;
