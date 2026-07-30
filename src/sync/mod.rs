// src/sync/mod.rs
//
// Gossip sync: the mechanism upstream uses to reconcile public history between
// peers that have been apart. Each side advertises what it holds as a compact
// probabilistic filter, and the other side returns only what the filter does not
// claim. See `bitchat/Sync/` upstream and WHITEPAPER.md section 6.3.
//
// We defined `RequestSync = 0x21` in `protocol.rs` and then dropped every one of
// these packets on the floor, which made this client a hole in every mesh it
// joined: the phones nearby ask several times a minute and heal each other from
// the answers, and we were the peer that never replied.
//
// Everything in here is a port with the upstream symbol named at each site. The
// dominant failure mode for this repo applies with full force — get a detail
// wrong and the peer ignores us without erroring — so the codec is pinned by
// hand-computed vectors rather than round-trips. A consistently wrong codec
// round-trips perfectly; NOTES.md already learned that from `npub`.

pub mod gcs;
pub mod packet_id;
pub mod request;
pub mod type_flags;
