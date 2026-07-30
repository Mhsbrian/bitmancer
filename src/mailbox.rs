// src/mailbox.rs
//
// The shelf mail sits on while it waits to be collected.
//
// A courier network needs someone to hold things, and holding things is where
// the honesty lives: this is other people's data, on this machine's disk, and
// every constant below is a promise about how much and for how long.
//
// The quotas are upstream's, and one of them encodes a judgement worth keeping:
// a *verified* deposit — a peer whose announce we checked, but who is not a
// mutual favourite — never displaces a favourite's mail. When the shelf is full
// of mail from people we actually know, a stranger's deposit is refused rather
// than evicting the trusted mail to fit it. Open couriering is offered, but not
// at the cost of the thing it is offered alongside.
//
// It persists, because a mailbox that forgets on restart is not a mailbox. Mail
// lives 24 hours, so surviving a restart is most of what being reliable means
// here. That is a real cost — strangers' ciphertext, on disk, until it expires —
// so it is bounded in count and size, cleared by `/wipe`, and never enabled
// unless asked for.
//
// We hold and deliver. We do not spray copies onward, and that is deliberate
// rather than unfinished: spraying is how a *moving* courier compensates for
// never meeting the recipient, and this client usually does not move. Being
// reliably in one place is what we offer instead, so the copy budget is
// preserved and honoured but never spent.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::courier::{Envelope, MAX_LIFETIME_SECONDS, TAG_BYTES};

/// Total envelopes on the shelf.
pub const MAX_HELD: usize = 40;
/// Of which at most this many may be from peers who are not favourites, so a
/// crowd of strangers can be served without filling the shelf.
pub const MAX_VERIFIED_HELD: usize = 20;
pub const MAX_PER_FAVOURITE: usize = 5;
pub const MAX_PER_VERIFIED: usize = 2;
/// Slack on an accepted expiry, for clocks that disagree. Beyond the lifetime
/// plus this, a depositor is trying to pin storage for longer than the message
/// itself would have been retained.
pub const EXPIRY_SLACK_SECONDS: u64 = 60 * 60;

/// How much a depositor is trusted, which is what decides their share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A mutual favourite: someone we chose and who chose us.
    Favourite,
    /// A signature-verified announce from someone we have no relationship with.
    Verified,
}

impl Tier {
    fn quota(&self) -> usize {
        match self {
            Self::Favourite => MAX_PER_FAVOURITE,
            Self::Verified => MAX_PER_VERIFIED,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Favourite => "favourite",
            Self::Verified => "verified",
        }
    }
}

/// What happened to a deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deposit {
    /// On the shelf.
    Accepted,
    /// We already had this exact mail. Not an error: a depositor who never saw
    /// an acknowledgement retries, and that must not shelve it twice.
    AlreadyHeld,
    Refused(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub envelope: Envelope,
    /// Who handed it over, so a share can be counted. This is the one piece of
    /// metadata a courier unavoidably learns, and it is kept for exactly that.
    pub depositor: String,
    pub tier: Tier,
    pub stored_at_ms: u64,
}

#[derive(Debug, Default)]
pub struct Mailbox {
    /// Off until asked. Holding strangers' data is a decision.
    enabled: bool,
    /// Oldest first, which is the order eviction wants.
    held: Vec<Held>,
    path: Option<PathBuf>,
    /// Mail handed over since the client started, for the readout.
    pub delivered: usize,
}

impl Mailbox {
    /// Opens the shelf, restoring anything still in date.
    pub fn open(now_ms: u64) -> Self {
        Self::open_at(default_path(), now_ms)
    }

    pub fn open_at(path: Option<PathBuf>, now_ms: u64) -> Self {
        let mut mailbox = Self {
            path,
            ..Default::default()
        };
        mailbox.held = mailbox.read_from_disk();
        // Anything that expired while we were off is dropped on the way in,
        // rather than being loaded and then swept — the promise was 24 hours,
        // and a restart does not extend it.
        mailbox.held.retain(|item| !item.envelope.is_expired(now_ms));
        mailbox
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Turns the mailbox on or off, reporting how much mail was dropped.
    ///
    /// Switching off discards the shelf. Those deposits were accepted on a
    /// promise being withdrawn, and keeping them would be the worst of both: the
    /// senders believe the mail is somewhere, and we still have it.
    pub fn set_enabled(&mut self, enabled: bool) -> usize {
        self.enabled = enabled;
        if enabled {
            return 0;
        }
        let dropped = self.held.len();
        self.held.clear();
        self.save();
        dropped
    }

    /// Takes a deposit, or explains why not.
    pub fn accept(
        &mut self,
        envelope: Envelope,
        depositor: &str,
        tier: Tier,
        now_ms: u64,
    ) -> Deposit {
        if !self.enabled {
            return Deposit::Refused("not holding mail");
        }
        if envelope.is_expired(now_ms) {
            return Deposit::Refused("already expired");
        }
        // A depositor must not be able to reserve the shelf for longer than the
        // message would have been kept anyway.
        let latest = now_ms + (MAX_LIFETIME_SECONDS + EXPIRY_SLACK_SECONDS) * 1000;
        if envelope.expiry_ms > latest {
            return Deposit::Refused("wants holding for longer than we hold anything");
        }

        self.prune(now_ms);

        // The same mail, handed over again. Keep the larger copy budget: before
        // any spraying, a carry-only copy can legitimately arrive ahead of the
        // original that had a budget.
        let fingerprint = envelope.fingerprint();
        if let Some(existing) = self
            .held
            .iter_mut()
            .find(|item| item.envelope.fingerprint() == fingerprint)
        {
            existing.envelope.copies = existing.envelope.copies.max(envelope.copies);
            self.save();
            return Deposit::AlreadyHeld;
        }

        let theirs = self
            .held
            .iter()
            .filter(|item| item.depositor == depositor)
            .count();
        if theirs >= tier.quota() {
            return Deposit::Refused("this peer's share of the shelf is full");
        }
        if tier == Tier::Verified && self.verified_held() >= MAX_VERIFIED_HELD {
            return Deposit::Refused("no room left for mail from peers we do not know");
        }

        if self.held.len() >= MAX_HELD && !self.make_room(tier) {
            return Deposit::Refused("the shelf is full of favourites' mail");
        }

        self.held.push(Held {
            envelope,
            depositor: depositor.to_string(),
            tier,
            stored_at_ms: now_ms,
        });
        self.save();
        Deposit::Accepted
    }

    /// Frees one slot, or reports that it will not.
    ///
    /// Sheds a stranger's mail first, and refuses a stranger's deposit rather
    /// than evicting a favourite's: open couriering must not crowd out the mail
    /// of people we actually know.
    fn make_room(&mut self, incoming: Tier) -> bool {
        if let Some(victim) = self
            .held
            .iter()
            .position(|item| item.tier == Tier::Verified)
        {
            self.held.remove(victim);
            return true;
        }
        if incoming == Tier::Favourite && !self.held.is_empty() {
            self.held.remove(0);
            return true;
        }
        false
    }

    /// Hands over everything addressed to whoever these tags belong to.
    ///
    /// Removed as it is handed over: the recipient is here, so we are no longer
    /// the reason the message exists. Holding a copy afterwards would keep
    /// someone's mail on our disk for no purpose.
    pub fn collect(&mut self, tags: &[[u8; TAG_BYTES]]) -> Vec<Envelope> {
        let mut theirs = Vec::new();
        self.held.retain(|item| {
            if tags.contains(&item.envelope.recipient_tag) {
                theirs.push(item.envelope.clone());
                false
            } else {
                true
            }
        });
        if !theirs.is_empty() {
            self.delivered += theirs.len();
            self.save();
        }
        theirs
    }

    /// Drops anything past its deadline, reporting how much went.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.held.len();
        self.held.retain(|item| !item.envelope.is_expired(now_ms));
        let dropped = before - self.held.len();
        if dropped > 0 {
            self.save();
        }
        dropped
    }

    /// A line per depositor, for the readout. Never any content — there is none
    /// to show.
    pub fn summary(&self, now_ms: u64) -> Vec<String> {
        let mut by_depositor: HashMap<&str, (usize, Tier, u64)> = HashMap::new();
        for item in &self.held {
            let entry = by_depositor
                .entry(item.depositor.as_str())
                .or_insert((0, item.tier, u64::MAX));
            entry.0 += 1;
            entry.2 = entry.2.min(item.envelope.remaining_seconds(now_ms));
        }
        let mut lines: Vec<String> = by_depositor
            .into_iter()
            .map(|(depositor, (count, tier, soonest))| {
                format!(
                    "  {:<18} {count} item(s), {tier}, next expires in {}",
                    crate::peer_id::short_display(depositor),
                    format_remaining(soonest),
                    tier = tier.label(),
                )
            })
            .collect();
        lines.sort();
        lines
    }

    fn verified_held(&self) -> usize {
        self.held
            .iter()
            .filter(|item| item.tier == Tier::Verified)
            .count()
    }

    /// Forgets everything, on disk as well as in memory.
    pub fn wipe(&mut self) {
        self.held.clear();
        self.delivered = 0;
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }

    // MARK: - Persistence
    //
    // Stored as the wire bytes plus the little we add, rather than a second
    // serialisation of the envelope: there is already one authoritative encoding
    // and a parallel one would be a second thing to get wrong.

    fn save(&self) {
        let Some(path) = &self.path else { return };
        if self.held.is_empty() {
            let _ = fs::remove_file(path);
            return;
        }
        let rows: Vec<String> = self
            .held
            .iter()
            .filter_map(|item| {
                let wire = item.envelope.encode()?;
                Some(format!(
                    "{}\t{}\t{}\t{}",
                    hex::encode(wire),
                    item.depositor,
                    match item.tier {
                        Tier::Favourite => "favourite",
                        Tier::Verified => "verified",
                    },
                    item.stored_at_ms
                ))
            })
            .collect();
        let temporary = path.with_extension("tmp");
        if fs::write(&temporary, rows.join("\n")).is_ok() && fs::rename(&temporary, path).is_err() {
            let _ = fs::remove_file(&temporary);
        }
    }

    fn read_from_disk(&self) -> Vec<Held> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        let Ok(text) = fs::read_to_string(path) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|row| {
                let mut fields = row.split('\t');
                let envelope = Envelope::decode(&hex::decode(fields.next()?).ok()?)?;
                let depositor = fields.next()?.to_string();
                let tier = match fields.next()? {
                    "favourite" => Tier::Favourite,
                    "verified" => Tier::Verified,
                    _ => return None,
                };
                let stored_at_ms = fields.next()?.parse().ok()?;
                Some(Held {
                    envelope,
                    depositor,
                    tier,
                    stored_at_ms,
                })
            })
            .collect()
    }
}

fn format_remaining(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn default_path() -> Option<PathBuf> {
    let state = crate::persistence::get_state_file_path();
    Some(state.parent()?.join("mailbox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;
    const ALICE: &str = "aa11bb22cc33dd44";
    const STRANGER: &str = "ff99ee88dd77cc66";

    fn mail(tag: u8, content: u8) -> Envelope {
        Envelope::new(
            [tag; TAG_BYTES],
            NOW + 3_600_000,
            vec![content; 64],
            1,
            None,
        )
        .unwrap()
    }

    fn holding() -> Mailbox {
        let mut mailbox = Mailbox::open_at(None, NOW);
        mailbox.set_enabled(true);
        mailbox
    }

    #[test]
    fn nothing_is_held_until_asked() {
        // Other people's data on this disk is a decision, not a default.
        let mut idle = Mailbox::open_at(None, NOW);
        assert!(!idle.is_enabled());
        assert_eq!(
            idle.accept(mail(1, 1), ALICE, Tier::Favourite, NOW),
            Deposit::Refused("not holding mail")
        );
    }

    #[test]
    fn mail_goes_on_the_shelf_and_comes_off_for_its_recipient() {
        let mut mailbox = holding();
        assert_eq!(
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW),
            Deposit::Accepted
        );
        assert_eq!(mailbox.held_count(), 1);

        // Somebody else's tags collect nothing.
        assert!(mailbox.collect(&[[9; TAG_BYTES]]).is_empty());
        assert_eq!(mailbox.held_count(), 1, "and nothing is lost trying");

        let theirs = mailbox.collect(&[[1; TAG_BYTES]]);
        assert_eq!(theirs.len(), 1);
        assert_eq!(mailbox.held_count(), 0, "handed over, not kept");
        assert_eq!(mailbox.delivered, 1);
    }

    #[test]
    fn any_of_a_peers_candidate_tags_collects_their_mail() {
        // Tags rotate daily, so mail sealed yesterday must still be collectable
        // today — that is precisely the mail that has waited longest.
        let mut mailbox = holding();
        mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        let tags = [[7; TAG_BYTES], [1; TAG_BYTES], [8; TAG_BYTES]];
        assert_eq!(mailbox.collect(&tags).len(), 1);
    }

    #[test]
    fn the_same_mail_handed_over_twice_is_shelved_once() {
        // A depositor that never saw an acknowledgement retries. Ordinary.
        let mut mailbox = holding();
        assert_eq!(
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW),
            Deposit::Accepted
        );
        assert_eq!(
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW),
            Deposit::AlreadyHeld
        );
        assert_eq!(mailbox.held_count(), 1);
    }

    #[test]
    fn a_repeat_deposit_keeps_the_larger_copy_budget() {
        // Before any spraying, a carry-only copy can legitimately arrive ahead
        // of the original that had a budget.
        let mut mailbox = holding();
        let carry_only = mail(1, 1);
        let mut sprayable = mail(1, 1);
        sprayable.copies = 6;

        mailbox.accept(carry_only, ALICE, Tier::Favourite, NOW);
        mailbox.accept(sprayable, ALICE, Tier::Favourite, NOW);
        assert_eq!(mailbox.held[0].envelope.copies, 6);
    }

    #[test]
    fn expired_mail_is_refused_and_swept() {
        let mut mailbox = holding();
        let stale = Envelope::new([1; TAG_BYTES], NOW - 1, vec![1; 64], 1, None).unwrap();
        assert_eq!(
            mailbox.accept(stale, ALICE, Tier::Favourite, NOW),
            Deposit::Refused("already expired")
        );

        mailbox.accept(mail(2, 2), ALICE, Tier::Favourite, NOW);
        assert_eq!(mailbox.prune(NOW), 0, "not yet");
        assert_eq!(mailbox.prune(NOW + 3_600_001), 1, "and then it is");
        assert_eq!(mailbox.held_count(), 0);
    }

    #[test]
    fn nobody_can_reserve_the_shelf_indefinitely() {
        let mut mailbox = holding();
        let greedy = Envelope::new(
            [1; TAG_BYTES],
            NOW + (MAX_LIFETIME_SECONDS + EXPIRY_SLACK_SECONDS + 60) * 1000,
            vec![1; 64],
            1,
            None,
        )
        .unwrap();
        assert_eq!(
            mailbox.accept(greedy, ALICE, Tier::Favourite, NOW),
            Deposit::Refused("wants holding for longer than we hold anything")
        );
    }

    #[test]
    fn one_peer_cannot_take_more_than_its_share() {
        let mut mailbox = holding();
        for index in 0..MAX_PER_FAVOURITE {
            assert_eq!(
                mailbox.accept(mail(index as u8, index as u8), ALICE, Tier::Favourite, NOW),
                Deposit::Accepted
            );
        }
        assert_eq!(
            mailbox.accept(mail(99, 99), ALICE, Tier::Favourite, NOW),
            Deposit::Refused("this peer's share of the shelf is full")
        );
    }

    #[test]
    fn a_stranger_gets_a_smaller_share_than_a_favourite() {
        // Open couriering is offered, deliberately, and deliberately not on
        // equal terms.
        const { assert!(MAX_PER_VERIFIED < MAX_PER_FAVOURITE) };
        let mut mailbox = holding();
        for index in 0..MAX_PER_VERIFIED {
            assert_eq!(
                mailbox.accept(mail(index as u8, index as u8), STRANGER, Tier::Verified, NOW),
                Deposit::Accepted
            );
        }
        assert_eq!(
            mailbox.accept(mail(99, 99), STRANGER, Tier::Verified, NOW),
            Deposit::Refused("this peer's share of the shelf is full")
        );
    }

    #[test]
    fn strangers_together_cannot_fill_the_shelf() {
        let mut mailbox = holding();
        let mut content = 0u8;
        for peer in 0..(MAX_VERIFIED_HELD / MAX_PER_VERIFIED + 2) {
            for _ in 0..MAX_PER_VERIFIED {
                content = content.wrapping_add(1);
                mailbox.accept(
                    mail(content, content),
                    &format!("{peer:016x}"),
                    Tier::Verified,
                    NOW,
                );
            }
        }
        assert_eq!(mailbox.held_count(), MAX_VERIFIED_HELD);
        assert_eq!(
            mailbox.accept(mail(200, 200), "cccccccccccccccc", Tier::Verified, NOW),
            Deposit::Refused("no room left for mail from peers we do not know")
        );
    }

    #[test]
    fn a_strangers_deposit_never_displaces_a_favourites_mail() {
        // The judgement worth keeping: when the shelf is full of mail from
        // people we know, a stranger is refused rather than served at their cost.
        let mut mailbox = holding();
        let mut content = 0u8;
        for peer in 0..(MAX_HELD / MAX_PER_FAVOURITE) {
            for _ in 0..MAX_PER_FAVOURITE {
                content = content.wrapping_add(1);
                mailbox.accept(
                    mail(content, content),
                    &format!("fav{peer:013x}"),
                    Tier::Favourite,
                    NOW,
                );
            }
        }
        assert_eq!(mailbox.held_count(), MAX_HELD);
        assert_eq!(
            mailbox.accept(mail(250, 250), STRANGER, Tier::Verified, NOW),
            Deposit::Refused("the shelf is full of favourites' mail")
        );
        assert_eq!(mailbox.held_count(), MAX_HELD, "and nothing was lost");
    }

    #[test]
    fn a_full_shelf_sheds_a_strangers_mail_first() {
        let mut mailbox = holding();
        mailbox.accept(mail(1, 1), STRANGER, Tier::Verified, NOW);
        let mut content = 1u8;
        for peer in 0..(MAX_HELD / MAX_PER_FAVOURITE) {
            for _ in 0..MAX_PER_FAVOURITE {
                content = content.wrapping_add(1);
                if mailbox.held_count() >= MAX_HELD {
                    break;
                }
                mailbox.accept(
                    mail(content, content),
                    &format!("fav{peer:013x}"),
                    Tier::Favourite,
                    NOW,
                );
            }
        }
        assert_eq!(mailbox.held_count(), MAX_HELD);

        // One more favourite deposit: the stranger's item is the one that goes.
        content = content.wrapping_add(1);
        assert_eq!(
            mailbox.accept(mail(content, content), "fav9999999999999", Tier::Favourite, NOW),
            Deposit::Accepted
        );
        assert_eq!(mailbox.held_count(), MAX_HELD);
        assert!(
            mailbox.held.iter().all(|item| item.tier == Tier::Favourite),
            "the stranger's mail was shed, not a favourite's"
        );
    }

    #[test]
    fn switching_off_drops_the_shelf() {
        // Those deposits were accepted on a promise being withdrawn.
        let mut mailbox = holding();
        mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        mailbox.accept(mail(2, 2), ALICE, Tier::Favourite, NOW);
        assert_eq!(mailbox.set_enabled(false), 2);
        assert_eq!(mailbox.held_count(), 0);
    }

    #[test]
    fn the_summary_says_who_and_how_long_and_never_what() {
        let mut mailbox = holding();
        mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        mailbox.accept(mail(2, 2), STRANGER, Tier::Verified, NOW);
        let lines = mailbox.summary(NOW);
        assert_eq!(lines.len(), 2);
        let text = lines.join("\n");
        assert!(text.contains("favourite") && text.contains("verified"));
        assert!(text.contains("1h00m"), "how long is the useful part: {text}");
        // There is no content to leak, and the summary must not invent one.
        assert!(!text.contains("64") || !text.contains("ciphertext"));
    }

    #[test]
    fn remaining_time_reads_the_way_someone_would_say_it() {
        assert_eq!(format_remaining(45), "45s");
        assert_eq!(format_remaining(600), "10m");
        assert_eq!(format_remaining(3_600), "1h00m");
        assert_eq!(format_remaining(23 * 3600 + 59 * 60), "23h59m");
    }

    // MARK: - Persistence

    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitmancer-mailbox-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn mail_survives_a_restart() {
        // A mailbox that forgets on restart is not a mailbox. Mail lives a day,
        // so outlasting a process is most of what being reliable means here.
        let path = scratch("restart");
        {
            let mut mailbox = Mailbox::open_at(Some(path.clone()), NOW);
            mailbox.set_enabled(true);
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
            mailbox.accept(mail(2, 2), STRANGER, Tier::Verified, NOW);
        }
        let reopened = Mailbox::open_at(Some(path.clone()), NOW);
        assert_eq!(reopened.held_count(), 2);
        assert_eq!(reopened.held[0].depositor, ALICE);
        assert_eq!(reopened.held[0].tier, Tier::Favourite);
        assert_eq!(reopened.held[1].tier, Tier::Verified);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_restart_does_not_extend_the_promise() {
        // Twenty-four hours means twenty-four hours, not twenty-four hours of
        // uptime.
        let path = scratch("expiry");
        {
            let mut mailbox = Mailbox::open_at(Some(path.clone()), NOW);
            mailbox.set_enabled(true);
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        }
        let reopened = Mailbox::open_at(Some(path.clone()), NOW + 3_600_001);
        assert_eq!(reopened.held_count(), 0, "it expired while we were off");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_wipe_leaves_nothing_on_disk() {
        let path = scratch("wipe");
        let mut mailbox = Mailbox::open_at(Some(path.clone()), NOW);
        mailbox.set_enabled(true);
        mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        assert!(path.exists());
        mailbox.wipe();
        assert!(!path.exists(), "other people's mail must not outlive a wipe");
        assert_eq!(Mailbox::open_at(Some(path.clone()), NOW).held_count(), 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_empty_shelf_leaves_no_file_behind() {
        // Collecting the last item should not leave a record that there was mail.
        let path = scratch("empty");
        let mut mailbox = Mailbox::open_at(Some(path.clone()), NOW);
        mailbox.set_enabled(true);
        mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW);
        mailbox.collect(&[[1; TAG_BYTES]]);
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_shelf_is_not_fatal() {
        // Losing held mail costs a delivery. Refusing to start costs the client.
        let path = scratch("corrupt");
        fs::write(&path, "not\ta\tvalid\trow\nzzzz\tx\tfavourite\t1").unwrap();
        let mailbox = Mailbox::open_at(Some(path.clone()), NOW);
        assert_eq!(mailbox.held_count(), 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn no_home_directory_is_survivable() {
        let mut mailbox = Mailbox::open_at(None, NOW);
        mailbox.set_enabled(true);
        assert_eq!(
            mailbox.accept(mail(1, 1), ALICE, Tier::Favourite, NOW),
            Deposit::Accepted,
            "still works for this session"
        );
    }
}
