// tests/terminal_restore.rs
//
// Does the terminal actually come back? The unit test beside `TerminalGuard`
// asserts `restore()` is idempotent, which is the property the guard rests on
// but not the claim anyone cares about. The claim is that a process which takes
// the terminal over and then dies badly leaves it usable — and that cannot be
// checked without a terminal.
//
// So: allocate a real pty with `script(1)`, run a child that drives the real
// `init()` and `TerminalGuard`, and read the pty's termios back afterwards with
// `stty -a`. `echo`/`icanon` present means the terminal was handed back; `-echo`
// `-icanon` means it was not.
//
// `panic_unguarded` is the reason the rest means anything. It reproduces the
// original bug — no guard, no hook — and must leave the pty in raw mode. If that
// one ever starts passing, this file has stopped measuring anything and the
// other assertions are worthless.
//
// The child is this same test binary, re-executed with BITMANCER_PTY_MODE set and
// filtered to `pty_child_entrypoint`. That way the code under test is the real
// `bitmancer::tui::tui`, not a copy that can drift away from it.
//
// One honest limit. Under `cargo test` the child runs inside libtest, which has
// installed its own panic hook, so `TerminalGuard::new()` chains in front of that
// rather than in front of the default one, and libtest catches the unwind. The
// hook — the half that restores the terminal before the message is printed — is
// exercised exactly as it is in `main`. `Drop` is not, because libtest does not
// let the unwind reach it. That makes this a test of the hook, and the negative
// control keeps it honest: libtest's own hook restores no terminals, which is why
// `panic_unguarded` still fails the way the real bug did.

use std::process::Command;

const MODE_VAR: &str = "BITMANCER_PTY_MODE";

/// Whether a pty can be allocated here at all. Absent `script(1)` the checks
/// below cannot run, and a test that silently reports success on a machine where
/// it never ran is worse than one that says why it skipped.
fn pty_available() -> bool {
    Command::new("script")
        .args(["-q", "-c", "true", "/dev/null"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

struct PtyRun {
    /// Everything the pty saw, escape sequences included.
    transcript: String,
    /// `stty -a` sampled after the child exited.
    termios: String,
}

impl PtyRun {
    fn raw_mode_left_on(&self) -> bool {
        // `stty -a` prints the negated form when a flag is off. Look for the
        // explicit negatives rather than the absence of the positives, so a
        // truncated or unexpected sample cannot read as "restored".
        let off = |flag: &str| {
            self.termios
                .split(|c: char| c.is_whitespace() || c == ';')
                .any(|word| word == format!("-{flag}"))
        };
        off("echo") || off("icanon")
    }

    fn panicked(&self) -> bool {
        self.transcript.contains("panicked")
    }

    /// Where the alternate screen was left, relative to the panic message. The
    /// message is only readable if it was written after the switch back.
    fn panic_message_was_visible(&self) -> bool {
        let leave = self.transcript.find("\x1b[?1049l");
        let message = self.transcript.find("panicked");
        match (leave, message) {
            (Some(leave), Some(message)) => message > leave,
            _ => false,
        }
    }
}

/// Distinguishes concurrent runs of this helper. The mode alone is not enough:
/// libtest runs these in parallel within one process, so two tests driving the
/// same mode would name the same transcript and overwrite each other's — a
/// failure that appears only under parallelism and only once a mode is used
/// twice. It was not hypothetical. Extending this file with a second
/// `panic_guarded` check produced exactly that, and it failed while
/// `--test-threads=1` passed.
static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Fresh transcript and termios paths for one run. Separated from the run so the
/// uniqueness can be asserted directly rather than inferred from a race.
fn paths_for(mode: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir();
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stamp = format!("{}-{run}", std::process::id());
    (
        dir.join(format!("bitmancer-pty-{mode}-{stamp}.log")),
        dir.join(format!("bitmancer-tty-{mode}-{stamp}.txt")),
    )
}

fn run_in_pty(mode: &str) -> PtyRun {
    let exe = std::env::current_exe().expect("the test binary must know its own path");
    let (transcript, termios) = paths_for(mode);

    // Run the child, then sample the pty it was using. Both happen inside the
    // one `script` invocation because the pty does not outlive it.
    let script = format!(
        "{exe} --exact pty_child_entrypoint --nocapture; stty -a > {termios} 2>&1",
        exe = exe.display(),
        termios = termios.display(),
    );

    let status = Command::new("script")
        .args(["-q", "-c", &script])
        .arg(&transcript)
        .env(MODE_VAR, mode)
        // `script` mirrors the pty to its own stdout as well as to the
        // transcript. Left connected, the child's libtest output — including a
        // "test result: FAILED" from the mode that is *supposed* to panic — lands
        // in this run's output and reads as a real failure. The transcript file is
        // written either way, and that is what gets inspected.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("script(1) should be runnable");
    assert!(status.success() || status.code().is_some(), "script did not run");

    let run = PtyRun {
        transcript: std::fs::read_to_string(&transcript).unwrap_or_default(),
        termios: std::fs::read_to_string(&termios).unwrap_or_default(),
    };
    let _ = std::fs::remove_file(&transcript);
    let _ = std::fs::remove_file(&termios);

    assert!(
        !run.termios.is_empty(),
        "stty produced nothing for mode {mode}; the pty sample is the measurement, \
         so an empty one means this test proved nothing"
    );
    run
}

/// The child half. A no-op unless re-executed with `BITMANCER_PTY_MODE` set,
/// which is why it is safe to leave in the normal suite.
#[test]
fn pty_child_entrypoint() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };

    use bitmancer::tui::tui::{init, TerminalGuard};

    match mode.as_str() {
        // main.rs before 90296c6: the terminal is taken and nothing gives it back.
        "panic_unguarded" => {
            let _terminal = init().expect("init");
            panic!("the original bug: no guard, no hook");
        }
        "panic_guarded" => {
            let _terminal = init().expect("init");
            let _guard = TerminalGuard::new();
            panic!("a panic with the guard held");
        }
        // The other half of the original bug: one of the four `?` sites inside
        // the loop returning past a `restore()` that sat after it.
        "early_return_guarded" => {
            fn run() -> std::io::Result<()> {
                let _terminal = init()?;
                let _guard = TerminalGuard::new();
                Err(std::io::Error::other("the draw call failed"))
            }
            let _ = run();
        }
        "clean_guarded" => {
            let _terminal = init().expect("init");
            let _guard = TerminalGuard::new();
        }
        other => panic!("unknown pty mode: {other}"),
    }
}

#[test]
fn an_unguarded_panic_really_does_strand_the_terminal() {
    // The negative control. Everything else in this file is only evidence
    // because this fails, so if it ever goes green the others stop counting.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let run = run_in_pty("panic_unguarded");

    assert!(run.panicked(), "the child was supposed to panic");
    assert!(
        run.raw_mode_left_on(),
        "without the guard the pty must be left in raw mode — if this passes, \
         this file is no longer measuring anything.\nstty: {}",
        run.termios
    );
    assert!(
        !run.panic_message_was_visible(),
        "and the message must be lost in the alternate screen, which is the \
         other half of the bug"
    );
}

#[test]
fn a_panic_hands_the_terminal_back_and_the_message_is_readable() {
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let run = run_in_pty("panic_guarded");

    assert!(run.panicked(), "the child was supposed to panic");
    assert!(
        !run.raw_mode_left_on(),
        "the guard must restore the terminal on a panic.\nstty: {}",
        run.termios
    );
    assert!(
        run.panic_message_was_visible(),
        "the message must be written after the alternate screen is left, or the \
         user reads nothing — that is what the chained hook buys over Drop alone"
    );
}

#[test]
fn an_early_return_hands_the_terminal_back() {
    // The failure that actually shipped: `restore()` existed, after the loop,
    // and every `?` inside the loop returned straight past it.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let run = run_in_pty("early_return_guarded");

    assert!(!run.panicked(), "this path returns an error, it does not panic");
    assert!(
        !run.raw_mode_left_on(),
        "an error return must not strand the terminal.\nstty: {}",
        run.termios
    );
}

#[test]
fn an_ordinary_quit_still_hands_the_terminal_back() {
    // The guard must not have broken the path that already worked.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let run = run_in_pty("clean_guarded");

    assert!(!run.panicked());
    assert!(
        !run.raw_mode_left_on(),
        "a clean exit must leave the terminal usable.\nstty: {}",
        run.termios
    );
}

#[test]
fn every_run_gets_its_own_transcript_even_on_one_mode() {
    // The deterministic guard, and the reason it is not a race.
    //
    // The path was keyed on mode and process id alone, so two tests driving the
    // same mode overwrote each other's transcript and the loser read nothing. I
    // first pinned that by racing two threads on one mode — but with the fix
    // reverted that caught it in only two runs out of three, because which
    // caller loses is up to the scheduler. A guard that is right most of the time
    // is how a flaky test gets introduced while fixing one.
    //
    // So assert the invariant instead: same mode, different paths, no processes
    // and no timing involved.
    let (first_log, first_tty) = paths_for("panic_guarded");
    let (second_log, second_tty) = paths_for("panic_guarded");

    assert_ne!(
        first_log, second_log,
        "two runs of one mode must not share a transcript path"
    );
    assert_ne!(
        first_tty, second_tty,
        "two runs of one mode must not share a termios path"
    );
}

#[test]
fn two_concurrent_runs_on_one_mode_both_survive() {
    // The realistic exercise alongside the invariant above: the actual scenario
    // that broke, run for real. Not the primary guard — see that test for why —
    // but it is the shape a future extension of this file will take, and it costs
    // one more pty.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }

    let runs: Vec<_> = (0..2)
        .map(|_| std::thread::spawn(|| run_in_pty("panic_guarded")))
        .collect();

    for (index, handle) in runs.into_iter().enumerate() {
        let run = handle.join().expect("a pty run must not panic in its thread");
        assert!(run.panicked(), "concurrent run {index} lost its transcript");
        assert!(
            !run.raw_mode_left_on(),
            "concurrent run {index} must still have restored the terminal.\nstty: {}",
            run.termios
        );
    }
}

/// Every private mode `init` turns on, `restore` must turn back off.
///
/// `restore`'s own comment says it "undoes each mode set by `init`". That was a
/// claim about a list someone has to keep in step by hand, and the two are
/// eleven lines apart in the same file — which is exactly the distance at which
/// a fourth mode gets added to one and not the other. Leaving a mode on outlives
/// the process, which is the whole reason `90296c6` exists.
///
/// The check derives the modes from the transcript rather than naming them, so
/// it cannot go stale: whatever `init` asks for is what `restore` is held to.
/// That matters more than it looks, because `EnableMouseCapture` is not one mode
/// — crossterm expands it to five (1000, 1002, 1003, 1006, 1015), and the
/// assertions elsewhere in this suite name only 1006.
fn private_modes(transcript: &str) -> (Vec<String>, Vec<String>) {
    let chars: Vec<char> = transcript.chars().collect();
    let (mut set, mut unset) = (Vec::new(), Vec::new());
    let mut index = 0;
    while index < chars.len() {
        // A private mode is ESC [ ? <digits> then 'h' to set or 'l' to reset.
        if chars[index] == '\x1b'
            && index + 2 < chars.len()
            && chars[index + 1] == '['
            && chars[index + 2] == '?'
        {
            let mut cursor = index + 3;
            let mut digits = String::new();
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                digits.push(chars[cursor]);
                cursor += 1;
            }
            if cursor < chars.len() && !digits.is_empty() {
                match chars[cursor] {
                    'h' => set.push(digits),
                    'l' => unset.push(digits),
                    _ => {}
                }
            }
            index = cursor;
        } else {
            index += 1;
        }
    }
    set.sort();
    set.dedup();
    unset.sort();
    unset.dedup();
    (set, unset)
}

#[test]
fn every_mode_the_client_turns_on_is_turned_back_off() {
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let run = run_in_pty("clean_guarded");
    let (set, unset) = private_modes(&run.transcript);

    // Guards against the vacuous pass. A transcript with no modes in it would
    // satisfy the pairing below completely, and that is the state this test
    // would be in if `init` silently stopped running. Naming the two rather than
    // asserting a count, because the count is an implementation choice that can
    // legitimately change while these two cannot: 1049 is the alternate screen
    // and 2004 is bracketed paste, and `init` is defined by setting them.
    assert!(
        set.contains(&"1049".to_string()) && set.contains(&"2004".to_string()),
        "the alternate screen and bracketed paste must both have been requested, \
         or this transcript is not of a client that started.\nset: {set:?}"
    );

    let left_on: Vec<&String> = set.iter().filter(|mode| !unset.contains(mode)).collect();
    assert!(
        left_on.is_empty(),
        "these were turned on and never off, and they outlive the process: {left_on:?}\n\
         set:   {set:?}\nunset: {unset:?}"
    );
}
