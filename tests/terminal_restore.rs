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

fn run_in_pty(mode: &str) -> PtyRun {
    let exe = std::env::current_exe().expect("the test binary must know its own path");
    let dir = std::env::temp_dir();
    let transcript = dir.join(format!("bitmancer-pty-{mode}-{}.log", std::process::id()));
    let termios = dir.join(format!("bitmancer-tty-{mode}-{}.txt", std::process::id()));

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
