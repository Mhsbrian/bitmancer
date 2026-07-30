// tests/terminal_events.rs
//
// The gap `5489bb6` names in its own commit message: the wheel and paste
// handlers are correct *given* crossterm delivers `Mouse` and `Paste` events,
// and its unit tests construct those events directly. That "given" is a
// terminal-protocol claim, and nothing had checked it.
//
// This checks it. Real escape sequences are written into a real pty — SGR mouse
// reports and a bracketed-paste wrapper — and the child, running with the modes
// `init()` actually sets, reads them back through `crossterm::event::read` and
// feeds them to the handlers. What the assertions look at is the state those
// handlers produced, so a break anywhere along the chain shows up: the mode not
// being enabled, crossterm not parsing the sequence, or the handler mishandling
// what it got.
//
// Companion to `terminal_restore.rs`, which covers the other direction — that
// the modes are given back. Same `script(1)` mechanism and the same rule about
// negative controls, deliberately not a second harness.

use std::io::Write;
use std::process::{Command, Stdio};

mod common;
use common::private_modes;

const CHILD_VAR: &str = "BITMANCER_EVENT_CHILD";

/// SGR mouse encoding, which is what crossterm asks the terminal for when mouse
/// capture goes on: `ESC [ < button ; column ; row M`. 64 is wheel up, 65 down.
const WHEEL_UP: &str = "\x1b[<64;10;10M";
const WHEEL_DOWN: &str = "\x1b[<65;10;10M";

/// A bracketed paste, which is what `EnableBracketedPaste` asks for. Everything
/// between the markers is content rather than keystrokes.
fn bracketed(text: &str) -> String {
    format!("\x1b[200~{text}\x1b[201~")
}

/// The sequences `init()` writes to ask the terminal for these modes. Asserting
/// on the *event* alone is not enough and a mutation proved it: because the test
/// injects the SGR and bracketed-paste bytes itself, crossterm parses them
/// whether or not the mode was ever requested, so removing `EnableMouseCapture`
/// or `EnableBracketedPaste` from `init()` left every assertion passing. These
/// check the half the injection cannot: that the terminal was actually asked.
const REQUEST_SGR_MOUSE: &str = "\x1b[?1006h";
const REQUEST_BRACKETED_PASTE: &str = "\x1b[?2004h";

fn pty_available() -> bool {
    Command::new("script")
        .args(["-q", "-c", "true", "/dev/null"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Runs the child in a pty with `input` written to it, and returns everything
/// the pty saw. The child reports state on stdout, so the transcript carries
/// both the escape sequences and the child's own findings.
fn drive(mode: &str, input: &str) -> String {
    static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let exe = std::env::current_exe().expect("the test binary must know its own path");
    let transcript = std::env::temp_dir().join(format!(
        "bitmancer-events-{mode}-{}-{run}.log",
        std::process::id()
    ));

    let script = format!("{exe} --exact event_child --nocapture", exe = exe.display());
    let mut child = Command::new("script")
        .args(["-q", "-c", &script])
        .arg(&transcript)
        .env(CHILD_VAR, mode)
        // As in terminal_restore.rs: `script` mirrors the pty to its own stdout,
        // and the child's libtest output would otherwise land in this run's.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .expect("script(1) should be runnable");

    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(input.as_bytes())
        .expect("writing to the pty");
    // Dropping stdin closes it, which the child sees as end of input and stops
    // waiting on.
    drop(child.stdin.take());
    let _ = child.wait();

    let transcript_text = std::fs::read_to_string(&transcript).unwrap_or_default();
    let _ = std::fs::remove_file(&transcript);

    assert!(
        !transcript_text.is_empty(),
        "the pty transcript for {mode} is empty; it is the measurement, so an \
         empty one means this test proved nothing"
    );
    transcript_text
}

/// The child. A no-op unless re-executed with the mode set, so it is harmless in
/// an ordinary run.
#[test]
fn event_child() {
    let Ok(mode) = std::env::var(CHILD_VAR) else {
        return;
    };

    use bitmancer::tui::app::App;
    use bitmancer::tui::event::{handle_mouse_event, handle_paste_event};
    use bitmancer::tui::tui::{init, init_with, TerminalGuard};
    use crossterm::event::{self, Event};

    // `nocapture` is the config's `mouse_capture = false` taken all the way to a
    // real terminal. Everything else goes through `init()` exactly as before.
    let _terminal = if mode == "nocapture" {
        init_with(false).expect("init_with")
    } else {
        init().expect("init")
    };
    let _guard = TerminalGuard::new();
    let mut app = App::new_with_nickname("tester".to_string());

    // Give the log something to scroll. The wheel is clamped at both ends, so
    // with an empty log an upward notch is indistinguishable from a dropped one.
    for index in 0..200 {
        app.add_channel_line(bitmancer::tui::app::IncomingLine {
            channel: "#public".to_string(),
            sender: "someone".to_string(),
            epoch: chrono::Local::now().timestamp() - (200 - index),
            content: format!("line {index}"),
        });
    }
    app.message_viewport_height = 10;
    let scroll_before = app.msg_scroll;

    // Read what arrives, hand each event to the same function main.rs calls, and
    // stop when the input runs out.
    while event::poll(std::time::Duration::from_millis(500)).unwrap_or(false) {
        match event::read() {
            Ok(Event::Mouse(mouse)) => {
                println!("EVENT mouse {:?}", mouse.kind);
                handle_mouse_event(&mut app, mouse);
            }
            Ok(Event::Paste(pasted)) => {
                println!("EVENT paste {pasted:?}");
                handle_paste_event(&mut app, &pasted);
            }
            Ok(Event::Key(_)) => {}
            Ok(_) => {}
            Err(_) => break,
        }
    }

    match mode.as_str() {
        "wheel" => {
            println!(
                "RESULT scroll_before={scroll_before} scroll_after={}",
                app.msg_scroll
            );
        }
        "paste" => {
            println!("RESULT compose={:?}", app.input.value());
        }
        "nocapture" => {
            println!("RESULT scroll_after={}", app.msg_scroll);
        }
        other => println!("RESULT unknown-mode={other}"),
    }
}

#[test]
fn a_wheel_notch_from_a_real_terminal_scrolls_the_log() {
    // The whole chain: SGR bytes on the wire, mouse capture on because `init()`
    // set it, crossterm parsing them, and `handle_mouse_event` moving the log.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let transcript = drive("wheel", WHEEL_UP);

    assert!(
        transcript.contains(REQUEST_SGR_MOUSE),
        "init() must ask the terminal for SGR mouse reporting; without that a real
         wheel never produces these bytes at all.\n{transcript}"
    );
    assert!(
        transcript.contains("EVENT mouse ScrollUp"),
        "the terminal's wheel report must reach crossterm as ScrollUp — if this \
         fails, mouse capture is not on or the sequence is not being parsed.\n{transcript}"
    );

    let (before, after) = scroll_pair(&transcript);
    assert_ne!(
        before, after,
        "a wheel notch must move the log; the handler is reached but did \
         nothing.\n{transcript}"
    );
}

#[test]
fn the_wheel_is_clamped_at_the_live_end() {
    // Scrolling down from the bottom must be inert rather than running the
    // offset past the end. The negative case for the test above: it proves the
    // scroll assertion is about the wheel's direction and not about any event
    // moving the log.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let transcript = drive("wheel", WHEEL_DOWN);

    assert!(
        transcript.contains("EVENT mouse ScrollDown"),
        "the down notch must arrive too.\n{transcript}"
    );
    let (before, after) = scroll_pair(&transcript);
    assert_eq!(
        before, after,
        "the log starts at the live end, so a downward notch has nowhere to go \
         and must leave the offset alone.\n{transcript}"
    );
}

#[test]
fn a_multi_line_paste_arrives_whole_and_is_not_sent() {
    // The dangerous one. Without bracketed paste each embedded return fires
    // Enter and sends half a message; with it the whole paste lands in the
    // compose box and nothing goes out until the user presses Enter.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }
    let transcript = drive("paste", &bracketed("first line\r\nsecond line"));

    assert!(
        transcript.contains(REQUEST_BRACKETED_PASTE),
        "init() must ask the terminal for bracketed paste; without that a real
         paste arrives as keystrokes and each return sends a partial line.\n{transcript}"
    );
    assert!(
        transcript.contains("EVENT paste"),
        "the paste must arrive as a Paste event rather than as keystrokes — if \
         this fails, bracketed paste is not enabled.\n{transcript}"
    );

    let compose = compose_value(&transcript);
    assert!(
        compose.contains("first line"),
        "the first line must be in the box: {compose:?}"
    );
    assert!(
        compose.contains("second line"),
        "and so must the second, which is the half that used to be sent \
         separately: {compose:?}"
    );
    assert!(
        !compose.contains('\n') && !compose.contains('\r'),
        "newlines fold to spaces, because the wire format has no multi-line \
         message: {compose:?}"
    );
}

/// Pulls `scroll_before=N scroll_after=M` out of the child's report.
fn scroll_pair(transcript: &str) -> (usize, usize) {
    let line = transcript
        .lines()
        .find(|line| line.contains("RESULT scroll_before="))
        .unwrap_or_else(|| panic!("the child reported no scroll state:\n{transcript}"));
    let number = |key: &str| -> usize {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("no {key} in {line:?}"))
    };
    (number("scroll_before="), number("scroll_after="))
}

/// Pulls the debug-quoted compose value out of the child's report.
fn compose_value(transcript: &str) -> String {
    let line = transcript
        .lines()
        .find(|line| line.contains("RESULT compose="))
        .unwrap_or_else(|| panic!("the child reported no compose state:\n{transcript}"));
    let quoted = line
        .split_once("compose=")
        .map(|(_, rest)| rest.trim())
        .unwrap_or_default();
    quoted.trim_matches('"').to_string()
}

#[test]
fn mouse_capture_false_does_not_ask_the_terminal_for_the_mouse() {
    // The config setting, driven to a real terminal rather than to a boolean.
    //
    // Without this, `init_with` could ignore its argument entirely and every
    // test still passed — checked by mutation, and it did. That is the same
    // shape as this file's own first version, where removing
    // `EnableMouseCapture` from `init()` left all four tests green because the
    // SGR bytes were injected regardless of whether the terminal had been asked
    // for them. A setting wired to nothing is worse than an absent setting: it
    // is documented, so someone will rely on it.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }

    // Derived rather than named, and the first version of this test was wrong
    // for exactly the reason `terminal_restore.rs` turned up: it asserted only
    // that 1006 was absent. `EnableMouseCapture` is five modes, and 1006 is the
    // SGR *encoding* — the ones that actually take click-drag selection are
    // 1000, 1002 and 1003. Checking the encoding while claiming to check the
    // capture would have passed against an `init_with` that dropped 1006 alone
    // and left the selection just as gone, which is the entire thing the setting
    // exists to give back.
    let (off_modes, _) = private_modes(&drive("nocapture", WHEEL_UP));
    let enabled = drive("wheel", WHEEL_UP);
    let (on_modes, _) = private_modes(&enabled);

    // The whole set, not a difference. The first version of this asserted that
    // nothing in `on_modes - off_modes` appeared in `off_modes`, which is
    // impossible by construction — a set difference never intersects the set it
    // was subtracted from — so it could not fail and a mutation proved it: an
    // `init_with` that dropped 1006 alone while still asking for 1000, 1002,
    // 1003 and 1015 passed, with the selection just as gone.
    //
    // 1049 and 2004 are named rather than derived because they are what `init`
    // is *defined by* — the alternate screen and bracketed paste, neither of
    // which has anything to do with the mouse. Everything else is the mouse, and
    // this says there is none of it, without needing to know how many modes
    // crossterm expands `EnableMouseCapture` into.
    assert_eq!(
        off_modes,
        vec!["1049".to_string(), "2004".to_string()],
        "mouse_capture = false must ask for the alternate screen and bracketed \
         paste and nothing else; anything extra here is a mouse mode, and the \
         selection this setting exists to hand back is still taken"
    );

    // The control. Capture on must ask for strictly more, or the assertion above
    // would be satisfied by an `init_with` that never enabled the mouse at all
    // and the setting would be indistinguishable from doing nothing.
    let capture_adds: Vec<&String> = on_modes
        .iter()
        .filter(|mode| !off_modes.contains(mode))
        .collect();
    assert!(
        !capture_adds.is_empty(),
        "capture on must ask for something capture off does not, or this test \
         cannot tell the two apart.\n{enabled}"
    );
}

#[test]
fn bracketed_paste_survives_turning_the_mouse_off() {
    // The two modes are set by the same `execute!` and it would be easy to drop
    // both while meaning to drop one. Paste is the half that stops a multi-line
    // paste sending itself a line at a time, so losing it silently is the more
    // expensive mistake of the two.
    if !pty_available() {
        eprintln!("skipping: script(1) is unavailable, so no pty can be allocated");
        return;
    }

    let transcript = drive("nocapture", WHEEL_UP);
    assert!(
        transcript.contains(REQUEST_BRACKETED_PASTE),
        "turning the mouse off must not take bracketed paste with it.\n{transcript}"
    );
}
