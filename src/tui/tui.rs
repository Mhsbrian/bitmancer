
// src/tui/tui.rs

use crossterm::{
    event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, stdout, Stdout};

/// A type alias for the terminal used in the application.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initializes the terminal for TUI rendering.
///
/// Mouse capture is on so the wheel can scroll the log. It costs the terminal's
/// own click-drag selection, which is a real trade — but in an alternate-screen
/// application there is no scrollback to select *from*, so what it costs is
/// selection over one visible frame and what it buys is a wheel that works.
/// `Shift`+drag reaches the terminal's selection underneath the capture in most
/// terminals; the README says so, because it is a terminal feature rather than
/// something this client can promise.
///
/// Bracketed paste is on so a pasted newline stays a newline. Without it a
/// multi-line paste arrives as individual keystrokes and every embedded return
/// sends the line — on a network where nothing can be unsent.
pub fn init() -> io::Result<Tui> {
    init_with(true)
}

/// `init` with the mouse capture made a choice rather than a given.
///
/// The capture buys the wheel and costs the terminal's own click-drag
/// selection, and `Shift`+drag reaching the selection underneath is the
/// terminal's behaviour rather than anything this client controls. Where it
/// does not work there was previously no way out, so `mouse_capture = false` in
/// the config hands the mouse back and gives up the wheel.
///
/// Kept as a second entry point rather than a parameter on `init`, because
/// `tests/terminal_events.rs` and `tests/terminal_restore.rs` both drive
/// `init()` and assert on the modes it sets. A signature change would have made
/// those a compile error and the capture assertion a decision about test
/// plumbing, which is exactly the kind of edit that quietly weakens a check.
pub fn init_with(mouse_capture: bool) -> io::Result<Tui> {
    execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    if mouse_capture {
        execute!(stdout(), EnableMouseCapture)?;
    }
    enable_raw_mode()?;
    Terminal::new(CrosstermBackend::new(stdout()))
}

/// Restores the terminal to its original state.
///
/// Safe to call more than once, which the guard below depends on: a panic
/// restores from the hook and then again as the guard unwinds past.
///
/// Undoes each mode set by `init`. Leaving bracketed paste on would outlive the
/// process and make the next program's pastes arrive wrapped in escape
/// sequences, which is the same class of discourtesy as leaving raw mode on.
pub fn restore() -> io::Result<()> {
    execute!(
        stdout(),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    disable_raw_mode()?;
    Ok(())
}

/// Puts the terminal back however the program leaves, including badly.
///
/// `init()` takes the terminal over completely — raw mode, alternate screen,
/// mouse capture — and only `restore()` gives it back. That used to be a single
/// call after the main loop, which meant every `?` inside the loop returned
/// straight past it: the user was left in a terminal that no longer echoes what
/// they type, looking at a screen about to be discarded, with the error written
/// on it. A panic was worse, because there was no hook at all and the message
/// went to a buffer nobody would ever see.
///
/// Holding a guard instead of remembering a call is the point. The next early
/// return someone adds above it cannot get this wrong.
pub struct TerminalGuard;

impl TerminalGuard {
    /// Installs the panic hook as well, chained in front of whatever hook was
    /// already there rather than replacing it. `Drop` alone is not enough: it
    /// runs while unwinding, which is *after* the runtime has already printed
    /// the panic into the alternate screen, and the one thing the user needed to
    /// read disappears with it.
    pub fn new() -> Self {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = restore();
            previous(info);
        }));
        Self
    }
}

impl Default for TerminalGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Nothing useful to do with a failure here — we are already on the way
        // out, and reporting it would mean writing to the terminal we have just
        // established we cannot drive.
        let _ = restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_twice_is_not_an_error() {
        // The property the guard rests on. A panic restores once from the hook
        // and once more as the guard drops on the way out, so the second call
        // has to be harmless rather than an error the process trips over while
        // it is already failing.
        assert!(restore().is_ok(), "first restore");
        assert!(restore().is_ok(), "second restore must also succeed");
    }
}
