
// src/tui/tui.rs

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, stdout, Stdout};

/// A type alias for the terminal used in the application.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initializes the terminal for TUI rendering.
pub fn init() -> io::Result<Tui> {
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    enable_raw_mode()?;
    Terminal::new(CrosstermBackend::new(stdout()))
}

/// Restores the terminal to its original state.
///
/// Safe to call more than once, which the guard below depends on: a panic
/// restores from the hook and then again as the guard unwinds past.
pub fn restore() -> io::Result<()> {
    execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
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
