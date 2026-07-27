// src/tui/theme.rs
//
// One visual system for the whole client.
//
// The rules, in order of importance:
//   1. Colour carries meaning, never decoration. Five roles, no more: chrome,
//      text, life (cyan), yours (mint), attention (amber), and the cursor
//      (magenta, reserved — nothing else is ever magenta).
//   2. No filled selection bars, no emoji, no ASCII art. Selection is a gutter
//      mark; structure is thin rules and negative space.
//   3. Dim by default. Brightness is spent only on the thing that changed.
//
// Everything reads at a glance in a dark terminal and stays readable for hours.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

// MARK: - Palette

/// Panel borders and other structure.
pub const CHROME: Color = Color::Rgb(72, 94, 104);
/// Structure that should barely register: grid ticks, rules, coastlines.
pub const FAINT: Color = Color::Rgb(58, 78, 88);
/// Body text.
pub const TEXT: Color = Color::Rgb(150, 172, 182);
/// Labels, timestamps, anything secondary.
pub const DIM: Color = Color::Rgb(96, 116, 126);
/// Life: other people, activity, live data.
pub const LIVE: Color = Color::Rgb(0, 240, 255);
/// Yours: your messages, your channels, a healthy link.
pub const MINE: Color = Color::Rgb(120, 255, 214);
/// Attention: unread counts, mentions of you.
pub const ALERT: Color = Color::Rgb(255, 176, 64);
/// Trouble: offline, failures.
pub const FAULT: Color = Color::Rgb(255, 92, 116);
/// The cursor. Reserved — if something is magenta, it is where you are pointing.
pub const CURSOR: Color = Color::Rgb(255, 74, 158);

/// Speakers get a stable hue from a deliberately narrow, cool set. Six values
/// is enough to tell people apart in a busy channel without turning the log
/// into confetti.
const VOICES: [Color; 6] = [
    Color::Rgb(126, 200, 227), // ice
    Color::Rgb(140, 190, 255), // periwinkle
    Color::Rgb(120, 222, 200), // seafoam
    Color::Rgb(176, 168, 240), // lavender
    Color::Rgb(150, 210, 170), // pale jade
    Color::Rgb(200, 186, 226), // orchid grey
];

/// Deterministic colour for a speaker, so the same person keeps the same hue
/// for the whole session.
pub fn speaker_color(name: &str) -> Color {
    let hash = name
        .bytes()
        .fold(0u32, |acc, byte| acc.wrapping_mul(31).wrapping_add(byte as u32));
    VOICES[(hash as usize) % VOICES.len()]
}

// MARK: - Structure

/// Panel border: lit when the pane has focus, structural otherwise.
pub fn border(focused: bool) -> Style {
    if focused {
        Style::default().fg(LIVE)
    } else {
        Style::default().fg(CHROME)
    }
}

/// Panel titles are set in spaced small-caps: quiet, but unmistakably chrome
/// rather than content.
pub fn panel_title(text: &str) -> Span<'static> {
    let spaced: String = text
        .to_uppercase()
        .chars()
        .flat_map(|c| [c, ' '])
        .collect::<String>()
        .trim_end()
        .to_string();
    Span::styled(format!(" {spaced} "), Style::default().fg(DIM))
}

/// A keycap in the hint bars.
pub fn key(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(TEXT))
}

/// The prose between keycaps.
pub fn hint(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(DIM))
}

/// Gutter mark for the selected row. A bar rather than a filled background:
/// inverse blocks read as a spreadsheet, a bar reads as a cursor.
pub const GUTTER_CURSOR: &str = "▌";
pub const GUTTER_ACTIVE: &str = "▏";
pub const GUTTER_EMPTY: &str = " ";

/// Disclosure markers for collapsible sections.
pub const OPEN: &str = "▾";
pub const CLOSED: &str = "▸";

/// A quiet spinner for work in progress. Braille frames rotate rather than
/// blink, which stays calm in peripheral vision.
const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

pub fn spinner(tick: usize) -> &'static str {
    SPINNER[(tick / 2) % SPINNER.len()]
}

/// Emphasis for a line that mentions you.
pub fn mention() -> Style {
    Style::default().fg(ALERT).add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speaker_colours_are_stable_and_in_palette() {
        let first = speaker_color("nerdetta");
        assert_eq!(first, speaker_color("nerdetta"), "same name, same hue");
        assert!(VOICES.contains(&first));
        assert!(VOICES.contains(&speaker_color("")));
    }

    #[test]
    fn different_speakers_generally_differ() {
        // Not guaranteed for every pair with six buckets, but the common case
        // must spread rather than collapse onto one colour.
        let names = ["alice", "bob", "carol", "dave", "erin", "frank"];
        let distinct: std::collections::HashSet<Color> =
            names.iter().map(|name| speaker_color(name)).collect();
        assert!(distinct.len() >= 3, "got {} distinct hues", distinct.len());
    }

    #[test]
    fn titles_are_spaced_small_caps() {
        let span = panel_title("messages");
        assert_eq!(span.content, " M E S S A G E S ");
    }

    #[test]
    fn spinner_cycles_without_panicking() {
        let frames: std::collections::HashSet<&str> =
            (0..64).map(spinner).collect();
        assert_eq!(frames.len(), SPINNER.len(), "every frame is reachable");
    }

    #[test]
    fn focus_lights_the_border() {
        assert_eq!(border(true).fg, Some(LIVE));
        assert_eq!(border(false).fg, Some(CHROME));
    }

    #[test]
    fn cursor_colour_is_reserved() {
        // Magenta must not double as a content colour, or the cursor stops
        // meaning "you are here".
        assert!(!VOICES.contains(&CURSOR));
        for role in [CHROME, FAINT, TEXT, DIM, LIVE, MINE, ALERT, FAULT] {
            assert_ne!(role, CURSOR);
        }
    }
}
