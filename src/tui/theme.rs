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
use std::time::Duration;

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

/// Hairlines. Panels are separated by single rules rather than boxed, which
/// spends the rows on information instead of on chrome.
pub const RULE_H: &str = "─";
pub const RULE_V: &str = "│";

/// A horizontal hairline of the given width.
pub fn rule(width: u16) -> Span<'static> {
    Span::styled(
        RULE_H.repeat(width as usize),
        Style::default().fg(FAINT),
    )
}

/// A labelled telemetry field: dim label, bright value, fixed spacing. The
/// readout is meant to be scanned, not read, so labels stay quiet and values
/// sit in a predictable place.
pub fn field(label: &str, value: impl Into<String>, tone: Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!("{} ", label.to_uppercase()),
            Style::default().fg(FAINT),
        ),
        Span::styled(value.into(), Style::default().fg(tone)),
    ]
}

/// Section heading used where a panel border used to be. Focus is carried by
/// brightness now that panels are not boxed.
pub fn section(label: &str, focused: bool) -> Span<'static> {
    let spaced: String = label
        .to_uppercase()
        .chars()
        .flat_map(|c| [c, ' '])
        .collect::<String>()
        .trim_end()
        .to_string();
    Span::styled(
        spaced,
        Style::default()
            .fg(if focused { LIVE } else { DIM })
            .add_modifier(if focused {
                Modifier::BOLD
            } else {
                Modifier::empty()
            }),
    )
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


// ── Arrival ─────────────────────────────────────────────────────────────────
//
// The palette rule is that brightness is spent only on what changed. Held
// still that is a rule about roles; given a clock it becomes a rule about time.
// A line lands lit and cools into the resting palette over about a second and a
// half, so a conversation reads as something arriving rather than something
// that was already there.

/// How long a line takes to cool from arrival to rest.
pub const SETTLE: Duration = Duration::from_millis(1500);

/// The opening fraction of that time spent at full brightness. Without a hold,
/// the brightest frame is also the shortest one, and an arrival registers as a
/// flicker rather than an entrance.
const HOLD: f32 = 0.2;

/// The cool white a line is lifted toward as it lands. Lifting toward a colour
/// rather than substituting one keeps every hue's identity: a speaker's colour
/// and an amber mention both brighten without either becoming something else,
/// and no hue has to travel through grey to get there.
const PHOSPHOR: Color = Color::Rgb(226, 248, 252);

/// How far toward that white a line goes at the instant it arrives. Enough to
/// carry across a full screen, short of washing the hue out.
const LIFT: f32 = 0.55;

/// How long a line takes to materialise. Short on purpose: this is the line
/// assembling itself, not a typewriter. Much beyond a quarter second and it
/// stops reading as arrival and starts reading as a delay before you can read
/// your own messages.
pub const REVEAL: Duration = Duration::from_millis(260);

/// The cells at the leading edge resolve through these before settling into
/// their real characters. Block and shade forms rather than random letters:
/// it should read as a signal coming into focus, not as scrambled text.
const RESOLVING: [&str; 6] = ["▚", "▞", "▒", "░", "▖", "▘"];

/// How many cells behind the leading edge are still resolving.
pub const RESOLVING_CELLS: usize = 2;

/// The cell at the leading edge of a line coming into existence.
pub const FRONTIER: &str = "▊";

/// How much of a line has materialised, from 0 to 1.
pub fn reveal_fraction(age: Duration) -> f32 {
    let elapsed = age.as_secs_f32() / REVEAL.as_secs_f32();
    if elapsed >= 1.0 {
        return 1.0;
    }
    // Eased so the sweep arrives rather than stopping dead against the end of
    // the line.
    1.0 - (1.0 - elapsed) * (1.0 - elapsed)
}

pub fn resolving_glyph(seed: u64) -> &'static str {
    RESOLVING[(seed % RESOLVING.len() as u64) as usize]
}

/// Where a line sits between arrival (1.0) and rest (0.0).
pub fn settle_intensity(age: Duration) -> f32 {
    let elapsed = age.as_secs_f32() / SETTLE.as_secs_f32();
    if elapsed >= 1.0 {
        return 0.0;
    }
    if elapsed <= HOLD {
        return 1.0;
    }
    let after = (elapsed - HOLD) / (1.0 - HOLD);
    // Quadratic ease-out: most of the fall happens early and then trails off, so
    // the line settles instead of switching off.
    (1.0 - after) * (1.0 - after)
}

/// Mixes two colours. An `amount` of 0 gives `from`, 1 gives `to`. Colours
/// outside the 24-bit palette have nothing to interpolate and so step over.
pub fn blend(from: Color, to: Color, amount: f32) -> Color {
    let amount = amount.clamp(0.0, 1.0);
    match (from, to) {
        (Color::Rgb(fr, fg, fb), Color::Rgb(tr, tg, tb)) => {
            let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * amount).round() as u8;
            Color::Rgb(mix(fr, tr), mix(fg, tg), mix(fb, tb))
        }
        _ => {
            if amount < 0.5 {
                from
            } else {
                to
            }
        }
    }
}

/// A resting colour lifted by how recently its line arrived.
pub fn arriving(resting: Color, intensity: f32) -> Color {
    blend(resting, PHOSPHOR, LIFT * intensity)
}

/// The mark down the left edge of a line that is still settling. It thins as it
/// fades, because a terminal cell cannot be half-lit: the ramp has to live in
/// glyph weight as well as in colour.
pub fn arrival_mark(intensity: f32) -> Option<(&'static str, Color)> {
    if intensity <= 0.02 {
        return None;
    }
    let glyph = if intensity > 0.6 { "▎" } else { "▏" };
    Some((glyph, blend(FAINT, LIVE, intensity)))
}

#[cfg(test)]
mod arrival_tests {
    use super::*;

    #[test]
    fn a_line_lands_lit_holds_then_reaches_rest() {
        assert_eq!(settle_intensity(Duration::ZERO), 1.0);
        assert_eq!(settle_intensity(SETTLE.mul_f32(HOLD * 0.5)), 1.0);
        assert_eq!(settle_intensity(SETTLE), 0.0);
        assert_eq!(settle_intensity(SETTLE * 10), 0.0, "no glow outlives the settle");
    }

    #[test]
    fn brightness_only_ever_falls() {
        // A line that brightened again partway through would read as a second
        // arrival that never happened.
        let mut previous = f32::INFINITY;
        for step in 0..=60 {
            let intensity = settle_intensity(SETTLE.mul_f32(step as f32 / 60.0));
            assert!(intensity <= previous, "brightness rose at step {step}");
            previous = intensity;
        }
    }

    #[test]
    fn a_settled_line_is_indistinguishable_from_one_that_never_animated() {
        // The whole animation has to leave no residue: an hour-old line and a
        // just-settled one must render identically, or the log ends up striped.
        for resting in [TEXT, DIM, ALERT, MINE, LIVE, speaker_color("anon")] {
            assert_eq!(arriving(resting, 0.0), resting);
        }
        assert_eq!(arrival_mark(0.0), None);
    }

    #[test]
    fn arrival_lifts_toward_white_without_discarding_the_hue() {
        // Amber must still read as amber while it is lit, or a mention stops
        // looking like a mention exactly when it matters most.
        let lit = arriving(ALERT, 1.0);
        let Color::Rgb(r, g, b) = lit else {
            panic!("expected rgb")
        };
        assert!(r > g && g > b, "amber must stay warm while lit: {lit:?}");

        // Brightness is the thing that rises, not any one channel: lifting a
        // warm hue toward a cool white takes a little red out of it while still
        // making the line lighter.
        let luminance = |colour: Color| {
            let Color::Rgb(r, g, b) = colour else {
                panic!("expected rgb")
            };
            0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32
        };
        for resting in [TEXT, DIM, ALERT, MINE, FAULT] {
            assert!(
                luminance(arriving(resting, 1.0)) > luminance(resting),
                "arrival must brighten {resting:?}"
            );
        }
    }

    #[test]
    fn blending_hits_both_ends_exactly() {
        let a = Color::Rgb(0, 0, 0);
        let b = Color::Rgb(200, 100, 50);
        assert_eq!(blend(a, b, 0.0), a);
        assert_eq!(blend(a, b, 1.0), b);
        assert_eq!(blend(a, b, 0.5), Color::Rgb(100, 50, 25));
        assert_eq!(blend(a, b, 9.0), b, "out of range cannot overshoot");
    }

    #[test]
    fn a_line_materialises_quickly_and_completely() {
        assert_eq!(reveal_fraction(Duration::ZERO), 0.0);
        assert_eq!(reveal_fraction(REVEAL), 1.0);
        assert_eq!(reveal_fraction(REVEAL * 4), 1.0);
        assert!(
            REVEAL < SETTLE,
            "a line has to finish arriving before it finishes cooling"
        );
    }

    #[test]
    fn the_sweep_only_ever_moves_forward() {
        let mut previous = -1.0;
        for step in 0..=40 {
            let fraction = reveal_fraction(REVEAL.mul_f32(step as f32 / 40.0));
            assert!(fraction >= previous, "the sweep went backwards at {step}");
            previous = fraction;
        }
    }

    #[test]
    fn the_mark_thins_as_it_fades() {
        assert_eq!(arrival_mark(1.0).unwrap().0, "▎");
        assert_eq!(arrival_mark(0.3).unwrap().0, "▏");
    }
}
