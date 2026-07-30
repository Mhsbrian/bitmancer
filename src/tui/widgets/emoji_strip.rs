// src/tui/widgets/emoji_strip.rs
//
// The matches for a shortcode being typed.
//
// One line, directly above the input, and only while it is useful. It is a hint
// rather than a dialogue: nothing has to be answered, Enter still sends, and
// carrying on typing narrows or dismisses it. A panel that had to be dealt with
// would cost more than typing the name.
//
// Same grammar as everything else: magenta is the cursor and nothing else, dim
// for the names, and no borders — a border around a single line of hints would
// weigh more than the hints.

use ratatui::layout::Rect;
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use crate::tui::app::App;
use crate::tui::emoji;
use crate::tui::theme::{CURSOR as ACCENT, DIM, TEXT};

/// Whether there is anything to draw, so the layout can give up the row when
/// there is not. Asked before splitting the screen rather than after.
pub fn visible(app: &App) -> bool {
    app.emoji_suggestions().is_some()
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let Some((query, matches)) = app.emoji_suggestions() else {
        return;
    };
    f.render_widget(Clear, area);

    let highlighted = app.emoji_selection.min(matches.len().saturating_sub(1));
    let mut spans = vec![Span::styled(" ", Style::default())];

    for (index, found) in matches.iter().enumerate() {
        let chosen = index == highlighted;
        let name = emoji::label_for(found, &query.text);

        // The glyph stays at full brightness whether or not it is highlighted:
        // it is the thing being chosen between, and dimming the alternatives
        // would make a row of emoji hard to read at a glance.
        spans.push(Span::styled(
            format!("{} ", found.glyph),
            Style::default().fg(TEXT),
        ));
        spans.push(Span::styled(
            format!(":{name}:"),
            if chosen {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DIM)
            },
        ));
        if index + 1 < matches.len() {
            spans.push(Span::styled("   ", Style::default()));
        }
    }

    // Said once, at the end, because the keys are only worth knowing while the
    // strip is up — and anyone who has used it once does not need telling again.
    spans.push(Span::styled("   tab", Style::default().fg(TEXT)));
    spans.push(Span::styled(" insert", Style::default().fg(DIM)));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    fn typing(text: &str) -> App {
        let mut app = App::new_with_nickname("tui".into());
        app.input = tui_input::Input::new(text.to_string()).with_cursor(text.chars().count());
        app
    }

    #[test]
    fn the_strip_appears_only_while_a_shortcode_is_being_typed() {
        assert!(!visible(&typing("hello")), "ordinary text");
        assert!(!visible(&typing("note:")), "a bare colon is punctuation");
        assert!(visible(&typing("note :fi")), "a shortcode with something to match");
        assert!(!visible(&typing(":zzzqqq")), "nothing matches");
    }

    #[test]
    fn a_colon_in_prose_never_raises_it() {
        // The case that would make this a tax on ordinary typing.
        for text in [
            "the thing: it was raining",
            "TODO: fix this",
            "9:30 tomorrow",
        ] {
            assert!(!visible(&typing(text)), "{text:?} must stay quiet");
        }
    }
}
