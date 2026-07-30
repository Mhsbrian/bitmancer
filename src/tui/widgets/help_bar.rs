// src/tui/widgets/help_bar.rs
//
// The key strip: what you can press right now, for the pane that has focus.
//
// Telemetry used to live on the right of this line and now sits in the status
// band, where it belongs. Saying the same thing twice on one screen trains the
// eye to ignore both.

use ratatui::{
    prelude::{Frame, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::{App, FocusArea};
use crate::tui::theme;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    f.render_widget(Paragraph::new(Line::from(keys_for(app))), area);
}

/// Only the keys that do something in the pane that has focus.
fn keys_for(app: &App) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw(" ")];

    // Search takes the keyboard, so it takes the strip too. Listing the pane's
    // ordinary keys underneath a prompt that will not deliver them is worse
    // than listing nothing.
    if app.search.prompt_open {
        return vec![
            Span::raw(" "),
            theme::key("⏎"),
            theme::hint(" find  "),
            theme::key("esc"),
            theme::hint(" cancel"),
        ];
    }
    // Only while the log has focus. `n` and `N` walk matches there and are
    // ordinary text in the compose box, so advertising them from the input box
    // would promise a key that types a letter instead.
    if app.search.is_walking() && app.focus_area == FocusArea::MainPanel {
        return vec![
            Span::raw(" "),
            theme::key("n"),
            theme::hint("/"),
            theme::key("N"),
            theme::hint(" next, previous  "),
            theme::key("esc"),
            theme::hint(" done  "),
            theme::key("tab"),
            theme::hint(" pane"),
        ];
    }

    match app.focus_area {
        FocusArea::Sidebar => spans.extend([
            theme::key("↑↓"),
            theme::hint(" move  "),
            theme::key("⏎"),
            theme::hint(" open  "),
            theme::key("m"),
            theme::hint(" map  "),
        ]),
        FocusArea::MainPanel => spans.extend([
            theme::key("↑↓"),
            theme::hint(" scroll  "),
            theme::key("/"),
            theme::hint(" find  "),
            theme::key("m"),
            theme::hint(" map  "),
        ]),
        FocusArea::InputBox => spans.extend([
            theme::key("⏎"),
            theme::hint(" send  "),
            theme::key("/map"),
            theme::hint(" world  "),
            theme::key("/help"),
            theme::hint("  "),
        ]),
    }
    spans.extend([theme::key("tab"), theme::hint(" pane")]);
    spans
}
