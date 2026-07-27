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
