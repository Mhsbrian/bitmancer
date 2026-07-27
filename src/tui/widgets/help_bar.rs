// src/tui/widgets/help_bar.rs
//
// The status strip. Two halves on one line: what you can press right now on the
// left, what the two networks are doing on the right. It replaces a paragraph
// of per-pane prose — a status bar that has to be read is not a status bar.

use ratatui::{
    prelude::{Frame, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::{App, FocusArea, TuiPhase};
use crate::tui::theme;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let left = keys_for(app);
    let right = status_for(app);

    let used: usize = left
        .iter()
        .chain(right.iter())
        .map(|span| span.content.chars().count())
        .sum();
    let gap = (area.width as usize).saturating_sub(used).max(1);

    let mut spans = left;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right);

    f.render_widget(Paragraph::new(Line::from(spans)), area);
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

/// Both networks, always visible: the mesh radio and the location channels.
fn status_for(app: &App) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    if !app.joined_geohashes.is_empty() {
        spans.push(Span::styled(
            format!("geo {}", app.joined_geohashes.len()),
            Style::default().fg(theme::MINE),
        ));
        spans.push(theme::hint("  ·  "));
    }

    spans.push(theme::hint("mesh "));
    match app.phase {
        TuiPhase::Connecting => {
            spans.push(Span::styled(
                format!("{} scanning", theme::spinner(app.tick)),
                Style::default().fg(theme::LIVE),
            ));
        }
        TuiPhase::Connected => {
            let peers = app.people.len();
            spans.push(Span::styled(
                if peers > 0 {
                    format!("◈ {peers}")
                } else {
                    "◈ linked".to_string()
                },
                Style::default().fg(theme::MINE),
            ));
        }
        TuiPhase::Error(_) => {
            spans.push(Span::styled("△ down", Style::default().fg(theme::FAULT)));
        }
    }
    spans.push(Span::raw(" "));
    spans
}
