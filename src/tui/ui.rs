// src/tui/ui.rs
//
// Screen layout.
//
// Panels are divided by hairlines rather than boxed. Six rows were being spent
// on box drawing that carried no information; a single rule divides just as
// clearly and gives the rows back to the log. Focus is signalled by the
// brightness of a section label instead of a lit border.
//
//   BITMANCER  callsign · id                 MESH ◈ 4  GEO 1  UP ..  clock
//   ─────────────────────────────────────────────────────────────────────────
//   #9q · 33 here                           │ N A V
//   ────────────────────────────────────    │ ▾ PUBLIC
//   07:15   anon5842   hello                │   public
//                                           │ ▾ CHANNELS
//   ────────────────────────────────────    │ ▏ #9q
//   ▌ compose                               │
//   ─────────────────────────────────────────────────────────────────────────
//   ⏎ send   /map world   tab pane

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::{
    app::{App, TuiPhase},
    theme, widgets,
};

/// Width of the navigation column.
const SIDEBAR_WIDTH: u16 = 26;

pub fn render(app: &mut App, f: &mut Frame) {
    let screen = f.size();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status band
            Constraint::Length(1), // rule
            Constraint::Min(3),    // body
            Constraint::Length(1), // rule
            Constraint::Length(1), // keys
        ])
        .split(screen);

    widgets::status_band::render(f, app, rows[0]);
    horizontal_rule(f, rows[1]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(20),
            Constraint::Length(1), // hairline
            Constraint::Length(SIDEBAR_WIDTH),
        ])
        .split(rows[2]);

    render_conversation(f, app, body[0]);
    vertical_rule(f, body[1]);
    widgets::sidebar::render(f, app, body[2]);

    horizontal_rule(f, rows[3]);
    widgets::help_bar::render(f, app, rows[4]);

    // Overlays cover everything beneath them.
    if app.viewer.open {
        app.pending_image_slot = widgets::image_panel::render(f, app, screen);
    } else if app.map_open {
        widgets::map_panel::render(f, app, screen);
    } else if app.popup_active {
        widgets::popup::render(f, app, screen);
    } else if !app.connection_popup_dismissed {
        match &app.phase {
            TuiPhase::Connecting | TuiPhase::Error(_) => widgets::popup::render(f, app, screen),
            TuiPhase::Connected => {}
        }
    }
}

/// Context line, log, and the compose prompt.
fn render_conversation(f: &mut Frame, app: &mut App, area: Rect) {
    let input_height = app
        .get_input_box_height(area.width as usize)
        .saturating_sub(2)
        .clamp(1, 5) as u16;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),            // context
            Constraint::Length(1),            // rule
            Constraint::Min(1),               // log
            Constraint::Length(1),            // rule
            Constraint::Length(input_height), // compose
        ])
        .split(area);

    widgets::main_panel::render_context(f, app, rows[0]);
    horizontal_rule(f, rows[1]);
    widgets::main_panel::render_log(f, app, rows[2]);
    horizontal_rule(f, rows[3]);
    widgets::input_box::render(f, app, rows[4]);
}

fn horizontal_rule(f: &mut Frame, area: Rect) {
    if area.width == 0 {
        return;
    }
    f.render_widget(Paragraph::new(Line::from(theme::rule(area.width))), area);
}

fn vertical_rule(f: &mut Frame, area: Rect) {
    let lines: Vec<Line> = (0..area.height)
        .map(|_| Line::from(Span::styled(theme::RULE_V, Style::default().fg(theme::FAINT))))
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}
