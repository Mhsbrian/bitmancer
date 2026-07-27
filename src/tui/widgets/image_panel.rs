// src/tui/widgets/image_panel.rs
//
// The image viewer overlay.
//
// Half-block output is drawn as ordinary ratatui content. Kitty graphics cannot
// be — they are escape sequences written straight to the terminal — so the
// panel leaves a hole of the right size and reports where it is; main.rs paints
// into that hole after the frame is flushed.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::media;
use crate::tui::app::App;
use crate::tui::image_render::{self, Backend};
use crate::tui::theme;
use crate::tui::viewer::LoadState;

/// Where the kitty image should be drawn, in terminal cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSlot {
    pub x: u16,
    pub y: u16,
    pub cols: u16,
    pub rows: u16,
}

/// Draws the overlay, returning the slot kitty should paint into (if any).
pub fn render(f: &mut Frame, app: &mut App, area: Rect) -> Option<ImageSlot> {
    let overlay = centered(area, 86, 84);
    f.render_widget(Clear, overlay);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // picture
            Constraint::Length(3), // provenance
            Constraint::Length(1), // keys
        ])
        .split(overlay);

    let slot = render_picture(f, app, chunks[0]);
    render_provenance(f, app, chunks[1]);
    render_keys(f, chunks[2]);
    slot
}

fn render_picture(f: &mut Frame, app: &mut App, area: Rect) -> Option<ImageSlot> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::CHROME))
        .title(theme::panel_title("image"));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let url = app.viewer.current().map(|link| link.url.clone());
    match app.viewer.state.clone() {
        LoadState::Idle => {
            centered_note(f, inner, "nothing loaded", theme::DIM);
            None
        }
        LoadState::Loading => {
            centered_note(
                f,
                inner,
                &format!("{} fetching", theme::spinner(app.tick)),
                theme::LIVE,
            );
            None
        }
        LoadState::Failed(reason) => {
            centered_note(f, inner, &format!("△  {reason}"), theme::FAULT);
            None
        }
        LoadState::Ready => {
            let Some(url) = url else { return None };
            let Some(image) = app.images.get(&url) else {
                centered_note(f, inner, "△  dropped from cache", theme::FAULT);
                return None;
            };
            let (cols, rows) =
                image_render::fit_cells(image.width(), image.height(), inner.width, inner.height);
            if cols == 0 || rows == 0 {
                return None;
            }
            // Centre the picture in the pane either way.
            let x = inner.x + (inner.width.saturating_sub(cols)) / 2;
            let y = inner.y + (inner.height.saturating_sub(rows)) / 2;

            match app.image_backend {
                Backend::HalfBlocks => {
                    let lines = image_render::half_blocks(image, cols, rows);
                    f.render_widget(Paragraph::new(lines), Rect::new(x, y, cols, rows));
                    None
                }
                // Leave the space empty; the escape sequence goes out after the
                // frame is flushed, otherwise ratatui would overwrite it.
                Backend::Kitty => Some(ImageSlot { x, y, cols, rows }),
            }
        }
    }
}

fn centered_note(f: &mut Frame, area: Rect, text: &str, colour: ratatui::style::Color) {
    let y = area.y + area.height / 2;
    let line = Paragraph::new(Line::from(Span::styled(
        text.to_string(),
        Style::default().fg(colour),
    )))
    .alignment(Alignment::Center);
    f.render_widget(line, Rect::new(area.x, y, area.width, 1));
}

/// Who posted it, where it came from, and where you are in the set. The host is
/// spelled out because opening an image is a request to that host.
fn render_provenance(f: &mut Frame, app: &App, area: Rect) {
    let conversation = app.active_conversation();
    let (position, total) = app.viewer.position_in(&conversation);

    let lines = match app.viewer.current() {
        None => vec![Line::from(Span::styled(
            "no image",
            Style::default().fg(theme::DIM),
        ))],
        Some(link) => {
            let dimensions = app
                .images_peek(&link.url)
                .map(|(w, h)| format!("{w}×{h}"))
                .unwrap_or_else(|| "—".to_string());
            vec![
                Line::from(vec![
                    Span::styled(
                        link.sender.clone(),
                        Style::default()
                            .fg(theme::speaker_color(&link.sender))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("  via  ", Style::default().fg(theme::DIM)),
                    Span::styled(
                        media::host_of(&link.url),
                        Style::default().fg(theme::TEXT),
                    ),
                    Span::styled(
                        format!("   {dimensions}   {position}/{total}"),
                        Style::default().fg(theme::DIM),
                    ),
                ]),
                Line::from(Span::styled(
                    truncate(&link.url, area.width.saturating_sub(2) as usize),
                    Style::default().fg(theme::FAINT),
                )),
            ]
        }
    };

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(theme::CHROME)),
        ),
        area,
    );
}

fn render_keys(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        theme::hint(" ".to_string()),
        theme::key("←→".to_string()),
        theme::hint(" other images  ".to_string()),
        theme::key("o".to_string()),
        theme::hint(" open in browser  ".to_string()),
        theme::key("esc".to_string()),
        theme::hint(" close".to_string()),
    ]);
    f.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(theme::CHROME)),
        ),
        area,
    );
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width || width < 2 {
        return text.to_string();
    }
    let kept: String = text.chars().take(width - 1).collect();
    format!("{kept}…")
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_truncated_with_an_ellipsis() {
        assert_eq!(truncate("short", 20), "short");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        // Degenerate widths must not panic or slice mid-character.
        assert_eq!(truncate("abc", 1), "abc");
        assert_eq!(truncate("日本語のURL", 3), "日本…");
    }
}
