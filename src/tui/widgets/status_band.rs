// src/tui/widgets/status_band.rs
//
// The band across the top: who you are on the left, what the two networks are
// doing on the right.
//
// It is a readout, not a header. Fields sit in fixed positions with quiet
// labels and bright values so the eye can check one of them without reading the
// rest, and the values are padded to a constant width so nothing shifts
// sideways while you are looking at it.

use ratatui::layout::Rect;
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::app::{App, TuiPhase};
use crate::tui::theme;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let left = identity(app);
    let right = telemetry(app);

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

/// Callsign block: the product, your nickname, and the first half of the peer
/// ID other people actually see you as.
fn identity(app: &App) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            " BITMANCER",
            Style::default()
                .fg(theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(app.nickname.clone(), Style::default().fg(theme::MINE)),
        Span::styled(
            format!(" · {}", app.short_peer_id),
            Style::default().fg(theme::FAINT),
        ),
    ]
}

/// Right-hand readout. Every field is fixed width so the block never reflows.
fn telemetry(app: &App) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    let (mesh_value, mesh_tone) = match app.phase {
        TuiPhase::Connecting => (
            format!("{} scan", theme::spinner(app.tick)),
            theme::LIVE,
        ),
        TuiPhase::Connected => (format!("◈ {:<3}", app.people.len()), theme::MINE),
        TuiPhase::Error(_) => ("△ down".to_string(), theme::FAULT),
    };
    spans.extend(theme::field("mesh", format!("{mesh_value:<7}"), mesh_tone));
    spans.push(Span::raw("  "));

    let geo = app.joined_geohashes.len();
    spans.extend(theme::field(
        "geo",
        format!("{geo:<3}"),
        if geo > 0 { theme::MINE } else { theme::DIM },
    ));
    spans.push(Span::raw("  "));

    // Only present while carrying, so the band does not spend width on a mode
    // that is off — and is impossible to miss while it is on.
    if let Some(carried) = app.carrying {
        spans.extend(theme::field("gw", format!("↑{carried:<4}"), theme::LIVE));
        spans.push(Span::raw("  "));
    }

    // Present only while holding, like the gateway field: the band should not
    // spend width on a mode that is off, nor let one that is on go unnoticed.
    if let Some(waiting) = app.holding {
        spans.extend(theme::field("post", format!("✉{waiting:<3}"), theme::LIVE));
        spans.push(Span::raw("  "));
    }

    spans.extend(theme::field("up", uptime(app.started.elapsed()), theme::TEXT));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        chrono::Local::now().format("%H:%M:%S").to_string(),
        Style::default().fg(theme::TEXT),
    ));
    spans.push(Span::raw(" "));
    spans
}

/// Session uptime as hh:mm:ss, which is what an operator would expect to read.
pub fn uptime(elapsed: std::time::Duration) -> String {
    let seconds = elapsed.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn uptime_is_zero_padded_and_carries_hours() {
        assert_eq!(uptime(Duration::from_secs(0)), "00:00:00");
        assert_eq!(uptime(Duration::from_secs(59)), "00:00:59");
        assert_eq!(uptime(Duration::from_secs(61)), "00:01:01");
        assert_eq!(uptime(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(uptime(Duration::from_secs(360_000)), "100:00:00");
    }

    #[test]
    fn telemetry_holds_its_width_as_values_change() {
        // The block must not reflow while it is being read, so a peer count
        // going from 9 to 10 cannot shift the clock sideways.
        let width = |app: &App| -> usize {
            telemetry(app)
                .iter()
                .map(|span| span.content.chars().count())
                .sum()
        };

        let mut app = App::new_with_nickname("tui".into());
        app.phase = TuiPhase::Connected;
        app.people = vec!["a".into()];
        let narrow = width(&app);

        app.people = (0..12).map(|index| index.to_string()).collect();
        assert_eq!(width(&app), narrow, "peer count must not move the fields");

        app.joined_geohashes.insert("9q".into());
        assert_eq!(width(&app), narrow, "geo count must not move the fields");
    }
}
