// src/tui/widgets/mesh_panel.rs
//
// The mesh, drawn.
//
// Same visual grammar as the world map, for the same reason: cyan means life,
// magenta is only ever the cursor or the thing being called out, structure is
// thin glyphs, and everything else is negative space.
//
// One departure worth stating. A link we observed and a link a peer merely
// claimed are drawn differently — solid and bright for ours, faint and dotted
// for hearsay — because they are different kinds of knowledge. Upstream calls
// gossiped neighbours advisory, and drawing an assertion with the same
// confidence as a measurement would quietly promote it.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Context, Line as CanvasLine};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::topology::Reach;
use crate::tui::app::App;
use crate::tui::theme::{CHROME, CURSOR as ACCENT, DIM as LABEL_DIM, LIVE, MINE, TEXT};

/// Room beyond the outermost ring, for the label hanging below it and a little
/// air. Without the margin a name on the edge is clipped by the border.
const MARGIN: f64 = 0.4;
/// How far below a node its name is drawn.
const LABEL_DROP: f64 = 0.22;
/// A claimed edge is drawn as spaced dots rather than a line, so hearsay reads as
/// hearsay from across the room.
const CLAIM_DOTS: usize = 9;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let overlay = centered(area, 88, 86);
    f.render_widget(Clear, overlay);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // the graph
            Constraint::Length(4), // what it means
            Constraint::Length(1), // keys
        ])
        .split(overlay);

    render_graph(f, app, chunks[0]);
    render_readout(f, app, chunks[1]);
    render_keys(f, chunks[2]);
}

fn render_graph(f: &mut Frame, app: &App, area: Rect) {
    let topology = &app.topology;
    let places = topology.layout();
    let nodes = topology.nodes();
    let edges = topology.edges();
    let extent = extent(!topology.gossiped().is_empty());

    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CHROME))
                .title(Line::from(Span::styled(
                    " MESH ",
                    Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                )))
                .title_alignment(Alignment::Left),
        )
        // Braille, like the map: four times the horizontal resolution, which a
        // radial layout needs more than a grid does.
        .marker(Marker::Braille)
        .x_bounds([-extent, extent])
        .y_bounds([-extent, extent])
        .paint(move |ctx: &mut Context| {
            // Edges under the labels, so a line never crosses a name.
            for edge in &edges {
                let (Some(&from), Some(&to)) = (places.get(&edge.from), places.get(&edge.to))
                else {
                    continue;
                };
                if edge.observed {
                    ctx.draw(&CanvasLine {
                        x1: from.0,
                        y1: from.1,
                        x2: to.0,
                        y2: to.1,
                        color: LIVE,
                    });
                } else {
                    dotted(ctx, from, to);
                }
            }
            ctx.layer();

            for node in &nodes {
                let Some(&(x, y)) = places.get(&node.peer_id) else {
                    continue;
                };
                let (mark, tone) = match node.reach {
                    // Us: the one node that is not a claim about anybody.
                    Reach::Ourselves => ("◉", ACCENT),
                    Reach::Direct => ("●", LIVE),
                    // Hollow, because we have never heard from them.
                    Reach::Gossiped => ("○", LABEL_DIM),
                };
                ctx.print(x, y, Span::styled(mark, Style::default().fg(tone)));
                // Names sit below their node so a long one runs into empty space
                // rather than through the graph.
                ctx.print(
                    x,
                    y - LABEL_DROP,
                    Span::styled(
                        node.label.clone(),
                        Style::default().fg(if node.reach == Reach::Gossiped {
                            LABEL_DIM
                        } else {
                            tone
                        }),
                    ),
                );
            }
        });
    f.render_widget(canvas, area);
}

/// Spaced dots along a line, for an edge we were told about rather than saw.
fn dotted(ctx: &mut Context, from: (f64, f64), to: (f64, f64)) {
    for step in 0..CLAIM_DOTS {
        // Skipping both ends keeps the dots clear of the node glyphs.
        let along = (step as f64 + 1.0) / (CLAIM_DOTS as f64 + 1.0);
        let x = from.0 + (to.0 - from.0) * along;
        let y = from.1 + (to.1 - from.1) * along;
        ctx.print(x, y, Span::styled("·", Style::default().fg(CHROME)));
    }
}

fn render_readout(f: &mut Frame, app: &App, area: Rect) {
    let topology = &app.topology;
    let direct = topology.direct_count();
    let gossiped = topology.gossiped().len();

    let mut lines = vec![Line::from(vec![
        Span::styled(
            format!("{direct} linked"),
            Style::default().fg(if direct > 0 { LIVE } else { LABEL_DIM }),
        ),
        Span::raw("   "),
        Span::styled(
            format!("{gossiped} one hop further"),
            Style::default().fg(LABEL_DIM),
        ),
        Span::raw("   "),
        Span::styled(
            format!("{}/{} link slots", direct.min(crate::transport::MAX_LINKS), crate::transport::MAX_LINKS),
            Style::default().fg(LABEL_DIM),
        ),
    ])];

    // The moment holding several links stops being a statistic. Said loudly
    // because it is the only time being this node matters to anyone else.
    if topology.we_are_a_bridge() {
        let islands = topology.islands_without_us();
        lines.push(Line::from(Span::styled(
            format!(
                "you are the only path between {} groups — traffic between them goes through you",
                islands.len()
            ),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
    } else if direct > 1 {
        lines.push(Line::from(Span::styled(
            "these peers can reach each other without you",
            Style::default().fg(LABEL_DIM),
        )));
    } else if direct == 0 {
        lines.push(Line::from(Span::styled(
            "nobody in range",
            Style::default().fg(LABEL_DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "one link — nothing to relay between yet",
            Style::default().fg(LABEL_DIM),
        )));
    }

    lines.push(Line::from(vec![
        Span::styled("●", Style::default().fg(LIVE)),
        Span::styled(" heard directly    ", Style::default().fg(LABEL_DIM)),
        Span::styled("○", Style::default().fg(LABEL_DIM)),
        Span::styled(
            " claimed by a neighbour, never heard here",
            Style::default().fg(LABEL_DIM),
        ),
    ]));

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(CHROME)),
        ),
        area,
    );
}

fn render_keys(f: &mut Frame, area: Rect) {
    let key = |text: &'static str| Span::styled(text, Style::default().fg(TEXT));
    let hint = |text: &'static str| Span::styled(text, Style::default().fg(LABEL_DIM));
    f.render_widget(
        Paragraph::new(Line::from(vec![
            hint(" "),
            key("esc"),
            hint(" back  "),
            key("q"),
            hint(" close"),
        ])),
        area,
    );
}

/// Same helper the map uses; kept local rather than shared because the two
/// overlays are free to disagree about their proportions.
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

/// How much of the plane to show, given what is actually on it.
///
/// Fixed at the two-ring extent, most of the canvas sat empty in the common case
/// of a couple of neighbours and nothing beyond them — a graph drawn small in the
/// middle of a large box, which reads as though something failed to load. The
/// bound follows the content instead.
fn extent(outer_ring: bool) -> f64 {
    let furthest = if outer_ring { 2.0 } else { 1.0 };
    furthest + LABEL_DROP + MARGIN
}

/// Kept so the palette cannot drift from the map's without someone noticing.
#[allow(dead_code)]
const _SHARED_WITH_THE_MAP: [Color; 4] = [LIVE, ACCENT, LABEL_DIM, MINE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overlay_stays_inside_its_area() {
        let area = Rect::new(0, 0, 80, 24);
        let overlay = centered(area, 88, 86);
        assert!(overlay.x + overlay.width <= area.width);
        assert!(overlay.y + overlay.height <= area.height);
    }

    #[test]
    fn a_tiny_terminal_does_not_panic() {
        for (width, height) in [(1, 1), (4, 2), (20, 6), (0, 0)] {
            let _ = centered(Rect::new(0, 0, width, height), 88, 86);
        }
    }

    #[test]
    fn the_view_fits_what_is_on_it_and_never_clips_a_label() {
        // Names hang below their node, so a bound at the ring radius would cut
        // off the thing each ring exists to show.
        assert!(extent(false) > 1.0 + LABEL_DROP, "inner ring labels clipped");
        assert!(extent(true) > 2.0 + LABEL_DROP, "outer ring labels clipped");
        assert!(
            extent(false) < extent(true),
            "a mesh with nothing beyond our neighbours should be drawn closer in"
        );
    }
}
