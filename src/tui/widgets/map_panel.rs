// src/tui/widgets/map_panel.rs
//
// The world map overlay.
//
// Visual grammar, kept deliberately narrow:
//   - coastlines in dim slate, never competing with data
//   - one hue for life (cyan), scaled by how much of it there is
//   - one accent (magenta) reserved solely for the cursor
//   - structure drawn with thin box glyphs; no fills, no gradients, no art
// Everything else is negative space.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Context, Line as CanvasLine, Map, MapResolution, Rectangle};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::geohash::GridCell;
use crate::tui::app::App;
use crate::tui::map::{MapFocus, MapState};

// The map speaks the same language as the rest of the client; only the two
// map-specific structural tones are local.
use crate::tui::theme::{self, CHROME, CURSOR as ACCENT, DIM as LABEL_DIM, MINE as JOINED, TEXT};
const COAST: Color = theme::FAINT;
/// Grid ticks sit a step below every other structure so they never compete.
const GRID: Color = Color::Rgb(34, 46, 54);

/// Cyan ramp from "someone is here" to "this place is busy".
fn heat_color(voices: usize, peak: usize) -> Color {
    if voices == 0 {
        return GRID;
    }
    let intensity = if peak <= 1 {
        1.0
    } else {
        (voices as f64 / peak as f64).clamp(0.0, 1.0)
    };
    // Perceptual-ish ramp: dim teal to full cyan.
    let low = (60.0, 90.0, 100.0);
    let high = (0.0, 240.0, 255.0);
    let lerp = |a: f64, b: f64| (a + (b - a) * intensity) as u8;
    Color::Rgb(
        lerp(low.0, high.0),
        lerp(low.1, high.1),
        lerp(low.2, high.2),
    )
}

// Column budget for a hotspot row:
//
//   mark │ #geohash │ bar │ count
//
// The panel's width is computed from these rather than chosen alongside them,
// so the two cannot disagree. The first version picked a width by eye and the
// footer was clipped mid-word, which reads as a rendering fault rather than a
// phrase that did not fit.
/// One cell for the cursor mark.
const MARK_COL: usize = 1;
/// A geohash reaches eight characters at the building level, plus the `#`.
const NAME_COL: usize = 9;
/// Cells in a hotspot bar.
const BAR_CELLS: usize = 8;
/// Enough for any crowd one cell will hold.
const COUNT_COL: usize = 4;
/// Everything a row draws, which is what any other text in the panel must fit.
const HOTSPOT_INNER: usize = MARK_COL + NAME_COL + BAR_CELLS + COUNT_COL;
/// The column itself: a row, plus its borders.
const HOTSPOT_WIDTH: u16 = HOTSPOT_INNER as u16 + 2;
/// Below this the map itself would be squeezed into uselessness, and a map too
/// small to read is worse than a list you have to press a key to see.
const HOTSPOT_MIN_CANVAS: u16 = 48;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    // Leave a margin so the map reads as an overlay, not a replacement.
    let overlay = centered(area, 92, 88);
    f.render_widget(Clear, overlay);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // canvas
            Constraint::Length(3), // readout
            Constraint::Length(1), // keys
        ])
        .split(overlay);

    // The list gives up its column before the map gives up its legibility.
    if chunks[0].width >= HOTSPOT_MIN_CANVAS + HOTSPOT_WIDTH {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(HOTSPOT_MIN_CANVAS), Constraint::Length(HOTSPOT_WIDTH)])
            .split(chunks[0]);
        render_canvas(f, app, split[0]);
        render_hotspots(f, app, split[1]);
    } else {
        render_canvas(f, app, chunks[0]);
    }

    render_readout(f, app, chunks[1]);
    render_keys(f, app, chunks[2]);
}

/// A bar `width` cells wide showing `value` against `peak`.
///
/// Eighth-blocks rather than whole ones: the interesting comparisons here are
/// between cells within one order of magnitude, and at eight cells a whole-block
/// bar rounds most of them to the same length.
fn bar(value: usize, peak: usize, width: usize) -> String {
    if value == 0 || peak == 0 || width == 0 {
        return String::new();
    }
    const EIGHTHS: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let filled = (value as f64 / peak as f64).clamp(0.0, 1.0) * width as f64;
    let whole = filled.floor() as usize;
    let mut out: String = "█".repeat(whole.min(width));
    // Anything present at all gets at least a sliver, so "one person here" is
    // never drawn as an empty row.
    if whole < width {
        let remainder = filled - whole as f64;
        let step = (remainder * 8.0).round() as usize;
        if step > 0 {
            out.push(EIGHTHS[(step - 1).min(7)]);
        } else if whole == 0 {
            out.push(EIGHTHS[0]);
        }
    }
    out
}

fn hotspot_footer(talking: usize, total: usize) -> String {
    format!(" chat in {talking} of {total}")
}

/// The busiest channels being sampled, and the way into them.
fn render_hotspots(f: &mut Frame, app: &App, area: Rect) {
    let map = &app.map;
    let ranked = map.top_hotspots();
    let has_keyboard = map.pane == MapFocus::Hotspots;
    let cursor = map.hotspot_cursor();
    // Scaled against the busiest row, not the busiest cell on the grid: this
    // column is a comparison between the places in it.
    let peak = ranked.first().map(|hotspot| hotspot.people).unwrap_or(0);

    let mut lines: Vec<Line> = Vec::new();
    if ranked.is_empty() {
        lines.push(Line::from(Span::styled(
            " listening…",
            Style::default().fg(LABEL_DIM),
        )));
        lines.push(Line::from(Span::styled(
            " nowhere in view is",
            Style::default().fg(LABEL_DIM),
        )));
        lines.push(Line::from(Span::styled(
            " saying anything yet",
            Style::default().fg(LABEL_DIM),
        )));
    }

    for (index, hotspot) in ranked.iter().enumerate() {
        let selected = has_keyboard && index == cursor;
        let joined = app.joined_geohashes.contains(&hotspot.geohash);
        let heat = heat_color(hotspot.people, peak);

        // The cursor is the one thing allowed to use the accent, so a row that
        // is merely joined is tinted rather than highlighted.
        let name_style = if selected {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else if joined {
            Style::default().fg(JOINED)
        } else {
            Style::default().fg(TEXT)
        };

        lines.push(Line::from(vec![
            Span::styled(
                if selected { "▸" } else { " " },
                Style::default().fg(ACCENT),
            ),
            Span::styled(
                format!("#{:<width$}", hotspot.geohash, width = NAME_COL - 1),
                name_style,
            ),
            Span::styled(
                format!(
                    "{:<width$}",
                    bar(hotspot.people, peak, BAR_CELLS),
                    width = BAR_CELLS
                ),
                Style::default().fg(heat),
            ),
            Span::styled(
                format!("{:>width$}", hotspot.people, width = COUNT_COL),
                Style::default().fg(heat),
            ),
        ]));
    }

    // Said once, under the list, rather than per row: the distinction between
    // being somewhere and talking there is the readout's job, and repeating it
    // eight times would bury the ranking it qualifies. Kept short enough to fit
    // the column — a footer clipped mid-word reads as a rendering fault.
    let talking = ranked.iter().filter(|hotspot| hotspot.messages > 0).count();
    if !ranked.is_empty() {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            hotspot_footer(talking, ranked.len()),
            Style::default().fg(LABEL_DIM),
        )));
    }

    let title = if has_keyboard {
        Span::styled(
            " HOTSPOTS ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" HOTSPOTS ", Style::default().fg(LABEL_DIM))
    };

    let panel = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if has_keyboard { ACCENT } else { CHROME }))
            .title(Line::from(title)),
    );
    f.render_widget(panel, area);
}

fn render_canvas(f: &mut Frame, app: &App, area: Rect) {
    let map = &app.map;
    let view = map.viewport();
    let peak = map.peak_activity();
    let selected = map.selected_geohash().to_string();
    let cells: Vec<GridCell> = map.cells().to_vec();

    let title = title_line(map);
    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CHROME))
                .title(title),
        )
        .marker(Marker::Braille)
        .x_bounds([view.lon_min, view.lon_max])
        .y_bounds([view.lat_min, view.lat_max])
        .paint(move |ctx: &mut Context| {
            // Layer 1: the world, quiet.
            ctx.draw(&Map {
                color: COAST,
                resolution: MapResolution::High,
            });

            // Layer 2: the lattice. Drawn as shared edges rather than 32
            // rectangles, so cell borders are one line thick instead of two
            // and the coastlines stay legible underneath.
            ctx.layer();
            let mut lons: Vec<f64> = Vec::new();
            let mut lats: Vec<f64> = Vec::new();
            for cell in &cells {
                for value in [cell.bbox.lon_min, cell.bbox.lon_max] {
                    if !lons.iter().any(|existing| (existing - value).abs() < 1e-9) {
                        lons.push(value);
                    }
                }
                for value in [cell.bbox.lat_min, cell.bbox.lat_max] {
                    if !lats.iter().any(|existing| (existing - value).abs() < 1e-9) {
                        lats.push(value);
                    }
                }
            }
            // Registration ticks at the intersections rather than full rules:
            // continuous lines cage the map and bury the coastlines, while
            // ticks imply the same grid and leave the world visible.
            let tick_lon = (view.lon_max - view.lon_min) / 90.0;
            let tick_lat = (view.lat_max - view.lat_min) / 60.0;
            for lon in &lons {
                for lat in &lats {
                    ctx.draw(&CanvasLine {
                        x1: lon - tick_lon,
                        y1: *lat,
                        x2: lon + tick_lon,
                        y2: *lat,
                        color: GRID,
                    });
                    ctx.draw(&CanvasLine {
                        x1: *lon,
                        y1: lat - tick_lat,
                        x2: *lon,
                        y2: lat + tick_lat,
                        color: GRID,
                    });
                }
            }

            // Layer 3: life. Drawn as a node centred in the cell rather than an
            // outline around it — neighbouring active cells would otherwise
            // share edges and merge back into the heavy rules we just removed.
            // The node grows with the traffic, so the map reads at a glance.
            ctx.layer();
            for cell in &cells {
                let voices = app
                    .map
                    .activity(&cell.geohash)
                    .map(|a| a.people())
                    .unwrap_or(0);
                let joined = app.joined_geohashes.contains(&cell.geohash);
                if voices == 0 && !joined {
                    continue;
                }
                let loudness = if peak <= 1 {
                    1.0
                } else {
                    (voices as f64 / peak as f64).clamp(0.0, 1.0)
                };
                // 20% of the cell when barely alive, 60% when it is the peak.
                let scale = 0.20 + 0.40 * loudness.sqrt();
                let width = cell.bbox.width() * scale;
                let height = cell.bbox.height() * scale;
                let (lat, lon) = cell.bbox.center();
                ctx.draw(&Rectangle {
                    x: lon - width / 2.0,
                    y: lat - height / 2.0,
                    width,
                    height,
                    color: if joined { JOINED } else { heat_color(voices, peak) },
                });
            }

            // Layer 4: the cursor, alone in its colour.
            ctx.layer();
            if let Some(cell) = cells.iter().find(|cell| cell.geohash == selected) {
                ctx.draw(&Rectangle {
                    x: cell.bbox.lon_min,
                    y: cell.bbox.lat_min,
                    width: cell.bbox.width(),
                    height: cell.bbox.height(),
                    color: ACCENT,
                });
            }

            // Layer 5: labels. Only where they can be read — a 32-cell world
            // grid at 80 columns cannot hold 32 labels without becoming soup,
            // so they appear once cells are wide enough.
            ctx.layer();
            let span_degrees = view.lon_max - view.lon_min;
            let label_budget = span_degrees / 12.0;
            for cell in &cells {
                if cell.bbox.width() < label_budget {
                    continue;
                }
                let (lat, lon) = cell.bbox.center();
                let voices = app
                    .map
                    .activity(&cell.geohash)
                    .map(|a| a.people())
                    .unwrap_or(0);
                let is_selected = cell.geohash == selected;
                let last = cell.geohash.chars().last().unwrap_or(' ');
                let text = if voices > 0 {
                    format!("{last}·{voices}")
                } else {
                    last.to_string()
                };
                let style = if is_selected {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else if app.joined_geohashes.contains(&cell.geohash) {
                    Style::default().fg(JOINED)
                } else if voices > 0 {
                    Style::default().fg(heat_color(voices, peak))
                } else {
                    Style::default().fg(LABEL_DIM)
                };
                ctx.print(lon, lat, Span::styled(text, style));
            }
        });

    f.render_widget(canvas, area);
}

fn title_line(map: &MapState) -> Line<'static> {
    let focus = if map.focus().is_empty() {
        "world".to_string()
    } else {
        format!("#{}", map.focus())
    };
    let level = map
        .level_label()
        .map(|label| format!(" · {label}"))
        .unwrap_or_default();

    Line::from(vec![
        Span::styled(" MAP ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(focus, Style::default().fg(TEXT)),
        Span::styled(level, Style::default().fg(LABEL_DIM)),
        Span::styled(
            format!(" · z{} ", map.precision()),
            Style::default().fg(CHROME),
        ),
    ])
}

fn render_readout(f: &mut Frame, app: &App, area: Rect) {
    let map = &app.map;
    let cell = map.selected();
    let (lat, lon) = cell.bbox.center();
    let activity = map.activity(&cell.geohash);
    let voices = activity.map(|a| a.people()).unwrap_or(0);
    let messages = activity.map(|a| a.messages).unwrap_or(0);
    let joined = app.joined_geohashes.contains(&cell.geohash);

    // "here" and "talking" are different things: a cell can hold two dozen
    // people who are all idle, and saying so up front avoids joining an
    // occupied but silent room expecting conversation.
    let status = if voices > 0 {
        Span::styled(
            format!(
                "{voices} here · {}",
                if messages > 0 {
                    format!("{messages} talking")
                } else {
                    "no chat yet".to_string()
                }
            ),
            Style::default().fg(heat_color(voices, map.peak_activity())),
        )
    } else if joined {
        Span::styled("joined", Style::default().fg(JOINED))
    } else {
        Span::styled("quiet", Style::default().fg(LABEL_DIM))
    };

    let level = crate::geohash::level_name(cell.geohash.chars().count())
        .map(|name| format!("{name} level"))
        .unwrap_or_else(|| "between levels".to_string());

    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!("#{}", cell.geohash),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   ", Style::default()),
            status,
        ]),
        Line::from(vec![Span::styled(
            format!(
                "{lat:>7.2}, {lon:>8.2}   {level}   {} of {} cells live",
                map.live_cells(),
                map.cells().len()
            ),
            Style::default().fg(LABEL_DIM),
        )]),
    ];

    let readout = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(CHROME)),
    );
    f.render_widget(readout, area);
}

fn render_keys(f: &mut Frame, app: &App, area: Rect) {
    let key = |text: String| Span::styled(text, Style::default().fg(TEXT));
    let hint = |text: String| Span::styled(text, Style::default().fg(LABEL_DIM));

    // Enter changes meaning with the level and with which pane has the
    // keyboard, so say which one it is rather than making the user discover it
    // by pressing.
    let on_list = app.map.pane == MapFocus::Hotspots;
    let enter_action = if on_list {
        match app.map.selected_hotspot() {
            Some(hotspot) => Span::styled(
                format!(" go to #{}  ", hotspot.geohash),
                Style::default().fg(JOINED),
            ),
            None => hint(" go  ".to_string()),
        }
    } else if app.map.level_label().is_some() || !app.map.can_drill_in() {
        Span::styled(
            format!(" enter #{}  ", app.map.selected_geohash()),
            Style::default().fg(JOINED),
        )
    } else {
        hint(" zoom in  ".to_string())
    };

    let mut spans = vec![
        hint(" ".to_string()),
        key("↑↓".to_string()),
    ];
    if on_list {
        spans.push(hint(" pick  ".to_string()));
    } else {
        spans.push(key("←→".to_string()));
        spans.push(hint(" move  ".to_string()));
    }
    spans.extend([
        key("⏎".to_string()),
        enter_action,
        key("tab".to_string()),
        hint(
            if on_list {
                " back to map  ".to_string()
            } else {
                " hotspots  ".to_string()
            },
        ),
    ]);
    if !on_list {
        spans.extend([
            key("+".to_string()),
            hint("/".to_string()),
            key("-".to_string()),
            hint(" zoom  ".to_string()),
        ]);
    }
    spans.extend([
        key("esc".to_string()),
        hint(" back  ".to_string()),
        key("q".to_string()),
        hint(" close".to_string()),
    ]);
    let line = Line::from(spans);

    f.render_widget(
        Paragraph::new(line)
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT).border_style(Style::default().fg(CHROME))),
        area,
    );
}

/// Centred rectangle sized as a percentage of the area.
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
    fn everything_in_the_panel_fits_the_column() {
        // The footer shipped two words too long and was clipped mid-word,
        // which looks like a bug in the renderer rather than a phrase that did
        // not fit. Widths are cheap to assert and impossible to eyeball.
        for (talking, total) in [(0, 8), (8, 8), (1, 8)] {
            let footer = hotspot_footer(talking, total);
            assert!(
                footer.chars().count() <= HOTSPOT_INNER,
                "footer {footer:?} is {} wide, column is {HOTSPOT_INNER}",
                footer.chars().count()
            );
        }

        // The longest name the map can reach still fits its column: a geohash
        // runs to eight characters at the building level, plus the '#'.
        let longest = format!("#{}", "9q8yyk8n");
        assert!(longest.chars().count() <= NAME_COL, "{longest} overflows its column");
    }

    #[test]
    fn the_empty_state_fits_too() {
        for line in [" listening…", " nowhere in view is", " saying anything yet"] {
            assert!(
                line.chars().count() <= HOTSPOT_INNER,
                "{line:?} does not fit"
            );
        }
    }

    #[test]
    fn a_bar_is_proportional_and_never_overflows_its_width() {
        // The width is a column budget, not a suggestion: a bar one cell too
        // long wraps the row and shears the whole list.
        for value in [0, 1, 3, 7, 8, 50, 1000] {
            let drawn = bar(value, 8, BAR_CELLS);
            assert!(
                drawn.chars().count() <= BAR_CELLS,
                "{value} drew {} cells",
                drawn.chars().count()
            );
        }
        assert_eq!(bar(8, 8, BAR_CELLS).chars().count(), BAR_CELLS, "the peak fills it");
    }

    #[test]
    fn a_single_voice_is_still_drawn() {
        // One person in a cell against a peak of two hundred rounds to nothing
        // in whole blocks. An empty row reads as silence, which is the one
        // thing it is not.
        let drawn = bar(1, 200, BAR_CELLS);
        assert!(!drawn.is_empty(), "presence must be visible at any scale");
    }

    #[test]
    fn nothing_is_drawn_for_nothing() {
        assert_eq!(bar(0, 10, BAR_CELLS), "");
        assert_eq!(bar(5, 0, BAR_CELLS), "", "no peak means no scale to draw against");
        assert_eq!(bar(5, 10, 0), "");
    }

    #[test]
    fn bars_grow_with_the_value() {
        // Not strictly required by anything, which is why it is worth pinning:
        // a ranking drawn with bars that do not order the same way as the
        // numbers beside them is actively misleading.
        let widths: Vec<usize> = [1, 2, 4, 8]
            .iter()
            .map(|value| bar(*value, 8, BAR_CELLS).chars().count())
            .collect();
        assert!(
            widths.windows(2).all(|pair| pair[0] <= pair[1]),
            "bars must not shrink as the count rises: {widths:?}"
        );
    }

    #[test]
    fn heat_ramps_from_grid_to_cyan() {
        assert_eq!(heat_color(0, 10), GRID, "silence is not coloured");
        let quiet = heat_color(1, 10);
        let loud = heat_color(10, 10);
        assert_ne!(quiet, loud);
        // The loud end is the full accent cyan.
        assert_eq!(loud, Color::Rgb(0, 240, 255));
    }

    #[test]
    fn a_lone_voice_is_fully_lit_when_it_is_the_peak() {
        assert_eq!(heat_color(1, 1), Color::Rgb(0, 240, 255));
    }

    #[test]
    fn centered_rect_stays_inside_its_area() {
        let area = Rect::new(0, 0, 100, 40);
        let inner = centered(area, 90, 80);
        assert!(inner.width <= area.width && inner.height <= area.height);
        assert!(inner.x >= area.x && inner.y >= area.y);
        assert!(inner.right() <= area.right() && inner.bottom() <= area.bottom());
    }
}
