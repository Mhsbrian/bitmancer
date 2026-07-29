// src/tui/widgets/main_panel.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use unicode_width::UnicodeWidthChar;

use crate::tui::app::App;
use crate::tui::theme;

/// "HH:MM"
const TIME_WIDTH: usize = 5;
/// Wide enough for most handles, narrow enough to leave the body room.
const SENDER_WIDTH: usize = 12;
/// Gutter between the name and the body, holding the image marker when there
/// is one. Fixed width so marked and unmarked lines stay in the same column.
const MARKER_WIDTH: usize = 3;

/// Right-aligns a name into the sender column, trimming over-long handles from
/// the front so the distinctive tail survives.
///
/// Padding is computed in display columns, not characters: an emoji handle like
/// "👀" occupies two cells, and counting it as one shifts that row's body out
/// of the column.
fn align_sender(name: &str) -> String {
    use unicode_width::UnicodeWidthStr;

    if name.width() <= SENDER_WIDTH {
        return format!("{}{name}", " ".repeat(SENDER_WIDTH - name.width()));
    }

    // Keep the tail, which is the part that distinguishes similar handles.
    let mut tail = String::new();
    for character in name.chars().rev() {
        let mut candidate = String::from(character);
        candidate.push_str(&tail);
        if candidate.width() > SENDER_WIDTH - 1 {
            break;
        }
        tail = candidate;
    }
    let ellipsis = " ".repeat(SENDER_WIDTH - 1 - tail.width());
    format!("{ellipsis}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn short_names_are_padded_to_the_column() {
        assert_eq!(align_sender("bob").width(), SENDER_WIDTH);
        assert!(align_sender("bob").ends_with("bob"));
    }

    #[test]
    fn wide_glyphs_are_measured_in_columns() {
        // Two double-width emoji are four columns, not two characters.
        assert_eq!(align_sender("👀").width(), SENDER_WIDTH);
        assert_eq!(align_sender("👀👀").width(), SENDER_WIDTH);
    }

    #[test]
    fn long_names_keep_their_tail() {
        let aligned = align_sender("averyveryverylonghandle");
        assert_eq!(aligned.width(), SENDER_WIDTH);
        assert!(aligned.contains('…'));
        assert!(aligned.ends_with("handle"), "{aligned}");
    }

    #[test]
    fn empty_names_do_not_panic() {
        assert_eq!(align_sender("").width(), SENDER_WIDTH);
    }
}

/// One line naming the conversation, with the headcount on the right.
pub fn render_context(f: &mut Frame, app: &App, area: Rect) {
    let (_, dm_target, channel_name) = app.get_current_messages();
    let (label, count) = match (dm_target, channel_name) {
        (Some(user), _) => (format!("dm  {user}"), None),
        (_, Some(channel)) if channel == "#public" => ("public".to_string(), None),
        (_, Some(channel)) => (channel.clone(), Some(app.people.len())),
        _ => ("public".to_string(), None),
    };

    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            label,
            Style::default()
                .fg(theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(count) = count.filter(|count| *count > 0) {
        spans.push(Span::styled(
            format!("   {count} here"),
            Style::default().fg(theme::DIM),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub fn render_log(f: &mut Frame, app: &mut App, area: Rect) {
    // No border to subtract now that the log is divided by rules instead.
    app.message_viewport_height = area.height as usize;
    let (messages, _, _) = app.get_current_messages();
    // One column of air on the left so text does not sit against the edge; the
    // scrollbar still uses the full width on the right.
    let messages_area = Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(1),
        ..area
    };

    // --- Message Panel Rendering ---
    let messages_height = app.message_viewport_height;
    let total_messages = messages.len();

    // Calculate visible message range
    let end = total_messages.saturating_sub(app.msg_scroll);
    let start = end.saturating_sub(messages_height);
    let visible_messages = if start < end && !messages.is_empty() {
        &messages[start..end]
    } else {
        &[]
    };

    let nickname = app.nickname.clone();
    // How lit each rendered row is, collected alongside the rows themselves so
    // the gutter beside the text can fade in step with a message that wraps.
    let mut gutter: Vec<f32> = Vec::new();
    let msg_items: Vec<ListItem> = visible_messages.iter().flat_map(|msg| {
        // A line lands lit and cools to the resting palette. Anything that was
        // never new to us reports zero and is drawn exactly as it always was.
        let age = msg.arrived.map(|at| at.elapsed());
        let intensity = age.map(theme::settle_intensity).unwrap_or(0.0);
        // How far the line has come into existence. A line that was never new
        // to us is simply already there.
        let total_chars = msg.content.chars().count();
        let revealed = match age {
            Some(age) => ((theme::reveal_fraction(age) * total_chars as f32).ceil() as usize)
                .max(1)
                .min(total_chars),
            None => total_chars,
        };
        // Steps the resolving cells at about 16fps, independent of the frame
        // rate, so the flicker is the same speed on any terminal.
        let seed = age.map(|age| age.as_millis() as u64 / 60).unwrap_or(0);
        // System lines are chrome, yours are mint, everyone else keeps a stable
        // hue so a busy channel stays legible without turning into confetti.
        let is_system = msg.sender == "system";
        let resting = if is_system {
            theme::DIM
        } else if msg.is_self {
            theme::MINE
        } else {
            theme::speaker_color(&msg.sender)
        };
        let color = theme::arriving(resting, intensity);
        // A line that says your name is the one thing worth interrupting for.
        let is_mention = !msg.is_self && !is_system && msg.content.contains(nickname.as_str());
        let body_resting = if is_mention {
            theme::ALERT
        } else if is_system {
            theme::DIM
        } else {
            theme::TEXT
        };
        let mut body_style = Style::default().fg(theme::arriving(body_resting, intensity));
        if is_mention {
            body_style = body_style.add_modifier(Modifier::BOLD);
        }

        // Names sit in a fixed, right-aligned column so every message body
        // starts on the same character. Ragged left edges are what make a chat
        // log look like a log file.
        let sender = align_sender(&msg.sender);
        let prefix_width = TIME_WIDTH + 1 + SENDER_WIDTH + MARKER_WIDTH;
        // Mark lines that carry a picture. Nothing is fetched to decide this —
        // it is pure text inspection — so the marker costs no network traffic.
        let carries_image = !crate::media::extract_image_urls(&msg.content).is_empty();
        let available_width = messages_area.width.saturating_sub(2) as usize; // Account for borders
        let content_width = available_width.saturating_sub(prefix_width);
        
        let rows: Vec<ListItem> = if content_width == 0 {
            // Fallback if no space for content
            let line = Line::from(vec![
                Span::styled(
                    msg.timestamp.clone(),
                    Style::default().fg(theme::arriving(theme::FAINT, intensity)),
                ),
                Span::raw(" "),
                Span::styled(sender.clone(), Style::default().fg(color)),
                Span::styled(
                    if carries_image { " ▣ " } else { "   " },
                    Style::default().fg(theme::arriving(theme::LIVE, intensity)),
                ),
                Span::styled(msg.content.clone(), body_style),
            ]);
            vec![ListItem::new(line)]
        } else {
            // Split content into lines that fit the available width using character-based operations
            let mut lines = Vec::new();
            let content = &msg.content;
            
            // Convert to character vector for safe operations
            let chars: Vec<char> = content.chars().collect();
            let mut current_pos = 0;
            let mut first_line = true;
            
            while current_pos < chars.len() {
                // Calculate how many characters can fit on this line
                let remaining_chars = chars.len() - current_pos;
                let max_chars_for_line = content_width.min(remaining_chars);
                
                // Find the best break point (prefer space, fallback to character limit)
                let break_point = if max_chars_for_line == remaining_chars {
                    // Last line, take all remaining characters
                    max_chars_for_line
                } else {
                    // Look for the last space in the available range
                    let search_range = &chars[current_pos..current_pos + max_chars_for_line];
                    if let Some(last_space_idx) = search_range.iter().rposition(|&c| c == ' ') {
                        last_space_idx + 1 // +1 to include the space
                    } else {
                        // No space found, break at character limit
                        max_chars_for_line
                    }
                };
                
                // Where this row starts within the whole message, so the sweep
                // can run across a wrapped paragraph as one continuous line.
                let row_start = current_pos;
                // Extract the line content
                let line_chars = &chars[current_pos..current_pos + break_point];
                let line_content: String = line_chars.iter().collect();
                
                // Create the line. The timestamp and the name are structure and
                // hold their columns while the words arrive; only the body
                // sweeps in, or the whole row jitters as it lands.
                if first_line {
                    let mut spans = vec![
                        Span::styled(
                            msg.timestamp.clone(),
                            Style::default().fg(theme::arriving(theme::FAINT, intensity)),
                        ),
                        Span::raw(" "),
                        Span::styled(sender.clone(), Style::default().fg(color)),
                        Span::styled(
                            if carries_image { " ▣ " } else { "   " },
                            Style::default().fg(theme::arriving(theme::LIVE, intensity)),
                        ),
                    ];
                    // Acknowledgement sits in the marker column on our own
                    // lines, where the image glyph would be. A private message
                    // is the only kind anyone acknowledges.
                    if let Some(status) = msg.delivery {
                        spans.pop();
                        spans.push(Span::styled(
                            match status {
                                crate::mesh::DeliveryStatus::Delivered => " ✓ ",
                                crate::mesh::DeliveryStatus::Read => " ✓✓",
                            },
                            Style::default().fg(theme::arriving(theme::MINE, intensity)),
                        ));
                    }
                    spans.extend(reveal_spans(
                        &line_content,
                        row_start,
                        revealed,
                        body_style,
                        seed,
                    ));
                    lines.push(ListItem::new(Line::from(spans)));
                    first_line = false;
                } else {
                    let mut spans = vec![Span::raw(" ".repeat(prefix_width))];
                    spans.extend(reveal_spans(
                        &line_content,
                        row_start,
                        revealed,
                        body_style,
                        seed,
                    ));
                    lines.push(ListItem::new(Line::from(spans)));
                }
                
                // Move to next position, skipping leading spaces on continuation lines
                current_pos += break_point;
                if !first_line && current_pos < chars.len() && chars[current_pos] == ' ' {
                    current_pos += 1; // Skip the space at the beginning of continuation lines
                }
            }
            
            lines
        };
        // The whole block a message occupies carries the mark, not only its
        // first row, so a wrapped paragraph settles as one thing.
        gutter.extend(std::iter::repeat_n(intensity, rows.len()));
        rows
    }).collect();

    // An empty pane says nothing; say what is true instead.
    let msg_items = if msg_items.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no traffic",
            Style::default().fg(theme::FAINT),
        )))]
    } else {
        msg_items
    };
    let list = List::new(msg_items);

    f.render_widget(list, messages_area);

    // The marks sit in the column of air to the left of the text, so arrival
    // reads as motion at the edge of vision without the text itself moving.
    render_arrival_gutter(f, Rect { width: 1, ..area }, &gutter);

    // --- Scroll indicator ---
    let max_scroll = total_messages.saturating_sub(messages_height);
    if total_messages > messages_height {
        let content_length = max_scroll + 1;
        let position = max_scroll.saturating_sub(app.msg_scroll);
        let mut scrollbar_state = ScrollbarState::default()
            .content_length(content_length)
            .viewport_content_length(std::cmp::max(1, content_length / 10))
            .position(position);
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_symbol("▐")
                .track_symbol(None),
            area,
            &mut scrollbar_state,
        );
    }
}


/// Draws the fading marks beside lines that are still settling. Rows that have
/// come to rest draw nothing at all, so the column is empty in a quiet channel.
fn render_arrival_gutter(f: &mut Frame, area: Rect, intensities: &[f32]) {
    if area.width == 0 || !intensities.iter().any(|intensity| *intensity > 0.0) {
        return;
    }
    let lines: Vec<Line> = intensities
        .iter()
        .take(area.height as usize)
        .map(|intensity| match theme::arrival_mark(*intensity) {
            Some((glyph, colour)) => Line::from(Span::styled(glyph, Style::default().fg(colour))),
            None => Line::from(" "),
        })
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}


/// Splits one row of a line into the part that has materialised, the cells
/// still resolving at the leading edge, and nothing at all past it.
///
/// Wrapping is computed on the whole message before any of this, so the sweep
/// never reflows the text it is revealing.
fn reveal_spans(
    text: &str,
    row_start: usize,
    revealed: usize,
    style: Style,
    seed: u64,
) -> Vec<Span<'static>> {
    let chars: Vec<char> = text.chars().collect();
    if revealed >= row_start + chars.len() {
        return vec![Span::styled(text.to_string(), style)];
    }
    if revealed <= row_start {
        // The sweep has not reached this row. It still occupies its height, so
        // the log does not jump as the words catch up.
        return Vec::new();
    }

    let shown = revealed - row_start;
    let resolving_from = shown.saturating_sub(theme::RESOLVING_CELLS);
    let mut spans = Vec::new();
    let settled: String = chars[..resolving_from].iter().collect();
    if !settled.is_empty() {
        spans.push(Span::styled(settled, style));
    }
    for (offset, character) in chars[resolving_from..shown].iter().enumerate() {
        // A double-width glyph standing in for a one-cell block would shift the
        // rest of the row sideways while it resolves, so only single-width
        // cells flicker.
        if character.width().unwrap_or(1) == 1 {
            spans.push(Span::styled(
                theme::resolving_glyph(seed.wrapping_add((resolving_from + offset) as u64)),
                Style::default().fg(theme::LIVE),
            ));
        } else {
            spans.push(Span::styled(character.to_string(), style));
        }
    }
    spans.push(Span::styled(
        theme::FRONTIER,
        Style::default().fg(theme::LIVE),
    ));
    spans
}

#[cfg(test)]
mod reveal_tests {
    use super::*;

    fn text_of(spans: &[Span]) -> String {
        spans.iter().map(|span| span.content.as_ref()).collect()
    }

    #[test]
    fn a_finished_line_is_just_its_text() {
        // Anything else would leave residue on every settled line in the log.
        let spans = reveal_spans("hello there", 0, 11, Style::default(), 0);
        assert_eq!(text_of(&spans), "hello there");
        assert_eq!(spans.len(), 1, "no leftover frontier once it has arrived");
    }

    #[test]
    fn a_row_the_sweep_has_not_reached_is_empty() {
        let spans = reveal_spans("second row", 20, 5, Style::default(), 0);
        assert!(spans.is_empty());
    }

    #[test]
    fn the_leading_edge_carries_the_frontier() {
        let spans = reveal_spans("hello there", 0, 5, Style::default(), 0);
        assert!(text_of(&spans).ends_with(theme::FRONTIER));
        assert_eq!(
            text_of(&spans).chars().count(),
            6,
            "five revealed cells and the edge"
        );
    }

    #[test]
    fn the_sweep_carries_across_a_wrapped_paragraph() {
        // Row two starts at character 20; a sweep at 25 has taken five of it.
        let spans = reveal_spans("second row here", 20, 25, Style::default(), 0);
        assert_eq!(text_of(&spans).chars().count(), 6);
    }

    #[test]
    fn a_wide_glyph_never_resolves_and_so_never_shifts_the_row() {
        // An emoji is two cells; swapping it for a one-cell block mid-sweep
        // would drag the rest of the row sideways and back again.
        let spans = reveal_spans("ab😀cd", 0, 3, Style::default(), 7);
        assert!(
            text_of(&spans).contains('😀'),
            "wide glyphs arrive whole: {}",
            text_of(&spans)
        );
    }
}
