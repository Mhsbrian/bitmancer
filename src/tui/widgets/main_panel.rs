// src/tui/widgets/main_panel.rs

use ratatui::{
    prelude::{Constraint, Direction, Frame, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::tui::app::{App, FocusArea};
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

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Message history
        ])
        .split(area);
    
    let header_area = chunks[0];
    let messages_area = chunks[1];
    
    // Update the viewport height before borrowing `app` for messages
    app.message_viewport_height = messages_area.height.saturating_sub(2) as usize;

    /// A location channel can be full of people and completely silent, so state
    /// the headcount rather than letting an empty message pane imply an empty
    /// room.
    fn channel_header(app: &App, channel: &str) -> String {
        if channel == "#public" {
            return "public".to_string();
        }
        match app.people.len() {
            0 => channel.to_string(),
            1 => format!("{channel}  ·  1 here"),
            count => format!("{channel}  ·  {count} here"),
        }
    }
    
    // Get the current conversation messages
    let (messages, dm_target, channel_name) = app.get_current_messages();
    
    // --- Header Rendering ---
    let header_text = if let Some(user) = dm_target {
        format!("Direct Message with {}", user)
    } else if let Some(channel) = channel_name {
        channel_header(app, &channel)
    } else {
        channel_header(app, &app.get_selected_channel_name())
    };
    let header = Paragraph::new(header_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(theme::panel_title("channel"))
                .border_style(Style::default().fg(theme::CHROME)),
        )
        .style(Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD));
    f.render_widget(header, header_area);

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
    let msg_items: Vec<ListItem> = visible_messages.iter().flat_map(|msg| {
        // System lines are chrome, yours are mint, everyone else keeps a stable
        // hue so a busy channel stays legible without turning into confetti.
        let is_system = msg.sender == "system";
        let color = if is_system {
            theme::DIM
        } else if msg.is_self {
            theme::MINE
        } else {
            theme::speaker_color(&msg.sender)
        };
        // A line that says your name is the one thing worth interrupting for.
        let body_style = if !msg.is_self && !is_system && msg.content.contains(nickname.as_str()) {
            theme::mention()
        } else if is_system {
            Style::default().fg(theme::DIM)
        } else {
            Style::default().fg(theme::TEXT)
        };

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
        
        if content_width == 0 {
            // Fallback if no space for content
            let line = Line::from(vec![
                Span::styled(msg.timestamp.clone(), Style::default().fg(theme::FAINT)),
                Span::raw(" "),
                Span::styled(sender.clone(), Style::default().fg(color)),
                Span::styled(
                    if carries_image { " ▣ " } else { "   " },
                    Style::default().fg(theme::LIVE),
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
                
                // Extract the line content
                let line_chars = &chars[current_pos..current_pos + break_point];
                let line_content: String = line_chars.iter().collect();
                
                // Create the line
                if first_line {
                    let line = Line::from(vec![
                        Span::styled(msg.timestamp.clone(), Style::default().fg(theme::FAINT)),
                        Span::raw(" "),
                        Span::styled(sender.clone(), Style::default().fg(color)),
                        Span::styled(
                            if carries_image { " ▣ " } else { "   " },
                            Style::default().fg(theme::LIVE),
                        ),
                        Span::styled(line_content.clone(), body_style),
                    ]);
                    lines.push(ListItem::new(line));
                    first_line = false;
                } else {
                    let line = Line::from(vec![
                        Span::raw(" ".repeat(prefix_width)),
                        Span::styled(line_content.clone(), body_style),
                    ]);
                    lines.push(ListItem::new(line));
                }
                
                // Move to next position, skipping leading spaces on continuation lines
                current_pos += break_point;
                if !first_line && current_pos < chars.len() && chars[current_pos] == ' ' {
                    current_pos += 1; // Skip the space at the beginning of continuation lines
                }
            }
            
            lines
        }
    }).collect();

    let list = List::new(msg_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(theme::panel_title("log"))
                .border_style(theme::border(app.focus_area == FocusArea::MainPanel)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, messages_area);
    
    // --- Scrollbar Rendering ---
    let max_scroll = total_messages.saturating_sub(messages_height);

    // Fix: Use scroll positions as content length, and invert app.msg_scroll for correct direction
    let (scrollbar_content_length, scrollbar_viewport_length, scrollbar_position) = if total_messages > messages_height {
        let content_length = max_scroll + 1;
        let position = max_scroll.saturating_sub(app.msg_scroll);
        // Set viewport length to a reasonable fraction of the content length for consistent thumb size
        let viewport_length = std::cmp::max(1, content_length / 10);
        (content_length, viewport_length, position)
    } else {
        (1, 1, 0)
    };

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(scrollbar_content_length)
        .viewport_content_length(scrollbar_viewport_length)
        .position(scrollbar_position);

    // Render the scrollbar only if scrolling is actually possible (prevents unnecessary rendering)
    if total_messages > messages_height {
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            messages_area, // Use full area to allow scrollbar to extend to bottom
            &mut scrollbar_state,
        );
    }
}
