
// src/tui/widgets/sidebar.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::tui::app::{App, FocusArea};

// Helper to calculate what items are visible for navigation
pub fn sidebar_visible_items(app: &App) -> Vec<(usize, Option<usize>)> {
    let mut items = Vec::new();
    for section in 0..5 { // Now 5 sections: Public, Channels, People, Blocked, Settings
        items.push((section, None)); // Section header
        if app.sidebar_state.expanded[section] {
            let count = match section {
                0 => 1, // Public: always 1 item
                1 => app.channels.len(),
                2 => app.people.len(),
                3 => app.blocked.len(),
                4 => 2, // Settings: Nickname, Network
                _ => 0,
            };
            for idx in 0..count {
                items.push((section, Some(idx)));
            }
        }
    }
    items
}


pub fn render(f: &mut Frame, app: &App, area: Rect) {
    use crate::tui::theme;

    let mut items: Vec<ListItem> = Vec::new();
    let section_titles = ["public", "channels", "people", "blocked", "system"];
    let focused = app.focus_area == FocusArea::Sidebar;
    let mut flat_idx = 0;

    // Selection is a gutter mark, not a filled bar: an inverse-video block
    // reads as a spreadsheet cell, a bar reads as a cursor.
    let gutter = |selected: bool, active: bool| {
        if selected && focused {
            Span::styled(theme::GUTTER_CURSOR, Style::default().fg(theme::CURSOR))
        } else if active {
            Span::styled(theme::GUTTER_ACTIVE, Style::default().fg(theme::MINE))
        } else {
            Span::raw(theme::GUTTER_EMPTY)
        }
    };

    for (i, section_title) in section_titles.iter().enumerate() {
        let is_selected = app.sidebar_flat_selected == flat_idx;
        let unread_count = app.get_section_unread_count(i);

        let marker = if app.sidebar_state.expanded[i] {
            theme::OPEN
        } else {
            theme::CLOSED
        };
        let mut spans = vec![
            gutter(is_selected, false),
            Span::styled(
                format!("{marker} "),
                Style::default().fg(if is_selected && focused {
                    theme::CURSOR
                } else {
                    theme::FAINT
                }),
            ),
            Span::styled(
                section_title.to_uppercase(),
                Style::default().fg(if is_selected && focused {
                    theme::TEXT
                } else {
                    theme::DIM
                }),
            ),
        ];
        if unread_count > 0 {
            spans.push(Span::styled(" ·", Style::default().fg(theme::ALERT)));
        }
        items.push(ListItem::new(Line::from(spans)));
        flat_idx += 1;

        if app.sidebar_state.expanded[i] {
            let list: Vec<(&str, Color, bool)> = match i {
                0 => vec![(
                    "public",
                    theme::TEXT,
                    app.sidebar_state.public_selected.unwrap_or(false),
                )],
                1 => app
                    .channels
                    .iter()
                    .enumerate()
                    .map(|(idx, s)| {
                        (
                            s.as_str(),
                            theme::MINE,
                            app.sidebar_state.channel_selected == Some(idx),
                        )
                    })
                    .collect(),
                2 => app
                    .people
                    .iter()
                    .enumerate()
                    .map(|(idx, s)| {
                        (
                            s.as_str(),
                            theme::speaker_color(s),
                            app.sidebar_state.people_selected == Some(idx),
                        )
                    })
                    .collect(),
                3 => app
                    .blocked
                    .iter()
                    .map(|s| (s.as_str(), theme::FAULT, false))
                    .collect(),
                _ => vec![],
            };

            for (item_str, color, is_active_conv) in list {
                let is_selected = app.sidebar_flat_selected == flat_idx;
                let unread_count = match i {
                    0 => app.get_unread_count("#public"),
                    1 => app.get_unread_count(item_str),
                    2 => app.get_unread_count(&format!("dm:{item_str}")),
                    _ => 0,
                };

                let text_style = if is_selected && focused {
                    Style::default().fg(theme::TEXT).bold()
                } else if is_active_conv {
                    Style::default().fg(color).bold()
                } else {
                    Style::default().fg(color)
                };

                let mut spans = vec![
                    gutter(is_selected, is_active_conv),
                    Span::raw("  "),
                    Span::styled(item_str.to_string(), text_style),
                ];
                if unread_count > 0 {
                    spans.push(Span::styled(
                        format!(" ·{unread_count}"),
                        Style::default().fg(theme::ALERT),
                    ));
                }
                items.push(ListItem::new(Line::from(spans)));
                flat_idx += 1;
            }

            if i == 4 {
                let is_selected = app.sidebar_flat_selected == flat_idx;
                items.push(ListItem::new(Line::from(vec![
                    gutter(is_selected, false),
                    Span::raw("  "),
                    Span::styled("nick ", Style::default().fg(theme::DIM)),
                    Span::styled(app.nickname.clone(), Style::default().fg(theme::TEXT)),
                ])));
                flat_idx += 1;

                let is_selected = app.sidebar_flat_selected == flat_idx;
                let (label, style) = if app.connected {
                    ("online", Style::default().fg(theme::MINE))
                } else {
                    ("offline", Style::default().fg(theme::FAULT))
                };
                items.push(ListItem::new(Line::from(vec![
                    gutter(is_selected, false),
                    Span::raw("  "),
                    Span::styled("mesh ", Style::default().fg(theme::DIM)),
                    Span::styled(label, style),
                ])));
                flat_idx += 1;
            }
        }
    }

    // No box: the column is already bounded by the hairline to its left, and
    // the heading carries focus by brightness.
    let mut rows = vec![ListItem::new(Line::from(vec![
        Span::raw(" "),
        theme::section("nav", focused),
    ]))];
    rows.extend(items);
    f.render_widget(List::new(rows), area);
}
