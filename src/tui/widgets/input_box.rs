
// src/tui/widgets/input_box.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    use crate::tui::theme;

    let focused = app.focus_area == FocusArea::InputBox;

    // Create wrapped text for the input
    let input_text = app.input.value();
    let available_width = area.width.saturating_sub(2) as usize; // Account for borders

    // Split text into lines based on available width
    let lines = wrap_text(input_text, available_width);

    // Name the destination rather than saying "type a message": in a client
    // with two networks and several channels, where the text is about to go is
    // the only thing worth putting in the chrome.
    let destination = app
        .current_conv
        .as_ref()
        .and_then(|(dm, channel)| {
            dm.as_ref()
                .map(|user| format!("→ {user}"))
                .or_else(|| channel.as_ref().map(|name| format!("→ {name}")))
        })
        .unwrap_or_else(|| "→ public".to_string());

    // A prompt, not a box: the rule above already separates it from the log,
    // and the destination belongs next to what you are typing rather than in a
    // border title.
    let prompt = Span::styled(
        "▌ ",
        Style::default().fg(if focused { theme::CURSOR } else { theme::FAINT }),
    );
    let mut rendered: Vec<Line> = Vec::with_capacity(lines.len());
    for (index, line) in lines.into_iter().enumerate() {
        let mut spans = vec![if index == 0 {
            prompt.clone()
        } else {
            Span::raw("  ")
        }];
        if index == 0 && line.spans.iter().all(|span| span.content.is_empty()) {
            // Empty compose line: say where it would go rather than nothing.
            spans.push(Span::styled(
                destination.clone(),
                Style::default().fg(theme::FAINT),
            ));
        } else {
            spans.extend(line.spans);
        }
        rendered.push(Line::from(spans));
    }

    f.render_widget(
        Paragraph::new(rendered).style(Style::default().fg(theme::TEXT)),
        area,
    );

    // Calculate cursor position for multi-line input
    // The character index, not the visual width: the column is computed from the
    // same rows the text is drawn in.
    let (cursor_line, cursor_col) =
        calculate_cursor_position(input_text, app.input.cursor(), available_width);
    
    // Two columns for the prompt glyph, no border row to skip.
    f.set_cursor(area.x + cursor_col as u16 + 2, area.y + cursor_line as u16);
}

/// One grapheme cluster: how many `char`s it spans, and how wide it draws.
///
/// The cluster is the unit, not the character, and that is the whole fix. An
/// emoji is frequently several characters — ❤️ is a heart plus an invisible
/// selector, 👨‍👩‍👧‍👦 is seven joined by zero-width joiners — and summing per-character
/// widths gets both wrong in opposite directions: 1 instead of 2 for the first,
/// 8 instead of 2 for the second. Measured whole, `unicode-width` answers both
/// correctly, so the text is walked in the units it can actually measure.
struct Cluster {
    chars: usize,
    width: usize,
    newline: bool,
    space: bool,
}

fn clusters(text: &str) -> Vec<Cluster> {
    UnicodeSegmentation::graphemes(text, true)
        .map(|cluster| Cluster {
            chars: cluster.chars().count(),
            width: UnicodeWidthStr::width(cluster),
            newline: cluster == "\n",
            space: cluster == " ",
        })
        .collect()
}

/// Character ranges, one per visual row, at a given width.
///
/// The single source of truth for where the compose text breaks. The rendered
/// rows and the cursor both come from this, because they have to agree — three
/// separate measurements is how the cursor ended up a cell to the left of the
/// text after every emoji.
///
/// Rows break between clusters, never inside one, so a family emoji cannot be
/// torn into its constituent people at the edge of the box.
fn wrap_rows(text: &str, max_width: usize) -> Vec<std::ops::Range<usize>> {
    let units = clusters(text);
    let total_chars: usize = units.iter().map(|unit| unit.chars).sum();
    if units.is_empty() || max_width == 0 {
        // One row holding everything. Bound to a name because `vec![0..n]` reads
        // as a range someone meant to expand into elements.
        let single_row = 0..total_chars;
        return vec![single_row];
    }

    // Character offset of each cluster, so a break expressed in clusters can be
    // reported in the character indices everything else speaks.
    let mut offsets = Vec::with_capacity(units.len() + 1);
    let mut running = 0usize;
    for unit in &units {
        offsets.push(running);
        running += unit.chars;
    }
    offsets.push(running);

    let mut rows = Vec::new();
    let mut row_start = 0usize; // cluster index
    let mut width = 0usize;
    // The last cluster boundary that falls between words, so a row ends there
    // rather than mid-word when there is a choice.
    let mut last_space: Option<usize> = None;
    let mut index = 0usize;

    while index < units.len() {
        let unit = &units[index];
        if unit.newline {
            rows.push(offsets[row_start]..offsets[index]);
            index += 1;
            row_start = index;
            width = 0;
            last_space = None;
            continue;
        }

        // Checked before the cluster is placed, so a two-cell glyph that will
        // not fit starts the next row rather than straddling the edge — which a
        // terminal renders by pushing everything after it along by a cell.
        if width + unit.width > max_width && index > row_start {
            let break_at = last_space.filter(|at| *at > row_start).unwrap_or(index);
            rows.push(offsets[row_start]..offsets[break_at]);
            row_start = break_at;
            width = units[break_at..index].iter().map(|unit| unit.width).sum();
            last_space = None;
        }

        if unit.space {
            last_space = Some(index + 1);
        }
        width += unit.width;
        index += 1;
    }
    rows.push(offsets[row_start]..total_chars);
    rows
}

/// The text laid out into rows.
fn wrap_text(text: &str, max_width: usize) -> Vec<ratatui::text::Line<'static>> {
    let chars: Vec<char> = text.chars().collect();
    wrap_rows(text, max_width)
        .into_iter()
        .map(|row| ratatui::text::Line::from(chars[row].iter().collect::<String>()))
        .collect()
}

/// Where the cursor belongs, as a row and a column in cells.
///
/// `cursor_chars` is a *character* index — `Input::cursor()`, not
/// `visual_cursor()`. The column is measured from the same rows the text is
/// drawn in, so the two cannot drift apart. Passing a width in as though it were
/// a character count, and then counting each character as one cell, is exactly
/// the pair of mistakes that cancelled for ASCII and compounded for emoji.
fn calculate_cursor_position(text: &str, cursor_chars: usize, max_width: usize) -> (usize, usize) {
    let total_chars = text.chars().count();
    let cursor_chars = cursor_chars.min(total_chars);
    let rows = wrap_rows(text, max_width);

    for (line, row) in rows.iter().enumerate() {
        let last = line + 1 == rows.len();
        if cursor_chars < row.end || (last && cursor_chars <= row.end) {
            // Clusters entirely before the cursor. A cursor that has landed
            // inside one — which character-wise editing can do to ❤️ — counts
            // from the cluster's start rather than inventing a column inside a
            // glyph that occupies no such position on screen.
            let row_text: String = text
                .chars()
                .skip(row.start)
                .take(row.end - row.start)
                .collect();
            let mut column = 0usize;
            let mut at = row.start;
            for cluster in clusters(&row_text) {
                if at + cluster.chars > cursor_chars {
                    break;
                }
                column += cluster.width;
                at += cluster.chars;
            }
            return (line, column);
        }
    }
    (rows.len().saturating_sub(1), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the cursor is drawn, and where the text actually ends. These must
    /// be the same number — the bug was that they were not.
    fn column_after(text: &str) -> (usize, usize) {
        let drawn = calculate_cursor_position(text, text.chars().count(), 40).1;
        let actual = UnicodeWidthStr::width(text);
        (drawn, actual)
    }

    #[test]
    fn the_cursor_lands_where_the_text_ends() {
        // The reported bug: an emoji is one character and two cells, so counting
        // characters left the cursor one cell behind for every emoji typed.
        for text in [
            "hello",
            "ship it 🔥",
            "🔥",
            "🔥🔥🔥",
            "a 🔥 b 🎉 c",
            "❤️ and 👍",
            "done ✅ next",
        ] {
            let (drawn, actual) = column_after(text);
            assert_eq!(drawn, actual, "cursor drifted on {text:?}");
        }
    }

    #[test]
    fn an_emoji_costs_two_cells_not_one() {
        // Stated directly, because it is the fact the old code got wrong.
        assert_eq!(column_after("🔥").1, 2);
        assert_eq!(calculate_cursor_position("🔥", 1, 40), (0, 2));
    }

    #[test]
    fn a_variation_selector_adds_no_column_of_its_own() {
        // ❤️ is a heart plus an invisible selector: two characters, two cells.
        // Counting characters would have put the cursor a cell too far right
        // here — the opposite drift, on the same line as the other kind.
        assert_eq!("❤️".chars().count(), 2);
        assert_eq!(column_after("❤️").1, 2);
        assert_eq!(calculate_cursor_position("❤️", 2, 40), (0, 2));
    }

    #[test]
    fn the_cursor_can_sit_before_an_emoji_as_well_as_after() {
        // Moving left through a message must not skip cells or double-count.
        let text = "ab🔥cd";
        assert_eq!(calculate_cursor_position(text, 0, 40), (0, 0));
        assert_eq!(calculate_cursor_position(text, 2, 40), (0, 2), "before the emoji");
        assert_eq!(calculate_cursor_position(text, 3, 40), (0, 4), "after it");
        assert_eq!(calculate_cursor_position(text, 5, 40), (0, 6), "at the end");
    }

    #[test]
    fn a_joined_emoji_is_two_cells_not_eight() {
        // 👨‍👩‍👧‍👦 is seven characters joined by zero-width joiners. Summing per
        // character gave 8 and pushed everything after it four cells right;
        // measured as one cluster it is 2, which is what a terminal draws.
        let family = "👨‍👩‍👧‍👦";
        assert_eq!(family.chars().count(), 7);
        assert_eq!(column_after(family), (2, 2));
    }

    #[test]
    fn wrapping_never_splits_an_emoji() {
        // Breaking inside a cluster turns one family into four people and a
        // stray joiner — visible corruption of what someone typed.
        let text = "👨‍👩‍👧‍👦👨‍👩‍👧‍👦👨‍👩‍👧‍👦";
        let chars: Vec<char> = text.chars().collect();
        for row in wrap_rows(text, 5) {
            let drawn: String = chars[row].iter().collect();
            assert!(
                !drawn.starts_with('\u{200d}') && !drawn.ends_with('\u{200d}'),
                "row {drawn:?} was cut through a joiner"
            );
        }
    }

    #[test]
    fn rows_never_exceed_the_width_they_were_given() {
        // A row wider than its column pushes everything after it along by a cell,
        // which is the same failure as the cursor drift wearing a different hat.
        let width = 12;
        for text in [
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥",
            "some words 🎉 and more 🔥 text here",
            "❤️❤️❤️❤️❤️❤️❤️",
        ] {
            let chars: Vec<char> = text.chars().collect();
            for row in wrap_rows(text, width) {
                let drawn = chars[row.clone()].iter().collect::<String>().width();
                assert!(
                    drawn <= width,
                    "row {row:?} of {text:?} draws {drawn} cells into {width}"
                );
            }
        }
    }

    #[test]
    fn wrapping_covers_every_character_exactly_once() {
        // Rows are ranges into the same string the cursor is measured against, so
        // a gap or an overlap would put the cursor on the wrong row.
        for text in ["hello world this wraps", "🔥 a 🎉 b", "no-spaces-at-all-here"] {
            let rows = wrap_rows(text, 8);
            let mut covered = 0usize;
            for row in &rows {
                assert!(row.start <= row.end);
                assert_eq!(row.start, covered, "gap or overlap in {text:?}");
                covered = row.end;
            }
            assert_eq!(covered, text.chars().count());
        }
    }

    #[test]
    fn the_drawn_rows_match_the_ranges() {
        let text = "wrap this line 🔥 please";
        let rows = wrap_rows(text, 10);
        let drawn = wrap_text(text, 10);
        assert_eq!(rows.len(), drawn.len());
        let rejoined: String = drawn
            .iter()
            .flat_map(|line| line.spans.iter().map(|span| span.content.to_string()))
            .collect();
        assert_eq!(rejoined, text, "the rows must reassemble into the message");
    }

    #[test]
    fn a_glyph_wider_than_the_column_still_appears() {
        // Otherwise the layout loops forever looking for somewhere it fits.
        let rows = wrap_rows("🔥", 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], 0..1);
    }

    #[test]
    fn empty_and_degenerate_inputs_do_not_panic() {
        assert_eq!(calculate_cursor_position("", 0, 40), (0, 0));
        let _ = calculate_cursor_position("hi", 99, 40);
        let _ = wrap_rows("hello", 0);
        let _ = wrap_text("", 40);
    }

    #[test]
    fn a_newline_starts_a_row() {
        let rows = wrap_rows("ab\ncd", 40);
        assert_eq!(rows.len(), 2);
        assert_eq!(calculate_cursor_position("ab\ncd", 5, 40), (1, 2));
    }
}
