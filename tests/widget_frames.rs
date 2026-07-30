// tests/widget_frames.rs
//
// The four render paths with no coverage at all: `tui/ui.rs`, and the `popup`,
// `sidebar` and `help_bar` widgets. 689 regions between them, none of which
// needs a radio, a relay or a terminal — `ratatui::backend::TestBackend` draws
// into an in-memory buffer, so a frame can be rendered and read back.
//
// These assert properties of the rendered buffer rather than whole-frame
// snapshots, deliberately. A golden frame over a TUI under active development
// gets a wrong-looking diff, a glance, and a blind update — which converts the
// test from a guard into a rubber stamp. Properties that state *why* they hold
// survive a layout change that a byte-exact frame would not, and fail for
// reasons someone can act on.
//
// The class that matters most is the degenerate size. ratatui panics when a
// layout is handed an area it cannot fit, and every one of these widgets does
// arithmetic on the `Rect` it is given — percentages, borders, splits. There is
// already precedent that this is the live risk here:
// `tui::widgets::mesh_panel::tests::a_tiny_terminal_does_not_panic`. This
// generalises it across the widgets that had nothing.

use bitmancer::tui::app::{App, FocusArea};
use bitmancer::tui::widgets::{help_bar, popup, sidebar};
use ratatui::{backend::TestBackend, prelude::Rect, Terminal};

fn app() -> App {
    App::new_with_nickname("tester".to_string())
}

/// Renders one widget at `width`x`height` and returns the buffer as lines of
/// text, so an assertion can talk about what is on screen rather than about
/// cells and styles.
fn frame_of<F>(width: u16, height: u16, mut draw: F) -> Vec<String>
where
    F: FnMut(&mut ratatui::Frame, Rect),
{
    let mut terminal =
        Terminal::new(TestBackend::new(width, height)).expect("TestBackend needs no real terminal");
    terminal
        .draw(|f| {
            let area = f.size();
            draw(f, area);
        })
        .expect("drawing into a buffer cannot fail for want of a terminal");

    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer.get(x, y).symbol().to_string())
                .collect::<String>()
        })
        .collect()
}

/// Sizes a terminal can genuinely be, including the ones that break layout
/// arithmetic: a single cell, one column, one row, and an ordinary window.
const DEGENERATE: &[(u16, u16)] = &[
    (1, 1),
    (1, 40),
    (40, 1),
    (2, 2),
    (3, 3),
    (10, 4),
    (80, 24),
    (200, 60),
];

#[test]
fn the_help_bar_survives_every_size_and_every_focus() {
    // The strip changes with focus, so each branch is a separate render path and
    // each gets tried at every size. A panic here takes the whole client down,
    // because this draws on every frame.
    for focus in [FocusArea::Sidebar, FocusArea::MainPanel, FocusArea::InputBox] {
        for &(width, height) in DEGENERATE {
            let mut app = app();
            app.focus_area = focus;
            let _ = frame_of(width, height, |f, area| help_bar::render(f, &app, area));
        }
    }
}

#[test]
fn the_help_bar_names_the_keys_for_the_focused_pane() {
    // Not a snapshot — the assertion is that the strip is about the pane with
    // focus. A help bar that shows the wrong pane's keys is worse than none,
    // since it is read as an instruction.
    let mut app = app();

    app.focus_area = FocusArea::Sidebar;
    let sidebar_keys = frame_of(80, 1, |f, area| help_bar::render(f, &app, area)).join("");
    assert!(
        sidebar_keys.contains("open"),
        "the sidebar strip should offer opening a channel: {sidebar_keys:?}"
    );

    app.focus_area = FocusArea::InputBox;
    let input_keys = frame_of(80, 1, |f, area| help_bar::render(f, &app, area)).join("");
    assert!(
        input_keys.contains("send"),
        "the compose strip should offer sending: {input_keys:?}"
    );

    assert_ne!(
        sidebar_keys, input_keys,
        "the two panes must not present the same keys, or focus is not reaching this widget"
    );
    for strip in [&sidebar_keys, &input_keys] {
        assert!(
            strip.contains("tab"),
            "tab switches panes from everywhere and must always be offered: {strip:?}"
        );
    }
}

#[test]
fn the_sidebar_survives_every_size() {
    for &(width, height) in DEGENERATE {
        let app = app();
        let _ = frame_of(width, height, |f, area| sidebar::render(f, &app, area));
    }
}

#[test]
fn the_sidebar_shows_the_public_channel() {
    // `#public` is always present — it is the mesh, not a joined channel — so an
    // empty sidebar means the widget is not rendering its own contents.
    let app = app();
    let frame = frame_of(30, 20, |f, area| sidebar::render(f, &app, area)).join("\n");
    assert!(
        frame.contains("public"),
        "the mesh channel should always be listed: {frame:?}"
    );
}

#[test]
fn the_sidebar_item_list_agrees_with_what_it_draws() {
    // `sidebar_visible_items` is what the arrow keys move through, and the
    // render is what the user sees. If those two disagree, selection lands on a
    // row other than the highlighted one — the kind of bug that is obvious in
    // use and invisible to a unit test of either half alone.
    let app = app();
    let items = sidebar::sidebar_visible_items(&app);
    let frame = frame_of(30, 20, |f, area| sidebar::render(f, &app, area)).join("\n");

    assert!(
        !items.is_empty(),
        "there is always at least #public to move through"
    );
    assert!(
        !frame.trim().is_empty(),
        "a non-empty item list must draw something"
    );
}

#[test]
fn the_connection_popup_survives_every_size() {
    // This one covers the whole UI while disconnected, and `centered_rect` does
    // percentage arithmetic on the area it is handed — the exact shape that
    // breaks on a two-cell terminal.
    for &(width, height) in DEGENERATE {
        let mut app = app();
        let _ = frame_of(width, height, |f, area| popup::render(f, &mut app, area));
    }
}

#[test]
fn the_nickname_popup_survives_every_size() {
    // The other branch of `popup::render`, which the connection path never
    // reaches.
    for &(width, height) in DEGENERATE {
        let mut app = app();
        app.popup_active = true;
        app.popup_title = "Set nickname".to_string();
        let _ = frame_of(width, height, |f, area| popup::render(f, &mut app, area));
    }
}

#[test]
fn the_nickname_popup_shows_its_title() {
    let mut app = app();
    app.popup_active = true;
    app.popup_title = "Set nickname".to_string();
    let frame = frame_of(80, 24, |f, area| popup::render(f, &mut app, area)).join("\n");
    assert!(
        frame.contains("nickname"),
        "the popup should say what it is asking for: {frame:?}"
    );
}

#[test]
fn a_very_long_title_does_not_escape_the_popup() {
    // Titles are not all ours — a nickname prompt can carry text from state, and
    // a title longer than the popup is wide must be clipped by the widget rather
    // than run into the frame around it.
    let mut app = app();
    app.popup_active = true;
    app.popup_title = "x".repeat(500);

    let frame = frame_of(80, 24, |f, area| popup::render(f, &mut app, area));

    assert_eq!(frame.len(), 24, "the frame must still be exactly 24 rows");
    for (row, line) in frame.iter().enumerate() {
        assert_eq!(
            line.chars().count(),
            80,
            "row {row} must be exactly 80 cells wide; a widget cannot widen the frame"
        );
    }
}

#[test]
fn the_whole_ui_survives_every_size() {
    // `ui::render` is the composition of every panel, and it is the one that
    // runs on each frame in `main`. If it panics at a size a user can produce by
    // dragging a window edge, the client dies — and until 90296c6 it would have
    // died without giving the terminal back.
    for &(width, height) in DEGENERATE {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("TestBackend");
        terminal
            .draw(|f| bitmancer::tui::ui::render(&mut app, f))
            .unwrap_or_else(|error| panic!("ui::render failed at {width}x{height}: {error}"));
    }
}

#[test]
fn the_whole_ui_fills_the_frame_it_is_given() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("TestBackend");
    terminal
        .draw(|f| bitmancer::tui::ui::render(&mut app, f))
        .expect("draw");

    let buffer = terminal.backend().buffer().clone();
    assert_eq!(buffer.area.width, 80);
    assert_eq!(buffer.area.height, 24);

    let painted = (0..buffer.area.height)
        .flat_map(|y| (0..buffer.area.width).map(move |x| (x, y)))
        .filter(|&(x, y)| buffer.get(x, y).symbol() != " ")
        .count();
    assert!(
        painted > 0,
        "a full UI render that paints nothing is a blank screen, which is what \
         this test exists to notice"
    );
}

// The search prompt and the match highlight. Both are render-only: the state
// they draw from is unit-tested in `tui::search`, but a search whose result is
// correct and invisible has not found anything as far as the user is concerned.
// This is the same "given" gap the wheel and paste commit named about itself.

use bitmancer::tui::widgets::input_box;

/// A conversation with something to find in it.
fn app_with_log() -> App {
    let mut app = App::new_with_nickname("tester".to_string());
    let now = chrono::Local::now().timestamp();
    for (index, text) in ["the relay is down", "which relay", "nothing here"]
        .iter()
        .enumerate()
    {
        app.add_channel_line(bitmancer::tui::app::IncomingLine {
            channel: "#public".to_string(),
            sender: "alice".to_string(),
            epoch: now - (3 - index as i64),
            content: text.to_string(),
        });
    }
    app
}

#[test]
fn the_search_prompt_shows_the_query_and_the_match_count() {
    let mut app = app_with_log();
    app.search.open(0);
    for character in "relay".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);

    let lines = frame_of(60, 1, |f, area| input_box::render(f, &mut app, area));
    let rendered = lines.join("");

    assert!(
        rendered.contains("relay"),
        "the query has to be on screen while it is being typed: {rendered:?}"
    );
    assert!(
        rendered.contains("2 of 2"),
        "the live count is the whole reason the prompt beats a blind search: {rendered:?}"
    );
}

#[test]
fn a_query_that_finds_nothing_says_so_before_it_is_committed() {
    let mut app = app_with_log();
    app.search.open(0);
    for character in "nonesuch".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);

    let rendered = frame_of(60, 1, |f, area| input_box::render(f, &mut app, area)).join("");
    assert!(
        rendered.contains("no matches"),
        "a dead query should say so while typing, not after Enter: {rendered:?}"
    );
}

#[test]
fn the_prompt_replaces_the_compose_line_rather_than_covering_the_log() {
    // The negative control for the two above. Without the prompt open the same
    // widget must draw the ordinary compose line, or these tests would pass
    // against a widget that always drew a search box.
    let mut app = app_with_log();
    let rendered = frame_of(60, 1, |f, area| input_box::render(f, &mut app, area)).join("");
    assert!(
        !rendered.contains('⌕'),
        "no search is open, so no search prompt: {rendered:?}"
    );
}

#[test]
fn a_narrow_terminal_keeps_the_query_and_drops_the_count() {
    // The count is the first thing to go when there is no room. Losing the
    // query instead would make the prompt unusable at exactly the width where
    // someone most needs to see what they typed.
    let mut app = app_with_log();
    app.search.open(0);
    for character in "relay".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);

    for width in [1u16, 2, 4, 8, 12, 20] {
        let rendered = frame_of(width, 1, |f, area| input_box::render(f, &mut app, area)).join("");
        assert!(
            !rendered.contains("2 of 2") || width >= 12,
            "the count should not crowd out the query at width {width}: {rendered:?}"
        );
    }
}

#[test]
fn the_search_prompt_survives_every_degenerate_size() {
    let mut app = app_with_log();
    app.search.open(0);
    for character in "relay".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);

    for (width, height) in DEGENERATE {
        let _ = frame_of(*width, *height, |f, area| {
            input_box::render(f, &mut app, area)
        });
    }
}

#[test]
fn the_help_bar_offers_the_search_keys_only_where_they_work() {
    let mut app = app_with_log();

    app.focus_area = FocusArea::MainPanel;
    let log_pane = frame_of(80, 1, |f, area| help_bar::render(f, &app, area)).join("");
    assert!(
        log_pane.contains("find"),
        "the log pane is where / searches: {log_pane:?}"
    );

    app.focus_area = FocusArea::InputBox;
    let compose = frame_of(80, 1, |f, area| help_bar::render(f, &app, area)).join("");
    assert!(
        !compose.contains("find"),
        "in the compose box / is the command prefix, not a search: {compose:?}"
    );
}

#[test]
fn the_help_bar_switches_to_the_walking_keys_once_a_search_lands() {
    let mut app = app_with_log();
    app.focus_area = FocusArea::MainPanel;
    app.search.open(0);
    for character in "relay".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);
    app.search.commit();

    let walking = frame_of(80, 1, |f, area| help_bar::render(f, &app, area)).join("");
    assert!(
        walking.contains("next, previous"),
        "n and N are live and the strip should say so: {walking:?}"
    );
}

/// Scrollback as a search actually finds it: settled, not arriving.
///
/// `add_channel_line` stamps `arrived`, which drives the reveal animation, and a
/// line one frame old has drawn about one character of its body. The highlight
/// is on the body, so there is nothing yet to colour. That is not a defect —
/// searching is a thing you do to history, and history has `arrived: None` —
/// but it did make the first version of the test below fail, and the honest fix
/// was the fixture rather than the assertion.
fn settled_log() -> App {
    let mut app = App::new_with_nickname("tester".to_string());
    let messages: Vec<bitmancer::tui::app::Message> = ["the relay is down", "which relay", "nothing here"]
        .iter()
        .map(|text| bitmancer::tui::app::Message {
            sender: "alice".to_string(),
            timestamp: "12:00".to_string(),
            content: text.to_string(),
            is_self: false,
            epoch: 0,
            message_id: None,
            delivery: None,
            arrived: None,
        })
        .collect();
    app.channel_messages.insert("#public".to_string(), messages);
    app
}

/// Which foreground colours appear on each row, so a test can talk about the
/// line being highlighted rather than about cells.
fn row_colours<F>(width: u16, height: u16, mut draw: F) -> Vec<Vec<ratatui::style::Color>>
where
    F: FnMut(&mut ratatui::Frame, Rect),
{
    let mut terminal =
        Terminal::new(TestBackend::new(width, height)).expect("TestBackend needs no real terminal");
    terminal
        .draw(|f| {
            let area = f.size();
            draw(f, area);
        })
        .expect("drawing into a buffer cannot fail");
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer.get(x, y).style().fg.unwrap_or(ratatui::style::Color::Reset))
                .collect()
        })
        .collect()
}

#[test]
fn the_line_a_search_landed_on_is_drawn_differently_from_its_neighbours() {
    // The whole visible promise of the feature. The jump puts the match on
    // screen; this is what tells the eye which of the rows it is.
    use bitmancer::tui::widgets::main_panel;

    let mut app = settled_log();
    app.message_viewport_height = 6;
    app.search.open(0);
    for character in "which".chars() {
        app.search.push(character);
    }
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);
    app.search.commit();
    let matched = app.search.current().expect("a match");

    let highlighted = row_colours(60, 6, |f, area| main_panel::render_log(f, &mut app, area));

    // Same frame with the search dropped, so the comparison is against this
    // exact log rather than against an assumption about the palette.
    let mut plain_app = settled_log();
    plain_app.message_viewport_height = 6;
    let plain = row_colours(60, 6, |f, area| main_panel::render_log(f, &mut plain_app, area));

    assert_ne!(
        highlighted, plain,
        "a walked search must change how the log is drawn, or the match is \
         invisible and the jump is the only cue"
    );
    // Exactly the matched row, not merely some row. "Something is lit" also
    // passes for an implementation that lights the whole log, which is a real
    // mutation this caught: `current_match.is_some()` in place of the index
    // comparison rendered every line highlighted and the weaker assertion was
    // happy with it.
    let lit: Vec<usize> = highlighted
        .iter()
        .enumerate()
        .filter(|(_, row)| row.contains(&bitmancer::tui::theme::ALERT))
        .map(|(row, _)| row)
        .collect();
    assert_eq!(
        lit,
        vec![matched],
        "index {matched} was selected, so exactly that row should be lit"
    );
    assert!(
        !plain
            .iter()
            .any(|row| row.contains(&bitmancer::tui::theme::ALERT)),
        "the negative control: with no search there is nothing lit, so the \
         assertion above cannot be passing on some unrelated line"
    );
}
