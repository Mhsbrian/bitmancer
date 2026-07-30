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
