// src/tui/event.rs

use crossterm::event::{
    Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent,
    MouseEventKind,
};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;

use crate::tui::app::{App, FocusArea};
use crate::tui::map::MapFocus;
use crate::tui::widgets::sidebar::sidebar_visible_items;

/// Lines the wheel moves per notch.
///
/// Three rather than one: a terminal reports a notch per physical click of the
/// wheel, and one line each makes a long log feel stuck. Three is what most
/// terminals and pagers settle on.
const WHEEL_LINES: usize = 3;

/// The wheel scrolls the log, wherever the keyboard focus happens to be.
///
/// Mouse capture was enabled from the very first commit of this TUI and no
/// handler ever read a `Mouse` event, so the capture only ever took the
/// terminal's own click-drag selection away and gave nothing back. This is the
/// half that gives something back.
///
/// Deliberately not focus-dependent. A wheel over a log is a scroll in every
/// other application, and requiring `Tab` to the log pane first would be a
/// surprise with no upside. The other panes have nothing scrollable in them.
pub fn handle_mouse_event(app: &mut App, mouse_event: MouseEvent) {
    // The overlays own the screen while they are up, and none of them scrolls.
    if app.popup_active || app.viewer.open || app.map_open || app.mesh_view_open {
        return;
    }

    let (messages, _, _) = app.get_current_messages();
    let max_scroll = messages.len().saturating_sub(app.message_viewport_height);

    match mouse_event.kind {
        // Up means back through history, matching the Up key above.
        MouseEventKind::ScrollUp => {
            app.msg_scroll = (app.msg_scroll + WHEEL_LINES).min(max_scroll);
        }
        MouseEventKind::ScrollDown => {
            app.msg_scroll = app.msg_scroll.saturating_sub(WHEEL_LINES);
        }
        _ => {}
    }
}

/// Pasted text goes into the compose box and is not sent.
///
/// Without bracketed paste a multi-line paste arrives as individual keystrokes
/// and each embedded return fires `Enter`, sending half a message and then the
/// next half. On a network where nothing can be unsent, that is the kind of
/// mistake the client should make impossible rather than merely unlikely.
///
/// Newlines are folded to spaces rather than kept: a chat line is one line, the
/// compose box draws one logical entry, and the wire format has no notion of a
/// multi-line message. Folding preserves the words; keeping them would send the
/// first line alone the moment `Enter` was pressed.
pub fn handle_paste_event(app: &mut App, pasted: &str) {
    if app.popup_active || app.viewer.open || app.map_open || app.mesh_view_open {
        return;
    }
    // Focus follows the paste: text arriving means the user means to type.
    app.focus_area = FocusArea::InputBox;

    let folded: String = pasted
        .replace(['\r', '\n'], " ")
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    // Emptiness is judged after trimming but the text is inserted untrimmed: a
    // paste of nothing but newlines folds to blanks and is worth dropping, while
    // a deliberate leading space in real text is the user's business. Checking
    // `folded.is_empty()` alone would insert those blanks, because the fold to
    // spaces happens before the control-character filter can see them.
    if folded.trim().is_empty() {
        return;
    }

    let mut value = app.input.value().to_string();
    value.push_str(&folded);
    let cursor = value.chars().count();
    app.input = tui_input::Input::new(value).with_cursor(cursor);
}

pub fn handle_key_event(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    if key_event.kind != KeyEventKind::Press {
        return;
    }
    if key_event.code == KeyCode::Char('c') && key_event.modifiers == KeyModifiers::CONTROL {
        app.should_quit = true;
        return;
    }
    // Not while the search prompt is taking keys. The guard below covers every
    // shortcut beneath it, but this one sits above — and the connection overlay
    // is dismissable precisely so the client stays usable offline, which is when
    // reading back through settled history is most likely. Searching for
    // "server" or "error" would otherwise reconnect on the `r` and drop the
    // character, and `trigger_connection_retry` also clears `popup_messages`, so
    // the failure the user was reading about disappears mid-word.
    if matches!(app.phase, crate::tui::app::TuiPhase::Error(_))
        && key_event.code == KeyCode::Char('r')
        && !app.search.prompt_open
    {
        app.trigger_connection_retry();
        return;
    }
    if app.popup_active {
        handle_popup_events(app, key_event, input_tx);
        return;
    }
    // Before every single-key shortcut below. While the prompt is open each
    // keystroke is query text, so typing "i" has to reach the query rather than
    // open the image viewer — searching for "invite" would otherwise be
    // impossible to type.
    if app.search.prompt_open {
        handle_search_events(app, key_event);
        return;
    }
    // The viewer takes the keyboard while it is open, before the map so the
    // two overlays cannot both react to one key.
    if app.viewer.open {
        handle_viewer_events(app, key_event);
        return;
    }
    // 'i' opens the newest image in the conversation on screen.
    if key_event.code == KeyCode::Char('i') && app.focus_area != FocusArea::InputBox {
        let conversation = app.active_conversation();
        app.viewer.open_in(&conversation, None);
        return;
    }
    if app.mesh_view_open {
        match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('m') => app.mesh_view_open = false,
            _ => {}
        }
        return;
    }
    // The map takes the whole keyboard while it is open. This must come before
    // the connection-overlay dismissal below, which would otherwise swallow
    // every Esc while offline and leave the map with no way back out.
    if app.map_open {
        handle_map_events(app, key_event);
        return;
    }
    // Emoji matches are dismissed before the connection overlay: the strip is
    // the more local thing, and Esc means "put away what just appeared". Without
    // this, Esc while offline would clear the overlay and leave the strip up.
    if key_event.code == KeyCode::Esc
        && app.focus_area == FocusArea::InputBox
        && app.emoji_suggestions().is_some()
    {
        app.dismiss_emoji();
        return;
    }
    // Dismiss the connection overlay so the client is usable while offline;
    // reconnection continues in the background either way.
    if !matches!(app.phase, crate::tui::app::TuiPhase::Connected)
        && key_event.code == KeyCode::Esc
    {
        app.connection_popup_dismissed = true;
        return;
    }
    // 'm' opens the map from anywhere the input box is not capturing text.
    if key_event.code == KeyCode::Char('m') && app.focus_area != FocusArea::InputBox {
        app.open_map();
        return;
    }
    // Tab cycles panes — unless emoji matches are showing, where it takes one.
    // This check has to be here rather than in the input handler: the pane cycle
    // runs before dispatch, so a completion that claimed Tab further down would
    // never see it. Found by pressing Tab in the running client and watching the
    // focus move instead.
    if key_event.code == KeyCode::Tab
        && app.focus_area == FocusArea::InputBox
        && app.emoji_suggestions().is_some()
    {
        app.accept_emoji();
        return;
    }
    if key_event.code == KeyCode::Tab {
        app.focus_area = match app.focus_area {
            FocusArea::Sidebar => FocusArea::MainPanel,
            FocusArea::MainPanel => FocusArea::InputBox,
            FocusArea::InputBox => FocusArea::Sidebar,
        };
        return;
    }
    match app.focus_area {
        FocusArea::Sidebar => handle_sidebar_events(app, key_event),
        FocusArea::MainPanel => handle_main_panel_events(app, key_event),
        FocusArea::InputBox => handle_input_events(app, key_event, input_tx),
    }
}

/// Image viewer. Left/right walk the conversation's images; nothing here can
/// start a network request except by moving to another image, which the user
/// asked for.
fn handle_viewer_events(app: &mut App, key_event: KeyEvent) {
    let conversation = app.active_conversation();
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') => app.viewer.close(),
        KeyCode::Left | KeyCode::Up => app.viewer.step(&conversation, -1),
        KeyCode::Right | KeyCode::Down => app.viewer.step(&conversation, 1),
        KeyCode::Char('o') => app.pending_image_open_external = true,
        _ => {}
    }
}

/// Map navigation. Enter drills toward the building level and joins once there
/// is nowhere deeper to go, so the common path is just "press Enter until you
/// are somewhere".
fn handle_map_events(app: &mut App, key_event: KeyEvent) {
    // Arrows move, Enter descends, j joins. Vim aliases are deliberately absent:
    // 'j' cannot mean both "down" and "join", and half a vim keymap is worse
    // than none.
    //
    // Getting *out* is offered several ways on purpose. Terminals disagree
    // about Backspace — most send DEL (0x7f), some send 0x08, which arrives as
    // Ctrl+H — and being unable to zoom out is a trap, so Esc and '-' work too.
    let ctrl = key_event.modifiers.contains(KeyModifiers::CONTROL);
    match key_event.code {
        KeyCode::Char('q') | KeyCode::Char('m') => app.map_open = false,
        // Esc steps back out, and only closes once there is nowhere to go.
        KeyCode::Esc => {
            if !app.map.drill_out() {
                app.map_open = false;
            }
        }
        KeyCode::Backspace | KeyCode::Char('-') => {
            app.map.drill_out();
        }
        KeyCode::Char('h') if ctrl => {
            app.map.drill_out();
        }
        // Tab moves the keyboard between the grid and the hotspot list. It
        // refuses to hand it to an empty list, so the key never appears to do
        // nothing while quietly taking the arrows away from the map.
        KeyCode::Tab | KeyCode::BackTab => {
            app.map.toggle_pane();
        }
        KeyCode::Up if app.map.pane == MapFocus::Hotspots => {
            app.map.move_hotspot_selection(-1)
        }
        KeyCode::Down if app.map.pane == MapFocus::Hotspots => {
            app.map.move_hotspot_selection(1)
        }
        KeyCode::Up => app.map.move_selection(-1, 0),
        KeyCode::Down => app.map.move_selection(1, 0),
        KeyCode::Left => app.map.move_selection(0, -1),
        KeyCode::Right => app.map.move_selection(0, 1),
        // On the list, Enter travels: the map re-centres on that cell with it
        // under the cursor, so the next Enter joins. Two presses to arrive and
        // commit, rather than one that does both and drops you somewhere you
        // have not seen.
        KeyCode::Enter if app.map.pane == MapFocus::Hotspots => {
            if let Some(hotspot) = app.map.selected_hotspot() {
                app.map.dive_to(&hotspot.geohash);
            }
        }
        // Enter is "go in" in the sense the user means it. On a cell that is a
        // real channel level, that means joining the conversation; on the
        // in-between precisions (1 and 3) no channel exists to join, so it
        // zooms instead. The key bar always states which one it will do.
        KeyCode::Enter => {
            if app.map.level_label().is_some() || !app.map.can_drill_in() {
                app.request_join_selected_cell();
            } else {
                app.map.drill_in();
            }
        }
        // Explicit zoom, for going deeper than the level you are standing on.
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('>') => {
            app.map.drill_in();
        }
        KeyCode::Char('<') => {
            app.map.drill_out();
        }
        KeyCode::Char('j') => app.request_join_selected_cell(),
        _ => {}
    }
}

fn handle_sidebar_events(app: &mut App, key_event: KeyEvent) {
    let visible_items = sidebar_visible_items(app);
    let current_selection = app.sidebar_flat_selected;
    match key_event.code {
        KeyCode::Tab => app.focus_area = FocusArea::MainPanel,
        KeyCode::Down => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = (current_selection + 1) % visible_items.len();
            }
        }
        KeyCode::Up => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = if current_selection == 0 { visible_items.len() - 1 } else { current_selection - 1 };
            }
        }
        KeyCode::Enter => {
            if let Some(&(section_idx, child_opt)) = visible_items.get(app.sidebar_flat_selected) {
                if let Some(child_idx) = child_opt {
                    app.sidebar_state.people_selected = None;
                    app.sidebar_state.channel_selected = None;
                    app.sidebar_state.public_selected = None;
                    match section_idx {
                        0 => { app.sidebar_state.public_selected = Some(true); app.switch_to_public(); }
                        1 => { if let Some(channel_name) = app.channels.get(child_idx) { app.switch_to_channel(channel_name.clone()); } }
                        2 => { if let Some(person_name) = app.people.get(child_idx) { app.switch_to_dm(person_name.clone()); } }
                        3 => app.sidebar_state.blocked_selected = Some(child_idx),
                        4 if child_idx == 0 => { app.open_nickname_popup(); }
                        _ => {}
                    }
                    if section_idx != 1 { app.update_current_conversation(); }
                } else {
                    app.sidebar_state.toggle_expand(section_idx);
                }
            }
        }
        _ => {}
    }
}

/// The search prompt, while it is taking keys.
///
/// The hits are recomputed on every keystroke rather than on Enter, so the count
/// beside the query is live and a query that finds nothing says so before it is
/// committed. The log does not move until Enter — jumping on each character
/// would drag the view around while someone is still deciding what to type.
fn handle_search_events(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc => {
            app.msg_scroll = app.search.cancel();
        }
        KeyCode::Enter => {
            app.search.commit();
            jump_to_current_match(app);
        }
        KeyCode::Backspace => {
            app.search.backspace();
            rerun_search(app);
        }
        // Shift is allowed through because that is how an uppercase letter
        // arrives; every other modifier is a chord, not text. Without this the
        // arm matched on the code alone and typed the bare letter: `Ctrl+W`,
        // which deletes a word almost everywhere, put a `w` in the query
        // instead, and so did twenty-four of its neighbours. Ignoring a chord is
        // the honest reading — a query is short and Backspace is right there —
        // and it is better than inventing editing bindings nobody asked for.
        KeyCode::Char(character)
            if key_event.modifiers.difference(KeyModifiers::SHIFT).is_empty() =>
        {
            app.search.push(character);
            rerun_search(app);
        }
        _ => {}
    }
}

fn rerun_search(app: &mut App) {
    // Cloned because `run` borrows the app mutably while `get_current_messages`
    // borrows it immutably. A conversation is bounded by what one person has
    // typed at a prompt, so this is not a hot path.
    let messages = app.get_current_messages().0.to_vec();
    app.search.run(&messages);
}

/// Scrolls the log so the selected match is on screen.
fn jump_to_current_match(app: &mut App) {
    let Some(index) = app.search.current() else {
        return;
    };
    let total = app.get_current_messages().0.len();
    app.msg_scroll = crate::tui::search::scroll_for(index, total, app.message_viewport_height);
}

fn handle_main_panel_events(app: &mut App, key_event: KeyEvent) {
    let (messages, _, _) = app.get_current_messages();
    let total_messages = messages.len();
    let messages_height = app.message_viewport_height;

    let max_scroll = total_messages.saturating_sub(messages_height);

    // `n` and `N` only mean "walk the matches" while there are matches to walk.
    // With none they fall through to the arms below and do nothing, rather than
    // being swallowed by a finished search that found nothing — a key that does
    // nothing silently reads as a wedged keyboard.
    if app.search.is_walking() {
        match key_event.code {
            KeyCode::Char('n') => {
                app.search.next();
                jump_to_current_match(app);
                return;
            }
            KeyCode::Char('N') => {
                app.search.previous();
                jump_to_current_match(app);
                return;
            }
            KeyCode::Esc => {
                app.msg_scroll = app.search.cancel();
                return;
            }
            _ => {}
        }
    }

    match key_event.code {
        // Opens the prompt. Safe as a bare key here because this handler only
        // runs when the log has focus — in the input box `/` is the command
        // prefix and stays one.
        KeyCode::Char('/') => {
            app.search.open(app.msg_scroll);
        }
        KeyCode::Tab => app.focus_area = FocusArea::InputBox,
        KeyCode::Up => {
            app.msg_scroll = (app.msg_scroll + 1).min(max_scroll);
        }
        KeyCode::Down => {
            app.msg_scroll = app.msg_scroll.saturating_sub(1);
        }
        KeyCode::PageUp => {
            app.msg_scroll = (app.msg_scroll + messages_height).min(max_scroll);
        }
        KeyCode::PageDown => {
            app.msg_scroll = app.msg_scroll.saturating_sub(messages_height);
        }
        KeyCode::Home => {
            app.msg_scroll = max_scroll;
        }
        KeyCode::End => {
            app.scroll_to_bottom_current_conversation();
        }
        _ => {}
    }
}

fn handle_popup_events(app: &mut App, key_event: KeyEvent, _input_tx: &mpsc::Sender<String>) {
    match key_event.code {
        KeyCode::Enter => {
            let new_nickname = app.popup_input.value().to_string();
            if !new_nickname.is_empty() {
                app.update_nickname(new_nickname);
                app.close_popup();
            }
        }
        KeyCode::Esc => app.close_popup(),
        _ => {
            // FIX: Ignore the return value of handle_event
            let _ = app.popup_input.handle_event(&CrosstermEvent::Key(key_event));
        }
    }
}

fn handle_input_events(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    // Emoji completion claims a few keys, and deliberately not Enter.
    //
    // Slack and Discord let Enter accept a completion, which is fine when a
    // picker only opens on purpose. Here a colon is punctuation far more often
    // than the start of an emoji, so hijacking Enter would mean "note: done"
    // followed by Enter silently inserting 😄 instead of sending. Tab accepts;
    // Enter always sends. Nothing surprising can happen to a message.
    if app.emoji_suggestions().is_some() {
        match key_event.code {
            KeyCode::Tab | KeyCode::BackTab => {
                app.accept_emoji();
                return;
            }
            KeyCode::Up => {
                app.move_emoji_selection(-1);
                return;
            }
            KeyCode::Down => {
                app.move_emoji_selection(1);
                return;
            }
            KeyCode::Esc => {
                app.dismiss_emoji();
                return;
            }
            _ => {}
        }
    }

    match key_event.code {
        KeyCode::Enter => {
            let input_str = app.input.value().to_string();
            if !input_str.is_empty()
                && input_tx.try_send(input_str.clone()).is_ok() {
                    if !input_str.starts_with('/') {
                        app.add_sent_message(input_str);
                    }
                    app.input.reset();
                }
        }
        _ => {
            let _ = app.input.handle_event(&CrosstermEvent::Key(key_event));
            // A closing colon completes a shortcode outright, so someone who
            // knows the name never sees the strip at all.
            if key_event.code == KeyCode::Char(':') {
                app.expand_finished_shortcode();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn map_app() -> App {
        let mut app = App::new_with_nickname("tui".into());
        app.open_map();
        app
    }

    /// A map with traffic in two cells, so the hotspot list has something in it.
    fn busy_map_app() -> App {
        let mut app = map_app();
        for index in 0..5 {
            app.map.note_voice("9q", &format!("p{index}"), index < 2);
        }
        app.map.note_voice("dr", "someone", false);
        app
    }

    fn composing(text: &str) -> App {
        let mut app = App::new_with_nickname("tui".into());
        app.focus_area = FocusArea::InputBox;
        app.input = tui_input::Input::new(text.to_string()).with_cursor(text.chars().count());
        app
    }

    /// Through the real entry point, because that is the only path a keystroke
    /// actually takes — a test that calls the inner handler can pass while the
    /// keyboard does something else entirely, which is exactly what happened.
    fn typed(app: &mut App, text: &str, input_tx: &mpsc::Sender<String>) {
        for character in text.chars() {
            handle_key_event(app, press(KeyCode::Char(character)), input_tx);
        }
    }

    #[test]
    fn a_finished_shortcode_expands_on_its_closing_colon() {
        // The path that matters once somebody knows three shortcodes: no strip to
        // read, no key to press.
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing("");
        typed(&mut app, "ship it :fire:", &tx);
        assert_eq!(app.input.value(), "ship it 🔥");
    }

    #[test]
    fn an_unknown_shortcode_is_left_as_typed() {
        // Not everything between colons is an emoji, and mangling text that
        // merely looks like one would be worse than doing nothing.
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing("");
        typed(&mut app, "see :zzzqqq:", &tx);
        assert_eq!(app.input.value(), "see :zzzqqq:");
    }

    #[test]
    fn tab_inserts_the_highlighted_match() {
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing("nice :fi");
        handle_key_event(&mut app, press(KeyCode::Tab), &tx);
        assert_eq!(app.input.value(), "nice 🔥");
        assert_eq!(
            app.focus_area,
            FocusArea::InputBox,
            "and the focus stays where the typing is"
        );
    }

    #[test]
    fn arrows_move_the_highlight_without_touching_the_text() {
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing(":s");
        let before = app.input.value().to_string();
        handle_key_event(&mut app, press(KeyCode::Down), &tx);
        assert_eq!(app.emoji_selection, 1);
        assert_eq!(app.input.value(), before);
        handle_key_event(&mut app, press(KeyCode::Up), &tx);
        assert_eq!(app.emoji_selection, 0);
    }

    #[test]
    fn enter_always_sends_and_never_inserts_an_emoji() {
        // The reason Enter is not a completion key. "note: done" then Enter must
        // send those words, not quietly become an emoji.
        let (tx, mut rx) = mpsc::channel(4);
        let mut app = composing("nice :fi");
        handle_key_event(&mut app, press(KeyCode::Enter), &tx);
        assert_eq!(
            rx.try_recv().ok().as_deref(),
            Some("nice :fi"),
            "the words as typed"
        );
        assert!(app.input.value().is_empty(), "and the box is cleared");
    }

    #[test]
    fn esc_hides_the_matches_and_keeps_the_text() {
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing("nice :fi");
        assert!(app.emoji_suggestions().is_some());
        handle_key_event(&mut app, press(KeyCode::Esc), &tx);
        assert!(app.emoji_suggestions().is_none(), "hidden");
        assert_eq!(app.input.value(), "nice :fi", "text untouched");

        // One more character is a different shortcode, so the matches return
        // rather than the feature staying off for the rest of the message.
        typed(&mut app, "r", &tx);
        assert!(app.emoji_suggestions().is_some());
    }

    #[test]
    fn tab_still_switches_panes_when_no_matches_are_showing() {
        // The completion borrows Tab; it must give it back.
        let (tx, _rx) = mpsc::channel(4);
        let mut app = composing("ordinary text");
        assert!(app.emoji_suggestions().is_none());
        handle_key_event(&mut app, press(KeyCode::Tab), &tx);
        assert_ne!(app.focus_area, FocusArea::InputBox, "focus moved on");
    }

    #[test]
    fn tab_moves_the_keyboard_to_the_hotspots_and_back() {
        let mut app = busy_map_app();
        assert_eq!(app.map.pane, MapFocus::Grid);
        handle_map_events(&mut app, press(KeyCode::Tab));
        assert_eq!(app.map.pane, MapFocus::Hotspots);
        handle_map_events(&mut app, press(KeyCode::Tab));
        assert_eq!(app.map.pane, MapFocus::Grid);
    }

    #[test]
    fn tab_does_nothing_visible_when_there_is_nothing_to_pick() {
        // Handing the keyboard to an empty list would take the arrows away
        // from the map and put them nowhere the user can see.
        let mut app = map_app();
        handle_map_events(&mut app, press(KeyCode::Tab));
        assert_eq!(app.map.pane, MapFocus::Grid);
        // And the arrows still drive the grid.
        let start = app.map.selected_geohash().to_string();
        handle_map_events(&mut app, press(KeyCode::Right));
        assert_ne!(app.map.selected_geohash(), start);
    }

    #[test]
    fn arrows_drive_whichever_pane_has_the_keyboard() {
        let mut app = busy_map_app();
        let cell = app.map.selected_geohash().to_string();

        handle_map_events(&mut app, press(KeyCode::Tab));
        handle_map_events(&mut app, press(KeyCode::Down));
        assert_eq!(app.map.hotspot_cursor(), 1, "the list moved");
        assert_eq!(
            app.map.selected_geohash(),
            cell,
            "and the grid cursor stayed exactly where it was"
        );

        handle_map_events(&mut app, press(KeyCode::Tab));
        handle_map_events(&mut app, press(KeyCode::Down));
        assert_ne!(app.map.selected_geohash(), cell, "now the grid moves again");
    }

    #[test]
    fn enter_on_a_hotspot_travels_rather_than_joining() {
        // Joining straight from the list would drop the user into a channel
        // they have not looked at. Enter takes them there; the next Enter
        // commits.
        let mut app = busy_map_app();
        handle_map_events(&mut app, press(KeyCode::Tab));
        let target = app.map.selected_hotspot().unwrap().geohash;
        assert_eq!(target, "9q", "the busiest cell is on top");

        handle_map_events(&mut app, press(KeyCode::Enter));
        assert!(app.map_open, "still on the map");
        assert_eq!(app.map.selected_geohash(), "9q", "with the cell under the cursor");
        assert_eq!(app.map.focus(), "9", "and its surroundings on screen");
        assert_eq!(app.map.pane, MapFocus::Grid, "keyboard handed back");

        // The second Enter is the one that joins.
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert!(!app.map_open, "joining closes the map");
    }

    #[test]
    fn arrows_move_the_cursor() {
        let mut app = map_app();
        let start = app.map.selected_geohash().to_string();
        handle_map_events(&mut app, press(KeyCode::Right));
        assert_ne!(app.map.selected_geohash(), start);
        handle_map_events(&mut app, press(KeyCode::Left));
        assert_eq!(app.map.selected_geohash(), start, "left undoes right");
    }

    #[test]
    fn enter_zooms_at_non_channel_levels_and_joins_at_channel_levels() {
        let mut app = map_app();
        // Precision 1 is not a channel level: nothing to join, so zoom.
        assert_eq!(app.map.level_label(), None);
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert_eq!(app.map.precision(), 2);
        assert!(app.pending_geohash_join.is_none());

        // Precision 2 is the region level — Enter goes into the conversation.
        assert_eq!(app.map.level_label(), Some("region"));
        let target = app.map.selected_geohash().to_string();
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert_eq!(app.pending_geohash_join.as_deref(), Some(target.as_str()));
        assert!(!app.map_open, "joining closes the map");
    }

    #[test]
    fn plus_and_minus_zoom_regardless_of_level() {
        let mut app = map_app();
        // '+' keeps drilling even where Enter would join.
        handle_map_events(&mut app, press(KeyCode::Char('+')));
        assert_eq!(app.map.precision(), 2);
        handle_map_events(&mut app, press(KeyCode::Char('+')));
        assert_eq!(app.map.precision(), 3);
        assert!(app.pending_geohash_join.is_none(), "'+' never joins");

        handle_map_events(&mut app, press(KeyCode::Char('-')));
        assert_eq!(app.map.precision(), 2);
    }

    #[test]
    fn enter_joins_at_the_deepest_level_where_zooming_is_impossible() {
        let mut app = map_app();
        for _ in 0..crate::tui::map::MAX_PRECISION - 1 {
            handle_map_events(&mut app, press(KeyCode::Char('+')));
        }
        assert_eq!(app.map.precision(), crate::tui::map::MAX_PRECISION);
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert_eq!(
            app.pending_geohash_join.as_deref().map(str::len),
            Some(crate::tui::map::MAX_PRECISION)
        );
    }

    #[test]
    fn esc_reaches_the_map_even_while_disconnected() {
        // Regression: the connection-overlay dismissal used to swallow Esc
        // before the map ever saw it, trapping the user at whatever depth they
        // had drilled to.
        let (tx, _rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("tui".into());
        assert!(
            !matches!(app.phase, crate::tui::app::TuiPhase::Connected),
            "this test is about the offline path"
        );
        app.open_map();
        handle_key_event(&mut app, press(KeyCode::Char('+')), &tx);
        assert_eq!(app.map.precision(), 2);

        handle_key_event(&mut app, press(KeyCode::Esc), &tx);
        assert_eq!(app.map.precision(), 1, "Esc must zoom the map out");
        assert!(app.map_open);
    }

    #[test]
    fn backspace_climbs_back_out() {
        let mut app = map_app();
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert_eq!(app.map.precision(), 2);
        handle_map_events(&mut app, press(KeyCode::Backspace));
        assert_eq!(app.map.precision(), 1);
        assert_eq!(app.map.focus(), "");
    }

    #[test]
    fn j_joins_the_selected_cell_without_drilling() {
        let mut app = map_app();
        let target = app.map.selected_geohash().to_string();
        handle_map_events(&mut app, press(KeyCode::Char('j')));
        assert_eq!(app.pending_geohash_join, Some(target));
    }

    #[test]
    fn esc_zooms_out_before_it_closes() {
        let mut app = map_app();
        handle_map_events(&mut app, press(KeyCode::Enter));
        assert_eq!(app.map.precision(), 2);

        handle_map_events(&mut app, press(KeyCode::Esc));
        assert_eq!(app.map.precision(), 1, "first Esc steps back out");
        assert!(app.map_open, "and does not close the map");

        handle_map_events(&mut app, press(KeyCode::Esc));
        assert!(!app.map_open, "Esc at the world level closes");
        assert!(app.pending_geohash_join.is_none());
    }

    #[test]
    fn q_closes_from_any_depth() {
        let mut app = map_app();
        handle_map_events(&mut app, press(KeyCode::Enter));
        handle_map_events(&mut app, press(KeyCode::Char('q')));
        assert!(!app.map_open);
    }

    #[test]
    fn every_documented_way_out_zooms_out() {
        // Terminals disagree about Backspace, so all of these must work.
        let ctrl_h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL);
        for exit in [press(KeyCode::Backspace), press(KeyCode::Char('-')), ctrl_h] {
            let mut app = map_app();
            handle_map_events(&mut app, press(KeyCode::Enter));
            assert_eq!(app.map.precision(), 2);
            handle_map_events(&mut app, exit);
            assert_eq!(app.map.precision(), 1, "{exit:?} should zoom out");
            assert!(app.map_open, "{exit:?} should not close the map");
        }
    }

    #[test]
    fn m_opens_the_map_unless_typing() {
        let (tx, _rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("tui".into());

        // The input box owns every printable key.
        app.focus_area = FocusArea::InputBox;
        handle_key_event(&mut app, press(KeyCode::Char('m')), &tx);
        assert!(!app.map_open);
        assert_eq!(app.input.value(), "m");

        app.focus_area = FocusArea::Sidebar;
        handle_key_event(&mut app, press(KeyCode::Char('m')), &tx);
        assert!(app.map_open);
    }

    #[test]
    fn opening_the_map_from_a_channel_lands_on_that_cell() {
        let mut app = App::new_with_nickname("tui".into());
        app.channels.push("#9q8yy".to_string());
        app.switch_to_channel("#9q8yy".to_string());
        app.open_map();
        assert_eq!(app.map.selected_geohash(), "9q8yy");
    }

    fn wheel(kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        }
    }

    /// A log longer than its viewport, so there is somewhere to scroll to.
    fn app_with_backlog() -> App {
        let mut app = App::new_with_nickname("tui".into());
        app.message_viewport_height = 10;
        let now = chrono::Local::now().timestamp();
        for index in 0..40 {
            app.add_channel_line(crate::tui::app::IncomingLine {
                channel: "#public".to_string(),
                sender: "alice".to_string(),
                epoch: now - (40 - index),
                content: format!("line {index}"),
            });
        }
        app
    }

    /// Drives the search prompt through the same entry point `main.rs` uses,
    /// rather than calling the handler directly. The ordering against the
    /// single-key shortcuts is the thing worth testing and it only exists in
    /// `handle_key_event`.
    fn type_into_search(app: &mut App, text: &str) {
        let (sender, _receiver) = mpsc::channel::<String>(8);
        for character in text.chars() {
            handle_key_event(app, press(KeyCode::Char(character)), &sender);
        }
    }

    /// A modifier chord is not text, and the query must not take it as text.
    ///
    /// The other direction of the sweep above. That one asks whether anything
    /// steals a character *from* the prompt; this asks whether the prompt takes
    /// something it should not. It did: the `Char` arm matched on the key code
    /// alone, so every `Ctrl` chord typed its bare letter — `Ctrl+W` and
    /// `Ctrl+U`, which delete a word and a line nearly everywhere, put a `w` and
    /// a `u` in the query. Twenty-five of the twenty-six, all but `Ctrl+C`,
    /// which quits above this handler and should.
    ///
    /// Found the same way `r` was: by driving the whole keyspace rather than by
    /// naming the keys the code was written for.
    #[test]
    fn a_modifier_chord_is_not_typed_into_the_query() {
        let (sender, _receiver) = mpsc::channel::<String>(64);
        for modifier in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            for character in 'a'..='z' {
                let mut app = searchable_app();
                app.search.open(app.msg_scroll);
                handle_key_event(
                    &mut app,
                    KeyEvent::new(KeyCode::Char(character), modifier),
                    &sender,
                );
                assert!(
                    app.search.query.is_empty(),
                    "{modifier:?}+{character} put a character in the query"
                );
            }
        }
    }

    #[test]
    fn shift_still_types_because_that_is_how_a_capital_arrives() {
        // The negative control for the test above. Rejecting every modifier
        // would satisfy it completely and make the prompt unable to type an
        // uppercase letter, which many terminals deliver as Char + SHIFT.
        let (sender, _receiver) = mpsc::channel::<String>(64);
        let mut app = searchable_app();
        app.search.open(app.msg_scroll);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT),
            &sender,
        );
        assert_eq!(app.search.query, "R", "a capital has to be typable");
    }

    /// Every printable character, in both connection phases, must land in the
    /// query rather than firing a shortcut.
    ///
    /// The existing tests name `i` and `m` because those are the shortcuts the
    /// guard was written for. Naming examples cannot show that nothing *else*
    /// gets through, and something did: `r` is the connection-retry key and it
    /// is handled above the guard rather than below it, so it only escaped while
    /// the client was in the error phase. The overlay is dismissable so the
    /// client stays usable offline, and reading back through settled history is
    /// exactly what one does offline — "server", "error" and "brian" all carry
    /// an r.
    #[test]
    fn no_printable_character_is_stolen_from_the_search_prompt() {
        let (sender, _receiver) = mpsc::channel::<String>(64);
        for error_phase in [false, true] {
            let mut stolen = Vec::new();
            for character in ' '..='~' {
                let mut app = searchable_app();
                app.phase = if error_phase {
                    crate::tui::app::TuiPhase::Error("offline".to_string())
                } else {
                    crate::tui::app::TuiPhase::Connected
                };
                app.search.open(app.msg_scroll);
                let before = app.search.query.clone();
                handle_key_event(&mut app, press(KeyCode::Char(character)), &sender);
                if app.search.query == before {
                    stolen.push(character);
                }
            }
            assert!(
                stolen.is_empty(),
                "error_phase={error_phase}: these never reached the query: {stolen:?}"
            );
        }
    }

    /// The other direction. Guarding the retry on the prompt must not stop it
    /// working when the prompt is shut, which is the only time it should.
    #[test]
    fn r_still_retries_the_connection_when_no_search_is_open() {
        let (sender, _receiver) = mpsc::channel::<String>(8);
        let mut app = searchable_app();
        app.phase = crate::tui::app::TuiPhase::Error("offline".to_string());
        assert!(!app.search.prompt_open, "precondition: no prompt");

        handle_key_event(&mut app, press(KeyCode::Char('r')), &sender);

        assert!(
            app.pending_connection_retry,
            "with no prompt open, r is still the retry key"
        );
    }

    fn searchable_app() -> App {
        let mut app = app_with_backlog();
        app.focus_area = FocusArea::MainPanel;
        app
    }

    #[test]
    fn slash_opens_the_prompt_from_the_log_and_esc_puts_the_scroll_back() {
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        app.msg_scroll = 12;

        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);
        assert!(app.search.prompt_open, "the log's / opens the prompt");

        type_into_search(&mut app, "line 3");
        handle_key_event(&mut app, press(KeyCode::Esc), &sender);

        assert!(!app.search.prompt_open);
        assert_eq!(app.msg_scroll, 12, "cancelling returns to where the log was");
    }

    #[test]
    fn typing_i_into_the_prompt_searches_rather_than_opening_the_viewer() {
        // `i` opens the image viewer from the log. While the prompt is taking
        // keys it must not, or no query containing an i can be typed at all —
        // and the ordering that guarantees that lives in `handle_key_event`,
        // which is why this drives the real entry point.
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);

        type_into_search(&mut app, "line");

        assert!(!app.viewer.open, "the viewer must not have opened");
        assert_eq!(app.search.query, "line");
    }

    #[test]
    fn typing_m_into_the_prompt_does_not_open_the_map() {
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);

        type_into_search(&mut app, "meshy");

        assert!(!app.map_open, "the map must not have opened");
        assert_eq!(app.search.query, "meshy");
    }

    #[test]
    fn committing_a_search_scrolls_the_match_into_view() {
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);
        type_into_search(&mut app, "line 5");
        handle_key_event(&mut app, press(KeyCode::Enter), &sender);

        assert!(!app.search.prompt_open, "Enter closes the prompt");
        // "line 5" matches only index 5 of the forty, so the log has to have
        // moved back from the newest end.
        assert!(app.msg_scroll > 0, "the log scrolled to reach the match");
        let (messages, _, _) = app.get_current_messages();
        let end = messages.len() - app.msg_scroll;
        let start = end.saturating_sub(app.message_viewport_height);
        assert!((start..end).contains(&5), "the match is on screen");
    }

    #[test]
    fn n_walks_matches_only_once_a_search_has_found_something() {
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);

        // Before any search, `n` is an ordinary key in the log and must not be
        // swallowed into a search that does not exist.
        let before = app.msg_scroll;
        handle_key_event(&mut app, press(KeyCode::Char('n')), &sender);
        assert_eq!(app.msg_scroll, before, "n does nothing with no search");

        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);
        type_into_search(&mut app, "line 1");
        handle_key_event(&mut app, press(KeyCode::Enter), &sender);

        // "line 1" matches 1 and 10..19 — eleven lines, so there is something
        // to walk in both directions.
        let first = app.search.current().expect("a match");
        handle_key_event(&mut app, press(KeyCode::Char('N')), &sender);
        let older = app.search.current().expect("a match");
        assert!(older < first, "N steps towards older matches");

        handle_key_event(&mut app, press(KeyCode::Char('n')), &sender);
        assert_eq!(app.search.current(), Some(first), "n comes back");
    }

    #[test]
    fn a_search_that_finds_nothing_leaves_the_log_where_it_was() {
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        app.msg_scroll = 7;

        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);
        type_into_search(&mut app, "nonesuch");
        handle_key_event(&mut app, press(KeyCode::Enter), &sender);

        assert_eq!(app.msg_scroll, 7, "nothing to jump to, nothing moved");
        assert!(!app.search.is_walking(), "and n is not captured");
    }

    #[test]
    fn switching_conversation_forgets_a_finished_search() {
        // The hits are indices into one conversation. Carried across a switch
        // they would point at whatever sits at that position in another log.
        let mut app = searchable_app();
        let (sender, _receiver) = mpsc::channel::<String>(8);
        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);
        type_into_search(&mut app, "line 5");
        handle_key_event(&mut app, press(KeyCode::Enter), &sender);
        assert!(app.search.is_walking());

        app.switch_to_public();

        assert!(!app.search.is_walking(), "the search did not survive the switch");
        assert_eq!(app.search.current(), None);
    }

    #[test]
    fn slash_in_the_compose_box_is_still_a_command_prefix() {
        // The one thing this feature must not break: `/` starts `/map`,
        // `/help` and the rest, and the log's `/` must not have stolen it.
        let mut app = composing("");
        let (sender, _receiver) = mpsc::channel::<String>(8);

        handle_key_event(&mut app, press(KeyCode::Char('/')), &sender);

        assert!(!app.search.prompt_open, "no search from the input box");
        assert_eq!(app.input.value(), "/", "the slash was typed as text");
    }

    #[test]
    fn the_wheel_scrolls_back_through_the_log_and_forward_again() {
        let mut app = app_with_backlog();
        assert_eq!(app.msg_scroll, 0, "starts at the newest line");

        handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.msg_scroll, WHEEL_LINES, "up goes back through history");

        handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.msg_scroll, 0, "down comes back to the present");
    }

    #[test]
    fn the_wheel_cannot_scroll_past_either_end() {
        let mut app = app_with_backlog();

        // Far more notches than there are lines.
        for _ in 0..100 {
            handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));
        }
        let ceiling = 40usize.saturating_sub(app.message_viewport_height);
        assert_eq!(app.msg_scroll, ceiling, "clamped to the oldest line");

        for _ in 0..100 {
            handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
        }
        assert_eq!(app.msg_scroll, 0, "and saturates at the newest, not below");
    }

    #[test]
    fn the_wheel_does_nothing_while_an_overlay_owns_the_screen() {
        // The map and the viewer cover the log. Scrolling something the user
        // cannot see, so that it has moved when they close the overlay, is worse
        // than ignoring the wheel.
        let mut app = app_with_backlog();
        app.open_map();

        handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));

        assert_eq!(app.msg_scroll, 0, "the log did not move behind the map");
    }

    #[test]
    fn a_pasted_newline_does_not_send_anything() {
        // The whole point. Without bracketed paste this arrived as keystrokes and
        // the embedded return fired Enter, sending "first" on its own.
        let (tx, mut rx) = mpsc::channel::<String>(4);
        let mut app = App::new_with_nickname("tui".into());

        handle_paste_event(&mut app, "first\nsecond");

        assert_eq!(
            app.input.value(),
            "first second",
            "both halves are in the box, newline folded to a space"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing was sent — a paste is composition, not a send"
        );
        drop(tx);
    }

    #[test]
    fn a_paste_appends_to_what_is_already_typed() {
        let mut app = App::new_with_nickname("tui".into());
        app.input = tui_input::Input::new("look at ".to_string()).with_cursor(8);

        handle_paste_event(&mut app, "https://example.invalid/x.png");

        assert_eq!(app.input.value(), "look at https://example.invalid/x.png");
    }

    #[test]
    fn a_paste_takes_the_focus_to_the_compose_box() {
        // Text arriving means the user means to type, wherever Tab left them.
        let mut app = App::new_with_nickname("tui".into());
        app.focus_area = FocusArea::Sidebar;

        handle_paste_event(&mut app, "words");

        assert_eq!(app.focus_area, FocusArea::InputBox);
    }

    #[test]
    fn a_paste_of_nothing_but_control_characters_is_dropped() {
        let mut app = App::new_with_nickname("tui".into());

        handle_paste_event(&mut app, "\r\n\t\u{7}");

        assert!(
            app.input.value().is_empty(),
            "got {:?}",
            app.input.value()
        );
    }

    #[test]
    fn a_paste_is_ignored_while_an_overlay_owns_the_screen() {
        let mut app = App::new_with_nickname("tui".into());
        app.open_map();

        handle_paste_event(&mut app, "words");

        assert!(app.input.value().is_empty(), "the map has the keyboard");
    }
}
