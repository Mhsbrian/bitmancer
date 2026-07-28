// src/tui/event.rs

use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers, KeyEventKind};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;

use crate::tui::app::{App, FocusArea};
use crate::tui::widgets::sidebar::sidebar_visible_items;

pub fn handle_key_event(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    if key_event.kind != KeyEventKind::Press {
        return;
    }
    if key_event.code == KeyCode::Char('c') && key_event.modifiers == KeyModifiers::CONTROL {
        app.should_quit = true;
        return;
    }
    if matches!(app.phase, crate::tui::app::TuiPhase::Error(_)) && key_event.code == KeyCode::Char('r') {
        app.trigger_connection_retry();
        return;
    }
    if app.popup_active {
        handle_popup_events(app, key_event, input_tx);
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
    // The map takes the whole keyboard while it is open. This must come before
    // the connection-overlay dismissal below, which would otherwise swallow
    // every Esc while offline and leave the map with no way back out.
    if app.map_open {
        handle_map_events(app, key_event);
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
        KeyCode::Up => app.map.move_selection(-1, 0),
        KeyCode::Down => app.map.move_selection(1, 0),
        KeyCode::Left => app.map.move_selection(0, -1),
        KeyCode::Right => app.map.move_selection(0, 1),
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

fn handle_main_panel_events(app: &mut App, key_event: KeyEvent) {
    let (messages, _, _) = app.get_current_messages();
    let total_messages = messages.len();
    let messages_height = app.message_viewport_height;
    
    let max_scroll = total_messages.saturating_sub(messages_height);

    match key_event.code {
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
            // FIX: Ignore the return value of handle_event
            let _ = app.input.handle_event(&CrosstermEvent::Key(key_event));
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
}
