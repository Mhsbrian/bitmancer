// src/tui/map.rs
//
// State for the world map view: where we are zoomed to, which cell is under the
// cursor, and how much life each visible cell is showing. Rendering lives in
// widgets/map_panel.rs and the network sampling in main.rs, so this stays pure
// and testable.

use std::collections::HashMap;

use crate::geohash::{self, BBox, GridCell};

/// Deepest cell the map will drill to — the building level, matching the
/// finest channel the phone app offers.
pub const MAX_PRECISION: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct CellActivity {
    /// Distinct identities seen in this cell. Counting raw events instead would
    /// report presence beacons — two dozen idle people beacon hundreds of times
    /// a minute, which reads as a busy conversation when it is an empty room.
    seen: std::collections::HashSet<String>,
    /// Chat messages, as opposed to bare presence beacons.
    pub messages: usize,
}

impl CellActivity {
    pub fn people(&self) -> usize {
        self.seen.len()
    }

    pub fn is_silent(&self) -> bool {
        self.seen.is_empty() && self.messages == 0
    }
}

/// How many cells the hotspot list will name.
///
/// Short on purpose. The point is to answer "where is anything happening" at a
/// glance; a list long enough to need reading is a list nobody reads.
pub const HOTSPOT_LIMIT: usize = 8;

/// A live channel, ranked against the others currently being sampled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hotspot {
    /// The channel itself, at the precision the sampler subscribed to — so this
    /// is a geohash someone can actually join, not a display cell.
    pub geohash: String,
    pub people: usize,
    pub messages: usize,
}

/// Which half of the map the keyboard is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapFocus {
    /// The grid of cells, navigated with the arrow keys.
    Grid,
    /// The hotspot list beside it.
    Hotspots,
}

pub struct MapState {
    /// Prefix currently subdivided across the grid. Empty means the world.
    focus: String,
    /// Index into `cells()`, in grid order.
    selection: usize,
    layout: Vec<GridCell>,
    activity: HashMap<String, CellActivity>,
    /// The same traffic, kept at the precision it actually arrived at.
    ///
    /// `activity` answers "how hot is this square", so it rolls every event up
    /// to whichever cell is on screen. That is the wrong shape for the question
    /// "where should I go": at the world view it collapses a thousand channels
    /// into thirty-two continents, and a continent is not somewhere you can
    /// join. The sampler has always subscribed to real channels and this keeps
    /// what it hears from them.
    hotspots: HashMap<String, CellActivity>,
    /// Index into `top_hotspots()`, when the list has the keyboard.
    hotspot_selection: usize,
    pub pane: MapFocus,
    /// Set by navigation so the main loop knows to re-point the sampler.
    pub view_dirty: bool,
}

impl Default for MapState {
    fn default() -> Self {
        Self::new()
    }
}

impl MapState {
    pub fn new() -> Self {
        let mut map = Self {
            focus: String::new(),
            selection: 0,
            layout: Vec::new(),
            activity: HashMap::new(),
            hotspots: HashMap::new(),
            hotspot_selection: 0,
            pane: MapFocus::Grid,
            view_dirty: true,
        };
        map.set_focus(String::new());
        map
    }

    /// Jumps straight to a cell, opening the map focused on its parent with the
    /// cell selected — used when opening the map while in a channel.
    pub fn focus_on(&mut self, geohash: &str) {
        let mut chars: Vec<char> = geohash.chars().collect();
        let Some(last) = chars.pop() else {
            return;
        };
        self.set_focus(chars.into_iter().collect());
        if let Some(index) = self
            .layout
            .iter()
            .position(|cell| cell.geohash.ends_with(last))
        {
            self.selection = index;
        }
    }

    fn set_focus(&mut self, focus: String) {
        self.focus = focus;
        self.layout = geohash::grid_layout(&self.focus);
        // Base32 index 0 is the *south-west* cell, which would make the cursor
        // appear in the bottom-left corner. Start north-west instead, so the
        // cursor lands where the eye does.
        self.selection = self
            .layout
            .iter()
            .position(|cell| cell.row == 0 && cell.col == 0)
            .unwrap_or(0);
        self.activity.clear();
        // Cleared with the view, not kept across it. Moving the map re-points
        // the sampler, so a leaderboard held over from the last view would be
        // sourced from subscriptions we no longer hold — stale readings
        // presented as live ones, which is worse than an empty list.
        self.hotspots.clear();
        self.hotspot_selection = 0;
        self.view_dirty = true;
    }

    pub fn focus(&self) -> &str {
        &self.focus
    }

    pub fn cells(&self) -> &[GridCell] {
        &self.layout
    }

    pub fn selected(&self) -> &GridCell {
        &self.layout[self.selection.min(self.layout.len() - 1)]
    }

    pub fn selected_geohash(&self) -> &str {
        &self.selected().geohash
    }

    /// Region the canvas should show: the focus cell with breathing room, or
    /// the whole world at the top level.
    pub fn viewport(&self) -> BBox {
        if self.focus.is_empty() {
            BBox::world()
        } else {
            geohash::bbox(&self.focus).padded(0.15)
        }
    }

    pub fn precision(&self) -> usize {
        self.focus.chars().count() + 1
    }

    /// Human label for the level currently shown, e.g. "city".
    pub fn level_label(&self) -> Option<&'static str> {
        geohash::level_name(self.precision())
    }

    pub fn can_drill_in(&self) -> bool {
        self.precision() < MAX_PRECISION
    }

    pub fn can_drill_out(&self) -> bool {
        !self.focus.is_empty()
    }

    /// Descends into the selected cell.
    pub fn drill_in(&mut self) -> bool {
        if !self.can_drill_in() {
            return false;
        }
        let target = self.selected_geohash().to_string();
        self.set_focus(target);
        true
    }

    /// Rises one level, keeping the cell we came from selected.
    pub fn drill_out(&mut self) -> bool {
        if !self.can_drill_out() {
            return false;
        }
        let previous = self.focus.clone();
        let mut chars: Vec<char> = previous.chars().collect();
        let last = chars.pop();
        self.set_focus(chars.into_iter().collect());
        if let Some(last) = last {
            if let Some(index) = self
                .layout
                .iter()
                .position(|cell| cell.geohash.ends_with(last))
            {
                self.selection = index;
            }
        }
        true
    }

    /// Moves the cursor across the grid as it is drawn.
    pub fn move_selection(&mut self, delta_row: isize, delta_col: isize) {
        let (rows, cols) = self.dimensions();
        let current = self.selected().clone();
        let row = (current.row as isize + delta_row).clamp(0, rows as isize - 1) as usize;
        let col = (current.col as isize + delta_col).clamp(0, cols as isize - 1) as usize;
        if let Some(index) = self
            .layout
            .iter()
            .position(|cell| cell.row == row && cell.col == col)
        {
            self.selection = index;
        }
    }

    pub fn dimensions(&self) -> (usize, usize) {
        let rows = self.layout.iter().map(|cell| cell.row).max().unwrap_or(0) + 1;
        let cols = self.layout.iter().map(|cell| cell.col).max().unwrap_or(0) + 1;
        (rows, cols)
    }

    // MARK: - Activity

    /// Records traffic heard anywhere inside a visible cell. Events are tagged
    /// with their own full geohash, so a message in `9q8yy` rolls up to the `9`
    /// cell when the world is on screen.
    pub fn note_voice(&mut self, geohash: &str, pubkey: &str, is_message: bool) {
        let Some(cell) = self
            .layout
            .iter()
            .find(|cell| geohash.starts_with(&cell.geohash))
            .map(|cell| cell.geohash.clone())
        else {
            return;
        };
        let entry = self.activity.entry(cell).or_default();
        entry.seen.insert(pubkey.to_string());
        if is_message {
            entry.messages += 1;
        }

        // The same event, kept where it happened. `geohash` here is the cell
        // the sampler subscribed to, so it is a channel with people in it
        // rather than the square it is drawn inside.
        let hotspot = self.hotspots.entry(geohash.to_string()).or_default();
        hotspot.seen.insert(pubkey.to_string());
        if is_message {
            hotspot.messages += 1;
        }
    }

    /// The busiest channels currently being sampled, best first.
    ///
    /// Ranked by people rather than messages, matching the heat on the grid: a
    /// room's draw is who is in it, and the readout has always distinguished
    /// being *there* from *talking*. Messages break the tie, so between two
    /// equally full cells the one holding a conversation wins, and the geohash
    /// breaks that — a list that reshuffles between frames cannot be read.
    pub fn top_hotspots(&self) -> Vec<Hotspot> {
        let mut ranked: Vec<Hotspot> = self
            .hotspots
            .iter()
            .filter(|(_, activity)| !activity.is_silent())
            .map(|(geohash, activity)| Hotspot {
                geohash: geohash.clone(),
                people: activity.people(),
                messages: activity.messages,
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.people
                .cmp(&a.people)
                .then(b.messages.cmp(&a.messages))
                .then(a.geohash.cmp(&b.geohash))
        });
        ranked.truncate(HOTSPOT_LIMIT);
        ranked
    }

    /// Where the cursor actually sits, which is not always where it was left.
    ///
    /// The list is rebuilt from live traffic and shrinks when a cell goes
    /// quiet, so the stored index can point past the end. Clamping in one place
    /// keeps the highlight and the Enter key agreeing about which row is under
    /// the cursor — if they ever disagreed, the map would dive somewhere other
    /// than the row the user is looking at.
    pub fn hotspot_cursor(&self) -> usize {
        self.hotspot_selection
            .min(self.top_hotspots().len().saturating_sub(1))
    }

    /// The hotspot under the cursor, when the list has the keyboard.
    pub fn selected_hotspot(&self) -> Option<Hotspot> {
        self.top_hotspots().into_iter().nth(self.hotspot_cursor())
    }

    /// Moves within the list, stopping at both ends.
    ///
    /// Deliberately not wrapping. The list reorders itself as traffic arrives,
    /// and a cursor that jumps from the last row to the first would be
    /// indistinguishable from the ranking shifting under it.
    pub fn move_hotspot_selection(&mut self, delta: isize) {
        let count = self.top_hotspots().len();
        if count == 0 {
            self.hotspot_selection = 0;
            return;
        }
        let next = (self.hotspot_selection as isize + delta).clamp(0, count as isize - 1);
        self.hotspot_selection = next as usize;
    }

    /// Switches which pane the keyboard drives.
    ///
    /// Refuses to hand the keyboard to an empty list, which would look exactly
    /// like the key doing nothing.
    pub fn toggle_pane(&mut self) -> MapFocus {
        self.pane = match self.pane {
            MapFocus::Grid if !self.top_hotspots().is_empty() => MapFocus::Hotspots,
            _ => MapFocus::Grid,
        };
        self.pane
    }

    /// Jumps the map to a cell and puts the cursor on it, so the surroundings
    /// are visible rather than the cell alone.
    ///
    /// Hands the keyboard back to the grid: having arrived somewhere, the next
    /// thing anyone wants is to look around it or go in.
    pub fn dive_to(&mut self, geohash: &str) {
        self.focus_on(geohash);
        self.pane = MapFocus::Grid;
    }

    pub fn activity(&self, geohash: &str) -> Option<&CellActivity> {
        self.activity.get(geohash)
    }

    /// Forgets sampled activity so a re-open starts cold.
    #[allow(dead_code)]
    pub fn clear_activity(&mut self) {
        self.activity.clear();
    }

    /// Busiest cell in view, used to scale the heat ramp.
    pub fn peak_activity(&self) -> usize {
        self.activity
            .values()
            .map(|activity| activity.people())
            .max()
            .unwrap_or(0)
    }

    pub fn live_cells(&self) -> usize {
        self.activity
            .values()
            .filter(|activity| !activity.is_silent())
            .count()
    }

    /// Geohashes the sampler should subscribe to for this view.
    ///
    /// Events are tagged with an exact geohash, and channels only exist at
    /// certain precisions (2, 4, 5, 6, 7, 8). A view whose cells are themselves
    /// a channel level can watch them directly; at the in-between levels (1 and
    /// 3) nobody publishes to the visible cells, so the sampler drops one level
    /// deeper — where the channels actually are — and `note_voice` rolls the
    /// traffic back up by prefix.
    pub fn sample_targets(&self) -> Vec<String> {
        if geohash::level_name(self.precision()).is_some() {
            return self
                .layout
                .iter()
                .map(|cell| cell.geohash.clone())
                .collect();
        }
        self.layout
            .iter()
            .flat_map(|cell| geohash::children(&cell.geohash))
            .collect()
    }
}

#[cfg(test)]
mod hotspot_tests {
    use super::*;

    /// Traffic in a cell, from `people` distinct identities.
    fn crowd(map: &mut MapState, geohash: &str, people: usize, messages: usize) {
        for index in 0..people {
            map.note_voice(geohash, &format!("{geohash}-person-{index}"), false);
        }
        for _ in 0..messages {
            map.note_voice(geohash, &format!("{geohash}-person-0"), true);
        }
    }

    #[test]
    fn the_list_names_channels_not_the_squares_they_are_drawn_in() {
        // The whole point. At the world view the grid shows 32 single-character
        // continents, and a continent is not somewhere anyone can join. The
        // sampler has always subscribed to real channels; this keeps what it
        // hears from them instead of averaging it into a landmass.
        let mut map = MapState::new();
        crowd(&mut map, "9q", 5, 2);
        crowd(&mut map, "9x", 2, 0);

        assert_eq!(map.activity("9").map(|a| a.people()), Some(7), "the square holds both");

        let top = map.top_hotspots();
        assert_eq!(top.len(), 2, "and the list keeps them apart");
        assert_eq!(top[0].geohash, "9q");
        assert_eq!(top[0].people, 5);
        assert_eq!(top[0].messages, 2);
        assert_eq!(top[1].geohash, "9x");
    }

    #[test]
    fn a_crowd_outranks_a_conversation_but_not_an_equal_one() {
        // People first, matching the grid's heat; messages break the tie, so
        // between two equally full rooms the one talking wins.
        let mut map = MapState::new();
        crowd(&mut map, "bc", 9, 0);
        crowd(&mut map, "cd", 3, 40);
        crowd(&mut map, "ce", 9, 5);

        let ranked = map.top_hotspots();
        let order: Vec<&str> = ranked.iter().map(|h| h.geohash.as_str()).collect();
        assert_eq!(order, vec!["ce", "bc", "cd"]);
    }

    #[test]
    fn the_order_is_stable_between_frames() {
        // The list is redrawn continuously. One that reshuffles when nothing
        // changed cannot be read, let alone aimed at.
        let mut map = MapState::new();
        for cell in ["bc", "cd", "ce", "cf"] {
            crowd(&mut map, cell, 4, 1);
        }
        assert_eq!(map.top_hotspots(), map.top_hotspots());
        let ranked = map.top_hotspots();
        let order: Vec<&str> = ranked.iter().map(|h| h.geohash.as_str()).collect();
        assert_eq!(order, vec!["bc", "cd", "ce", "cf"], "ties fall back to the name");
    }

    #[test]
    fn the_list_is_short_and_silent_cells_are_left_out() {
        let mut map = MapState::new();
        // Real children of a real cell, so these are geohashes the view
        // actually contains rather than strings that merely look like them.
        for (index, cell) in crate::geohash::children("z")
            .into_iter()
            .take(HOTSPOT_LIMIT + 6)
            .enumerate()
        {
            crowd(&mut map, &cell, index + 1, 0);
        }
        assert_eq!(map.top_hotspots().len(), HOTSPOT_LIMIT);
        assert!(
            map.top_hotspots().iter().all(|hotspot| hotspot.people > 0),
            "a cell nobody is in is not a place to go"
        );
    }

    #[test]
    fn moving_the_map_forgets_the_list() {
        // Navigating re-points the sampler. A leaderboard carried across would
        // be built from subscriptions we no longer hold — stale numbers shown
        // as live ones, which is worse than showing nothing.
        let mut map = MapState::new();
        crowd(&mut map, "9q", 5, 1);
        assert!(!map.top_hotspots().is_empty());
        map.drill_in();
        assert!(map.top_hotspots().is_empty());
    }

    #[test]
    fn the_cursor_never_points_past_the_list() {
        // The list shrinks when a cell goes quiet. If the highlight and the
        // Enter key disagreed about which row is under the cursor, the map
        // would dive somewhere other than where the user is looking.
        let mut map = MapState::new();
        crowd(&mut map, "bc", 3, 0);
        crowd(&mut map, "cd", 2, 0);
        map.toggle_pane();
        map.move_hotspot_selection(5);
        assert_eq!(map.hotspot_cursor(), 1, "clamped to the last row");
        assert_eq!(map.selected_hotspot().unwrap().geohash, "cd");

        // Now the list is rebuilt shorter, without the cursor being touched.
        map.hotspots.remove("cd");
        assert_eq!(map.hotspot_cursor(), 0);
        assert_eq!(map.selected_hotspot().unwrap().geohash, "bc");
    }

    #[test]
    fn the_cursor_stops_at_both_ends() {
        let mut map = MapState::new();
        crowd(&mut map, "bc", 3, 0);
        crowd(&mut map, "cd", 2, 0);
        map.move_hotspot_selection(-5);
        assert_eq!(map.hotspot_cursor(), 0, "and does not wrap round to the bottom");
        map.move_hotspot_selection(1);
        assert_eq!(map.hotspot_cursor(), 1);
    }

    #[test]
    fn the_keyboard_is_never_handed_to_an_empty_list() {
        // Otherwise the key looks broken: focus moves somewhere invisible and
        // every subsequent arrow press does nothing.
        let mut map = MapState::new();
        assert_eq!(map.toggle_pane(), MapFocus::Grid);

        crowd(&mut map, "9q", 1, 0);
        assert_eq!(map.toggle_pane(), MapFocus::Hotspots);
        assert_eq!(map.toggle_pane(), MapFocus::Grid, "and back again");
    }

    #[test]
    fn diving_shows_the_cell_in_its_surroundings() {
        // Not the cell alone: arriving somewhere with no context is
        // disorienting, and the next thing anyone does is look around.
        let mut map = MapState::new();
        crowd(&mut map, "9q", 5, 2);
        map.toggle_pane();
        let target = map.selected_hotspot().unwrap().geohash;
        assert_eq!(target, "9q");

        map.dive_to(&target);
        assert_eq!(map.focus(), "9", "focused on the parent");
        assert_eq!(map.selected_geohash(), "9q", "with the cell under the cursor");
        assert_eq!(map.pane, MapFocus::Grid, "and the keyboard back on the grid");
        assert!(map.view_dirty, "so the sampler follows");
    }

    #[test]
    fn a_dive_target_is_a_channel_anyone_can_join() {
        // The list is built from what the sampler subscribed to, and the
        // sampler only ever subscribes at real channel precisions. If that
        // stopped holding, Enter would offer to join something that cannot be.
        let map = MapState::new();
        for target in map.sample_targets() {
            assert!(
                crate::geohash::level_name(target.chars().count()).is_some(),
                "{target} is not a channel level"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_the_world_with_a_selection() {
        let map = MapState::new();
        assert_eq!(map.focus(), "");
        assert_eq!(map.cells().len(), 32);
        assert_eq!(map.precision(), 1);
        assert_eq!(map.viewport(), BBox::world());
        assert!(map.can_drill_in());
        assert!(!map.can_drill_out(), "already at the top");
    }

    #[test]
    fn drilling_in_and_out_returns_to_where_you_were() {
        let mut map = MapState::new();
        map.move_selection(1, 3);
        let departed = map.selected_geohash().to_string();

        assert!(map.drill_in());
        assert_eq!(map.focus(), departed);
        assert_eq!(map.precision(), 2);
        assert!(map.selected_geohash().starts_with(&departed));

        assert!(map.drill_out());
        assert_eq!(map.focus(), "");
        assert_eq!(
            map.selected_geohash(),
            departed,
            "the cell we came from stays under the cursor"
        );
    }

    #[test]
    fn drilling_stops_at_the_building_level() {
        let mut map = MapState::new();
        for _ in 0..MAX_PRECISION * 2 {
            map.drill_in();
        }
        assert_eq!(map.precision(), MAX_PRECISION);
        assert!(!map.can_drill_in());
        assert!(!map.drill_in(), "must refuse rather than go deeper");
        assert_eq!(map.focus().chars().count(), MAX_PRECISION - 1);
    }

    #[test]
    fn the_cursor_starts_north_west() {
        let map = MapState::new();
        assert_eq!((map.selected().row, map.selected().col), (0, 0));
    }

    #[test]
    fn selection_moves_on_the_visible_grid_and_clamps() {
        let mut map = MapState::new();
        let (rows, cols) = map.dimensions();
        assert_eq!((rows, cols), (4, 8));

        map.move_selection(-1, -1);
        assert_eq!(
            (map.selected().row, map.selected().col),
            (0, 0),
            "clamped at the north-west corner"
        );

        map.move_selection(1, 1);
        assert_eq!((map.selected().row, map.selected().col), (1, 1));

        map.move_selection(10, 10);
        assert_eq!(
            (map.selected().row, map.selected().col),
            (rows - 1, cols - 1),
            "clamped at the far corner"
        );
    }

    #[test]
    fn moving_west_decreases_longitude() {
        let mut map = MapState::new();
        map.move_selection(0, 4);
        let east = map.selected().bbox.center().1;
        map.move_selection(0, -1);
        let west = map.selected().bbox.center().1;
        assert!(west < east, "left must go west: {west} vs {east}");
    }

    #[test]
    fn moving_north_increases_latitude() {
        let mut map = MapState::new();
        map.move_selection(3, 0);
        let south = map.selected().bbox.center().0;
        map.move_selection(-1, 0);
        let north = map.selected().bbox.center().0;
        assert!(north > south, "up must go north: {north} vs {south}");
    }

    #[test]
    fn viewport_tightens_as_you_drill() {
        let mut map = MapState::new();
        let world = map.viewport();
        map.drill_in();
        let region = map.viewport();
        assert!(region.width() < world.width());
        assert!(region.height() < world.height());
    }

    #[test]
    fn focus_on_selects_the_cell_inside_its_parent() {
        let mut map = MapState::new();
        map.focus_on("9q8yy");
        assert_eq!(map.focus(), "9q8y");
        assert_eq!(map.selected_geohash(), "9q8yy");
        assert_eq!(map.precision(), 5);
        assert_eq!(map.level_label(), Some("city"));
    }

    #[test]
    fn level_labels_only_appear_at_channel_precisions() {
        let mut map = MapState::new();
        assert_eq!(map.level_label(), None, "precision 1 is not a level");
        map.drill_in();
        assert_eq!(map.level_label(), Some("region"));
        map.drill_in();
        assert_eq!(map.level_label(), None, "precision 3 is not a level");
        map.drill_in();
        assert_eq!(map.level_label(), Some("province"));
    }

    #[test]
    fn activity_accumulates_and_resets_on_navigation() {
        let mut map = MapState::new();
        let cell = map.selected_geohash().to_string();
        map.note_voice(&cell, "alice", true);
        map.note_voice(&cell, "alice", false);
        map.note_voice(&cell, "bob", false);

        let activity = map.activity(&cell).expect("recorded");
        assert_eq!(activity.people(), 2, "two identities, three events");
        assert_eq!(activity.messages, 1);
        assert_eq!(map.peak_activity(), 2);
        assert_eq!(map.live_cells(), 1);

        map.drill_in();
        assert!(map.activity(&cell).is_none(), "a new view starts cold");
        assert_eq!(map.peak_activity(), 0);
    }

    #[test]
    fn navigation_marks_the_view_dirty_for_the_sampler() {
        let mut map = MapState::new();
        map.view_dirty = false;
        map.move_selection(0, 1);
        assert!(!map.view_dirty, "moving the cursor does not change the view");

        map.drill_in();
        assert!(map.view_dirty, "drilling changes what must be sampled");
    }

    #[test]
    fn sample_targets_reach_the_nearest_channel_level() {
        // Precision 1 is not a channel level, so watch the regions beneath it.
        let map = MapState::new();
        let targets = map.sample_targets();
        assert_eq!(targets.len(), 32 * 32);
        assert!(targets.contains(&"9q".to_string()));
        assert!(!targets.contains(&"9".to_string()));

        // Precision 2 is the region level, watched directly.
        let mut map = MapState::new();
        map.drill_in();
        let targets = map.sample_targets();
        assert_eq!(targets.len(), 32);
        assert!(targets.iter().all(|cell| cell.chars().count() == 2));
    }

    #[test]
    fn activity_rolls_up_to_the_visible_cell() {
        // A message in a city channel should light up the region cell that
        // contains it when the world is on screen.
        let mut map = MapState::new();
        map.note_voice("9q8yy", "alice", true);
        let cell = map
            .cells()
            .iter()
            .find(|cell| cell.geohash == "9")
            .expect("cell 9 is on the world grid");
        let activity = map.activity(&cell.geohash).expect("rolled up");
        assert_eq!(activity.people(), 1);
        assert_eq!(activity.messages, 1);
    }

    #[test]
    fn activity_outside_the_view_is_ignored() {
        let mut map = MapState::new();
        map.drill_in(); // focused on one cell's children
        let focus = map.focus().to_string();
        let elsewhere = if focus == "9" { "dr5r" } else { "9q8yy" };
        map.note_voice(elsewhere, "alice", true);
        assert_eq!(map.peak_activity(), 0);
    }
}
