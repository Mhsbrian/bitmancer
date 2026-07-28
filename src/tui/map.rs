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

pub struct MapState {
    /// Prefix currently subdivided across the grid. Empty means the world.
    focus: String,
    /// Index into `cells()`, in grid order.
    selection: usize,
    layout: Vec<GridCell>,
    activity: HashMap<String, CellActivity>,
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
