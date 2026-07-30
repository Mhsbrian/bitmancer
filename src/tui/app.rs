// src/tui/app.rs

use tui_input::Input;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use regex::Regex;
use chrono;

#[derive(Debug, Clone)]
pub struct Message {
    pub sender: String,
    pub timestamp: String,
    pub content: String,
    pub is_self: bool,
    /// Seconds since the epoch, used only for ordering. Relays replay stored
    /// events at their own pace, so a slow one can deliver an hour-old message
    /// after the live ones; appending in arrival order puts it at the bottom.
    pub epoch: i64,
    /// Wire identifier, on private messages we sent. A receipt names this, and
    /// without it an acknowledgement could only ever tick the newest line.
    pub message_id: Option<String>,
    /// How far this message has got, once a peer has said.
    pub delivery: Option<crate::mesh::DeliveryStatus>,
    /// When this line landed, which drives the arrival animation. `None` means
    /// it was never new to us — replayed history, or one of a flood — and it is
    /// drawn at rest.
    pub arrived: Option<Instant>,
}

impl Message {
    fn now(sender: String, content: String, is_self: bool) -> Self {
        let now = chrono::Local::now();
        Self {
            sender,
            timestamp: now.format("%H:%M").to_string(),
            content,
            is_self,
            epoch: now.timestamp(),
            message_id: None,
            delivery: None,
            arrived: Some(Instant::now()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SidebarSection {
    Channels,
    People,
    Blocked,
    Settings,
}

pub struct SidebarMenuState {
    pub expanded: [bool; 5], // Public, Channels, People, Blocked, Settings
    pub public_selected: Option<bool>,
    pub channel_selected: Option<usize>,
    pub people_selected: Option<usize>,
    pub blocked_selected: Option<usize>,
}

impl SidebarMenuState {
    pub fn new() -> Self {
        Self {
            expanded: [true, true, true, true, true], // All sections expanded by default
            public_selected: Some(true), // Default to public selected
            channel_selected: None, // No channel selected by default since public is selected
            people_selected: None,
            blocked_selected: None,
        }
    }

    pub fn toggle_expand(&mut self, section_index: usize) {
        if section_index < self.expanded.len() {
            self.expanded[section_index] = !self.expanded[section_index];
        }
    }
}

pub enum TuiPhase {
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    MainPanel,
    InputBox,
}

pub struct App {
    // UI state
    pub input: Input,
    pub phase: TuiPhase,
    pub should_quit: bool,
    pub focus_area: FocusArea,
    pub sidebar_flat_selected: usize,
    pub msg_scroll: usize,
    pub message_viewport_height: usize, // ADDED: To store the height of the message panel
    
    // Data state for rendering
    pub nickname: String,
    #[allow(dead_code)]
    pub network_name: String,
    pub connected: bool,
    pub channels: Vec<String>,
    pub people: Vec<String>,
    pub blocked: Vec<String>,
    
    // Message storage
    pub channel_messages: HashMap<String, Vec<Message>>,
    pub dm_messages: HashMap<String, Vec<Message>>,
    
    // Navigation and Popups
    pub sidebar_state: SidebarMenuState,
    pub popup_messages: Vec<String>,
    
    // To track current conversation for message routing and scroll reset
    pub current_conv: Option<(Option<String>, Option<String>)>, // (DM target, Channel name)
    
    // To signal when backend channel switch is needed
    pub pending_channel_switch: Option<String>,
    // To signal when backend DM switch is needed
    pub pending_dm_switch: Option<(String, String)>, // (nickname, peer_id)
    // To signal when backend nickname update is needed
    pub pending_nickname_update: Option<String>,
    // To signal when backend should retry connection
    pub pending_connection_retry: bool,
    // To signal when conversation should be cleared
    pub pending_clear_conversation: bool,
    
    // Unread message tracking
    pub unread_counts: HashMap<String, usize>, // Channel/DM name -> unread count
    pub last_read_messages: HashMap<String, usize>, // Channel/DM name -> last read message count
    
    // Popup state
    pub popup_active: bool,
    pub popup_input: Input,
    pub popup_title: String,
    /// The connection popup covers the whole UI. Since reconnection now runs
    /// forever in the background, Esc dismisses it so the client stays usable
    /// (history, /help, composing) while offline.
    pub connection_popup_dismissed: bool,

    /// Which emoji suggestion is highlighted, and whether the strip has been
    /// dismissed for the shortcode currently being typed.
    ///
    /// The query itself is not stored — it is derived from the input every frame,
    /// so it cannot drift out of step with what is actually on screen.
    pub emoji_selection: usize,
    emoji_dismissed_for: Option<String>,

    /// Frame counter, used only to animate the connection spinner.
    pub tick: usize,
    /// When this session began, for the uptime readout.
    pub started: std::time::Instant,
    /// First half of our mesh peer ID, as shown in the status band.
    pub short_peer_id: String,

    // Images posted as links
    pub viewer: crate::tui::viewer::Viewer,
    pub images: crate::media::ImageCache,
    /// Sizes kept alongside the cache so the panel can show them without
    /// borrowing the cache mutably mid-render.
    pub image_dimensions: std::collections::HashMap<String, (u32, u32)>,
    pub image_backend: crate::tui::image_render::Backend,
    /// Where the kitty escape sequence should paint, set during render and
    /// consumed by the main loop after the frame is flushed.
    pub pending_image_slot: Option<crate::tui::widgets::image_panel::ImageSlot>,
    /// Set when the user asks to hand the current image to their browser.
    pub pending_image_open_external: bool,

    // World map overlay
    pub map_open: bool,
    pub map: crate::tui::map::MapState,
    /// Geohash channels currently joined, so the map can mark them.
    pub joined_geohashes: std::collections::HashSet<String>,
    /// How much of other people's traffic we have carried, and `None` when we
    /// are not carrying at all.
    ///
    /// On the status band rather than behind a command: this mode spends the
    /// user's bandwidth and puts their address on relays for messages they did
    /// not write, and a mode like that should not be possible to forget.
    pub carrying: Option<usize>,
    /// How much mail is on the shelf, and `None` when not holding any.
    ///
    /// On the band for the same reason as `carrying`: this one stores other
    /// people's data on the user's disk, and that should not be forgettable.
    pub holding: Option<usize>,
    /// The mesh graph overlay, and the picture it draws. Rebuilt from the mesh
    /// layer each frame it is open — cheap for a handful of peers, and always
    /// current, which a cached graph of a moving mesh would not be.
    pub mesh_view_open: bool,
    pub topology: crate::topology::Topology,
    /// Set when the map asks to join the cell under the cursor.
    pub pending_geohash_join: Option<String>,
    /// Recognises floods of arriving lines so they do not all light up.
    arrival_gate: ArrivalGate,
    /// Messages we have already told the sender we read.
    read_receipts_sent: std::collections::HashSet<String>,
}

/// A flood is not news. A relay flushing its backlog delivers dozens of lines
/// in one instant, and lighting all of them turns a cascade into a flash, so a
/// burst settles silently instead.
const BURST_WINDOW: Duration = Duration::from_millis(400);
const BURST_LIMIT: usize = 4;

/// How far behind our own clock a line can be stamped and still count as news.
///
/// Generous on purpose. A geohash event carries the *sender's* clock from
/// before it was mined and relayed, so reaching us a few seconds "in the past"
/// is the normal case rather than the exception, and two phones in the same
/// channel rarely agree to the second. Judging newness by position in the log
/// instead — which is what this replaced — silently muted almost every real
/// message, because the live divider is stamped with our own clock and
/// everything that arrived afterwards sorted in behind it.
const LIVE_HORIZON: i64 = 120;

/// Whether a line's own timestamp says it belongs to the present. An hour-old
/// backlog is nowhere near, which is the distinction that matters.
fn is_current(epoch: i64) -> bool {
    chrono::Local::now().timestamp() - epoch <= LIVE_HORIZON
}

/// Places a message by time rather than by arrival, so a slow relay replaying
/// an old backlog cannot drop an hour-old line under the live conversation.
/// Walks from the end because the common case is "newest, goes last".
fn insert_in_time_order(
    messages: &mut Vec<Message>,
    mut message: Message,
    admitted: Option<Instant>,
) {
    let position = messages
        .iter()
        .rposition(|existing| existing.epoch <= message.epoch)
        .map(|index| index + 1)
        .unwrap_or(0);

    // Newness is about the clock, not about where the line lands. A message
    // that sorts into the middle because its sender's clock runs a little slow
    // is still something that just happened; one stamped an hour ago is the
    // backlog, wherever it ends up sitting.
    if is_current(message.epoch) {
        apply_admission(messages, &mut message, admitted);
    } else {
        message.arrived = None;
    }
    messages.insert(position, message);
}

/// Counts how fast lines are landing, so a flood can be recognised as one.
///
/// This has to live outside the messages themselves: clearing a line's arrival
/// stamp is exactly what marks it as part of a burst, which also destroys the
/// evidence that it was ever part of one. Counting here instead means the run
/// is measured from the first line of the flood rather than from the last one
/// that happened to still be lit.
#[derive(Debug, Default)]
pub struct ArrivalGate {
    recent: VecDeque<Instant>,
}

impl ArrivalGate {
    /// Stamps a line as newly arrived, or refuses it because too many have
    /// landed together to be worth announcing individually.
    fn admit(&mut self) -> Option<Instant> {
        let now = Instant::now();
        while self
            .recent
            .front()
            .is_some_and(|at| now.duration_since(*at) >= BURST_WINDOW)
        {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        (self.recent.len() <= BURST_LIMIT).then_some(now)
    }
}

/// Appends a line and applies the same arrival policy the time-ordered path
/// uses, so a command that prints fifteen rows at once settles quietly instead
/// of lighting the whole pane.
fn push_arrival(messages: &mut Vec<Message>, mut message: Message, admitted: Option<Instant>) {
    apply_admission(messages, &mut message, admitted);
    messages.push(message);
}

/// Carries the gate's verdict onto a line, and retracts the glow from any that
/// went up before the flood was recognisable — the first few lines of a backlog
/// should not flicker before the client works out what is happening.
fn apply_admission(messages: &mut [Message], message: &mut Message, admitted: Option<Instant>) {
    message.arrived = admitted;
    if admitted.is_some() {
        return;
    }
    for earlier in messages.iter_mut().rev() {
        if earlier.arrived.is_none() {
            break;
        }
        earlier.arrived = None;
    }
}

impl App {
    /// The shortcode being typed and what it matches, when the strip should show.
    ///
    /// Requires at least one character after the colon. A bare `:` is punctuation
    /// far more often than the start of an emoji, and a strip that appeared on
    /// every colon in prose would be a tax on ordinary typing.
    pub fn emoji_suggestions(&self) -> Option<(crate::tui::emoji::Query, Vec<&'static crate::tui::emoji::Emoji>)> {
        let query = crate::tui::emoji::query_at(self.input.value(), self.input.cursor())?;
        if query.text.is_empty() {
            return None;
        }
        if self.emoji_dismissed_for.as_deref() == Some(query.text.as_str()) {
            return None;
        }
        let matches = crate::tui::emoji::suggestions(&query.text);
        if matches.is_empty() {
            return None;
        }
        Some((query, matches))
    }

    /// Moves the highlight, stopping at both ends.
    ///
    /// Not wrapping: the list is rebuilt as the query narrows, and a highlight
    /// that jumped from the last row to the first would be indistinguishable
    /// from the matches shifting underneath it.
    pub fn move_emoji_selection(&mut self, delta: isize) {
        let Some((_, matches)) = self.emoji_suggestions() else {
            return;
        };
        let next = (self.emoji_selection as isize + delta).clamp(0, matches.len() as isize - 1);
        self.emoji_selection = next as usize;
    }

    /// Puts the highlighted emoji into the input, replacing the shortcode.
    pub fn accept_emoji(&mut self) -> bool {
        let Some((query, matches)) = self.emoji_suggestions() else {
            return false;
        };
        let Some(chosen) = matches.get(self.emoji_selection.min(matches.len() - 1)) else {
            return false;
        };
        let (text, cursor) = crate::tui::emoji::apply(self.input.value(), &query, chosen.glyph);
        self.input = Input::new(text).with_cursor(cursor);
        self.emoji_selection = 0;
        self.emoji_dismissed_for = None;
        true
    }

    /// Hides the strip without changing the text.
    ///
    /// Remembered against the specific shortcode, so typing one more character
    /// brings the matches back rather than leaving the feature switched off for
    /// the rest of the message.
    pub fn dismiss_emoji(&mut self) {
        if let Some(query) = crate::tui::emoji::query_at(self.input.value(), self.input.cursor()) {
            self.emoji_dismissed_for = Some(query.text);
        }
        self.emoji_selection = 0;
    }

    /// Expands `:name:` the moment the closing colon is typed.
    ///
    /// The path that matters once somebody knows three shortcodes: type it and it
    /// is simply there, with no strip to read and no key to press. A picker that
    /// always demands a selection is slower than the thing it replaced.
    pub fn expand_finished_shortcode(&mut self) -> bool {
        let value = self.input.value().to_string();
        let cursor = self.input.cursor();
        let chars: Vec<char> = value.chars().collect();
        // Only ever triggered by the colon just typed.
        if cursor == 0 || chars.get(cursor - 1) != Some(&':') {
            return false;
        }
        // The name sits between this colon and the one before it.
        let Some(query) = crate::tui::emoji::query_at(&value, cursor - 1) else {
            return false;
        };
        if query.text.is_empty() {
            return false;
        }
        let Some(found) = crate::tui::emoji::exact(&query.text) else {
            return false;
        };
        // Replace the whole `:name:`, closing colon included.
        let closed = crate::tui::emoji::Query {
            start: query.start,
            end: cursor,
            text: query.text,
        };
        let (text, position) = crate::tui::emoji::apply(&value, &closed, found.glyph);
        self.input = Input::new(text).with_cursor(position);
        self.emoji_selection = 0;
        self.emoji_dismissed_for = None;
        true
    }

    /// Whether anything on screen is still arriving, so the main loop knows to
    /// draw at the animation rate rather than the idle one. Only the tail of
    /// the conversation can be mid-arrival, so the scan stops early.
    pub fn is_animating(&self) -> bool {
        let (messages, _, _) = self.get_current_messages();
        messages
            .iter()
            .rev()
            .take(64)
            .any(|message| {
                message
                    .arrived
                    .is_some_and(|at| at.elapsed() < crate::tui::theme::SETTLE)
            })
    }

    /// Lines the connection popup can show before older ones scroll off.
    const MAX_POPUP_MESSAGES: usize = 4;

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::new_with_nickname("anonymous".to_string())
    }

    pub fn new_with_nickname(nickname: String) -> Self {
        let channels = Vec::new();
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new());
        
        let mut app = Self {
            input: Input::default(),
            arrival_gate: ArrivalGate::default(),
            read_receipts_sent: std::collections::HashSet::new(),
            phase: TuiPhase::Connecting,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            message_viewport_height: 10, // ADDED: Default value
            nickname,
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            channels,
            people: Vec::new(),
            blocked: Vec::new(),
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))),
            pending_channel_switch: None,
            pending_dm_switch: None,
            pending_nickname_update: None,
            pending_connection_retry: false,
            pending_clear_conversation: false,
            unread_counts: HashMap::new(),
            last_read_messages: HashMap::new(),
            popup_active: false,
            popup_input: Input::default(),
            popup_title: String::new(),
            connection_popup_dismissed: false,
            tick: 0,
            started: std::time::Instant::now(),
            short_peer_id: String::new(),
            viewer: crate::tui::viewer::Viewer::new(),
            images: crate::media::ImageCache::new(),
            image_dimensions: std::collections::HashMap::new(),
            image_backend: crate::tui::image_render::detect_backend(),
            pending_image_slot: None,
            pending_image_open_external: false,
            map_open: false,
            map: crate::tui::map::MapState::new(),
            joined_geohashes: std::collections::HashSet::new(),
            emoji_selection: 0,
            emoji_dismissed_for: None,
            carrying: None,
            holding: None,
            mesh_view_open: false,
            topology: crate::topology::Topology::default(),
            pending_geohash_join: None,
        };
        
        app.update_current_conversation();
        app
    }
    
    // Gets the currently selected conversation messages
    pub fn get_current_messages(&self) -> (&[Message], Option<String>, Option<String>) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                let messages = self.dm_messages.get(user).map(|v| v.as_slice()).unwrap_or(&[]);
                return (messages, Some(user.clone()), None);
            }
        }
        
        let ch = self.get_selected_channel_name();
        let messages = self.channel_messages.get(&ch).map(|v| v.as_slice()).unwrap_or(&[]);
        (messages, None, Some(ch))
    }

    pub fn get_selected_channel_name(&self) -> String {
        if self.sidebar_state.public_selected.unwrap_or(false) {
            return "#public".to_string();
        }
        
        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        "#public".to_string()
    }

    pub fn update_current_conversation(&mut self) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                self.current_conv = Some((Some(user.clone()), None));
                return;
            }
        }
        
        if self.sidebar_state.public_selected.unwrap_or(false) {
            self.current_conv = Some((None, Some("#public".to_string())));
            return;
        }
        
        if let Some(channel_idx) = self.sidebar_state.channel_selected {
            if let Some(channel) = self.channels.get(channel_idx) {
                self.current_conv = Some((None, Some(channel.clone())));
                return;
            }
        }
        
        self.current_conv = Some((None, Some("#public".to_string())));
    }

    pub fn add_log_message(&mut self, raw_message: String) {
        let cleaned_message = String::from_utf8(strip_ansi_escapes::strip(&raw_message)).unwrap_or_default();
        let trimmed = cleaned_message.trim();
        
        if trimmed.is_empty() || trimmed.starts_with('>') || trimmed.starts_with("Â»") {
            return;
        }

        // Our own half of a private conversation. The wire copy is encrypted
        // to the peer and never echoes back, so this is the only record of it.
        if trimmed.starts_with("__DM_SENT__:") {
            let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
            if parts.len() >= 5 {
                let target = parts[1].to_string();
                let raw = parts[2].to_string();
                let message_id = parts[3].to_string();
                let content = parts[4].to_string();
                let timestamp = if raw.len() == 4 {
                    format!("{}:{}", &raw[0..2], &raw[2..4])
                } else {
                    raw
                };
                let msg = Message {
                    sender: self.nickname.clone(),
                    timestamp,
                    content,
                    is_self: true,
                    epoch: chrono::Local::now().timestamp(),
                    message_id: (!message_id.is_empty()).then_some(message_id),
                    delivery: None,
                    arrived: Some(Instant::now()),
                };
                let admitted = self.arrival_gate.admit();
                push_arrival(self.dm_messages.entry(target).or_default(), msg, admitted);
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if trimmed.starts_with("__DM__:") {
            let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
            if parts.len() >= 5 {
                let sender = parts[1].to_string();
                let timestamp_raw = parts[2].to_string();
                let message_id = parts[3].to_string();
                let content = parts[4].to_string();
                
                let timestamp = if timestamp_raw.len() == 4 { format!("{}:{}", &timestamp_raw[0..2], &timestamp_raw[2..4]) } else { timestamp_raw };

                let sender_clone = sender.clone();
                let msg = Message { sender, timestamp, content, is_self: false, epoch: chrono::Local::now().timestamp(), message_id: (!message_id.is_empty()).then_some(message_id), delivery: None, arrived: Some(Instant::now()) };

                let admitted = self.arrival_gate.admit();
                push_arrival(self.dm_messages.entry(sender_clone.clone()).or_default(), msg, admitted);
                
                let dm_key = format!("dm:{}", sender_clone);
                let (_, current_dm_target, _) = self.get_current_messages();
                if current_dm_target.as_ref() != Some(&sender_clone) {
                    self.add_unread_message(dm_key);
                }
                
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if trimmed.starts_with("__CHANNEL__:") {
            let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
            if parts.len() >= 5 {
                let channel = parts[1].to_string();
                let sender = parts[2].to_string();
                let epoch: i64 = parts[3].parse().unwrap_or_else(|_| chrono::Local::now().timestamp());
                let content = parts[4].to_string();

                let timestamp = chrono::DateTime::from_timestamp(epoch, 0)
                    .map(|utc| utc.with_timezone(&chrono::Local).format("%H:%M").to_string())
                    .unwrap_or_else(|| chrono::Local::now().format("%H:%M").to_string());

                self.note_image_link(&sender, &channel, &content);
                let msg = Message { sender, timestamp, content, is_self: false, epoch, message_id: None, delivery: None, arrived: Some(Instant::now()) };

                let admitted = self.arrival_gate.admit();
                insert_in_time_order(
                    self.channel_messages.entry(channel.clone()).or_default(),
                    msg,
                    admitted,
                );
                
                let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
                let in_dm = dm_target.is_some();
                if channel == "#public" {
                    // If not currently viewing public (i.e., in DM or in another channel), add unread
                    if !self.sidebar_state.public_selected.unwrap_or(false) {
                        self.add_unread_message("#public".to_string());
                    }
                } else {
                    // For other channels, only add unread if not currently viewing that channel
                    if channel_name.as_deref() != Some(&channel) || in_dm {
                        self.add_unread_message(channel);
                    }
                }
                
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if let Some(captures) = Regex::new(r"(\w+) connected").unwrap().captures(trimmed) {
            let name = captures.get(1).unwrap().as_str().to_string();
            if !self.people.contains(&name) {
                self.people.push(name);
            }
            return;
        }
        
        if let Some(captures) = Regex::new(r"\[(\d{2}:\d{2})\] <(\w+)> (.*)").unwrap().captures(trimmed) {
            let timestamp = captures.get(1).unwrap().as_str().to_string();
            let sender = captures.get(2).unwrap().as_str().to_string();
            let content = captures.get(3).unwrap().as_str().to_string();
            
            if sender == self.nickname { return; }
            
            let msg = Message { sender, timestamp, content, is_self: false, epoch: chrono::Local::now().timestamp(), message_id: None, delivery: None, arrived: Some(Instant::now()) };
            let current_channel = self.get_selected_channel_name();
            let admitted = self.arrival_gate.admit();
            push_arrival(self.channel_messages.entry(current_channel).or_default(), msg, admitted);
            self.scroll_to_bottom_current_conversation();
            return;
        }

        if Regex::new(r"^system: (.+)$").unwrap().is_match(trimmed) {
            // For system messages, we need to preserve the original message with colors
            // So we'll work with the original raw_message instead of the cleaned one
            if let Some(captures_raw) = Regex::new(r"^system: (.+)$").unwrap().captures(&raw_message) {
                let content = captures_raw.get(1).unwrap().as_str().to_string();
                let lines: Vec<&str> = content.split('\n').collect();
                
                for line in lines {
                    let trimmed_line = line.trim();
                    if !trimmed_line.is_empty() {
                        let msg = Message::now("system".to_string(), trimmed_line.to_string(), false);
                        
                        // Check if we're in a DM conversation or channel conversation
                        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
                        if let Some(target) = dm_target {
                            // We're in a DM, add to DM messages
                            let admitted = self.arrival_gate.admit();
                            push_arrival(self.dm_messages.entry(target).or_default(), msg, admitted);
                        } else if let Some(channel) = channel_name {
                            // We're in a channel, add to channel messages
                            let admitted = self.arrival_gate.admit();
                            push_arrival(self.channel_messages.entry(channel).or_default(), msg, admitted);
                        } else {
                            // Fallback to current channel (shouldn't happen but just in case)
                            let current_channel = self.get_selected_channel_name();
                            let admitted = self.arrival_gate.admit();
                            push_arrival(self.channel_messages.entry(current_channel.clone()).or_default(), msg, admitted);
                        }
                    }
                }
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if trimmed.contains(&self.nickname) { return; }
        
        let lines: Vec<&str> = trimmed.split('\n').collect();
        let current_channel = self.get_selected_channel_name();
        
        for line in lines {
            let trimmed_line = line.trim();
            if !trimmed_line.is_empty() {
                let msg = Message::now("system".to_string(), trimmed_line.to_string(), false);
                let admitted = self.arrival_gate.admit();
                push_arrival(self.channel_messages.entry(current_channel.clone()).or_default(), msg, admitted);
            }
        }
        self.scroll_to_bottom_current_conversation();
    }
    
    pub fn add_sent_message(&mut self, text: String) {
        // Your own links are viewable too — the alternative is a client that
        // can show everyone's pictures except yours.
        let conversation = self.active_conversation();
        let nickname = self.nickname.clone();
        self.note_image_link(&nickname, &conversation, &text);
        let _timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message::now(self.nickname.clone(), text, true);

        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            let admitted = self.arrival_gate.admit();
            push_arrival(self.dm_messages.entry(target).or_default(), msg, admitted);
        } else if let Some(channel) = channel_name {
            let admitted = self.arrival_gate.admit();
            push_arrival(self.channel_messages.entry(channel).or_default(), msg, admitted);
        }
        self.scroll_to_bottom_current_conversation();
    }


    pub fn scroll_to_bottom_current_conversation(&mut self) {
        self.msg_scroll = 0;
    }
    
    pub fn transition_to_connected(&mut self) {
        self.phase = TuiPhase::Connected;
        self.connected = true;
        let mut final_messages = self.popup_messages.drain(..).map(|content| Message::now("system".to_string(), content, false)).collect();
        self.channel_messages.entry("#public".to_string()).or_default().append(&mut final_messages);
    }

    pub fn transition_to_error(&mut self, error: String) {
        let cleaned_error = String::from_utf8(strip_ansi_escapes::strip(&error)).unwrap_or_default();
        self.phase = TuiPhase::Error(cleaned_error);
    }

    pub fn add_popup_message(&mut self, message: String) {
        let cleaned_message = String::from_utf8(strip_ansi_escapes::strip(&message)).unwrap_or_default();
        let trimmed = cleaned_message.trim().to_string();
        if trimmed.is_empty() { return; }
        // The connection popup only has room for a handful of lines, so keep
        // the most recent ones rather than letting older text push the live
        // status off the bottom.
        self.popup_messages.push(trimmed);
        while self.popup_messages.len() > Self::MAX_POPUP_MESSAGES {
            self.popup_messages.remove(0);
        }
    }

    pub fn join_channel(&mut self, channel_name: String) {
        if channel_name == "#public" { return; }
        if !self.channels.contains(&channel_name) { self.channels.push(channel_name.clone()); }
        self.sidebar_state.public_selected = None;
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_channel_switch = Some(channel_name.clone());
        }
        self.channel_messages.entry(channel_name).or_default();
    }

    pub fn switch_to_channel(&mut self, channel_name: String) {
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            // Clear other selections when switching to a channel
            self.sidebar_state.public_selected = None;
            self.sidebar_state.people_selected = None;
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_channel_switch = Some(channel_name);
        }
    }

    pub fn switch_to_public(&mut self) {
        self.sidebar_state.public_selected = Some(true);
        self.sidebar_state.channel_selected = None;
        self.sidebar_state.people_selected = None;
        self.update_current_conversation();
        self.update_sidebar_flat_selection();
        self.mark_current_conversation_as_read();
        self.pending_channel_switch = Some("#public".to_string());
    }

    pub fn switch_to_dm(&mut self, target_nickname: String) {
        self.sidebar_state.public_selected = None;
        self.sidebar_state.channel_selected = None;
        if let Some(person_idx) = self.people.iter().position(|p| p == &target_nickname) {
            self.sidebar_state.people_selected = Some(person_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_dm_switch = Some((target_nickname, String::new()));
        }
    }

    pub fn mark_current_conversation_as_read(&mut self) {
        let (messages, dm_target, channel_name) = self.get_current_messages();
        let conversation_key = if let Some(target) = dm_target { format!("dm:{}", target) } else if let Some(channel) = channel_name { channel } else { return; };
        let message_count = messages.len();
        self.last_read_messages.insert(conversation_key.clone(), message_count);
        self.unread_counts.remove(&conversation_key);
    }

    pub fn add_unread_message(&mut self, conversation_key: String) {
        let (_, dm_target, channel_name) = self.get_current_messages();
        let current_key = if let Some(target) = dm_target { format!("dm:{}", target) } else if let Some(channel) = channel_name { channel } else { return; };
        if current_key == conversation_key { return; }
        *self.unread_counts.entry(conversation_key).or_insert(0) += 1;
    }

    pub fn get_unread_count(&self, conversation_key: &str) -> usize {
        self.unread_counts.get(conversation_key).copied().unwrap_or(0)
    }

    pub fn get_section_unread_count(&self, section: usize) -> usize {
        match section {
            0 => { if self.get_unread_count("#public") > 0 { 1 } else { 0 } }
            1 => { self.channels.iter().map(|ch| self.get_unread_count(ch)).sum() }
            2 => { self.people.iter().map(|person| self.get_unread_count(&format!("dm:{}", person))).sum() }
            _ => 0,
        }
    }

    /// Name of the conversation on screen, used to scope image links.
    pub fn active_conversation(&self) -> String {
        match self.current_conv.as_ref() {
            Some((Some(user), _)) => format!("dm:{user}"),
            Some((_, Some(channel))) => channel.clone(),
            _ => "#public".to_string(),
        }
    }

    /// Dimensions of a cached image without disturbing cache ordering.
    pub fn images_peek(&self, url: &str) -> Option<(u32, u32)> {
        self.image_dimensions.get(url).copied()
    }

    /// Records an image link found in a message.
    pub fn note_image_link(&mut self, sender: &str, conversation: &str, content: &str) {
        for url in crate::media::extract_image_urls(content) {
            self.viewer.remember(crate::media::ImageLink {
                url,
                sender: sender.to_string(),
                conversation: conversation.to_string(),
            });
        }
    }

    /// Opens the map, starting on the channel being viewed when there is one so
    /// the cursor lands somewhere meaningful rather than at 0,0 in the Pacific.
    pub fn open_map(&mut self) {
        if let Some(geohash) = self
            .current_conv
            .as_ref()
            .and_then(|(_, channel)| channel.as_deref())
            .and_then(|channel| {
                let candidate = channel.trim_start_matches('#').to_lowercase();
                (candidate != "public" && crate::geohash::is_valid(&candidate))
                    .then_some(candidate)
            })
        {
            self.map.focus_on(&geohash);
        }
        self.map.view_dirty = true;
        self.map_open = true;
    }

    /// Asks the main loop to join whatever the map cursor is on.
    pub fn request_join_selected_cell(&mut self) {
        self.pending_geohash_join = Some(self.map.selected_geohash().to_string());
        self.map_open = false;
    }

    pub fn open_nickname_popup(&mut self) {
        self.popup_active = true;
        self.popup_title = "Edit Nickname".to_string();
        self.popup_input = Input::default();
        self.focus_area = FocusArea::InputBox;
    }

    pub fn close_popup(&mut self) {
        self.popup_active = false;
        self.popup_input = Input::default();
        self.popup_title = String::new();
        self.focus_area = FocusArea::Sidebar;
    }

    pub fn update_nickname(&mut self, new_nickname: String) {
        self.nickname = new_nickname.clone();
        self.pending_nickname_update = Some(new_nickname);
    }

    pub fn trigger_connection_retry(&mut self) {
        self.pending_connection_retry = true;
        self.phase = TuiPhase::Connecting;
        self.connected = false;
        self.popup_messages.clear();
    }

    pub fn clear_current_conversation(&mut self) {
        // Check if we're in a DM conversation
        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            // We're in a DM, clear DM messages
            if let Some(messages) = self.dm_messages.get_mut(&target) {
                messages.clear();
            }
        } else if let Some(channel) = channel_name {
            // We're in a channel, clear channel messages
            if let Some(messages) = self.channel_messages.get_mut(&channel) {
                messages.clear();
            }
        } else {
            // Fallback to current channel (shouldn't happen but just in case)
            let current_channel = self.get_selected_channel_name();
            if let Some(messages) = self.channel_messages.get_mut(&current_channel) {
                messages.clear();
            }
        }
        self.msg_scroll = 0;
    }

    /// Drops every conversation, peer and cached image.
    ///
    /// Paired with the on-disk wipe: clearing one without the other leaves
    /// either the history or the keys behind.
    pub fn wipe(&mut self) {
        self.channel_messages.clear();
        self.dm_messages.clear();
        self.popup_messages.clear();
        self.people.clear();
        self.blocked.clear();
        self.channels.clear();
        self.joined_geohashes.clear();
        self.images.clear();
        self.read_receipts_sent.clear();
        self.image_dimensions.clear();
        self.viewer.open = false;
        self.map_open = false;
        // Leave a single empty public conversation so the pane is not a
        // dangling reference to something that no longer exists.
        self.channel_messages.insert("#public".to_string(), Vec::new());
    }

    /// Records that a peer acknowledged one of our messages.
    ///
    /// Only ever raises the status. Read and delivered can race, and a delivery
    /// acknowledgement arriving after a read must not walk the line backwards -
    /// upstream drops that case as stale, and so does this.
    pub fn mark_delivery(&mut self, message_id: &str, status: crate::mesh::DeliveryStatus) {
        for messages in self.dm_messages.values_mut() {
            for message in messages.iter_mut() {
                if message.message_id.as_deref() == Some(message_id) {
                    if message.delivery.is_none_or(|current| status > current) {
                        message.delivery = Some(status);
                    }
                    return;
                }
            }
        }
    }

    /// Messages from this peer we have now shown and not yet acknowledged.
    ///
    /// Marks them as receipted on the way out, so the caller cannot send the
    /// same receipt on every frame — this is called from the draw loop.
    pub fn take_unreceipted_from(&mut self, peer: &str) -> Vec<String> {
        let Some(messages) = self.dm_messages.get(peer) else {
            return Vec::new();
        };
        let fresh: Vec<String> = messages
            .iter()
            .filter(|m| !m.is_self)
            .filter_map(|m| m.message_id.clone())
            .filter(|id| !self.read_receipts_sent.contains(id))
            .collect();
        for id in &fresh {
            self.read_receipts_sent.insert(id.clone());
        }
        fresh
    }

    pub fn update_blocked_list(&mut self, blocked_nicknames: Vec<String>) {
        self.blocked = blocked_nicknames;
    }

    pub fn update_sidebar_flat_selection(&mut self) {
        let mut flat_idx = 0;
        for section in 0..5 {
            flat_idx += 1;
            if self.sidebar_state.expanded[section] {
                let count = match section {
                    0 => 1,
                    1 => self.channels.len(),
                    2 => self.people.len(),
                    3 => self.blocked.len(),
                    4 => 2,
                    _ => 0,
                };
                let is_current_section = match section {
                    0 => self.sidebar_state.public_selected.unwrap_or(false),
                    1 => self.sidebar_state.channel_selected.is_some(),
                    2 => self.sidebar_state.people_selected.is_some(),
                    _ => false,
                };
                if is_current_section {
                    let item_idx = match section {
                        0 => 0,
                        1 => self.sidebar_state.channel_selected.unwrap_or(0),
                        2 => self.sidebar_state.people_selected.unwrap_or(0),
                        _ => 0,
                    };
                    self.sidebar_flat_selected = flat_idx + item_idx;
                    return;
                }
                flat_idx += count;
            }
        }
    }
    
    pub fn get_input_box_height(&self, available_width: usize) -> usize {
        // Measured in display cells, like the wrapping and the cursor: counting
        // characters made an emoji-heavy line report fewer rows than it draws,
        // so the last row was clipped.
        let text = self.input.value();
        if text.is_empty() {
            return 3; // Minimum height
        }
        let usable = available_width.saturating_sub(2).max(1);
        let mut rows = 1usize;
        let mut width = 0usize;
        for character in text.chars() {
            if character == '\n' {
                rows += 1;
                width = 0;
                continue;
            }
            let cell_width = unicode_width::UnicodeWidthChar::width(character).unwrap_or(0);
            if width + cell_width > usable {
                rows += 1;
                width = 0;
            }
            width += cell_width;
        }
        rows + 2
    }
}

#[cfg(test)]
mod arrival_tests {
    use super::*;

    fn message(epoch: i64) -> Message {
        Message {
            sender: "anon".to_string(),
            timestamp: "12:00".to_string(),
            content: "hello".to_string(),
            is_self: false,
            epoch,
            message_id: None,
            delivery: None,
            arrived: Some(Instant::now()),
        }
    }

    /// Runs a batch of lines through the gate the way the client does. Offsets
    /// are seconds behind the present, which is how a real event's `created_at`
    /// reaches us.
    fn land(offsets: impl IntoIterator<Item = i64>) -> Vec<Message> {
        let now = chrono::Local::now().timestamp();
        let (mut log, mut gate) = (Vec::new(), ArrivalGate::default());
        for offset in offsets {
            let admitted = gate.admit();
            insert_in_time_order(&mut log, message(now - offset), admitted);
        }
        log
    }

    #[test]
    fn lines_landing_now_are_new() {
        let log = land([1, 0]);
        assert!(log.iter().all(|m| m.arrived.is_some()));
    }

    #[test]
    fn an_hour_old_line_is_not_new_wherever_it_lands() {
        // The backlog a slow relay finally delivered. It belongs in the log at
        // its own time, but it is not something that just happened.
        let log = land([0, 3600]);
        assert!(log[0].arrived.is_none(), "replayed history must not light up");
        assert!(log[1].arrived.is_some(), "the live line keeps its arrival");
    }

    #[test]
    fn arriving_out_of_order_does_not_mute_a_live_line() {
        // Two phones, clocks a few seconds apart. Both are talking now.
        let log = land([0, 5]);
        assert!(
            log.iter().all(|m| m.arrived.is_some()),
            "a slightly-behind clock is still the present"
        );
    }

    #[test]
    fn a_flood_arrives_completely_dark() {
        // A backlog flush lands in one instant. Not even its opening lines may
        // glow: the flood has to be retracted once it becomes recognisable, or
        // joining a busy channel opens with a strobe.
        let log = land(0..40);
        assert!(
            log.iter().all(|m| m.arrived.is_none()),
            "every line of a burst must be dark, including the first few"
        );
    }

    #[test]
    fn the_flood_stays_dark_however_long_it_runs() {
        // The regression a screenshot caught: counting only the lines still lit
        // restarted the tally each time a group was cleared, so a long burst lit
        // a fresh group every few lines all the way down.
        let log = land(0..(BURST_LIMIT as i64 * 5));
        assert_eq!(
            log.iter().filter(|m| m.arrived.is_some()).count(),
            0,
            "no group anywhere in the flood may light up"
        );
    }

    #[test]
    fn a_handful_of_live_lines_still_animate() {
        // The ordinary case: a few people talking at once should cascade.
        let log = land(0..BURST_LIMIT as i64);
        assert!(log.iter().all(|m| m.arrived.is_some()));
    }

    #[test]
    fn the_gate_reopens_once_the_rush_has_passed() {
        let mut gate = ArrivalGate::default();
        for _ in 0..BURST_LIMIT * 3 {
            gate.admit();
        }
        assert!(gate.admit().is_none(), "still mid-flood");
        gate.recent.clear(); // stand in for BURST_WINDOW elapsing
        assert!(gate.admit().is_some(), "a later line is news again");
    }
}

#[cfg(test)]
mod push_arrival_tests {
    use super::*;

    #[test]
    fn a_command_that_prints_a_wall_of_text_does_not_light_it_all() {
        // /help is fifteen lines in one instant. Lighting every one of them is
        // the same flash the relay backlog would have caused.
        let (mut log, mut gate) = (Vec::new(), ArrivalGate::default());
        for index in 0..15 {
            let admitted = gate.admit();
            push_arrival(
                &mut log,
                Message::now("system".to_string(), format!("line {index}"), false),
                admitted,
            );
        }
        assert!(log.iter().all(|m| m.arrived.is_none()));
    }

    #[test]
    fn a_single_notice_still_announces_itself() {
        let (mut log, mut gate) = (Vec::new(), ArrivalGate::default());
        let admitted = gate.admit();
        push_arrival(
            &mut log,
            Message::now("system".to_string(), "peer left".to_string(), false),
            admitted,
        );
        assert!(log[0].arrived.is_some());
    }
}

#[cfg(test)]
mod inbound_arrival_tests {
    use super::*;

    fn channel_line(sender: &str, epoch: i64, content: &str) -> String {
        format!("__CHANNEL__:#9q:{sender}:{epoch}:{content}")
    }

    fn lines(app: &App) -> &Vec<Message> {
        app.channel_messages.get("#9q").expect("channel exists")
    }

    #[test]
    fn a_live_message_into_a_quiet_channel_animates() {
        let mut app = App::new_with_nickname("me".into());
        let now = chrono::Local::now().timestamp();
        app.add_log_message(channel_line("alice", now, "hello"));
        assert!(lines(&app)[0].arrived.is_some());
    }

    #[test]
    fn hour_old_backlog_does_not_animate() {
        let mut app = App::new_with_nickname("me".into());
        let now = chrono::Local::now().timestamp();
        app.add_log_message(channel_line("alice", now, "recent"));
        app.add_log_message(channel_line("bob", now - 3600, "ancient"));
        let ancient = lines(&app).iter().find(|m| m.content == "ancient").unwrap();
        assert!(ancient.arrived.is_none(), "replayed history must stay dark");
    }

    #[test]
    fn a_message_that_took_a_few_seconds_to_reach_us_still_animates() {
        // What actually happens on a geohash channel: the live divider is
        // stamped with our own clock at EOSE, and the next real message carries
        // the sender's created_at from before it was mined and relayed. It
        // sorts *behind* the divider and so never counted as new.
        let mut app = App::new_with_nickname("me".into());
        let now = chrono::Local::now().timestamp();
        app.add_log_message(channel_line("system", now, "─── live ───"));
        app.add_log_message(channel_line("alice", now - 5, "hello"));
        let hello = lines(&app).iter().find(|m| m.content == "hello").unwrap();
        assert!(
            hello.arrived.is_some(),
            "a message a few seconds behind our clock is still news"
        );
    }

    #[test]
    fn clock_skew_between_two_speakers_does_not_mute_the_second() {
        let mut app = App::new_with_nickname("me".into());
        let now = chrono::Local::now().timestamp();
        app.add_log_message(channel_line("alice", now, "first"));
        app.add_log_message(channel_line("bob", now - 3, "second"));
        let second = lines(&app).iter().find(|m| m.content == "second").unwrap();
        assert!(second.arrived.is_some(), "a slightly-behind clock is still live");
    }
}

#[cfg(test)]
mod wipe_tests {
    use super::*;

    #[test]
    fn a_wipe_leaves_no_conversation_peer_or_image_behind() {
        let mut app = App::new_with_nickname("me".into());
        app.add_log_message("__CHANNEL__:#public:alice:1700000000:hello".to_string());
        app.add_log_message("__DM__:bob:1200:private words".to_string());
        app.people = vec!["alice".into(), "bob".into()];
        app.blocked = vec!["carol".into()];
        app.joined_geohashes.insert("9q".into());
        app.image_dimensions.insert("http://x/y.png".into(), (10, 10));

        app.wipe();

        assert!(app.dm_messages.is_empty(), "private history must not survive");
        assert!(app.people.is_empty());
        assert!(app.blocked.is_empty());
        assert!(app.joined_geohashes.is_empty());
        assert!(app.image_dimensions.is_empty());
        assert!(
            app.channel_messages
                .get("#public")
                .is_some_and(|messages| messages.is_empty()),
            "public survives as an empty pane, not as history"
        );
    }

    #[test]
    fn a_wipe_closes_any_overlay() {
        // Quitting through an open viewer would render one last frame of
        // something the user just asked to destroy.
        let mut app = App::new_with_nickname("me".into());
        app.viewer.open = true;
        app.map_open = true;
        app.wipe();
        assert!(!app.viewer.open);
        assert!(!app.map_open);
    }
}
