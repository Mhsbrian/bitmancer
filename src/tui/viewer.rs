// src/tui/viewer.rs
//
// State for the image viewer: which links the current conversation has offered,
// which one is on screen, and what happened when we tried to load it.
//
// Loading is a state machine rather than a bool because every outcome has to be
// visible — an image that silently fails to appear is indistinguishable from a
// broken client.

use crate::media::ImageLink;

#[derive(Debug, Clone, PartialEq)]
pub enum LoadState {
    /// Found in chat, not requested. Nothing has left the machine.
    Idle,
    Loading,
    Ready,
    Failed(String),
}

pub struct Viewer {
    pub open: bool,
    /// Image links seen in the active conversation, oldest first.
    links: Vec<ImageLink>,
    index: usize,
    pub state: LoadState,
    /// Set when the viewer wants the main loop to fetch a URL.
    pub pending_fetch: Option<String>,
}

impl Default for Viewer {
    fn default() -> Self {
        Self::new()
    }
}

impl Viewer {
    pub fn new() -> Self {
        Self {
            open: false,
            links: Vec::new(),
            index: 0,
            state: LoadState::Idle,
            pending_fetch: None,
        }
    }

    /// Records a link discovered in chat. Newest ends up last.
    pub fn remember(&mut self, link: ImageLink) {
        if self.links.iter().any(|existing| existing.url == link.url) {
            return;
        }
        self.links.push(link);
    }

    /// Links posted in one conversation, oldest first.
    pub fn links_in(&self, conversation: &str) -> Vec<&ImageLink> {
        self.links
            .iter()
            .filter(|link| link.conversation == conversation)
            .collect()
    }

    pub fn count_in(&self, conversation: &str) -> usize {
        self.links_in(conversation).len()
    }

    pub fn current(&self) -> Option<&ImageLink> {
        self.links.get(self.index)
    }

    /// Opens the viewer on the newest image in a conversation, or the nth
    /// (1-based, counting from the newest) when given a position.
    ///
    /// Returns false when the conversation has no images, so the caller can say
    /// so rather than opening an empty window.
    pub fn open_in(&mut self, conversation: &str, from_newest: Option<usize>) -> bool {
        let urls: Vec<String> = self
            .links_in(conversation)
            .iter()
            .map(|link| link.url.clone())
            .collect();
        if urls.is_empty() {
            return false;
        }
        let offset = from_newest.unwrap_or(1).max(1).min(urls.len());
        let target = &urls[urls.len() - offset];

        self.index = self
            .links
            .iter()
            .position(|link| &link.url == target)
            .unwrap_or(0);
        self.open = true;
        self.request_current();
        true
    }

    pub fn close(&mut self) {
        self.open = false;
        self.pending_fetch = None;
    }

    /// Steps through the images of the conversation currently on screen.
    pub fn step(&mut self, conversation: &str, delta: isize) {
        let urls: Vec<String> = self
            .links_in(conversation)
            .iter()
            .map(|link| link.url.clone())
            .collect();
        if urls.is_empty() {
            return;
        }
        let current = self
            .current()
            .and_then(|link| urls.iter().position(|url| url == &link.url))
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(urls.len() as isize) as usize;

        if let Some(position) = self.links.iter().position(|link| link.url == urls[next]) {
            self.index = position;
            self.request_current();
        }
    }

    /// Position of the current image within its conversation, 1-based.
    pub fn position_in(&self, conversation: &str) -> (usize, usize) {
        let urls = self.links_in(conversation);
        let total = urls.len();
        let current = self
            .current()
            .and_then(|link| urls.iter().position(|other| other.url == link.url))
            .map(|index| index + 1)
            .unwrap_or(0);
        (current, total)
    }

    fn request_current(&mut self) {
        let Some(url) = self.current().map(|link| link.url.clone()) else {
            return;
        };
        self.state = LoadState::Loading;
        self.pending_fetch = Some(url);
    }

    /// Called when a fetch finishes, successfully or not.
    pub fn finish(&mut self, url: &str, outcome: Result<(), String>) {
        // A slow fetch for an image we have already navigated away from must
        // not overwrite the state of the one now on screen.
        if self.current().map(|link| link.url.as_str()) != Some(url) {
            return;
        }
        self.state = match outcome {
            Ok(()) => LoadState::Ready,
            Err(reason) => LoadState::Failed(reason),
        };
    }

    /// Marks an already-cached image as ready without a fetch.
    pub fn mark_ready(&mut self) {
        self.state = LoadState::Ready;
        self.pending_fetch = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(url: &str, conversation: &str) -> ImageLink {
        ImageLink {
            url: url.to_string(),
            sender: "alice".to_string(),
            conversation: conversation.to_string(),
        }
    }

    fn viewer_with_two() -> Viewer {
        let mut viewer = Viewer::new();
        viewer.remember(link("https://a/1.png", "#9q"));
        viewer.remember(link("https://a/2.png", "#9q"));
        viewer.remember(link("https://a/other.png", "#public"));
        viewer
    }

    #[test]
    fn nothing_is_requested_until_the_viewer_is_opened() {
        let viewer = viewer_with_two();
        assert!(!viewer.open);
        assert_eq!(viewer.state, LoadState::Idle);
        assert!(
            viewer.pending_fetch.is_none(),
            "detecting a link must never trigger a request"
        );
    }

    #[test]
    fn links_are_scoped_to_their_conversation() {
        let viewer = viewer_with_two();
        assert_eq!(viewer.count_in("#9q"), 2);
        assert_eq!(viewer.count_in("#public"), 1);
        assert_eq!(viewer.count_in("#nowhere"), 0);
    }

    #[test]
    fn duplicate_links_are_recorded_once() {
        let mut viewer = viewer_with_two();
        viewer.remember(link("https://a/1.png", "#9q"));
        assert_eq!(viewer.count_in("#9q"), 2);
    }

    #[test]
    fn opening_starts_on_the_newest_and_requests_it() {
        let mut viewer = viewer_with_two();
        assert!(viewer.open_in("#9q", None));
        assert!(viewer.open);
        assert_eq!(viewer.current().unwrap().url, "https://a/2.png");
        assert_eq!(viewer.state, LoadState::Loading);
        assert_eq!(viewer.pending_fetch.as_deref(), Some("https://a/2.png"));
    }

    #[test]
    fn opening_can_target_an_older_image() {
        let mut viewer = viewer_with_two();
        assert!(viewer.open_in("#9q", Some(2)));
        assert_eq!(viewer.current().unwrap().url, "https://a/1.png");
        // Out of range clamps rather than failing.
        assert!(viewer.open_in("#9q", Some(99)));
        assert_eq!(viewer.current().unwrap().url, "https://a/1.png");
    }

    #[test]
    fn opening_an_imageless_conversation_reports_failure() {
        let mut viewer = viewer_with_two();
        assert!(!viewer.open_in("#empty", None));
        assert!(!viewer.open);
    }

    #[test]
    fn stepping_wraps_within_the_conversation() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None); // on 2.png
        viewer.step("#9q", 1);
        assert_eq!(viewer.current().unwrap().url, "https://a/1.png", "wrapped");
        viewer.step("#9q", -1);
        assert_eq!(viewer.current().unwrap().url, "https://a/2.png");
    }

    #[test]
    fn stepping_never_leaves_the_conversation() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None);
        for _ in 0..10 {
            viewer.step("#9q", 1);
            assert_ne!(
                viewer.current().unwrap().url,
                "https://a/other.png",
                "must not wander into #public"
            );
        }
    }

    #[test]
    fn position_is_reported_for_the_status_line() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None);
        assert_eq!(viewer.position_in("#9q"), (2, 2));
        viewer.step("#9q", 1);
        assert_eq!(viewer.position_in("#9q"), (1, 2));
    }

    #[test]
    fn a_failure_is_surfaced_not_swallowed() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None);
        viewer.finish("https://a/2.png", Err("404".into()));
        assert_eq!(viewer.state, LoadState::Failed("404".into()));
    }

    #[test]
    fn a_late_fetch_cannot_clobber_the_current_image() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None); // requesting 2.png
        viewer.step("#9q", 1); // now on 1.png, requesting it
        assert_eq!(viewer.state, LoadState::Loading);

        // The abandoned fetch for 2.png finally fails; 1.png must be untouched.
        viewer.finish("https://a/2.png", Err("timeout".into()));
        assert_eq!(viewer.state, LoadState::Loading);

        viewer.finish("https://a/1.png", Ok(()));
        assert_eq!(viewer.state, LoadState::Ready);
    }

    #[test]
    fn closing_drops_any_pending_request() {
        let mut viewer = viewer_with_two();
        viewer.open_in("#9q", None);
        viewer.close();
        assert!(!viewer.open);
        assert!(viewer.pending_fetch.is_none());
    }
}
