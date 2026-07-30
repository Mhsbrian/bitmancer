// src/media.rs
//
// Finding and fetching images that people post as links.
//
// The one rule that shapes this module: **nothing is ever fetched
// automatically.** A chat line is written by a stranger, and requesting the URL
// in it hands that stranger your IP address, your rough location and a timing
// signal — on a network whose entire point is not doing that. So links are
// detected and listed for free, and a request only leaves the machine when you
// press a key.

use std::collections::HashMap;
use std::time::Duration;

/// Refuse anything larger than this. A chat image has no business being bigger,
/// and an unbounded read is a denial-of-service invitation.
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Decoded images are big; keep only a handful.
const CACHE_CAPACITY: usize = 8;

const IMAGE_EXTENSIONS: [&str; 7] = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif"];

/// An image someone linked, with the context needed to show it.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageLink {
    pub url: String,
    pub sender: String,
    /// Where it appeared, so the viewer can be scoped to one conversation.
    pub conversation: String,
}

/// Pulls image URLs out of a line of chat.
///
/// Deliberately conservative: a known image extension, or a path that looks
/// like a media endpoint. Guessing wider would mean offering to fetch arbitrary
/// links, and the whole point is that fetching is a considered act.
pub fn extract_image_urls(content: &str) -> Vec<String> {
    content
        .split_whitespace()
        .filter_map(|token| {
            let trimmed = token.trim_matches(|c: char| {
                matches!(c, '<' | '>' | '(' | ')' | '[' | ']' | '"' | '\'' | ',' | ';')
            });
            is_image_url(trimmed).then(|| trimmed.to_string())
        })
        .collect()
}

pub fn is_image_url(candidate: &str) -> bool {
    let lowered = candidate.to_lowercase();
    if !(lowered.starts_with("http://") || lowered.starts_with("https://")) {
        return false;
    }
    // Ignore query strings and fragments when judging the extension.
    let path = lowered
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();

    if IMAGE_EXTENSIONS
        .iter()
        .any(|extension| path.ends_with(&format!(".{extension}")))
    {
        return true;
    }
    // bitchat clients post uploads through media endpoints that carry no
    // extension, e.g. https://host/api/media/<hash>.
    path.contains("/api/media/") || path.contains("/media/") || path.contains("/blossom/")
}

/// Prefix marking an image that arrived over the mesh rather than by link.
/// Such images are already in hand, so they are never fetched.
pub const MESH_SCHEME: &str = "mesh:";

/// Stable key for an image delivered over the radio.
pub fn mesh_key(sender: &str, name: &str) -> String {
    format!("{MESH_SCHEME}{sender}/{name}")
}

/// Distinguishes a mesh-delivered image from a fetched one. Kept for the
/// viewer work that will need to say where a picture came from.
#[allow(dead_code)]
pub fn is_mesh_key(url: &str) -> bool {
    url.starts_with(MESH_SCHEME)
}

/// Host shown in the viewer, so it is obvious who is about to be contacted.
pub fn host_of(url: &str) -> String {
    if let Some(rest) = url.strip_prefix(MESH_SCHEME) {
        // Nothing was contacted; say so rather than inventing a hostname.
        return format!("bluetooth mesh · {rest}");
    }
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url)
        .to_string()
}

#[derive(Debug)]
pub enum FetchError {
    Network(String),
    TooLarge(usize),
    NotAnImage(String),
    Decode(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Network(detail) => write!(f, "could not reach it: {detail}"),
            FetchError::TooLarge(bytes) => {
                write!(f, "too large ({} MB cap)", MAX_IMAGE_BYTES / 1024 / 1024)
                    .and_then(|_| write!(f, ", got at least {} bytes", bytes))
            }
            FetchError::NotAnImage(kind) => write!(f, "not an image ({kind})"),
            FetchError::Decode(detail) => write!(f, "could not decode: {detail}"),
        }
    }
}

/// Blocking fetch, meant to be run on a worker thread.
pub fn fetch_image(url: &str) -> Result<image::DynamicImage, FetchError> {
    use std::io::Read;

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        // A redirect chain is a fine way to bounce a client somewhere it never
        // agreed to talk to; allow a couple, not a maze.
        .max_redirects(3)
        .build()
        .new_agent();

    let mut response = agent
        .get(url)
        .call()
        .map_err(|error| FetchError::Network(error.to_string()))?;

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !content_type.is_empty() && !content_type.starts_with("image/") {
        return Err(FetchError::NotAnImage(content_type));
    }

    // Read one byte past the cap so an oversized body is detected rather than
    // silently truncated into a corrupt image.
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| FetchError::Network(error.to_string()))?;
    if body.len() > MAX_IMAGE_BYTES {
        return Err(FetchError::TooLarge(body.len()));
    }

    image::load_from_memory(&body).map_err(|error| FetchError::Decode(error.to_string()))
}

/// Small LRU of decoded images, so paging back and forth does not refetch.
pub struct ImageCache {
    entries: HashMap<String, image::DynamicImage>,
    order: Vec<String>,
}

impl Default for ImageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageCache {
    /// Drops every decoded image. Cached pictures were fetched from links
    /// strangers posted, so a wipe that left them in memory would leave the
    /// most identifying thing behind.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn get(&mut self, url: &str) -> Option<&image::DynamicImage> {
        if self.entries.contains_key(url) {
            self.touch(url);
        }
        self.entries.get(url)
    }

    pub fn insert(&mut self, url: String, image: image::DynamicImage) {
        self.entries.insert(url.clone(), image);
        self.touch(&url);
        while self.order.len() > CACHE_CAPACITY {
            if let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                self.entries.remove(&oldest);
            }
        }
    }

    fn touch(&mut self, url: &str) {
        self.order.retain(|existing| existing != url);
        self.order.push(url.to_string());
    }

    /// Cached image count, for tests and diagnostics.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether anything has been cached yet. Paired with `len` because a public
    /// `len` without it is the kind of API that reads fine and then makes every
    /// caller write `len() == 0`.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_common_image_links() {
        for url in [
            "https://example.com/cat.png",
            "http://example.com/a/b/photo.JPG",
            "https://example.com/x.jpeg?width=200",
            "https://example.com/anim.gif#frag",
            "https://glub.chat/api/media/7675e27138cbe0b8.gif",
        ] {
            assert!(is_image_url(url), "{url} should be an image");
        }
    }

    #[test]
    fn recognises_extensionless_media_endpoints() {
        // bitchat uploads land on paths like this with no extension at all.
        assert!(is_image_url("https://glub.chat/api/media/7675e27138cbe0b8"));
        assert!(is_image_url("https://host.tld/blossom/abc123"));
    }

    #[test]
    fn ignores_everything_else() {
        for url in [
            "https://example.com/page.html",
            "example.com/cat.png",
            "ftp://example.com/cat.png",
            "not a url",
            "",
            // No scheme-relative or javascript nonsense.
            "//example.com/cat.png",
            "javascript:alert(1)",
        ] {
            assert!(!is_image_url(url), "{url} should not be an image");
        }
    }

    #[test]
    fn extracts_urls_from_a_chat_line() {
        let line = "look at this https://example.com/cat.png and (https://example.com/b.jpg)";
        assert_eq!(
            extract_image_urls(line),
            vec![
                "https://example.com/cat.png".to_string(),
                "https://example.com/b.jpg".to_string()
            ]
        );
    }

    #[test]
    fn extracts_nothing_from_ordinary_chat() {
        assert!(extract_image_urls("hello there, how are you?").is_empty());
        assert!(extract_image_urls("see https://example.com/article").is_empty());
    }

    #[test]
    fn shows_the_host_that_would_be_contacted() {
        assert_eq!(host_of("https://glub.chat/api/media/x.gif"), "glub.chat");
        assert_eq!(host_of("http://1.2.3.4:8080/a.png"), "1.2.3.4:8080");
    }

    #[test]
    fn mesh_images_are_marked_as_needing_no_network() {
        let key = mesh_key("bob", "cat.png");
        assert!(is_mesh_key(&key));
        assert!(!is_mesh_key("https://example.com/cat.png"));
        // The viewer must not claim a host was contacted for a radio delivery.
        assert_eq!(host_of(&key), "bluetooth mesh · bob/cat.png");
    }

    #[test]
    fn cache_evicts_the_least_recently_used() {
        let mut cache = ImageCache::new();
        let blank = || image::DynamicImage::new_rgb8(1, 1);
        for index in 0..CACHE_CAPACITY + 3 {
            cache.insert(format!("url{index}"), blank());
        }
        assert_eq!(cache.len(), CACHE_CAPACITY);
        assert!(cache.get("url0").is_none(), "oldest evicted");
        assert!(cache.get(&format!("url{}", CACHE_CAPACITY + 2)).is_some());
    }

    #[test]
    fn cache_keeps_what_is_being_used() {
        let mut cache = ImageCache::new();
        let blank = || image::DynamicImage::new_rgb8(1, 1);
        cache.insert("keep".into(), blank());
        for index in 0..CACHE_CAPACITY {
            // Touch the entry so it stays the most recent.
            assert!(cache.get("keep").is_some());
            cache.insert(format!("filler{index}"), blank());
        }
        assert!(cache.get("keep").is_some(), "recently used must survive");
    }
}
