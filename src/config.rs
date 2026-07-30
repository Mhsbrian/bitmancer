// src/config.rs

//! Settings the operator writes, as distinct from state the client writes.
//!
//! `persistence.rs` already keeps a `state.json` next to this file, and the two
//! are deliberately not the same thing. That one holds identity keys, joined
//! channels and favourites — written by the client, read by the client, and
//! containing an X25519 private key, so it is not a file anyone should be
//! hand-editing or committing to a dotfiles repo. This one is the reverse: the
//! client only ever reads it, so a stray write can never destroy something the
//! user typed, and nothing secret is ever put in it.
//!
//! Plain `key = value` rather than TOML or JSON. The whole file is a handful of
//! keys, so a parser is thirty lines and a dependency is a dependency — on a
//! crate whose premise is not leaking a private key, the bar for adding one to
//! read two settings is higher than the convenience is worth. JSON was already
//! available and rejected for the opposite reason: a config a human is expected
//! to edit wants comments, and JSON has none.

use std::path::{Path, PathBuf};

/// Where the file lives: beside `state.json`, in `~/.bitmancer/`.
pub fn config_file_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".bitmancer");
    path.push("config");
    path
}

pub struct Config {
    /// Used when no identity has been minted yet. An existing `state.json`
    /// wins, because the nickname there is the one peers have already seen and
    /// silently changing it under them is worse than ignoring a setting.
    pub nickname: Option<String>,

    /// Whether to take the mouse. On by default, because that is what buys the
    /// wheel. Turning it off hands click-drag selection back to the terminal,
    /// which is the escape hatch for terminals where `Shift`+drag does not
    /// reach the selection underneath — a real gap, since that behaviour is the
    /// terminal's and not something this client can promise.
    pub mouse_capture: bool,

    /// Lines that could not be understood, in the order they appeared.
    ///
    /// Surfaced at startup rather than dropped. A mistyped key that silently
    /// does nothing is the characteristic way a config file wastes someone's
    /// afternoon, and the file is small enough that there is no such thing as
    /// an acceptable unread line in it.
    pub warnings: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: None,
            mouse_capture: true,
            warnings: Vec::new(),
        }
    }
}

/// Reads the config, falling back to defaults for anything absent.
///
/// A missing file is not a warning: not having one is the normal case and the
/// client is fully usable without it.
pub fn load() -> Config {
    load_from(&config_file_path())
}

/// The `_at` half, following `persistence.rs`'s `load_state_at`/`wipe_state_at`
/// convention rather than inventing a second one. Every test points here; none
/// can reach the operator's real file.
pub fn load_from(path: &Path) -> Config {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Config::default();
    };
    parse(&contents)
}

fn parse(contents: &str) -> Config {
    let mut config = Config::default();

    for (number, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        // A comment marker anywhere but the start is left alone: a nickname is
        // allowed to contain a `#`, and stripping trailing comments would make
        // that unrepresentable for no gain on a file this size.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            config
                .warnings
                .push(format!("config line {}: expected key = value", number + 1));
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "nickname" => {
                if value.is_empty() {
                    config
                        .warnings
                        .push(format!("config line {}: nickname is empty", number + 1));
                } else {
                    config.nickname = Some(value.to_string());
                }
            }
            "mouse_capture" => match value {
                "true" => config.mouse_capture = true,
                "false" => config.mouse_capture = false,
                other => config.warnings.push(format!(
                    "config line {}: mouse_capture wants true or false, not {other:?}",
                    number + 1
                )),
            },
            unknown => config.warnings.push(format!(
                "config line {}: unknown setting {unknown:?}",
                number + 1
            )),
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_file_is_the_defaults_and_not_an_error() {
        // Never a path in the repo or the home directory: the point of
        // `load_from` is that a test cannot read the developer's real config.
        let config = load_from(Path::new("/nonexistent/bitmancer/config"));
        assert!(config.nickname.is_none());
        assert!(config.mouse_capture, "the wheel is on unless asked otherwise");
        assert!(
            config.warnings.is_empty(),
            "not having a config is normal, not a problem to report"
        );
    }

    #[test]
    fn both_settings_are_read() {
        let config = parse("nickname = alice\nmouse_capture = false\n");
        assert_eq!(config.nickname.as_deref(), Some("alice"));
        assert!(!config.mouse_capture);
        assert!(config.warnings.is_empty());
    }

    #[test]
    fn whitespace_around_the_equals_does_not_matter() {
        for line in ["nickname=alice", "nickname   =alice", "  nickname = alice  "] {
            let config = parse(line);
            assert_eq!(config.nickname.as_deref(), Some("alice"), "parsing {line:?}");
        }
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let config = parse("# who I am\n\n   \nnickname = alice\n# trailing\n");
        assert_eq!(config.nickname.as_deref(), Some("alice"));
        assert!(config.warnings.is_empty(), "a comment is not a bad line");
    }

    #[test]
    fn a_hash_inside_a_value_is_kept() {
        // Only a leading `#` starts a comment. Stripping trailing ones would
        // make a nickname containing a hash impossible to write.
        let config = parse("nickname = anon#7956");
        assert_eq!(config.nickname.as_deref(), Some("anon#7956"));
    }

    #[test]
    fn an_unknown_setting_is_reported_rather_than_ignored() {
        // The whole reason `warnings` exists. A typo that silently does nothing
        // is how a config file wastes an afternoon.
        let config = parse("nicknme = alice\n");
        assert_eq!(config.warnings.len(), 1);
        assert!(
            config.warnings[0].contains("nicknme"),
            "the warning has to name the offending key: {:?}",
            config.warnings[0]
        );
        assert!(config.warnings[0].contains('1'), "and say which line");
    }

    #[test]
    fn a_line_with_no_equals_is_reported() {
        let config = parse("nickname alice\n");
        assert_eq!(config.warnings.len(), 1);
        assert!(config.nickname.is_none());
    }

    #[test]
    fn a_bad_boolean_is_reported_and_leaves_the_default_standing() {
        let config = parse("mouse_capture = yes\n");
        assert_eq!(config.warnings.len(), 1);
        assert!(
            config.mouse_capture,
            "an unreadable value must not silently flip a setting"
        );
    }

    #[test]
    fn an_empty_nickname_is_reported_rather_than_accepted() {
        // `nickname =` with nothing after it is a mistake, and taking it would
        // announce an empty name to the mesh.
        let config = parse("nickname =\n");
        assert_eq!(config.warnings.len(), 1);
        assert!(config.nickname.is_none());
    }

    #[test]
    fn warnings_name_the_line_they_came_from() {
        let config = parse("# fine\nnickname = alice\nbogus = 1\nalso bad\n");
        assert_eq!(config.warnings.len(), 2);
        assert!(config.warnings[0].contains('3'), "{:?}", config.warnings[0]);
        assert!(config.warnings[1].contains('4'), "{:?}", config.warnings[1]);
        assert_eq!(
            config.nickname.as_deref(),
            Some("alice"),
            "a bad line later in the file must not discard a good one before it"
        );
    }

    #[test]
    fn the_last_setting_of_a_kind_wins() {
        let config = parse("nickname = alice\nnickname = bob\n");
        assert_eq!(config.nickname.as_deref(), Some("bob"));
    }

    #[test]
    fn a_file_of_nothing_but_noise_still_parses_to_the_defaults() {
        // Whatever is in the file, startup has to survive it. This is a config
        // read on the path to a terminal takeover: a panic here leaves no UI to
        // report it in.
        let config = parse("\0\n===\n= = =\n\n\u{1}\u{2}\n");
        assert!(config.mouse_capture);
        assert!(config.nickname.is_none());
        assert!(!config.warnings.is_empty(), "and says what it could not read");
    }

    #[test]
    fn reading_a_real_file_goes_through_the_same_path() {
        // `parse` is what the other tests exercise; this pins that `load_from`
        // actually reaches it, so the tests above are not testing a function
        // nothing calls.
        let path = std::env::temp_dir().join("bitmancer-config-test");
        std::fs::write(&path, "nickname = fromdisk\nmouse_capture = false\n")
            .expect("temp dir is writable");
        let config = load_from(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.nickname.as_deref(), Some("fromdisk"));
        assert!(!config.mouse_capture);
    }
}
