// src/data_structures.rs
//
// What survives of the old shared types: the debug macros and trace writer the
// Noise stack logs through, and the encryption-status enum it reports. Packet
// types, header flags and the legacy BitchatPacket now live in `protocol.rs`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

// Debug levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum DebugLevel {
    Clean = 0, // Default - minimal output
    Basic = 1, // Connection info, key exchanges
    Full = 2,  // All debug output
}

// Global debug level
pub static mut DEBUG_LEVEL: DebugLevel = DebugLevel::Clean;

// Debug macro for basic debug (level 1+)
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        // Only the static read needs unsafe. Expanding the caller's tokens
        // inside the block would hand them unsafe they never asked for.
        {
            let level = unsafe { $crate::data_structures::DEBUG_LEVEL as u8 };
            if level >= $crate::data_structures::DebugLevel::Basic as u8 {
                println!($($arg)*);
            }
        }
    };
}

// Debug macro for full debug (level 2)
#[macro_export]
macro_rules! debug_full_println {
    ($($arg:tt)*) => {
        // Only the static read needs unsafe. Expanding the caller's tokens
        // inside the block would hand them unsafe they never asked for.
        {
            let level = unsafe { $crate::data_structures::DEBUG_LEVEL as u8 };
            if level >= $crate::data_structures::DebugLevel::Full as u8 {
                println!($($arg)*);
            }
        }
    };
}

// MARK: - Noise trace

/// Appends a line to the Noise trace, but only when the operator has asked for
/// one by pointing `BITMANCER_NOISE_LOG` at a path.
///
/// Both halves of the Noise stack log through here, and that is the point. They
/// used to own a copy of this function each, both writing to a fixed filename in
/// the current working directory, and only one copy was ever fixed:
/// `noise_session.rs` learned to ask permission while `noise_protocol.rs` kept
/// appending `noise_protocol_debug.log` wherever the client happened to be
/// launched from. A trace of every handshake and every encrypt carries peer ids,
/// message sizes and timings that nobody asked to have written to disk — on a
/// client whose whole purpose is not leaving that trail. One writer means the
/// next module that wants a trace cannot reintroduce the ungated variant.
///
/// The gate is an environment variable rather than `DEBUG_LEVEL` because
/// `/debug` toggles that level at runtime: a user asking to see packets on
/// screen has not asked to start a multi-megabyte file on disk.
pub fn noise_trace(message: &str) {
    let Ok(path) = std::env::var("BITMANCER_NOISE_LOG") else {
        return;
    };
    append_trace(Path::new(&path), message);
}

/// The write itself, separate from the gate so it can be tested without
/// touching the process environment.
///
/// Every failure is swallowed on purpose. A trace is a courtesy to whoever is
/// debugging, and an unwritable path must not take a chat client down with it —
/// which is also why the clock is read with a fallback rather than unwrapped.
fn append_trace(path: &Path, message: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since_epoch| since_epoch.as_secs())
            .unwrap_or(0);
        let _ = file.write_all(format!("[{timestamp}] {message}\n").as_bytes());
    }
}

// BLE identifiers (unchanged across the protocol overhaul).
pub const BITCHAT_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);
pub const BITCHAT_CHARACTERISTIC_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

#[cfg(test)]
mod noise_trace_tests {
    use super::*;

    /// Never a path in the repo: the whole defect being fixed here was a writer
    /// that dropped a file wherever it was standing.
    fn scratch(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitmancer-trace-{name}-{}.log", std::process::id()));
        path
    }

    #[test]
    fn each_line_is_appended_rather_than_replacing_the_one_before() {
        let path = scratch("appends");
        let _ = std::fs::remove_file(&path);

        append_trace(&path, "first");
        append_trace(&path, "second");

        let written = std::fs::read_to_string(&path).expect("the trace file was created");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "both lines survive: {written:?}");
        assert!(lines[0].ends_with(" first"), "got {:?}", lines[0]);
        assert!(lines[1].ends_with(" second"), "got {:?}", lines[1]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_line_carries_a_timestamp_the_reader_can_parse() {
        // The format is `[secs] message`. A trace nobody can order is not one.
        let path = scratch("timestamp");
        let _ = std::fs::remove_file(&path);

        append_trace(&path, "an event");

        let written = std::fs::read_to_string(&path).expect("the trace file was created");
        let seconds = written
            .trim_start_matches('[')
            .split(']')
            .next()
            .and_then(|digits| digits.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("no parsable timestamp in {written:?}"));
        assert!(seconds > 1_700_000_000, "clock looks wrong: {seconds}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_path_that_cannot_be_opened_is_not_fatal() {
        // Reaching this assertion at all is the assertion: a trace that cannot
        // be written must not panic a running client.
        append_trace(
            Path::new("/nonexistent-bitmancer-directory/trace.log"),
            "dropped",
        );
    }

    #[test]
    fn the_trace_is_silent_unless_the_operator_asks_for_it() {
        // The gate reads one variable and returns. Asserted through the public
        // entry point, which is the only thing the Noise stack calls.
        //
        // Deliberately does not set the variable: the process environment is
        // shared with every other test in this binary, and a test that mutates
        // it would be a race dressed up as coverage.
        if std::env::var("BITMANCER_NOISE_LOG").is_ok() {
            return; // An operator is tracing this very run; nothing to assert.
        }
        noise_trace("this must not reach any file");

        let stray = std::path::Path::new("noise_protocol_debug.log");
        let before = stray.metadata().map(|meta| meta.len());
        noise_trace("nor this");
        let after = stray.metadata().map(|meta| meta.len());
        assert_eq!(
            before.ok(),
            after.ok(),
            "the ungated writer is back: {} grew",
            stray.display()
        );
    }
}
