// tests/common/mod.rs
//
// Shared by the two pty suites. Each file under `tests/` is its own crate, so
// without this the parser below would exist twice — which is the shape this repo
// has already been bitten by once, when the Noise trace writer had a gated copy
// and an ungated one and only the gated one got fixed. A helper that decides
// what a terminal was asked for is exactly the kind that must not drift.

/// Every private mode the transcript sets and resets, deduplicated and sorted.
///
/// A private mode is `ESC [ ? <digits>` then `h` to set or `l` to reset.
///
/// Derived rather than named on purpose. `EnableMouseCapture` is not one mode,
/// it is **five** — 1000, 1002, 1003, 1006 and 1015 — and every hand-written
/// assertion in these suites names only 1006, the SGR *encoding*. The modes that
/// actually take the terminal's click-drag selection away are 1000, 1002 and
/// 1003, so a check that names 1006 is checking the wrong thing for anything
/// about selection. Reading the numbers out of the transcript means no list has
/// to be maintained and none can be incomplete.
pub fn private_modes(transcript: &str) -> (Vec<String>, Vec<String>) {
    let chars: Vec<char> = transcript.chars().collect();
    let (mut set, mut unset) = (Vec::new(), Vec::new());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\x1b'
            && index + 2 < chars.len()
            && chars[index + 1] == '['
            && chars[index + 2] == '?'
        {
            let mut cursor = index + 3;
            let mut digits = String::new();
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                digits.push(chars[cursor]);
                cursor += 1;
            }
            if cursor < chars.len() && !digits.is_empty() {
                match chars[cursor] {
                    'h' => set.push(digits),
                    'l' => unset.push(digits),
                    _ => {}
                }
            }
            index = cursor;
        } else {
            index += 1;
        }
    }
    set.sort();
    set.dedup();
    unset.sort();
    unset.dedup();
    (set, unset)
}
