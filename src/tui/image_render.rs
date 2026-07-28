// src/tui/image_render.rs
//
// Getting a picture onto a text grid, two ways.
//
// Kitty's graphics protocol draws real pixels and is what this machine has, so
// it is the default when available. Everywhere else falls back to half-block
// cells: each character shows two vertically stacked pixels using a foreground
// and background colour, which doubles the vertical resolution and looks far
// better than any ASCII-ramp approach. The feature degrades rather than
// disappearing.

use image::imageops::FilterType;
use image::DynamicImage;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// A terminal cell is roughly twice as tall as it is wide, so an image scaled
/// to a cell grid must be squashed vertically to keep its proportions.
const CELL_ASPECT: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Real pixels via the kitty graphics protocol.
    Kitty,
    /// Two pixels per character cell, works everywhere.
    HalfBlocks,
}

impl Backend {
    /// Human name for the detected backend, for /status.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Backend::Kitty => "kitty graphics",
            Backend::HalfBlocks => "half-blocks",
        }
    }
}

/// Picks the best renderer the terminal admits to supporting.
pub fn detect_backend() -> Backend {
    detect_backend_from(
        std::env::var("TERM").ok().as_deref(),
        std::env::var("KITTY_WINDOW_ID").is_ok(),
        std::env::var("BITMANCER_IMAGES").ok().as_deref(),
    )
}

/// Split out so the decision is testable without touching the environment.
pub fn detect_backend_from(
    term: Option<&str>,
    kitty_window: bool,
    override_value: Option<&str>,
) -> Backend {
    // An escape hatch matters here: graphics protocols misbehave under
    // multiplexers, and being able to force the portable path is the
    // difference between a degraded image and a corrupted screen.
    match override_value.map(str::to_lowercase).as_deref() {
        Some("halfblocks") | Some("blocks") | Some("off") => return Backend::HalfBlocks,
        Some("kitty") => return Backend::Kitty,
        _ => {}
    }

    let term = term.unwrap_or_default();
    // tmux and screen rewrite escape sequences; do not gamble on passthrough.
    if term.starts_with("tmux") || term.starts_with("screen") {
        return Backend::HalfBlocks;
    }
    if kitty_window || term.contains("kitty") || term.contains("ghostty") {
        return Backend::Kitty;
    }
    Backend::HalfBlocks
}

/// Cell dimensions that fit `image` inside `max_cols` x `max_rows` while
/// preserving its aspect ratio.
pub fn fit_cells(
    image_width: u32,
    image_height: u32,
    max_cols: u16,
    max_rows: u16,
) -> (u16, u16) {
    if image_width == 0 || image_height == 0 || max_cols == 0 || max_rows == 0 {
        return (0, 0);
    }
    let aspect = image_height as f64 / image_width as f64;

    // Try full width first, then clamp by height.
    let mut cols = max_cols as f64;
    let mut rows = cols * aspect / CELL_ASPECT;
    if rows > max_rows as f64 {
        rows = max_rows as f64;
        cols = rows * CELL_ASPECT / aspect;
    }
    (cols.floor().max(1.0) as u16, rows.floor().max(1.0) as u16)
}

/// Renders into half-block lines: one character per cell, upper half painted
/// with the foreground colour and lower half with the background.
pub fn half_blocks(image: &DynamicImage, cols: u16, rows: u16) -> Vec<Line<'static>> {
    if cols == 0 || rows == 0 {
        return Vec::new();
    }
    // Two pixel rows per character row.
    let resized = image
        .resize_exact(cols as u32, rows as u32 * 2, FilterType::Triangle)
        .to_rgb8();

    (0..rows)
        .map(|row| {
            let spans: Vec<Span<'static>> = (0..cols)
                .map(|col| {
                    let top = resized.get_pixel(col as u32, row as u32 * 2).0;
                    let bottom = resized.get_pixel(col as u32, row as u32 * 2 + 1).0;
                    Span::styled(
                        "▀",
                        Style::default()
                            .fg(Color::Rgb(top[0], top[1], top[2]))
                            .bg(Color::Rgb(bottom[0], bottom[1], bottom[2])),
                    )
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

// MARK: - Kitty graphics protocol

/// Identifier we reuse for every image, so a new one replaces the old.
pub const KITTY_IMAGE_ID: u32 = 8115;
/// Kitty requires escape payloads to be chunked.
const CHUNK: usize = 4096;

/// Escape sequence transmitting a PNG and displaying it at the cursor.
///
/// Sent as `f=100` (PNG data) with an explicit id, chunked with `m=1` on every
/// piece but the last. `q=2` suppresses the terminal's acknowledgement, which
/// would otherwise land in the key input stream and be read as junk keystrokes.
pub fn kitty_transmit(png: &[u8], cols: u16, rows: u16) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(png);

    let mut out = String::with_capacity(encoded.len() + 128);
    let chunks: Vec<&str> = encoded
        .as_bytes()
        .chunks(CHUNK)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();

    for (index, chunk) in chunks.iter().enumerate() {
        let more = if index + 1 < chunks.len() { 1 } else { 0 };
        if index == 0 {
            // a=T transmits and displays in one go; c/r scale it to our cells.
            out.push_str(&format!(
                "\x1b_Ga=T,f=100,i={KITTY_IMAGE_ID},c={cols},r={rows},q=2,m={more};{chunk}\x1b\\"
            ));
        } else {
            out.push_str(&format!("\x1b_Gm={more},q=2;{chunk}\x1b\\"));
        }
    }
    out
}

/// Re-displays an image already transmitted under `KITTY_IMAGE_ID`.
///
/// ratatui redraws every frame and the image must be re-placed each time, but
/// re-sending the payload would push kilobytes down the pty ten times a second.
/// Placement is a few dozen bytes.
pub fn kitty_place(cols: u16, rows: u16) -> String {
    format!("\x1b_Ga=p,i={KITTY_IMAGE_ID},c={cols},r={rows},q=2\x1b\\")
}

/// Removes our image from the screen.
pub fn kitty_delete() -> String {
    format!("\x1b_Ga=d,d=i,i={KITTY_IMAGE_ID},q=2\x1b\\")
}

/// Encodes to PNG for transmission, since kitty takes PNG directly and it
/// avoids shipping raw RGBA for large images.
pub fn to_png(image: &DynamicImage, cols: u16, rows: u16) -> Option<Vec<u8>> {
    // Scale to roughly the pixel size of the target cell box. Guessing 8x16
    // pixels per cell is close enough on every normal font, and kitty rescales
    // to the c/r box anyway.
    let target_width = (cols as u32 * 8).max(1);
    let target_height = (rows as u32 * 16).max(1);
    let scaled = image.resize(target_width, target_height, FilterType::Triangle);

    let mut png = Vec::new();
    scaled
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .ok()?;
    Some(png)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_kitty_from_either_signal() {
        assert_eq!(
            detect_backend_from(Some("xterm-kitty"), false, None),
            Backend::Kitty
        );
        assert_eq!(
            detect_backend_from(Some("xterm-256color"), true, None),
            Backend::Kitty
        );
        assert_eq!(
            detect_backend_from(Some("xterm-ghostty"), false, None),
            Backend::Kitty
        );
    }

    #[test]
    fn falls_back_everywhere_else() {
        for term in ["xterm-256color", "alacritty", "linux", ""] {
            assert_eq!(
                detect_backend_from(Some(term), false, None),
                Backend::HalfBlocks,
                "{term}"
            );
        }
        assert_eq!(detect_backend_from(None, false, None), Backend::HalfBlocks);
    }

    #[test]
    fn multiplexers_never_get_graphics() {
        // Even inside kitty, tmux rewrites escapes and would corrupt the screen.
        assert_eq!(
            detect_backend_from(Some("tmux-256color"), true, None),
            Backend::HalfBlocks
        );
        assert_eq!(
            detect_backend_from(Some("screen.xterm"), true, None),
            Backend::HalfBlocks
        );
    }

    #[test]
    fn the_override_wins_both_ways() {
        assert_eq!(
            detect_backend_from(Some("xterm-kitty"), true, Some("halfblocks")),
            Backend::HalfBlocks
        );
        assert_eq!(
            detect_backend_from(Some("dumb"), false, Some("kitty")),
            Backend::Kitty
        );
    }

    #[test]
    fn fitting_preserves_aspect_within_the_box() {
        // A wide image fills the width and stays short.
        let (cols, rows) = fit_cells(800, 400, 80, 40);
        assert_eq!(cols, 80);
        assert_eq!(rows, 20, "800x400 at 80 cols is 40 px-rows = 20 cells");

        // A tall image is limited by height instead.
        let (cols, rows) = fit_cells(400, 1600, 80, 20);
        assert!(rows <= 20);
        assert!(cols <= 80);
        assert!(cols >= 1 && rows >= 1);
    }

    #[test]
    fn fitting_degenerate_input_does_not_panic() {
        assert_eq!(fit_cells(0, 0, 10, 10), (0, 0));
        assert_eq!(fit_cells(10, 10, 0, 10), (0, 0));
        // A one-pixel image still gets one cell rather than zero.
        let (cols, rows) = fit_cells(1, 1, 10, 10);
        assert!(cols >= 1 && rows >= 1);
    }

    #[test]
    fn half_blocks_produce_one_span_per_cell() {
        let image = DynamicImage::new_rgb8(4, 4);
        let lines = half_blocks(&image, 6, 3);
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert_eq!(line.spans.len(), 6);
            assert_eq!(line.spans[0].content, "▀");
            // Both halves must be painted or the cell shows terminal default.
            assert!(line.spans[0].style.fg.is_some());
            assert!(line.spans[0].style.bg.is_some());
        }
    }

    #[test]
    fn half_blocks_sample_the_actual_colours() {
        // Top half red, bottom half blue: one cell row should show exactly that.
        let mut buffer = image::RgbImage::new(1, 2);
        buffer.put_pixel(0, 0, image::Rgb([255, 0, 0]));
        buffer.put_pixel(0, 1, image::Rgb([0, 0, 255]));
        let image = DynamicImage::ImageRgb8(buffer);

        let lines = half_blocks(&image, 1, 1);
        let span = &lines[0].spans[0];
        assert_eq!(span.style.fg, Some(Color::Rgb(255, 0, 0)));
        assert_eq!(span.style.bg, Some(Color::Rgb(0, 0, 255)));
    }

    #[test]
    fn kitty_payload_is_well_formed_and_chunked() {
        let png = to_png(&DynamicImage::new_rgb8(64, 64), 20, 10).expect("encodes");
        let escape = kitty_transmit(&png, 20, 10);

        assert!(escape.starts_with("\x1b_Ga=T,f=100,"), "{}", &escape[..40]);
        assert!(escape.contains(&format!("i={KITTY_IMAGE_ID}")));
        assert!(escape.contains("c=20,r=10"));
        assert!(escape.ends_with("\x1b\\"));
        // Acknowledgements must be suppressed or they arrive as keystrokes.
        assert!(escape.contains("q=2"));
        // Every chunk but the last is marked as continuing.
        assert!(escape.contains("m=1;") || png.len() < 3000);
        assert!(escape.contains("m=0;"), "final chunk must close the stream");
    }

    #[test]
    fn placement_is_tiny_compared_to_transmission() {
        let png = to_png(&DynamicImage::new_rgb8(256, 256), 40, 20).expect("encodes");
        let transmit = kitty_transmit(&png, 40, 20);
        let place = kitty_place(40, 20);

        assert!(place.contains("a=p"));
        assert!(place.contains(&format!("i={KITTY_IMAGE_ID}")));
        assert!(place.contains("c=40,r=20"));
        assert!(
            place.len() * 20 < transmit.len(),
            "placement {} vs transmit {}",
            place.len(),
            transmit.len()
        );
    }

    #[test]
    fn delete_targets_only_our_image() {
        let escape = kitty_delete();
        assert!(escape.contains(&format!("i={KITTY_IMAGE_ID}")));
        assert!(escape.contains("a=d"));
    }

    #[test]
    fn png_encoding_shrinks_to_the_cell_box() {
        let png = to_png(&DynamicImage::new_rgb8(4000, 4000), 10, 5).expect("encodes");
        let decoded = image::load_from_memory(&png).expect("valid png");
        // 10 cols x 8 px = 80 wide at most, so the 4000px original was scaled.
        assert!(decoded.width() <= 80, "got {}", decoded.width());
    }
}
