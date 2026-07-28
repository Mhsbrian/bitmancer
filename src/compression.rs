// src/compression.rs
//
// bitchat compresses payloads with Apple's `COMPRESSION_ZLIB`, which despite the
// name emits *raw* DEFLATE (RFC 1951) with no zlib wrapper and no checksum. The
// old client used LZ4 here, so every compressed frame from a real peer failed to
// decode.

use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::collections::HashSet;
use std::io::Write;

/// Matches `Constants.compressionThresholdBytes`.
pub const COMPRESSION_THRESHOLD: usize = 100;

/// Port of `CompressionUtil.shouldCompress`. We only use this to mirror the
/// peer's decision when reasoning about canonical signing bytes — outbound
/// frames are currently always sent uncompressed.
pub fn should_compress(data: &[u8]) -> bool {
    if data.len() < COMPRESSION_THRESHOLD {
        return false;
    }
    let unique: HashSet<u8> = data.iter().copied().collect();
    let sample_size = data.len().min(256);
    (unique.len() as f64 / sample_size as f64) < 0.9
}

/// Unused outbound: we never compress, because a canonical re-encode on the
/// far side would not reproduce our DEFLATE. Kept as the inverse of `decompress`,
/// which the round-trip tests exercise.
#[allow(dead_code)]
pub fn compress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < COMPRESSION_THRESHOLD {
        return None;
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).ok()?;
    let compressed = encoder.finish().ok()?;
    if compressed.is_empty() || compressed.len() >= data.len() {
        return None;
    }
    Some(compressed)
}

pub fn decompress(data: &[u8], original_size: usize) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateDecoder::new(Vec::with_capacity(original_size));
    decoder
        .write_all(data)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    decoder
        .finish()
        .map_err(|e| format!("Decompression failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_raw_deflate() {
        let data = b"the mesh is the message ".repeat(20);
        let compressed = compress(&data).expect("compressible input");
        assert!(compressed.len() < data.len());
        let restored = decompress(&compressed, data.len()).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn skips_small_payloads() {
        assert!(compress(b"short").is_none());
        assert!(!should_compress(b"short"));
    }

    #[test]
    fn should_compress_rejects_high_entropy() {
        // 256 distinct bytes: ratio 1.0, above the 0.9 cutoff.
        let high_entropy: Vec<u8> = (0..=255u8).collect();
        assert!(!should_compress(&high_entropy));
        // Repetitive text compresses well and sits far below the cutoff.
        assert!(should_compress(&b"aaaaaaaaaa".repeat(20)));
    }
}
