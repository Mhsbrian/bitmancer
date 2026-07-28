// src/geohash.rs
//
// Geohash encoding and the geo relay directory, ported from
// bitchat/Protocols/Geohash.swift and bitchat/Nostr/GeoRelayDirectory.swift.
//
// Relay selection has to agree with every other client bit for bit: a geohash
// channel only works because publishers and subscribers independently pick the
// same relays from the same directory. Upstream sorts by haversine distance
// from the geohash centre and breaks ties by host, so we do exactly that.

const BASE32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// The directory upstream ships and refreshes from
/// https://raw.githubusercontent.com/permissionlesstech/bitchat/refs/heads/main/relays/online_relays_gps.csv
const RELAY_CSV: &str = include_str!("../assets/online_relays_gps.csv");

/// Channel precisions offered by the phone app (GeohashChannelLevel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLevel {
    Building,
    Block,
    Neighborhood,
    City,
    Province,
    Region,
}

impl ChannelLevel {
    pub fn precision(self) -> usize {
        match self {
            ChannelLevel::Building => 8,
            ChannelLevel::Block => 7,
            ChannelLevel::Neighborhood => 6,
            ChannelLevel::City => 5,
            ChannelLevel::Province => 4,
            ChannelLevel::Region => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ChannelLevel::Building => "building",
            ChannelLevel::Block => "block",
            ChannelLevel::Neighborhood => "neighborhood",
            ChannelLevel::City => "city",
            ChannelLevel::Province => "province",
            ChannelLevel::Region => "region",
        }
    }

    pub const ALL: [ChannelLevel; 6] = [
        ChannelLevel::Building,
        ChannelLevel::Block,
        ChannelLevel::Neighborhood,
        ChannelLevel::City,
        ChannelLevel::Province,
        ChannelLevel::Region,
    ];
}

/// A non-empty base32 geohash of at most 12 characters.
pub fn is_valid(geohash: &str) -> bool {
    let length = geohash.chars().count();
    if !(1..=12).contains(&length) {
        return false;
    }
    geohash
        .to_lowercase()
        .bytes()
        .all(|byte| BASE32.contains(&byte))
}

/// Normalises user input: strips a leading '#' and lowercases.
pub fn normalize(input: &str) -> String {
    input.trim().trim_start_matches('#').to_lowercase()
}

/// The inverse of `decode`, exercised by the round-trip tests. Nothing in the
/// client encodes a geohash today; the map works from cells it was given.
#[allow(dead_code)]
pub fn encode(latitude: f64, longitude: f64, precision: usize) -> String {
    if precision == 0 {
        return String::new();
    }
    let mut lat_interval = (-90.0f64, 90.0f64);
    let mut lon_interval = (-180.0f64, 180.0f64);
    let lat = latitude.clamp(-90.0, 90.0);
    let lon = longitude.clamp(-180.0, 180.0);

    let mut is_even = true;
    let mut bit = 0;
    let mut ch = 0usize;
    let mut out = String::with_capacity(precision);

    while out.len() < precision {
        if is_even {
            let mid = (lon_interval.0 + lon_interval.1) / 2.0;
            if lon >= mid {
                ch |= 1 << (4 - bit);
                lon_interval.0 = mid;
            } else {
                lon_interval.1 = mid;
            }
        } else {
            let mid = (lat_interval.0 + lat_interval.1) / 2.0;
            if lat >= mid {
                ch |= 1 << (4 - bit);
                lat_interval.0 = mid;
            } else {
                lat_interval.1 = mid;
            }
        }
        is_even = !is_even;
        if bit < 4 {
            bit += 1;
        } else {
            out.push(BASE32[ch] as char);
            bit = 0;
            ch = 0;
        }
    }
    out
}

/// The geographic extent of a geohash cell.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BBox {
    pub lat_min: f64,
    pub lat_max: f64,
    pub lon_min: f64,
    pub lon_max: f64,
}

impl BBox {
    pub fn world() -> Self {
        Self {
            lat_min: -90.0,
            lat_max: 90.0,
            lon_min: -180.0,
            lon_max: 180.0,
        }
    }

    pub fn center(&self) -> (f64, f64) {
        (
            (self.lat_min + self.lat_max) / 2.0,
            (self.lon_min + self.lon_max) / 2.0,
        )
    }

    pub fn width(&self) -> f64 {
        self.lon_max - self.lon_min
    }

    pub fn height(&self) -> f64 {
        self.lat_max - self.lat_min
    }

    /// Grows the box by a fraction of its size on every side, so a drilled-in
    /// cell is drawn with some surrounding context rather than edge to edge.
    pub fn padded(&self, fraction: f64) -> Self {
        let pad_lat = self.height() * fraction;
        let pad_lon = self.width() * fraction;
        Self {
            lat_min: (self.lat_min - pad_lat).max(-90.0),
            lat_max: (self.lat_max + pad_lat).min(90.0),
            lon_min: (self.lon_min - pad_lon).max(-180.0),
            lon_max: (self.lon_max + pad_lon).min(180.0),
        }
    }
}

/// Bounding box of a geohash cell. An empty geohash is the whole world.
pub fn bbox(geohash: &str) -> BBox {
    let mut lat = (-90.0f64, 90.0f64);
    let mut lon = (-180.0f64, 180.0f64);
    let mut is_even = true;

    for character in geohash.to_lowercase().chars() {
        let Some(index) = BASE32.iter().position(|&b| b as char == character) else {
            continue;
        };
        for bit in (0..5).rev() {
            let value = (index >> bit) & 1;
            if is_even {
                let mid = (lon.0 + lon.1) / 2.0;
                if value == 1 {
                    lon.0 = mid;
                } else {
                    lon.1 = mid;
                }
            } else {
                let mid = (lat.0 + lat.1) / 2.0;
                if value == 1 {
                    lat.0 = mid;
                } else {
                    lat.1 = mid;
                }
            }
            is_even = !is_even;
        }
    }

    BBox {
        lat_min: lat.0,
        lat_max: lat.1,
        lon_min: lon.0,
        lon_max: lon.1,
    }
}

/// The 32 cells one character deeper than `prefix`.
pub fn children(prefix: &str) -> Vec<String> {
    BASE32
        .iter()
        .map(|&byte| format!("{prefix}{}", byte as char))
        .collect()
}

/// A child cell placed on the grid the eye sees.
#[derive(Debug, Clone, PartialEq)]
pub struct GridCell {
    pub geohash: String,
    pub row: usize,
    pub col: usize,
    pub bbox: BBox,
}

/// Lays the 32 children out in geographic order: row 0 is the northernmost,
/// column 0 the westernmost. Geohash alternates between 8x4 and 4x8 grids as
/// precision increases, so the shape is derived from the cells themselves
/// rather than hardcoded.
pub fn grid_layout(prefix: &str) -> Vec<GridCell> {
    let cells: Vec<(String, BBox)> = children(prefix)
        .into_iter()
        .map(|geohash| {
            let box_ = bbox(&geohash);
            (geohash, box_)
        })
        .collect();

    let mut lats: Vec<f64> = cells.iter().map(|(_, b)| b.center().0).collect();
    let mut lons: Vec<f64> = cells.iter().map(|(_, b)| b.center().1).collect();
    lats.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal)); // north first
    lons.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)); // west first
    lats.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
    lons.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);

    cells
        .into_iter()
        .map(|(geohash, box_)| {
            let (lat, lon) = box_.center();
            let row = lats
                .iter()
                .position(|value| (value - lat).abs() < f64::EPSILON)
                .unwrap_or(0);
            let col = lons
                .iter()
                .position(|value| (value - lon).abs() < f64::EPSILON)
                .unwrap_or(0);
            GridCell {
                geohash,
                row,
                col,
                bbox: box_,
            }
        })
        .collect()
}

/// Rows and columns in the child grid of `prefix`.
/// Cell counts for a precision. Exercised by the layout tests; the map derives
/// its grid from the visible bounding box instead.
#[allow(dead_code)]
pub fn grid_dimensions(prefix: &str) -> (usize, usize) {
    let layout = grid_layout(prefix);
    let rows = layout.iter().map(|cell| cell.row).max().unwrap_or(0) + 1;
    let cols = layout.iter().map(|cell| cell.col).max().unwrap_or(0) + 1;
    (rows, cols)
}

/// Name of the channel level a precision corresponds to, if any. Levels 1 and
/// 3 exist as geohashes but are not channel levels in the app.
pub fn level_name(precision: usize) -> Option<&'static str> {
    ChannelLevel::ALL
        .iter()
        .find(|level| level.precision() == precision)
        .map(|level| level.label())
}

/// Centre of the geohash cell.
pub fn decode_center(geohash: &str) -> (f64, f64) {
    let mut lat_interval = (-90.0f64, 90.0f64);
    let mut lon_interval = (-180.0f64, 180.0f64);
    let mut is_even = true;

    for character in geohash.to_lowercase().chars() {
        let Some(index) = BASE32.iter().position(|&b| b as char == character) else {
            continue;
        };
        for bit in (0..5).rev() {
            let value = (index >> bit) & 1;
            if is_even {
                let mid = (lon_interval.0 + lon_interval.1) / 2.0;
                if value == 1 {
                    lon_interval.0 = mid;
                } else {
                    lon_interval.1 = mid;
                }
            } else {
                let mid = (lat_interval.0 + lat_interval.1) / 2.0;
                if value == 1 {
                    lat_interval.0 = mid;
                } else {
                    lat_interval.1 = mid;
                }
            }
            is_even = !is_even;
        }
    }

    (
        (lat_interval.0 + lat_interval.1) / 2.0,
        (lon_interval.0 + lon_interval.1) / 2.0,
    )
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().asin()
}

#[derive(Debug, Clone)]
struct RelayEntry {
    host: String,
    lat: f64,
    lon: f64,
}

fn directory() -> &'static [RelayEntry] {
    use std::sync::OnceLock;
    static ENTRIES: OnceLock<Vec<RelayEntry>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        RELAY_CSV
            .lines()
            .skip(1) // header: Relay URL,Latitude,Longitude
            .filter_map(|line| {
                let mut fields = line.split(',');
                let host = fields.next()?.trim();
                let lat = fields.next()?.trim().parse().ok()?;
                let lon = fields.next()?.trim().parse().ok()?;
                if host.is_empty() {
                    return None;
                }
                Some(RelayEntry {
                    host: host.to_string(),
                    lat,
                    lon,
                })
            })
            .collect()
    })
}

/// Up to `count` relay URLs closest to the geohash centre. Ties break by host
/// so every client derives the same set.
pub fn closest_relays(geohash: &str, count: usize) -> Vec<String> {
    let (lat, lon) = decode_center(geohash);
    closest_relays_to(lat, lon, count)
}

pub fn closest_relays_to(lat: f64, lon: f64, count: usize) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    let mut ranked: Vec<(f64, &RelayEntry)> = directory()
        .iter()
        .map(|entry| (haversine_km(lat, lon, entry.lat, entry.lon), entry))
        .collect();

    ranked.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.host.cmp(&b.1.host))
    });

    ranked
        .into_iter()
        .take(count)
        .map(|(_, entry)| format!("wss://{}", entry.host))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_reference_points() {
        // Canonical geohash examples.
        assert_eq!(encode(57.64911, 10.40744, 11), "u4pruydqqvj");
        assert_eq!(encode(48.858370, 2.294481, 7), "u09tunq"); // Eiffel Tower
        assert_eq!(encode(-33.856159, 151.215256, 6), "r3gx2u"); // Sydney Opera House
    }

    #[test]
    fn decode_center_round_trips_encoding() {
        for (lat, lon) in [(37.7749, -122.4194), (-33.8568, 151.2153), (0.0, 0.0)] {
            let geohash = encode(lat, lon, 9);
            let (dlat, dlon) = decode_center(&geohash);
            // Precision 9 is sub-5m, so a coarse bound is plenty.
            assert!((dlat - lat).abs() < 0.001, "{geohash}: lat {dlat} vs {lat}");
            assert!((dlon - lon).abs() < 0.001, "{geohash}: lon {dlon} vs {lon}");
        }
    }

    #[test]
    fn validates_like_upstream() {
        assert!(is_valid("u4pruydqqvj"));
        assert!(is_valid("9q8yy"));
        assert!(is_valid("U4PR")); // case-insensitive
        assert!(!is_valid(""), "empty");
        assert!(!is_valid("abcdefghijklm"), "13 chars is too long");
        assert!(!is_valid("9q8ail"), "a, i, l and o are not in the alphabet");
        assert!(!is_valid("9q8-yy"));
    }

    #[test]
    fn normalizes_user_input() {
        assert_eq!(normalize("#9Q8YY"), "9q8yy");
        assert_eq!(normalize("  9q8yy "), "9q8yy");
    }

    #[test]
    fn channel_levels_match_upstream_precisions() {
        assert_eq!(ChannelLevel::Building.precision(), 8);
        assert_eq!(ChannelLevel::Block.precision(), 7);
        assert_eq!(ChannelLevel::Neighborhood.precision(), 6);
        assert_eq!(ChannelLevel::City.precision(), 5);
        assert_eq!(ChannelLevel::Province.precision(), 4);
        assert_eq!(ChannelLevel::Region.precision(), 2);
    }

    #[test]
    fn relay_directory_loads() {
        let entries = directory();
        assert!(entries.len() > 400, "got {} entries", entries.len());
        assert!(entries.iter().all(|e| !e.host.is_empty()));
        assert!(entries.iter().all(|e| (-90.0..=90.0).contains(&e.lat)));
        assert!(entries.iter().all(|e| (-180.0..=180.0).contains(&e.lon)));
    }

    #[test]
    fn closest_relays_are_deterministic_and_wss() {
        let first = closest_relays("9q8yy", 5);
        let second = closest_relays("9q8yy", 5);
        assert_eq!(first.len(), 5);
        assert_eq!(first, second, "selection must be stable across calls");
        assert!(first.iter().all(|url| url.starts_with("wss://")));
    }

    #[test]
    fn distant_geohashes_select_different_relays() {
        let san_francisco = closest_relays("9q8yy", 5);
        let tokyo = closest_relays("xn76u", 5);
        assert_ne!(san_francisco, tokyo);
    }

    #[test]
    fn bbox_of_the_empty_geohash_is_the_world() {
        assert_eq!(bbox(""), BBox::world());
    }

    #[test]
    fn bbox_contains_its_centre_and_shrinks_with_precision() {
        let coarse = bbox("9q");
        let fine = bbox("9q8yy");
        assert!(fine.width() < coarse.width());
        assert!(fine.height() < coarse.height());

        let (lat, lon) = decode_center("9q8yy");
        assert!(fine.lat_min <= lat && lat <= fine.lat_max);
        assert!(fine.lon_min <= lon && lon <= fine.lon_max);

        // A child must sit inside its parent.
        assert!(fine.lat_min >= coarse.lat_min && fine.lat_max <= coarse.lat_max);
        assert!(fine.lon_min >= coarse.lon_min && fine.lon_max <= coarse.lon_max);
    }

    #[test]
    fn children_are_the_thirty_two_base32_cells() {
        let kids = children("9q");
        assert_eq!(kids.len(), 32);
        assert_eq!(kids[0], "9q0");
        assert_eq!(kids[31], "9qz");
        assert!(kids.iter().all(|child| is_valid(child)));
    }

    #[test]
    fn children_tile_their_parent_exactly() {
        let parent = bbox("9q");
        let area: f64 = children("9q")
            .iter()
            .map(|child| {
                let b = bbox(child);
                b.width() * b.height()
            })
            .sum();
        let parent_area = parent.width() * parent.height();
        assert!(
            (area - parent_area).abs() < 1e-9,
            "children area {area} != parent {parent_area}"
        );
    }

    #[test]
    fn grid_alternates_between_eight_by_four_and_four_by_eight() {
        // Odd precision splits 3 lon / 2 lat bits, even precision the reverse.
        assert_eq!(grid_dimensions(""), (4, 8));
        assert_eq!(grid_dimensions("9"), (8, 4));
        assert_eq!(grid_dimensions("9q"), (4, 8));
    }

    #[test]
    fn grid_is_ordered_north_west_first() {
        let layout = grid_layout("9");
        assert_eq!(layout.len(), 32);

        let top_left = layout
            .iter()
            .find(|cell| cell.row == 0 && cell.col == 0)
            .expect("a north-west cell");
        for cell in &layout {
            // Nothing is further north or further west than row 0 / col 0.
            assert!(cell.bbox.center().0 <= top_left.bbox.center().0 + f64::EPSILON);
            assert!(cell.bbox.center().1 >= top_left.bbox.center().1 - f64::EPSILON);
        }

        // Every grid position is occupied exactly once.
        let (rows, cols) = grid_dimensions("9");
        let mut seen = vec![false; rows * cols];
        for cell in &layout {
            let index = cell.row * cols + cell.col;
            assert!(!seen[index], "duplicate grid position");
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|occupied| occupied));
    }

    #[test]
    fn level_names_cover_only_channel_precisions() {
        assert_eq!(level_name(2), Some("region"));
        assert_eq!(level_name(5), Some("city"));
        assert_eq!(level_name(8), Some("building"));
        assert_eq!(level_name(1), None, "precision 1 is not a channel level");
        assert_eq!(level_name(3), None);
    }

    #[test]
    fn padding_stays_within_world_bounds() {
        let padded = bbox("").padded(0.5);
        assert_eq!(padded, BBox::world(), "cannot pad past the poles");
        let local = bbox("9q8yy").padded(0.25);
        assert!(local.width() > bbox("9q8yy").width());
    }

    #[test]
    fn haversine_matches_known_distances() {
        // SF to NYC is ~4130 km.
        let km = haversine_km(37.7749, -122.4194, 40.7128, -74.0060);
        assert!((km - 4130.0).abs() < 50.0, "got {km} km");
        assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0);
    }
}
