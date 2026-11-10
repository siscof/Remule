// SPDX-License-Identifier: GPL-2.0-or-later
//! Number formatting, after `CastItoXBytes` / `CastSecondsToHM` in
//! aMule's `OtherFunctions.cpp` (binary units, short labels).

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["bytes", "kB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} bytes");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

pub fn speed(bytes_per_sec: u64) -> String {
    format!("{:.1} kB/s", bytes_per_sec as f64 / 1024.0)
}

pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Seconds until done at the current rate, or "" when stalled.
pub fn eta(remaining: u64, speed: u64) -> String {
    if speed == 0 || remaining == 0 {
        String::new()
    } else {
        duration(remaining / speed)
    }
}

/// Parse a size typed in MB ("" means no limit).
pub fn parse_mb(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    s.replace(',', ".")
        .parse::<f64>()
        .ok()
        .filter(|v| *v >= 0.0)
        .map(|v| (v * 1024.0 * 1024.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(bytes(512), "512 bytes");
        assert_eq!(bytes(1536), "1.50 kB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(speed(10 * 1024), "10.0 kB/s");
        assert_eq!(duration(3725), "1h 2m");
        assert_eq!(eta(100, 0), "");
        assert_eq!(parse_mb("1.5"), Some(1_572_864));
        assert_eq!(parse_mb(""), Some(0));
        assert_eq!(parse_mb("x"), None);
    }
}
