// SPDX-License-Identifier: GPL-2.0-or-later
//! How amulecmd writes values: sizes and speeds (`OtherFunctions.cpp`),
//! priorities (`DataToText.cpp`), a download's status and a statistics
//! tree node's label (`ECSpecialTags.cpp`), log lines (`LogText.h`) and
//! search progress (`SearchProgressReport.cpp`), in aMule's English.

use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `CastItoXBytes`: IEC units, with C's float arithmetic.
pub fn xbytes(count: u64) -> String {
    if count < 1024 {
        plural(count, "byte", "bytes")
    } else if count < 1_048_576 {
        format!("{} KiB", count >> 10)
    } else if count < 1_073_741_824 {
        format!("{:.2} MiB", (count as u32) as f32 / 1_048_576.0)
    } else if count < 1_099_511_627_776 {
        format!("{:.3} GiB", ((count / 1024) as u32) as f32 / 1_048_576.0)
    } else {
        format!("{:.3} TiB", count as f32 / 1_099_511_627_776.0)
    }
}

/// `CastItoIShort`.
pub fn ishort(count: u64) -> String {
    if count < 1000 {
        format!("{count}")
    } else if count < 1_000_000 {
        format!("{:.0}k", (count as u32) as f32 / 1000.0)
    } else if count < 1_000_000_000 {
        format!("{:.2}M", (count as u32) as f32 / 1_000_000.0)
    } else if count < 1_000_000_000_000 {
        format!("{:.2}G", ((count / 1000) as u32) as f32 / 1_000_000.0)
    } else {
        format!("{:.2}T", count as f32 / 1.0e12)
    }
}

/// `CastItoSpeed`.
pub fn speed(bytes: u32) -> String {
    if bytes < 1024 {
        plural(u64::from(bytes), "byte/sec", "bytes/sec")
    } else if bytes < 1_048_576 {
        format!("{:.2} KiB/s", f64::from(bytes) / 1024.0)
    } else {
        format!("{:.2} MiB/s", f64::from(bytes) / 1_048_576.0)
    }
}

/// `CastSecondsToHM` without milliseconds.
pub fn seconds_hm(count: u32) -> String {
    if count < 60 {
        format!("{count:02} secs")
    } else if count < 3600 {
        format!("{}:{:02} mins", count / 60, count % 60)
    } else if count < 86400 {
        format!("{}:{:02} hours", count / 3600, (count % 3600) / 60)
    } else {
        format!(
            "{} days {:02}:{:02} hours",
            count / 86400,
            (count % 86400) / 3600,
            (count % 3600) / 60
        )
    }
}

pub const PR_LOW: u8 = 0;
pub const PR_NORMAL: u8 = 1;
pub const PR_HIGH: u8 = 2;
pub const PR_VERYHIGH: u8 = 3;
pub const PR_VERY_LOW: u8 = 4;
pub const PR_AUTO: u8 = 5;
pub const PR_POWERSHARE: u8 = 6;

/// `PriorityToStr`.
pub fn priority(prio: u8, auto: bool) -> &'static str {
    match (auto, prio) {
        (true, PR_LOW) => "Auto [Lo]",
        (true, PR_NORMAL) => "Auto [No]",
        (true, PR_HIGH) => "Auto [Hi]",
        (false, PR_VERY_LOW) => "Very low",
        (false, PR_LOW) => "Low",
        (false, PR_NORMAL) => "Normal",
        (false, PR_HIGH) => "High",
        (false, PR_VERYHIGH) => "Very High",
        (false, PR_POWERSHARE) => "Release",
        _ => "Unknown",
    }
}

const PS_WAITING_FOR_HASH: u8 = 2;
const PS_HASHING: u8 = 3;
const PS_ERROR: u8 = 4;
const PS_INSUFFICIENT: u8 = 5;
const PS_PAUSED: u8 = 7;
const PS_COMPLETING: u8 = 8;
const PS_COMPLETE: u8 = 9;
const PS_ALLOCATING: u8 = 10;

/// `CEC_PartFile_Tag::GetFileStatusString`.
pub fn file_status(status: u8, stopped: bool, sources_xfer: u16) -> &'static str {
    if status == PS_HASHING || status == PS_WAITING_FOR_HASH {
        return "Hashing";
    }
    if status == PS_ALLOCATING {
        return "Allocating";
    }
    if stopped && status != PS_COMPLETE {
        return "Stopped";
    }
    match status {
        PS_COMPLETING => "Completing",
        PS_COMPLETE => "Complete",
        PS_PAUSED => "Paused",
        PS_ERROR => "Erroneous",
        PS_INSUFFICIENT => "Insufficient disk space",
        _ if sources_xfer > 0 => "Downloading",
        _ => "Waiting",
    }
}

/// `ECLogToText`: each line without the display byte EC keeps for old GUIs.
pub fn log_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match line.as_bytes().first() {
            Some(b' ' | b'!' | b'.') => out.push_str(&line[1..]),
            _ => out.push_str(line),
        }
    }
    out
}

/// One value for [`cformat`].
#[derive(Clone, Debug)]
pub enum Arg {
    Int(u64),
    Double(f64),
    Str(String),
}

/// `%g` as C prints it: six significant digits, trailing zeros dropped.
fn general(v: f64, precision: usize) -> String {
    let p = precision.max(1);
    if v == 0.0 {
        return "0".into();
    }
    if !v.is_finite() {
        return format!("{v}");
    }
    let sci = format!("{:.*e}", p - 1, v);
    let exp: i32 = sci[sci.find('e').unwrap() + 1..].parse().unwrap_or(0);
    if exp < -4 || exp >= p as i32 {
        let (mantissa, _) = sci.split_once('e').unwrap();
        let mantissa = trim_zeros(mantissa);
        format!(
            "{mantissa}e{}{:02}",
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        )
    } else {
        trim_zeros(&format!("{:.*}", (p as i32 - 1 - exp).max(0) as usize, v)).to_string()
    }
}

fn trim_zeros(s: &str) -> &str {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        s
    }
}

fn pad(s: String, width: usize, left: bool, zero: bool) -> String {
    let n = s.chars().count();
    if n >= width {
        return s;
    }
    let fill = width - n;
    if left {
        format!("{s}{}", " ".repeat(fill))
    } else if zero {
        let (sign, digits) = match s.strip_prefix('-') {
            Some(d) => ("-", d),
            None => ("", s.as_str()),
        };
        format!("{sign}{}{digits}", "0".repeat(fill))
    } else {
        format!("{}{s}", " ".repeat(fill))
    }
}

/// aMule's `CFormat`: printf conversions filled in order. A conversion
/// with no value left stays as written, as `CFormat::GetString` leaves it.
pub fn cformat(fmt: &str, args: &[Arg]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut chars = fmt.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        if let Some(&(_, '%')) = chars.peek() {
            chars.next();
            out.push('%');
            continue;
        }
        let (mut left, mut zero) = (false, false);
        let mut width = 0usize;
        let mut precision: Option<usize> = None;
        let mut conv = None;
        let mut end = fmt.len();
        while let Some(&(i, d)) = chars.peek() {
            chars.next();
            match d {
                '-' if width == 0 && precision.is_none() => left = true,
                '0' if width == 0 && precision.is_none() => zero = true,
                '+' | ' ' | '#' => {}
                '0'..='9' => match precision.as_mut() {
                    Some(p) => *p = *p * 10 + (d as usize - '0' as usize),
                    None => width = width * 10 + (d as usize - '0' as usize),
                },
                '.' => precision = Some(0),
                'h' | 'l' | 'L' | 'q' | 'j' | 'z' | 't' => {}
                _ => {
                    conv = Some(d);
                    end = i + d.len_utf8();
                    break;
                }
            }
        }
        let Some(conv) = conv else {
            out.push_str(&fmt[start..]);
            break;
        };
        let Some(arg) = args.next() else {
            out.push_str(&fmt[start..end]);
            continue;
        };
        let text = match (conv, arg) {
            ('d' | 'i', Arg::Int(v)) => format!("{}", *v as i64),
            ('u', Arg::Int(v)) => format!("{v}"),
            ('x', Arg::Int(v)) => format!("{v:x}"),
            ('X', Arg::Int(v)) => format!("{v:X}"),
            ('f' | 'F', Arg::Double(v)) => format!("{:.*}", precision.unwrap_or(6), v),
            ('f' | 'F', Arg::Int(v)) => format!("{:.*}", precision.unwrap_or(6), *v as f64),
            ('g' | 'G', Arg::Double(v)) => general(*v, precision.unwrap_or(6)),
            ('g' | 'G', Arg::Int(v)) => general(*v as f64, precision.unwrap_or(6)),
            ('d' | 'i' | 'u', Arg::Double(v)) => format!("{}", *v as i64),
            (_, Arg::Str(s)) => match precision {
                Some(p) if conv == 's' => s.chars().take(p).collect(),
                _ => s.clone(),
            },
            (_, Arg::Int(v)) => format!("{v}"),
            (_, Arg::Double(v)) => format!("{v}"),
        };
        out.push_str(&pad(text, width, left, zero && conv != 's'));
    }
    out
}

/// What one `EC_TAG_STAT_NODE_VALUE` puts in its label (`FormatValue`).
fn stat_value(tag: &Tag) -> Arg {
    let ty_of = |t: &Tag| {
        t.child(EC_TAG_STAT_VALUE_TYPE)
            .map_or(EC_VALUE_INTEGER, |v| v.as_int() as u8)
    };
    let extra = match tag.child(EC_TAG_STAT_NODE_VALUE) {
        Some(inner) => {
            let spec = match ty_of(inner) {
                EC_VALUE_INTEGER => "%llu",
                EC_VALUE_DOUBLE => "%.2f%%",
                _ => "%s",
            };
            cformat(&format!(" ({spec})"), &[stat_value(inner)])
        }
        None => String::new(),
    };
    match ty_of(tag) {
        EC_VALUE_INTEGER => Arg::Int(tag.as_int()),
        EC_VALUE_ISTRING => Arg::Str(format!("{}{extra}", tag.as_int() as u32)),
        EC_VALUE_BYTES => Arg::Str(xbytes(tag.as_int()) + &extra),
        EC_VALUE_ISHORT => Arg::Str(ishort(tag.as_int()) + &extra),
        EC_VALUE_TIME => Arg::Str(seconds_hm(tag.as_int() as u32) + &extra),
        EC_VALUE_SPEED => Arg::Str(speed(tag.as_int() as u32) + &extra),
        EC_VALUE_STRING => Arg::Str(tag.as_str() + &extra),
        EC_VALUE_DOUBLE => Arg::Double(tag.as_double()),
        _ => Arg::Str(String::new()),
    }
}

/// `CEC_StatTree_Node_Tag::GetDisplayString`.
pub fn stat_label(node: &Tag) -> String {
    let args: Vec<Arg> = node
        .children
        .iter()
        .filter(|c| c.name == EC_TAG_STAT_NODE_VALUE)
        .map(stat_value)
        .collect();
    cformat(&node.as_str(), &args)
}

/// `StatTree2Text`: one node a line, indented a space a level.
pub fn stat_tree(node: Option<&Tag>, depth: usize) -> String {
    let Some(node) = node else {
        return String::new();
    };
    let mut out = format!("{}{}\n", " ".repeat(depth), stat_label(node));
    for child in node.children.iter() {
        if child.name == EC_TAG_STATTREE_NODE {
            out += &stat_tree(Some(child), depth + 1);
        }
    }
    out
}

fn state_name(state: u64) -> &'static str {
    match state {
        1 => "running",
        2 => "finished",
        _ => "idle",
    }
}

fn progress_line(id: u64, name: &str, state: u64, percent: u64, results: u64) -> String {
    let (id, percent, results) = (id as u32, percent as u32, results as u32);
    if name.is_empty() {
        format!(
            "Search {id}: {}, {percent} % ({results} results)\n",
            state_name(state)
        )
    } else {
        format!(
            "Search {id} \"{name}\": {}, {percent} % ({results} results)\n",
            state_name(state)
        )
    }
}

/// `ecprogress::FormatSearchProgress`: every shape of progress reply.
pub fn search_progress(reply: &Packet) -> String {
    if reply.tag(EC_TAG_SEARCH_EXPIRED).is_some() {
        return "Search expired or unknown ID. Start a new search.\n".into();
    }
    let int_or = |t: Option<&Tag>| t.map_or(0, Tag::as_int);
    let name_of = |t: Option<&Tag>| t.map(Tag::as_str).unwrap_or_default();
    let mut out = String::new();
    for entry in reply.tags_named(EC_TAG_SEARCH_ID) {
        let Some(percent) = entry.child(EC_TAG_SEARCH_LIFECYCLE_PERCENT) else {
            continue;
        };
        out += &progress_line(
            entry.as_int(),
            &name_of(entry.child(EC_TAG_SEARCH_NAME)),
            int_or(entry.child(EC_TAG_SEARCH_LIFECYCLE_STATE)),
            percent.as_int(),
            int_or(entry.child(EC_TAG_SEARCH_RESULT_COUNT)),
        );
    }
    if !out.is_empty() {
        return out;
    }
    if let Some(percent) = reply.tag(EC_TAG_SEARCH_LIFECYCLE_PERCENT) {
        return progress_line(
            int_or(reply.tag(EC_TAG_SEARCH_ID)),
            &name_of(reply.tag(EC_TAG_SEARCH_NAME)),
            int_or(reply.tag(EC_TAG_SEARCH_LIFECYCLE_STATE)),
            percent.as_int(),
            int_or(reply.tag(EC_TAG_SEARCH_RESULT_COUNT)),
        );
    }
    if let Some(status) = reply.tag(EC_TAG_SEARCH_STATUS) {
        let progress = status.as_int() as u32;
        if progress <= 100 {
            return format!("Search progress: {progress} % \n");
        }
        return "Search progress not available\n".into();
    }
    "No search to report on.\n".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_speeds_as_amule_writes_them() {
        assert_eq!(xbytes(0), "0 bytes");
        assert_eq!(xbytes(1), "1 byte");
        assert_eq!(xbytes(1023), "1023 bytes");
        assert_eq!(xbytes(300_000), "292 KiB");
        assert_eq!(xbytes(5 * 1_048_576 + 524_288), "5.50 MiB");
        assert_eq!(xbytes(3 * 1_073_741_824), "3.000 GiB");
        assert_eq!(xbytes(2 * 1_099_511_627_776), "2.000 TiB");
        assert_eq!(speed(0), "0 bytes/sec");
        assert_eq!(speed(1), "1 byte/sec");
        assert_eq!(speed(1536), "1.50 KiB/s");
        assert_eq!(speed(3 * 1_048_576), "3.00 MiB/s");
        assert_eq!(ishort(999), "999");
        assert_eq!(ishort(1500), "2k");
        assert_eq!(ishort(2_500_000), "2.50M");
        assert_eq!(seconds_hm(5), "05 secs");
        assert_eq!(seconds_hm(65), "1:05 mins");
        assert_eq!(seconds_hm(3700), "1:01 hours");
        assert_eq!(seconds_hm(90_000), "1 days 01:00 hours");
    }

    #[test]
    fn priorities_and_statuses() {
        assert_eq!(priority(PR_NORMAL, false), "Normal");
        assert_eq!(priority(PR_HIGH, true), "Auto [Hi]");
        assert_eq!(priority(PR_POWERSHARE, false), "Release");
        assert_eq!(priority(9, false), "Unknown");
        assert_eq!(file_status(0, false, 0), "Waiting");
        assert_eq!(file_status(0, false, 2), "Downloading");
        assert_eq!(file_status(0, true, 2), "Stopped");
        assert_eq!(file_status(PS_COMPLETE, true, 0), "Complete");
        assert_eq!(file_status(PS_HASHING, true, 0), "Hashing");
        assert_eq!(file_status(PS_PAUSED, false, 0), "Paused");
    }

    #[test]
    fn cformat_fills_conversions_in_order() {
        let f = |s: &str, a: &[Arg]| cformat(s, a);
        assert_eq!(f("Total: %llu", &[Arg::Int(7)]), "Total: 7");
        assert_eq!(f("Peak: %i", &[Arg::Int(3)]), "Peak: 3");
        assert_eq!(f("Occ: %.2f%%", &[Arg::Double(12.345)]), "Occ: 12.35%");
        assert_eq!(f("Avg: %g", &[Arg::Double(2.5)]), "Avg: 2.5");
        assert_eq!(f("Avg: %g", &[Arg::Double(0.0)]), "Avg: 0");
        assert_eq!(f("Avg: %g", &[Arg::Double(1234567.0)]), "Avg: 1.23457e+06");
        assert_eq!(f("%s of %s", &[Arg::Str("a".into())]), "a of %s");
        assert_eq!(f("[%4i]", &[Arg::Int(5)]), "[   5]");
        assert_eq!(f("[%03u]", &[Arg::Int(5)]), "[005]");
        assert_eq!(f("no values", &[Arg::Int(5)]), "no values");
    }

    #[test]
    fn stat_labels_with_nested_values() {
        let bytes = Tag::int(EC_TAG_STAT_NODE_VALUE, 2048)
            .with(Tag::int(EC_TAG_STAT_VALUE_TYPE, EC_VALUE_BYTES.into()))
            .with(
                Tag::int(EC_TAG_STAT_NODE_VALUE, 1500)
                    .with(Tag::int(EC_TAG_STAT_VALUE_TYPE, EC_VALUE_ISHORT.into())),
            );
        let node = Tag::string(EC_TAG_STATTREE_NODE, "Total Overhead (Packets): %s").with(bytes);
        assert_eq!(stat_label(&node), "Total Overhead (Packets): 2 KiB (2k)");
        let tree = Tag::string(EC_TAG_STATTREE_NODE, "Statistics")
            .with(node.clone())
            .with(
                Tag::string(EC_TAG_STATTREE_NODE, "Uptime: %s").with(
                    Tag::int(EC_TAG_STAT_NODE_VALUE, 61)
                        .with(Tag::int(EC_TAG_STAT_VALUE_TYPE, EC_VALUE_TIME.into())),
                ),
            );
        assert_eq!(
            stat_tree(Some(&tree), 0),
            "Statistics\n Total Overhead (Packets): 2 KiB (2k)\n Uptime: 1:01 mins\n"
        );
    }

    #[test]
    fn log_lines_lose_only_their_marker() {
        assert_eq!(log_text(" a\n!b\n.c\nd\n !e"), "a\nb\nc\nd\n!e");
    }

    #[test]
    fn search_progress_shapes() {
        let union = Packet::new(EC_OP_SEARCH_PROGRESS).with(
            Tag::int(EC_TAG_SEARCH_ID, 3)
                .with(Tag::string(EC_TAG_SEARCH_NAME, "linux"))
                .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_STATE, 1))
                .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_PERCENT, 40))
                .with(Tag::int(EC_TAG_SEARCH_RESULT_COUNT, 12)),
        );
        assert_eq!(
            search_progress(&union),
            "Search 3 \"linux\": running, 40 % (12 results)\n"
        );
        let single = Packet::new(EC_OP_SEARCH_PROGRESS)
            .with(Tag::int(EC_TAG_SEARCH_ID, 4))
            .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_STATE, 2))
            .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_PERCENT, 100));
        assert_eq!(
            search_progress(&single),
            "Search 4: finished, 100 % (0 results)\n"
        );
        let old = Packet::new(EC_OP_SEARCH_PROGRESS).with(Tag::int(EC_TAG_SEARCH_STATUS, 0xfffe));
        assert_eq!(search_progress(&old), "Search progress not available\n");
        assert_eq!(
            search_progress(&Packet::new(EC_OP_SEARCH_PROGRESS)),
            "No search to report on.\n"
        );
    }
}
