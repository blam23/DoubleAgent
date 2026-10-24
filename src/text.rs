//! Text helpers: invisible-character classification and escaping, base64
//! decoding, truncation.

/// Classes of characters that render as nothing (or mislead) but are read by models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Invisible {
    /// Unicode tag characters U+E0000..U+E007F: can smuggle a whole ASCII message.
    Tag,
    /// Variation selectors (incl. supplement U+E0100..): can encode arbitrary bytes.
    VariationSelector,
    /// Bidirectional controls: reorder how text displays (Trojan Source).
    Bidi,
    /// Zero-width and blank-looking characters.
    ZeroWidth,
    /// C0/C1 control characters (incl. ANSI escape).
    Control,
    /// Private use area.
    PrivateUse,
}

pub fn classify(c: char) -> Option<Invisible> {
    let u = c as u32;
    match u {
        0xE0000..=0xE007F => Some(Invisible::Tag),
        0xE0100..=0xE01EF | 0xFE00..=0xFE0D => Some(Invisible::VariationSelector),
        0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C => Some(Invisible::Bidi),
        0x200B
        | 0x200C
        | 0x200D
        | 0x2060..=0x2064
        | 0xFEFF
        | 0x180E
        | 0x00AD
        | 0x034F
        | 0x115F
        | 0x1160
        | 0x3164
        | 0xFFA0
        | 0x2800
        | 0x17B4
        | 0x17B5 => Some(Invisible::ZeroWidth),
        0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F..=0x9F => Some(Invisible::Control),
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD => Some(Invisible::PrivateUse),
        _ => None,
    }
}

/// Is `c` an emoji-ish code point (used to allow ZWJ / VS16 inside emoji sequences).
pub fn is_emoji_context(c: char) -> bool {
    let u = c as u32;
    (0x1F000..=0x1FAFF).contains(&u) || (0x2600..=0x27BF).contains(&u) || (0x1F3FB..=0x1F3FF).contains(&u) || u == 0xFE0F
}

/// Escape invisible / control characters as `<U+XXXX>` so they are visible to humans
/// in reports. Tabs and newlines are kept.
pub fn escape_invisible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' || c == '\t' || c == '\r' {
            out.push(c);
        } else if classify(c).is_some() {
            out.push_str(&format!("<U+{:04X}>", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Truncate to at most `max` characters, appending an ellipsis.
pub fn clip(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        return t.to_string();
    }
    let mut o: String = t.chars().take(max).collect();
    o.push('…');
    o
}

/// Decode standard or URL-safe base64 (padding optional). Returns None on any invalid byte.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in bytes {
        buf = (buf << 6) | val(b)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Fraction of characters that are printable text.
pub fn printable_ratio(s: &str) -> f64 {
    let total = s.chars().count();
    if total == 0 {
        return 0.0;
    }
    let ok = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
        .count();
    ok as f64 / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        assert_eq!(b64_decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(b64_decode("aGVsbG8gd29ybGQ").unwrap(), b"hello world");
        assert!(b64_decode("a").is_none());
        assert!(b64_decode("!!!!").is_none());
    }

    #[test]
    fn escapes() {
        assert_eq!(escape_invisible("a\u{200B}b"), "a<U+200B>b");
        assert_eq!(escape_invisible("x\u{E0041}"), "x<U+E0041>");
        assert_eq!(escape_invisible("ok\n"), "ok\n");
    }
}
