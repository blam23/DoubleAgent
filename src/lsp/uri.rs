//! `file:` URIs <-> paths, and the workspace roots an `initialize` request carries.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let path = decode(rest.split(['?', '#']).next().unwrap_or(rest));
    if cfg!(windows) {
        let trimmed = path.strip_prefix('/').unwrap_or(&path);
        let mut chars = trimmed.chars();
        let drive = chars.next().filter(char::is_ascii_alphabetic)?;
        (chars.next() == Some(':')).then(|| PathBuf::from(format!("{}{}", drive.to_ascii_uppercase(), trimmed[1..].replace('/', "\\"))))
    } else {
        Some(PathBuf::from(path))
    }
}

pub fn from_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut out = String::from("file://");
    if !text.starts_with('/') {
        out.push('/');
    }
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Workspace folders from `initialize`, falling back to the legacy `rootUri`.
pub fn roots(params: &Value) -> Vec<PathBuf> {
    let folders: Vec<PathBuf> = params["workspaceFolders"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f["uri"].as_str().and_then(to_path))
        .collect();
    if !folders.is_empty() {
        return folders;
    }
    params["rootUri"].as_str().and_then(to_path).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_paths_with_spaces_and_unicode() {
        let path = if cfg!(windows) {
            PathBuf::from(r"C:\My Code\é\AGENTS.md")
        } else {
            PathBuf::from("/my code/é/AGENTS.md")
        };
        let uri = from_path(&path);
        assert!(uri.contains("%20") && !uri.contains(' '));
        assert_eq!(to_path(&uri), Some(path));
    }

    #[cfg(windows)]
    #[test]
    fn editor_style_drive_uris_are_normalised() {
        assert_eq!(
            to_path("file:///c%3A/Users/me/AGENTS.md"),
            Some(PathBuf::from(r"C:\Users\me\AGENTS.md"))
        );
    }
}
