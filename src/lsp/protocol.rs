//! LSP base protocol: `Content-Length` framed JSON-RPC over stdio.

use serde_json::Value;
use std::io::{BufRead, Write};

/// Next message, or `None` at end of input or on a framing error.
pub fn read(input: &mut impl BufRead) -> Option<Value> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if input.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let mut body = vec![0u8; length?];
    input.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

pub fn write(message: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(message)?;
    let mut out = std::io::stdout().lock();
    write!(out, "Content-Length: {}\r\n\r\n", body.len())?;
    out.write_all(&body)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_framed_messages_back_to_back() {
        let data = b"Content-Length: 17\r\n\r\n{\"jsonrpc\":\"2.0\"}Content-Length: 2\r\n\r\n{}";
        let mut input = std::io::Cursor::new(&data[..]);
        assert_eq!(read(&mut input).unwrap()["jsonrpc"], "2.0");
        assert_eq!(read(&mut input).unwrap(), serde_json::json!({}));
        assert!(read(&mut input).is_none());
    }
}
