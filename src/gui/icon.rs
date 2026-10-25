//! Application and tray icons: the PNGs rendered from `assets/icons/*.svg`
//! (`npm run render-icons` in `vscode-extension/` regenerates them).

use anyhow::{bail, Context as _, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Unread,
    Stopped,
}

impl Status {
    /// Colour of the status dot in the window's status bar.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Status::Running => [46, 204, 113],
            Status::Unread => [255, 193, 7],
            Status::Stopped => [231, 76, 60],
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Running => "monitoring",
            Status::Unread => "new alert",
            Status::Stopped => "stopped",
        }
    }
}

pub struct Rgba {
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

const TRAY_JADE: &[u8] = include_bytes!("../../assets/icons/png/doubleagent-jade-32.png");
const TRAY_YELLOW: &[u8] = include_bytes!("../../assets/icons/png/doubleagent-yellow-32.png");
const TRAY_RED: &[u8] = include_bytes!("../../assets/icons/png/doubleagent-red-32.png");
const WINDOW: &[u8] = include_bytes!("../../assets/icons/png/doubleagent-jade-256.png");

/// The tray icon for a status: jade while monitoring, yellow for an unseen alert, red when stopped.
pub fn tray(status: Status) -> Result<Rgba> {
    decode(match status {
        Status::Running => TRAY_JADE,
        Status::Unread => TRAY_YELLOW,
        Status::Stopped => TRAY_RED,
    })
}

pub fn window() -> Result<Rgba> {
    decode(WINDOW)
}

fn decode(bytes: &[u8]) -> Result<Rgba> {
    let mut reader = png::Decoder::new(std::io::Cursor::new(bytes)).read_info().context("reading icon")?;
    let mut pixels = vec![0; reader.output_buffer_size().context("icon too large")?];
    let info = reader.next_frame(&mut pixels).context("decoding icon")?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        bail!("icons must be 8-bit RGBA PNGs, got {:?}/{:?}", info.color_type, info.bit_depth);
    }
    pixels.truncate(info.buffer_size());
    Ok(Rgba {
        pixels,
        width: info.width,
        height: info.height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icons_decode_and_the_status_icons_differ() {
        let window = window().unwrap();
        assert_eq!((window.width, window.height), (256, 256));
        assert_eq!(window.pixels.len(), 256 * 256 * 4);
        let [jade, yellow, red] = [Status::Running, Status::Unread, Status::Stopped].map(|s| tray(s).unwrap());
        assert_eq!((jade.width, jade.height), (32, 32));
        assert_ne!(jade.pixels, yellow.pixels);
        assert_ne!(jade.pixels, red.pixels);
        assert_ne!(yellow.pixels, red.pixels);
        // Corners are transparent: the icon sits on the taskbar's own background.
        assert_eq!(jade.pixels[3], 0);
    }
}
