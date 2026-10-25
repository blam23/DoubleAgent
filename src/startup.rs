//! Run-on-startup support. Windows gets an Internet Shortcut (`.url`) in the per-user Startup folder.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[cfg(windows)]
const SHORTCUT_NAME: &str = "DoubleAgent.url";

/// Where the startup shortcut lives. `None` on platforms without one.
pub fn shortcut_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        dirs::config_dir().map(|roaming| roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup").join(SHORTCUT_NAME))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

pub fn is_enabled() -> bool {
    shortcut_path().is_some_and(|p| p.exists())
}

/// Create or remove the startup shortcut for `exe`. A no-op where unsupported.
pub fn set_enabled(enabled: bool, exe: &Path) -> Result<()> {
    let Some(path) = shortcut_path() else { return Ok(()) };
    if enabled {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(&path, url_shortcut(exe)).with_context(|| format!("writing {}", path.display()))?;
    } else if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

pub fn url_shortcut(exe: &Path) -> String {
    let exe = exe.display().to_string().trim_start_matches(r"\\?\").replace('\\', "/");
    format!("[InternetShortcut]\r\nURL=file:///{exe}\r\nIconIndex=0\r\nIconFile={exe}\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_points_at_the_executable_with_forward_slashes() {
        let text = url_shortcut(Path::new(r"\\?\C:\Apps\DoubleAgent\doubleagent-gui.exe"));
        assert!(text.starts_with("[InternetShortcut]\r\n"));
        assert!(text.contains("URL=file:///C:/Apps/DoubleAgent/doubleagent-gui.exe\r\n"));
        assert!(text.contains("IconFile=C:/Apps/DoubleAgent/doubleagent-gui.exe\r\n"));
    }
}
