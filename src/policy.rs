//! Policy engine: maps final severity to actions. Default is report-only.
//! Optional: OS notification, hook command, quarantine (move, never delete).

use anyhow::{bail, Context as _, Result};
use notify_rust::Notification;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::{app_dir, Config};
use crate::model::Report;
use crate::scanner::sha256_file;
use crate::store::Store;

pub fn quarantine_dir(cfg: &Config) -> PathBuf {
    cfg.policy.quarantine_dir.clone().unwrap_or_else(|| app_dir().join("quarantine"))
}

/// Apply configured actions to one report. Returns a description of each action taken.
pub fn apply(report: &mut Report, cfg: &Config, store: &Store, fresh: bool) -> Vec<String> {
    let mut done = Vec::new();
    if report.suppressed {
        return done;
    }
    let sev = report.severity;
    if fresh && cfg.policy.notify_at.map(|t| sev >= t).unwrap_or(false) {
        let msg = format!(
            "{} risk ({}) agent file: {}",
            sev.as_str().to_uppercase(),
            report.scores.final_score,
            report.path.display()
        );
        match notify(&msg) {
            Ok(()) => done.push("notified".to_string()),
            Err(e) => done.push(format!("notify failed: {e}")),
        }
    }
    if fresh && cfg.policy.hook_at.map(|t| sev >= t).unwrap_or(false) && !cfg.policy.hook_command.is_empty() {
        match run_hook(&cfg.policy.hook_command, report) {
            Ok(()) => done.push("hook ran".to_string()),
            Err(e) => done.push(format!("hook failed: {e}")),
        }
    }
    if cfg.policy.quarantine_at.map(|t| sev >= t).unwrap_or(false) {
        match quarantine(&report.path, &report.sha256, cfg, store, report, false) {
            Ok((id, dest)) => {
                done.push(format!(
                    "quarantined as #{id} → {} (restore with `doubleagent restore {id}`)",
                    dest.display()
                ));
                report.disposition = Some("quarantined".into());
            }
            Err(e) => done.push(format!("quarantine skipped: {e}")),
        }
    }
    for a in &done {
        let _ = store.audit("action", &format!("{} {}", report.path.display(), a));
    }
    done
}

pub fn notify(msg: &str) -> Result<()> {
    Notification::new().summary("DoubleAgent").body(msg).show()?;
    Ok(())
}

fn run_hook(cmd: &[String], report: &Report) -> Result<()> {
    let (prog, args) = cmd.split_first().context("empty hook_command")?;
    let mut child = Command::new(prog)
        .args(args)
        .env("DA_PATH", &report.path)
        .env("DA_SEVERITY", report.severity.as_str())
        .env("DA_SCORE", report.scores.final_score.to_string())
        .env("DA_SHA256", &report.sha256)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {prog}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(serde_json::to_string(report)?.as_bytes());
    }
    let st = child.wait()?;
    if !st.success() {
        bail!("exited with {st}");
    }
    Ok(())
}

fn move_file(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    // Cross-volume: copy, verify, then remove the original (a move, not a delete).
    std::fs::copy(src, dst)?;
    let a = sha256_file(src, u64::MAX)?;
    let b = sha256_file(dst, u64::MAX)?;
    if a != b {
        let _ = std::fs::remove_file(dst);
        bail!("copy verification failed");
    }
    std::fs::remove_file(src)?;
    Ok(())
}

pub fn quarantine(path: &Path, expected_sha: &str, cfg: &Config, store: &Store, report: &Report, manual: bool) -> Result<(i64, PathBuf)> {
    // Re-hash right before moving: if the file changed since it was rated, don't act on stale data.
    let now_sha = sha256_file(path, cfg.scan.max_file_size)?;
    if now_sha != expected_sha {
        bail!("file changed since it was scanned; will re-evaluate on the next scan");
    }
    let dir = quarantine_dir(cfg);
    std::fs::create_dir_all(&dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let dest = dir.join(format!("{stamp}-{}-{name}.quarantined", &expected_sha[..12]));
    move_file(path, &dest)?;
    let meta = serde_json::json!({"original_path": path, "sha256": expected_sha, "quarantined_at": crate::store::now(), "manual": manual});
    let _ = std::fs::write(dest.with_extension("json"), serde_json::to_string_pretty(&meta)?);
    let id = store.add_quarantine(path, &dest, expected_sha, manual, Some(report))?;
    store.audit("quarantine", &format!("#{id} {} -> {}", path.display(), dest.display()))?;
    Ok((id, dest))
}

pub fn restore(id: i64, store: &Store) -> Result<PathBuf> {
    let row = store
        .list_quarantine()?
        .into_iter()
        .find(|q| q.id == id)
        .with_context(|| format!("no quarantine entry #{id}"))?;
    if row.restored {
        bail!("entry #{id} was already restored");
    }
    let orig = PathBuf::from(&row.original_path);
    if orig.exists() {
        bail!("{} already exists; move it aside first", orig.display());
    }
    if let Some(p) = orig.parent() {
        std::fs::create_dir_all(p)?;
    }
    move_file(Path::new(&row.stored_path), &orig)?;
    let _ = std::fs::remove_file(Path::new(&row.stored_path).with_extension("json"));
    store.mark_restored(id)?;
    store.audit("restore", &format!("#{id} -> {}", orig.display()))?;
    Ok(orig)
}
