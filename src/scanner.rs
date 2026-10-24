//! Candidate discovery (parallel walker) and safe file reading.

use anyhow::{Context as _, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::UNIX_EPOCH;

use crate::config::ScanConfig;

#[derive(Debug, Clone)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: String,
}

/// Decides whether a path is an agent instruction file.
pub struct Matcher {
    names: HashSet<String>,
    patterns: GlobSet,
    exclude_dirs: HashSet<String>,
    exclude: GlobSet,
}

fn build_set(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        let glob = globset::GlobBuilder::new(g)
            .case_insensitive(true)
            .literal_separator(false)
            .build()
            .with_context(|| format!("bad glob {g}"))?;
        b.add(glob);
    }
    Ok(b.build()?)
}

pub fn glob_set(globs: &[String]) -> Result<GlobSet> {
    build_set(globs)
}

/// Normalise to forward slashes for glob matching (Windows paths included).
pub fn slash_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

impl Matcher {
    pub fn new(cfg: &ScanConfig) -> Result<Self> {
        let _ = Glob::new("x"); // keep the import meaningful across globset versions
        Ok(Self {
            names: cfg.filenames.iter().map(|n| n.to_lowercase()).collect(),
            patterns: build_set(&cfg.patterns)?,
            exclude_dirs: cfg.exclude_dirs.iter().map(|n| n.to_lowercase()).collect(),
            exclude: build_set(&cfg.exclude_globs)?,
        })
    }

    pub fn is_candidate(&self, path: &Path) -> bool {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_lowercase()) else {
            return false;
        };
        if self.is_excluded(path) {
            return false;
        }
        self.names.contains(&name) || self.patterns.is_match(slash_path(path))
    }

    pub fn is_candidate_name(&self, name: &str) -> bool {
        self.names.contains(&name.to_lowercase())
    }

    pub fn is_excluded_dir_name(&self, name: &str) -> bool {
        self.exclude_dirs.contains(&name.to_lowercase())
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        if !self.exclude.is_empty() && self.exclude.is_match(slash_path(path)) {
            return true;
        }
        path.parent()
            .map(|p| p.components().any(|c| self.is_excluded_dir_name(&c.as_os_str().to_string_lossy())))
            .unwrap_or(false)
    }
}

/// Walk the roots in parallel and return candidate files.
pub fn walk(roots: &[PathBuf], cfg: &ScanConfig, matcher: &Matcher) -> (Vec<PathBuf>, Vec<Skipped>) {
    let (tx, rx) = mpsc::channel::<Result<PathBuf, Skipped>>();
    let net_mounts = if cfg.skip_network_mounts { network_mounts() } else { vec![] };
    for root in roots {
        if !root.exists() {
            let _ = tx.send(Err(Skipped {
                path: root.clone(),
                reason: "root does not exist".into(),
            }));
            continue;
        }
        if root.is_file() {
            let _ = tx.send(Ok(root.clone()));
            continue;
        }
        let mut wb = ignore::WalkBuilder::new(root);
        wb.hidden(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .require_git(false)
            .follow_links(cfg.follow_symlinks)
            .same_file_system(false)
            .threads(cfg.threads);
        let excl: HashSet<String> = cfg.exclude_dirs.iter().map(|s| s.to_lowercase()).collect();
        let mounts = net_mounts.clone();
        let root_c = root.clone();
        wb.filter_entry(move |e| {
            if e.depth() == 0 {
                return true;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if excl.contains(&n) {
                    return false;
                }
                if mounts.iter().any(|m| e.path() == m.as_path() && !root_c.starts_with(m)) {
                    return false;
                }
            }
            true
        });
        let walker = wb.build_parallel();
        walker.run(|| {
            let tx = tx.clone();
            Box::new(move |res| {
                match res {
                    Ok(entry) => {
                        let is_file = entry.file_type().map(|t| t.is_file() || t.is_symlink()).unwrap_or(false);
                        if is_file && matcher.is_candidate(entry.path()) {
                            let _ = tx.send(Ok(entry.into_path()));
                        }
                    }
                    Err(err) => {
                        // Permission denied, symlink loops, vanished files: record and keep going.
                        let path = match &err {
                            ignore::Error::WithPath { path, .. } => path.clone(),
                            _ => PathBuf::new(),
                        };
                        let msg = err.to_string();
                        if msg.contains("File system loop") || msg.contains("denied") || msg.contains("Access is denied") {
                            let _ = tx.send(Err(Skipped { path, reason: msg }));
                        }
                    }
                }
                ignore::WalkState::Continue
            })
        });
    }
    drop(tx);
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    let mut seen = HashSet::new();
    for r in rx {
        match r {
            Ok(p) => {
                if seen.insert(p.clone()) {
                    found.push(p)
                }
            }
            Err(s) => skipped.push(s),
        }
    }
    found.sort();
    (found, skipped)
}

/// Linux mount points of network / foreign filesystems that we skip by default.
fn network_mounts() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let Ok(text) = std::fs::read_to_string("/proc/mounts") else {
            return vec![];
        };
        let net = [
            "nfs",
            "nfs4",
            "cifs",
            "smb3",
            "smbfs",
            "sshfs",
            "fuse.sshfs",
            "9p",
            "drvfs",
            "fuse.rclone",
            "afs",
            "davfs",
            "fuse.davfs2",
        ];
        text.lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let _dev = it.next()?;
                let mp = it.next()?;
                let fs = it.next()?;
                net.contains(&fs).then(|| PathBuf::from(mp.replace("\\040", " ")))
            })
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![]
    }
}

#[derive(Debug, Clone)]
pub struct FileData {
    pub path: PathBuf,
    pub text: String,
    pub sha256: String,
    pub size: u64,
    pub truncated: bool,
    pub mtime: i64,
    pub file_id: String,
    pub symlink_target: Option<PathBuf>,
    pub world_writable: bool,
}

pub enum ReadOutcome {
    Read(FileData),
    Skip(String),
}

#[cfg(windows)]
fn cloud_placeholder(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x40000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x400000;
    meta.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}
#[cfg(not(windows))]
fn cloud_placeholder(_meta: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn file_identity(meta: &std::fs::Metadata) -> (String, bool) {
    use std::os::unix::fs::MetadataExt;
    (format!("{}:{}", meta.dev(), meta.ino()), meta.mode() & 0o002 != 0)
}
#[cfg(windows)]
fn file_identity(meta: &std::fs::Metadata) -> (String, bool) {
    use std::os::windows::fs::MetadataExt;
    (format!("c{}", meta.creation_time()), false)
}
#[cfg(not(any(unix, windows)))]
fn file_identity(_meta: &std::fs::Metadata) -> (String, bool) {
    (String::new(), false)
}

/// Stat without opening, so cloud placeholders are never hydrated.
pub fn quick_stat(path: &Path) -> Option<(u64, i64, String)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some((meta.len(), mtime, file_identity(&meta).0))
}

/// Read a candidate through a single open handle and hash exactly the bytes read
/// (no time-of-check/time-of-use gap between hashing and analysis).
pub fn read_candidate(path: &Path, cfg: &ScanConfig) -> Result<ReadOutcome> {
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return Ok(ReadOutcome::Skip(format!("stat failed: {e}"))),
    };
    if cfg.skip_cloud_placeholders && cloud_placeholder(&lmeta) {
        return Ok(ReadOutcome::Skip("cloud placeholder (online-only); not hydrated".into()));
    }
    let is_symlink = lmeta.file_type().is_symlink();
    let symlink_target = if is_symlink { std::fs::read_link(path).ok() } else { None };
    if is_symlink {
        if let Ok(tmeta) = std::fs::metadata(path) {
            if cfg.skip_cloud_placeholders && cloud_placeholder(&tmeta) {
                return Ok(ReadOutcome::Skip("symlink to cloud placeholder; not hydrated".into()));
            }
            if !tmeta.is_file() {
                return Ok(ReadOutcome::Skip("symlink target is not a regular file".into()));
            }
        } else {
            return Ok(ReadOutcome::Skip("dangling symlink".into()));
        }
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Ok(ReadOutcome::Skip(format!("open failed: {e}"))),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(ReadOutcome::Skip("not a regular file".into()));
    }
    let mut bytes = Vec::with_capacity(meta.len().min(cfg.max_file_size) as usize);
    file.take(cfg.max_file_size + 1).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > cfg.max_file_size;
    if truncated {
        bytes.truncate(cfg.max_file_size as usize);
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (file_id, world_writable) = file_identity(&meta);
    Ok(ReadOutcome::Read(FileData {
        path: path.to_path_buf(),
        size: meta.len(),
        text,
        sha256,
        truncated,
        mtime,
        file_id,
        symlink_target,
        world_writable,
    }))
}

pub fn sha256_file(path: &Path, max: u64) -> Result<String> {
    let f = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    f.take(max).read_to_end(&mut bytes)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_names_case_insensitively() {
        let m = Matcher::new(&ScanConfig::default()).unwrap();
        assert!(m.is_candidate(Path::new("/x/agents.md")));
        assert!(m.is_candidate(Path::new("/x/Claude.MD")));
        assert!(m.is_candidate(Path::new("/x/.cursor/rules/a.mdc")));
        assert!(m.is_candidate(Path::new("C:\\proj\\.github\\instructions\\x.instructions.md")));
        assert!(!m.is_candidate(Path::new("/x/README.md")));
        assert!(!m.is_candidate(Path::new("/x/.git/AGENTS.md")));
    }
}
