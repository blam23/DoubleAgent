//! Context enricher: git provenance, dependency folders, parent/sibling
//! instruction files, symlinks and permissions.
//!
//! Git is run defensively: a cloned repo is attacker-controlled, and repo-local
//! config such as `core.fsmonitor` can execute programs. Every git call disables
//! fsmonitor, hooks and pagers, and only read-only plumbing commands are used.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::ProvenanceConfig;
use crate::model::Context;
use crate::scanner::{FileData, Matcher};

#[derive(Clone, Debug)]
struct GitRepo {
    root: PathBuf,
    remote: Option<String>,
}

pub struct Enricher<'a> {
    cfg: &'a ProvenanceConfig,
    matcher: &'a Matcher,
    git_ok: bool,
    repos: Mutex<HashMap<PathBuf, Option<GitRepo>>>,
    dir_listing: Mutex<HashMap<PathBuf, Vec<PathBuf>>>,
}

fn git_cmd(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=",
            "--no-pager",
        ])
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Never inherit our stdin: a host (like the language server) may be blocked reading it.
        .stdin(Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

fn run_git(dir: &Path, args: &[&str]) -> Option<(bool, String)> {
    let out = git_cmd(dir).args(args).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

/// Strip credentials from a remote URL before it is stored or reported.
fn sanitize_remote(u: &str) -> String {
    if let Some((scheme, rest)) = u.split_once("://") {
        if let Some((_, host)) = rest.split_once('@') {
            return format!("{scheme}://{host}");
        }
    }
    u.to_string()
}

impl<'a> Enricher<'a> {
    pub fn new(cfg: &'a ProvenanceConfig, matcher: &'a Matcher) -> Self {
        let git_ok = cfg.use_git
            && Command::new("git")
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        Self {
            cfg,
            matcher,
            git_ok,
            repos: Mutex::new(HashMap::new()),
            dir_listing: Mutex::new(HashMap::new()),
        }
    }

    fn find_git_root(start: &Path) -> Option<PathBuf> {
        let mut cur = Some(start);
        while let Some(d) = cur {
            if d.join(".git").exists() {
                return Some(d.to_path_buf());
            }
            cur = d.parent();
        }
        None
    }

    fn repo_for(&self, dir: &Path) -> Option<GitRepo> {
        let root = Self::find_git_root(dir)?;
        if let Some(r) = self.repos.lock().unwrap().get(&root) {
            return r.clone();
        }
        let remote = if self.git_ok {
            run_git(&root, &["config", "--get", "remote.origin.url"])
                .filter(|(ok, _)| *ok)
                .map(|(_, s)| sanitize_remote(&s))
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        let repo = Some(GitRepo {
            root: root.clone(),
            remote,
        });
        self.repos.lock().unwrap().insert(root, repo.clone());
        repo
    }

    /// Instruction files directly inside `dir` (cached).
    fn instruction_files_in(&self, dir: &Path) -> Vec<PathBuf> {
        if let Some(v) = self.dir_listing.lock().unwrap().get(dir) {
            return v.clone();
        }
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_file() || t.is_symlink()).unwrap_or(false))
                    .filter(|e| self.matcher.is_candidate_name(&e.file_name().to_string_lossy()))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        self.dir_listing.lock().unwrap().insert(dir.to_path_buf(), v.clone());
        v
    }

    pub fn enrich(&self, fd: &FileData) -> Context {
        let path = &fd.path;
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut ctx = Context::default();

        if let Some(repo) = self.repo_for(dir) {
            ctx.git_root = Some(repo.root.clone());
            ctx.git_remote = repo.remote.clone();
            if self.git_ok {
                if let Ok(rel) = path.strip_prefix(&repo.root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    ctx.git_tracked = run_git(&repo.root, &["ls-files", "--error-unmatch", "--", &rel]).map(|(ok, _)| ok);
                    if ctx.git_tracked == Some(true) {
                        ctx.last_commit = run_git(
                            &repo.root,
                            &["log", "-1", "--no-show-signature", "--format=%an <%ae> %cI %h", "--", &rel],
                        )
                        .filter(|(ok, s)| *ok && !s.is_empty())
                        .map(|(_, s)| s);
                    }
                }
            }
        }

        // Dependency / vendor trees and risky locations.
        let lower: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect();
        let deps: Vec<String> = self.cfg.dependency_dirs.iter().map(|d| d.to_lowercase()).collect();
        ctx.dependency_dir = lower.iter().find(|c| deps.contains(c)).cloned();
        if lower.iter().any(|c| c == "downloads") {
            ctx.location_hint = Some("downloads".into());
        } else if lower.iter().any(|c| c == "temp" || c == "tmp") {
            ctx.location_hint = Some("temp".into());
        }

        ctx.symlink_target = fd.symlink_target.clone();
        ctx.world_writable = fd.world_writable;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        ctx.recently_modified = fd.mtime > 0 && now - fd.mtime < (self.cfg.recent_hours as i64) * 3600;

        // Parent chain: instruction files in ancestor folders up to the git root
        // (or the filesystem root when the file isn't in a repo).
        let stop = ctx.git_root.clone();
        let mut cur = dir.parent();
        while let Some(d) = cur {
            for p in self.instruction_files_in(d) {
                ctx.parents.push(p);
            }
            if stop.as_deref() == Some(d) {
                break;
            }
            cur = d.parent();
        }
        ctx.siblings = self.instruction_files_in(dir).into_iter().filter(|p| p != path).collect();
        ctx
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_remote;
    #[test]
    fn strips_creds() {
        assert_eq!(sanitize_remote("https://user:tok@github.com/a/b.git"), "https://github.com/a/b.git");
        assert_eq!(sanitize_remote("git@github.com:a/b.git"), "git@github.com:a/b.git");
    }
}
