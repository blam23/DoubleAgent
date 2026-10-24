//! Configuration: loaded from TOML, every field has a safe default.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::model::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub scan: ScanConfig,
    pub analyzer: AnalyzerConfig,
    pub provenance: ProvenanceConfig,
    pub scoring: ScoringConfig,
    pub policy: PolicyConfig,
    pub watch: WatchConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Roots to scan when none are given on the command line. Empty = home folder.
    pub roots: Vec<PathBuf>,
    /// Exact file names (case-insensitive) treated as agent instruction files.
    pub filenames: Vec<String>,
    /// Glob patterns (matched against the full path, `/` separators) for
    /// instruction files that live in well-known folders.
    pub patterns: Vec<String>,
    /// Directory names never descended into (case-insensitive).
    pub exclude_dirs: Vec<String>,
    /// Glob patterns for paths to skip entirely.
    pub exclude_globs: Vec<String>,
    /// Bytes read per file. Larger files are analyzed up to this cap and flagged.
    pub max_file_size: u64,
    /// Follow symlinks / junctions while walking. Off by default (loop safety).
    pub follow_symlinks: bool,
    /// Skip network filesystems (NFS, SMB, sshfs, WSL drvfs).
    pub skip_network_mounts: bool,
    /// Skip cloud placeholder files (OneDrive "online-only") so they are never hydrated.
    pub skip_cloud_placeholders: bool,
    /// Walker threads. 0 = automatic.
    pub threads: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: vec![],
            filenames: [
                "AGENTS.md",
                "AGENTS.override.md",
                "AGENT.md",
                "CLAUDE.md",
                "CLAUDE.local.md",
                "GEMINI.md",
                ".cursorrules",
                ".windsurfrules",
                ".clinerules",
                ".goosehints",
                "copilot-instructions.md",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            patterns: [
                "**/.cursor/rules/*.mdc",
                "**/.cursor/rules/*.md",
                "**/.clinerules/*.md",
                "**/.windsurf/rules/*.md",
                "**/.github/instructions/*.instructions.md",
                "**/.github/prompts/*.prompt.md",
                "**/.claude/commands/*.md",
                "**/.claude/agents/*.md",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            exclude_dirs: [
                ".git",
                "$recycle.bin",
                "system volume information",
                ".trash",
                ".cache",
                "target",
                ".doubleagent-quarantine",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            exclude_globs: vec![],
            max_file_size: 256 * 1024,
            follow_symlinks: false,
            skip_network_mounts: true,
            skip_cloud_placeholders: true,
            threads: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalyzerConfig {
    /// Domains (and their subdomains) that do not raise "unknown domain" findings.
    pub trusted_domains: Vec<String>,
    /// Minimum length of a base64-looking run before it is decoded and inspected.
    pub base64_min_len: usize,
    /// Rule IDs to switch off, e.g. ["URL001"].
    pub disabled_rules: Vec<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            trusted_domains: [
                "github.com",
                "githubusercontent.com",
                "gitlab.com",
                "bitbucket.org",
                "docs.rs",
                "crates.io",
                "rust-lang.org",
                "npmjs.com",
                "pypi.org",
                "python.org",
                "go.dev",
                "golang.org",
                "nodejs.org",
                "mozilla.org",
                "microsoft.com",
                "apple.com",
                "google.com",
                "anthropic.com",
                "openai.com",
                "stackoverflow.com",
                "wikipedia.org",
                "readthedocs.io",
                "example.com",
                "localhost",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            base64_min_len: 120,
            disabled_rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProvenanceConfig {
    /// Path components that mark a dependency / vendored tree.
    pub dependency_dirs: Vec<String>,
    /// Git remotes you trust (substring match). Empty = don't score remotes.
    pub trusted_remotes: Vec<String>,
    /// A file modified within this many hours counts as "recently appeared".
    pub recent_hours: u64,
    /// Use the `git` executable for tracked / last-commit information.
    pub use_git: bool,
}

impl Default for ProvenanceConfig {
    fn default() -> Self {
        Self {
            dependency_dirs: [
                "node_modules",
                "bower_components",
                ".pnpm-store",
                ".yarn",
                ".venv",
                "venv",
                "site-packages",
                "dist-packages",
                "__pypackages__",
                ".tox",
                ".nox",
                "vendor",
                "third_party",
                "third-party",
                ".cargo",
                ".rustup",
                ".gradle",
                ".m2",
                "pods",
                "elm-stuff",
                ".nuget",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            trusted_remotes: vec![],
            recent_hours: 24,
            use_git: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScoreKind {
    Provenance,
    Shadow,
}

/// One provenance or shadow rule. Built-ins live in `src/rules/scoring.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoringRule {
    pub id: String,
    /// Which score the points go to.
    pub score: ScoreKind,
    /// Added when `when` is true. Negative points lower the score (never below 0).
    pub points: i32,
    /// Condition, e.g. `in_git && untracked`. `doubleagent config rules` lists the names.
    pub when: String,
    /// Shown in reports. `{fact}` placeholders are filled in.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringConfig {
    /// Built-in (or config) scoring rule IDs to switch off, e.g. ["PROV004"].
    pub disabled_rules: Vec<String>,
    /// Extra rules. A rule with the same `id` as a built-in replaces it.
    pub rules: Vec<ScoringRule>,
    pub combine: CombineConfig,
}

/// final = max(content, provenance * provenance_pct%, shadow * shadow_pct%) + amplification, capped at 100.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CombineConfig {
    /// How much of the provenance score counts on its own (percent).
    pub provenance_pct: u32,
    /// How much of the shadow score counts on its own (percent).
    pub shadow_pct: u32,
    /// Provenance and shadow amplify the content score only when it is at least this.
    pub amplify_min_content: u32,
    /// Amplification = (provenance + shadow) * amplify_pct%, at most amplify_cap.
    pub amplify_pct: u32,
    pub amplify_cap: u32,
}

impl Default for CombineConfig {
    fn default() -> Self {
        Self {
            provenance_pct: 50,
            shadow_pct: 60,
            amplify_min_content: 20,
            amplify_pct: 25,
            amplify_cap: 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            low: 20,
            medium: 40,
            high: 65,
            critical: 85,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct PolicyConfig {
    pub thresholds: Thresholds,
    /// Show an OS notification at or above this severity. Unset = never.
    pub notify_at: Option<Severity>,
    /// Run `hook_command` (report JSON on stdin) at or above this severity.
    pub hook_at: Option<Severity>,
    pub hook_command: Vec<String>,
    /// Move files to the quarantine folder at or above this severity.
    /// Unset (the default) = report-only. Files are never deleted.
    pub quarantine_at: Option<Severity>,
    pub quarantine_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchConfig {
    pub debounce_ms: u64,
    /// Full reconcile scan interval (catches dropped watcher events).
    pub reconcile_minutes: u64,
    /// Use polling instead of native events.
    pub force_polling: bool,
    pub poll_interval_secs: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 1500,
            reconcile_minutes: 15,
            force_polling: false,
            poll_interval_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    /// Append every report to this JSON Lines file (scan and watch).
    pub jsonl_path: Option<PathBuf>,
    /// POST reports at or above `webhook_min_severity` to this URL.
    pub webhook_url: Option<String>,
    pub webhook_min_severity: Severity,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            jsonl_path: None,
            webhook_url: None,
            webhook_min_severity: Severity::High,
        }
    }
}

pub fn app_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("DoubleAgent")
}

pub fn default_config_path() -> PathBuf {
    dirs::config_dir().unwrap_or_else(app_dir).join("DoubleAgent").join("config.toml")
}

pub fn default_db_path() -> PathBuf {
    app_dir().join("state.db")
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<(Config, PathBuf)> {
        let p = path.map(Path::to_path_buf).unwrap_or_else(default_config_path);
        if !p.exists() {
            if path.is_some() {
                bail!("config file not found: {}", p.display());
            }
            return Ok((Config::default(), p));
        }
        let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let table: toml::Table = toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
        let cfg: Config = table.try_into().with_context(|| format!("parsing {}", p.display()))?;
        cfg.validate()?;
        Ok((cfg, p))
    }

    pub fn validate(&self) -> Result<()> {
        let t = &self.policy.thresholds;
        if !(t.low < t.medium && t.medium < t.high && t.high < t.critical && t.critical <= 100) {
            bail!("policy.thresholds must be strictly increasing and <= 100");
        }
        let c = &self.scoring.combine;
        if c.provenance_pct > 100 || c.shadow_pct > 100 || c.amplify_pct > 100 {
            bail!("scoring.combine percentages must be <= 100");
        }
        crate::score::RuleSet::new(&self.scoring)?;
        Ok(())
    }

    pub fn default_toml() -> String {
        let body = toml::to_string_pretty(&Config::default()).unwrap_or_default();
        format!("# DoubleAgent configuration. Every value shown is the default.\n\n{body}")
    }
}
