//! Shared data types: findings, context, verdicts and the per-file report.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config::Thresholds;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u32, t: &Thresholds) -> Severity {
        if score >= t.critical {
            Severity::Critical
        } else if score >= t.high {
            Severity::High
        } else if score >= t.medium {
            Severity::Medium
        } else if score >= t.low {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "none" | "clean" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::parse(s).ok_or_else(|| format!("unknown severity '{s}' (info, low, medium, high, critical)"))
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One deterministic rule hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    /// MITRE ATLAS technique IDs associated with the finding; empty when no direct mapping applies.
    #[serde(default)]
    pub atlas: Vec<String>,
    pub title: String,
    pub category: String,
    /// Contribution to the static score (0-100).
    pub weight: u32,
    pub severity: Severity,
    pub line: Option<usize>,
    pub column: Option<usize>,
    /// The offending text, with invisible characters escaped as <U+XXXX>.
    pub excerpt: String,
    pub reason: String,
}

/// Provenance signals gathered by the context enricher.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub git_root: Option<PathBuf>,
    pub git_remote: Option<String>,
    /// None = not in a git repo, or git unavailable.
    pub git_tracked: Option<bool>,
    pub last_commit: Option<String>,
    pub dependency_dir: Option<String>,
    pub location_hint: Option<String>,
    pub symlink_target: Option<PathBuf>,
    pub world_writable: bool,
    pub recently_modified: bool,
    /// Instruction files in ancestor folders that this file overrides (nearest first).
    pub parents: Vec<PathBuf>,
    /// Instruction files in the same folder (e.g. AGENTS.md next to AGENTS.override.md).
    pub siblings: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scores {
    /// Static analyzer score.
    pub content: u32,
    pub provenance: u32,
    pub shadow: u32,
    pub final_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub truncated: bool,
    pub scanned_at: String,
    pub severity: Severity,
    pub scores: Scores,
    pub findings: Vec<Finding>,
    pub provenance_reasons: Vec<String>,
    pub shadow_reasons: Vec<String>,
    pub context: Context,
    /// allowed / pinned / pin-mismatch / quarantined
    pub disposition: Option<String>,
    /// Hidden from default output by an allow rule or hash pin.
    pub suppressed: bool,
    pub changed_since_last_scan: bool,
    pub actions: Vec<String>,
}
