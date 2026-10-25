//! Scoring model: content, provenance and shadow risk combine into a final score.
//!
//! Provenance and shadow scores come from declarative rules (built-ins in
//! `rules/scoring.toml`, plus `[scoring]` in the config). Each rule's condition
//! is an [`Expr`] over the [`Facts`] gathered for a file.

use anyhow::{anyhow, bail, Context as _, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::config::{CombineConfig, ProvenanceConfig, ScoreKind, ScoringConfig, ScoringRule};
use crate::expr::{Env, Expr, Ty, Value};
use crate::model::{Context, Finding};

const BUILTIN: &str = include_str!("rules/scoring.toml");

/// Every name a rule condition or reason can use: (name, type, meaning).
pub const FACTS: &[(&str, Ty, &str)] = &[
    ("in_git", Ty::Bool, "inside a git working tree"),
    ("tracked", Ty::Bool, "tracked by git"),
    ("untracked", Ty::Bool, "inside a git repo but not tracked"),
    ("has_remote", Ty::Bool, "the repo has an origin remote"),
    ("remote", Ty::Str, "origin remote URL (empty if none)"),
    (
        "remote_untrusted",
        Ty::Bool,
        "provenance.trusted_remotes is set and the remote matches none of it",
    ),
    ("in_dependency_dir", Ty::Bool, "inside a dependency/vendor folder"),
    ("dependency_dir", Ty::Str, "name of that folder, e.g. node_modules (empty if none)"),
    ("location", Ty::Str, "\"downloads\", \"temp\" or empty"),
    ("is_symlink", Ty::Bool, "the file is a symlink"),
    ("symlink_target", Ty::Str, "where the symlink points (empty if not a symlink)"),
    ("world_writable", Ty::Bool, "anyone can write the file"),
    ("recently_modified", Ty::Bool, "modified within provenance.recent_hours"),
    ("recent_hours", Ty::Int, "provenance.recent_hours"),
    ("untrusted_location", Ty::Bool, "in a dependency folder, untracked, or outside git"),
    ("pin_mismatch", Ty::Bool, "hash-pinned, but the content no longer matches"),
    ("changed", Ty::Bool, "content changed since the last scan"),
    ("changes_7d", Ty::Int, "distinct content revisions observed in the last 7 days"),
    ("file_name", Ty::Str, "file name, e.g. AGENTS.override.md"),
    ("is_override_file", Ty::Bool, "file name contains \"override\""),
    ("has_siblings", Ty::Bool, "other instruction files in the same folder"),
    ("has_parent", Ty::Bool, "overrides an instruction file in a parent folder"),
    ("parent", Ty::Str, "nearest parent instruction file (empty if none)"),
    (
        "parent_content",
        Ty::Int,
        "highest static content score among the parents (0 if none)",
    ),
    ("has_trusted_parent", Ty::Bool, "a parent is git-tracked or hash-pinned"),
    ("trusted_parent", Ty::Str, "nearest trusted parent (empty if none)"),
    ("shadows", Ty::Bool, "has_parent, or an override file next to a sibling"),
    ("content", Ty::Int, "static content score of this file"),
];

pub const FUNCTIONS: &[(&str, &str)] = &[
    (
        "finding(\"ID\", ...)",
        "a static finding with any of these rule IDs fired (TAG:/B64: prefixes ignored)",
    ),
    ("contains(text, \"needle\")", "case-insensitive substring test"),
    ("matches(text, \"regex\")", "regular expression test"),
];

fn fact_type(name: &str) -> Option<Ty> {
    FACTS.iter().find(|(n, _, _)| *n == name).map(|(_, t, _)| *t)
}

pub struct ParentInfo {
    pub path: String,
    pub content_score: u32,
    pub trusted: bool,
}

/// What is known about one file when its provenance and shadow rules run.
pub struct Subject<'a> {
    pub ctx: &'a Context,
    pub cfg: &'a ProvenanceConfig,
    pub file_name: &'a str,
    pub content: u32,
    pub findings: &'a [Finding],
    /// Parent instruction files, nearest first.
    pub parents: &'a [&'a ParentInfo],
    pub pin_mismatch: bool,
    /// Changed since a previous scan (false on first sight).
    pub changed: bool,
    /// Distinct content revisions observed in the previous seven days, including this scan's change.
    pub changes_7d: u32,
}

pub struct Facts {
    values: BTreeMap<&'static str, Value>,
    findings: HashSet<String>,
}

impl Facts {
    pub fn new(s: &Subject) -> Facts {
        let ctx = s.ctx;
        let in_git = ctx.git_root.is_some();
        let untracked = ctx.git_tracked == Some(false);
        let untrusted_location = ctx.dependency_dir.is_some() || untracked || !in_git;
        let remote_untrusted = match &ctx.git_remote {
            Some(r) => !s.cfg.trusted_remotes.is_empty() && !s.cfg.trusted_remotes.iter().any(|t| r.contains(t.as_str())),
            None => false,
        };
        let is_override_file = s.file_name.to_lowercase().contains("override");
        let has_siblings = !ctx.siblings.is_empty();
        let trusted_parent = s.parents.iter().find(|p| p.trusted);
        let text = |v: Option<String>| Value::Str(v.unwrap_or_default());
        let values = BTreeMap::from([
            ("in_git", Value::Bool(in_git)),
            ("tracked", Value::Bool(ctx.git_tracked == Some(true))),
            ("untracked", Value::Bool(untracked)),
            ("has_remote", Value::Bool(ctx.git_remote.is_some())),
            ("remote", text(ctx.git_remote.clone())),
            ("remote_untrusted", Value::Bool(remote_untrusted)),
            ("in_dependency_dir", Value::Bool(ctx.dependency_dir.is_some())),
            ("dependency_dir", text(ctx.dependency_dir.clone())),
            ("location", text(ctx.location_hint.clone())),
            ("is_symlink", Value::Bool(ctx.symlink_target.is_some())),
            ("symlink_target", text(ctx.symlink_target.as_ref().map(|t| t.display().to_string()))),
            ("world_writable", Value::Bool(ctx.world_writable)),
            ("recently_modified", Value::Bool(ctx.recently_modified)),
            ("recent_hours", Value::Int(s.cfg.recent_hours as i64)),
            ("untrusted_location", Value::Bool(untrusted_location)),
            ("pin_mismatch", Value::Bool(s.pin_mismatch)),
            ("changed", Value::Bool(s.changed)),
            ("changes_7d", Value::Int(s.changes_7d as i64)),
            ("file_name", Value::Str(s.file_name.to_string())),
            ("is_override_file", Value::Bool(is_override_file)),
            ("has_siblings", Value::Bool(has_siblings)),
            ("has_parent", Value::Bool(!s.parents.is_empty())),
            ("parent", text(s.parents.first().map(|p| p.path.clone()))),
            (
                "parent_content",
                Value::Int(s.parents.iter().map(|p| p.content_score).max().unwrap_or(0) as i64),
            ),
            ("has_trusted_parent", Value::Bool(trusted_parent.is_some())),
            ("trusted_parent", text(trusted_parent.map(|p| p.path.clone()))),
            ("shadows", Value::Bool(!s.parents.is_empty() || (is_override_file && has_siblings))),
            ("content", Value::Int(s.content as i64)),
        ]);
        let findings = s
            .findings
            .iter()
            .map(|f| f.rule_id.rsplit(':').next().unwrap_or("").to_ascii_uppercase())
            .collect();
        Facts { values, findings }
    }
}

impl Env for Facts {
    fn get(&self, name: &str) -> Option<Value> {
        self.values.get(name).cloned()
    }
    fn has_finding(&self, id: &str) -> bool {
        self.findings.contains(id)
    }
}

/// A reason string with `{fact}` placeholders, checked at compile time.
struct Template(Vec<Piece>);

enum Piece {
    Text(String),
    Fact(String),
}

impl Template {
    fn compile(src: &str) -> Result<Template> {
        let mut pieces = Vec::new();
        let mut rest = src;
        while let Some(open) = rest.find('{') {
            let close = rest[open..].find('}').ok_or_else(|| anyhow!("unclosed `{{` in reason"))? + open;
            let name = rest[open + 1..close].trim();
            if fact_type(name).is_none() {
                bail!("unknown placeholder {{{name}}} in reason");
            }
            pieces.push(Piece::Text(rest[..open].to_string()));
            pieces.push(Piece::Fact(name.to_string()));
            rest = &rest[close + 1..];
        }
        pieces.push(Piece::Text(rest.to_string()));
        Ok(Template(pieces))
    }

    fn render(&self, f: &Facts) -> String {
        self.0
            .iter()
            .map(|p| match p {
                Piece::Text(t) => t.clone(),
                Piece::Fact(name) => f.get(name).map(|v| v.to_string()).unwrap_or_default(),
            })
            .collect()
    }
}

struct Compiled {
    id: String,
    atlas: Vec<String>,
    kind: ScoreKind,
    points: i32,
    when: Expr,
    reason: Template,
}

pub struct Scored {
    pub score: u32,
    pub reasons: Vec<String>,
}

pub struct RuleSet {
    rules: Vec<Compiled>,
    combine: CombineConfig,
}

#[derive(Deserialize, Serialize)]
struct RuleFile {
    rules: Vec<ScoringRule>,
}

pub fn builtin_rules() -> Vec<ScoringRule> {
    toml::from_str::<RuleFile>(BUILTIN)
        .expect("built-in rules/scoring.toml is valid")
        .rules
}

/// Built-ins, with config rules replacing same-ID built-ins in place or appended, minus disabled ones.
pub fn effective_rules(cfg: &ScoringConfig) -> Result<Vec<ScoringRule>> {
    let mut rules = builtin_rules();
    let mut seen = HashSet::new();
    for r in &cfg.rules {
        let id = r.id.trim().to_ascii_uppercase();
        if id.is_empty() {
            bail!("scoring.rules: every rule needs an `id`");
        }
        if !seen.insert(id.clone()) {
            bail!("scoring.rules: rule {id} is defined twice");
        }
        let r = ScoringRule {
            id: id.clone(),
            ..r.clone()
        };
        match rules.iter_mut().find(|b| b.id == id) {
            Some(b) => {
                let r = ScoringRule {
                    atlas: if r.atlas.is_empty() { b.atlas.clone() } else { r.atlas },
                    ..r
                };
                *b = r;
            }
            None => rules.push(r),
        }
    }
    for d in &cfg.disabled_rules {
        let d = d.trim().to_ascii_uppercase();
        if !rules.iter().any(|r| r.id == d) {
            bail!("scoring.disabled_rules: unknown rule {d} (static analyzer rules go in analyzer.disabled_rules)");
        }
        rules.retain(|r| r.id != d);
    }
    Ok(rules)
}

impl RuleSet {
    pub fn new(cfg: &ScoringConfig) -> Result<RuleSet> {
        let rules = effective_rules(cfg)?
            .into_iter()
            .map(|r| {
                for id in &r.atlas {
                    if !crate::atlas::is_known_technique(id) {
                        bail!("scoring rule {}: unknown MITRE ATLAS technique {id}", r.id);
                    }
                }
                let when = Expr::compile(&r.when, &fact_type).with_context(|| format!("scoring rule {}: bad `when`", r.id))?;
                let reason = Template::compile(&r.reason).with_context(|| format!("scoring rule {}", r.id))?;
                Ok(Compiled {
                    id: r.id,
                    atlas: r.atlas,
                    kind: r.score,
                    points: r.points,
                    when,
                    reason,
                })
            })
            .collect::<Result<_>>()?;
        Ok(RuleSet {
            rules,
            combine: cfg.combine.clone(),
        })
    }

    /// Run every rule: (provenance, shadow).
    pub fn evaluate(&self, f: &Facts) -> (Scored, Scored) {
        let run = |kind: ScoreKind| {
            let mut total = 0i32;
            let mut reasons = Vec::new();
            for r in self.rules.iter().filter(|r| r.kind == kind && r.when.eval(f)) {
                total = total.saturating_add(r.points);
                let atlas = if r.atlas.is_empty() {
                    String::new()
                } else {
                    format!(" (ATLAS {})", r.atlas.join(", "))
                };
                reasons.push(format!("{:+} {} [{}]{atlas}", r.points, r.reason.render(f), r.id));
            }
            Scored {
                score: total.clamp(0, 100) as u32,
                reasons,
            }
        };
        (run(ScoreKind::Provenance), run(ScoreKind::Shadow))
    }

    /// Combine. With the default weights, provenance or shadow alone tops out at medium;
    /// they amplify real content risk.
    pub fn combine(&self, content: u32, provenance: u32, shadow: u32) -> u32 {
        let c = &self.combine;
        let prov_c = provenance * c.provenance_pct / 100;
        let shadow_c = shadow * c.shadow_pct / 100;
        let amp = if content >= c.amplify_min_content {
            ((provenance + shadow) * c.amplify_pct / 100).min(c.amplify_cap)
        } else {
            0
        };
        (content.max(prov_c).max(shadow_c) + amp).min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn defaults() -> RuleSet {
        RuleSet::new(&ScoringConfig::default()).unwrap()
    }

    fn eval_with(rs: &RuleSet, ctx: &Context, name: &str, content: u32, parents: &[&ParentInfo]) -> (Scored, Scored) {
        let cfg = ProvenanceConfig::default();
        rs.evaluate(&Facts::new(&Subject {
            ctx,
            cfg: &cfg,
            file_name: name,
            content,
            findings: &[],
            parents,
            pin_mismatch: false,
            changed: false,
            changes_7d: 0,
        }))
    }

    #[test]
    fn combine_rules() {
        let rs = defaults();
        assert_eq!(rs.combine(0, 0, 0), 0);
        assert_eq!(rs.combine(0, 60, 0), 30); // clean file in node_modules → low
        assert_eq!(rs.combine(70, 60, 0), 85); // malicious + bad provenance → critical
        assert_eq!(rs.combine(90, 100, 100), 100);
    }

    #[test]
    fn builtins_compile_and_facts_match_schema() {
        assert!(!builtin_rules().is_empty());
        defaults();
        let cfg = ProvenanceConfig::default();
        let f = Facts::new(&Subject {
            ctx: &Context::default(),
            cfg: &cfg,
            file_name: "AGENTS.md",
            content: 0,
            findings: &[],
            parents: &[],
            pin_mismatch: false,
            changed: false,
            changes_7d: 0,
        });
        let names: Vec<&str> = FACTS.iter().map(|(n, _, _)| *n).collect();
        let mut keys: Vec<&str> = f.values.keys().copied().collect();
        let mut sorted = names.clone();
        sorted.sort();
        keys.sort();
        assert_eq!(keys, sorted, "Facts::new and FACTS are out of sync");
        for (n, t, _) in FACTS {
            let v = f.get(n).unwrap();
            assert_eq!(fact_type(n), Some(*t));
            assert!(
                matches!(
                    (t, v),
                    (Ty::Bool, Value::Bool(_)) | (Ty::Int, Value::Int(_)) | (Ty::Str, Value::Str(_))
                ),
                "{n}"
            );
        }
    }

    #[test]
    fn dependency_file() {
        let ctx = Context {
            git_root: Some(PathBuf::from("/r")),
            git_remote: Some("https://github.com/a/b".into()),
            git_tracked: Some(false),
            dependency_dir: Some("node_modules".into()),
            ..Default::default()
        };
        let (p, s) = eval_with(&defaults(), &ctx, "CLAUDE.md", 0, &[]);
        assert_eq!(p.score, 15);
        assert_eq!(p.reasons, ["+15 inside a dependency/vendor folder (node_modules) [PROV001]"]);
        assert_eq!(s.score, 0);
    }

    #[test]
    fn shadowing_untrusted_file() {
        let ctx = Context {
            git_root: Some(PathBuf::from("/r")),
            git_remote: Some("x".into()),
            git_tracked: Some(false),
            ..Default::default()
        };
        let parent = ParentInfo {
            path: "/r/AGENTS.md".into(),
            content_score: 5,
            trusted: true,
        };
        let (_, s) = eval_with(&defaults(), &ctx, "AGENTS.md", 60, &[&parent]);
        assert_eq!(s.score, 55);
        assert_eq!(s.reasons[2], "+20 much riskier than its parent(s) (content 60 vs 5) [SHAD005]");
    }

    #[test]
    fn repeated_recent_content_changes_raise_provenance() {
        let rs = defaults();
        let cfg = ProvenanceConfig::default();
        let ctx = Context::default();
        let facts = Facts::new(&Subject {
            ctx: &ctx,
            cfg: &cfg,
            file_name: "AGENTS.md",
            content: 0,
            findings: &[],
            parents: &[],
            pin_mismatch: false,
            changed: false,
            changes_7d: 3,
        });
        let (p, _) = rs.evaluate(&facts);
        assert!(p.reasons.iter().any(|r| r.contains("[PROV014]")));
    }

    #[test]
    fn config_overrides_disables_and_adds() {
        let cfg: ScoringConfig = toml::from_str(
            r#"
            disabled_rules = ["prov003"]
            [[rules]]
            id = "PROV001"
            score = "provenance"
            points = 50
            when = "in_dependency_dir"
            reason = "vendored"
            [[rules]]
            id = "LOCAL001"
            score = "provenance"
            points = -20
            when = "contains(remote, \"github.com/myorg/\")"
            reason = "our org"
            [[rules]]
            id = "SHAD003"
            score = "shadow"
            points = 1
            when = "false"
            reason = "override"
            "#,
        )
        .unwrap();
        let rs = RuleSet::new(&cfg).unwrap();
        let inherited = effective_rules(&cfg).unwrap().into_iter().find(|r| r.id == "SHAD003").unwrap();
        assert_eq!(inherited.atlas, ["AML.T0051.001"]);
        let ctx = Context {
            dependency_dir: Some("vendor".into()),
            git_remote: Some("https://GitHub.com/MyOrg/x".into()),
            ..Default::default()
        };
        let (p, _) = eval_with(&rs, &ctx, "AGENTS.md", 0, &[]);
        assert_eq!(p.reasons, ["+50 vendored [PROV001]", "-20 our org [LOCAL001]"]);
        assert_eq!(p.score, 30);
    }

    #[test]
    fn config_errors_name_the_rule() {
        let bad = |toml_src: &str| {
            let cfg: ScoringConfig = toml::from_str(toml_src).unwrap();
            format!("{:#}", RuleSet::new(&cfg).err().unwrap())
        };
        let rule = |when: &str, reason: &str| {
            format!("[[rules]]\nid = \"X1\"\nscore = \"shadow\"\npoints = 5\nwhen = '{when}'\nreason = '{reason}'\n")
        };
        assert!(bad(&rule("in_gti", "r")).contains("X1: bad `when`: unknown name `in_gti`"));
        assert!(bad(&rule("in_git", "{nope}")).contains("unknown placeholder {nope}"));
        assert!(bad("disabled_rules = [\"PI001\"]").contains("analyzer.disabled_rules"));
    }
}
