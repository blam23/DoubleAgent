//! Pipeline: read → static analysis → enrichment → allow rules → provenance /
//! shadow scoring → policy → store.

use anyhow::Result;
use globset::GlobSet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyzer::{Analyzer, StaticResult};
use crate::config::Config;
use crate::enrich::Enricher;
use crate::model::{Context, Report, Scores, Severity};
use crate::scanner::{self, glob_set, slash_path, FileData, Matcher, ReadOutcome, Skipped};
use crate::score::{self, Facts, ParentInfo, RuleSet, Subject};
use crate::store::{self, AllowRule, Store};
use crate::{output, policy};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub apply_actions: bool,
    /// Skip files whose size/mtime/file-id match the store (reconcile mode).
    pub skip_unchanged: bool,
}

#[derive(Default)]
pub struct Outcome {
    pub reports: Vec<Report>,
    pub skipped: Vec<Skipped>,
    pub unchanged: usize,
    pub notes: Vec<String>,
}

struct Analyzed {
    fd: FileData,
    stat: StaticResult,
    ctx: Context,
}

struct Allow {
    rules: Vec<AllowRule>,
    path_sets: Vec<(i64, GlobSet)>,
}

impl Allow {
    fn load(store: &Store) -> Result<Allow> {
        let rules = store.list_allow()?;
        let mut path_sets = Vec::new();
        for r in rules.iter().filter(|r| r.kind == "path") {
            if let Ok(gs) = glob_set(std::slice::from_ref(&r.pattern)) {
                path_sets.push((r.id, gs));
            }
        }
        Ok(Allow { rules, path_sets })
    }

    fn pin(&self, path: &Path) -> Option<&AllowRule> {
        let p = path.to_string_lossy();
        self.rules
            .iter()
            .find(|r| r.kind == "pin" && (r.pattern == p || (cfg!(windows) && r.pattern.eq_ignore_ascii_case(&p))))
    }

    fn allowed_by(&self, path: &Path, ctx: &Context) -> Option<String> {
        let sp = slash_path(path);
        for (id, gs) in &self.path_sets {
            if gs.is_match(&sp) {
                return Some(format!("allowed by path rule #{id}"));
            }
        }
        if let Some(remote) = &ctx.git_remote {
            for r in self.rules.iter().filter(|r| r.kind == "remote") {
                if remote.contains(&r.pattern) {
                    return Some(format!("allowed by remote rule #{}", r.id));
                }
            }
        }
        None
    }
}

pub struct Engine<'a> {
    pub cfg: &'a Config,
    pub store: &'a Store,
    pub matcher: &'a Matcher,
    analyzer: Analyzer,
    rules: RuleSet,
    pub opts: RunOptions,
}

impl<'a> Engine<'a> {
    pub fn new(cfg: &'a Config, store: &'a Store, matcher: &'a Matcher, opts: RunOptions) -> Result<Self> {
        Ok(Self {
            cfg,
            store,
            matcher,
            analyzer: Analyzer::new(&cfg.analyzer, &cfg.policy.thresholds),
            rules: RuleSet::new(&cfg.scoring)?,
            opts,
        })
    }

    pub fn process(&self, paths: Vec<PathBuf>) -> Result<Outcome> {
        self.run(paths, self.opts.skip_unchanged)
    }

    /// Process files a watcher reported as changed. Never takes the size/mtime fast
    /// path: a same-size rewrite with its mtime restored would look unchanged.
    pub fn process_changed(&self, paths: Vec<PathBuf>) -> Result<Outcome> {
        self.run(paths, false)
    }

    fn run(&self, paths: Vec<PathBuf>, skip_unchanged: bool) -> Result<Outcome> {
        let mut out = Outcome::default();
        let enricher = Enricher::new(&self.cfg.provenance, self.matcher);
        let allow = Allow::load(self.store)?;

        // 0. Reconcile fast path.
        let mut todo = Vec::new();
        for p in paths {
            if skip_unchanged {
                if let (Some((size, mtime, fid)), Some(row)) = (scanner::quick_stat(&p), self.store.get_file(&p)?) {
                    if row.size == size && row.mtime == mtime && row.file_id == fid {
                        out.unchanged += 1;
                        continue;
                    }
                }
            }
            todo.push(p);
        }

        // 1. Read, analyze and enrich in parallel.
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16);
        let chunk = todo.len().div_ceil(workers).max(1);
        let mut analyzed: Vec<Analyzed> = Vec::new();
        let scan_cfg = &self.cfg.scan;
        let analyzer = &self.analyzer;
        std::thread::scope(|s| {
            let handles: Vec<_> = todo
                .chunks(chunk)
                .map(|ch| {
                    let enricher = &enricher;
                    s.spawn(move || {
                        let mut a = Vec::new();
                        let mut sk = Vec::new();
                        for p in ch {
                            match scanner::read_candidate(p, scan_cfg) {
                                Ok(ReadOutcome::Read(fd)) => {
                                    let stat = analyzer.analyze(&fd.text);
                                    let ctx = enricher.enrich(&fd);
                                    a.push(Analyzed { fd, stat, ctx });
                                }
                                Ok(ReadOutcome::Skip(reason)) => sk.push(Skipped { path: p.clone(), reason }),
                                Err(e) => sk.push(Skipped {
                                    path: p.clone(),
                                    reason: e.to_string(),
                                }),
                            }
                        }
                        (a, sk)
                    })
                })
                .collect();
            for h in handles {
                if let Ok((a, sk)) = h.join() {
                    analyzed.extend(a);
                    out.skipped.extend(sk);
                }
            }
        });
        analyzed.sort_by(|a, b| a.fd.path.cmp(&b.fd.path));

        // 2. Parent information for shadow scoring.
        let mut parent_cache: HashMap<PathBuf, ParentInfo> = HashMap::new();
        for a in &analyzed {
            let trusted = a.ctx.git_tracked == Some(true)
                || allow
                    .pin(&a.fd.path)
                    .map(|p| p.sha256.as_deref() == Some(&a.fd.sha256))
                    .unwrap_or(false);
            parent_cache.insert(
                a.fd.path.clone(),
                ParentInfo {
                    path: a.fd.path.display().to_string(),
                    content_score: a.stat.score,
                    trusted,
                },
            );
        }
        let needed: Vec<PathBuf> = analyzed
            .iter()
            .flat_map(|a| a.ctx.parents.iter().cloned())
            .filter(|p| !parent_cache.contains_key(p))
            .collect();
        for p in needed {
            if parent_cache.contains_key(&p) {
                continue;
            }
            if let Ok(ReadOutcome::Read(fd)) = scanner::read_candidate(&p, &self.cfg.scan) {
                let st = self.analyzer.analyze(&fd.text);
                let ctx = enricher.enrich(&fd);
                let trusted =
                    ctx.git_tracked == Some(true) || allow.pin(&p).map(|r| r.sha256.as_deref() == Some(&fd.sha256)).unwrap_or(false);
                parent_cache.insert(
                    p.clone(),
                    ParentInfo {
                        path: p.display().to_string(),
                        content_score: st.score,
                        trusted,
                    },
                );
            }
        }

        // 3. Per-file provenance and shadow scoring.
        struct Pre {
            prov: score::Scored,
            shadow: score::Scored,
            disposition: Option<String>,
            pinned_ok: bool,
            allowed: bool,
            changed: bool,
            first_seen_now: bool,
        }
        let mut pre = Vec::new();
        for a in &analyzed {
            let row = self.store.get_file(&a.fd.path)?;
            let changed = row.as_ref().map(|r| r.sha256 != a.fd.sha256).unwrap_or(true);
            let pin = allow.pin(&a.fd.path);
            let pinned_ok = pin.map(|p| p.sha256.as_deref() == Some(&a.fd.sha256)).unwrap_or(false);
            let pin_mismatch = pin.is_some() && !pinned_ok;
            let mut disposition = None;
            let mut allowed = false;
            if pinned_ok {
                disposition = Some("pinned".to_string());
            } else if pin_mismatch {
                disposition = Some("pin-mismatch: changed since pinned, re-review required".to_string());
            } else if let Some(why) = allow.allowed_by(&a.fd.path, &a.ctx) {
                disposition = Some(why);
                allowed = true;
            }
            let parents: Vec<&ParentInfo> = a.ctx.parents.iter().filter_map(|p| parent_cache.get(p)).collect();
            let name = a.fd.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (prov, shadow) = self.rules.evaluate(&Facts::new(&Subject {
                ctx: &a.ctx,
                cfg: &self.cfg.provenance,
                file_name: &name,
                content: a.stat.score,
                findings: &a.stat.findings,
                parents: &parents,
                pin_mismatch,
                changed: changed && row.is_some(),
            }));
            pre.push(Pre {
                prov,
                shadow,
                disposition,
                pinned_ok,
                allowed,
                changed,
                first_seen_now: row.is_none(),
            });
        }

        // 4. Final scoring, policy, persistence.
        let t = &self.cfg.policy.thresholds;
        let ts = store::now();
        let mut webhook = Vec::new();
        for (a, p) in analyzed.into_iter().zip(pre) {
            let content = a.stat.score;
            let final_score = self.rules.combine(content, p.prov.score, p.shadow.score);
            let severity = Severity::from_score(final_score, t);
            // Hash pins suppress. Path/remote allow rules suppress everything except critical.
            let suppressed = p.pinned_ok || (p.allowed && severity < Severity::Critical);
            let mut report = Report {
                path: a.fd.path.clone(),
                sha256: a.fd.sha256.clone(),
                size: a.fd.size,
                truncated: a.fd.truncated,
                scanned_at: ts.clone(),
                severity,
                scores: Scores {
                    content,
                    provenance: p.prov.score,
                    shadow: p.shadow.score,
                    final_score,
                },
                findings: a.stat.findings,
                provenance_reasons: p.prov.reasons,
                shadow_reasons: p.shadow.reasons,
                context: a.ctx,
                disposition: p.disposition,
                suppressed,
                changed_since_last_scan: p.changed,
                actions: vec![],
            };
            if a.fd.truncated {
                report.provenance_reasons.push(format!(
                    "file larger than {} bytes; analyzed the first part only",
                    self.cfg.scan.max_file_size
                ));
            }
            if self.opts.apply_actions {
                // Notifications and hooks fire once per new/changed content; quarantine applies whenever due.
                report.actions = policy::apply(&mut report, self.cfg, self.store, p.changed || p.first_seen_now);
            }
            self.store.record_report(&report, &a.fd.file_id, a.fd.mtime)?;
            if report.disposition.as_deref() == Some("quarantined") {
                self.store.mark_missing(&report.path.to_string_lossy())?;
            }
            if (p.changed || p.first_seen_now) && !report.suppressed && report.severity >= self.cfg.output.webhook_min_severity {
                webhook.push(report.clone());
            }
            out.reports.push(report);
        }
        out.reports
            .sort_by(|a, b| b.scores.final_score.cmp(&a.scores.final_score).then(a.path.cmp(&b.path)));

        if let Some(j) = &self.cfg.output.jsonl_path {
            if !out.reports.is_empty() {
                if let Err(e) = output::append_jsonl(j, &out.reports) {
                    out.notes.push(format!("could not append JSONL to {}: {e}", j.display()));
                }
            }
        }
        if let Some(url) = &self.cfg.output.webhook_url {
            let refs: Vec<&Report> = webhook.iter().collect();
            if let Err(e) = output::post_webhook(url, &refs) {
                out.notes.push(e.to_string());
            }
        }
        let hi = out.reports.iter().filter(|r| r.severity >= Severity::High && !r.suppressed).count();
        self.store.audit(
            "scan",
            &format!(
                "{} files, {} high+, {} skipped, {} unchanged",
                out.reports.len(),
                hi,
                out.skipped.len(),
                out.unchanged
            ),
        )?;
        Ok(out)
    }
}
