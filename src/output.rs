//! Report renderers: console text, JSON, JSON Lines, SARIF 2.1.0, webhook.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;

use crate::model::{Report, Severity};
use crate::redact::Redactor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Jsonl,
    Sarif,
}

pub struct Summary {
    pub scanned: usize,
    pub skipped: usize,
    pub suppressed: usize,
    pub by_severity: BTreeMap<Severity, usize>,
}

pub fn summarize(reports: &[Report], skipped: usize) -> Summary {
    let mut by = BTreeMap::new();
    for r in reports.iter().filter(|r| !r.suppressed) {
        *by.entry(r.severity).or_insert(0) += 1;
    }
    Summary {
        scanned: reports.len(),
        skipped,
        suppressed: reports.iter().filter(|r| r.suppressed).count(),
        by_severity: by,
    }
}

fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
        return false;
    }
    if cfg!(windows) {
        return std::env::var_os("WT_SESSION").is_some() || std::env::var_os("TERM_PROGRAM").is_some();
    }
    true
}

fn paint(s: &str, sev: Severity, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    let code = match sev {
        Severity::Critical => "1;97;41",
        Severity::High => "1;31",
        Severity::Medium => "33",
        Severity::Low => "36",
        Severity::Info => "2",
    };
    format!("\x1b[{code}m{s}\x1b[0m")
}

pub fn render_text(reports: &[Report], summary: &Summary, min: Severity, show_all: bool, w: &mut dyn Write) -> Result<()> {
    let color = use_color();
    let mut shown = 0;
    for r in reports {
        if (r.suppressed && !show_all) || r.severity < min {
            continue;
        }
        shown += 1;
        let tag = format!("[{} {:>3}]", r.severity.as_str().to_uppercase(), r.scores.final_score);
        writeln!(w, "{} {}", paint(&tag, r.severity, color), r.path.display())?;
        let s = &r.scores;
        writeln!(w, "    content {} · provenance {} · shadow {}", s.content, s.provenance, s.shadow)?;
        if let Some(d) = &r.disposition {
            writeln!(w, "    disposition: {d}{}", if r.suppressed { " (suppressed)" } else { "" })?;
        }
        for f in r.findings.iter().filter(|f| f.weight >= 10).take(12) {
            let line = f.line.map(|l| format!("L{l}")).unwrap_or_else(|| "  -".into());
            let atlas = if f.atlas.is_empty() {
                String::new()
            } else {
                format!(" [{}]", f.atlas.join(", "))
            };
            writeln!(w, "    {:>5}  {:<10} {}: {}{}", line, f.rule_id, f.title, f.excerpt, atlas)?;
        }
        let minor =
            r.findings.iter().filter(|f| f.weight < 10).count() + r.findings.iter().filter(|f| f.weight >= 10).count().saturating_sub(12);
        if minor > 0 {
            writeln!(w, "           (+{minor} more findings; use --format json for all)")?;
        }
        for reason in r.provenance_reasons.iter().chain(r.shadow_reasons.iter()) {
            writeln!(w, "    · {reason}")?;
        }
        for a in &r.actions {
            writeln!(w, "    action: {a}")?;
        }
        writeln!(w)?;
    }
    if shown == 0 {
        writeln!(w, "No agent files at or above '{min}'.")?;
    }
    let counts: Vec<String> = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .iter()
        .map(|s| format!("{} {}", summary.by_severity.get(s).copied().unwrap_or(0), s))
        .collect();
    writeln!(
        w,
        "Scanned {} agent file(s): {}. {} suppressed by allow rules, {} skipped.",
        summary.scanned,
        counts.join(", "),
        summary.suppressed,
        summary.skipped
    )?;
    Ok(())
}

pub fn render_json(reports: &[Report], summary: &Summary, w: &mut dyn Write) -> Result<()> {
    let by: BTreeMap<String, usize> = summary.by_severity.iter().map(|(k, v)| (k.as_str().to_string(), *v)).collect();
    let v = json!({
        "tool": "doubleagent",
        "version": env!("CARGO_PKG_VERSION"),
        "generated_at": crate::store::now(),
        "summary": {"scanned": summary.scanned, "skipped": summary.skipped, "suppressed": summary.suppressed, "by_severity": by},
        "reports": reports,
    });
    serde_json::to_writer_pretty(&mut *w, &v)?;
    writeln!(w)?;
    Ok(())
}

pub fn render_jsonl(reports: &[Report], w: &mut dyn Write) -> Result<()> {
    for r in reports {
        serde_json::to_writer(&mut *w, r)?;
        writeln!(w)?;
    }
    Ok(())
}

pub fn append_jsonl(path: &Path, reports: &[Report]) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    render_jsonl(reports, &mut f)
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

fn artifact_uri(p: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            return rel.to_string_lossy().replace('\\', "/");
        }
    }
    let s = p.to_string_lossy().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

pub fn render_sarif(reports: &[Report], min: Severity, w: &mut dyn Write) -> Result<()> {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();
    rules.insert(
        "DA-FILE".into(),
        json!({"id": "DA-FILE", "name": "RogueAgentFile", "shortDescription": {"text": "Agent instruction file rated risky"},
               "fullDescription": {"text": "Combined content, provenance and shadowing risk for an agent instruction file."}}),
    );
    for r in reports.iter().filter(|r| !r.suppressed && r.severity >= min) {
        let uri = artifact_uri(&r.path);
        let mut msg = format!(
            "{} risk (score {}): content {}, provenance {}, shadow {}.",
            r.severity, r.scores.final_score, r.scores.content, r.scores.provenance, r.scores.shadow
        );
        for reason in r.provenance_reasons.iter().chain(r.shadow_reasons.iter()) {
            msg.push_str(&format!(" {reason};"));
        }
        results.push(json!({
            "ruleId": "DA-FILE", "level": sarif_level(r.severity), "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}],
            "partialFingerprints": {"sha256": r.sha256},
            "properties": {"severity": r.severity, "score": r.scores.final_score}
        }));
        for f in r.findings.iter().filter(|f| f.weight >= 20) {
            rules.entry(f.rule_id.clone()).or_insert_with(|| {
                json!({"id": f.rule_id, "name": f.title.replace(' ', ""), "shortDescription": {"text": f.title},
                       "properties": {"category": f.category, "atlas": &f.atlas}})
            });
            results.push(json!({
                "ruleId": f.rule_id, "level": sarif_level(f.severity),
                "message": {"text": format!("{}: {} — {}", f.title, f.excerpt, f.reason)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                    "region": {"startLine": f.line.unwrap_or(1).max(1), "startColumn": f.column.unwrap_or(1).max(1)}}}],
                "properties": {"category": f.category, "weight": f.weight, "atlas": &f.atlas}
            }));
        }
    }
    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "DoubleAgent", "version": env!("CARGO_PKG_VERSION"),
                                "informationUri": "https://github.com/", "rules": rules.into_values().collect::<Vec<_>>()}},
            "results": results
        }]
    });
    serde_json::to_writer_pretty(&mut *w, &sarif)?;
    writeln!(w)?;
    Ok(())
}

fn is_local_url(u: &str) -> bool {
    let rest = u.split_once("://").map(|x| x.1).unwrap_or(u);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map(|x| x.1).unwrap_or(host);
    let host = if host.starts_with('[') {
        host.trim_start_matches('[').split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    host == "localhost" || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

pub fn post_webhook(url: &str, reports: &[&Report]) -> Result<()> {
    if reports.is_empty() {
        return Ok(());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .try_proxy_from_env(!is_local_url(url))
        .build();
    let body = json!({"tool": "doubleagent", "generated_at": crate::store::now(), "reports": reports});
    // Excerpts can contain secrets: redact before anything leaves the machine.
    let text = Redactor::new().redact(&serde_json::to_string(&body)?);
    agent
        .post(url)
        .set("content-type", "application/json")
        .send_string(&text)
        .map_err(|e| anyhow::anyhow!("webhook: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_urls() {
        assert!(is_local_url("http://127.0.0.1:11434/v1"));
        assert!(is_local_url("http://localhost:8000"));
        assert!(is_local_url("http://[::1]:8000/v1"));
        assert!(!is_local_url("https://api.openai.com/v1"));
        assert!(!is_local_url("http://localhost.evil.com/v1"));
    }
}
