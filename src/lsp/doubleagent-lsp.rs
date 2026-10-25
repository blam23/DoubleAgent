//! DoubleAgent language server: rates agent instruction files while they are edited and
//! publishes the findings as diagnostics. Speaks LSP over stdio.
//!
//! It analyses the editor's buffer (not just what is on disk), reads the same pins and allow
//! rules as the CLI, and writes nothing except a pin when the user asks for one. If a
//! DoubleAgent service (daemon or desktop app) is listening, its verdicts are folded in.

mod protocol;
mod uri;

use anyhow::{Context as _, Result};
use clap::Parser;
use doubleagent::config::{app_dir, default_db_path, Config};
use doubleagent::engine::{Engine, RunOptions};
use doubleagent::model::{Report, Severity};
use doubleagent::scanner::{self, Matcher};
use doubleagent::service;
use doubleagent::store::Store;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const DEBOUNCE: Duration = Duration::from_millis(300);
const SERVICE_POLL: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(name = "doubleagent-lsp", version, about = "DoubleAgent language server (stdio)")]
struct Args {
    /// Config file (default: the per-user DoubleAgent config).
    #[arg(long)]
    config: Option<PathBuf>,
    /// State database. Default: the shared DoubleAgent database if it exists, else a private one.
    #[arg(long)]
    db: Option<PathBuf>,
    /// Never contact a running DoubleAgent service.
    #[arg(long)]
    no_service: bool,
    /// Accepted for compatibility with generic LSP clients.
    #[arg(long, hide = true)]
    stdio: bool,
}

enum Event {
    Message(Value),
    Walked(Vec<PathBuf>),
    Closed,
}

struct Doc {
    path: PathBuf,
    text: String,
    version: i64,
    due: Option<Instant>,
}

struct Server<'a> {
    engine: &'a Engine<'a>,
    use_service: bool,
    roots: Vec<PathBuf>,
    docs: HashMap<String, Doc>,
    /// Latest report and the text it was computed from, by document URI.
    reports: HashMap<String, (Report, String)>,
    queue: VecDeque<PathBuf>,
    service_reports: HashMap<String, Report>,
    service_up: bool,
    next_poll: Instant,
    events: Sender<Event>,
    shutdown: bool,
}

fn severity_code(severity: Severity) -> u8 {
    match severity {
        Severity::Critical | Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

fn utf16_len(text: &str) -> u32 {
    text.encode_utf16().count() as u32
}

/// LSP columns count UTF-16 units; findings carry a 1-based byte column.
fn utf16_column(line: &str, byte_column: usize) -> u32 {
    let mut end = byte_column.saturating_sub(1).min(line.len());
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    utf16_len(&line[..end])
}

fn diagnostics(report: &Report, text: &str) -> Vec<Value> {
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let line_range = |line: usize, column: Option<usize>| {
        let text = lines.get(line).copied().unwrap_or("");
        json!({
            "start": {"line": line, "character": column.map_or(0, |c| utf16_column(text, c))},
            "end": {"line": line, "character": utf16_len(text).max(1)},
        })
    };
    let top = line_range(0, None);
    if report.suppressed {
        let why = report.disposition.as_deref().unwrap_or("trusted");
        return vec![json!({
            "range": top, "severity": 4, "source": "DoubleAgent", "code": "DA-TRUSTED",
            "message": format!("DoubleAgent: {why}. Findings are hidden for this exact content."),
        })];
    }
    let mut out: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let line = f.line.map_or(0, |l| l.saturating_sub(1));
            let atlas = if f.atlas.is_empty() {
                String::new()
            } else {
                format!(" (ATLAS {})", f.atlas.join(", "))
            };
            json!({
                "range": line_range(line, f.column),
                "severity": severity_code(f.severity),
                "source": "DoubleAgent",
                "code": f.rule_id,
                "message": format!("{}: {}{atlas}", f.title, f.reason),
            })
        })
        .collect();
    let notes: Vec<&str> = report
        .provenance_reasons
        .iter()
        .chain(&report.shadow_reasons)
        .map(String::as_str)
        .collect();
    if report.severity >= Severity::Low && !notes.is_empty() {
        out.push(json!({
            "range": top,
            "severity": severity_code(report.severity),
            "source": "DoubleAgent",
            "code": "DA-FILE",
            "message": format!(
                "{} risk (score {}): {}",
                report.severity.as_str().to_uppercase(),
                report.scores.final_score,
                notes.join("; ")
            ),
        }));
    }
    out
}

fn hover_text(report: &Report, line: usize, service: Option<&Report>) -> Option<String> {
    let mut parts = Vec::new();
    if line == 0 {
        let mut head = format!(
            "**DoubleAgent** · {} · score {} (content {}, provenance {}, shadow {})",
            report.severity.as_str().to_uppercase(),
            report.scores.final_score,
            report.scores.content,
            report.scores.provenance,
            report.scores.shadow
        );
        if let Some(d) = &report.disposition {
            head.push_str(&format!("\n\n_{d}_"));
        }
        for note in report.provenance_reasons.iter().chain(&report.shadow_reasons) {
            head.push_str(&format!("\n- {note}"));
        }
        if let Some(s) = service {
            head.push_str(&format!(
                "\n\nMonitor last rated this file **{}** (score {}) at {}.",
                s.severity.as_str().to_uppercase(),
                s.scores.final_score,
                s.scanned_at
            ));
        }
        parts.push(head);
    }
    for f in report.findings.iter().filter(|f| f.line.map_or(0, |l| l - 1) == line) {
        let atlas = if f.atlas.is_empty() {
            String::new()
        } else {
            format!(" · ATLAS {}", f.atlas.join(", "))
        };
        parts.push(format!("**{}** `{}`{atlas}\n\n{}", f.title, f.rule_id, f.reason));
    }
    (!parts.is_empty()).then(|| parts.join("\n\n---\n\n"))
}

impl<'a> Server<'a> {
    fn send(&self, message: Value) {
        if let Err(error) = protocol::write(&message) {
            eprintln!("write failed: {error}");
        }
    }

    fn notify(&self, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn respond(&self, id: &Value, result: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    fn respond_error(&self, id: &Value, code: i64, message: &str) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}));
    }

    fn message(&self, kind: u8, text: &str) {
        self.notify("window/showMessage", json!({"type": kind, "message": text}));
    }

    fn handle(&mut self, message: Value) {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("").to_owned();
        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        match method.as_str() {
            "initialize" => {
                self.roots = uri::roots(&params);
                self.respond(&id.unwrap_or(Value::Null), initialize_result());
            }
            "initialized" => self.scan_workspace(),
            "shutdown" => {
                self.shutdown = true;
                self.respond(&id.unwrap_or(Value::Null), Value::Null);
            }
            "exit" => self.shutdown = true,
            "textDocument/didOpen" => {
                let doc = &params["textDocument"];
                if let (Some(u), Some(text)) = (doc["uri"].as_str(), doc["text"].as_str()) {
                    if let Some(path) = uri::to_path(u) {
                        self.docs.insert(
                            u.to_owned(),
                            Doc {
                                path,
                                text: text.to_owned(),
                                version: doc["version"].as_i64().unwrap_or(0),
                                due: Some(Instant::now()),
                            },
                        );
                    }
                }
            }
            "textDocument/didChange" => {
                let u = params["textDocument"]["uri"].as_str().unwrap_or("");
                // Full-document sync: the last change carries the whole text.
                let text = params["contentChanges"]
                    .as_array()
                    .and_then(|c| c.last())
                    .and_then(|c| c["text"].as_str());
                if let (Some(doc), Some(text)) = (self.docs.get_mut(u), text) {
                    doc.text = text.to_owned();
                    doc.version = params["textDocument"]["version"].as_i64().unwrap_or(doc.version);
                    doc.due = Some(Instant::now() + DEBOUNCE);
                }
            }
            "textDocument/didSave" => {
                if let Some(doc) = self.docs.get_mut(params["textDocument"]["uri"].as_str().unwrap_or("")) {
                    doc.due = Some(Instant::now());
                }
            }
            "textDocument/didClose" => {
                let u = params["textDocument"]["uri"].as_str().unwrap_or("").to_owned();
                if let Some(doc) = self.docs.remove(&u) {
                    if self.in_workspace(&doc.path) {
                        self.queue.push_front(doc.path);
                    } else {
                        self.reports.remove(&u);
                        self.notify("textDocument/publishDiagnostics", json!({"uri": u, "diagnostics": []}));
                        self.send_summary();
                    }
                }
            }
            "workspace/didChangeWatchedFiles" => {
                for change in params["changes"].as_array().into_iter().flatten() {
                    let Some(u) = change["uri"].as_str() else { continue };
                    let Some(path) = uri::to_path(u) else { continue };
                    if self.docs.contains_key(u) || !self.engine.matcher.is_candidate(&path) {
                        continue;
                    }
                    if change["type"].as_i64() == Some(3) || !path.exists() {
                        self.reports.remove(u);
                        self.notify("textDocument/publishDiagnostics", json!({"uri": u, "diagnostics": []}));
                        self.send_summary();
                    } else {
                        self.queue.push_back(path);
                    }
                }
            }
            "doubleagent/rescan" => self.scan_workspace(),
            "doubleagent/reports" => self.respond(&id.unwrap_or(Value::Null), self.report_list()),
            "textDocument/hover" => {
                let result = self.hover(&params).unwrap_or(Value::Null);
                self.respond(&id.unwrap_or(Value::Null), result);
            }
            "textDocument/codeAction" => {
                let result = self.code_actions(&params);
                self.respond(&id.unwrap_or(Value::Null), result);
            }
            "workspace/executeCommand" => {
                let result = self.execute(&params);
                match (&id, result) {
                    (Some(id), Ok(())) => self.respond(id, Value::Null),
                    (Some(id), Err(error)) => {
                        self.message(1, &format!("DoubleAgent: {error:#}"));
                        self.respond_error(id, -32603, &format!("{error:#}"));
                    }
                    _ => {}
                }
            }
            other => {
                // Unknown requests need an answer; unknown notifications are ignored.
                if let Some(id) = id {
                    if !other.starts_with("$/") {
                        self.respond_error(&id, -32601, &format!("method not supported: {other}"));
                    }
                }
            }
        }
    }

    fn in_workspace(&self, path: &Path) -> bool {
        let key = path_key(path);
        self.roots.iter().any(|r| key.starts_with(&path_key(r)))
    }

    fn scan_workspace(&mut self) {
        let roots = self.roots.clone();
        let (cfg, events) = (self.engine.cfg.scan.clone(), self.events.clone());
        thread::spawn(move || {
            let Ok(matcher) = Matcher::new(&cfg) else { return };
            let (found, _) = scanner::walk(&roots, &cfg, &matcher);
            let _ = events.send(Event::Walked(found));
        });
    }

    fn analyze(&mut self, uri_text: &str, path: &Path, text: &str, version: Option<i64>) {
        if !self.engine.matcher.is_candidate(path) {
            return;
        }
        let mut report = match self.engine.evaluate_buffer(path, text) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("analysis failed for {}: {error:#}", path.display());
                return;
            }
        };
        // With a private database the user's allow rules aren't visible; the service's verdict
        // for the same content carries them.
        if !report.suppressed {
            if let Some(known) = self.service_reports.get(&path_key(path)) {
                if known.sha256 == report.sha256 && known.suppressed {
                    report.suppressed = true;
                    report.disposition = known.disposition.clone();
                }
            }
        }
        let mut params = json!({"uri": uri_text, "diagnostics": diagnostics(&report, text)});
        if let Some(version) = version {
            params["version"] = json!(version);
        }
        self.notify("textDocument/publishDiagnostics", params);
        self.reports.insert(uri_text.to_owned(), (report, text.to_owned()));
        self.send_summary();
    }

    fn analyze_doc(&mut self, uri_text: &str) {
        let Some(doc) = self.docs.get_mut(uri_text) else { return };
        doc.due = None;
        let (path, text, version) = (doc.path.clone(), doc.text.clone(), doc.version);
        self.analyze(uri_text, &path, &text, Some(version));
    }

    fn analyze_from_disk(&mut self, path: PathBuf) {
        let uri_text = uri::from_path(&path);
        if self.docs.contains_key(&uri_text) {
            return;
        }
        let cap = self.engine.cfg.scan.max_file_size;
        let Ok(file) = std::fs::File::open(&path) else { return };
        let mut bytes = Vec::new();
        if std::io::Read::read_to_end(&mut std::io::Read::take(file, cap), &mut bytes).is_err() {
            return;
        }
        self.analyze(&uri_text, &path, &String::from_utf8_lossy(&bytes), None);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self
            .docs
            .iter()
            .filter(|(_, d)| d.due.is_some_and(|t| t <= now))
            .map(|(u, _)| u.clone())
            .collect();
        if !due.is_empty() {
            for u in due {
                self.analyze_doc(&u);
            }
            return;
        }
        if let Some(path) = self.queue.pop_front() {
            self.analyze_from_disk(path);
            return;
        }
        if self.use_service && now >= self.next_poll {
            self.next_poll = now + SERVICE_POLL;
            self.poll_service();
        }
    }

    fn poll_service(&mut self) {
        let up = service::probe(service::DEFAULT_ADDR);
        if up {
            if let Ok(reports) = service::fetch_reports(service::DEFAULT_ADDR) {
                self.service_reports = reports.into_iter().map(|r| (path_key(&r.path), r)).collect();
            }
        } else {
            self.service_reports.clear();
        }
        if up != self.service_up {
            self.service_up = up;
            self.send_summary();
        }
    }

    fn counts(&self) -> Value {
        let mut counts = [0u32; 5];
        for (report, _) in self.reports.values().filter(|(r, _)| !r.suppressed) {
            counts[report.severity as usize] += 1;
        }
        json!({"info": counts[0], "low": counts[1], "medium": counts[2], "high": counts[3], "critical": counts[4]})
    }

    fn send_summary(&self) {
        self.notify(
            "doubleagent/summary",
            json!({"files": self.reports.len(), "counts": self.counts(), "service": self.service_up}),
        );
    }

    fn report_list(&self) -> Value {
        let mut rows: Vec<&(Report, String)> = self.reports.values().collect();
        rows.sort_by(|a, b| b.0.scores.final_score.cmp(&a.0.scores.final_score).then(a.0.path.cmp(&b.0.path)));
        Value::Array(
            rows.into_iter()
                .map(|(r, _)| {
                    json!({
                        "uri": uri::from_path(&r.path),
                        "path": r.path,
                        "severity": r.severity.as_str(),
                        "score": r.scores.final_score,
                        "suppressed": r.suppressed,
                        "disposition": r.disposition,
                        "findings": r.findings.iter().map(|f| json!({
                            "ruleId": f.rule_id, "title": f.title, "severity": f.severity.as_str(),
                            "line": f.line.map_or(0, |l| l.saturating_sub(1)), "reason": f.reason,
                        })).collect::<Vec<_>>(),
                        "notes": r.provenance_reasons.iter().chain(&r.shadow_reasons).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    }

    fn hover(&self, params: &Value) -> Option<Value> {
        let u = params["textDocument"]["uri"].as_str()?;
        let line = params["position"]["line"].as_u64()? as usize;
        let (report, _) = self.reports.get(u)?;
        let known = self.service_reports.get(&path_key(&report.path));
        let text = hover_text(report, line, known)?;
        Some(json!({"contents": {"kind": "markdown", "value": text}}))
    }

    fn code_actions(&self, params: &Value) -> Value {
        let u = params["textDocument"]["uri"].as_str().unwrap_or("");
        let Some((report, _)) = self.reports.get(u) else { return json!([]) };
        let mut actions = Vec::new();
        let pinned = report.disposition.as_deref() == Some("pinned");
        if pinned {
            actions.push(json!({
                "title": "DoubleAgent: stop trusting this file (remove pin)",
                "kind": "quickfix",
                "command": {"title": "Unpin", "command": "doubleagent.unpin", "arguments": [u]},
            }));
        } else if report.severity > Severity::Info || !report.findings.is_empty() {
            actions.push(json!({
                "title": "DoubleAgent: trust this exact content (pin hash)",
                "kind": "quickfix",
                "command": {"title": "Pin", "command": "doubleagent.pin", "arguments": [u]},
            }));
        }
        Value::Array(actions)
    }

    fn execute(&mut self, params: &Value) -> Result<()> {
        let command = params["command"].as_str().unwrap_or("");
        let u = params["arguments"][0].as_str().context("missing document")?.to_owned();
        let path = uri::to_path(&u).context("not a file URI")?;
        let store = self.engine.store;
        match command {
            "doubleagent.pin" => {
                let on_disk = scanner::sha256_file(&path, self.engine.cfg.scan.max_file_size).context("reading the saved file")?;
                let (report, _) = self.reports.get(&u).context("file has not been analysed yet")?;
                if report.sha256 != on_disk {
                    anyhow::bail!("save the file first: the pin covers the saved content, which differs from what is in the editor");
                }
                store.add_allow("pin", &path.to_string_lossy(), Some(&on_disk), Some("pinned from the editor"))?;
                store.audit("allow", &format!("pin {} (from editor)", path.display()))?;
            }
            "doubleagent.unpin" => {
                let wanted = path_key(&path);
                let rules: Vec<_> = store
                    .list_allow()?
                    .into_iter()
                    .filter(|r| r.kind == "pin" && path_key(Path::new(&r.pattern)) == wanted)
                    .collect();
                anyhow::ensure!(!rules.is_empty(), "this file has no pin");
                for rule in rules {
                    store.remove_allow(rule.id)?;
                    store.audit("allow", &format!("unpin {} (from editor)", path.display()))?;
                }
            }
            other => anyhow::bail!("unknown command {other}"),
        }
        match self.docs.get_mut(&u) {
            Some(doc) => doc.due = Some(Instant::now()),
            None => self.queue.push_front(path),
        }
        Ok(())
    }

    fn run(&mut self, events: Receiver<Event>) {
        while !self.shutdown {
            match events.recv_timeout(Duration::from_millis(100)) {
                Ok(Event::Message(message)) => self.handle(message),
                Ok(Event::Walked(paths)) => self.queue.extend(paths),
                Ok(Event::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => self.tick(),
            }
        }
    }
}

fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "textDocumentSync": {"openClose": true, "change": 1, "save": {"includeText": false}},
            "hoverProvider": true,
            "codeActionProvider": {"codeActionKinds": ["quickfix"]},
            "executeCommandProvider": {"commands": ["doubleagent.pin", "doubleagent.unpin"]},
        },
        "serverInfo": {"name": "doubleagent-lsp", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (cfg, _) = Config::load(args.config.as_deref()).unwrap_or_else(|error| {
        eprintln!("config not loaded, using defaults: {error:#}");
        (Config::default(), PathBuf::new())
    });
    let db_path = args.db.unwrap_or_else(|| {
        let shared = default_db_path();
        if shared.exists() {
            shared
        } else {
            app_dir().join("lsp.db")
        }
    });
    let store = Store::open(&db_path)?;
    let matcher = Matcher::new(&cfg.scan)?;
    let engine = Engine::new(
        &cfg,
        &store,
        &matcher,
        RunOptions {
            apply_actions: false,
            skip_unchanged: false,
        },
    )?;

    let (tx, rx) = mpsc::channel();
    let reader_tx = tx.clone();
    thread::spawn(move || {
        let mut input = std::io::BufReader::new(std::io::stdin().lock());
        while let Some(message) = protocol::read(&mut input) {
            if reader_tx.send(Event::Message(message)).is_err() {
                return;
            }
        }
        let _ = reader_tx.send(Event::Closed);
    });

    let mut server = Server {
        engine: &engine,
        use_service: !args.no_service,
        roots: Vec::new(),
        docs: HashMap::new(),
        reports: HashMap::new(),
        queue: VecDeque::new(),
        service_reports: HashMap::new(),
        service_up: false,
        next_poll: Instant::now(),
        events: tx,
        shutdown: false,
    };
    server.run(rx);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_are_utf16_units_not_bytes() {
        // U+E0041 is 4 bytes in UTF-8 and a surrogate pair (2 units) in UTF-16.
        let line = "a\u{E0041}b needle";
        assert_eq!(utf16_column(line, 1), 0);
        assert_eq!(utf16_column(line, 2), 1);
        assert_eq!(utf16_column(line, 6), 3);
        assert_eq!(utf16_column("short", 99), 5);
    }
}
