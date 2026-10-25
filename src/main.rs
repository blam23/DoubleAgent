//! DoubleAgent: rogue AGENTS.md sentinel.

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand};
use doubleagent::{atlas, config, engine, model, output, policy, scanner, score, service, store, tui, watch};
use std::io::Write;
use std::path::{Path, PathBuf};

use config::Config;
use engine::{Engine, RunOptions};
use model::Severity;
use output::Format;
use scanner::Matcher;
use store::Store;

#[derive(Parser)]
#[command(
    name = "doubleagent",
    version,
    about = "Find, rate and report rogue agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, ...)"
)]
struct Cli {
    /// Config file (default: per-user config dir, DoubleAgent/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// State database (default: per-user data dir, DoubleAgent/state.db).
    #[arg(long, global = true)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan folders (default: configured roots, or your home folder) and report.
    Scan {
        paths: Vec<PathBuf>,
        #[arg(long, short, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Write the report to a file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Lowest severity to show.
        #[arg(long, default_value = "low")]
        min_severity: Severity,
        /// Exit with code 1 if any unsuppressed file is at or above this severity (CI mode).
        #[arg(long)]
        fail_on: Option<Severity>,
        /// Include files suppressed by allow rules / pins.
        #[arg(long)]
        all: bool,
        /// Don't run notify / hook / quarantine actions.
        #[arg(long)]
        no_actions: bool,
        /// List files that were skipped (unreadable, cloud placeholders, loops).
        #[arg(long, short)]
        verbose: bool,
    },
    /// Watch folders continuously and report new or changed agent files.
    Watch {
        paths: Vec<PathBuf>,
        #[arg(long, default_value = "low")]
        min_severity: Severity,
        #[arg(long)]
        no_actions: bool,
    },
    /// Run the live monitor with local read-only JSON IPC enabled.
    Daemon {
        paths: Vec<PathBuf>,
        #[arg(long)]
        no_actions: bool,
    },
    /// Open the terminal verdict browser.
    Tui,
    /// Generate an OS user-service definition for this executable.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Show the latest stored verdicts without rescanning.
    Report {
        #[arg(long, short, value_enum, default_value_t = Format::Text)]
        format: Format,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "low")]
        min_severity: Severity,
        #[arg(long)]
        all: bool,
        /// Show verdict history for one file instead.
        #[arg(long)]
        history: Option<PathBuf>,
    },
    /// Manage allow rules and hash pins.
    Allow {
        #[command(subcommand)]
        cmd: AllowCmd,
    },
    /// List quarantined files.
    Quarantine,
    /// Move a quarantined file back to where it was.
    Restore { id: i64 },
    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Inspect or verify the tamper-evident audit log.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
}

#[derive(Subcommand)]
enum AllowCmd {
    /// Trust a file at its current content. Any change re-triggers review.
    Pin {
        file: PathBuf,
        #[arg(long)]
        note: Option<String>,
    },
    /// Allow files matching a path glob (critical findings still surface).
    Path {
        glob: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Allow files in repos whose origin remote contains this text (critical still surfaces).
    Remote {
        pattern: String,
        #[arg(long)]
        note: Option<String>,
    },
    List,
    Remove {
        id: i64,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Write a default config file.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Print the effective configuration.
    Show,
    /// Print the provenance/shadow scoring rules in effect, and the names a rule can use.
    Rules,
    /// Print config, database and quarantine locations.
    Path,
}

#[derive(Subcommand)]
enum AuditCmd {
    Show {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Verify,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Write the current platform's service/task files into a directory.
    Files { directory: Option<PathBuf> },
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn resolve_roots(paths: Vec<PathBuf>, cfg: &Config) -> Result<Vec<PathBuf>> {
    let roots = if !paths.is_empty() {
        paths
    } else if !cfg.scan.roots.is_empty() {
        cfg.scan.roots.clone()
    } else {
        vec![dirs::home_dir().context("no home folder; pass a path to scan")?]
    };
    Ok(roots.into_iter().map(|p| absolute(&p)).collect())
}

fn absolute(p: &Path) -> PathBuf {
    // canonicalize() on Windows yields \\?\ paths (long-path safe) but they read badly; prefer a plain absolute path.
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf())
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn writer(output: &Option<PathBuf>) -> Result<Box<dyn Write>> {
    Ok(match output {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => Box::new(std::io::stdout().lock()),
    })
}

fn render(fmt: Format, reports: &[model::Report], summary: &output::Summary, min: Severity, all: bool, w: &mut dyn Write) -> Result<()> {
    let visible: Vec<model::Report> = reports
        .iter()
        .filter(|r| (all || !r.suppressed) && r.severity >= min)
        .cloned()
        .collect();
    match fmt {
        Format::Text => output::render_text(reports, summary, min, all, w),
        Format::Json => output::render_json(&visible, summary, w),
        Format::Jsonl => output::render_jsonl(&visible, w),
        Format::Sarif => output::render_sarif(reports, min, w),
    }
}

fn print_scoring_rules(cfg: &Config) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Rules {
        rules: Vec<config::ScoringRule>,
    }
    #[derive(serde::Serialize)]
    struct Wrapper {
        scoring: Rules,
    }
    println!("# Facts a rule's `when` and `reason` can use:");
    for (name, ty, about) in score::FACTS {
        println!("#   {name:<20} {:<7} {about}", ty.as_str());
    }
    println!("# Functions:");
    for (sig, about) in score::FUNCTIONS {
        println!("#   {sig:<28} {about}");
    }
    println!("# Operators: || && ! == != < <= > >= + -");
    println!();
    println!("# Rules in effect. Copy one into your config and edit it to override it by ID.");
    println!(
        "# ATLAS technique IDs use release {}. An empty `atlas` list means no direct technique mapping.",
        atlas::VERSION
    );
    println!();
    let rules = score::effective_rules(&cfg.scoring)?;
    print!("{}", toml::to_string_pretty(&Wrapper { scoring: Rules { rules } })?);
    Ok(())
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    // `config init` must work before the file exists (and even if an old one is broken).
    let is_init = matches!(
        &cli.cmd,
        Cmd::Config {
            cmd: ConfigCmd::Init { .. }
        }
    );
    let (cfg, cfg_path) = if is_init {
        (Config::default(), cli.config.clone().unwrap_or_else(config::default_config_path))
    } else {
        Config::load(cli.config.as_deref())?
    };
    let db_path = cli.db.clone().unwrap_or_else(config::default_db_path);

    if let Cmd::Config { cmd } = &cli.cmd {
        {
            match cmd {
                ConfigCmd::Init { force } => {
                    if cfg_path.exists() && !*force {
                        bail!("{} already exists (use --force to overwrite)", cfg_path.display());
                    }
                    if let Some(d) = cfg_path.parent() {
                        std::fs::create_dir_all(d)?;
                    }
                    std::fs::write(&cfg_path, Config::default_toml())?;
                    println!("Wrote {}", cfg_path.display());
                }
                ConfigCmd::Show => print!("{}", toml::to_string_pretty(&cfg)?),
                ConfigCmd::Rules => print_scoring_rules(&cfg)?,
                ConfigCmd::Path => {
                    println!(
                        "config:     {}{}",
                        cfg_path.display(),
                        if cfg_path.exists() { "" } else { " (not created; defaults in use)" }
                    );
                    println!("database:   {}", db_path.display());
                    println!("quarantine: {}", policy::quarantine_dir(&cfg).display());
                }
            }
            return Ok(0);
        }
    }

    let store = Store::open(&db_path)?;
    let matcher = Matcher::new(&cfg.scan)?;

    match cli.cmd {
        Cmd::Scan {
            paths,
            format,
            output,
            min_severity,
            fail_on,
            all,
            no_actions,
            verbose,
        } => {
            let roots = resolve_roots(paths, &cfg)?;
            let opts = RunOptions {
                apply_actions: !no_actions,
                skip_unchanged: false,
            };
            let engine = Engine::new(&cfg, &store, &matcher, opts)?;
            let (found, skipped) = scanner::walk(&roots, &cfg.scan, &matcher);
            let mut outcome = engine.process(found)?;
            outcome.skipped.extend(skipped);

            for n in &outcome.notes {
                eprintln!("note: {n}");
            }
            if verbose {
                for s in &outcome.skipped {
                    eprintln!("skipped: {} ({})", s.path.display(), s.reason);
                }
            }
            let summary = output::summarize(&outcome.reports, outcome.skipped.len());
            let mut w = writer(&output)?;
            render(format, &outcome.reports, &summary, min_severity, all, &mut *w)?;
            w.flush()?;
            if let Some(t) = fail_on {
                if outcome.reports.iter().any(|r| !r.suppressed && r.severity >= t) {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        Cmd::Watch {
            paths,
            min_severity,
            no_actions,
        } => {
            let roots = resolve_roots(paths, &cfg)?;
            let opts = RunOptions {
                apply_actions: !no_actions,
                skip_unchanged: true,
            };
            let engine = Engine::new(&cfg, &store, &matcher, opts)?;
            watch::run(&engine, &roots, |out, label| {
                let shown: Vec<&model::Report> = out.reports.iter().filter(|r| !r.suppressed && r.severity >= min_severity).collect();
                let ts = chrono::Local::now().format("%H:%M:%S");
                if label != "change" || !shown.is_empty() {
                    eprintln!(
                        "[{ts}] {label}: {} checked, {} unchanged, {} at or above {min_severity}",
                        out.reports.len(),
                        out.unchanged,
                        shown.len()
                    );
                }
                for n in &out.notes {
                    eprintln!("note: {n}");
                }
                if !shown.is_empty() {
                    let owned: Vec<model::Report> = shown.into_iter().cloned().collect();
                    let summary = output::summarize(&owned, 0);
                    let mut so = std::io::stdout().lock();
                    let _ = output::render_text(&owned, &summary, min_severity, false, &mut so);
                }
            })?;
            Ok(0)
        }
        Cmd::Daemon { paths, no_actions } => {
            let roots = resolve_roots(paths, &cfg)?;
            let addr = service::start(db_path.clone())?;
            eprintln!("Read-only local IPC listening at http://{addr}/");
            let opts = RunOptions {
                apply_actions: !no_actions,
                skip_unchanged: true,
            };
            let engine = Engine::new(&cfg, &store, &matcher, opts)?;
            watch::run(&engine, &roots, |out, label| {
                if label != "change" || !out.reports.is_empty() {
                    eprintln!("{label}: {} files checked, {} unchanged", out.reports.len(), out.unchanged);
                }
            })?;
            Ok(0)
        }
        Cmd::Tui => {
            tui::run(&store.latest_reports(Severity::Info)?)?;
            Ok(0)
        }
        Cmd::Service {
            cmd: ServiceCmd::Files { directory },
        } => {
            let exe = std::env::current_exe().context("resolving executable path")?;
            let dir = directory.unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join("service-files"));
            let files = service::write_service_files(&dir, &exe)?;
            if files.is_empty() {
                bail!("service packaging is unsupported on this platform");
            }
            for path in files {
                println!("Wrote {}", path.display());
            }
            Ok(0)
        }
        Cmd::Report {
            format,
            output,
            min_severity,
            all,
            history,
        } => {
            if let Some(h) = history {
                let p = absolute(&h);
                let rows = store.history(&p)?;
                if rows.is_empty() {
                    println!("No history for {}", p.display());
                }
                for (ts, sha, sev, score) in rows {
                    println!("{ts}  {:<8} {:>3}  {}", sev, score, &sha[..12.min(sha.len())]);
                }
                return Ok(0);
            }
            let reports = store.latest_reports(Severity::Info)?;
            let summary = output::summarize(&reports, 0);
            let mut w = writer(&output)?;
            render(format, &reports, &summary, min_severity, all, &mut *w)?;
            w.flush()?;
            Ok(0)
        }
        Cmd::Allow { cmd } => {
            match cmd {
                AllowCmd::Pin { file, note } => {
                    let p = absolute(&file);
                    if !p.is_file() {
                        bail!("{} is not a file", p.display());
                    }
                    let sha = scanner::sha256_file(&p, cfg.scan.max_file_size)?;
                    let id = store.add_allow("pin", &p.to_string_lossy(), Some(&sha), note.as_deref())?;
                    println!(
                        "Pinned #{id}: {} at sha256 {}…; any change will be re-reviewed.",
                        p.display(),
                        &sha[..16]
                    );
                }
                AllowCmd::Path { glob, note } => {
                    scanner::glob_set(std::slice::from_ref(&glob))?;
                    let id = store.add_allow("path", &glob, None, note.as_deref())?;
                    println!("Added path rule #{id}: {glob} (critical findings still surface)");
                }
                AllowCmd::Remote { pattern, note } => {
                    let id = store.add_allow("remote", &pattern, None, note.as_deref())?;
                    println!("Added remote rule #{id}: {pattern} (critical findings still surface)");
                }
                AllowCmd::List => {
                    let rules = store.list_allow()?;
                    if rules.is_empty() {
                        println!("No allow rules.");
                    }
                    for r in rules {
                        let sha = r
                            .sha256
                            .as_deref()
                            .map(|s| format!(" sha256:{}…", &s[..12.min(s.len())]))
                            .unwrap_or_default();
                        println!(
                            "#{:<4} {:<6} {}{}{}",
                            r.id,
                            r.kind,
                            r.pattern,
                            sha,
                            r.note.map(|n| format!("  ({n})")).unwrap_or_default()
                        );
                    }
                }
                AllowCmd::Remove { id } => {
                    if store.remove_allow(id)? {
                        println!("Removed rule #{id}");
                    } else {
                        bail!("no rule #{id}");
                    }
                }
            }
            Ok(0)
        }
        Cmd::Quarantine => {
            let rows = store.list_quarantine()?;
            if rows.is_empty() {
                println!("Nothing quarantined. (Quarantine is off unless policy.quarantine_at is set.)");
            }
            for q in rows {
                println!(
                    "#{:<4} {} {}  {}\n      stored at {}",
                    q.id,
                    q.ts,
                    if q.restored { "[restored]" } else { "" },
                    q.original_path,
                    q.stored_path
                );
            }
            Ok(0)
        }
        Cmd::Restore { id } => {
            let p = policy::restore(id, &store)?;
            println!("Restored #{id} to {}", p.display());
            Ok(0)
        }
        Cmd::Audit { cmd } => {
            match cmd {
                AuditCmd::Show { limit } => {
                    for (id, ts, action, detail) in store.audit_entries(limit)? {
                        println!("{id:>6} {ts} {action:<12} {detail}");
                    }
                }
                AuditCmd::Verify => {
                    let n = store.audit_verify()?;
                    println!("Audit log intact: {n} entries verified.");
                }
            }
            Ok(0)
        }
        Cmd::Config { .. } => unreachable!(),
    }
}
