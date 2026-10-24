//! Live monitor: native watcher (inotify / FSEvents / ReadDirectoryChangesW),
//! debounced and coalesced, with a periodic reconcile scan to catch dropped
//! events and a polling fallback.

use anyhow::Result;
use notify::{Event, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::engine::{Engine, Outcome};
use crate::scanner;

pub fn run(engine: &Engine, roots: &[PathBuf], mut on_outcome: impl FnMut(&Outcome, &str)) -> Result<()> {
    let cfg = engine.cfg;
    check_inotify_limits();

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut native: Option<notify::RecommendedWatcher> = None;
    let mut poll: Option<notify::PollWatcher> = None;
    let mut mode = "native";

    if !cfg.watch.force_polling {
        match notify::recommended_watcher(tx.clone()) {
            Ok(mut w) => {
                let mut ok = true;
                for r in roots {
                    if let Err(e) = w.watch(r, RecursiveMode::Recursive) {
                        eprintln!("native watch failed for {}: {e}", r.display());
                        ok = false;
                        break;
                    }
                }
                if ok {
                    native = Some(w);
                }
            }
            Err(e) => eprintln!("native watcher unavailable: {e}"),
        }
    }
    if native.is_none() {
        mode = "polling";
        let pcfg = notify::Config::default().with_poll_interval(Duration::from_secs(cfg.watch.poll_interval_secs.max(2)));
        let mut w = notify::PollWatcher::new(tx.clone(), pcfg)?;
        for r in roots {
            w.watch(r, RecursiveMode::Recursive)?;
        }
        poll = Some(w);
    }
    eprintln!(
        "Watching {} root(s) with {mode} events; reconcile every {} min. Press Ctrl+C to stop.",
        roots.len(),
        cfg.watch.reconcile_minutes
    );

    // Initial reconcile so the store reflects the current state.
    reconcile(engine, roots, &mut on_outcome, "initial scan")?;

    let debounce = Duration::from_millis(cfg.watch.debounce_ms.max(100));
    let reconcile_every = Duration::from_secs(cfg.watch.reconcile_minutes.max(1) * 60);
    let mut last_reconcile = Instant::now();
    let mut pending: HashSet<PathBuf> = HashSet::new();
    let mut last_event = Instant::now();
    let mut need_full = false;

    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(ev)) => {
                if ev.need_rescan() {
                    need_full = true;
                }
                for p in ev.paths {
                    // Cheap pre-filter: candidate files, or directories (a whole clone can land at once).
                    if engine.matcher.is_excluded(&p) {
                        continue;
                    }
                    pending.insert(p);
                }
                last_event = Instant::now();
            }
            Ok(Err(e)) => {
                eprintln!("watcher error: {e}; scheduling reconcile");
                need_full = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if need_full || last_reconcile.elapsed() >= reconcile_every {
            pending.clear();
            need_full = false;
            reconcile(engine, roots, &mut on_outcome, "reconcile")?;
            last_reconcile = Instant::now();
            continue;
        }

        if !pending.is_empty() && last_event.elapsed() >= debounce {
            let batch: Vec<PathBuf> = pending.drain().collect();
            let mut candidates = HashSet::new();
            let mut dirs = Vec::new();
            for p in batch {
                if p.is_dir() {
                    dirs.push(p);
                } else if engine.matcher.is_candidate(&p) {
                    if p.exists() {
                        candidates.insert(p);
                    } else if engine.store.get_file(&p)?.is_some() {
                        engine.store.mark_missing(&p.to_string_lossy())?;
                        engine.store.audit("removed", &p.display().to_string())?;
                        eprintln!("removed: {}", p.display());
                    }
                }
            }
            if !dirs.is_empty() {
                let (found, _) = scanner::walk(&dirs, &cfg.scan, engine.matcher);
                candidates.extend(found);
            }
            if !candidates.is_empty() {
                let mut v: Vec<PathBuf> = candidates.into_iter().collect();
                v.sort();
                let out = engine.process(v)?;
                on_outcome(&out, "change");
            }
        }
    }
    drop(native);
    drop(poll);
    Ok(())
}

fn reconcile(engine: &Engine, roots: &[PathBuf], on_outcome: &mut impl FnMut(&Outcome, &str), label: &str) -> Result<()> {
    let (found, skipped) = scanner::walk(roots, &engine.cfg.scan, engine.matcher);
    let found_set: HashSet<String> = found.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    for p in engine.store.present_files_under(roots)? {
        if !found_set.contains(&p) {
            engine.store.mark_missing(&p)?;
            engine.store.audit("removed", &p)?;
        }
    }
    let mut out = engine.process(found)?;
    out.skipped.extend(skipped);
    on_outcome(&out, label);
    Ok(())
}

fn check_inotify_limits() {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches") {
            if let Ok(n) = s.trim().parse::<u64>() {
                if n < 65_536 {
                    eprintln!(
                        "warning: fs.inotify.max_user_watches is {n}. Large trees may exceed it; the reconcile scan still catches changes. \
                         Raise it with: sudo sysctl fs.inotify.max_user_watches=524288"
                    );
                }
            }
        }
    }
}
