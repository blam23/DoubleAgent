//! Live monitor: native watcher (inotify / FSEvents / ReadDirectoryChangesW),
//! debounced and coalesced, with a periodic reconcile scan to catch dropped
//! events and a polling fallback.

use anyhow::Result;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::engine::{Engine, Outcome};
use crate::scanner::{self, Matcher};

/// A batch waits at most this many debounce periods, however busy the tree is.
const MAX_WAIT_DEBOUNCES: u32 = 4;

/// Work collected from watcher events.
#[derive(Debug, Default, PartialEq, Eq)]
struct Batch {
    /// Agent files that were created, changed or removed.
    files: HashSet<PathBuf>,
    /// Directories that appeared (a clone, an extracted archive, a folder moved in).
    dirs: HashSet<PathBuf>,
    /// Other paths that disappeared. They may have been directories holding agent files.
    gone: HashSet<PathBuf>,
}

/// Turns raw events into batches: keeps only the events that matter, waits for
/// `debounce` of quiet, but never longer than `max_wait` from the first event.
///
/// Only kept events restart the quiet period. Windows in particular reports a
/// steady stream of events from busy folders (AppData, build output), and a
/// "modified" event on every directory whose contents change; letting those
/// reset the timer, or walking those directories, starves real work.
struct Batcher {
    debounce: Duration,
    max_wait: Duration,
    batch: Batch,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Batcher {
    fn new(debounce: Duration) -> Batcher {
        Batcher {
            debounce,
            max_wait: debounce * MAX_WAIT_DEBOUNCES,
            batch: Batch::default(),
            first: None,
            last: None,
        }
    }

    fn add(&mut self, ev: &Event, matcher: &Matcher, now: Instant) {
        let appeared = matches!(
            ev.kind,
            EventKind::Create(_)
                | EventKind::Modify(ModifyKind::Name(RenameMode::To | RenameMode::Both | RenameMode::Any))
                | EventKind::Any
        );
        let vanished = matches!(
            ev.kind,
            EventKind::Remove(_)
                | EventKind::Modify(ModifyKind::Name(RenameMode::From | RenameMode::Both | RenameMode::Any))
                | EventKind::Any
        );
        let mut kept = false;
        for p in &ev.paths {
            if matcher.is_excluded(p) {
                continue;
            }
            let set = if matcher.is_candidate(p) {
                &mut self.batch.files
            } else if appeared && p.is_dir() {
                &mut self.batch.dirs
            } else if vanished && !p.exists() {
                &mut self.batch.gone
            } else {
                // A non-agent file changing, or a directory's own "modified" event:
                // neither can change a verdict, so drop it without touching the timer.
                continue;
            };
            set.insert(p.clone());
            kept = true;
        }
        if kept {
            self.first.get_or_insert(now);
            self.last = Some(now);
        }
    }

    fn take(&mut self, now: Instant) -> Option<Batch> {
        let (first, last) = (self.first?, self.last?);
        if now.duration_since(last) < self.debounce && now.duration_since(first) < self.max_wait {
            return None;
        }
        self.first = None;
        self.last = None;
        Some(std::mem::take(&mut self.batch))
    }

    fn clear(&mut self) {
        *self = Batcher::new(self.debounce);
    }
}

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

    let mut batcher = Batcher::new(Duration::from_millis(cfg.watch.debounce_ms.max(100)));
    let reconcile_every = Duration::from_secs(cfg.watch.reconcile_minutes.max(1) * 60);
    let mut last_reconcile = Instant::now();
    let mut need_full = false;

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(ev)) => {
                if ev.need_rescan() {
                    need_full = true;
                }
                batcher.add(&ev, engine.matcher, Instant::now());
            }
            Ok(Err(e)) => {
                eprintln!("watcher error: {e}; scheduling reconcile");
                need_full = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if need_full || last_reconcile.elapsed() >= reconcile_every {
            batcher.clear();
            need_full = false;
            reconcile(engine, roots, &mut on_outcome, "reconcile")?;
            last_reconcile = Instant::now();
            continue;
        }

        if let Some(batch) = batcher.take(Instant::now()) {
            apply(engine, batch, &mut on_outcome)?;
        }
    }
    drop(native);
    drop(poll);
    Ok(())
}

fn apply(engine: &Engine, batch: Batch, on_outcome: &mut impl FnMut(&Outcome, &str)) -> Result<()> {
    let mut candidates = HashSet::new();
    for p in batch.files {
        if p.exists() {
            candidates.insert(p);
        } else if engine.store.get_file(&p)?.is_some() {
            removed(engine, &p.to_string_lossy())?;
        }
    }
    if !batch.gone.is_empty() {
        let gone: Vec<PathBuf> = batch.gone.into_iter().collect();
        for p in engine.store.present_files_under(&gone)? {
            if !Path::new(&p).exists() {
                removed(engine, &p)?;
            }
        }
    }
    if !batch.dirs.is_empty() {
        let dirs: Vec<PathBuf> = batch.dirs.into_iter().collect();
        let (found, _) = scanner::walk(&dirs, &engine.cfg.scan, engine.matcher);
        candidates.extend(found);
    }
    if !candidates.is_empty() {
        let mut v: Vec<PathBuf> = candidates.into_iter().collect();
        v.sort();
        let out = engine.process_changed(v)?;
        on_outcome(&out, "change");
    }
    Ok(())
}

fn removed(engine: &Engine, path: &str) -> Result<()> {
    engine.store.mark_missing(path)?;
    engine.store.audit("removed", path)?;
    eprintln!("removed: {path}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use notify::event::{CreateKind, DataChange, RemoveKind};

    const DEBOUNCE: Duration = Duration::from_millis(300);

    fn ev(kind: EventKind, paths: &[&Path]) -> Event {
        paths.iter().fold(Event::new(kind), |e, p| e.add_path(p.to_path_buf()))
    }

    fn setup() -> (tempfile::TempDir, Matcher, Batcher, Instant) {
        let tmp = tempfile::tempdir().unwrap();
        (
            tmp,
            Matcher::new(&ScanConfig::default()).unwrap(),
            Batcher::new(DEBOUNCE),
            Instant::now(),
        )
    }

    const MODIFY: EventKind = EventKind::Modify(ModifyKind::Any);

    #[test]
    fn waits_for_quiet_then_flushes() {
        let (tmp, m, mut b, t0) = setup();
        let f = tmp.path().join("AGENTS.md");
        b.add(&ev(MODIFY, &[&f]), &m, t0);
        b.add(&ev(MODIFY, &[&f]), &m, t0 + Duration::from_millis(200));
        assert_eq!(b.take(t0 + Duration::from_millis(400)), None, "only 200ms since the last event");
        let batch = b.take(t0 + Duration::from_millis(500)).unwrap();
        assert_eq!(batch.files, HashSet::from([f]));
        assert_eq!(b.take(t0 + Duration::from_secs(5)), None, "batch was drained");
    }

    #[test]
    fn steady_agent_file_events_flush_after_max_wait() {
        let (tmp, m, mut b, t0) = setup();
        let f = tmp.path().join("AGENTS.md");
        let mut t = t0;
        let mut flushed_at = None;
        while t < t0 + Duration::from_secs(3) {
            b.add(&ev(MODIFY, &[&f]), &m, t);
            if b.take(t).is_some() {
                flushed_at = Some(t - t0);
                break;
            }
            t += Duration::from_millis(100);
        }
        assert_eq!(flushed_at, Some(DEBOUNCE * MAX_WAIT_DEBOUNCES));
    }

    #[test]
    fn noise_does_not_postpone_a_pending_change() {
        let (tmp, m, mut b, t0) = setup();
        let noise_dir = tmp.path().join("AppData");
        std::fs::create_dir(&noise_dir).unwrap();
        let noise_file = noise_dir.join("cache.bin");
        std::fs::write(&noise_file, "x").unwrap();
        let f = tmp.path().join("AGENTS.md");
        b.add(&ev(MODIFY, &[&f]), &m, t0);
        for i in 1..10 {
            let t = t0 + Duration::from_millis(30 * i);
            b.add(&ev(EventKind::Modify(ModifyKind::Data(DataChange::Any)), &[&noise_file]), &m, t);
            // ReadDirectoryChangesW also reports the parent directory as modified.
            b.add(&ev(MODIFY, &[&noise_dir]), &m, t);
            b.add(&ev(EventKind::Create(CreateKind::Any), &[&noise_file]), &m, t);
        }
        let batch = b.take(t0 + DEBOUNCE).expect("noise must not reset the quiet period");
        assert_eq!(
            batch,
            Batch {
                files: HashSet::from([f]),
                ..Batch::default()
            }
        );
    }

    #[test]
    fn noise_alone_never_schedules_work() {
        let (tmp, m, mut b, t0) = setup();
        let dir = tmp.path().join("build");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("out.o");
        std::fs::write(&file, "x").unwrap();
        b.add(&ev(MODIFY, &[&dir]), &m, t0);
        b.add(&ev(MODIFY, &[&file]), &m, t0);
        b.add(&ev(EventKind::Create(CreateKind::Any), &[&file]), &m, t0);
        assert_eq!(b.take(t0 + Duration::from_secs(10)), None);
    }

    #[test]
    fn new_directories_are_walked_but_modified_ones_are_not() {
        let (tmp, m, mut b, t0) = setup();
        let created = tmp.path().join("clone");
        let renamed = tmp.path().join("moved-in");
        let modified = tmp.path().join("existing");
        for d in [&created, &renamed, &modified] {
            std::fs::create_dir(d).unwrap();
        }
        b.add(&ev(EventKind::Create(CreateKind::Folder), &[&created]), &m, t0);
        b.add(&ev(EventKind::Modify(ModifyKind::Name(RenameMode::To)), &[&renamed]), &m, t0);
        b.add(&ev(MODIFY, &[&modified]), &m, t0);
        let batch = b.take(t0 + DEBOUNCE).unwrap();
        assert_eq!(batch.dirs, HashSet::from([created, renamed]));
    }

    #[test]
    fn vanished_paths_are_kept_for_removal() {
        let (tmp, m, mut b, t0) = setup();
        let moved_out = tmp.path().join("repo"); // never created: it is gone
        let deleted = tmp.path().join("old");
        let still_there = tmp.path().join("kept");
        std::fs::create_dir(&still_there).unwrap();
        let agent = tmp.path().join("sub").join("CLAUDE.md");
        b.add(&ev(EventKind::Modify(ModifyKind::Name(RenameMode::From)), &[&moved_out]), &m, t0);
        b.add(&ev(EventKind::Remove(RemoveKind::Any), &[&deleted, &still_there]), &m, t0);
        b.add(&ev(EventKind::Remove(RemoveKind::File), &[&agent]), &m, t0);
        let batch = b.take(t0 + DEBOUNCE).unwrap();
        assert_eq!(batch.gone, HashSet::from([moved_out, deleted]));
        assert_eq!(batch.files, HashSet::from([agent]));
    }

    #[test]
    fn rename_pair_and_untyped_events() {
        // inotify reports an in-tree rename as one event with [from, to]; polling and
        // some backends report EventKind::Any.
        let (tmp, m, mut b, t0) = setup();
        let from = tmp.path().join("a");
        let to = tmp.path().join("b");
        std::fs::create_dir(&to).unwrap();
        b.add(&ev(EventKind::Modify(ModifyKind::Name(RenameMode::Both)), &[&from, &to]), &m, t0);
        let other = tmp.path().join("c");
        std::fs::create_dir(&other).unwrap();
        b.add(&ev(EventKind::Any, &[&other]), &m, t0);
        let batch = b.take(t0 + DEBOUNCE).unwrap();
        assert_eq!(batch.gone, HashSet::from([from]));
        assert_eq!(batch.dirs, HashSet::from([to, other]));
    }

    #[test]
    fn excluded_paths_are_ignored() {
        let (tmp, m, mut b, t0) = setup();
        let f = tmp.path().join("node").join(".git").join("AGENTS.md");
        b.add(&ev(EventKind::Create(CreateKind::File), &[&f]), &m, t0);
        assert_eq!(b.take(t0 + Duration::from_secs(10)), None);
    }
}
