//! SQLite state store: files, verdict history, allow rules, quarantine
//! records and a hash-chained audit log.

use anyhow::{bail, Context as _, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::model::{Report, Severity};

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // full row kept for future `report` views
pub struct FileRow {
    pub path: String,
    pub file_id: String,
    pub size: u64,
    pub mtime: i64,
    pub sha256: String,
    pub first_seen: String,
    pub last_seen: String,
    pub last_severity: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AllowRule {
    pub id: i64,
    pub kind: String, // path | remote | pin
    pub pattern: String,
    pub sha256: Option<String>,
    pub note: Option<String>,
    pub created: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineRow {
    pub id: i64,
    pub original_path: String,
    pub stored_path: String,
    pub sha256: String,
    pub ts: String,
    pub restored: bool,
    /// Quarantined by hand from the desktop app rather than by policy.
    pub manual: bool,
    /// The verdict that led to the quarantine (findings and provenance).
    pub report: Option<Report>,
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn key(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS files(
               path TEXT PRIMARY KEY, file_id TEXT, size INTEGER, mtime INTEGER, sha256 TEXT,
               first_seen TEXT, last_seen TEXT, last_severity TEXT, last_score INTEGER, present INTEGER DEFAULT 1);
             CREATE TABLE IF NOT EXISTS content_revisions(
               id INTEGER PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, ts TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS content_revisions_path ON content_revisions(path, id);
             INSERT INTO content_revisions(path,sha256,ts)
               SELECT f.path,f.sha256,f.last_seen FROM files f
               WHERE f.sha256 IS NOT NULL AND NOT EXISTS(
                 SELECT 1 FROM content_revisions c WHERE c.path=f.path);
             CREATE TABLE IF NOT EXISTS verdicts(
               id INTEGER PRIMARY KEY, path TEXT, sha256 TEXT, ts TEXT, severity TEXT, score INTEGER, report TEXT);
             CREATE INDEX IF NOT EXISTS verdicts_path ON verdicts(path, id);
             DROP TABLE IF EXISTS ai_cache;
             DROP TABLE IF EXISTS ai_usage;
             CREATE TABLE IF NOT EXISTS allow_rules(id INTEGER PRIMARY KEY, kind TEXT, pattern TEXT, sha256 TEXT, note TEXT, created TEXT);
             CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, original_path TEXT, stored_path TEXT, sha256 TEXT, ts TEXT, restored INTEGER DEFAULT 0, manual INTEGER DEFAULT 0, report TEXT);
             CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT, prev_hash TEXT, hash TEXT);",
        )?;
        // Databases created before manual / report existed.
        for (column, ddl) in [("manual", "INTEGER DEFAULT 0"), ("report", "TEXT")] {
            let has: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('quarantine') WHERE name=?1",
                params![column],
                |r| r.get(0),
            )?;
            if !has {
                conn.execute_batch(&format!("ALTER TABLE quarantine ADD COLUMN {column} {ddl}"))?;
            }
        }
        Ok(Store { conn })
    }

    // ---------- files ----------
    pub fn get_file(&self, path: &Path) -> Result<Option<FileRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT path,file_id,size,mtime,sha256,first_seen,last_seen,last_severity FROM files WHERE path=?1",
                params![key(path)],
                |r| {
                    Ok(FileRow {
                        path: r.get(0)?,
                        file_id: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        size: r.get::<_, i64>(2)? as u64,
                        mtime: r.get(3)?,
                        sha256: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        first_seen: r.get(5)?,
                        last_seen: r.get(6)?,
                        last_severity: r.get(7)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn present_files_under(&self, roots: &[PathBuf]) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT path FROM files WHERE present=1")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for p in rows {
            let p = p?;
            if roots.iter().any(|r| Path::new(&p).starts_with(r)) {
                out.push(p);
            }
        }
        Ok(out)
    }

    pub fn mark_missing(&self, path: &str) -> Result<()> {
        self.conn.execute("UPDATE files SET present=0 WHERE path=?1", params![path])?;
        Ok(())
    }

    pub fn record_report(&self, r: &Report, file_id: &str, mtime: i64) -> Result<()> {
        let ts = &r.scanned_at;
        let p = key(&r.path);
        let previous_hash: Option<String> = self
            .conn
            .query_row("SELECT sha256 FROM files WHERE path=?1", params![p], |row| row.get(0))
            .optional()?;
        if previous_hash.as_deref() != Some(&r.sha256) {
            self.conn.execute(
                "INSERT INTO content_revisions(path,sha256,ts) VALUES(?1,?2,?3)",
                params![p, r.sha256, ts],
            )?;
        }
        self.conn.execute(
            "INSERT INTO files(path,file_id,size,mtime,sha256,first_seen,last_seen,last_severity,last_score,present)
             VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8,1)
             ON CONFLICT(path) DO UPDATE SET file_id=?2,size=?3,mtime=?4,sha256=?5,last_seen=?6,last_severity=?7,last_score=?8,present=1",
            params![
                p,
                file_id,
                r.size as i64,
                mtime,
                r.sha256,
                ts,
                r.severity.as_str(),
                r.scores.final_score as i64
            ],
        )?;
        // Only append verdict history when the content or verdict changed.
        let last: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT sha256, severity FROM verdicts WHERE path=?1 ORDER BY id DESC LIMIT 1",
                params![p],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if last.as_ref() != Some(&(r.sha256.clone(), r.severity.as_str().to_string())) {
            self.conn.execute(
                "INSERT INTO verdicts(path,sha256,ts,severity,score,report) VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    p,
                    r.sha256,
                    ts,
                    r.severity.as_str(),
                    r.scores.final_score as i64,
                    serde_json::to_string(r)?
                ],
            )?;
        } else {
            self.conn.execute(
                "UPDATE verdicts SET report=?2, ts=?3 WHERE id=(SELECT id FROM verdicts WHERE path=?1 ORDER BY id DESC LIMIT 1)",
                params![p, serde_json::to_string(r)?, ts],
            )?;
        }
        Ok(())
    }

    /// Latest report per present file.
    pub fn latest_reports(&self, min: Severity) -> Result<Vec<Report>> {
        let mut st = self.conn.prepare(
            "SELECT v.report FROM verdicts v JOIN files f ON f.path=v.path
             WHERE f.present=1 AND v.id=(SELECT MAX(id) FROM verdicts WHERE path=v.path)",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(rep) = serde_json::from_str::<Report>(&row?) {
                if rep.severity >= min {
                    out.push(rep);
                }
            }
        }
        out.sort_by(|a, b| b.scores.final_score.cmp(&a.scores.final_score).then(a.path.cmp(&b.path)));
        Ok(out)
    }

    pub fn history(&self, path: &Path) -> Result<Vec<(String, String, String, u32)>> {
        let mut st = self
            .conn
            .prepare("SELECT ts, sha256, severity, score FROM verdicts WHERE path=?1 ORDER BY id")?;
        let rows = st.query_map(params![key(path)], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? as u32))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Count distinct content revisions observed since an RFC3339 cutoff.
    /// Repeated verdicts for the same hash do not count as changes.
    pub fn content_changes_since(&self, path: &Path, cutoff: &str) -> Result<u32> {
        let mut st = self
            .conn
            .prepare("SELECT ts, sha256 FROM content_revisions WHERE path=?1 ORDER BY id")?;
        let rows = st.query_map(params![key(path)], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut previous: Option<String> = None;
        let mut changes = 0u32;
        for row in rows {
            let (ts, sha256) = row?;
            if previous.as_ref().is_some_and(|p| p != &sha256) && ts.as_str() >= cutoff {
                changes = changes.saturating_add(1);
            }
            previous = Some(sha256);
        }
        Ok(changes)
    }

    // ---------- allow rules ----------
    pub fn add_allow(&self, kind: &str, pattern: &str, sha256: Option<&str>, note: Option<&str>) -> Result<i64> {
        if kind == "pin" {
            self.conn
                .execute("DELETE FROM allow_rules WHERE kind='pin' AND pattern=?1", params![pattern])?;
        }
        self.conn.execute(
            "INSERT INTO allow_rules(kind,pattern,sha256,note,created) VALUES(?1,?2,?3,?4,?5)",
            params![kind, pattern, sha256, note, now()],
        )?;
        let id = self.conn.last_insert_rowid();
        self.audit("allow-add", &format!("{kind} {pattern} {}", sha256.unwrap_or("")))?;
        Ok(id)
    }
    pub fn list_allow(&self) -> Result<Vec<AllowRule>> {
        let mut st = self
            .conn
            .prepare("SELECT id,kind,pattern,sha256,note,created FROM allow_rules ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(AllowRule {
                id: r.get(0)?,
                kind: r.get(1)?,
                pattern: r.get(2)?,
                sha256: r.get(3)?,
                note: r.get(4)?,
                created: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
    pub fn remove_allow(&self, id: i64) -> Result<bool> {
        let n = self.conn.execute("DELETE FROM allow_rules WHERE id=?1", params![id])?;
        if n > 0 {
            self.audit("allow-remove", &id.to_string())?;
        }
        Ok(n > 0)
    }

    // ---------- quarantine ----------
    pub fn add_quarantine(&self, original: &Path, stored: &Path, sha: &str, manual: bool, report: Option<&Report>) -> Result<i64> {
        let report = report.map(serde_json::to_string).transpose()?;
        self.conn.execute(
            "INSERT INTO quarantine(original_path,stored_path,sha256,ts,manual,report) VALUES(?1,?2,?3,?4,?5,?6)",
            params![key(original), key(stored), sha, now(), manual, report],
        )?;
        Ok(self.conn.last_insert_rowid())
    }
    pub fn list_quarantine(&self) -> Result<Vec<QuarantineRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id,original_path,stored_path,sha256,ts,restored,manual,report FROM quarantine ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(QuarantineRow {
                id: r.get(0)?,
                original_path: r.get(1)?,
                stored_path: r.get(2)?,
                sha256: r.get(3)?,
                ts: r.get(4)?,
                restored: r.get::<_, i64>(5)? != 0,
                manual: r.get::<_, Option<i64>>(6)?.unwrap_or(0) != 0,
                report: r.get::<_, Option<String>>(7)?.and_then(|text| serde_json::from_str(&text).ok()),
            })
        })?;
        let mut rows: Vec<QuarantineRow> = rows.collect::<std::result::Result<_, _>>()?;
        // Entries from before the reason was stored: fall back to the verdict recorded for that content.
        for row in rows.iter_mut().filter(|row| row.report.is_none()) {
            row.report = self.verdict_for(&row.original_path, &row.sha256)?;
        }
        Ok(rows)
    }
    fn verdict_for(&self, path: &str, sha256: &str) -> Result<Option<Report>> {
        let text: Option<String> = self
            .conn
            .query_row(
                "SELECT report FROM verdicts WHERE path=?1 AND sha256=?2 ORDER BY id DESC LIMIT 1",
                params![path, sha256],
                |r| r.get(0),
            )
            .optional()?;
        Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
    }
    pub fn mark_restored(&self, id: i64) -> Result<()> {
        self.conn.execute("UPDATE quarantine SET restored=1 WHERE id=?1", params![id])?;
        Ok(())
    }

    // ---------- audit log (hash chained) ----------
    pub fn audit(&self, action: &str, detail: &str) -> Result<()> {
        let prev: String = self
            .conn
            .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let ts = now();
        let hash = chain_hash(&prev, &ts, action, detail);
        self.conn.execute(
            "INSERT INTO audit(ts,action,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)",
            params![ts, action, detail, prev, hash],
        )?;
        Ok(())
    }

    pub fn audit_entries(&self, limit: usize) -> Result<Vec<(i64, String, String, String)>> {
        let mut st = self
            .conn
            .prepare("SELECT id,ts,action,detail FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map(params![limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        let mut v: Vec<_> = rows.collect::<std::result::Result<_, _>>()?;
        v.reverse();
        Ok(v)
    }

    /// Returns number of entries verified, or an error naming the first broken link.
    pub fn audit_verify(&self) -> Result<usize> {
        let mut st = self
            .conn
            .prepare("SELECT id,ts,action,detail,prev_hash,hash FROM audit ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut prev = "0".repeat(64);
        let mut n = 0;
        for row in rows {
            let (id, ts, action, detail, p, h) = row?;
            if p != prev {
                bail!("audit chain broken at entry {id}: prev_hash does not match previous entry");
            }
            if chain_hash(&p, &ts, &action, &detail) != h {
                bail!("audit entry {id} was modified (hash mismatch)");
            }
            prev = h;
            n += 1;
        }
        Ok(n)
    }
}

fn chain_hash(prev: &str, ts: &str, action: &str, detail: &str) -> String {
    let mut h = Sha256::new();
    for part in [prev, ts, action, detail] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_content_changes_ignore_repeated_hashes_and_old_revisions() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE content_revisions(id INTEGER PRIMARY KEY, path TEXT, ts TEXT, sha256 TEXT)",
            [],
        )
        .unwrap();
        for (ts, hash) in [
            ("2026-10-01T00:00:00Z", "a"),
            ("2026-10-20T00:00:00Z", "b"),
            ("2026-10-21T00:00:00Z", "b"),
            ("2026-10-22T00:00:00Z", "c"),
            ("2026-10-23T00:00:00Z", "b"),
        ] {
            conn.execute("INSERT INTO content_revisions(path,ts,sha256) VALUES('f',?1,?2)", params![ts, hash])
                .unwrap();
        }
        let store = Store { conn };
        assert_eq!(store.content_changes_since(Path::new("f"), "2026-10-19T00:00:00Z").unwrap(), 3);
        assert_eq!(store.content_changes_since(Path::new("f"), "2026-10-22T12:00:00Z").unwrap(), 1);
    }
}
