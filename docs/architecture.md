# Rogue AGENTS.md Sentinel: Architecture

## 1. Problem framing

An `AGENTS.md` is an instruction file that coding agents read and obey automatically. Nested files typically override parent ones, so a planted file in a cloned repo, a dependency, or a downloaded archive can steer an agent into running commands or leaking secrets. "Rogue" means a file that is dangerous in **content**, suspicious in **provenance** (unexpected location, unknown origin), or **shadowing** a trusted file. The design scores these separately, because a clean-looking file inside `node_modules` is a different problem from a malicious file in your own repo.

## 2. High-level design

```
 ┌──────────────┐   ┌───────────────┐
 │ Initial Scan │   │ Live Monitor  │  inotify / FSEvents / ReadDirectoryChangesW
 │ (parallel    │   │ + periodic    │  + reconcile scan + polling fallback
 │  walker)     │   │ reconcile     │
 └──────┬───────┘   └──────┬────────┘
        └────────┬─────────┘
                 ▼
        ┌─────────────────┐
        │ Candidate Filter│  name patterns, size cap, allowlist/hash pins
        └────────┬────────┘
                 ▼
        ┌─────────────────┐     ┌──────────────────┐
        │ Context Enricher│────▶│  State Store     │
        │ git, parents,   │     │  (SQLite)        │
        │ symlinks, owner │     └──────────────────┘
        └────────┬────────┘              ▲
                 ▼                       │
        ┌─────────────────┐              │
        │ Static Analyzer │ deterministic rules, hidden-Unicode, URLs,
        │                 │ shell patterns → content score + findings
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Scoring Rules   │ provenance + shadow rules → final score
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Policy Engine   │ thresholds → actions
        └────────┬────────┘
                 ▼
   CLI / TUI / localhost dashboard / notifications / JSONL / webhook / SARIF
```

## 3. Components

**Language and packaging.** Rust or Go, shipped as a single static binary with subcommands (`scan`, `watch`, `report`, `allow`, `config`). Rust has the stronger watcher ecosystem (`notify`, `ignore`, `rusqlite`). Go is faster to build and equally portable.

**Scanner.**
- Parallel directory walker with ignore rules and cycle detection (symlinks, Windows junctions).
- Match filenames case-insensitively, since macOS and Windows are case-insensitive by default.
- The filename list is configurable: `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `copilot-instructions.md`, and so on.
- Do not descend into archives by default; offer opt-in `.zip`/`.tar` peeking.

**Monitor.**
- Native watchers per OS, debounced and coalesced.
- Watch limits and dropped events are real (inotify caps, buffer overflows), so a periodic reconcile scan compares mtime and file ID against the store, with polling as the fallback. Windows can use the NTFS USN journal for fast change detection.
- Watch directory creation events too, because a cloned repo arrives as a whole tree at once.

**State store (SQLite).** Per file: path, inode or file ID, size, mtime, SHA-256, first and last seen, verdict history, and user disposition (allowed, quarantined, ignored). Also an append-only audit log of scans and actions.

**Context enricher.** Computes provenance signals:
- Git root, remote URL, whether the file is tracked, and who last committed it.
- Whether it sits in a dependency or vendor directory (`node_modules`, `.venv`, `vendor`).
- The parent `AGENTS.md` chain, so the tool can flag **shadowing** (a nested file overriding a trusted one).
- Symlink target, file owner, and permissions.

**Static analyzer.** Cheap and deterministic. It detects:
- Hidden or invisible Unicode (zero-width characters, bidi controls, tag characters) and long base64 blobs.
- Shell patterns like `curl | sh`, and references to `.env`, SSH keys, or cloud credentials.
- Instructions to disable approvals or sandboxing, edit agent config, or add MCP servers.
- Unknown domains and classic "ignore previous instructions" phrasing.

It produces the content score and a list of findings, each with a rule ID.

**Policy engine.** Maps final severity to actions. Default is **report-only**. Optional actions are notify, run a hook, and quarantine (move to a holding directory with a restore command). Never delete. Allowlists are by path glob, repo remote, or **hash pin**, and a pinned file is re-reviewed automatically if its hash changes.

**Interfaces.** CLI and TUI first. The dashboard is bound to `127.0.0.1` only. Outputs include OS notifications, JSON Lines, syslog, webhooks, and SARIF for CI. The daemon runs as a systemd user unit, a launchd agent, or a Windows service, with a Unix socket or named pipe for CLI-to-daemon IPC.

## 4. Scoring model

Three scores combine into a final severity:

| Score | Source |
|---|---|
| Content risk | Static analyzer findings |
| Provenance risk | Context enricher and stored history (untracked, in dependencies, unknown remote, recent changes, repeated content revisions) |
| Shadow risk | Overrides or contradicts a trusted parent file |

Provenance and shadow are computed by a small rule engine: each rule is an ID, a target score, points, a type-checked condition over facts about the file, and a reason template. Built-in rules ship as data (`src/rules/scoring.toml`). The config can disable, replace or add rules and tune the combine weights (`[scoring]`), without a rebuild.

## 5. Privacy

Scanned content never leaves the machine except through outputs you configure. Webhook payloads have secret-shaped strings redacted (`[REDACTED:kind]`) before they are sent.

## 6. Cross-platform gotchas

- **Windows:** long paths, junctions and reparse points, and cloud placeholders (OneDrive). Never trigger hydration of online-only files.
- **macOS:** privacy prompts (TCC) for Documents, Desktop, and Downloads, so the tool needs a guided Full Disk Access flow.
- **Linux:** raise or detect inotify limits, and handle bind mounts and container overlays.
- **WSL:** watching `/mnt/c` from Linux is unreliable. Run the scanner on the Windows side and treat WSL filesystems as a separate root.
- **Network mounts:** excluded by default.

## 7. Tool self-defense

Read files by file descriptor and hash exactly the bytes you read, to avoid time-of-check/time-of-use races. Never execute or follow instructions in any scanned file. Run as the normal user, not root. Keep the audit log tamper-evident (hash-chained entries).

## 8. Suggested phases

1. Scanner, SQLite store, static analyzer, CLI report.
2. Live monitor, reconcile loop, allowlists and hash pins.
3. Daemon and service packaging, notifications, dashboard.
4. Quarantine, SARIF and CI mode.

## Open decisions

- Report-only by default (my recommendation), or should quarantine be on?
- Home directory only, or whole-disk scanning including system paths?

I can turn this into a shareable doc, flesh out the config schema, or scaffold the Rust or Go project if you'd like to go further.
