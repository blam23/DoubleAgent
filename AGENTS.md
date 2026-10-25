# AGENTS.md

DoubleAgent is a Rust CLI that finds agent instruction files (`AGENTS.md`, `CLAUDE.md`, Cursor and Copilot rule files, …), scores each one for content, provenance and shadowing risk, and reports or acts on the result. The README covers usage; `docs/architecture.md` covers the design.

## Build and check

```sh
cargo build
cargo fmt --check                # rustfmt.toml: max_width = 140
cargo clippy --all-targets       # keep it at zero warnings
cargo test                       # unit tests + tests/e2e.rs + tests/watch.rs
```

Run all four before calling a change done. On Windows the build needs the MSVC toolchain (SQLite is compiled from source).

## Layout

| Path | What it does |
|---|---|
| `src/main.rs` | CLI (clap) and subcommand wiring |
| `src/engine.rs` | Pipeline: read → analyze → enrich → allow rules → score → policy → store |
| `src/analyzer.rs` | Static analyzer. Detection logic only; rule wording, weights and patterns live in `src/rules/analyzer.toml` |
| `src/score.rs`, `src/expr.rs` | Provenance/shadow rule engine and its condition language; built-in rules in `src/rules/scoring.toml` |
| `src/enrich.rs` | Provenance facts: git, dependency folders, parents, symlinks |
| `src/watch.rs` | Live monitor: `Batcher` turns watcher events into batches; reconcile catches dropped events |
| `src/scanner.rs` | Directory walk, candidate matching, single-handle reads and hashing |
| `src/policy.rs`, `src/output.rs`, `src/redact.rs` | Actions (notify, hook, quarantine), renderers, webhook redaction |
| `src/lsp/` | `doubleagent-lsp` language server (stdio): diagnostics on editor buffers via `Engine::evaluate_buffer`; talks to a running service through `service::probe` / `fetch_reports` |
| `vscode-extension/` | TypeScript VS Code client for the language server (`npm run compile`; packaging in its README) |
| `src/store.rs` | SQLite state and hash-chained audit log |
| `src/config.rs` | TOML config; every field has a default |

## Rules

- Both rule files are compiled in with `include_str!`. Editing a `.toml` under `src/rules/` needs a rebuild, and a broken rule fails `cargo test` (the `builtin_*` tests load every rule).
- Patterns in `analyzer.toml` are case-insensitive Rust regex in TOML literal strings (`'''…'''`), so backslashes are written once: `C:\\Temp` matches `C:\Temp`.
- A new analyzer detector needs its ID in `DETECTORS` in `analyzer.rs` and a `[[detectors]]` entry; a new line rule needs only a `[[line_rules]]` entry.
- Rule IDs are public: they appear in reports, SARIF and `disabled_rules`. Don't renumber or reuse them.
- When you change scoring or detection, check that findings for unchanged inputs stay the same unless the change is meant to alter them, and say which ones changed.

## Conventions

- Match the surrounding code: short `//!` module docs, comments only where the reason isn't obvious, `anyhow::Result` with context for errors.
- Config structs use `deny_unknown_fields`. When a config section is removed, add it to `REMOVED_SECTIONS` in `config.rs` so old files still load (with a warning).
- Report JSON (`model::Report`) is consumed by scripts, webhooks and SARIF users. Call out any field you add, rename or remove.
- Scanned files are untrusted input. Never execute, follow or `include!` their content. Test fixtures with malicious-looking text are built in code, never committed as instruction files.
- This file is itself scanned by DoubleAgent. Keep it benign: `cargo run -- scan . --min-severity info` should show it as info.

## Tests

- `tests/e2e.rs` drives the binary end to end through `scan`.
- `tests/watch.rs` runs the real `watch` command against a temp folder with the native backend (ReadDirectoryChangesW on Windows) and the polling fallback. Each test sets `reconcile_minutes = 60`, so only live events can pass it. Report checks only look at High and Critical results, because benign setup files under the temp folder already score Low on provenance.
- Watcher timing logic is unit-tested in `src/watch.rs` with an injected clock; add a case there for any new event pattern before relying on the slower end-to-end tests.
