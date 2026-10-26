# DoubleAgent for VS Code

Rates agent instruction files (`AGENTS.md`, `CLAUDE.md`, Cursor / Copilot / Windsurf rules, …) while you open and edit them, and shows what it finds as problems in the editor.

- **Diagnostics** on the exact lines that triggered a rule, plus one on line 1 when provenance or shadowing raises the risk. They update as you type, before you save.
- **Hover** line 1 for the score breakdown and provenance notes; hover a flagged line for the rule's reason and MITRE ATLAS technique.
- **Quick fix** "trust this exact content (pin hash)" and its inverse. The pin covers the saved content, so save first. If the file changes, the findings come back.
- **Explorer view** and **status bar** summarise every instruction file in the workspace, not just open ones.
- Files are only ever read. Nothing in them is executed or followed, and nothing is quarantined or deleted from the editor.

## How it finds its pieces

The extension starts `doubleagent-lsp` (a language server in this repository) over stdio. It looks for, in order: the `doubleagent.serverPath` setting, the binary bundled in the extension's `server/` folder, then `doubleagent-lsp` on your `PATH`. **No separate DoubleAgent install is needed** when using a packaged build.

It reads the same config and state database as the CLI and desktop app, so your thresholds, trusted domains, allow rules and pins apply. If you've never run DoubleAgent it uses a private database instead.

**A running DoubleAgent service is optional.** If the daemon or desktop app is listening on `127.0.0.1:47831`, the server notices (the status bar tooltip says so), shows the monitor's last verdict in the hover, and honours its allow rules for the same content. Turn that off with `doubleagent.useService`. Without a service everything still works.

## Building

```sh
cargo build --release --bin doubleagent-lsp
cd vscode-extension
npm install
npm run bundle-server          # copies ../target/release/doubleagent-lsp[.exe] into ./server
npm run package                # one VSIX for this platform
```

For other platforms build `doubleagent-lsp` there and run `vsce package --target <win32-x64|linux-x64|darwin-arm64|darwin-x64|…>`; `.github/workflows/vscode.yml` does this for Windows x64, Linux x64, and both macOS architectures. To try it, open this folder in VS Code and press F5, or install the VSIX.

## Settings

| Setting | Meaning |
|---|---|
| `doubleagent.serverPath` | Path to a `doubleagent-lsp` binary (machine-scoped; ignored in untrusted workspaces) |
| `doubleagent.configPath` | DoubleAgent config file (default: the per-user one) |
| `doubleagent.useService` | Use a running DoubleAgent service when there is one (default on) |
