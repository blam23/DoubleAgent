import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { LanguageClient, LanguageClientOptions, ServerOptions } from 'vscode-languageclient/node';

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface Summary {
  files: number;
  counts: Record<Severity, number>;
  service: boolean;
}

interface FindingRow {
  ruleId: string;
  title: string;
  severity: Severity;
  line: number;
  reason: string;
}

interface ReportRow {
  uri: string;
  path: string;
  severity: Severity;
  score: number;
  suppressed: boolean;
  disposition: string | null;
  findings: FindingRow[];
  notes: string[];
}

type Node =
  | { kind: 'file'; row: ReportRow }
  | { kind: 'finding'; row: ReportRow; finding: FindingRow }
  | { kind: 'note'; text: string };

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

let client: LanguageClient | undefined;
let log: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let tree: FindingsProvider;

/** The configured binary, else the one shipped in this extension, else PATH. */
function serverCommand(context: vscode.ExtensionContext): string {
  const exe = process.platform === 'win32' ? 'doubleagent-lsp.exe' : 'doubleagent-lsp';
  const configured = vscode.workspace.getConfiguration('doubleagent').get<string>('serverPath', '').trim();
  if (configured) return configured;
  const target = `${process.platform}-${process.arch}`;
  const bundled = context.asAbsolutePath(path.join('server', target, exe));
  return fs.existsSync(bundled) ? bundled : 'doubleagent-lsp';
}

function serverArgs(): string[] {
  const settings = vscode.workspace.getConfiguration('doubleagent');
  const args: string[] = [];
  const config = settings.get<string>('configPath', '').trim();
  if (config) args.push('--config', config);
  if (!settings.get<boolean>('useService', true)) args.push('--no-service');
  return args;
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  const command = serverCommand(context);
  const serverOptions: ServerOptions = { command, args: serverArgs() };
  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: 'file' }],
    outputChannel: log,
    synchronize: {
      // The server decides which of these are agent instruction files.
      fileEvents: vscode.workspace.createFileSystemWatcher('**/{*.md,*.mdc,.cursorrules,.windsurfrules,.clinerules,.goosehints}'),
    },
  };
  const next = new LanguageClient('doubleagent', 'DoubleAgent', serverOptions, clientOptions);
  next.onNotification('doubleagent/summary', (summary: Summary) => {
    showSummary(summary);
    tree.refresh();
  });
  client = next;
  try {
    await next.start();
  } catch (error) {
    client = undefined;
    setStatus('$(shield) DoubleAgent: not running', 'The language server could not start. Click for details.');
    const pick = await vscode.window.showErrorMessage(
      `DoubleAgent could not start "${command}". Build it with "cargo build --release --bin doubleagent-lsp" and set doubleagent.serverPath, or put it on your PATH. (${error})`,
      'Show log',
    );
    if (pick) log.show();
  }
}

async function restart(context: vscode.ExtensionContext): Promise<void> {
  const old = client;
  client = undefined;
  tree.refresh();
  if (old) await old.stop().catch(() => undefined);
  await startClient(context);
}

function setStatus(text: string, tooltip: string, background?: string): void {
  status.text = text;
  status.tooltip = tooltip;
  status.backgroundColor = background ? new vscode.ThemeColor(background) : undefined;
  status.show();
}

function showSummary(summary: Summary): void {
  const worst = ORDER.find((s) => summary.counts[s] > 0 && s !== 'info');
  const service = summary.service ? 'Connected to the DoubleAgent service.' : 'No DoubleAgent service running (not required).';
  const checked = `${summary.files} instruction file${summary.files === 1 ? '' : 's'} checked.`;
  if (!worst) {
    setStatus('$(shield) DoubleAgent', `${checked} Nothing to review.\n${service}`);
    return;
  }
  const flagged = ORDER.filter((s) => s !== 'info' && summary.counts[s] > 0)
    .map((s) => `${summary.counts[s]} ${s}`)
    .join(', ');
  const background = worst === 'critical' || worst === 'high' ? 'statusBarItem.errorBackground' : worst === 'medium' ? 'statusBarItem.warningBackground' : undefined;
  setStatus(`$(shield) DoubleAgent: ${flagged}`, `${checked}\n${service}`, background);
}

class FindingsProvider implements vscode.TreeDataProvider<Node> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;
  private rows: ReportRow[] = [];
  private timer: NodeJS.Timeout | undefined;

  refresh(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(async () => {
      this.rows = client?.isRunning() ? await client.sendRequest<ReportRow[]>('doubleagent/reports').catch(() => []) : [];
      this.changed.fire();
    }, 150);
  }

  getTreeItem(node: Node): vscode.TreeItem {
    switch (node.kind) {
      case 'file': {
        const { row } = node;
        const item = new vscode.TreeItem(path.basename(row.path), row.findings.length || row.notes.length ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
        item.description = row.suppressed ? `trusted · ${row.disposition ?? ''}` : `${row.severity} · ${row.score}`;
        item.tooltip = `${row.path}\n${row.disposition ?? ''}`.trim();
        item.resourceUri = vscode.Uri.parse(row.uri);
        item.iconPath = icon(row.suppressed ? 'info' : row.severity, row.suppressed);
        item.command = { command: 'vscode.open', title: 'Open', arguments: [vscode.Uri.parse(row.uri)] };
        return item;
      }
      case 'finding': {
        const { finding, row } = node;
        const item = new vscode.TreeItem(`${finding.ruleId} ${finding.title}`);
        item.description = `line ${finding.line + 1}`;
        item.tooltip = finding.reason;
        item.iconPath = icon(finding.severity, false);
        const at = new vscode.Range(finding.line, 0, finding.line, 0);
        item.command = { command: 'vscode.open', title: 'Open', arguments: [vscode.Uri.parse(row.uri), { selection: at }] };
        return item;
      }
      case 'note': {
        const item = new vscode.TreeItem(node.text);
        item.tooltip = node.text;
        item.iconPath = new vscode.ThemeIcon('git-branch');
        return item;
      }
    }
  }

  getChildren(node?: Node): Node[] {
    if (!node) return this.rows.map((row) => ({ kind: 'file', row }));
    if (node.kind !== 'file') return [];
    return [
      ...node.row.findings.map((finding): Node => ({ kind: 'finding', row: node.row, finding })),
      ...node.row.notes.map((text): Node => ({ kind: 'note', text })),
    ];
  }
}

function icon(severity: Severity, trusted: boolean): vscode.ThemeIcon {
  if (trusted) return new vscode.ThemeIcon('verified', new vscode.ThemeColor('testing.iconPassed'));
  switch (severity) {
    case 'critical':
    case 'high':
      return new vscode.ThemeIcon('error', new vscode.ThemeColor('list.errorForeground'));
    case 'medium':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground'));
    case 'low':
      return new vscode.ThemeIcon('info');
    default:
      return new vscode.ThemeIcon('pass');
  }
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  log = vscode.window.createOutputChannel('DoubleAgent');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = 'doubleagent.findings.focus';
  tree = new FindingsProvider();
  context.subscriptions.push(
    log,
    status,
    vscode.window.registerTreeDataProvider('doubleagent.findings', tree),
    vscode.commands.registerCommand('doubleagent.rescan', () => client?.sendNotification('doubleagent/rescan')),
    vscode.commands.registerCommand('doubleagent.restart', () => restart(context)),
    vscode.commands.registerCommand('doubleagent.showLog', () => log.show()),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('doubleagent')) void restart(context);
    }),
  );
  setStatus('$(shield) DoubleAgent', 'Starting…');
  await startClient(context);
}

export async function deactivate(): Promise<void> {
  await client?.stop();
}
