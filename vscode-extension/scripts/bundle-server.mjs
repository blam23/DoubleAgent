// Copies a built doubleagent-lsp binary into ./server/<target> for platform-specific VSIXs.
//   cargo build --release --bin doubleagent-lsp
//   npm run bundle-server                            (uses ../target/release and detects this platform)
//   node scripts/bundle-server.mjs <path> <target>   (e.g. a cross-compiled one)
import { chmodSync, copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const exe = process.platform === 'win32' ? 'doubleagent-lsp.exe' : 'doubleagent-lsp';
const source = resolve(process.argv[2] ?? join('..', 'target', 'release', exe));
const target = process.argv[3] ?? `${process.platform}-${process.arch}`;
if (!existsSync(source)) {
  console.error(`No binary at ${source}. Build it first: cargo build --release --bin doubleagent-lsp`);
  process.exit(1);
}
const targetDir = join('server', target);
mkdirSync(targetDir, { recursive: true });
const destination = join(targetDir, basename(source).startsWith('doubleagent-lsp') ? basename(source) : exe);
copyFileSync(source, destination);
if (!destination.endsWith('.exe')) chmodSync(destination, 0o755);
console.log(`Bundled ${source} -> ${destination}`);
