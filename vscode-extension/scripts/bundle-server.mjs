// Copies a built doubleagent-lsp binary into ./server so `vsce package` ships it.
//   cargo build --release --bin doubleagent-lsp
//   npm run bundle-server                       (uses ../target/release)
//   node scripts/bundle-server.mjs <path-to-binary>   (e.g. a cross-compiled one)
import { chmodSync, copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const exe = process.platform === 'win32' ? 'doubleagent-lsp.exe' : 'doubleagent-lsp';
const source = resolve(process.argv[2] ?? join('..', 'target', 'release', exe));
if (!existsSync(source)) {
  console.error(`No binary at ${source}. Build it first: cargo build --release --bin doubleagent-lsp`);
  process.exit(1);
}
mkdirSync('server', { recursive: true });
const target = join('server', basename(source).startsWith('doubleagent-lsp') ? basename(source) : exe);
copyFileSync(source, target);
if (process.platform !== 'win32') chmodSync(target, 0o755);
console.log(`Bundled ${source} -> ${target}`);
