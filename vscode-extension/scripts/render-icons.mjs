// Renders ../assets/icons/*.svg into the files the apps embed. Re-run after changing an SVG:
//   npm run render-icons
import { Resvg } from '@resvg/resvg-js';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const icons = join('..', 'assets', 'icons');
const png = (svg, size) => new Resvg(svg, { fitTo: { mode: 'width', value: size } }).render().asPng();
const read = (color) => readFileSync(join(icons, `doubleagent-${color}.svg`), 'utf8');

mkdirSync(join(icons, 'png'), { recursive: true });
for (const color of ['jade', 'yellow', 'red', 'grey']) {
  for (const size of [32, 256]) {
    writeFileSync(join(icons, 'png', `doubleagent-${color}-${size}.png`), png(read(color), size));
  }
}

// Windows .ico (PNG-compressed entries) from the default jade icon.
const sizes = [16, 24, 32, 48, 64, 128, 256];
const images = sizes.map((size) => png(read('jade'), size));
const header = Buffer.alloc(6 + 16 * sizes.length);
header.writeUInt16LE(1, 2); // type: icon
header.writeUInt16LE(sizes.length, 4);
let offset = header.length;
sizes.forEach((size, i) => {
  const at = 6 + 16 * i;
  header.writeUInt8(size === 256 ? 0 : size, at);
  header.writeUInt8(size === 256 ? 0 : size, at + 1);
  header.writeUInt16LE(1, at + 4); // planes
  header.writeUInt16LE(32, at + 6); // bits per pixel
  header.writeUInt32LE(images[i].length, at + 8);
  header.writeUInt32LE(offset, at + 12);
  offset += images[i].length;
});
writeFileSync(join(icons, 'doubleagent.ico'), Buffer.concat([header, ...images]));

// Marketplace / extension icon.
mkdirSync('media', { recursive: true });
writeFileSync(join('media', 'icon.png'), png(read('jade'), 256));
console.log('Rendered icons.');
