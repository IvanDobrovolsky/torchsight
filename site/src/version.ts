import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const versionFile = join(__dirname, '..', '..', 'VERSION');

let ver: string;
try {
  ver = 'v' + readFileSync(versionFile, 'utf-8').trim();
} catch {
  ver = 'v1.0.0-rc5';
}

export const VERSION = ver;
