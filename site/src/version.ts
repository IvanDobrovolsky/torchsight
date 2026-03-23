import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let ver: string;
try {
  // Local dev / standard build
  ver = 'v' + readFileSync(join(__dirname, '..', '..', 'VERSION'), 'utf-8').trim();
} catch {
  try {
    // Cloudflare build (repo root is at different path)
    ver = 'v' + readFileSync(join(__dirname, '..', '..', '..', 'VERSION'), 'utf-8').trim();
  } catch {
    try {
      // Try process.cwd() as last resort
      ver = 'v' + readFileSync(join(process.cwd(), 'VERSION'), 'utf-8').trim();
    } catch {
      try {
        ver = 'v' + readFileSync(join(process.cwd(), '..', 'VERSION'), 'utf-8').trim();
      } catch {
        ver = 'v1.0.0-rc6';
      }
    }
  }
}

export const VERSION = ver;
