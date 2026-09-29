// Shared test helpers (no tests of its own). It is named *.test.ts so the build
// config leaves it out of dist/ and tsconfig.test.json type-checks it with Node's
// types.

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The oracle fixture, captured from the worked example's served docs/ at b40c30f (fixtures/core-satellite/README.md). */
export const FIXTURE = fileURLToPath(new URL('../fixtures/core-satellite/', import.meta.url));
export const INPUT = join(FIXTURE, 'input');
export const EXPECTED = join(FIXTURE, 'expected');

/** The built bin: the child-process tests drive what npm publishes. */
export const BIN = fileURLToPath(new URL('../dist/bin/main.js', import.meta.url));

/** Every file under `dir`, keyed by its `/`-separated path relative to `dir`. */
export function loadDir(dir: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else out.set(relative(dir, full).split(sep).join('/'), new Uint8Array(readFileSync(full)));
    }
  };
  walk(dir);
  return out;
}

export const readJson = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'));

export const text = (bytes: Uint8Array | undefined): string => (bytes === undefined ? '<absent>' : new TextDecoder().decode(bytes));
