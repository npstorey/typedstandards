// Shared test helpers (no tests of its own). It is named *.test.ts so the build
// config leaves it out of dist/ and tsconfig.test.json type-checks it with Node's
// types.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

/** Run the built bin in a child process with an empty environment. */
export function host(args: string[], cwd?: string): { code: number | null; out: string; err: string } {
  assert.ok(existsSync(BIN), `${BIN} is missing: run \`npm run build --workspace @typedstandards/host-core\` first`);
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: {}, ...(cwd ? { cwd } : {}) });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
