// Browser-safety guard for @typedstandards/produce-core.
//
// The package's load-bearing promise is that it is I/O-free and runs
// unchanged in a browser: no `node:crypto` / `fs` / `path` / `process` /
// `Buffer`, no `node:*` import. Cloned from verify-core's guard: the ESLint
// `no-restricted-imports` config in this package enforces the rule at lint
// time; this dependency-free test (it runs under the same `node --test` the
// rest of the suite uses, adding no devDependency) fails CI if a Node
// built-in ever creeps into the shipped source. Test files are exempt: they
// legitimately use `node:test` / `node:crypto` to build fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SRC_DIR = dirname(fileURLToPath(import.meta.url));

// Specifiers a browser-safe module must never import. `Buffer` is a global, not an
// import, so it is checked separately below.
const FORBIDDEN_SPECIFIERS = [
  'node:crypto',
  'crypto',
  'node:fs',
  'fs',
  'node:fs/promises',
  'fs/promises',
  'node:path',
  'path',
  'node:process',
  'process',
  'node:os',
  'node:url',
  'node:util',
];

function shippedSourceFiles(): string[] {
  return readdirSync(SRC_DIR)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .map((f) => join(SRC_DIR, f));
}

// Match the module specifier of any static/dynamic import or re-export.
const IMPORT_RE = /(?:import|export)\s[^'"`]*?from\s*['"]([^'"`]+)['"]|import\s*\(\s*['"]([^'"`]+)['"]\s*\)/g;

test('browser-safety: no shipped source imports a Node built-in', () => {
  const files = shippedSourceFiles();
  assert.ok(files.length > 5, 'expected to find the produce-core source files');

  for (const file of files) {
    const code = readFileSync(file, 'utf8');
    for (const m of code.matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2] ?? '';
      assert.ok(
        !FORBIDDEN_SPECIFIERS.includes(spec) && !spec.startsWith('node:'),
        `${file.split('/').pop()} imports "${spec}" — produce-core must stay browser-safe (use @typedstandards/verify-core primitives and keep I/O caller-side).`,
      );
    }
  }
});

// Match actual Buffer *usage* (`Buffer.from`, `Buffer(`, `new Buffer`), not the
// bare word — the source comments legitimately mention Buffer to explain why it
// is avoided.
const BUFFER_USE_RE = /\bnew\s+Buffer\b|\bBuffer\s*[.(]/;

test('browser-safety: no shipped source uses the Buffer global', () => {
  for (const file of shippedSourceFiles()) {
    const code = readFileSync(file, 'utf8');
    assert.ok(
      !BUFFER_USE_RE.test(code),
      `${file.split('/').pop()} uses Buffer — use atob / btoa / Uint8Array / TextDecoder / verify-core primitives instead.`,
    );
  }
});

// Determinism guard (the produce-side addition to verify-core's clone): the
// shipped source must not read a clock or an RNG — `packageId` / `createdAt`
// are caller-supplied inputs, which is what makes byte-golden fixtures
// possible.
const NONDETERMINISM_RE =
  /\bDate\.now\s*\(|\bnew\s+Date\s*\(|\bMath\.random\s*\(|\brandomUUID\s*\(|\bgetRandomValues\s*\(/;

test('determinism: no shipped source reads a clock or an RNG', () => {
  for (const file of shippedSourceFiles()) {
    const code = readFileSync(file, 'utf8');
    assert.ok(
      !NONDETERMINISM_RE.test(code),
      `${file.split('/').pop()} reads a clock/RNG — determinism inputs (packageId, createdAt) are caller-supplied in produce-core.`,
    );
  }
});
