// Browser-safety guard for @typedstandards/verify-core.
//
// The package's load-bearing promise is that it runs unchanged in a browser:
// no `node:crypto` / `fs` / `path` / `process` / `Buffer`, no `node:*` import.
// In civic-ai-tools-website this was enforced by an ESLint `no-restricted-imports`
// rule scoped to the verify-core directory. The source now lives here, so the
// guarantee moves here too — as a dependency-free test (it runs under the same
// `node --test` the rest of the suite uses, adding no devDependency) that fails
// CI if a Node built-in ever creeps into the shipped source. Test files are
// exempt: they legitimately use `node:test` / `node:crypto` to build fixtures.

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
  assert.ok(files.length > 5, 'expected to find the verify-core source files');

  for (const file of files) {
    const code = readFileSync(file, 'utf8');
    for (const m of code.matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2] ?? '';
      assert.ok(
        !FORBIDDEN_SPECIFIERS.includes(spec) && !spec.startsWith('node:'),
        `${file.split('/').pop()} imports "${spec}" — verify-core must stay browser-safe (use @noble/hashes / @noble/curves and inject network I/O).`,
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
      `${file.split('/').pop()} uses Buffer — use atob / Uint8Array / TextDecoder / @noble/hashes utils instead.`,
    );
  }
});
