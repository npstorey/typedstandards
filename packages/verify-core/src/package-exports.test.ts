// Regression guard for the package exports map (civic-ai-tools-website#119 P2a / P4).
//
// The `.` export originally defined only `types` + `import`, so generic resolvers
// (plain `node`, `require`, `tsx`) hit ERR_PACKAGE_PATH_NOT_EXPORTED — a recurring
// blocker that bit Phase C and the P1 backfill. The `default` condition fixes it.
// This asserts the condition stays present (and last, as Node requires) so the fix
// can't silently regress. (Manual cross-check: `node --input-type=module -e
// "import('@typedstandards/verify-core')"` resolves with no flags.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { exports: Record<string, Record<string, string>> };

test('the `.` export resolves under generic conditions (default present, last)', () => {
  const dot = pkg.exports['.'];
  assert.ok(dot, 'package must export "."');
  assert.equal(dot.default, './dist/index.js', 'a `default` condition must resolve to dist');
  // Node matches conditions in order and requires `default` to be last.
  assert.equal(Object.keys(dot).at(-1), 'default', '`default` must be the last condition');
});
