// THROWAWAY — Wave N11 F-T's red instrument (civic-ai-tools-website#434, G41 D4). Never merged.
// Run by CI's `npm run test` because it sits under produce-core's src/.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8');

function ciRuns(): string[] {
  return [...read('.github/workflows/ci.yml').matchAll(/^\s*(?:-\s+)?run:[ \t]*(.+?)[ \t]*$/gm)].map((m) => m[1]);
}

/** The commands impl.md's report section lists, in the order it lists them. */
function implListed(): string[] {
  const md = read('.claude/agents/impl.md');
  const at = md.indexOf('every check CI gates on');
  assert.ok(at !== -1, 'PREMISE: impl.md still carries its gate-list sentence');
  const sentence = md.slice(at, md.indexOf('.\n', md.indexOf('npm run check:budgets', at)) + 1);
  return [...sentence.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

function frontmatter(path: string): string {
  const md = read(path);
  const m = /^---\n([\s\S]*?)\n---/.exec(md);
  assert.ok(m, `${path} has no frontmatter`);
  return m[1];
}

test('PREMISE: ci.yml and impl.md both yield a non-empty command sequence', () => {
  assert.ok(ciRuns().length >= 8, `ci.yml: ${ciRuns().length} run steps`);
  assert.ok(implListed().length >= 5, `impl.md: ${JSON.stringify(implListed())}`);
});

test("RED gate list: impl.md lists exactly the gate steps ci.yml runs after install, in ci.yml's order", () => {
  const gates = ciRuns().filter((c) => !/^npm ci\b/.test(c));
  assert.deepEqual(implListed(), gates);
});

test('RED effort: both agent definitions pin effort: high', () => {
  for (const p of ['.claude/agents/impl.md', '.claude/agents/cold-read.md']) {
    assert.match(frontmatter(p), /^effort:\s*high\s*$/m, `${p} carries no effort line`);
  }
});

test("RED purity clause: purity.md's typecheck bullet says a triple-slash Node reference defeats the typecheck, and names what catches it", () => {
  const md = read('.claude/rules/purity.md');
  const start = md.indexOf('- **Typecheck**');
  assert.ok(start !== -1, 'PREMISE: purity.md still carries its Typecheck bullet');
  const bullet = md.slice(start, md.indexOf('\n- **', start + 1));
  assert.match(bullet, /reference types=["']?node/);
});
