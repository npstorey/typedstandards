// THROWAWAY — Wave N11 P-T1's red instrument (civic-ai-tools-website#434, typedstandards#68).
// Never merged. Run by CI's `npm run test` because it sits under produce-core's src/.
//
// It reads the repository from the root and spawns the real tools (tsc, npm), so
// every assertion is about what the gates do, not about what a config file says.
// Node built-ins only; no bare import, so the dependency-budget checker is unaffected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const TSC = join(ROOT, 'node_modules/.bin/tsc');
type Core = { dir: string; name: string; injected: string };
const CORES: Core[] = [
  { dir: 'packages/produce-core', name: '@typedstandards/produce-core', injected: 'src/envelope.test.ts' },
  { dir: 'packages/verify-core', name: '@typedstandards/verify-core', injected: 'src/verify-core.test.ts' },
];

function run(cmd: string, args: string[]) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

// The universe: every test file on disk under a core's src/, derived, never listed.
function testFilesOf(core: Core): string[] {
  const src = join(ROOT, core.dir, 'src');
  return readdirSync(src, { recursive: true })
    .map(String)
    .filter((f) => f.endsWith('.test.ts'))
    .map((f) => join(src, f));
}

// The configs a core's `typecheck` script actually runs: every `-p <file>` / `--project <file>`.
function typecheckConfigsOf(core: Core) {
  const pkg = JSON.parse(readFileSync(join(ROOT, core.dir, 'package.json'), 'utf8'));
  const script = String(pkg.scripts?.typecheck ?? '');
  const configs = [...script.matchAll(/(?:-p|--project)\s+(\S+)/g)].map((m) => join(ROOT, core.dir, m[1]));
  return { script, configs };
}

// A probe that includes the test files, extending the core's own build config.
function probeConfigFor(core: Core): string {
  const d = mkdtempSync(join(tmpdir(), 'n11-pt1-'));
  const abs = join(ROOT, core.dir);
  const p = join(d, 'tsconfig.json');
  writeFileSync(
    p,
    JSON.stringify({
      extends: join(abs, 'tsconfig.json'),
      compilerOptions: { noEmit: true },
      include: [join(abs, 'src/**/*.ts')],
      exclude: [join(abs, 'dist'), join(abs, 'node_modules')],
    }),
  );
  return p;
}

for (const core of CORES) {
  test(`PREMISE ${core.dir}: the injected line in ${core.injected} IS a type error (a probe that includes tests reports TS2322 there)`, () => {
    const r = run(TSC, ['-p', probeConfigFor(core)]);
    assert.notEqual(r.status, 0, `probe tsc exited 0 — the injection does nothing:\n${r.out}`);
    assert.match(r.out, new RegExp(`${core.injected.replace(/[.]/g, '\\.')}\\(\\d+,\\d+\\): error TS2322`));
  });

  test(`PREMISE ${core.dir}: nothing the package publishes names a test file`, () => {
    const r = spawnSync('npm', ['pack', '--dry-run', '--json'], { cwd: join(ROOT, core.dir), encoding: 'utf8' });
    const files = JSON.parse(r.stdout)[0].files.map((f: { path: string }) => f.path);
    assert.ok(files.length > 0, 'npm pack listed no files — the instrument saw nothing');
    assert.deepEqual(files.filter((f: string) => f.includes('.test.')), []);
  });

  test(`RED #68 ${core.dir}: every test file on disk is in the program of a config the typecheck script runs`, () => {
    const tests = testFilesOf(core);
    assert.ok(tests.length > 0, 'derived zero test files — the instrument saw nothing');
    const { script, configs } = typecheckConfigsOf(core);
    assert.ok(configs.length > 0, `could not read a -p config from typecheck script "${script}"`);
    const inProgram = new Set<string>();
    for (const c of configs) {
      for (const line of run(TSC, ['-p', c, '--listFilesOnly']).out.split('\n')) inProgram.add(resolve(line.trim()));
    }
    const missing = tests.filter((t) => !inProgram.has(t)).map((t) => t.slice(ROOT.length + 1));
    assert.deepEqual(missing, [], `${missing.length} of ${tests.length} test files are type-checked by no config "${script}" runs`);
  });

  test(`RED #68 ${core.dir}: the package's own typecheck script fails on the injected type error`, () => {
    const r = run('npm', ['run', 'typecheck', '--workspace', core.name]);
    assert.notEqual(r.status, 0, `npm run typecheck exited 0 with a type error in ${core.injected}`);
    assert.match(r.out, new RegExp(core.injected.replace(/[.]/g, '\\.')));
  });
}

test('RED purity: verify-core shipped source reading `process` fails a gate (its typecheck script)', () => {
  const src = readFileSync(join(ROOT, 'packages/verify-core/src/index.ts'), 'utf8');
  assert.match(src, /process\.env\.N11_PT1_PURITY_PROBE/, 'PREMISE: the process read is present in shipped source');
  const r = run('npm', ['run', 'typecheck', '--workspace', '@typedstandards/verify-core']);
  assert.notEqual(r.status, 0, 'verify-core typecheck exited 0 with `process` read in shipped src (no lint exists for verify-core; browser-safety.test.ts checks imports and Buffer only)');
  assert.match(r.out, /src\/index\.ts\(\d+,\d+\): error TS/);
});

test('RED gate row: CLAUDE.md pins no pass count', () => {
  const md = readFileSync(join(ROOT, 'CLAUDE.md'), 'utf8');
  const pinned = md.split('\n').filter((l) => /# pass`? *[1-9]\d*/.test(l));
  assert.deepEqual(pinned, []);
});

test('RED D7: the typedstandards vocabulary copy reads "Analysis notebook (not executed)" and calls skeleton reserved nowhere', () => {
  const ts = readFileSync(join(ROOT, 'apps/web/src/lib/trust-signal.ts'), 'utf8');
  assert.match(ts, /label: 'Analysis notebook \(not executed\)'/);
  assert.doesNotMatch(ts, /'skeleton'` is reserved/);
});
