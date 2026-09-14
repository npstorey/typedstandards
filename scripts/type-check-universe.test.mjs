// Guard: every test file in every workspace is type-checked by a config its
// `typecheck` script runs, and no config that emits contains a test file
// (typedstandards#68); and a published workspace's build configs resolve no
// Node type definitions, so the typecheck enforces the purity rule (second
// section below). Run: node --test scripts/type-check-universe.test.mjs
// (after `npm run build`: the pack check needs each published `dist/`).
//
// WHAT WAS MEASURED. At 1d24991 both cores' build configs excluded
// `src/**/*.test.ts` and each `typecheck` script ran only the build config, so
// 0 of 12 produce-core and 0 of 8 verify-core test files were in any program a
// gate ran. A type error injected into a test file of each core passed every CI
// step: build, test, typecheck, lint and both budget steps.
//
// THE FIX, AND WHY TWO CONFIGS. The build config emits `dist/`, and a core's
// `files` publishes `dist/`, so folding the tests into it would publish them.
// Each core's `tsconfig.test.json` extends the build config, emits nothing, and
// includes the tests; the `typecheck` script runs both.
//
// WHY THIS GUARD IS NOT A LIST. Every universe it checks is derived:
//   - workspaces: expanded from the root manifest's `workspaces` globs;
//   - test files: `git ls-files --cached --others --exclude-standard` under each
//     workspace, so a test file in a directory that does not exist yet is
//     covered the moment it is written, and ignored build output is not;
//   - configs a script runs: parsed out of that script's own `tsc` invocations;
//   - configs that could emit: every `tsconfig*.json` in the workspace directory
//     plus every config any of its scripts names;
//   - file sets: TypeScript's own config parser, resolved from the workspace's
//     own `typescript`, which is the code path `tsc -p` takes.
// The script-parsing extractor is itself driven over samples with the answers
// written out, so an extractor that returns nothing cannot pass.
//
// Blind spots, stated: a config reached only through `extends` from a file
// outside the workspace directory and named by no script is not enumerated;
// `tsc --build` invocations are refused rather than interpreted.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TEST_FILE_RE = /\.test\.[cm]?tsx?$/;
const rel = (p) => relative(ROOT, p);

// ---------------------------------------------------------------------------
// Extractors

/** The config paths every `tsc` invocation in an npm script compiles. */
export function tscConfigsOf(script, cwd) {
  const configs = [];
  for (const segment of String(script ?? '').split(/&&|\|\||;/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    const at = tokens[0] === 'npx' ? 1 : 0;
    if (tokens[at] !== 'tsc') continue;
    if (tokens.some((t) => t === '-b' || t === '--build')) {
      throw new Error(`tsc --build is not interpreted by this guard: "${segment.trim()}"`);
    }
    const flag = tokens.findIndex((t) => t === '-p' || t === '--project');
    let target = resolve(cwd, flag === -1 ? 'tsconfig.json' : tokens[flag + 1] ?? '');
    if (existsSync(target) && statSync(target).isDirectory()) target = join(target, 'tsconfig.json');
    configs.push(target);
  }
  return configs;
}

/** Workspace directories, expanded from the root manifest's `workspaces` globs. */
export function workspaceDirs(root = ROOT) {
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const dirs = [];
  for (const pattern of manifest.workspaces ?? []) {
    const m = /^([^*]+)\/\*$/.exec(pattern);
    if (!m) throw new Error(`workspace pattern "${pattern}" has a shape this guard does not expand`);
    const parent = join(root, m[1]);
    for (const entry of readdirSync(parent, { withFileTypes: true })) {
      if (entry.isDirectory() && existsSync(join(parent, entry.name, 'package.json'))) {
        dirs.push(join(parent, entry.name));
      }
    }
  }
  return dirs.sort();
}

function manifestOf(dir) {
  return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
}

function testFilesOf(dir) {
  const out = execFileSync(
    'git',
    ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', rel(dir)],
    { cwd: ROOT, encoding: 'utf8' },
  );
  return out
    .split('\0')
    .filter((f) => f && TEST_FILE_RE.test(f) && existsSync(join(ROOT, f)))
    .map((f) => join(ROOT, f))
    .sort();
}

/** The file set and options `tsc -p <config>` would use, from the workspace's own TypeScript. */
function parseConfig(dir, configPath) {
  const ts = createRequire(join(dir, 'package.json'))('typescript');
  const fatal = [];
  const parsed = ts.getParsedCommandLineOfConfigFile(configPath, {}, {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: (d) => fatal.push(d),
  });
  const errors = [...fatal, ...(parsed?.errors ?? [])].map(
    (d) => `TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, ' ')}`,
  );
  assert.deepEqual(errors, [], `${rel(configPath)} does not parse cleanly`);
  return { ts, parsed, fileNames: new Set(parsed.fileNames.map((f) => resolve(f))) };
}

/** Every config that could emit for a workspace: tsconfig*.json on disk, plus any config a script names. */
function candidateConfigsOf(dir) {
  const onDisk = readdirSync(dir)
    .filter((f) => /^tsconfig.*\.json$/.test(f))
    .map((f) => join(dir, f));
  const named = Object.values(manifestOf(dir).scripts ?? {}).flatMap((s) => tscConfigsOf(s, dir));
  return [...new Set([...onDisk, ...named])].filter((c) => existsSync(c)).sort();
}

// ---------------------------------------------------------------------------
// The extractor, driven over samples with the answers written out

test('extractor: tscConfigsOf reads every tsc invocation of a script, and nothing else', () => {
  const cwd = '/w';
  assert.deepEqual(tscConfigsOf('tsc -p tsconfig.json --noEmit && tsc -p tsconfig.test.json', cwd), [
    '/w/tsconfig.json',
    '/w/tsconfig.test.json',
  ]);
  assert.deepEqual(tscConfigsOf('tsc --noEmit', cwd), ['/w/tsconfig.json']);
  assert.deepEqual(tscConfigsOf('npx tsc --project cfg/tsconfig.x.json', cwd), ['/w/cfg/tsconfig.x.json']);
  assert.deepEqual(tscConfigsOf('eslint . && node --test "src/**/*.test.ts"', cwd), []);
  assert.deepEqual(tscConfigsOf(undefined, cwd), []);
  assert.throws(() => tscConfigsOf('tsc -b', cwd), /--build/);
});

test('extractor: workspaceDirs expands the real root manifest to real workspaces', () => {
  const dirs = workspaceDirs().map(rel);
  assert.ok(dirs.length >= 2, `derived ${dirs.length} workspaces`);
  for (const d of dirs) assert.ok(existsSync(join(ROOT, d, 'package.json')), d);
});

// ---------------------------------------------------------------------------
// #68

test('#68 PREMISE: every workspace with a test script has test files on disk, and a typecheck script that runs tsc', () => {
  for (const dir of workspaceDirs()) {
    const scripts = manifestOf(dir).scripts ?? {};
    if (!scripts.test) continue;
    assert.ok(testFilesOf(dir).length > 0, `${rel(dir)} has a test script and no test file was derived`);
    assert.ok(
      tscConfigsOf(scripts.typecheck, dir).length > 0,
      `${rel(dir)} has tests but its typecheck script runs no tsc: "${scripts.typecheck ?? ''}"`,
    );
  }
});

test('#68: every test file on disk is in a NON-EMITTING config that its typecheck script runs', () => {
  const uncovered = [];
  let seen = 0;
  for (const dir of workspaceDirs()) {
    const configs = tscConfigsOf(manifestOf(dir).scripts?.typecheck, dir);
    const covered = new Set();
    for (const config of configs) {
      const { parsed, fileNames } = parseConfig(dir, config);
      if (parsed.options.noEmit) for (const f of fileNames) covered.add(f);
    }
    for (const file of testFilesOf(dir)) {
      seen++;
      if (!covered.has(file)) uncovered.push(rel(file));
    }
  }
  assert.ok(seen > 0, 'derived zero test files: the instrument saw nothing');
  assert.deepEqual(
    uncovered,
    [],
    `${uncovered.length} of ${seen} test files are in no non-emitting config a typecheck script runs; ` +
      'a type error there passes every CI step',
  );
});

test('#68: no config that emits contains a test file', () => {
  let emitting = 0;
  const offenders = [];
  for (const dir of workspaceDirs()) {
    for (const config of candidateConfigsOf(dir)) {
      const { parsed, fileNames } = parseConfig(dir, config);
      if (parsed.options.noEmit) continue;
      emitting++;
      for (const f of fileNames) if (TEST_FILE_RE.test(f)) offenders.push(`${rel(config)}: ${rel(f)}`);
    }
  }
  assert.ok(emitting > 0, 'no emitting config was found anywhere: this assertion would be vacuous');
  assert.deepEqual(offenders, [], 'an emitting config carries test files, which the published dist would then contain');
});

test('#68: npm pack lists no test file for any published workspace', () => {
  const published = workspaceDirs().filter((d) => manifestOf(d).private !== true);
  assert.ok(published.length > 0, 'derived no published workspace');
  for (const dir of published) {
    const r = spawnSync('npm', ['pack', '--dry-run', '--json'], { cwd: dir, encoding: 'utf8' });
    assert.equal(r.status, 0, `npm pack --dry-run failed in ${rel(dir)}:\n${r.stderr}`);
    const files = JSON.parse(r.stdout)[0].files.map((f) => f.path);
    assert.ok(
      files.some((f) => f.startsWith('dist/') && f.endsWith('.js')),
      `${rel(dir)}: npm pack lists no dist/*.js, so this check could not see a test file; run npm run build first`,
    );
    assert.deepEqual(files.filter((f) => /\.test\./.test(f)), [], `${rel(dir)} would publish test files`);
  }
});

test("#68: CI's typecheck step runs every workspace's typecheck script", () => {
  const root = manifestOf(ROOT);
  assert.match(root.scripts?.typecheck ?? '', /npm run typecheck --workspaces\b/);
  const ci = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const runs = [...ci.matchAll(/^\s*(?:-\s+)?run:\s*(.+?)\s*$/gm)].map((m) => m[1]);
  assert.ok(runs.length > 0, 'read no run step from ci.yml: the instrument saw nothing');
  assert.ok(runs.includes('npm run typecheck'), `ci.yml runs no \`npm run typecheck\` step; its steps: ${runs.join(' | ')}`);
});

// ---------------------------------------------------------------------------
// Purity: shipped source of a published workspace cannot reach Node's types
//
// WHAT WAS MEASURED. At 1d24991 no build config set `types`, so TypeScript
// loaded every hoisted `node_modules/@types/*`, including `@types/node` (63
// files in each core's build program). `process` and `Buffer` therefore
// type-checked in shipped source. verify-core has no lint, and its
// browser-safety.test.ts checks imports and Buffer usage but not `process`: a
// `process.env` read appended to verify-core/src/index.ts passed every CI step.
//
// Universe: every emitting config of every non-private (published) workspace.

function emittingConfigsOfPublished() {
  const out = [];
  for (const dir of workspaceDirs().filter((d) => manifestOf(d).private !== true)) {
    for (const config of candidateConfigsOf(dir)) {
      const parsedConfig = parseConfig(dir, config);
      if (!parsedConfig.parsed.options.noEmit) out.push({ dir, config, ...parsedConfig });
    }
  }
  assert.ok(out.length > 0, 'derived no emitting config of a published workspace: these assertions would be vacuous');
  return out;
}

/** Diagnostics for one in-memory source file compiled under a config's options. */
function diagnoseVirtual(ts, parsed, fileName, text) {
  const host = ts.createCompilerHost(parsed.options);
  const { getSourceFile, fileExists, readFile } = host;
  const isProbe = (f) => resolve(f) === fileName;
  host.getSourceFile = (f, language, ...rest) =>
    isProbe(f) ? ts.createSourceFile(f, text, language, true) : getSourceFile.call(host, f, language, ...rest);
  host.fileExists = (f) => isProbe(f) || fileExists.call(host, f);
  host.readFile = (f) => (isProbe(f) ? text : readFile.call(host, f));
  const program = ts.createProgram({ rootNames: [fileName], options: parsed.options, host });
  return ts.getPreEmitDiagnostics(program).map((d) => ({
    code: d.code,
    line: d.file && d.start !== undefined ? d.file.getLineAndCharacterOfPosition(d.start).line + 1 : 0,
    file: d.file ? resolve(d.file.fileName) : '',
    text: ts.flattenDiagnosticMessageText(d.messageText, ' '),
  }));
}

test('purity: every config a published workspace builds with is also run by its typecheck script', () => {
  for (const dir of workspaceDirs().filter((d) => manifestOf(d).private !== true)) {
    const { build, typecheck } = manifestOf(dir).scripts ?? {};
    const built = tscConfigsOf(build, dir);
    assert.ok(built.length > 0, `${rel(dir)} is published and its build script runs no tsc: "${build ?? ''}"`);
    const checked = new Set(tscConfigsOf(typecheck, dir));
    assert.deepEqual(built.filter((c) => !checked.has(c)).map(rel), [], `${rel(dir)}: built but not type-checked`);
  }
});

test('purity: no emitting config of a published workspace resolves Node type definitions', () => {
  for (const { dir, config, ts, parsed } of emittingConfigsOfPublished()) {
    assert.ok(parsed.fileNames.length > 0, `${rel(config)} compiles no file`);
    const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
    const nodeTypes = program
      .getSourceFiles()
      .map((sf) => resolve(sf.fileName))
      .filter((f) => f.includes(`${join('node_modules', '@types', 'node')}/`));
    assert.deepEqual(
      nodeTypes.map((f) => relative(dir, f)).slice(0, 3),
      [],
      `${rel(config)} loads ${nodeTypes.length} @types/node files, so \`process\` and \`Buffer\` type-check in shipped source`,
    );
  }
});

test('purity: a `process` read, a `Buffer` use, or a Node built-in import in shipped source is a type error', () => {
  for (const { config, ts, parsed } of emittingConfigsOfPublished()) {
    const srcDir = parsed.options.rootDir ?? dirname(config);

    // Control: browser-safe code under the same options produces no diagnostic,
    // so a red below is the probe's content and not a broken instrument.
    const control = diagnoseVirtual(ts, parsed, join(srcDir, '__purity-control__.ts'),
      "export const ok = new TextEncoder().encode(atob('cHJvYmU='));\n");
    assert.deepEqual(control, [], `${rel(config)}: the control probe does not type-check cleanly`);

    const probe = join(srcDir, '__purity-probe__.ts');
    const diagnostics = diagnoseVirtual(ts, parsed, probe, [
      'export const env = process.env.PURITY_PROBE;',
      "export const bytes = Buffer.from('probe');",
      "export { readFileSync } from 'node:fs';",
      '',
    ].join('\n'));
    const onLine = (n) => diagnostics.filter((d) => d.file === probe && d.line === n);
    assert.ok(onLine(1).some((d) => /'process'/.test(d.text)), `${rel(config)}: a \`process\` read type-checks: ${JSON.stringify(diagnostics)}`);
    assert.ok(onLine(2).some((d) => /'Buffer'/.test(d.text)), `${rel(config)}: a \`Buffer\` use type-checks: ${JSON.stringify(diagnostics)}`);
    assert.ok(onLine(3).some((d) => /'node:fs'/.test(d.text)), `${rel(config)}: a node:fs import type-checks: ${JSON.stringify(diagnostics)}`);
  }
});
