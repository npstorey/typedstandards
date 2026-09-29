// The publish script's pure helpers (typedstandards#113 D12, #112).
// Run: node --test scripts/publish.test.mjs
// Not a CI step: the gate list is pinned by scripts/claude-md-gate-list.test.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PACKAGES,
  changelogHeadingProblem,
  expectedHeading,
  fetchRegistryDocument,
  filesOutside,
  headingCheckPackages,
  inRepoRanges,
  isFullSha,
  localDate,
  normalizeBin,
  oneLine,
  publishArgs,
  rangeAdmits,
  rangeProblems,
  readBackProblems,
  registryHeaders,
  registryUrl,
  waitDelays,
} from './publish-lib.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifestOf = (dir) => JSON.parse(readFileSync(join(ROOT, dir, 'package.json'), 'utf8'));

/** A fetch stub that records each request and answers with `status` and `body`. */
function recordingFetch(status, body = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return { status, ok: status >= 200 && status < 300, json: async () => body };
  };
  return { calls, fetchImpl };
}

// ---- the registry read (#112) ----

test('the registry URL carries a cache-busting query of the current time', () => {
  assert.equal(
    registryUrl('@typedstandards/verify-core', 179000000123),
    'https://registry.npmjs.org/@typedstandards%2fverify-core?t=179000000123',
  );
  assert.notEqual(registryUrl('@typedstandards/cli', 1), registryUrl('@typedstandards/cli', 2));
  assert.throws(() => registryUrl('@typedstandards/cli', undefined), TypeError);
});

test('the registry request headers ask for no-cache', () => {
  const h = registryHeaders();
  assert.equal(h['cache-control'], 'no-cache');
  assert.equal(h.accept, 'application/json');
});

test('every registry read sends the no-cache header and a fresh ?t= query', async () => {
  const { calls, fetchImpl } = recordingFetch(200, { versions: {} });
  let t = 179000000000;
  const now = () => (t += 1000);
  await fetchRegistryDocument('@typedstandards/produce-core', { fetchImpl, now });
  await fetchRegistryDocument('@typedstandards/produce-core', { fetchImpl, now });
  assert.equal(calls.length, 2);
  for (const { url, init } of calls) {
    const u = new URL(url);
    assert.equal(u.origin + u.pathname, 'https://registry.npmjs.org/@typedstandards%2fproduce-core');
    assert.match(u.searchParams.get('t') ?? '', /^\d+$/, `no cache-busting query on ${url}`);
    assert.equal(new Headers(init.headers).get('cache-control'), 'no-cache', `no no-cache header on ${url}`);
  }
  assert.notEqual(calls[0].url, calls[1].url, 'two reads share one URL, so a cache could answer the second');
});

test('a 404 reads as null; another failure throws', async () => {
  assert.equal(await fetchRegistryDocument('@typedstandards/cli', { fetchImpl: recordingFetch(404).fetchImpl }), null);
  await assert.rejects(fetchRegistryDocument('@typedstandards/cli', { fetchImpl: recordingFetch(503).fetchImpl }), /503/);
  const doc = { versions: { '0.2.0': {} } };
  assert.deepEqual(await fetchRegistryDocument('@typedstandards/cli', { fetchImpl: recordingFetch(200, doc).fetchImpl }), doc);
});

test('the script reads the registry only through fetchRegistryDocument', () => {
  const script = readFileSync(join(ROOT, 'scripts', 'publish.mjs'), 'utf8');
  assert.doesNotMatch(script, /\bfetch\s*\(/, 'publish.mjs calls fetch directly');
  assert.match(script, /fetchRegistryDocument\(/);
});

// ---- the CHANGELOG heading ----

test('the expected heading is the version, an em dash, and the date', () => {
  assert.equal(expectedHeading('0.13.0', '2026-09-27'), '## 0.13.0 — 2026-09-27');
});

test('the heading form matches the existing release headings', () => {
  const vc = readFileSync(join(ROOT, 'packages/verify-core/CHANGELOG.md'), 'utf8');
  assert.ok(vc.split('\n').includes(expectedHeading('0.12.0', '2026-09-24')), 'verify-core 0.12.0 heading form changed');
});

test('the CHANGELOG check passes only the version dated today, as the first ## heading', () => {
  const log = '# Changelog\n\nIntro.\n\n## 0.13.0 — 2026-09-27\n\n- x\n\n## 0.12.0 — 2026-09-24\n';
  assert.equal(changelogHeadingProblem(log, '0.13.0', '2026-09-27'), null);
  assert.match(changelogHeadingProblem(log, '0.13.0', '2026-09-28'), /not "## 0\.13\.0 — 2026-09-28"/, 'a heading dated another day passed');
  assert.match(changelogHeadingProblem(log, '0.14.0', '2026-09-27'), /first heading is "## 0\.13\.0/);
  assert.match(changelogHeadingProblem('# C\n\n## Unreleased\n\n## 0.13.0 — 2026-09-27\n', '0.13.0', '2026-09-27'), /"## Unreleased"/);
  assert.match(changelogHeadingProblem('## 0.13.0 - 2026-09-27\n', '0.13.0', '2026-09-27'), /not/, 'a hyphen passed for the em dash');
  assert.match(changelogHeadingProblem('# nothing\n', '0.13.0', '2026-09-27'), /"\(none\)"/);
});

test('the local date is YYYY-MM-DD in local time', () => {
  assert.equal(localDate(new Date(2026, 8, 27, 23, 59)), '2026-09-27');
  assert.equal(localDate(new Date(2026, 0, 5, 0, 0)), '2026-01-05');
});

// ---- the range check ----

test('a 0.x caret admits patches and excludes the next minor', () => {
  assert.equal(rangeAdmits('^0.12.0', '0.12.0').admits, true);
  assert.equal(rangeAdmits('^0.12.0', '0.12.3').admits, true);
  assert.equal(rangeAdmits('^0.12.0', '0.13.0').admits, false, 'a range that excludes the new version passed');
  assert.equal(rangeAdmits('^0.7.0', '0.8.0').admits, false);
  assert.equal(rangeAdmits('^0.13.0', '0.13.0').admits, true);
  assert.equal(rangeAdmits('^0.13.0', '0.12.9').admits, false);
  assert.equal(rangeAdmits('^0.0.3', '0.0.4').admits, false);
  assert.equal(rangeAdmits('^1.2.0', '1.9.0').admits, true);
  assert.equal(rangeAdmits('^1.2.0', '2.0.0').admits, false);
  assert.equal(rangeAdmits('~0.13.0', '0.13.4').admits, true);
  assert.equal(rangeAdmits('~0.13.0', '0.14.0').admits, false);
  assert.equal(rangeAdmits('0.13.0', '0.13.0').admits, true);
  assert.equal(rangeAdmits('0.13.0', '0.13.1').admits, false);
  assert.match(rangeAdmits('^0.12.0', '0.13.0').reason, /"\^0\.12\.0" excludes 0\.13\.0/);
});

test('a range form the check does not read fails closed', () => {
  for (const r of ['*', '>=0.12.0', '0.x', 'workspace:*', '^0.12', 'latest', '^0.12.0 || ^0.13.0']) {
    const res = rangeAdmits(r, '0.13.0');
    assert.equal(res.admits, false, r);
    assert.match(res.reason, /not a range form/, r);
  }
  assert.equal(rangeAdmits('^0.13.0', '0.13.0-rc.1').admits, false);
});

test('the range check names each in-repo range that excludes a version being published', () => {
  const ws = [
    { path: 'packages/produce-core', manifest: { dependencies: { '@typedstandards/verify-core': '^0.12.0', '@noble/curves': '^2.2.0' } } },
    { path: 'apps/web', manifest: { dependencies: { '@typedstandards/verify-core': '^0.13.0' }, devDependencies: { '@typedstandards/produce-core': '^0.7.0' } } },
  ];
  const published = { '@typedstandards/verify-core': '0.13.0', '@typedstandards/produce-core': '0.8.0' };
  assert.deepEqual(rangeProblems(ws, published), [
    'packages/produce-core dependencies @typedstandards/verify-core: "^0.12.0" excludes 0.13.0',
    'apps/web devDependencies @typedstandards/produce-core: "^0.7.0" excludes 0.8.0',
  ]);
  const fixed = structuredClone(ws);
  fixed[0].manifest.dependencies['@typedstandards/verify-core'] = '^0.13.0';
  fixed[1].manifest.devDependencies['@typedstandards/produce-core'] = '^0.8.0';
  assert.deepEqual(rangeProblems(fixed, published), []);
});

test('the in-repo ranges the check reads are the seven: the five D12 names and host-core\'s two', () => {
  const dirs = ['packages', 'apps'].flatMap((p) =>
    readdirSync(join(ROOT, p)).map((d) => `${p}/${d}`).filter((d) => existsSync(join(ROOT, d, 'package.json'))),
  );
  const ws = dirs.map((path) => ({ path, manifest: manifestOf(path) }));
  const published = Object.fromEntries(PACKAGES.map((p) => [p.name, manifestOf(p.dir).version]));
  const edges = inRepoRanges(ws, published).map((e) => `${e.from} ${e.field} ${e.dep}`).sort();
  assert.deepEqual(edges, [
    'apps/web dependencies @typedstandards/verify-core',
    'apps/web devDependencies @typedstandards/produce-core',
    'packages/cli dependencies @typedstandards/produce-core',
    'packages/cli dependencies @typedstandards/verify-core',
    'packages/host-core dependencies @typedstandards/produce-core',
    'packages/host-core dependencies @typedstandards/verify-core',
    'packages/produce-core dependencies @typedstandards/verify-core',
  ]);
});

// ---- the package order ----

test('the packages publish verify-core, then produce-core, then cli, then host-core', () => {
  assert.deepEqual(PACKAGES.map((p) => p.name), ['@typedstandards/verify-core', '@typedstandards/produce-core', '@typedstandards/cli', '@typedstandards/host-core']);
  for (const p of PACKAGES) assert.equal(manifestOf(p.dir).name, p.name);
  assert.ok(Object.isFrozen(PACKAGES));
});

test('each package publishes after every in-repo package it depends on', () => {
  const index = new Map(PACKAGES.map((p, i) => [p.name, i]));
  for (const [i, p] of PACKAGES.entries()) {
    for (const dep of Object.keys(manifestOf(p.dir).dependencies ?? {})) {
      if (index.has(dep)) assert.ok(index.get(dep) < i, `${p.name} publishes before its dependency ${dep}`);
    }
  }
});

// ---- the rest ----

test('npm publish takes --dry-run only in dry-run mode', () => {
  assert.deepEqual(publishArgs(true), ['publish', '--dry-run']);
  assert.deepEqual(publishArgs(false), ['publish']);
});

test('--merged must be a full 40-hex SHA', () => {
  assert.equal(isFullSha('64ee4188e274be49232dd13d86cdfbe6cdf4306a'), true);
  assert.equal(isFullSha('64ee418'), false);
  assert.equal(isFullSha('64EE4188E274BE49232DD13D86CDFBE6CDF4306A'), false);
  assert.equal(isFullSha('HEAD'), false);
  assert.equal(isFullSha(undefined), false);
});

test('the pack check names files outside "files"', () => {
  const files = ['dist', 'README.md', 'CHANGELOG.md', 'LICENSE'];
  assert.deepEqual(filesOutside(['package.json', 'dist/index.js', 'README.md', 'LICENSE', 'CHANGELOG.md'], files), []);
  assert.deepEqual(filesOutside(['package.json', 'dist/index.js', 'scripts/publish.mjs', 'distx/a.js'], files), ['scripts/publish.mjs', 'distx/a.js']);
});

test('the read-back compares version, ranges, bin and integrity', () => {
  const manifest = {
    name: '@typedstandards/cli',
    version: '0.2.0',
    bin: { typedstandards: './dist/bin/main.js' },
    dependencies: { '@typedstandards/verify-core': '^0.13.0', '@typedstandards/produce-core': '^0.8.0' },
    devDependencies: { typescript: '^5.9.3' },
  };
  const published = {
    version: '0.2.0',
    bin: { typedstandards: 'dist/bin/main.js' },
    dependencies: { '@typedstandards/produce-core': '^0.8.0', '@typedstandards/verify-core': '^0.13.0' },
    dist: { integrity: 'sha512-AAA' },
  };
  assert.deepEqual(readBackProblems(published, manifest, 'sha512-AAA'), []);
  assert.match(readBackProblems(published, manifest, 'sha512-BBB').join(), /dist\.integrity sha512-AAA is not the local pack's sha512-BBB/);
  assert.match(readBackProblems({ ...published, version: '0.1.0' }, manifest, 'sha512-AAA').join(), /version 0\.1\.0/);
  assert.match(
    readBackProblems({ ...published, dependencies: { '@typedstandards/verify-core': '^0.12.0', '@typedstandards/produce-core': '^0.8.0' } }, manifest, 'sha512-AAA').join(),
    /dependencies/,
  );
  assert.match(readBackProblems({ ...published, bin: { other: 'x.js' } }, manifest, 'sha512-AAA').join(), /bin/);
  assert.match(readBackProblems(published, manifest, undefined).join(), /no integrity/);
  const core = { name: '@typedstandards/verify-core', version: '0.13.0', dependencies: { canonicalize: '^3.0.0' } };
  assert.deepEqual(readBackProblems({ version: '0.13.0', dependencies: { canonicalize: '^3.0.0' }, dist: { integrity: 'sha512-C' } }, core, 'sha512-C'), []);
});

test('bin normalization', () => {
  assert.deepEqual(normalizeBin('./dist/bin/main.js', '@typedstandards/cli'), { cli: 'dist/bin/main.js' });
  assert.deepEqual(normalizeBin(undefined, 'x'), {});
});

test('the wait backs off and sums to about five minutes by default', () => {
  const d = waitDelays();
  assert.equal(d.reduce((a, b) => a + b, 0), 300);
  for (let i = 1; i < d.length - 1; i++) assert.ok(d[i] >= d[i - 1], 'the delays do not back off');
  assert.deepEqual(waitDelays(0), []);
  assert.deepEqual(waitDelays(12), [5, 7]);
});

test('a stop message is one line', () => {
  assert.equal(oneLine('a\n b\r\nc'), 'a; b; c');
});

// ---- #125 D13: the registry is read first; the heading check covers only unpublished versions ----

const VC = '@typedstandards/verify-core';
const PC = '@typedstandards/produce-core';
const CLI = '@typedstandards/cli';
const HOST = '@typedstandards/host-core';
const FOUR = [VC, PC, CLI, HOST].map((name) => ({ name, dir: `packages/${name.split('/')[1]}` }));
const VERSIONS = { [VC]: { version: '0.13.0' }, [PC]: { version: '0.8.0' }, [CLI]: { version: '0.2.0' }, [HOST]: { version: '0.1.0' } };
/** A registry package document listing `versions`. */
const docListing = (...versions) => ({ versions: Object.fromEntries(versions.map((v) => [v, { version: v }])) });
const namesOf = (packages) => packages.map((p) => p.name);

test('the CHANGELOG heading check covers only a version the registry does not show', () => {
  const docs = {
    [VC]: docListing('0.12.0', '0.13.0'),
    [PC]: docListing('0.7.0', '0.8.0'),
    [CLI]: docListing('0.1.0'),
    [HOST]: null,
  };
  assert.deepEqual(namesOf(headingCheckPackages(FOUR, VERSIONS, docs)), [CLI, HOST], 'a listed version was checked, or a 404 or an unlisted version was not');
  const allListed = { [VC]: docListing('0.13.0'), [PC]: docListing('0.8.0'), [CLI]: docListing('0.2.0'), [HOST]: docListing('0.1.0') };
  assert.deepEqual(headingCheckPackages(FOUR, VERSIONS, allListed), []);
  const none = { [VC]: null, [PC]: null, [CLI]: null, [HOST]: null };
  assert.deepEqual(namesOf(headingCheckPackages(FOUR, VERSIONS, none)), [VC, PC, CLI, HOST], 'the order changed');
  assert.deepEqual(namesOf(headingCheckPackages(FOUR, VERSIONS, { ...allListed, [HOST]: docListing('0.0.1') })), [HOST]);
});

test('the heading-check scope fails closed on a package the registry was not read for', () => {
  const read = { [VC]: docListing('0.13.0'), [PC]: docListing('0.8.0'), [CLI]: docListing('0.2.0') };
  assert.throws(() => headingCheckPackages(FOUR, VERSIONS, read), /host-core/);
  assert.throws(() => headingCheckPackages(FOUR, { ...VERSIONS, [HOST]: {} }, { ...read, [HOST]: null }), /host-core/);
});

test('a registry read fails closed: a non-OK answer other than 404, a network error, or a malformed body throws', async () => {
  const read = (fetchImpl) => fetchRegistryDocument(HOST, { fetchImpl });
  await assert.rejects(read(recordingFetch(500).fetchImpl), /500/);
  await assert.rejects(read(recordingFetch(403).fetchImpl), /403/);
  await assert.rejects(read(async () => { throw new TypeError('fetch failed'); }), /fetch failed/);
  const notJson = async () => ({ status: 200, ok: true, json: async () => { throw new SyntaxError('Unexpected token < in JSON at position 0'); } });
  await assert.rejects(read(notJson), /JSON/);
  for (const body of [null, [], 'x', 42, {}, { versions: null }, { versions: [] }, { versions: 'x' }]) {
    await assert.rejects(read(recordingFetch(200, body).fetchImpl), /malformed/, `a 200 with ${JSON.stringify(body)} read as a document`);
  }
});

test('main() reads the registry before the CHANGELOG check, and the check takes its scope from that read', () => {
  const script = readFileSync(join(ROOT, 'scripts', 'publish.mjs'), 'utf8');
  const main = script.slice(script.indexOf('async function main()'));
  const read = main.search(/\bregistryDocument\(/);
  const scope = main.search(/\bheadingCheckPackages\(/);
  const headings = main.search(/\bcheckChangelogs\(/);
  assert.ok(headings > 0, 'main() no longer calls checkChangelogs');
  assert.ok(read >= 0 && read < headings, 'main() checks the CHANGELOG headings before it reads the registry');
  assert.ok(scope > read && scope < headings, 'the heading check does not take its scope from the registry read');
});

test('the script states no fixed package count: its closing lines count PACKAGES', () => {
  const script = readFileSync(join(ROOT, 'scripts', 'publish.mjs'), 'utf8');
  assert.doesNotMatch(script, /\b(all|the) three\b/, 'a line still says "three"');
  assert.match(script, /PACKAGES\.length/);
});
