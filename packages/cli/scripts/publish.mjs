#!/usr/bin/env node
// Publish @typedstandards/cli (typedstandards#109). The owner runs it from a
// detached worktree at the merged commit:
//
//   node packages/cli/scripts/publish.mjs --merged <sha> --dry-run
//   node packages/cli/scripts/publish.mjs --merged <sha>
//
// It publishes nothing, and says why, when: `npm whoami` fails; the tree is dirty;
// HEAD is not the merged commit; the CHANGELOG's first heading is not this version
// dated today; the version is already on npm (a 404 on the package means the name
// was never published); or `npm pack --dry-run` lists a file outside `files`. Then
// it installs, builds and tests the package, and publishes (`npm publish
// --dry-run` under --dry-run).
//
// After a publish it waits for the registry, about five minutes with backoff; reads
// back the version, its bin and its dependency ranges; and runs the published
// `verify` on scripts/fixtures/published-verify.bundle.json from a clean temporary
// directory. If the wait ends first, the publish was sent and is not yet visible:
// re-run with --readback-only, never publish again.

import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_DIR = resolve(HERE, '..');
const FIXTURE = join(HERE, 'fixtures', 'published-verify.bundle.json');

const { values } = parseArgs({
  options: {
    merged: { type: 'string' },
    'dry-run': { type: 'boolean' },
    'readback-only': { type: 'boolean' },
    'wait-seconds': { type: 'string' },
  },
  strict: true,
  allowPositionals: false,
});

function stop(message) {
  console.error(`stopped: ${message}`);
  process.exit(1);
}

/** Run a command; captured unless `inherit`. */
function sh(command, args, { cwd = PKG_DIR, inherit = false } = {}) {
  const r = spawnSync(command, args, { cwd, encoding: 'utf8', stdio: inherit ? 'inherit' : 'pipe' });
  return { code: r.status, out: (r.stdout ?? '').trim(), err: (r.stderr ?? '').trim() };
}

function step(label) {
  console.log(`\n== ${label}`);
}

const manifest = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8'));
const { name, version } = manifest;
const REGISTRY_URL = `https://registry.npmjs.org/${name.replace('/', '%2f')}`;

/** The package document from the registry, or null when the name was never published. */
async function registryDocument() {
  const res = await fetch(REGISTRY_URL, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(30_000) });
  if (res.status === 404) return null;
  if (!res.ok) stop(`the registry answered ${res.status} for ${name}`);
  return res.json();
}

function today() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const stripDot = (p) => p.replace(/^\.\//, '');

async function checksBeforePublish() {
  step('npm whoami');
  const who = sh('npm', ['whoami']);
  if (who.code !== 0) stop(`npm whoami failed; log in with npm login first (${who.err.split('\n')[0] || 'no output'})`);
  console.log(`logged in as ${who.out}`);

  step('the tree');
  const root = sh('git', ['rev-parse', '--show-toplevel']);
  if (root.code !== 0) stop('not inside a git checkout');
  const dirty = sh('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: root.out });
  if (dirty.out) stop(`the tree is dirty:\n${dirty.out}`);
  if (!values.merged) stop('--merged <sha> is required: the merge commit this publishes');
  const head = sh('git', ['rev-parse', 'HEAD']).out;
  const merged = sh('git', ['rev-parse', '--verify', '--quiet', `${values.merged}^{commit}`]).out;
  if (!merged) stop(`--merged ${values.merged} is not a commit in this checkout`);
  if (head !== merged) stop(`HEAD is ${head}, not the merged commit ${merged}`);
  console.log(`clean, at ${head}`);

  step('the CHANGELOG');
  const heading = readFileSync(join(PKG_DIR, 'CHANGELOG.md'), 'utf8').split('\n').find((l) => l.startsWith('## '));
  const expected = `## ${version} — ${today()}`;
  if (heading !== expected) stop(`the CHANGELOG's first heading is "${heading ?? '(none)'}", not "${expected}"`);
  console.log(heading);

  step('the registry');
  const doc = await registryDocument();
  if (doc === null) console.log(`${name} is not on npm yet (404): this is the name's first publish`);
  else if (doc.versions?.[version]) stop(`${name}@${version} is already on npm`);
  else console.log(`${name} is on npm; ${version} is not`);

  const root2 = root.out;
  step('install, build, test');
  for (const [cmd, args, cwd] of [
    ['npm', ['ci', '--ignore-scripts'], root2],
    ['npm', ['run', 'build:verify-core'], root2],
    ['npm', ['run', 'build', '--workspace', name], root2],
    ['npm', ['run', 'test', '--workspace', name], root2],
  ]) {
    const r = sh(cmd, args, { cwd, inherit: true });
    if (r.code !== 0) stop(`${cmd} ${args.join(' ')} failed`);
  }

  step('npm pack --dry-run');
  const pack = sh('npm', ['pack', '--dry-run', '--json']);
  if (pack.code !== 0) stop(`npm pack --dry-run failed: ${pack.err}`);
  const files = JSON.parse(pack.out)[0].files.map((f) => f.path);
  const allowed = (manifest.files ?? []).map(stripDot);
  const outside = files.filter((f) => f !== 'package.json' && !allowed.some((a) => f === a || f.startsWith(`${a}/`)));
  if (outside.length) stop(`npm pack lists files outside "files" [${allowed.join(', ')}]: ${outside.join(', ')}`);
  console.log(`${files.length} files, all within "files" [${allowed.join(', ')}]`);
}

/** Run a CLI binary's verify on the fixture, copied into a clean temporary directory. */
function verifyFixture(bin, cwd) {
  copyFileSync(FIXTURE, join(cwd, 'bundle.json'));
  const r = spawnSync(process.execPath, [bin, 'verify', '--input', 'bundle.json', '--json'], { cwd, encoding: 'utf8', env: {} });
  if (r.status !== 0) stop(`verify exited ${r.status} on the fixture: ${r.stderr.trim()}`);
  const out = JSON.parse(r.stdout);
  if (out.ok !== true || out.lifecycle?.status !== 'withdrawn') {
    stop(`verify read the fixture as ok=${out.ok}, lifecycle ${out.lifecycle?.status}; expected ok, withdrawn`);
  }
  console.log(`verify: ok, nodeId ${out.nodeId}, lifecycle ${out.lifecycle.status}`);
}

async function readBack() {
  const waitSeconds = Number(values['wait-seconds'] ?? 300);
  step(`waiting for ${name}@${version} on the registry (up to ${waitSeconds}s)`);
  let doc = null;
  let waited = 0;
  for (const delay of [5, 10, 20, 30, 45, 60, 60, 70]) {
    doc = await registryDocument();
    if (doc?.versions?.[version]) break;
    if (waited >= waitSeconds) break;
    const d = Math.min(delay, waitSeconds - waited);
    console.log(`not visible yet; checking again in ${d}s`);
    await sleep(d);
    waited += d;
  }
  if (!doc?.versions?.[version]) {
    console.error(`sent, not yet visible: ${name}@${version} did not appear within ${waitSeconds}s. Re-run with --readback-only; do not publish again.`);
    process.exit(2);
  }

  step('read back');
  const published = doc.versions[version];
  const localBin = Object.fromEntries(Object.entries(manifest.bin ?? {}).map(([k, v]) => [k, stripDot(v)]));
  const remoteBin = Object.fromEntries(Object.entries(published.bin ?? {}).map(([k, v]) => [k, stripDot(v)]));
  console.log(`version ${published.version}\nbin ${JSON.stringify(remoteBin)}\ndependencies ${JSON.stringify(published.dependencies ?? {})}`);
  if (published.version !== version) stop(`the registry has ${published.version}, not ${version}`);
  if (JSON.stringify(remoteBin) !== JSON.stringify(localBin)) stop(`the published bin ${JSON.stringify(remoteBin)} is not ${JSON.stringify(localBin)}`);
  if (JSON.stringify(published.dependencies ?? {}) !== JSON.stringify(manifest.dependencies ?? {})) {
    stop(`the published dependencies ${JSON.stringify(published.dependencies)} are not ${JSON.stringify(manifest.dependencies)}`);
  }

  step('the published verify, from a clean temporary directory');
  const dir = mkdtempSync(join(tmpdir(), 'typedstandards-cli-published-'));
  try {
    let install = { code: 1 };
    for (const delay of [0, 30, 60]) {
      if (delay) await sleep(delay);
      install = sh('npm', ['install', '--no-audit', '--no-fund', '--prefix', dir, `${name}@${version}`], { cwd: dir });
      if (install.code === 0) break;
    }
    if (install.code !== 0) stop(`npm install ${name}@${version} failed in ${dir}: ${install.err.split('\n').slice(-3).join(' ')}`);
    const bin = join(dir, 'node_modules', ...name.split('/'), stripDot(manifest.bin.typedstandards));
    verifyFixture(bin, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(`\n${name}@${version} is on npm and its verify passes on the fixture.`);
}

if (values['readback-only']) {
  await readBack();
} else {
  await checksBeforePublish();
  if (values['dry-run']) {
    step('npm publish --dry-run');
    const r = sh('npm', ['publish', '--dry-run'], { inherit: true });
    if (r.code !== 0) stop('npm publish --dry-run failed');
    step('the local verify on the fixture, from a clean temporary directory');
    const dir = mkdtempSync(join(tmpdir(), 'typedstandards-cli-dry-'));
    try {
      verifyFixture(join(PKG_DIR, stripDot(manifest.bin.typedstandards)), dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    console.log('\ndry run: nothing was published.');
  } else {
    step('npm publish');
    const r = sh('npm', ['publish'], { inherit: true });
    if (r.code !== 0) stop('npm publish failed; check the registry before any retry (npm view @typedstandards/cli versions)');
    await readBack();
  }
}
