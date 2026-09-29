#!/usr/bin/env node
// Publish the packages PACKAGES lists (scripts/publish-lib.mjs), in its order:
// @typedstandards/verify-core, then @typedstandards/produce-core, then
// @typedstandards/cli (typedstandards#113 G0 D12; replaces
// packages/cli/scripts/publish.mjs). The owner runs it from a detached worktree
// at the release PR's merge commit:
//
//   node scripts/publish.mjs --merged <sha> --dry-run
//   node scripts/publish.mjs --merged <sha>
//   node scripts/publish.mjs --merged <sha> --readback-only
//
// <sha> is the full 40-hex merge commit. --wait-seconds <n> sets the registry
// wait per package (default 300).
//
// It publishes nothing, and prints one line naming the failed check, when:
//   - the working tree is not clean;
//   - --merged is not a full 40-hex SHA, or HEAD is not that commit;
//   - a registry read fails (#125 D13). The registry is read for every listed
//     package before any CHANGELOG is checked, and the read fails closed: a 404
//     counts as not on npm, while a network error, any other non-OK answer, or a
//     body that is not a package document stops the run;
//   - for each listed package whose version that read does not show, its
//     CHANGELOG's first `## ` heading is not `## <version> — <today>`, today being
//     the local date. A version already on npm is exempt: it is read back below,
//     never published again, so its heading keeps its own release date;
//   - an in-repo range on a published package does not admit the version being
//     published (under 0.x a caret range excludes the next minor): produce-core →
//     verify-core; cli → produce-core, verify-core; apps/web → verify-core, and its
//     devDependency → produce-core;
//   - `npm whoami` fails;
//   - `npm ci --ignore-scripts`, a clean build (in dependency order, verify-core's
//     dist first) or a package's tests fail;
//   - `npm pack --dry-run --json` for a package lists a file outside its `files`.
//
// Then, per package and strictly in order, it reads the registry again. A
// version already on npm is not published again: it is read back and the run
// moves on, so a re-run after a partial publish completes the rest. A version the
// first read showed on npm and this read does not stops the run: its heading was
// not checked, so it is not published. Otherwise it publishes
// (`npm publish`, `--dry-run` appended under --dry-run) and waits for the
// registry, about five minutes with backoff, before the next package starts. It
// reads back the version, the dependency ranges (equal to package.json's), the
// bin, and dist.integrity (equal to the local `npm pack` of the same package at
// the merged commit). Every registry read sends `Cache-Control: no-cache` and a
// cache-busting `?t=<epoch ms>` query (#112).
//
// If the wait ends first, the package was sent and is not yet visible: it exits
// 2 and says to re-run with --readback-only, never to publish again.
// --readback-only publishes nothing and checks no CHANGELOG: it checks the tree
// and HEAD, installs and clean-builds (for the local pack's integrity), and reads
// every listed package back.
//
// Last, it runs the published cli's `verify` from a clean temporary directory on
// packages/cli/scripts/fixtures/published-verify.bundle.json (under --dry-run,
// the local build's, unless that cli version is already on npm).
//
// It prints no credential and reads no .npmrc or token file: npm handles auth.

import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
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
  oneLine,
  publishArgs,
  rangeProblems,
  readBackProblems,
  stripDot,
  versionOnRegistry,
  waitDelays,
} from './publish-lib.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE = join(ROOT, 'packages', 'cli', 'scripts', 'fixtures', 'published-verify.bundle.json');

function stop(check, message) {
  console.error(`stopped at ${check}: ${oneLine(message)}`);
  process.exit(1);
}

/** Run a command; captured unless `inherit`. */
function sh(command, args, { cwd = ROOT, inherit = false } = {}) {
  const r = spawnSync(command, args, { cwd, encoding: 'utf8', stdio: inherit ? 'inherit' : 'pipe' });
  return { code: r.status, out: (r.stdout ?? '').trim(), err: (r.stderr ?? '').trim() };
}

function step(label) {
  console.log(`\n== ${label}`);
}

const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const manifestOf = (dir) => JSON.parse(readFileSync(join(ROOT, dir, 'package.json'), 'utf8'));

/** Every workspace manifest, from the root's `workspaces` globs (`dir/*` form). */
function workspaces() {
  const out = [];
  for (const glob of manifestOf('.').workspaces ?? []) {
    const parent = glob.replace(/\/\*$/, '');
    for (const entry of readdirSync(join(ROOT, parent), { withFileTypes: true })) {
      const path = `${parent}/${entry.name}`;
      if (entry.isDirectory() && existsSync(join(ROOT, path, 'package.json'))) out.push({ path, manifest: manifestOf(path) });
    }
  }
  return out;
}

async function registryDocument(name, check) {
  try {
    return await fetchRegistryDocument(name);
  } catch (e) {
    stop(check, `reading ${name} from the registry failed: ${e.message}`);
  }
}

/** The integrity of the local `npm pack` of a package, and its file list. */
function localPack(pkg, check) {
  const r = sh('npm', ['pack', '--dry-run', '--json'], { cwd: join(ROOT, pkg.dir) });
  if (r.code !== 0) stop(check, `npm pack --dry-run for ${pkg.name} failed: ${r.err.split('\n').slice(-2).join(' ')}`);
  const [entry] = JSON.parse(r.out);
  return { integrity: entry.integrity, files: entry.files.map((f) => f.path) };
}

/** The one place `npm publish` runs. */
function npmPublish(pkg, dryRun) {
  const args = publishArgs(dryRun);
  step(`npm ${args.join(' ')} (${pkg.name})`);
  return sh('npm', args, { cwd: join(ROOT, pkg.dir), inherit: true }).code === 0;
}

function checkTreeAndHead(merged) {
  step('the tree');
  const top = sh('git', ['rev-parse', '--show-toplevel']);
  if (top.code !== 0) stop('the tree', 'not inside a git checkout');
  if (realpathSync(top.out) !== realpathSync(ROOT)) stop('the tree', `the checkout root is ${top.out}, not this script's ${ROOT}`);
  const dirty = sh('git', ['status', '--porcelain', '--untracked-files=all']);
  if (dirty.code !== 0) stop('the tree', `git status failed: ${dirty.err}`);
  if (dirty.out) {
    const paths = dirty.out.split('\n');
    stop('the tree', `the working tree is not clean (${paths.length} path${paths.length === 1 ? '' : 's'}: ${paths.slice(0, 5).map((l) => l.trim()).join(', ')}${paths.length > 5 ? ', …' : ''})`);
  }
  console.log('clean');

  step('the merged commit');
  if (!merged) stop('the merged commit', '--merged <sha> is required: the full 40-hex merge commit this publishes');
  if (!isFullSha(merged)) stop('the merged commit', `--merged ${merged} is not a full 40-hex SHA`);
  const head = sh('git', ['rev-parse', 'HEAD']).out;
  if (head !== merged) stop('the merged commit', `HEAD is ${head}, not the merged commit ${merged}`);
  console.log(`HEAD is ${head}`);
}

/** The CHANGELOG headings of `packages`: the listed packages whose version the registry does not show (#125 D13). */
function checkChangelogs(manifests, packages) {
  const today = localDate();
  step(`the CHANGELOGs of the versions not on npm (today is ${today})`);
  if (packages.length === 0) console.log('none: every listed version is on npm');
  for (const pkg of packages) {
    const { version } = manifests[pkg.name];
    const problem = changelogHeadingProblem(readFileSync(join(ROOT, pkg.dir, 'CHANGELOG.md'), 'utf8'), version, today);
    if (problem) stop('the CHANGELOG heading', `${pkg.dir}/CHANGELOG.md: ${problem}`);
    console.log(`${pkg.name}: ${expectedHeading(version, today)}`);
  }
}

function checkRanges(manifests) {
  step('the in-repo ranges');
  const published = Object.fromEntries(PACKAGES.map((p) => [p.name, manifests[p.name].version]));
  const all = workspaces();
  const problems = rangeProblems(all, published);
  if (problems.length) stop('the ranges', problems.join('; '));
  for (const e of inRepoRanges(all, published)) console.log(`${e.from} ${e.field} ${e.dep} ${e.range} admits ${e.version}`);
}

function installBuildTest({ test }) {
  const check = test ? 'install, build, test' : 'install, build';
  step(check);
  const cmds = [['npm', ['ci', '--ignore-scripts']]];
  // Clean before building, as each package's prepublishOnly does: `npm ci` links
  // the cli's bin and marks an existing dist/bin/main.js executable, and a rebuild
  // over it keeps that mode, so the local pack's integrity would differ from the
  // published tarball's (built fresh by prepublishOnly).
  for (const pkg of PACKAGES) cmds.push(['npm', ['run', 'clean', '--workspace', pkg.name]]);
  for (const pkg of PACKAGES) cmds.push(['npm', ['run', 'build', '--workspace', pkg.name]]);
  if (test) for (const pkg of PACKAGES) cmds.push(['npm', ['run', 'test', '--workspace', pkg.name]]);
  for (const [cmd, args] of cmds) {
    const r = sh(cmd, args, { inherit: true });
    if (r.code !== 0) stop(check, `${cmd} ${args.join(' ')} failed (exit ${r.code})`);
  }
}

function checkPacks(manifests) {
  step('npm pack --dry-run');
  for (const pkg of PACKAGES) {
    const { files } = localPack(pkg, 'the pack');
    const outside = filesOutside(files, manifests[pkg.name].files);
    if (outside.length) stop('the pack', `npm pack for ${pkg.name} lists files outside "files" [${manifests[pkg.name].files.join(', ')}]: ${outside.join(', ')}`);
    console.log(`${pkg.name}: ${files.length} files, all within "files" [${manifests[pkg.name].files.join(', ')}]`);
  }
}

/** Wait for the version on the registry, then read it back against the local manifest and pack. */
async function readBack(pkg, manifest, waitSeconds) {
  const { name, version } = manifest;
  step(`waiting for ${name}@${version} on the registry (up to ${waitSeconds}s, cache bypassed)`);
  const read = async () => {
    try {
      return await fetchRegistryDocument(name);
    } catch (e) {
      console.log(`the read failed (${e.message}); retrying`);
      return undefined;
    }
  };
  let doc = await read();
  for (const d of waitDelays(waitSeconds)) {
    if (doc?.versions?.[version]) break;
    console.log(`not visible yet; checking again in ${d}s`);
    await sleep(d);
    doc = await read();
  }
  if (!doc?.versions?.[version]) {
    console.error(`sent, not yet visible: ${name}@${version} did not appear within ${waitSeconds}s. Re-run with --readback-only; do not publish again.`);
    process.exit(2);
  }

  step(`read back ${name}@${version}`);
  const published = doc.versions[version];
  const { integrity } = localPack(pkg, 'the read-back');
  console.log(`version ${published.version}`);
  console.log(`dependencies ${JSON.stringify(published.dependencies ?? {})}`);
  if (published.bin || manifest.bin) console.log(`bin ${JSON.stringify(published.bin ?? {})}`);
  console.log(`dist.integrity ${published.dist?.integrity}`);
  console.log(`local pack     ${integrity}`);
  const problems = readBackProblems(published, manifest, integrity);
  if (problems.length) stop('the read-back', `${name}@${version}: ${problems.join('; ')}`);
  console.log(`${name}@${version} reads back as package.json and the local pack.`);
}

/** Run a CLI binary's verify on the fixture, copied into a clean temporary directory. */
function verifyFixture(bin, cwd) {
  copyFileSync(FIXTURE, join(cwd, 'bundle.json'));
  const r = spawnSync(process.execPath, [bin, 'verify', '--input', 'bundle.json', '--json'], { cwd, encoding: 'utf8', env: {} });
  if (r.status !== 0) stop('the verify', `verify exited ${r.status} on the fixture: ${r.stderr.trim()}`);
  const out = JSON.parse(r.stdout);
  if (out.ok !== true || out.lifecycle?.status !== 'withdrawn') {
    stop('the verify', `verify read the fixture as ok=${out.ok}, lifecycle ${out.lifecycle?.status}; expected ok, withdrawn`);
  }
  console.log(`verify: ok, nodeId ${out.nodeId}, lifecycle ${out.lifecycle.status}`);
}

async function publishedVerify(manifest) {
  const { name, version } = manifest;
  step(`the published ${name}@${version} verify, from a clean temporary directory`);
  const dir = mkdtempSync(join(tmpdir(), 'typedstandards-cli-published-'));
  try {
    let install = { code: 1, err: '' };
    for (const delay of [0, 30, 60]) {
      if (delay) await sleep(delay);
      install = sh('npm', ['install', '--prefer-online', '--no-audit', '--no-fund', '--prefix', dir, `${name}@${version}`], { cwd: dir });
      if (install.code === 0) break;
    }
    if (install.code !== 0) stop('the verify', `npm install ${name}@${version} failed in ${dir}: ${install.err.split('\n').slice(-3).join(' ')}`);
    verifyFixture(join(dir, 'node_modules', ...name.split('/'), stripDot(manifest.bin.typedstandards)), dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function localVerify(pkg, manifest) {
  step('the local verify on the fixture, from a clean temporary directory');
  const dir = mkdtempSync(join(tmpdir(), 'typedstandards-cli-dry-'));
  try {
    verifyFixture(join(ROOT, pkg.dir, stripDot(manifest.bin.typedstandards)), dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
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
  const dryRun = values['dry-run'] === true;
  const readbackOnly = values['readback-only'] === true;
  if (dryRun && readbackOnly) stop('the arguments', '--dry-run and --readback-only do not combine');
  const waitSeconds = Number(values['wait-seconds'] ?? 300);
  if (!Number.isInteger(waitSeconds) || waitSeconds < 0) stop('the arguments', `--wait-seconds ${values['wait-seconds']} is not a whole number of seconds`);
  console.log(`mode: ${readbackOnly ? 'read back only (publishes nothing)' : dryRun ? 'dry run (publishes nothing)' : 'publish'}`);

  const manifests = Object.fromEntries(PACKAGES.map((p) => [p.name, manifestOf(p.dir)]));
  checkTreeAndHead(values.merged);

  if (readbackOnly) {
    installBuildTest({ test: false });
    for (const pkg of PACKAGES) await readBack(pkg, manifests[pkg.name], waitSeconds);
    await publishedVerify(manifests['@typedstandards/cli']);
    console.log(`\nread back only: all ${PACKAGES.length} listed packages are on npm as package.json and the local packs, and the published verify passes.`);
    return;
  }

  // The registry first, failing closed (#125 D13): a heading is checked only for
  // a version the registry does not show.
  step('the registry, before the CHANGELOGs');
  const docs = {};
  for (const pkg of PACKAGES) {
    const { version } = manifests[pkg.name];
    const doc = await registryDocument(pkg.name, 'the registry');
    docs[pkg.name] = doc;
    console.log(
      versionOnRegistry(doc, version)
        ? `${pkg.name}@${version} is on npm: read back below; its CHANGELOG heading is not checked`
        : `${pkg.name}@${version} is not on npm${doc === null ? ' (404)' : ''}: its CHANGELOG heading is checked`,
    );
  }
  let unpublished;
  try {
    unpublished = headingCheckPackages(PACKAGES, manifests, docs);
  } catch (e) {
    stop('the registry', e.message);
  }
  checkChangelogs(manifests, unpublished);
  checkRanges(manifests);

  step('npm whoami');
  const who = sh('npm', ['whoami']);
  if (who.code !== 0) stop('npm whoami', `npm whoami failed; log in with npm login first (${who.err.split('\n')[0] || 'no output'})`);
  console.log(`logged in as ${who.out}`);

  installBuildTest({ test: true });
  checkPacks(manifests);

  let cliOnNpm = false;
  for (const pkg of PACKAGES) {
    const manifest = manifests[pkg.name];
    step(`the registry: ${pkg.name}@${manifest.version}`);
    const doc = await registryDocument(pkg.name, 'the registry');
    if (versionOnRegistry(doc, manifest.version)) {
      console.log(`${pkg.name}@${manifest.version} is already on npm: not publishing it again; reading it back`);
      await readBack(pkg, manifest, waitSeconds);
      if (pkg.name === '@typedstandards/cli') cliOnNpm = true;
      continue;
    }
    if (!unpublished.some((p) => p.name === pkg.name)) {
      stop('the registry', `${pkg.name}@${manifest.version} was on npm at the first read and is not now; its CHANGELOG heading was not checked, so it is not published`);
    }
    console.log(doc === null ? `${pkg.name} answers 404: not on npm yet, or not yet visible` : `${pkg.name} is on npm; ${manifest.version} is not`);
    if (dryRun) {
      const before = localPack(pkg, 'the dry-run publish').integrity;
      if (!npmPublish(pkg, true)) stop('the dry-run publish', `npm publish --dry-run failed for ${pkg.name}`);
      const after = localPack(pkg, 'the dry-run publish').integrity;
      if (before !== after) stop('the dry-run publish', `${pkg.name}'s pack integrity changed across npm publish --dry-run (${before} → ${after}): a real read-back would not match`);
      console.log(`${pkg.name}: the pack integrity is unchanged across the publish's rebuild (${after})`);
    } else {
      if (!npmPublish(pkg, false)) {
        stop('npm publish', `npm publish failed for ${pkg.name}@${manifest.version}; it may still have landed: re-run this script, which reads the registry first and does not publish a version already there`);
      }
      await readBack(pkg, manifest, waitSeconds);
      if (pkg.name === '@typedstandards/cli') cliOnNpm = true;
    }
  }

  const cli = PACKAGES.find((p) => p.name === '@typedstandards/cli');
  if (cliOnNpm) await publishedVerify(manifests[cli.name]);
  else localVerify(cli, manifests[cli.name]);

  console.log(dryRun ? '\ndry run: nothing was published.' : `\nall ${PACKAGES.length} listed packages are on npm, read back, and the published verify passes on the fixture.`);
}

await main();
