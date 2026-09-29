// The pure helpers of scripts/publish.mjs (typedstandards#113, #112). Importing
// this module runs nothing; scripts/publish.test.mjs tests it under node --test.

/** The published packages, in the order they publish: each one's range needs the one before it on the registry. */
export const PACKAGES = Object.freeze([
  Object.freeze({ name: '@typedstandards/verify-core', dir: 'packages/verify-core' }),
  Object.freeze({ name: '@typedstandards/produce-core', dir: 'packages/produce-core' }),
  Object.freeze({ name: '@typedstandards/cli', dir: 'packages/cli' }),
]);

export const REGISTRY = 'https://registry.npmjs.org';

/**
 * The registry URL for a package document, with a cache-busting query (#112): a
 * newly published name can otherwise be answered from a cached 404.
 */
export function registryUrl(name, nowMs) {
  if (!Number.isFinite(nowMs)) throw new TypeError('registryUrl needs the current time in ms');
  return `${REGISTRY}/${name.replace('/', '%2f')}?t=${nowMs}`;
}

/** The request headers for every registry read: `Cache-Control: no-cache` asks each cache on the way to revalidate (#112). */
export function registryHeaders() {
  return { accept: 'application/json', 'cache-control': 'no-cache' };
}

/**
 * Read a package document from the registry, bypassing caches. Both of the
 * script's registry reads, the pre-publish "already on npm?" read and the
 * post-publish wait, go through here. Returns null on a 404 (the name was never
 * published, or not yet visible); throws on any other non-OK answer.
 */
export async function fetchRegistryDocument(name, { fetchImpl = globalThis.fetch, now = Date.now, timeoutMs = 30_000 } = {}) {
  const res = await fetchImpl(registryUrl(name, now()), {
    headers: registryHeaders(),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`the registry answered ${res.status} for ${name}`);
  return res.json();
}

/**
 * The packages whose CHANGELOG heading the run checks, from the registry
 * documents read before the check (#125 D13). Stub: every package, the check's
 * scope before D13; the fix commit narrows it.
 */
export function headingCheckPackages(packages, manifests, docs) {
  void manifests;
  void docs;
  return [...packages];
}

/** The local calendar date, YYYY-MM-DD, as the CHANGELOG headings write it. */
export function localDate(d = new Date()) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/** The heading a release's CHANGELOG must open with: `## 0.12.0 — 2026-09-24` (an em dash). */
export function expectedHeading(version, date) {
  return `## ${version} — ${date}`;
}

/** Null when the CHANGELOG's first `## ` heading is this version dated `date`; otherwise why not. */
export function changelogHeadingProblem(changelog, version, date) {
  const first = changelog.split(/\r?\n/).find((l) => l.startsWith('## '));
  const expected = expectedHeading(version, date);
  if (first === expected) return null;
  return `the first heading is "${first ?? '(none)'}", not "${expected}"`;
}

const PLAIN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** [major, minor, patch] of a plain x.y.z version; null for anything else (a prerelease included). */
export function parseVersion(v) {
  const m = PLAIN.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/**
 * Whether `range` admits `version`, for the range forms this repo writes: an
 * exact x.y.z, ^x.y.z and ~x.y.z. Under 0.x a caret range admits patches only:
 * ^0.12.0 is >=0.12.0 <0.13.0, so it excludes 0.13.0. Any other form, or a
 * version that is not plain x.y.z, reads as not admitted (fail closed), with the
 * reason.
 * @returns {{ admits: boolean, reason?: string }}
 */
export function rangeAdmits(range, version) {
  const v = parseVersion(version);
  if (!v) return { admits: false, reason: `"${version}" is not a plain x.y.z version` };
  const m = /^([\^~]?)(.*)$/.exec(range.trim());
  const base = parseVersion(m[2]);
  if (!base) return { admits: false, reason: `"${range}" is not a range form this check reads (x.y.z, ^x.y.z, ~x.y.z)` };
  let upper;
  if (m[1] === '') upper = null;
  else if (m[1] === '~') upper = [base[0], base[1] + 1, 0];
  else if (base[0] > 0) upper = [base[0] + 1, 0, 0];
  else if (base[1] > 0) upper = [0, base[1] + 1, 0];
  else upper = [0, 0, base[2] + 1];
  const admits = upper === null ? cmp(v, base) === 0 : cmp(v, base) >= 0 && cmp(v, upper) < 0;
  return admits ? { admits } : { admits, reason: `"${range}" excludes ${version}` };
}

export const DEPENDENCY_FIELDS = Object.freeze(['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']);

/**
 * Every in-repo range on a published package: for each workspace manifest, each
 * dependency field naming one of `published`.
 * @param {{ path: string, manifest: object }[]} workspaces
 * @param {Record<string, string>} published name → the version being published
 */
export function inRepoRanges(workspaces, published) {
  const edges = [];
  for (const { path, manifest } of workspaces) {
    for (const field of DEPENDENCY_FIELDS) {
      for (const [dep, range] of Object.entries(manifest[field] ?? {})) {
        if (Object.hasOwn(published, dep)) edges.push({ from: path, field, dep, range, version: published[dep] });
      }
    }
  }
  return edges;
}

/** The in-repo ranges that do not admit the version being published, each with its reason. */
export function rangeProblems(workspaces, published) {
  return inRepoRanges(workspaces, published)
    .map((e) => ({ ...e, ...rangeAdmits(e.range, e.version) }))
    .filter((e) => !e.admits)
    .map((e) => `${e.from} ${e.field} ${e.dep}: ${e.reason}`);
}

export const stripDot = (p) => p.replace(/^\.\//, '');

/** The packed paths outside the manifest's `files` (package.json always ships). */
export function filesOutside(packedPaths, filesField) {
  const allowed = (filesField ?? []).map(stripDot);
  return packedPaths.filter((f) => f !== 'package.json' && !allowed.some((a) => f === a || f.startsWith(`${a}/`)));
}

/** True when `s` is a full 40-hex commit SHA. */
export function isFullSha(s) {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}

/** A string bin as npm normalizes it, `./` stripped, keys sorted. */
export function normalizeBin(bin, name) {
  if (bin === undefined || bin === null) return {};
  const entries = typeof bin === 'string' ? [[name.split('/').pop(), bin]] : Object.entries(bin);
  return Object.fromEntries(entries.map(([k, v]) => [k, stripDot(v)]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

const sortedEntries = (o) => JSON.stringify(Object.entries(o ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

/**
 * What the published version document disagrees with, against the local
 * manifest and the integrity of the local `npm pack` at the merged commit: the
 * version, each dependency field's ranges, the bin, and dist.integrity.
 * @returns {string[]} empty when the read-back matches
 */
export function readBackProblems(published, manifest, localIntegrity) {
  const problems = [];
  if (published.version !== manifest.version) problems.push(`the registry has version ${published.version}, not ${manifest.version}`);
  for (const field of DEPENDENCY_FIELDS.filter((f) => f !== 'devDependencies')) {
    if (sortedEntries(published[field]) !== sortedEntries(manifest[field])) {
      problems.push(`the published ${field} ${JSON.stringify(published[field] ?? {})} are not package.json's ${JSON.stringify(manifest[field] ?? {})}`);
    }
  }
  const remoteBin = normalizeBin(published.bin, manifest.name);
  const localBin = normalizeBin(manifest.bin, manifest.name);
  if (JSON.stringify(remoteBin) !== JSON.stringify(localBin)) problems.push(`the published bin ${JSON.stringify(remoteBin)} is not ${JSON.stringify(localBin)}`);
  const remoteIntegrity = published.dist?.integrity;
  if (!localIntegrity) problems.push('the local npm pack gave no integrity');
  else if (remoteIntegrity !== localIntegrity) problems.push(`the registry's dist.integrity ${remoteIntegrity ?? '(none)'} is not the local pack's ${localIntegrity}`);
  return problems;
}

/**
 * The sleeps between registry reads while waiting for a version, backing off,
 * summing to `totalSeconds` (about five minutes by default). The wait reads once
 * before the first sleep and once after each.
 */
export function waitDelays(totalSeconds = 300) {
  const schedule = [5, 10, 20, 30, 45, 60];
  const delays = [];
  let left = totalSeconds;
  for (let i = 0; left > 0; i++) {
    const d = Math.min(schedule[Math.min(i, schedule.length - 1)], left);
    delays.push(d);
    left -= d;
  }
  return delays;
}

/** The `npm publish` arguments: `--dry-run` appended in dry-run mode, nothing else. */
export function publishArgs(dryRun) {
  return dryRun ? ['publish', '--dry-run'] : ['publish'];
}

/** One line: a stop message never spans lines. */
export function oneLine(s) {
  return String(s).replace(/\s*\r?\n\s*/g, '; ').trim();
}
