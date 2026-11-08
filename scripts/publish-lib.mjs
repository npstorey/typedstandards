// The pure helpers of scripts/publish.mjs (typedstandards#113, #112). Importing
// this module runs nothing; scripts/publish.test.mjs tests it under node --test.

import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { gunzipSync } from 'node:zlib';

/** The published packages, in the order they publish: each one's range needs the one before it on the registry. */
export const PACKAGES = Object.freeze([
  Object.freeze({ name: '@typedstandards/verify-core', dir: 'packages/verify-core' }),
  Object.freeze({ name: '@typedstandards/produce-core', dir: 'packages/produce-core' }),
  Object.freeze({ name: '@typedstandards/cli', dir: 'packages/cli' }),
  Object.freeze({ name: '@typedstandards/host-core', dir: 'packages/host-core' }),
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

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Read a package document from the registry, bypassing caches. Every registry
 * read the script makes goes through here: the read before the CHANGELOG check
 * (#125 D13), the per-package "already on npm?" read, and the post-publish
 * wait. Returns null on a 404 (the name was never published, or not yet
 * visible). Fails closed on anything else: a network error, a non-OK answer, a
 * body that is not JSON, or a JSON body that is not a package document (an
 * object with a `versions` object) each throw.
 */
export async function fetchRegistryDocument(name, { fetchImpl = globalThis.fetch, now = Date.now, timeoutMs = 30_000 } = {}) {
  const res = await fetchImpl(registryUrl(name, now()), {
    headers: registryHeaders(),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`the registry answered ${res.status} for ${name}`);
  let body;
  try {
    body = await res.json();
  } catch (e) {
    throw new Error(`the registry's answer for ${name} is not JSON: ${e.message}`);
  }
  if (!isObject(body) || !isObject(body.versions)) throw new Error(`the registry's document for ${name} is malformed: it has no "versions" object`);
  return body;
}

/** Whether a registry document (null for a 404) lists `version`. */
export function versionOnRegistry(doc, version) {
  const versions = doc?.versions;
  return isObject(versions) && Object.hasOwn(versions, version) && Boolean(versions[version]);
}

/**
 * The packages whose CHANGELOG heading the run checks (#125 D13): each one whose
 * version the registry does not show. A version already on npm is read back, not
 * published, so its heading keeps its own release date. `docs` maps each name to
 * the registry document read before the check, null for a 404. The scope is
 * never guessed: a package with no document entry, or no version in `manifests`,
 * throws.
 * @param {{ name: string }[]} packages in publish order; the result keeps it
 * @param {Record<string, { version?: string }>} manifests name → package.json
 * @param {Record<string, object | null>} docs name → registry document, or null
 */
export function headingCheckPackages(packages, manifests, docs) {
  return packages.filter((pkg) => {
    const version = manifests[pkg.name]?.version;
    if (typeof version !== 'string' || version === '') throw new Error(`${pkg.name} has no version in package.json`);
    if (!Object.hasOwn(docs, pkg.name) || docs[pkg.name] === undefined) throw new Error(`the registry was not read for ${pkg.name}`);
    return !versionOnRegistry(docs[pkg.name], version);
  });
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

/** The integrity npm writes for a tarball: `sha512-` and the base64 SHA-512 of its bytes. */
export function sha512Integrity(bytes) {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

/**
 * Read a published version's tarball, `dist.tarball`, and check its bytes
 * against `dist.integrity` (#174). It sends the no-cache header and a
 * cache-busting `?t=` query, as every registry read does (#112). Fails closed: a
 * tarball URL outside the registry, an integrity that is not one sha512, a
 * network error, a non-OK answer, or bytes that do not hash to `dist.integrity`
 * each throw.
 * @returns {Promise<Uint8Array>} the tarball's bytes
 */
export async function fetchPublishedTarball(dist, { fetchImpl = globalThis.fetch, now = Date.now, timeoutMs = 60_000 } = {}) {
  const tarball = dist?.tarball;
  if (typeof tarball !== 'string' || !tarball.startsWith(`${REGISTRY}/`)) throw new Error(`the tarball URL ${tarball} is not on ${REGISTRY}`);
  if (typeof dist.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(dist.integrity)) throw new Error(`dist.integrity ${dist.integrity} is not one sha512 integrity`);
  if (!Number.isFinite(now())) throw new TypeError('fetchPublishedTarball needs the current time in ms');
  const url = new URL(tarball);
  url.searchParams.set('t', String(now()));
  const res = await fetchImpl(url.href, { headers: { 'cache-control': 'no-cache' }, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`the registry answered ${res.status} for ${tarball}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const integrity = sha512Integrity(bytes);
  if (integrity !== dist.integrity) throw new Error(`the tarball at ${tarball} hashes to ${integrity}, not dist.integrity ${dist.integrity}`);
  return bytes;
}

const ascii = (bytes) => String.fromCharCode(...bytes);

/** A NUL-terminated header field. */
function tarField(header, start, length) {
  const field = header.subarray(start, start + length);
  const end = field.indexOf(0);
  return new TextDecoder('utf-8', { fatal: true }).decode(end === -1 ? field : field.subarray(0, end));
}

/** An octal header number; anything else (base-256 included) throws. */
function tarOctal(header, start, length, what) {
  const text = ascii(header.subarray(start, start + length)).replace(/[\0 ]+$/, '').replace(/^ +/, '');
  if (!/^[0-7]+$/.test(text)) throw new Error(`a tar header's ${what} "${text}" is not an octal number`);
  return parseInt(text, 8);
}

/** The records of a pax extended header: `<length> <key>=<value>\n`, the length counting the whole record in bytes. */
function paxRecords(body) {
  const records = {};
  for (let at = 0; at < body.length; ) {
    const space = body.indexOf(0x20, at);
    const length = space === -1 || space - at > 20 ? NaN : Number(ascii(body.subarray(at, space)));
    if (!Number.isInteger(length) || length <= space - at + 1 || at + length > body.length || body[at + length - 1] !== 0x0a) throw new Error('a pax header record is malformed');
    const record = new TextDecoder('utf-8', { fatal: true }).decode(body.subarray(space + 1, at + length - 1));
    const eq = record.indexOf('=');
    if (eq <= 0) throw new Error('a pax header record has no key');
    records[record.slice(0, eq)] = record.slice(eq + 1);
    at += length;
  }
  return records;
}

/**
 * The files of an npm tarball (a gzipped ustar archive, as `npm pack` writes
 * it), path → bytes, each path without its top directory (`package/`), as npm
 * installs it (#174). Directory entries are skipped; a pax header's `path` is
 * honoured. Fails closed: a header whose checksum fails, a header that is not
 * POSIX ustar, an entry other than a file, a directory or a pax header (a link
 * included), a pax `size`, a path with no top directory or with an empty, `.`
 * or `..` segment, a path given twice, or a truncated archive each throw.
 * @param {Uint8Array} tgz
 * @returns {Map<string, Uint8Array>}
 */
export function tarFiles(tgz) {
  const tar = gunzipSync(tgz);
  const files = new Map();
  let pax = {};
  for (let at = 0; ; ) {
    if (at + 512 > tar.length) throw new Error('the tarball ends before its end-of-archive block');
    const header = tar.subarray(at, at + 512);
    if (header.every((b) => b === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i];
    if (sum !== tarOctal(header, 148, 8, 'checksum')) throw new Error(`the tar header at byte ${at} fails its checksum`);
    if (ascii(header.subarray(257, 263)) !== 'ustar\0') throw new Error(`the tar header at byte ${at} is not POSIX ustar`);
    const size = tarOctal(header, 124, 12, 'size');
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const body = tar.subarray(at + 512, at + 512 + size);
    if (body.length !== size) throw new Error(`the tar entry at byte ${at} is truncated`);
    at += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') {
      pax = paxRecords(body);
      if (Object.hasOwn(pax, 'size')) throw new Error('a pax header sets a size, which this reader does not read');
      continue;
    }
    const name = tarField(header, 0, 100);
    const prefix = tarField(header, 345, 155);
    const path = pax.path ?? (prefix ? `${prefix}/${name}` : name);
    pax = {};
    if (type === '5') continue;
    if (type !== '0') throw new Error(`the tar entry ${path} has type "${type}", not a file or a directory`);
    const segments = path.split('/');
    if (segments.length < 2 || segments.some((s) => s === '' || s === '.' || s === '..')) throw new Error(`the tar entry ${path} is not a file under a top directory`);
    const inPackage = segments.slice(1).join('/');
    if (files.has(inPackage)) throw new Error(`the tarball has ${inPackage} twice`);
    files.set(inPackage, body);
  }
  return files;
}

const sameBytes = (a, b) => a.length === b.length && Buffer.compare(a, b) === 0;

/** package.json's bytes as JSON, or the reason they are not. */
function parsePackageJson(bytes) {
  try {
    return { json: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
  } catch (e) {
    return { error: e.message };
  }
}

/**
 * What a consumer would install differently from the published tarball (#174):
 * every file but package.json byte for byte, the same file set, and package.json
 * equal as JSON with devDependencies set aside.
 * @param {Map<string, Uint8Array>} published the published tarball's files (tarFiles)
 * @param {Map<string, Uint8Array>} local the local pack's files (tarFiles)
 * @returns {string[]} empty when they install the same
 */
export function installedContentProblems(published, local) {
  const problems = [];
  const onlyPublished = [...published.keys()].filter((p) => !local.has(p)).sort();
  const onlyLocal = [...local.keys()].filter((p) => !published.has(p)).sort();
  if (onlyPublished.length) problems.push(`the published tarball has files the local pack does not: ${onlyPublished.join(', ')}`);
  if (onlyLocal.length) problems.push(`the local pack has files the published tarball does not: ${onlyLocal.join(', ')}`);
  const differing = [...published.keys()].filter((p) => p !== 'package.json' && local.has(p) && !sameBytes(published.get(p), local.get(p))).sort();
  if (differing.length) problems.push(`these files differ from the local pack's: ${differing.join(', ')}`);
  if (published.has('package.json') && local.has('package.json')) {
    const remote = parsePackageJson(published.get('package.json'));
    const here = parsePackageJson(local.get('package.json'));
    if (remote.error || here.error) {
      problems.push(`package.json does not parse (${remote.error ?? here.error})`);
    } else {
      const { devDependencies: _r, ...remoteRest } = remote.json;
      const { devDependencies: _l, ...localRest } = here.json;
      const keys = [...new Set([...Object.keys(remoteRest), ...Object.keys(localRest)])];
      const changed = keys.filter((k) => !isDeepStrictEqual(remoteRest[k], localRest[k])).sort();
      if (changed.length) problems.push(`package.json differs from the local pack's beyond devDependencies, in: ${changed.join(', ')}`);
    }
  }
  return problems;
}

/**
 * What the published version document disagrees with, against the local
 * manifest and the local `npm pack` at the merged commit: the version, each
 * dependency field's ranges but devDependencies', the bin, and then one of two:
 *
 * - without `contents`: dist.integrity, equal to the local pack's;
 * - with `contents`, `{ published, local }`, each a tarball's files (tarFiles):
 *   what a consumer installs (installedContentProblems), whatever the integrity.
 *
 * The script passes `contents` only for a version already on npm when the run
 * began whose dist.integrity is not the local pack's (#174), so a
 * devDependency-only bump after a release does not stop the run. A version the
 * run publishes is read back by its integrity.
 * @returns {string[]} empty when the read-back matches
 */
export function readBackProblems(published, manifest, localIntegrity, contents) {
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
  else if (contents !== undefined) problems.push(...installedContentProblems(contents.published, contents.local));
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
