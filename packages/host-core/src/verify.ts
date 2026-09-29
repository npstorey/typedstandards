// `verify` (typedstandards#125): offline verification of what a host serves. For
// every record the served index lists, verify-core's `verifyRecord` runs over the
// served bundle with the network blocked: the global `fetch` is replaced for the
// run by a stub that throws and counts, and the fetch injected into verify-core
// throws and counts too. Both counts must end at 0.
//
// Derived from the worked example's verify.mjs (b40c30f, :64-110) and its offline
// fetch stub (package/build.mjs, verifyOffline), with the example's own lines left
// out: the file on disk, #11, #12 and #16, and its pending-file and role totals.
//
// A record is ok when:
//   - #1 reads `verified` and #2 `true`: a host serves only what it holds in full;
//   - no check reads alarm, by the alarm entries of typedstandards.org's verifier
//     (apps/web/src/lib/trust-signal.ts, as the CLI's readings.ts copies them at
//     41c43c9), and, when a registry is served, #5 reads `active`: host-core built
//     that registry from these records, so any other reading is an inconsistency;
//   - every carried attestation targets this record, is intact and validly signed;
//   - the status the carried attestations give (verifyLifecycleChain, bound by the
//     record's own key) equals the index's, with its withdrawn or superseded fields;
//   - the index's packageHash, createdAt, type and signer are the bundle's, its type
//     as verify-core's resolvePackageType resolves it (a package with no type is
//     content/analysis/v1, spec §8.8.1); the view's copied fields equal its
//     package's; and the view names the index's trustRegistryUrl and carries the
//     served registry.

import {
  resolvePackageType,
  validateRegistry,
  verifyAttestationNode,
  verifyRecord as coreVerifyRecord,
  type FetchLike,
  type LifecycleResolution,
  type TrustRegistry,
  type VerifyResult,
} from '@typedstandards/verify-core';
import { HostError, isObject, parseJsonFile, sameJson, type FileMap, type JsonObject } from './json.ts';
import { checkCarriedNode, checkSignature, indexLifecycleOf, lifecycleOf, signerIdentifierOf, type CarriedNode } from './records.ts';
import { INDEX_PATH, REGISTRY_PATH, parseIndex, type HostIndex, type IndexRecord } from './served.ts';

export interface VerifyTotals {
  records: number;
  ok: number;
  failed: number;
  active: number;
  withdrawn: number;
  superseded: number;
}

export interface VerifyReport {
  ok: boolean;
  /** What `typedstandards-host verify` prints, one entry per line. */
  lines: string[];
  totals: VerifyTotals;
  fetch: { global: number; injected: number };
}

export interface VerifyOptions {
  /** verify-core's `verifyRecord`, replaceable so a test can make a check fetch. */
  verifyRecord?: typeof coreVerifyRecord;
}

// The alarm entries of the verifier's tables, by check.
const ALARM = {
  contentHash: ['content_hash_mismatch'],
  keyTrust: ['deprecated_invalid', 'revoked'],
  signingKeyIdConsistency: ['signingKeyId_mismatch'],
  signerIdentity: ['signer_identity_mismatch', 'key_derived_mismatch'],
  blobRef: ['invalid_ref', 'size_mismatch', 'hash_mismatch'],
} as const;

const includes = (list: readonly string[], v: string | undefined): boolean => v !== undefined && list.includes(v);

/** The failures verify-core's result shows for a record a host serves. */
function checkFailures(r: VerifyResult, registryServed: boolean): string[] {
  const out: string[] = [];
  const integrity = r.envelopeIntegrity.status === 'unavailable' ? `unavailable:${r.envelopeIntegrity.reason ?? 'unfetchable'}` : r.envelopeIntegrity.status;
  if (r.envelopeIntegrity.status !== 'verified') out.push(`#1 envelopeIntegrity ${integrity}`);
  if (r.signatureValid !== true) out.push(`#2 signatureValid ${String(r.signatureValid)}`);
  if (includes(ALARM.contentHash, r.contentHash?.status)) out.push(`#4 contentHash ${r.contentHash!.status}`);
  const trust = r.keyTrust?.status;
  if (includes(ALARM.keyTrust, trust) || (registryServed && trust !== 'active')) out.push(`#5 keyTrust ${String(trust)}`);
  if (includes(ALARM.signingKeyIdConsistency, r.signingKeyIdConsistency?.status)) out.push(`#6 signingKeyIdConsistency ${r.signingKeyIdConsistency!.status}`);
  for (const ref of r.blobRefs) if (!ref.ok && includes(ALARM.blobRef, ref.reason)) out.push(`#9 blobRefs.${ref.field} ${String(ref.reason)}`);
  if (includes(ALARM.signerIdentity, r.signerIdentity?.status)) out.push(`#14 signerIdentity ${r.signerIdentity!.status}`);
  return out;
}

function carriedFailures(carried: CarriedNode[], packageHash: string): string[] {
  const out: string[] = [];
  carried.forEach((entry, i) => {
    const field = `#10 lifecycleAttestations[${i}]`;
    if (entry.node['targetNodeId'] !== packageHash) {
      out.push(`${field} targets another record`);
      return;
    }
    const verdict = verifyAttestationNode(entry.node, entry.nodeId, entry.signature ?? null);
    if (!verdict.nodeIdMatches) out.push(`${field}.nodeId does not match the node`);
    if (verdict.signatureValid !== true) out.push(`${field}.signature ${String(verdict.signatureValid)}`);
  });
  return out;
}

function lifecycleFailures(life: LifecycleResolution, rec: IndexRecord): string[] {
  const read = indexLifecycleOf(life);
  const stated = { status: rec.status, withdrawn: rec.withdrawn, superseded: rec.superseded };
  if (sameJson(read, stated)) return [];
  if (read.status !== rec.status) return [`#10 the carried attestations give ${read.status}, the index says ${rec.status}`];
  return [`#10 the index's ${rec.status} fields differ from what the carried attestations give`];
}

const VIEW_COPIES = ['producerProfile', 'type', 'signer', 'contentHash', 'contentCanonicalization'] as const;

function viewFailures(b: JsonObject, pkg: JsonObject, rec: IndexRecord, index: HostIndex, registry: TrustRegistry | undefined): string[] {
  const out: string[] = [];
  const metadata = isObject(pkg['metadata']) ? pkg['metadata'] : {};
  if (b['packageHash'] !== rec.packageHash) out.push('the index\'s packageHash is not the bundle\'s');
  if (metadata['createdAt'] !== rec.createdAt) out.push('the index\'s createdAt is not the package\'s');
  if (resolvePackageType(pkg).type !== rec.type) out.push('the index\'s type is not the package\'s, as verify-core resolves it');
  if (signerIdentifierOf(pkg) !== rec.signer) out.push('the index\'s signer is not the package\'s');
  const differ: string[] = VIEW_COPIES.filter((k) => !sameJson(b[k], pkg[k]));
  if ((b['captureMethod'] ?? null) !== (metadata['captureMethod'] ?? null)) differ.push('captureMethod');
  if (differ.length) out.push(`the view's ${differ.join(', ')} differ from the package's`);
  if (b['trustRegistryUrl'] !== index.trustRegistryUrl) out.push('the view does not name the index\'s trustRegistryUrl');
  if (registry ? !sameJson(b['trustRegistry'], registry) : 'trustRegistry' in b) {
    out.push(registry ? 'the view does not carry the served registry' : 'the view carries a registry the host does not serve');
  }
  return out;
}

/** Where a record's bundle is served, as a key of the served map, or undefined when it is served elsewhere. */
function servedKeyOf(bundle: string, host: string): string | undefined {
  if (/^https?:\/\//i.test(bundle)) return bundle.startsWith(host) ? bundle.slice(host.length) : undefined;
  return bundle;
}

interface RecordResult {
  ok: boolean;
  status: string;
  failures: string[];
}

async function verifyOne(
  rec: IndexRecord,
  served: FileMap,
  index: HostIndex,
  registry: TrustRegistry | undefined,
  fetch: FetchLike,
  verify: typeof coreVerifyRecord,
): Promise<RecordResult> {
  const fail = (failures: string[]): RecordResult => ({ ok: false, status: rec.status, failures });
  const key = servedKeyOf(rec.bundle, index.host);
  if (key === undefined) return fail([`${rec.bundle} is served elsewhere, so it cannot be verified offline here`]);
  const bytes = served.get(key);
  if (bytes === undefined) return fail([`${key} is not served`]);
  let b: unknown;
  try {
    b = parseJsonFile(bytes, key);
  } catch (err) {
    return fail([(err as Error).message]);
  }
  if (!isObject(b) || !isObject(b['package']) || typeof b['packageHash'] !== 'string') return fail([`${key} carries no package and packageHash`]);
  let carried: CarriedNode[];
  let signature;
  try {
    signature = checkSignature(b['signature'], `${key}: signature`);
    const list = b['lifecycleAttestations'] ?? [];
    if (!Array.isArray(list)) throw new HostError(`${key}: lifecycleAttestations must be an array`);
    carried = list.map((c, i) => checkCarriedNode(c, `${key}: lifecycleAttestations[${i}]`));
  } catch (err) {
    return fail([(err as Error).message]);
  }
  const pkg = b['package'];
  const packageHash = b['packageHash'];
  const life = lifecycleOf(carried, packageHash, pkg, signature);
  const result = await verify(
    { package: JSON.parse(JSON.stringify(pkg)) as JsonObject, packageHash, signature },
    { registry, ...(registry ? { registryProvenance: 'declared-url' as const } : {}), fetch, lifecycleResolution: life },
  );
  const failures = [
    ...checkFailures(result, registry !== undefined),
    ...carriedFailures(carried, packageHash),
    ...lifecycleFailures(result.lifecycle, rec),
    ...viewFailures(b, pkg, rec, index, registry),
  ];
  return { ok: failures.length === 0, status: result.lifecycle.status, failures };
}

function registryOf(served: FileMap, index: HostIndex): { registry?: TrustRegistry; failure?: string; line: string } {
  const bytes = served.get(REGISTRY_PATH);
  if (index.trustRegistryUrl === undefined) {
    if (bytes !== undefined) return { failure: 'registry', line: `registry: ${REGISTRY_PATH} is served, but ${INDEX_PATH} names no trustRegistryUrl` };
    return { line: `registry: none served; ${INDEX_PATH} names no trustRegistryUrl` };
  }
  if (index.trustRegistryUrl !== `${index.host}${REGISTRY_PATH}`) {
    return { failure: 'registry', line: `registry: ${INDEX_PATH} names ${index.trustRegistryUrl}, not ${index.host}${REGISTRY_PATH}, so the served copy is not what a verifier fetches` };
  }
  if (bytes === undefined) return { failure: 'registry', line: `registry: ${INDEX_PATH} names ${index.trustRegistryUrl}, and ${REGISTRY_PATH} is not served` };
  let parsed: unknown;
  try {
    parsed = parseJsonFile(bytes, REGISTRY_PATH);
  } catch (err) {
    return { failure: 'registry', line: `registry: ${(err as Error).message}` };
  }
  const registry = validateRegistry(parsed);
  if (!registry) return { failure: 'registry', line: `registry: ${REGISTRY_PATH} does not validate under verify-core` };
  return { registry, line: `registry: ${REGISTRY_PATH} validates, and each record's key reads active in it (#5)` };
}

/**
 * Verify every record the served index lists, offline. `served` holds the served
 * directory's files at host-core's paths: `records.json`, the registry, and the
 * bundles. Throws `HostError` when the index is missing or malformed.
 */
export async function verifyServed(served: FileMap, options: VerifyOptions = {}): Promise<VerifyReport> {
  const indexBytes = served.get(INDEX_PATH);
  if (indexBytes === undefined) throw new HostError(`${INDEX_PATH} is not served; run build first`);
  const index = parseIndex(parseJsonFile(indexBytes, INDEX_PATH));
  const verify = options.verifyRecord ?? coreVerifyRecord;
  const n = index.records.length;
  const lines = [
    `typedstandards-host verify: ${INDEX_PATH} lists ${n} record${n === 1 ? '' : 's'}, each verified offline by @typedstandards/verify-core with the network blocked`,
    'ok: the envelope hash and signature verify, no check reads alarm, the carried attestations give the status the index states, and the view matches its package and the served registry',
  ];
  const totals: VerifyTotals = { records: n, ok: 0, failed: 0, active: 0, withdrawn: 0, superseded: 0 };
  const counts = { global: 0, injected: 0 };
  const failed = new Set<string>();
  const reg = registryOf(served, index);
  if (reg.failure) failed.add(reg.failure);

  const injected: FetchLike = async (url) => {
    counts.injected += 1;
    throw new Error(`network blocked: ${url}`);
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    counts.global += 1;
    throw new Error(`network blocked: ${String(input)}`);
  }) as typeof globalThis.fetch;
  try {
    for (const rec of index.records) {
      const r = await verifyOne(rec, served, index, reg.registry, injected, verify);
      if (r.ok) totals.ok += 1;
      else {
        totals.failed += 1;
        failed.add('records');
      }
      if (r.status === 'active' || r.status === 'withdrawn' || r.status === 'superseded') totals[r.status] += 1;
      lines.push(`  ${r.ok ? 'ok  ' : 'FAIL'}  ${r.status.padEnd(10)} ${rec.name}${r.failures.length ? `: ${r.failures.join('; ')}` : ''}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  lines.push(
    `records: ${n} listed, ${totals.ok} ok, ${totals.failed} failed; active ${totals.active}, withdrawn ${totals.withdrawn}, superseded ${totals.superseded}`,
  );
  lines.push(reg.line);
  lines.push(`network: global fetch calls ${counts.global}; injected fetch calls ${counts.injected}`);
  if (counts.global !== 0 || counts.injected !== 0) failed.add('network');
  const order = ['records', 'registry', 'network'].filter((f) => failed.has(f));
  lines.push(order.length === 0 ? 'result: all checks passed' : `result: FAILED (${order.join(', ')})`);
  return { ok: order.length === 0, lines, totals, fetch: counts };
}
