// Offline verification, and the `verify` command (typedstandards#109 G0 D3).
//
// One function verifies a record for all three commands that need it: `sign`
// checks its own result with it before printing, `view` checks the record it is
// asked to serve, and `verify` reports it. verify-core's `verifyRecord` runs the
// checks with the offline fetcher and no trust registry; the lifecycle comes from
// the carried withdrawals through `verifyLifecycleChain`.

import {
  isBlobRef,
  sha256Hex,
  verifyLifecycleChain,
  verifyRecord,
  type BlobRef,
  type BlobRefField,
  type LifecycleResolution,
  type VerifyResult,
  type VerifySignatureEnvelope,
} from '@typedstandards/verify-core';
import { EXIT, usageError } from './errors.ts';
import { isObject, readBytes, readJson, type JsonObject } from './input.ts';
import type { Io } from './io.ts';
import { offlineFetch } from './offline.ts';
import { readingsOf, type CarriedNode, type Reading } from './readings.ts';

export interface Verdict {
  /** No check reads `alarm`. */
  ok: boolean;
  /** The recomputed envelope hash (check #13). */
  nodeId: string | null;
  failures: Reading[];
  attention: Reading[];
  checks: VerifyResult;
  lifecycle: LifecycleResolution;
  /** URLs a check asked for and the offline fetcher refused: not checked. */
  refused: string[];
}

export interface RecordToVerify {
  package: JsonObject;
  packageHash: string;
  signature: VerifySignatureEnvelope;
  carried: CarriedNode[];
  /** Local bytes for BlobRef URLs, served by the offline fetcher. */
  local?: ReadonlyMap<string, Uint8Array>;
}

export async function verifyOffline(io: Io, record: RecordToVerify): Promise<Verdict> {
  const offline = offlineFetch(record.local);
  const signer = record.package['signer'];
  const signerId = isObject(signer) && typeof signer['identifier'] === 'string' ? signer['identifier'] : '';
  const lifecycleResolution =
    record.carried.length > 0 ? verifyLifecycleChain(record.carried, record.packageHash, signerId) : undefined;
  const checks = await (io.verifyRecord ?? verifyRecord)(
    { package: record.package, packageHash: record.packageHash, signature: record.signature },
    { registry: undefined, fetch: offline.fetch, ...(lifecycleResolution ? { lifecycleResolution } : {}) },
  );
  const readings = readingsOf(checks, record.carried, record.packageHash);
  const failures = readings.filter((r) => r.tier === 'alarm');
  return {
    ok: failures.length === 0,
    nodeId: checks.nodeId,
    failures,
    attention: readings.filter((r) => r.tier === 'attention'),
    checks,
    lifecycle: checks.lifecycle,
    refused: offline.refused,
  };
}

const describe = (r: Reading) => `${r.check} ${r.field}: ${r.status} (${r.tier})`;

/** Print what a verdict found that is not plain success, on stderr. */
export function reportVerdict(io: Io, command: string, verdict: Verdict): void {
  for (const r of [...verdict.failures, ...verdict.attention]) io.stderr(`typedstandards ${command}: ${describe(r)}\n`);
  for (const url of new Set(verdict.refused)) io.stderr(`typedstandards ${command}: not checked offline: ${url}\n`);
}

export function failureSummary(verdict: Verdict): string {
  return verdict.failures.map(describe).join('; ') || 'no alarm, but the record did not read as verified';
}

// ---------------------------------------------------------------------------
// What `sign`, `withdraw` and `view` print, read back

const HEX_64 = /^[0-9a-f]{64}$/;

export function checkSignature(value: unknown, where: string): VerifySignatureEnvelope {
  if (!isObject(value) || typeof value['signature'] !== 'string' || typeof value['publicKey'] !== 'string') {
    throw usageError(`${where} must be an object with a signature and a publicKey string`);
  }
  for (const key of ['algorithm', 'kid']) {
    if (key in value && typeof value[key] !== 'string') throw usageError(`${where}.${key} must be a string`);
  }
  return value as unknown as VerifySignatureEnvelope;
}

function exactKeys(value: JsonObject, keys: readonly string[], what: string): void {
  const extra = Object.keys(value).filter((k) => !keys.includes(k));
  if (extra.length) throw usageError(`${extra.join(', ')}: not part of ${what}`);
  const missing = keys.filter((k) => !(k in value));
  if (missing.length) throw usageError(`${what} is missing ${missing.join(', ')}`);
}

/** `sign`'s output: `{package, envelopeHash, signature}`. */
export function checkSignedDocument(value: unknown, flag: string): { package: JsonObject; envelopeHash: string; signature: VerifySignatureEnvelope } {
  if (!isObject(value)) throw usageError(`${flag} must be what sign prints: {package, envelopeHash, signature}`);
  exactKeys(value, ['package', 'envelopeHash', 'signature'], `${flag}, which sign prints`);
  if (!isObject(value['package'])) throw usageError(`${flag}: package must be an object`);
  if (typeof value['envelopeHash'] !== 'string' || !HEX_64.test(value['envelopeHash'])) {
    throw usageError(`${flag}: envelopeHash must be 64 lowercase hex characters`);
  }
  return {
    package: value['package'],
    envelopeHash: value['envelopeHash'],
    signature: checkSignature(value['signature'], `${flag}: signature`),
  };
}

/** `withdraw`'s output: `{node, nodeId, signature}`. */
export function checkCarriedNode(value: unknown, where: string): CarriedNode {
  if (!isObject(value)) throw usageError(`${where} must be what withdraw prints: {node, nodeId, signature}`);
  exactKeys(value, ['node', 'nodeId', 'signature'], `${where}, which withdraw prints`);
  if (!isObject(value['node'])) throw usageError(`${where}: node must be an object`);
  if (typeof value['nodeId'] !== 'string') throw usageError(`${where}: nodeId must be a string`);
  checkSignature(value['signature'], `${where}: signature`);
  return value as unknown as CarriedNode;
}

// The keys `view` can emit: buildCommitmentView's, from the inputs view passes it,
// plus the inline package.
const BUNDLE_KEYS = [
  'protocolVersion',
  'packageHash',
  'packageUrl',
  'visibility',
  'captureMethod',
  'contentProfile',
  'producerProfile',
  'type',
  'signer',
  'contentHash',
  'contentCanonicalization',
  'signature',
  'lifecycle',
  'lifecycleAttestations',
  'trustRegistryUrl',
  'subjectTitle',
  'subjectSummary',
  'package',
];

// verify-core's BlobRef fields (checks.ts BLOB_REF_FIELDS, not exported).
const BLOB_REF_FIELDS = { output: true, trace: true, 'skillMetadata.skillText': true } satisfies Record<BlobRefField, true>;

function blobRefsOf(pkg: JsonObject): BlobRef[] {
  return Object.keys(BLOB_REF_FIELDS).flatMap((path) => {
    let current: unknown = pkg;
    for (const segment of path.split('.')) current = isObject(current) ? current[segment] : undefined;
    return isBlobRef(current) ? [current] : [];
  });
}

/**
 * Pair `--blob` files with the record's BlobRefs: by SHA-256 first; then, when
 * exactly one file and one reference are left, with each other, so a changed
 * file reads as a mismatch rather than as unmatched. Anything else is refused.
 */
export function pairBlobs(io: Io, paths: readonly string[], pkg: JsonObject): Map<string, Uint8Array> {
  const refs = blobRefsOf(pkg);
  const files = paths.map((path) => ({ path, bytes: readBytes(io, path, '--blob') }));
  const local = new Map<string, Uint8Array>();
  const unmatchedRefs = refs.filter((ref) => {
    const file = files.find((f) => `blob:sha256:${sha256Hex(f.bytes)}` === ref.ref);
    if (file) local.set(ref.url, file.bytes);
    return !file;
  });
  const unmatchedFiles = files.filter((f) => !refs.some((ref) => ref.ref === `blob:sha256:${sha256Hex(f.bytes)}`));
  if (unmatchedFiles.length === 1 && unmatchedRefs.length === 1) {
    local.set(unmatchedRefs[0].url, unmatchedFiles[0].bytes);
  } else if (unmatchedFiles.length > 0) {
    throw usageError(
      `--blob ${unmatchedFiles.map((f) => f.path).join(', ')}: matches no BlobRef in the record, and cannot be paired with one`,
    );
  }
  return local;
}

export const VERIFY_OPTIONS = {
  input: { type: 'string' },
  blob: { type: 'string', multiple: true },
  json: { type: 'boolean' },
} as const;

export interface VerifyValues {
  input?: string;
  blob?: string[];
  json?: boolean;
}

/** `verify`: offline verification of what `sign` or `view` printed. */
export async function verifyCommand(values: VerifyValues, io: Io): Promise<{ document: JsonObject; code: number }> {
  if (values.input === undefined) throw usageError('--input is required: a file sign or view printed, or - for standard input');
  const value = readJson(io, values.input, '--input');
  if (!isObject(value)) throw usageError('--input must be what sign or view prints');
  let record: RecordToVerify;
  if ('envelopeHash' in value) {
    const signed = checkSignedDocument(value, '--input');
    record = { package: signed.package, packageHash: signed.envelopeHash, signature: signed.signature, carried: [] };
  } else if ('packageHash' in value) {
    const extra = Object.keys(value).filter((k) => !BUNDLE_KEYS.includes(k));
    if (extra.length) throw usageError(`--input: ${extra.join(', ')}: verify reads what sign and view print, and view prints none of these`);
    if (!isObject(value['package'])) throw usageError('--input: the bundle carries no package; verify runs offline and needs it inline');
    if (typeof value['packageHash'] !== 'string') throw usageError('--input: packageHash must be a string');
    const carriedValue = value['lifecycleAttestations'] ?? [];
    if (!Array.isArray(carriedValue)) throw usageError('--input: lifecycleAttestations must be an array');
    record = {
      package: value['package'],
      packageHash: value['packageHash'],
      signature: checkSignature(value['signature'], '--input: signature'),
      carried: carriedValue.map((c, i) => checkCarriedNode(c, `--input: lifecycleAttestations[${i}]`)),
    };
  } else {
    throw usageError('--input must be what sign prints ({package, envelopeHash, signature}) or what view prints (a bundle)');
  }
  record.local = pairBlobs(io, values.blob ?? [], record.package);
  const verdict = await verifyOffline(io, record);
  reportVerdict(io, 'verify', verdict);
  const document: JsonObject = {
    ok: verdict.ok,
    nodeId: verdict.nodeId,
    failures: verdict.failures.map(({ check, field, status }) => ({ check, field, status })),
    ...(values.json ? { checks: verdict.checks, lifecycle: verdict.lifecycle } : {}),
  };
  return { document, code: verdict.ok ? EXIT.ok : EXIT.verificationFailed };
}
