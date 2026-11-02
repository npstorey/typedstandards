// Offline verification, and the `verify` command (typedstandards#109 G0 D3).
//
// One function verifies a record for all three commands that need it: `sign`
// checks its own result with it before printing, `view` checks the record it is
// asked to serve, and `verify` reports it. verify-core's `verifyRecord` runs the
// checks with the offline fetcher and no trust registry; the lifecycle comes from
// the carried withdrawals through `verifyLifecycleChain`.
//
// `verify` also reads the commitment view a host serves (typedstandards#166):
// produce-core's `buildCommitmentView` with the host's additions. Its RFC 3161 token
// and log inclusion proof go to verify-core, which checks them offline (#7, #8).
// Its log entry id does not: checking that entry's hash against the record needs
// the log, so `verify` reports it as not checked. What else a host adds is its own
// unsigned statement, accepted and not read.

import {
  isBlobRef,
  parseInclusionProof,
  sha256Hex,
  verifyLifecycleChain,
  verifyRecord,
  type BlobRef,
  type BlobRefField,
  type LifecycleResolution,
  type RekorInclusionProof,
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
  /** What the record carried that offline verification does not check. */
  notChecked: string[];
}

/** A commitment view's proofs, as verify-core takes them (checks #7 and #8). */
export interface CarriedProofsInput {
  rfc3161Timestamp?: string;
  rekorInclusionProof?: RekorInclusionProof | null;
  rekorEntryBody?: string;
}

export interface RecordToVerify {
  package: JsonObject;
  packageHash: string;
  signature: VerifySignatureEnvelope;
  carried: CarriedNode[];
  /** Local bytes for BlobRef URLs, served by the offline fetcher. */
  local?: ReadonlyMap<string, Uint8Array>;
  /** The proofs a host-served view carries, passed to verify-core as they are. */
  proofs?: CarriedProofsInput;
  /** The view's transparency-log entry id, which is not checked offline. */
  rekorEntryId?: string;
}

export async function verifyOffline(io: Io, record: RecordToVerify): Promise<Verdict> {
  const offline = offlineFetch(record.local);
  const signer = record.package['signer'];
  const signerId = isObject(signer) && typeof signer['identifier'] === 'string' ? signer['identifier'] : '';
  // A carried attestation moves status only when its key is bound to the signer it
  // names; the record's own signing key is what verify holds to bind it.
  const lifecycleResolution =
    record.carried.length > 0
      ? verifyLifecycleChain(record.carried, record.packageHash, signerId, { targetPublicKey: record.signature.publicKey })
      : undefined;
  const checks = await (io.verifyRecord ?? verifyRecord)(
    { package: record.package, packageHash: record.packageHash, signature: record.signature, ...record.proofs },
    { registry: undefined, fetch: offline.fetch, ...(lifecycleResolution ? { lifecycleResolution } : {}) },
  );
  const readings = readingsOf(
    checks,
    record.carried,
    record.packageHash,
    { signerIdentifier: signerId, publicKey: record.signature.publicKey },
    { rekorEntryCarried: record.rekorEntryId !== undefined },
  );
  const failures = readings.filter((r) => r.tier === 'alarm');
  return {
    ok: failures.length === 0,
    nodeId: checks.nodeId,
    failures,
    attention: readings.filter((r) => r.tier === 'attention'),
    checks,
    lifecycle: checks.lifecycle,
    refused: offline.refused,
    notChecked: record.rekorEntryId !== undefined ? [`the log's copy of entry ${record.rekorEntryId}`] : [],
  };
}

const describe = (r: Reading) => `${r.check} ${r.field}: ${r.status} (${r.tier})`;

/** Print what a verdict found that is not plain success, on stderr. */
export function reportVerdict(io: Io, command: string, verdict: Verdict): void {
  for (const r of [...verdict.failures, ...verdict.attention]) io.stderr(`typedstandards ${command}: ${describe(r)}\n`);
  for (const url of new Set(verdict.refused)) io.stderr(`typedstandards ${command}: not checked offline: ${url}\n`);
  for (const what of verdict.notChecked) io.stderr(`typedstandards ${command}: not checked offline: ${what}\n`);
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

/** `withdraw`'s and `attest`'s output: `{node, nodeId, signature}`. */
export function checkCarriedNode(value: unknown, where: string): CarriedNode {
  if (!isObject(value)) throw usageError(`${where} must be what withdraw or attest prints: {node, nodeId, signature}`);
  exactKeys(value, ['node', 'nodeId', 'signature'], `${where}, which withdraw and attest print`);
  if (!isObject(value['node'])) throw usageError(`${where}: node must be an object`);
  if (typeof value['nodeId'] !== 'string') throw usageError(`${where}: nodeId must be a string`);
  checkSignature(value['signature'], `${where}: signature`);
  return value as unknown as CarriedNode;
}

// The keys of a commitment view: first those `view` can emit (buildCommitmentView's,
// from the inputs view passes it, plus the inline package), then those
// buildCommitmentView emits from inputs a host passes it, the prior-era name of
// `protocolVersion`, and the registry copy a host serves beside an inline package.
const VIEW_KEYS = [
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
  'signerIdentity',
  'rfc3161Timestamp',
  'rekorEntryId',
  'rekorInclusionProof',
  'rekorEntryBody',
  'trustRegistryUrlLegacy',
  'evidenceProtocolVersion',
  'trustRegistry',
];

// The flags a host adds to a carried attestation: its unsigned statement that it
// holds a timestamp or a log entry for the node. Accepted, and removed before the
// node is read, so nothing reports them.
const HOST_ATTESTATION_FLAGS = ['hasTimestamp', 'hasRekor'];

function withoutHostFlags(value: unknown, where: string): unknown {
  if (!isObject(value)) return value;
  const node: JsonObject = {};
  for (const [key, flag] of Object.entries(value)) {
    if (!HOST_ATTESTATION_FLAGS.includes(key)) node[key] = flag;
    else if (typeof flag !== 'boolean') throw usageError(`${where}.${key} must be a boolean`);
  }
  return node;
}

function optionalString(value: JsonObject, key: string): string | undefined {
  if (!(key in value)) return undefined;
  if (typeof value[key] !== 'string') throw usageError(`--input: ${key} must be a string`);
  return value[key];
}

/** A commitment view's proofs and log entry id; each key is passed on only when present. */
function viewProofs(value: JsonObject): { proofs: CarriedProofsInput; rekorEntryId?: string } {
  const proofs: CarriedProofsInput = {};
  const rfc3161Timestamp = optionalString(value, 'rfc3161Timestamp');
  if (rfc3161Timestamp !== undefined) proofs.rfc3161Timestamp = rfc3161Timestamp;
  // The proof is carried as JSON text; verify-core's one guard parses it, and an
  // unusable one is null, so inclusion reads not verified.
  const proofText = optionalString(value, 'rekorInclusionProof');
  if (proofText !== undefined) proofs.rekorInclusionProof = parseInclusionProof(proofText);
  const rekorEntryBody = optionalString(value, 'rekorEntryBody');
  if (rekorEntryBody !== undefined) proofs.rekorEntryBody = rekorEntryBody;
  const rekorEntryId = optionalString(value, 'rekorEntryId');
  return { proofs, ...(rekorEntryId !== undefined ? { rekorEntryId } : {}) };
}

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
  package: { type: 'string' },
  blob: { type: 'string', multiple: true },
  json: { type: 'boolean' },
} as const;

export interface VerifyValues {
  input?: string;
  package?: string;
  blob?: string[];
  json?: boolean;
}

/** `verify`: offline verification of what `sign` or `view` printed, or of the commitment view a host serves. */
export async function verifyCommand(values: VerifyValues, io: Io): Promise<{ document: JsonObject; code: number }> {
  if (values.input === undefined) throw usageError('--input is required: a file sign or view printed or a host served, or - for standard input');
  if (values.input === '-' && values.package === '-') throw usageError('--input and --package cannot both read standard input');
  const value = readJson(io, values.input, '--input');
  if (!isObject(value)) throw usageError('--input must be a JSON object: what sign prints or a commitment view');
  let record: RecordToVerify;
  if ('envelopeHash' in value) {
    if (values.package !== undefined) throw usageError('--package: the input is what sign prints, which carries its package');
    const signed = checkSignedDocument(value, '--input');
    record = { package: signed.package, packageHash: signed.envelopeHash, signature: signed.signature, carried: [] };
  } else if ('packageHash' in value) {
    const extra = Object.keys(value).filter((k) => !VIEW_KEYS.includes(k));
    if (extra.length) throw usageError(`--input: ${extra.join(', ')}: not part of a commitment view (what view prints or a host serves)`);
    let pkg = value['package'];
    if (values.package !== undefined) {
      if ('package' in value) throw usageError('--package: the view already carries a package');
      pkg = readJson(io, values.package, '--package');
      if (!isObject(pkg)) throw usageError('--package must be a package: a JSON object');
    }
    if (!isObject(pkg)) {
      throw usageError('--input: the view carries no package, and verify runs offline: include it as package, or name its file with --package');
    }
    if (typeof value['packageHash'] !== 'string') throw usageError('--input: packageHash must be a string');
    const carriedValue = value['lifecycleAttestations'] ?? [];
    if (!Array.isArray(carriedValue)) throw usageError('--input: lifecycleAttestations must be an array');
    record = {
      package: pkg,
      packageHash: value['packageHash'],
      signature: checkSignature(value['signature'], '--input: signature'),
      carried: carriedValue.map((c, i) => {
        const where = `--input: lifecycleAttestations[${i}]`;
        return checkCarriedNode(withoutHostFlags(c, where), where);
      }),
      ...viewProofs(value),
    };
  } else {
    throw usageError('--input must be what sign prints ({package, envelopeHash, signature}) or a commitment view with packageHash (what view prints or a host serves)');
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
