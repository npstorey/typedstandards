// #89, ruling D2 (sprint #98): a referenced file that cannot be fetched is an
// availability problem, so check #9 reads amber and the verdict is caveated — the
// reading check #4 already gives the same fact. A referenced file that is fetched and
// does not match (wrong hash, wrong size) or a malformed reference still fails the
// package: the verdict's alarm reads the reason, not `blobRefsVerified === false`.
//
// The packages are minted in process (Ed25519 via node:crypto, signed over the
// package-hash string as verify-flow.test.ts's `mintSigned` does); the referenced
// file's digest is computed here from the bytes it names. Each run goes through the
// whole page in URL mode, with the referenced file served, altered, or blocked.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import {
  recomputePackageHash,
  sha256Hex,
  utf8ToBytes,
  RAW_BYTES_CANONICALIZATION,
  type VerifyResult,
  type EnvelopeIntegrityResult,
} from '@typedstandards/verify-core';
import {
  resolveInput,
  buildVerifyInput,
  runVerify,
  presentVerification,
  rollupVerdict,
  buildCheckRows,
  HOST_DIRECTORY,
  type CheckRow,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

const REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const COMMITMENT_URL = 'https://registry-host.test/api/records/p2-blob/commitment';
const OUTPUT_URL = 'https://blobs.registry-host.test/output.csv';
const TRACE_URL = 'https://blobs.registry-host.test/trace.json';

const OUTPUT_BYTES = utf8ToBytes('column_a,column_b\r\nvalue,2\n');
const TRACE_BYTES = utf8ToBytes('{"resourceSpans":[]}');
/** Same length as the named bytes, different content: a hash mismatch, not a size one. */
const sameSizeOther = (bytes: Uint8Array): Uint8Array => bytes.map((b, i) => (i === 0 ? b ^ 0x01 : b));

const blobRef = (bytes: Uint8Array, url: string, contentType: string) => ({
  ref: `blob:sha256:${sha256Hex(bytes)}`,
  url,
  contentType,
  size: bytes.byteLength,
});

/** A signed commitment for a package under raw-bytes/v1 whose `output` is a BlobRef,
 *  optionally with a BlobRef `trace` too. Its registry lists the key active. */
function mintBlobRecord(opts: { trace?: boolean } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const kid = 'test:synthetic-2026';
  const signer = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:synthetic-publisher' };
  const pkg: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    type: 'content/analysis/v1',
    signer,
    metadata: { signingKeyId: kid },
    contentCanonicalization: RAW_BYTES_CANONICALIZATION,
    output: blobRef(OUTPUT_BYTES, OUTPUT_URL, 'text/csv'),
    contentHash: { sha256: sha256Hex(OUTPUT_BYTES) },
    ...(opts.trace ? { trace: blobRef(TRACE_BYTES, TRACE_URL, 'application/json') } : {}),
  };
  const packageHash = recomputePackageHash(pkg);
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      {
        kid,
        publicKey: publicKeyB64,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: signer,
      },
    ],
  };
  const commitment = {
    protocolVersion: '0.1.0',
    packageHash,
    package: pkg,
    signer,
    signature: {
      algorithm: 'Ed25519',
      publicKey: publicKeyB64,
      signature: Buffer.from(nodeSign(null, Buffer.from(packageHash, 'utf8'), privateKey)).toString('base64'),
      kid,
    },
    trustRegistryUrl: REGISTRY_URL,
  };
  return { commitment, registry };
}

type FileReply = Uint8Array | 'blocked' | 'not found';

/** Verify the record by URL with each referenced file answered as `files` says.
 *  Records every URL requested. */
async function pageWith(m: ReturnType<typeof mintBlobRecord>, files: Record<string, FileReply>) {
  const json: Record<string, unknown> = { [COMMITMENT_URL]: m.commitment, [REGISTRY_URL]: m.registry, [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };
  const calls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    calls.push(u);
    if (u in json) {
      return Promise.resolve(
        new Response(JSON.stringify(json[u]), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    }
    const reply = files[u];
    if (reply === 'blocked') return Promise.reject(new TypeError('network blocked'));
    if (reply instanceof Uint8Array) return Promise.resolve(new Response(new Blob([new Uint8Array(reply)]), { status: 200 }));
    return Promise.resolve(new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('url', COMMITMENT_URL);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    const shown = presentVerification(resolved, vinput, result);
    return { result, rows: shown.rows, verdict: shown.verdict, calls };
  } finally {
    globalThis.fetch = real;
  }
}

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

const notGreen = (rows: CheckRow[]) =>
  rows.filter((r) => r.signal.tier === 'attention' || r.signal.tier === 'alarm').map((r) => `${r.num}:${r.signal.tier}`);

test('#89 control: every referenced file fetched and matching reads Verified', async () => {
  const page = await pageWith(mintBlobRecord({ trace: true }), { [OUTPUT_URL]: OUTPUT_BYTES, [TRACE_URL]: TRACE_BYTES });
  assert.equal(page.result.blobRefsVerified, true);
  assert.equal(page.result.contentHash?.status, 'ok');
  assert.deepEqual(notGreen(page.rows), []);
  assert.equal(page.verdict.headline, 'Verified');
});

test('#89: a referenced file that cannot be fetched reads caveated, with #9 and #4 amber for the one blocked fetch', async () => {
  for (const reply of ['blocked', 'not found'] as const) {
    const page = await pageWith(mintBlobRecord(), { [OUTPUT_URL]: reply });
    assert.equal(page.result.blobRefs[0]?.reason, 'fetch_failed', reply);
    assert.equal(page.result.contentHash?.status, 'content_bytes_unavailable', reply);
    // One request for the file, read by both checks (#90).
    assert.equal(page.calls.filter((u) => u === OUTPUT_URL).length, 1, `${reply}: fetched once`);
    assert.deepEqual(notGreen(page.rows), ['4:attention', '9:attention'], `${reply}: #4 and #9 give one reading`);
    assert.equal(rowOf(page.rows, '9').signal.label, 'Referenced content could not be retrieved', reply);
    assert.notEqual(page.verdict.headline, 'Verification failed', reply);
    assert.equal(page.verdict.headline, 'Verified, with caveats', reply);
    assert.equal(page.verdict.tier, 'attention', reply);
    assert.ok(page.verdict.detail.includes('#4 Content fingerprint'), page.verdict.detail);
    assert.ok(page.verdict.detail.includes('#9 Referenced content'), page.verdict.detail);
  }
  // A referenced file #4 does not fingerprint (a trace): #9 alone reads amber.
  const trace = await pageWith(mintBlobRecord({ trace: true }), { [OUTPUT_URL]: OUTPUT_BYTES, [TRACE_URL]: 'blocked' });
  assert.deepEqual(notGreen(trace.rows), ['9:attention']);
  assert.equal(trace.verdict.headline, 'Verified, with caveats');
});

test('#89: a referenced file fetched with the wrong hash or the wrong size reads "Verification failed"', async () => {
  const cases: { label: string; files: Record<string, FileReply>; reason: string }[] = [
    { label: 'trace, wrong hash', files: { [OUTPUT_URL]: OUTPUT_BYTES, [TRACE_URL]: sameSizeOther(TRACE_BYTES) }, reason: 'hash_mismatch' },
    { label: 'trace, wrong size', files: { [OUTPUT_URL]: OUTPUT_BYTES, [TRACE_URL]: utf8ToBytes('{}') }, reason: 'size_mismatch' },
    // A mismatch beside a file that could not be fetched still fails.
    { label: 'trace wrong hash, output blocked', files: { [OUTPUT_URL]: 'blocked', [TRACE_URL]: sameSizeOther(TRACE_BYTES) }, reason: 'hash_mismatch' },
  ];
  for (const c of cases) {
    const page = await pageWith(mintBlobRecord({ trace: true }), c.files);
    assert.ok(page.result.blobRefs.some((r) => r.reason === c.reason), c.label);
    assert.equal(rowOf(page.rows, '9').signal.tier, 'alarm', c.label);
    assert.equal(page.verdict.headline, 'Verification failed', c.label);
    assert.equal(page.verdict.tier, 'alarm', c.label);
  }
  // The raw-bytes output itself, wrong hash: #9 and #4 both fail.
  const output = await pageWith(mintBlobRecord(), { [OUTPUT_URL]: sameSizeOther(OUTPUT_BYTES) });
  assert.equal(output.result.blobRefs[0]?.reason, 'hash_mismatch');
  assert.equal(output.result.contentHash?.status, 'content_hash_mismatch');
  assert.equal(output.verdict.headline, 'Verification failed');
});

/** A result green in every check but #9, whose references read `refs`. */
function withRefs(refs: { ok: boolean; reason?: string }[], over: Partial<VerifyResult> = {}): VerifyResult {
  return {
    hashMatch: true,
    envelopeIntegrity: { status: 'verified' } as EnvelopeIntegrityResult,
    recomputedHash: 'a'.repeat(64),
    nodeId: 'a'.repeat(64),
    signatureValid: true,
    hasSigning: true,
    rekorVerified: true,
    rekorDetails: null,
    rekorInclusion: null,
    hasRekor: true,
    hasTimestamp: false,
    rfc3161: null,
    keyTrust: { status: 'active' },
    blobRefsVerified: refs.every((r) => r.ok),
    blobRefs: refs.map((r, i) => ({ field: i === 0 ? 'output' : 'trace', ref: `blob:sha256:${'b'.repeat(64)}`, url: TRACE_URL, size: 2, contentType: 'x', ...r })),
    contentCanonicalization: { status: 'ok', rule: 'x' },
    contentHash: { status: 'ok' },
    typeResolution: { status: 'ok', type: 'content/analysis/v1' },
    signerIdentity: { status: 'ok' },
    captureMethodVocab: { status: 'ok', profileType: 'x' },
    contentProfile: { status: 'ok' },
    lifecycle: { status: 'active', source: 'none' },
    ...over,
  } as unknown as VerifyResult;
}

const DECLARED_META = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;
const ROW_INPUT = buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {});

test('#89: the verdict reads the reason of every reference — a malformed reference fails, fetch failures alone caveat', () => {
  const read = (refs: { ok: boolean; reason?: string }[], over: Partial<VerifyResult> = {}) => {
    const result = withRefs(refs, over);
    return {
      verdict: rollupVerdict(result, DECLARED_META),
      row9: rowOf(buildCheckRows(result, ROW_INPUT, { packageHash: 'ab'.repeat(32) }, DECLARED_META), '9').signal.tier,
    };
  };
  for (const reason of ['invalid_ref', 'size_mismatch', 'hash_mismatch']) {
    const r = read([{ ok: false, reason }]);
    assert.equal(r.verdict.headline, 'Verification failed', reason);
    assert.equal(r.row9, 'alarm', reason);
    const mixed = read([{ ok: false, reason: 'fetch_failed' }, { ok: false, reason }]);
    assert.equal(mixed.verdict.headline, 'Verification failed', `${reason} beside fetch_failed`);
  }
  const unfetched = read([{ ok: false, reason: 'fetch_failed' }, { ok: false, reason: 'fetch_failed' }]);
  assert.equal(unfetched.verdict.headline, 'Verified, with caveats');
  assert.equal(unfetched.row9, 'attention');
  const partly = read([{ ok: true }, { ok: false, reason: 'fetch_failed' }]);
  assert.equal(partly.verdict.headline, 'Verified, with caveats');
  // A failed reference with no reason is read as failed, as before.
  assert.equal(read([{ ok: false }]).verdict.headline, 'Verification failed');
  // The self-certified and content-private branches caveat the same way.
  const sc = read([{ ok: false, reason: 'fetch_failed' }], {
    keyTrust: { status: 'self_certified', verified: false } as VerifyResult['keyTrust'],
    signerIdentity: { status: 'key_derived_match' } as VerifyResult['signerIdentity'],
  });
  assert.equal(sc.verdict.headline, 'Signature valid, with caveats — self-certified signer');
});
