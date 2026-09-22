// #88, the site half (sprint #98): check #6 — the signature envelope's `kid` against
// `metadata.signingKeyId` (spec §9.2 #6, §8.3.1) — has a row, which verify-core
// reports since P1 (`VerifyResult.signingKeyIdConsistency`). Tiers:
//   - `ok` → verified;
//   - `signingKeyId_mismatch` → alarm, and it fails the package: §8.3.1 requires the
//     two to be equal and the specification reads a difference as envelope drift;
//   - `signingKeyId_absent` → attention: the envelope `kid` is bound by nothing
//     signed, so the check cannot confirm it — unconfirmed, not evidence of change;
//   - `kid_absent` → normal: nothing to compare (legacy packages, and a key-derived
//     signer, for whom `kid` is optional).
// A result without the check (no package, or no parsed envelope) has no row.
//
// Packages are minted at test time (Ed25519 via node:crypto); the captured bundles
// are the committed `__fixtures__/q15-*.json`, read unchanged.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { recomputePackageHash, type VerifyResult, type EnvelopeIntegrityResult } from '@typedstandards/verify-core';
import {
  resolveInput,
  buildVerifyInput,
  runVerify,
  resolveCarriedLifecycle,
  presentVerification,
  rollupVerdict,
  buildCheckRows,
  registryMetaOf,
  HOST_DIRECTORY,
  type CheckRow,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

const REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const COMMITMENT_URL = 'https://registry-host.test/api/records/p2-kid/commitment';

/** A signed record whose envelope `kid` is `kid` and whose package carries
 *  `signingKeyId` (omitted when undefined). The registry lists the envelope's kid. */
function mint(kid: string, signingKeyId: string | undefined) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const signer = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:synthetic-publisher' };
  const pkg: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    type: 'content/analysis/v1',
    signer,
    metadata: signingKeyId === undefined ? {} : { signingKeyId },
    output: 'A minted record package for the check #6 tests.',
  };
  const packageHash = recomputePackageHash(pkg);
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      { kid, publicKey: publicKeyB64, status: 'active', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: null, revokedAt: null, signerIdentity: signer },
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

async function pageByUrl(m: ReturnType<typeof mint>) {
  const routes: Record<string, unknown> = { [COMMITMENT_URL]: m.commitment, [REGISTRY_URL]: m.registry, [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    return Promise.resolve(
      u in routes
        ? new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }),
    );
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('url', COMMITMENT_URL);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg);
    const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    const shown = presentVerification(resolved, vinput, result);
    return { result, rows: shown.rows, verdict: shown.verdict };
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

test('#88: the #6 row renders for a matching kid, in number order, and the record reads Verified', async () => {
  const page = await pageByUrl(mint('test:synthetic-2026', 'test:synthetic-2026'));
  assert.equal(page.result.signingKeyIdConsistency?.status, 'ok');
  const row = rowOf(page.rows, '6');
  assert.equal(row.name, 'Signing key id');
  assert.equal(row.signal.tier, 'verified');
  assert.deepEqual(
    row.math.map((m) => [m.label, m.value]),
    [
      ['Envelope kid', 'test:synthetic-2026'],
      ['metadata.signingKeyId', 'test:synthetic-2026'],
    ],
  );
  const nums = page.rows.map((r) => Number(r.num));
  assert.deepEqual(nums, [...nums].sort((a, b) => a - b), 'rows in check-number order');
  assert.deepEqual(notGreen(page.rows), []);
  assert.equal(page.verdict.headline, 'Verified');
});

test('#88: a kid that differs from metadata.signingKeyId renders the #6 row at alarm and fails the package', async () => {
  const page = await pageByUrl(mint('test:synthetic-2026', 'test:another-2026'));
  assert.equal(page.result.signatureValid, true, 'the signature itself verifies');
  assert.equal(page.result.signingKeyIdConsistency?.status, 'signingKeyId_mismatch');
  const row = rowOf(page.rows, '6');
  assert.equal(row.signal.tier, 'alarm');
  assert.deepEqual(
    row.math.map((m) => [m.label, m.value]),
    [
      ['Envelope kid', 'test:synthetic-2026'],
      ['metadata.signingKeyId', 'test:another-2026'],
    ],
  );
  assert.deepEqual(notGreen(page.rows), ['6:alarm']);
  assert.equal(page.verdict.headline, 'Verification failed');
  assert.equal(page.verdict.tier, 'alarm');
});

test('#88: a package with no metadata.signingKeyId under an envelope kid reads #6 attention and a caveated headline', async () => {
  const page = await pageByUrl(mint('test:synthetic-2026', undefined));
  assert.equal(page.result.signingKeyIdConsistency?.status, 'signingKeyId_absent');
  const row = rowOf(page.rows, '6');
  assert.equal(row.signal.tier, 'attention');
  assert.equal(rowOf(page.rows, '6').math.find((m) => m.label === 'metadata.signingKeyId')?.value, 'absent');
  assert.deepEqual(notGreen(page.rows), ['6:attention']);
  assert.equal(page.verdict.headline, 'Verified, with caveats');
  assert.ok(page.verdict.detail.includes('#6 Signing key id'), page.verdict.detail);
});

/** The page for a committed captured bundle, offline (every fetch throws). */
async function capturedPage(short: string) {
  const raw = readFileSync(new URL(`./__fixtures__/q15-${short}.json`, import.meta.url), 'utf8');
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    throw new Error(`NETWORK BLOCKED: ${String(input)}`);
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('bundle', raw);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, resolveCarriedLifecycle(resolved.commitment), resolved.registryProvenance);
    const meta = registryMetaOf(resolved);
    return { result, rows: buildCheckRows(result, vinput, resolved.commitment, meta), verdict: rollupVerdict(result, meta) };
  } finally {
    globalThis.fetch = real;
  }
}

test('#88: the captured bundles read #6 as measured in P1 — ok for the two with both fields, kid_absent (calm) for the legacy one', async () => {
  for (const short of ['d67b8e', '255b8e']) {
    const page = await capturedPage(short);
    assert.equal(page.result.signingKeyIdConsistency?.status, 'ok', short);
    assert.equal(rowOf(page.rows, '6').signal.tier, 'verified', short);
    assert.equal(page.verdict.headline, 'Verified, with caveats', `${short}: unchanged (the bundle's registry)`);
  }
  const legacy = await capturedPage('da9246');
  assert.equal(legacy.result.signingKeyIdConsistency?.status, 'kid_absent');
  assert.equal(rowOf(legacy.rows, '6').signal.tier, 'normal');
  assert.equal(legacy.verdict.headline, 'Verified, with caveats', 'da9246: unchanged');
});

/** A green result with check #6 at `status`. */
function withCheck6(status: string | null): VerifyResult {
  return {
    hashMatch: true,
    envelopeIntegrity: { status: 'verified' } as EnvelopeIntegrityResult,
    recomputedHash: 'a'.repeat(64),
    nodeId: 'a'.repeat(64),
    signatureValid: true,
    kid: 'test:synthetic-2026',
    hasSigning: true,
    rekorVerified: true,
    rekorDetails: null,
    rekorInclusion: null,
    hasRekor: true,
    hasTimestamp: false,
    rfc3161: null,
    keyTrust: { status: 'active' },
    blobRefsVerified: null,
    blobRefs: [],
    contentCanonicalization: { status: 'ok', rule: 'x' },
    contentHash: { status: 'ok' },
    typeResolution: { status: 'ok', type: 'content/analysis/v1' },
    signerIdentity: { status: 'ok' },
    signingKeyIdConsistency: status === null ? null : { status },
    captureMethodVocab: { status: 'ok', profileType: 'x' },
    contentProfile: { status: 'ok' },
    lifecycle: { status: 'active', source: 'none' },
  } as unknown as VerifyResult;
}

test('#88: the #6 row and the headline for each status, and no row without the check', () => {
  const meta = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;
  const input = buildVerifyInput({ packageHash: 'ab'.repeat(32) }, { metadata: { signingKeyId: 'test:synthetic-2026' } });
  const expected: Record<string, { tier: string; headline: string }> = {
    ok: { tier: 'verified', headline: 'Verified' },
    kid_absent: { tier: 'normal', headline: 'Verified' },
    signingKeyId_absent: { tier: 'attention', headline: 'Verified, with caveats' },
    signingKeyId_mismatch: { tier: 'alarm', headline: 'Verification failed' },
  };
  for (const [status, e] of Object.entries(expected)) {
    const result = withCheck6(status);
    const rows = buildCheckRows(result, input, { packageHash: 'ab'.repeat(32) }, meta);
    assert.equal(rowOf(rows, '6').signal.tier, e.tier, status);
    assert.equal(rollupVerdict(result, meta).headline, e.headline, status);
  }
  const none = buildCheckRows(withCheck6(null), input, { packageHash: 'ab'.repeat(32) }, meta);
  assert.equal(none.find((r) => r.num === '6'), undefined, 'no row without the check');
  assert.equal(rollupVerdict(withCheck6(null), meta).headline, 'Verified');
});
