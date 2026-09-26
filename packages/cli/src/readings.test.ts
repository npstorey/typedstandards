// The alarm table of G0 D3 (typedstandards#109): verify fails exactly on the
// statuses typedstandards.org's verifier reads as alarm, and the copied tables
// still equal the site's, tier by tier.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import type { VerifyResult } from '@typedstandards/verify-core';
import { SITE_TABLES, readingsOf, type Tier } from './readings.ts';

// Read at run time by path, so the site's source stays out of this package's
// type-check program.
const SITE = fileURLToPath(new URL('../../../apps/web/src/lib/trust-signal.ts', import.meta.url));

test('the copied tiers equal typedstandards.org\'s, table by table (apps/web/src/lib/trust-signal.ts)', async () => {
  const site = (await import(SITE)) as Record<string, { tier: Tier } | Record<string, { tier: Tier }>>;
  let compared = 0;
  for (const [name, ours] of Object.entries(SITE_TABLES)) {
    const theirs = site[name];
    assert.ok(theirs, `trust-signal.ts no longer exports ${name}`);
    if (typeof ours === 'string') {
      const tier = (theirs as { tier: Tier }).tier;
      assert.equal(ours, tier, `${name}: the CLI reads ${ours}, the site ${String(tier)}`);
      compared++;
      continue;
    }
    const siteTiers = Object.fromEntries(Object.entries(theirs as Record<string, { tier: Tier }>).map(([k, v]) => [k, v.tier]));
    assert.deepEqual(ours, siteTiers, `${name}: the CLI's tiers differ from the site's`);
    compared += Object.keys(ours).length;
  }
  assert.ok(compared >= 50, `compared ${compared} readings: the instrument saw too little`);
});

/** A result every check of which passes; each test changes one field. */
function clean(): VerifyResult {
  return {
    hashMatch: true,
    envelopeIntegrity: { status: 'verified' },
    recomputedHash: 'a'.repeat(64),
    nodeId: 'a'.repeat(64),
    signatureValid: true,
    hasSigning: true,
    rekorVerified: null,
    rekorDetails: null,
    rekorInclusion: null,
    hasRekor: false,
    hasTimestamp: false,
    rfc3161: null,
    keyTrust: { status: 'self_certified' } as VerifyResult['keyTrust'],
    blobRefsVerified: null,
    blobRefs: [],
    contentCanonicalization: { status: 'ok' } as VerifyResult['contentCanonicalization'],
    contentHash: { status: 'ok' } as VerifyResult['contentHash'],
    typeResolution: { status: 'ok' } as VerifyResult['typeResolution'],
    signerIdentity: { status: 'key_derived_match' } as VerifyResult['signerIdentity'],
    signingKeyIdConsistency: { status: 'ok' },
    captureMethodVocab: { status: 'ok' } as VerifyResult['captureMethodVocab'],
    contentProfile: { status: 'contentProfile_absent' } as VerifyResult['contentProfile'],
    lifecycle: { status: 'active', source: 'none', chain: [] },
  };
}

const alarms = (r: VerifyResult) => readingsOf(r, [], 'a'.repeat(64)).filter((x) => x.tier === 'alarm').map((x) => `${x.check} ${x.status}`);

test('a clean result has no alarm', () => {
  assert.deepEqual(alarms(clean()), []);
});

test('each alarm status the memo lists reads alarm', () => {
  const cases: Array<[Partial<VerifyResult>, string]> = [
    [{ envelopeIntegrity: { status: 'altered' } }, '#1 altered'],
    [{ signatureValid: false }, '#2 false'],
    [{ contentHash: { status: 'content_hash_mismatch' } as VerifyResult['contentHash'] }, '#4 content_hash_mismatch'],
    [{ keyTrust: { status: 'revoked' } as VerifyResult['keyTrust'] }, '#5 revoked'],
    [{ keyTrust: { status: 'deprecated_invalid' } as VerifyResult['keyTrust'] }, '#5 deprecated_invalid'],
    [{ signingKeyIdConsistency: { status: 'signingKeyId_mismatch' } }, '#6 signingKeyId_mismatch'],
    [{ blobRefs: [{ field: 'output', ref: 'r', url: 'u', size: 1, contentType: 't', ok: false, reason: 'hash_mismatch' }] }, '#9 hash_mismatch'],
    [{ blobRefs: [{ field: 'output', ref: 'r', url: 'u', size: 1, contentType: 't', ok: false, reason: 'size_mismatch' }] }, '#9 size_mismatch'],
    [{ blobRefs: [{ field: 'output', ref: 'r', url: 'u', size: 1, contentType: 't', ok: false, reason: 'invalid_ref' }] }, '#9 invalid_ref'],
    [{ signerIdentity: { status: 'signer_identity_mismatch' } as VerifyResult['signerIdentity'] }, '#14 signer_identity_mismatch'],
    [{ signerIdentity: { status: 'key_derived_mismatch' } as VerifyResult['signerIdentity'] }, '#14 key_derived_mismatch'],
  ];
  for (const [change, expected] of cases) assert.deepEqual(alarms({ ...clean(), ...change }), [expected]);
});

test('attention readings do not fail: a key with no registry, an unfetched file, an unknown type', () => {
  const r = {
    ...clean(),
    keyTrust: { status: 'registry_unavailable' } as VerifyResult['keyTrust'],
    blobRefs: [{ field: 'output' as const, ref: 'r', url: 'u', size: 1, contentType: 't', ok: false, reason: 'fetch_failed' as const }],
    typeResolution: { status: 'unknown_type' } as VerifyResult['typeResolution'],
    contentHash: { status: 'content_bytes_unavailable' } as VerifyResult['contentHash'],
  };
  assert.deepEqual(alarms(r), []);
  const attention = readingsOf(r, [], 'a'.repeat(64)).filter((x) => x.tier === 'attention').map((x) => x.check);
  assert.deepEqual(attention.sort(), ['#12', '#4', '#5', '#9'].sort());
});
