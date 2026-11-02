// The alarm table of G0 D3 (typedstandards#109): verify fails exactly on the
// statuses typedstandards.org's verifier reads as alarm, and the copied tables
// still equal the site's, tier by tier.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { RFC3161_FAIL_REASONS, type Rfc3161VerifyResult, type RekorInclusionResult, type VerifyResult } from '@typedstandards/verify-core';
import { REKOR_INCLUDED_TIER, SITE_TABLES, TIMESTAMP_REASON_TIERS, readingsOf, type Tier } from './readings.ts';

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
    systemPrompt: { status: 'not_applicable' },
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

test('check #17: a datHere package without its system prompt reads attention and does not fail', () => {
  const absent = { ...clean(), systemPrompt: { status: 'skillText_absent' } } as VerifyResult;
  assert.deepEqual(alarms(absent), []);
  const reading = readingsOf(absent, [], 'a'.repeat(64)).find((x) => x.check === '#17');
  assert.deepEqual(reading, { check: '#17', field: 'systemPrompt', status: 'skillText_absent', tier: 'attention' });
  const tiers = (status: string) =>
    readingsOf({ ...clean(), systemPrompt: { status } } as VerifyResult, [], 'a'.repeat(64)).find((x) => x.check === '#17')?.tier;
  assert.equal(tiers('ok'), 'verified');
  assert.equal(tiers('not_applicable'), 'normal');
  // No package, no reading.
  assert.equal(readingsOf({ ...clean(), systemPrompt: null }, [], 'a'.repeat(64)).find((x) => x.check === '#17'), undefined);
});

test('the check #17 table is compared with the site\'s', () => {
  assert.ok('SYSTEM_PROMPT_SIGNALS' in SITE_TABLES);
  assert.deepEqual(Object.keys(SITE_TABLES.SYSTEM_PROMPT_SIGNALS).sort(), ['not_applicable', 'ok', 'skillText_absent']);
});

// Checks #7 and #8 (typedstandards#166): a commitment view a host serves carries an
// RFC 3161 token and a transparency-log inclusion proof, which verify-core checks
// offline. Their tiers are copied from the site's TIMESTAMP_SIGNALS and REKOR_SIGNALS.

test('the check #7 and check #8 tables are compared with the site\'s', async () => {
  assert.ok('TIMESTAMP_SIGNALS' in SITE_TABLES, 'check #7 is not compared');
  assert.ok('REKOR_SIGNALS' in SITE_TABLES, 'check #8 is not compared');
  const site = (await import(SITE)) as {
    TIMESTAMP_FAILURE_CLASS: Record<string, 'fails' | 'caveats'>;
    TIMESTAMP_SIGNALS: Record<'failed' | 'unconfirmed', { tier: Tier }>;
  };
  // Each reason a token that does not verify can carry reads at the tier the site's
  // class for it gives: fails, the site's `failed`; caveats, its `unconfirmed`.
  assert.deepEqual(Object.keys(TIMESTAMP_REASON_TIERS).sort(), [...RFC3161_FAIL_REASONS].sort());
  for (const reason of RFC3161_FAIL_REASONS) {
    const siteClass = site.TIMESTAMP_FAILURE_CLASS[reason];
    const expected = site.TIMESTAMP_SIGNALS[siteClass === 'fails' ? 'failed' : 'unconfirmed'].tier;
    assert.equal(TIMESTAMP_REASON_TIERS[reason], expected, `${reason}: the CLI reads ${TIMESTAMP_REASON_TIERS[reason]}, the site ${expected}`);
  }
});

const reading = (r: VerifyResult, check: string) => readingsOf(r, [], 'a'.repeat(64)).filter((x) => x.check === check);

test('check #7: a token that verifies reads verified; one that does not reads as the site\'s verdict reads its reason', () => {
  const token = (rfc3161: Partial<Rfc3161VerifyResult>): VerifyResult => ({ ...clean(), hasTimestamp: true, rfc3161: rfc3161 as Rfc3161VerifyResult });
  assert.deepEqual(reading(token({ verified: true }), '#7'), [{ check: '#7', field: 'rfc3161', status: 'verified', tier: 'verified' }]);
  assert.deepEqual(reading(token({ verified: false, reason: 'imprint_mismatch' }), '#7'), [
    { check: '#7', field: 'rfc3161', status: 'imprint_mismatch', tier: 'alarm' },
  ]);
  assert.deepEqual(reading(token({ verified: false, reason: 'untrusted_root' }), '#7'), [
    { check: '#7', field: 'rfc3161', status: 'untrusted_root', tier: 'attention' },
  ]);
  // A token present but not evaluated reads as the site's verdict reads it: caveated.
  assert.deepEqual(reading({ ...clean(), hasTimestamp: true, rfc3161: null }, '#7'), [
    { check: '#7', field: 'rfc3161', status: 'not_evaluated', tier: 'attention' },
  ]);
  // No token, no reading.
  assert.deepEqual(reading(clean(), '#7'), []);
});

test('check #8: an inclusion proof that verifies offline reads REKOR_INCLUDED_TIER; one that does not reads attention, never alarm', () => {
  const inclusion = (r: Partial<RekorInclusionResult>): VerifyResult => ({ ...clean(), rekorInclusion: r as RekorInclusionResult });
  assert.ok(REKOR_INCLUDED_TIER === 'verified' || REKOR_INCLUDED_TIER === 'normal', `REKOR_INCLUDED_TIER is ${REKOR_INCLUDED_TIER}`);
  assert.deepEqual(reading(inclusion({ inclusionVerified: true, checkpointVerified: true }), '#8'), [
    { check: '#8', field: 'rekorInclusion', status: 'included', tier: REKOR_INCLUDED_TIER },
  ]);
  for (const reason of ['root_mismatch', 'checkpoint_signature_invalid', 'checkpoint_unknown_anchor'] as const) {
    const verifiedFold = reason !== 'root_mismatch';
    assert.deepEqual(reading(inclusion({ inclusionVerified: verifiedFold, checkpointVerified: false, reason }), '#8'), [
      { check: '#8', field: 'rekorInclusion', status: reason, tier: 'attention' },
    ]);
  }
  // A log entry with no inclusion proof: the host names an entry, nothing offline confirms it.
  assert.deepEqual(readingsOf(clean(), [], 'a'.repeat(64), undefined, { rekorEntryCarried: true }).filter((x) => x.check === '#8'), [
    { check: '#8', field: 'rekorInclusion', status: 'not_carried', tier: 'attention' },
  ]);
  // Nothing carried, no reading.
  assert.deepEqual(reading(clean(), '#8'), []);
});
