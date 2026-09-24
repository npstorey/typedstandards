// #104, ruled C by the owner (issuecomment-5794006401): the #7 row reads `attention`
// only for a token whose reason `TIMESTAMP_FAILURE_CLASS` classes as a caveat, and then
// says the timestamp was not confirmed against a pinned authority, not that it did not
// verify. A fail-class reason keeps `alarm` and "Timestamp did not verify". A result
// with no reason, and a token present but not evaluated, keep `alarm` (the #95 test,
// '#86, widened', pins the no-reason case). The row reads the class the headline reads,
// so for every reason verify-core reports, the two agree.
//
// Results are built here, as timestamp-verdict.test.ts's `failedWith` builds them: every
// check green but the timestamp. The end-to-end cases, through `verifyRecord` over a
// real FreeTSA token, are in timestamp-verdict.test.ts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RFC3161_FAIL_REASONS, type VerifyResult, type EnvelopeIntegrityResult } from '@typedstandards/verify-core';
import { TIMESTAMP_FAILURE_CLASS } from './trust-signal.ts';
import { buildCheckRows, buildVerifyInput, rollupVerdict, type CheckRow } from './verify-flow.ts';

const DECLARED_META = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;
const COMMITMENT = { packageHash: 'ab'.repeat(32) };

/** A result green in every check but the timestamp. */
function withTimestamp(rfc3161: VerifyResult['rfc3161'], hasTimestamp = true): VerifyResult {
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
    hasTimestamp,
    rfc3161,
    keyTrust: { status: 'active' },
    blobRefsVerified: null,
    blobRefs: [],
    contentCanonicalization: { status: 'ok', rule: 'x' },
    contentHash: { status: 'ok' },
    typeResolution: { status: 'ok', type: 'content/analysis/v1' },
    signerIdentity: { status: 'ok' },
    captureMethodVocab: { status: 'ok', profileType: 'x' },
    contentProfile: { status: 'ok' },
    lifecycle: { status: 'active', source: 'none' },
  } as unknown as VerifyResult;
}

/** A token that did not verify, with `reason`. */
const failedWith = (reason?: string): VerifyResult =>
  withTimestamp({ verified: false, chainVerified: false, ...(reason ? { reason } : {}) } as VerifyResult['rfc3161']);

function row7(result: VerifyResult): CheckRow {
  const rows = buildCheckRows(result, buildVerifyInput(COMMITMENT, null), COMMITMENT, DECLARED_META);
  const r = rows.find((x) => x.num === '7');
  assert.ok(r, 'row #7 is rendered');
  return r;
}

const headlineOf = (result: VerifyResult) => rollupVerdict(result, DECLARED_META).headline;

test('#104 caveat: a caveat-class reason (untrusted_root) reads attention on the #7 row — not confirmed against a pinned authority — under the caveated headline', () => {
  const result = failedWith('untrusted_root');
  const r = row7(result);
  assert.equal(r.signal.tier, 'attention');
  assert.notEqual(r.signal.label, 'Timestamp did not verify');
  assert.match(r.signal.label, /not confirmed against a pinned authority/);
  assert.doesNotMatch(r.signal.detail ?? '', /did not verify/);
  assert.equal(headlineOf(result), 'Verified, with caveats');
});

test('#104 fail: a fail-class reason (signature_invalid) keeps alarm and "Timestamp did not verify" under "Verification failed"', () => {
  const result = failedWith('signature_invalid');
  const r = row7(result);
  assert.equal(r.signal.tier, 'alarm');
  assert.equal(r.signal.label, 'Timestamp did not verify');
  assert.equal(headlineOf(result), 'Verification failed');
});

test('#104: a result with no reason, a token present but not evaluated, and a reason this site does not know keep alarm', () => {
  assert.equal(row7(failedWith(undefined)).signal.tier, 'alarm', 'no reason');
  assert.equal(row7(withTimestamp(null)).signal.tier, 'alarm', 'not evaluated');
  assert.equal(row7(failedWith('a_reason_added_later')).signal.tier, 'alarm', 'not a class entry');
  assert.equal(row7(failedWith('toString')).signal.tier, 'alarm', 'not a prototype key');
  // The calm and green readings are unchanged.
  assert.equal(row7(withTimestamp(null, false)).signal.tier, 'normal', 'absent');
  assert.equal(row7(withTimestamp({ verified: true, chainVerified: true } as VerifyResult['rfc3161'])).signal.tier, 'verified');
});

test('#104: for every reason verify-core reports, the #7 row and the headline read the same class', () => {
  for (const reason of RFC3161_FAIL_REASONS) {
    const result = failedWith(reason);
    const tier = row7(result).signal.tier;
    const headline = headlineOf(result);
    if (TIMESTAMP_FAILURE_CLASS[reason] === 'fails') {
      assert.deepEqual([tier, headline], ['alarm', 'Verification failed'], reason);
    } else {
      assert.deepEqual([tier, headline], ['attention', 'Verified, with caveats'], reason);
    }
  }
});

test('#100 and #104: a chain link whose signature does not verify fails with an alarm row; a link signed with an algorithm the validator does not implement is caveated with an attention row', () => {
  const invalid = failedWith('chain_signature_invalid');
  assert.deepEqual([row7(invalid).signal.tier, headlineOf(invalid)], ['alarm', 'Verification failed']);
  const unsupported = failedWith('chain_algorithm_unsupported');
  assert.deepEqual([row7(unsupported).signal.tier, headlineOf(unsupported)], ['attention', 'Verified, with caveats']);
});
