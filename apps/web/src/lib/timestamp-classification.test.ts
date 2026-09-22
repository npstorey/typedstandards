// Guards over the site's readings of verify-core's status lists (sprint #98). Each is
// derived from the list verify-core exports at run time, not from a hand-kept copy,
// so a status verify-core adds fails here until the site classifies it:
//   - every RFC 3161 failure reason is classified as failing the package or caveating
//     it (#94) — `RFC3161_FAIL_REASONS`, exported since P1b;
//   - every check #6 status has a tier (#88) — `SIGNING_KEY_ID_CONSISTENCY_STATUSES`;
//   - every BlobRef failure reason has a tier, and only `fetch_failed` is not alarm
//     (#89) — `BLOB_REF_VERIFY_REASONS`.
// The same maps carry a `Record<…>` type over verify-core's unions, so the compiler
// also fails on a missing key; these tests fail at run time as well.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  RFC3161_FAIL_REASONS,
  SIGNING_KEY_ID_CONSISTENCY_STATUSES,
  BLOB_REF_VERIFY_REASONS,
  type VerifyResult,
} from '@typedstandards/verify-core';
import {
  TIMESTAMP_FAILURE_CLASS,
  classifyTimestamp,
  SIGNING_KEY_ID_SIGNALS,
  BLOB_REF_REASON_SIGNALS,
  BLOB_REFS_UNAVAILABLE,
  blobRefsOnlyUnfetched,
  resolveBlobRefResults,
} from './trust-signal.ts';
import { bundleRegistrySetAside, canRecheckKeyTrust } from './verify-flow.ts';

const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** The guard: throws, naming them, when any of `codes` has no classification. */
function assertClassified(codes: readonly string[]): void {
  const missing = codes.filter((c) => !has(TIMESTAMP_FAILURE_CLASS, c));
  assert.deepEqual(missing, [], `RFC 3161 reasons the site has not classified: ${missing.join(', ')}`);
}

test('guard: every RFC 3161 reason verify-core reports is classified, and no classification names a reason it does not report', () => {
  assertClassified(RFC3161_FAIL_REASONS);
  const reported = new Set<string>(RFC3161_FAIL_REASONS);
  assert.deepEqual(Object.keys(TIMESTAMP_FAILURE_CLASS).filter((k) => !reported.has(k)), []);
  assert.equal(RFC3161_FAIL_REASONS.length, 13);
});

test('guard: a reason code verify-core adds without a classification turns the guard red', () => {
  assert.throws(
    () => assertClassified([...RFC3161_FAIL_REASONS, 'a_reason_added_later']),
    /RFC 3161 reasons the site has not classified: a_reason_added_later/,
  );
});

test('#94: the classification is the seat’s, code by code (issuecomment-5784230955; chain_signature_invalid per #100)', () => {
  assert.deepEqual(TIMESTAMP_FAILURE_CLASS, {
    parse_error: 'fails',
    imprint_mismatch: 'fails',
    no_message_digest: 'fails',
    content_not_bound: 'fails',
    no_signing_cert: 'fails',
    eku_not_timestamping: 'fails',
    genTime_outside_validity: 'fails',
    signature_invalid: 'fails',
    unexpected_algorithm: 'caveats',
    untrusted_root: 'caveats',
    chain_incomplete: 'caveats',
    chain_signature_invalid: 'caveats',
    chain_outside_validity: 'caveats',
  });
  for (const reason of RFC3161_FAIL_REASONS) {
    assert.equal(classifyTimestamp(true, { verified: false, reason }), TIMESTAMP_FAILURE_CLASS[reason], reason);
  }
  assert.equal(classifyTimestamp(false, null), 'absent');
  assert.equal(classifyTimestamp(true, { verified: true }), 'verified');
  // No reason, not evaluated, or a reason this site does not know: a caveat.
  assert.equal(classifyTimestamp(true, { verified: false }), 'caveats');
  assert.equal(classifyTimestamp(true, null), 'caveats');
  assert.equal(classifyTimestamp(true, { verified: false, reason: 'a_reason_added_later' }), 'caveats');
  assert.equal(classifyTimestamp(true, { verified: false, reason: 'toString' }), 'caveats', 'not a prototype key');
});

test('guard: every check #6 status verify-core reports has a tier; only a mismatch alarms', () => {
  assert.deepEqual(Object.keys(SIGNING_KEY_ID_SIGNALS).sort(), [...SIGNING_KEY_ID_CONSISTENCY_STATUSES].sort());
  assert.deepEqual(
    Object.fromEntries(SIGNING_KEY_ID_CONSISTENCY_STATUSES.map((s) => [s, SIGNING_KEY_ID_SIGNALS[s].tier])),
    { ok: 'verified', signingKeyId_mismatch: 'alarm', kid_absent: 'normal', signingKeyId_absent: 'attention' },
  );
});

test('guard: every BlobRef reason verify-core reports has a tier; a file that could not be fetched is the only one that does not alarm (#89)', () => {
  assert.deepEqual(Object.keys(BLOB_REF_REASON_SIGNALS).sort(), [...BLOB_REF_VERIFY_REASONS].sort());
  for (const reason of BLOB_REF_VERIFY_REASONS) {
    assert.equal(BLOB_REF_REASON_SIGNALS[reason].tier, reason === 'fetch_failed' ? 'attention' : 'alarm', reason);
  }
  assert.equal(BLOB_REFS_UNAVAILABLE.tier, 'attention');
  assert.equal(blobRefsOnlyUnfetched([]), false, 'nothing failed');
  assert.equal(blobRefsOnlyUnfetched([{ ok: true }]), false);
  assert.equal(blobRefsOnlyUnfetched([{ ok: false, reason: 'fetch_failed' }, { ok: true }]), true);
  assert.equal(blobRefsOnlyUnfetched([{ ok: false }]), false, 'no reason reads as a mismatch');
  // A failed check with no reference listed reads as it did: alarm.
  assert.equal(resolveBlobRefResults(false, []).tier, 'alarm');
});

test('#97: bundleRegistrySetAside is exactly the key-derived, set-aside, inline-registry case, and the re-check needs an https: URL', () => {
  const setAside = {
    keyTrust: { status: 'registry_unavailable', verified: false },
    signerIdentity: { status: 'key_derived_match' },
  } as unknown as VerifyResult;
  const inline = { kind: 'inline', available: true, provenance: 'bundle', url: 'https://registry-host.test/r.json' } as const;
  assert.equal(bundleRegistrySetAside(inline, setAside), true);
  assert.equal(canRecheckKeyTrust(inline, setAside), true);
  assert.equal(canRecheckKeyTrust({ ...inline, url: 'http://registry-host.test/r.json' }, setAside), false, 'not https:');
  assert.equal(canRecheckKeyTrust({ kind: 'inline', available: true, provenance: 'bundle' }, setAside), false, 'no URL');
  // Each departure from the case.
  assert.equal(bundleRegistrySetAside({ ...inline, available: false }, setAside), false, 'bundle registry not valid');
  assert.equal(bundleRegistrySetAside({ kind: 'fetched', available: true, provenance: 'declared-url' }, setAside), false, 'fetched');
  const notKeyDerived = { ...setAside, signerIdentity: { status: 'ok' } } as unknown as VerifyResult;
  assert.equal(bundleRegistrySetAside(inline, notKeyDerived), false, 'not key-derived');
  assert.equal(canRecheckKeyTrust(inline, notKeyDerived), false, 'registry_unavailable alone is still not offered');
  const mismatch = { ...setAside, signerIdentity: { status: 'key_derived_mismatch' } } as unknown as VerifyResult;
  assert.equal(canRecheckKeyTrust(inline, mismatch), false, 'a mismatching identifier fails at #14');
});

test('#97: the re-check panel says the bundle’s registry was not used when it was set aside', () => {
  const source = readFileSync(new URL('../components/Verifier.tsx', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  assert.ok(source.includes('setAside={bundleRegistrySetAside(registryMetaOf(resolved), result)}'), 'the page passes the reading');
  assert.ok(source.includes('The registry carried in this bundle was not used.'), 'the set-aside lead');
  assert.ok(source.includes('Key trust used the registry carried in this bundle.'), 'the snapshot lead is kept for every other case');
});
