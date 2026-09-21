// Check #16 — `metadata.contentProfile` (hub ADR-0029 §5). Four statuses:
//   - `ok`                          present, known, consistent (or producerProfile absent);
//   - `contentProfile_absent`       the key is absent (read as "default", spec §8.1.2);
//   - `contentProfile_unknown`      present and neither "default" nor "datHere";
//   - `contentProfile_inconsistent` present, known, producerProfile present, and
//                                   the ADR-0006 §2 invariant fails.
// The invariant is compared only when BOTH fields are present.
//
// Synthetic packages only: each is the minimal object the check reads.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkContentProfile,
  verifyRecord,
  CONTENT_PROFILE_STATUSES,
  KNOWN_CONTENT_PROFILES,
  type FetchLike,
} from './index.ts';

const failFetch: FetchLike = async () => {
  throw new Error('no network in this test');
};

function pkgWith(
  contentProfile: unknown,
  producerProfile?: string,
): Record<string, unknown> {
  const metadata: Record<string, unknown> = { captureMethod: 'script-run' };
  if (contentProfile !== undefined) metadata['contentProfile'] = contentProfile;
  return {
    metadata,
    ...(producerProfile !== undefined ? { producerProfile } : {}),
  };
}

test('the status list is exactly the four ADR-0029 §5 statuses', () => {
  assert.deepEqual(
    [...CONTENT_PROFILE_STATUSES],
    ['ok', 'contentProfile_absent', 'contentProfile_unknown', 'contentProfile_inconsistent'],
  );
  assert.deepEqual([...KNOWN_CONTENT_PROFILES], ['default', 'datHere']);
});

test('an unknown contentProfile is reported contentProfile_unknown by verifyRecord, not passed', async () => {
  const pkg = pkgWith('adopter-profile', 'scripted-recomputation/eval-run');
  const result = await verifyRecord(
    { package: pkg, packageHash: 'a'.repeat(64) },
    { registry: undefined, fetch: failFetch },
  );
  assert.equal(result.contentProfile?.status, 'contentProfile_unknown');
  assert.equal(result.contentProfile?.contentProfile, 'adopter-profile');
});

test('contentProfile_unknown: any value other than "default" / "datHere"', () => {
  assert.equal(checkContentProfile(pkgWith('adopter-profile')).status, 'contentProfile_unknown');
  // Case matters: the known value is "datHere".
  assert.equal(checkContentProfile(pkgWith('dathere')).status, 'contentProfile_unknown');
  assert.equal(checkContentProfile(pkgWith('')).status, 'contentProfile_unknown');
  // A present non-string value is not a known value either.
  assert.equal(checkContentProfile(pkgWith(7)).status, 'contentProfile_unknown');
  assert.equal(checkContentProfile(pkgWith(null)).status, 'contentProfile_unknown');
  // Consistency is not judged for an unknown value, whatever producerProfile says.
  assert.equal(
    checkContentProfile(pkgWith('adopter-profile', 'ai-assisted-analysis/datHere')).status,
    'contentProfile_unknown',
  );
});

test('contentProfile_absent: no key, no metadata, with or without producerProfile', () => {
  assert.equal(checkContentProfile(pkgWith(undefined)).status, 'contentProfile_absent');
  assert.equal(
    checkContentProfile(pkgWith(undefined, 'scripted-recomputation/eval-run')).status,
    'contentProfile_absent',
  );
  // An absent key is never compared, even against a datHere producerProfile.
  assert.equal(
    checkContentProfile(pkgWith(undefined, 'ai-assisted-analysis/datHere')).status,
    'contentProfile_absent',
  );
  assert.equal(checkContentProfile({}).status, 'contentProfile_absent');
});

test('ok: a known value with producerProfile absent is not compared', () => {
  assert.equal(checkContentProfile(pkgWith('default')).status, 'ok');
  // "datHere" with no producerProfile: the invariant needs both fields, so ok.
  const r = checkContentProfile(pkgWith('datHere'));
  assert.deepEqual(r, { status: 'ok', contentProfile: 'datHere' });
});

test('ok: a known value consistent with a present producerProfile', () => {
  assert.equal(
    checkContentProfile(pkgWith('datHere', 'ai-assisted-analysis/datHere')).status,
    'ok',
  );
  assert.equal(
    checkContentProfile(pkgWith('default', 'ai-assisted-analysis/general')).status,
    'ok',
  );
  assert.deepEqual(checkContentProfile(pkgWith('default', 'scripted-recomputation/eval-run')), {
    status: 'ok',
    contentProfile: 'default',
    producerProfile: 'scripted-recomputation/eval-run',
  });
});

test('contentProfile_inconsistent: both present and the invariant fails, in either direction', () => {
  // "datHere" without a datHere producerProfile.
  assert.equal(
    checkContentProfile(pkgWith('datHere', 'scripted-recomputation/eval-run')).status,
    'contentProfile_inconsistent',
  );
  assert.equal(
    checkContentProfile(pkgWith('datHere', 'ai-assisted-analysis/general')).status,
    'contentProfile_inconsistent',
  );
  // A datHere producerProfile without "datHere".
  assert.equal(
    checkContentProfile(pkgWith('default', 'ai-assisted-analysis/datHere')).status,
    'contentProfile_inconsistent',
  );
});

test('verifyRecord reports null for #16 when the package is unavailable', async () => {
  const result = await verifyRecord(
    { package: null, packageHash: 'a'.repeat(64), contentUnavailableReason: 'private' },
    { registry: undefined, fetch: failFetch },
  );
  assert.equal(result.contentProfile, null);
});
