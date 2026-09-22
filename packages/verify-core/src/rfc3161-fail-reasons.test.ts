// The timestamp failure reasons verify-core exports (sprint typedstandards#98, phase
// P1b): RFC3161_FAIL_REASONS, every reason `verifyRfc3161Timestamp` can return and the
// source of truth `Rfc3161FailReason` is derived from, so a consumer's classification of
// the reasons (#94, ruling D1) can fail when a new reason arrives unclassified. The shape
// follows BLOB_REF_VERIFY_REASONS in blob-ref.ts; frozen, unlike that one, so a consumer
// that reads it cannot change it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  RFC3161_FAIL_REASONS,
  verifyRfc3161Timestamp,
  type Rfc3161FailReason,
  type Rfc3161VerifyResult,
} from './index.ts';

// --- The timestamp failure reasons (check #7) ------------------------------------

// Compile-time: `Rfc3161FailReason` is the array's element type, and the result's
// `reason` field carries exactly that type, so every reason the verifier can return
// is a member. `npm run typecheck` (tsconfig.test.json) fails if either drifts.
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const reasonTypeIsDerived: Equal<Rfc3161FailReason, (typeof RFC3161_FAIL_REASONS)[number]> = true;
const resultReasonIsAMember: Equal<
  NonNullable<Rfc3161VerifyResult['reason']>,
  (typeof RFC3161_FAIL_REASONS)[number]
> = true;

test('RFC3161_FAIL_REASONS is exported, frozen, and holds the twelve reason codes', () => {
  assert.ok(reasonTypeIsDerived && resultReasonIsAMember);
  assert.ok(Object.isFrozen(RFC3161_FAIL_REASONS), 'the reason list must be read-only at runtime');
  assert.throws(() => (RFC3161_FAIL_REASONS as unknown as string[]).push('example'), TypeError);
  assert.deepEqual(
    [...RFC3161_FAIL_REASONS],
    [
      'parse_error',
      'unexpected_algorithm',
      'no_message_digest',
      'content_not_bound',
      'imprint_mismatch',
      'no_signing_cert',
      'eku_not_timestamping',
      'genTime_outside_validity',
      'chain_incomplete',
      'chain_signature_invalid',
      'untrusted_root',
      'signature_invalid',
    ],
  );
});

test('reasons returned by verifyRfc3161Timestamp on real inputs are members of RFC3161_FAIL_REASONS', async () => {
  const fx = JSON.parse(
    readFileSync(new URL('./__fixtures__/rfc3161-token.json', import.meta.url), 'utf8'),
  ) as { tokenB64: string; expectedHashHex: string };
  const raw = Buffer.from(fx.tokenB64, 'base64');
  raw[raw.length - 1] ^= 0xff;
  const forged = raw.toString('base64');
  const results = await Promise.all([
    verifyRfc3161Timestamp('bm90LWEtdG9rZW4=', fx.expectedHashHex),
    verifyRfc3161Timestamp(fx.tokenB64, 'f'.repeat(64)),
    verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, []),
    verifyRfc3161Timestamp(forged, fx.expectedHashHex),
    verifyRfc3161Timestamp(forged, fx.expectedHashHex, []),
  ]);
  const reasons = results.map((r) => r.reason);
  assert.deepEqual(reasons, [
    'parse_error',
    'imprint_mismatch',
    'untrusted_root',
    'signature_invalid',
    'signature_invalid',
  ]);
  for (const reason of reasons) {
    assert.ok((RFC3161_FAIL_REASONS as readonly string[]).includes(reason!), reason);
  }
});
