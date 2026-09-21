// The scripted-recomputation Producer Profile (hub ADR-0029 §2, §6) on a real
// signed package.
//
// Fixture: `__fixtures__/adr-0028-recomputation.package.json` is
// `package/recomputation.package.json` from the ADR-0028 eval-run example
// repository at commit 9031a94, copied byte for byte (`cmp` clean; file SHA-256
// pinned below). It is signed and cannot be re-signed, so the byte-equal checks
// are load-bearing: the file's SHA-256, and the envelope hash recomputed from it,
// which equals the hash its signature covers.
//
// Before ADR-0029, check #15 reported `producerProfile_bundle_unresolved` on this
// package (profileType `scripted-recomputation`). The package uses legacy-json/v1,
// so it does not exercise the raw-bytes rule.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  computeEnvelopeHash,
  resolveContentCanonicalization,
  verifyContentHash,
  checkCaptureMethodVocab,
  checkContentProfile,
  captureVocabForProfile,
  sha256Hex,
  LEGACY_JSON_CANONICALIZATION,
  PROFILE_CAPTURE_VOCAB,
} from './index.ts';

const FIXTURE_BYTES = new Uint8Array(
  readFileSync(new URL('./__fixtures__/adr-0028-recomputation.package.json', import.meta.url)),
);
/** `shasum -a 256 package/recomputation.package.json` at the source commit. */
const FIXTURE_FILE_SHA256 = 'e9e23334d9544cae02fdbfa17a1522aee5d71f0670cdf91d5cd17ee14f887ab2';
/** The envelope hash the package's signature covers (ADR-0028, ADR-0029 §6). */
const ENVELOPE_HASH = 'abb93f781ae71480bf8075474facbb272f3dcc38d50eeecda79be33427924a9c';

const pkg = JSON.parse(new TextDecoder().decode(FIXTURE_BYTES)) as Record<string, unknown>;

test('fixture is the source file byte for byte', () => {
  assert.equal(sha256Hex(FIXTURE_BYTES), FIXTURE_FILE_SHA256);
});

test('fixture recomputes to the signed envelope hash', () => {
  assert.equal(computeEnvelopeHash(pkg), ENVELOPE_HASH);
});

test('the fallback table carries scripted-recomputation with exactly two values', () => {
  assert.deepEqual(PROFILE_CAPTURE_VOCAB['scripted-recomputation'], ['script-run', 'tool-emitted']);
  assert.deepEqual(captureVocabForProfile('scripted-recomputation/any-subtype'), [
    'script-run',
    'tool-emitted',
  ]);
  // The ai-assisted-analysis entry is unchanged.
  assert.deepEqual(PROFILE_CAPTURE_VOCAB['ai-assisted-analysis'], [
    'chat-flow-stream',
    'claude-code-jsonl-readback',
    'claude-code-self-report',
  ]);
});

test('check #15 on the ADR-0028 recomputation package is ok', () => {
  assert.deepEqual(checkCaptureMethodVocab(pkg), {
    status: 'ok',
    captureMethod: 'script-run',
    profileType: 'scripted-recomputation',
  });
});

test('#15: a value from the other profile is captureMethod_unknown under scripted-recomputation', () => {
  const other = {
    ...pkg,
    metadata: { ...(pkg['metadata'] as Record<string, unknown>), captureMethod: 'chat-flow-stream' },
  };
  assert.equal(checkCaptureMethodVocab(other).status, 'captureMethod_unknown');
});

test('content-profile check (#16) on the package is contentProfile_absent', () => {
  assert.ok(!('contentProfile' in (pkg['metadata'] as Record<string, unknown>)));
  assert.deepEqual(checkContentProfile(pkg), {
    status: 'contentProfile_absent',
    producerProfile: 'scripted-recomputation/eval-run',
  });
});

test('checks #3 and #4 on the package are ok under legacy-json/v1 (unchanged)', () => {
  const res = resolveContentCanonicalization(pkg);
  assert.deepEqual(res, { status: 'ok', rule: LEGACY_JSON_CANONICALIZATION });
  const ch = verifyContentHash(pkg, res);
  assert.equal(ch.status, 'ok');
  assert.equal(ch.matched, 'sha256');
});
