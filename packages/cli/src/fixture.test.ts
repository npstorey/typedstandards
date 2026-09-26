// The publish script's fixture, scripts/fixtures/published-verify.bundle.json:
// the bundle the published `verify` must read as ok and withdrawn. Its provenance
// is this test. It regenerates the fixture from the RFC 8032 §7.1 TEST 1 seed and
// fixed ids through the built CLI (sign, withdraw, view), and requires the
// committed bytes to equal the regenerated ones.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RFC8032_TEST_1_B64, SEED_VARIABLE, cli, fileInput, scratch } from './harness.test.ts';

const FIXTURE = fileURLToPath(new URL('../scripts/fixtures/published-verify.bundle.json', import.meta.url));

/** Build the fixture's bytes from their inputs. */
export function regenerate(): string {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: RFC8032_TEST_1_B64 };
    const signed = cli(
      [
        'sign',
        '--input',
        dir.write('input.json', JSON.stringify(fileInput({ packageId: 'f1e2d3c4-b5a6-4978-8a6b-5c4d3e2f1a0b', createdAt: '2026-09-26T00:00:00.000Z' }))),
        '--output-file',
        dir.write('record.txt', 'An example record, signed with the RFC 8032 section 7.1 TEST 1 seed.\n'),
      ],
      { env },
    );
    assert.equal(signed.code, 0, signed.err);
    const withdrawal = cli(['withdraw', '--input', '-'], {
      env,
      stdin: JSON.stringify({
        targetNodeId: signed.json()['envelopeHash'],
        reason: 'An example withdrawal.',
        signer: { bindingTier: 'pseudonymous', displayName: 'Example signer' },
        packageId: 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d',
        createdAt: '2026-09-26T00:01:00.000Z',
      }),
    });
    assert.equal(withdrawal.code, 0, withdrawal.err);
    const view = cli([
      'view',
      '--signed',
      dir.write('signed.json', signed.out),
      '--withdrawal',
      dir.write('withdrawal.json', withdrawal.out),
      '--visibility',
      'public',
      '--title',
      'Published-verify fixture',
    ]);
    assert.equal(view.code, 0, view.err);
    return view.out;
  } finally {
    dir.cleanup();
  }
}

test('the publish script\'s fixture regenerates byte for byte, and verify reads it as ok and withdrawn', () => {
  assert.equal(readFileSync(FIXTURE, 'utf8'), regenerate(), 'the committed fixture differs from what this build regenerates');
  const r = cli(['verify', '--input', FIXTURE, '--json']);
  assert.equal(r.code, 0, r.err);
  const out = r.json() as { ok: boolean; lifecycle: { status: string } };
  assert.equal(out.ok, true);
  assert.equal(out.lifecycle.status, 'withdrawn');
});
