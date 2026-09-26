// Acceptance 1 (typedstandards#109): every envelope case in produce-core's
// reference-golden.json, and its withdraws case, driven through the BUILT CLI as a
// child process from the case's JSON input, yields the recorded bytes, content hash
// and envelope hash (node id for the withdrawal).
//
// Fixture provenance: packages/produce-core/src/__fixtures__/reference-golden.json,
// read in place (not copied), captured from the reference implementation at
// civic-ai-tools-website d39fdc1 as its _meta records. The cases are derived from
// the file, so a case added there is replayed here the moment it lands.
//
// The seed does not enter the envelope hash. Each case is signed with a fresh test
// seed, except v01-self-certified-signer: its signer is the did:key of RFC 8032
// §7.1 TEST 1, and `sign` verifies its own result, so only that published test
// vector's seed can sign it. The test proves the vector names that identifier.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveKeyDerivedIdentifierFromKey } from '@typedstandards/produce-core';
import { RFC8032_TEST_1, RFC8032_TEST_1_B64, SEED_VARIABLE, cli, golden, newSeed, scratch } from './harness.test.ts';

const SELF_CERTIFIED = 'v01-self-certified-signer';

test('golden replay: the fixture holds the cases this test replays', () => {
  assert.ok(golden.envelopeCases.length >= 9, `derived ${golden.envelopeCases.length} envelope cases`);
  assert.ok(golden.attestationCases.some((c) => c.name === 'withdraws'), 'no withdraws case in the fixture');
  assert.ok(golden.envelopeCases.some((c) => c.name === SELF_CERTIFIED));
});

test('golden replay: RFC 8032 TEST 1 derives the self-certified case\'s identifier', () => {
  const c = golden.envelopeCases.find((x) => x.name === SELF_CERTIFIED)!;
  const identifier = deriveKeyDerivedIdentifierFromKey(Buffer.from(RFC8032_TEST_1, 'hex'));
  assert.equal((c.input['signer'] as { identifier: string }).identifier, identifier);
});

for (const c of golden.envelopeCases) {
  test(`golden replay [${c.name}]: sign prints the recorded bytes, content hash and envelope hash`, () => {
    const dir = scratch();
    try {
      const seed = c.name === SELF_CERTIFIED ? RFC8032_TEST_1_B64 : newSeed().b64;
      const r = cli(['sign', '--input', dir.write('input.json', JSON.stringify(c.input))], { env: { [SEED_VARIABLE]: seed } });
      assert.equal(r.code, 0, `${c.name}: sign exited ${r.code}: ${r.err}`);
      const printed = r.json() as { package: Record<string, unknown>; envelopeHash: string };

      assert.equal(JSON.stringify(printed.package), c.expected.serializedJson, `${c.name}: serialized JSON diverged`);
      if (c.expected.contentHashSha256 === null) {
        assert.ok(!('contentHash' in printed.package), `${c.name}: legacy case must not carry contentHash`);
      } else {
        assert.equal((printed.package['contentHash'] as { sha256: string }).sha256, c.expected.contentHashSha256);
      }
      assert.equal(printed.envelopeHash, c.expected.envelopeHash, `${c.name}: envelope hash diverged`);
    } finally {
      dir.cleanup();
    }
  });
}

test('golden replay [withdraws]: withdraw prints the recorded bytes, content hash and node id', () => {
  const c = golden.attestationCases.find((x) => x.name === 'withdraws')!;
  const dir = scratch();
  try {
    const r = cli(['withdraw', '--input', dir.write('input.json', JSON.stringify(c.input))], { env: { [SEED_VARIABLE]: newSeed().b64 } });
    assert.equal(r.code, 0, `withdraw exited ${r.code}: ${r.err}`);
    const printed = r.json() as { node: Record<string, unknown>; nodeId: string };
    assert.equal(JSON.stringify(printed.node), c.expected.serializedJson, 'serialized JSON diverged');
    assert.equal((printed.node['contentHash'] as { sha256: string }).sha256, c.expected.contentHashSha256);
    assert.equal(printed.nodeId, c.expected.nodeId);
  } finally {
    dir.cleanup();
  }
});
