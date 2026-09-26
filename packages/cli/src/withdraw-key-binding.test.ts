// A lifecycle attestation moves a record's status only when its signing key is
// bound to the signer it names (typedstandards#113, G0 D5). For the CLI:
//   - `withdraw` verifies its own result before printing, so a did:key its seed
//     does not derive fails that check: exit 1, nothing on stdout;
//   - `view` and `verify` pass the record's own signing key, which binds a
//     withdrawal signed by that key under a registry-bound identifier.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ATTESTATION_WITHDRAWS,
  buildAttestationNode,
  deriveKeyDerivedIdentifierFromKey,
  signEnvelopeHash,
  type SignerIdentity,
} from '@typedstandards/produce-core';
import { EXIT } from './errors.ts';
import { SEED_VARIABLE, cli, fileInput, golden, newSeed, scratch } from './harness.test.ts';

const FILE = 'A signed file.\n';
const REGISTRY_URL = 'https://registry.example/.well-known/typed-publisher.json';

test('withdraw exits 1 with nothing on stdout when signer.identifier is a did:key its seed does not derive', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const s = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE)], { env });
    assert.equal(s.code, 0, s.err);
    const target = (s.json() as { envelopeHash: string }).envelopeHash;
    const otherIdentifier = deriveKeyDerivedIdentifierFromKey(newSeed().bytes);
    const w = cli(['withdraw', '--input', '-'], {
      env,
      stdin: JSON.stringify({ targetNodeId: target, reason: 'r', signer: { bindingTier: 'pseudonymous', displayName: 'Example signer', identifier: otherIdentifier } }),
    });
    assert.equal(w.code, EXIT.verificationFailed);
    assert.equal(w.stdout.length, 0);
    assert.match(w.err, /did not verify offline, so nothing was printed/);
  } finally {
    dir.cleanup();
  }
});

test('withdraw under the seed\'s own identifier prints, and view then verify read withdrawn', () => {
  const dir = scratch();
  try {
    const seed = newSeed();
    const env = { [SEED_VARIABLE]: seed.b64 };
    const s = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE)], { env });
    assert.equal(s.code, 0, s.err);
    const target = (s.json() as { envelopeHash: string }).envelopeHash;
    const identifier = deriveKeyDerivedIdentifierFromKey(seed.bytes);
    const w = cli(['withdraw', '--input', '-'], {
      env,
      stdin: JSON.stringify({ targetNodeId: target, reason: 'r', signer: { bindingTier: 'pseudonymous', displayName: 'Example signer', identifier } }),
    });
    assert.equal(w.code, 0, w.err);
    const view = cli(['view', '--signed', dir.write('signed.json', s.out), '--visibility', 'public', '--withdrawal', dir.write('w.json', w.out)]);
    assert.equal(view.code, 0, view.err);
    assert.equal((view.json()['lifecycle'] as { status: string }).status, 'withdrawn');
    const v = cli(['verify', '--input', dir.write('view.json', view.out), '--json']);
    assert.equal(v.code, 0, v.err);
    assert.equal((v.json()['lifecycle'] as { status: string }).status, 'withdrawn');
  } finally {
    dir.cleanup();
  }
});

/** A withdrawal of `target`, naming `signer`, signed by `seed`: what withdraw prints. */
function withdrawalBy(seed: Uint8Array, target: string, signer: SignerIdentity): string {
  const kid = 'example:withdrawal-key';
  const { node, nodeId } = buildAttestationNode({
    type: ATTESTATION_WITHDRAWS,
    packageId: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e',
    createdAt: '2026-09-26T12:00:00.000Z',
    signingKeyId: kid,
    targetNodeId: target,
    signer,
    reason: 'r',
  });
  return JSON.stringify({ node, nodeId, signature: signEnvelopeHash(nodeId, seed, kid) });
}

for (const c of [
  { name: 'signed by the record\'s own key reads withdrawn', sameKey: true, status: 'withdrawn' },
  { name: 'signed by another key reads active', sameKey: false, status: 'active' },
]) {
  test(`view and verify, registry-bound signer: a withdrawal ${c.name}`, () => {
    const dir = scratch();
    try {
      const seed = newSeed();
      const env = { [SEED_VARIABLE]: seed.b64 };
      const input = golden.envelopeCases.find((x) => x.name === 'v01-signer-producer-capture')!.input;
      const s = cli(['sign', '--input', dir.write('platform.json', JSON.stringify(input))], { env });
      assert.equal(s.code, 0, s.err);
      const signed = s.json() as { envelopeHash: string; package: { signer: SignerIdentity } };
      const withdrawal = withdrawalBy(c.sameKey ? seed.bytes : newSeed().bytes, signed.envelopeHash, signed.package.signer);

      const view = cli([
        'view', '--signed', dir.write('signed.json', s.out), '--visibility', 'public',
        '--trust-registry-url', REGISTRY_URL, '--withdrawal', dir.write('w.json', withdrawal),
      ]);
      assert.equal(view.code, 0, view.err);
      assert.equal((view.json()['lifecycle'] as { status: string }).status, c.status);
      const v = cli(['verify', '--input', dir.write('view.json', view.out), '--json']);
      assert.equal(v.code, 0, v.err);
      const lifecycle = v.json()['lifecycle'] as { status: string; chain: Array<{ keyBound?: boolean }> };
      assert.equal(lifecycle.chain.length, 1, 'surfaced in the chain');
      assert.equal(lifecycle.chain[0].keyBound, c.sameKey);
      assert.equal(lifecycle.status, c.status);
    } finally {
      dir.cleanup();
    }
  });
}
