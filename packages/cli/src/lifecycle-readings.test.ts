// The CLI's reading of a carried lifecycle node's signer (typedstandards#113, G0 D6
// as corrected), and `view` carrying a `superseded` status (G0 D2).
//
// `verify` gives each carried lifecycle node (`withdraws`, `reinstates`,
// `supersedes`, `revises`) a signer reading with three outcomes, its tiers copied
// from typedstandards.org's ATTESTATION_AUTHORIZATION_SIGNALS:
//   - signed under the record's signer by a key bound to it: `authorized`, verified;
//   - a third party's event (another signer.identifier): `other_signer`, normal;
//   - an event naming the record's signer, signed by a key not bound to it:
//     `publisher_key_unbound`, attention — printed on stderr, exit 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signEnvelopeHash, type SignerIdentity } from '@typedstandards/produce-core';
import {
  computeContentHashSha256,
  computeEnvelopeHash,
  LEGACY_JSON_CANONICALIZATION,
  verifyRecord,
} from '@typedstandards/verify-core';
import { SEED_VARIABLE, cli, golden, newSeed, scratch } from './harness.test.ts';
import { readingsOf, type CarriedNode, type Reading } from './readings.ts';

const REGISTRY_URL = 'https://registry.example/.well-known/typed-publisher.json';
const THIRD_PARTY: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:another-party', displayName: 'Another party' };
const SUCCESSOR = 'e'.repeat(64);
const KID = 'example:lifecycle-key';

/** A lifecycle node of `type` on `target`, naming `signer`, signed by `seed`: the
 *  shape withdraw prints. Built by hand, since produce-core emits only withdraws
 *  and reinstates until P2. */
function carriedNode(type: string, seed: Uint8Array, target: string, signer: SignerIdentity, payload: Record<string, unknown>): CarriedNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e', createdAt: '2026-09-26T12:00:00.000Z', signingKeyId: KID },
    type,
    signer,
    targetNodeId: target,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...payload,
  };
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  return { node, nodeId, signature: signEnvelopeHash(nodeId, seed, KID) };
}

const WITHDRAWS = ['attestation/withdraws/v1', { reason: 'a stated reason' }] as const;
const SUPERSEDES = ['attestation/supersedes/v1', { successorNodeId: SUCCESSOR }] as const;

/** Sign the golden platform-signer input with a fresh seed; view it carrying one
 *  node; verify the view. */
function run(nodeOf: (seed: Uint8Array, target: string, signer: SignerIdentity) => CarriedNode) {
  const dir = scratch();
  try {
    const seed = newSeed();
    const env = { [SEED_VARIABLE]: seed.b64 };
    const input = golden.envelopeCases.find((x) => x.name === 'v01-signer-producer-capture')!.input;
    const s = cli(['sign', '--input', dir.write('platform.json', JSON.stringify(input))], { env });
    assert.equal(s.code, 0, s.err);
    const signed = s.json() as { envelopeHash: string; package: { signer: SignerIdentity } };
    const carried = nodeOf(seed.bytes, signed.envelopeHash, signed.package.signer);
    const view = cli([
      'view', '--signed', dir.write('signed.json', s.out), '--visibility', 'public',
      '--trust-registry-url', REGISTRY_URL, '--withdrawal', dir.write('node.json', JSON.stringify(carried)),
    ]);
    assert.equal(view.code, 0, view.err);
    const verify = cli(['verify', '--input', dir.write('view.json', view.out), '--json']);
    return { view, verify };
  } finally {
    dir.cleanup();
  }
}

test('verify: an event naming the record\'s signer, signed by an unbound key, reads attention on stderr and exits 0', () => {
  const { verify } = run((_seed, target, signer) => carriedNode(WITHDRAWS[0], newSeed().bytes, target, signer, WITHDRAWS[1]));
  assert.equal(verify.code, 0, verify.err);
  assert.equal((verify.json() as { ok: boolean }).ok, true);
  assert.match(verify.err, /typedstandards verify: #10 lifecycleAttestations\[0\]\.signer: publisher_key_unbound \(attention\)/);
});

test('verify: a third party\'s event prints nothing and exits 0', () => {
  const { verify } = run((_seed, target) => carriedNode(WITHDRAWS[0], newSeed().bytes, target, THIRD_PARTY, WITHDRAWS[1]));
  assert.equal(verify.code, 0, verify.err);
  assert.doesNotMatch(verify.err, /lifecycleAttestations\[0\]\.signer/);
});

test('verify: an event signed by the record\'s own key prints nothing and exits 0', () => {
  const { verify } = run((seed, target, signer) => carriedNode(WITHDRAWS[0], seed, target, signer, WITHDRAWS[1]));
  assert.equal(verify.code, 0, verify.err);
  assert.doesNotMatch(verify.err, /lifecycleAttestations\[0\]\.signer/);
});

test('readingsOf: the three outcomes, each at the tier the site gives it', async () => {
  const seed = newSeed().bytes;
  const other = newSeed().bytes;
  const target = 'a'.repeat(64);
  const publisher: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
  const { publicKey } = signEnvelopeHash(target, seed, KID);
  const result = await verifyRecord({ package: null, packageHash: target }, { registry: undefined });
  const read = (c: CarriedNode): Reading[] =>
    (readingsOf as (...a: unknown[]) => Reading[])(result, [c], target, { signerIdentifier: publisher.identifier, publicKey })
      .filter((r) => r.field === 'lifecycleAttestations[0].signer');
  for (const [type, payload] of [WITHDRAWS, SUPERSEDES, ['attestation/reinstates/v1', { priorWithdrawalNodeId: 'c'.repeat(64) }], ['attestation/revises/v1', { successorNodeId: SUCCESSOR }]] as const) {
    assert.deepEqual(read(carriedNode(type, seed, target, publisher, payload)), [
      { check: '#10', field: 'lifecycleAttestations[0].signer', status: 'authorized', tier: 'verified' },
    ], type);
    assert.deepEqual(read(carriedNode(type, other, target, THIRD_PARTY, payload)), [
      { check: '#10', field: 'lifecycleAttestations[0].signer', status: 'other_signer', tier: 'normal' },
    ], type);
    assert.deepEqual(read(carriedNode(type, other, target, publisher, payload)), [
      { check: '#10', field: 'lifecycleAttestations[0].signer', status: 'publisher_key_unbound', tier: 'attention' },
    ], type);
  }
});

test('view carries a superseded status, with its successor, through to the view\'s lifecycle', () => {
  const { view, verify } = run((seed, target, signer) => carriedNode(SUPERSEDES[0], seed, target, signer, SUPERSEDES[1]));
  const lifecycle = view.json()['lifecycle'] as { status: string; successorNodeId?: string; supersededAt?: string };
  assert.equal(lifecycle.status, 'superseded');
  assert.equal(lifecycle.successorNodeId, SUCCESSOR);
  assert.equal(lifecycle.supersededAt, '2026-09-26T12:00:00.000Z');
  assert.equal(verify.code, 0, verify.err);
  assert.equal((verify.json()['lifecycle'] as { status: string }).status, 'superseded');
});
