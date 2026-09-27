// `verify` on a view carrying a lifecycle node that lacks a field the standard
// requires of its sub-type (spec §8.12.1, §8.12.3; typedstandards#113, the P5 ruling
// on F1, as the owner corrected it at the P5-fix gate): the node does not move the
// status, and each missing field gets a reading, per node, naming the field:
//   - on a node naming the record's signer, `attention`, printed on stderr; exit 0;
//   - on a third party's node, `normal`, as any third-party event reads (G0 D6 as
//     corrected), so nothing is printed.
// The tiers are copied from typedstandards.org's table, which readings.test.ts holds
// equal.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signEnvelopeHash, type SignerIdentity } from '@typedstandards/produce-core';
import {
  computeContentHashSha256,
  computeEnvelopeHash,
  LEGACY_JSON_CANONICALIZATION,
  verifyLifecycleChain,
  verifyRecord,
} from '@typedstandards/verify-core';
import { SEED_VARIABLE, cli, golden, newSeed, scratch } from './harness.test.ts';
import { SITE_TABLES, readingsOf, type CarriedNode } from './readings.ts';

const REGISTRY_URL = 'https://registry.example/.well-known/typed-publisher.json';
const KID = 'example:lifecycle-key';
const SUCCESSOR = 'e'.repeat(64);
const THIRD_PARTY: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:another-party', displayName: 'Another party' };

/** A lifecycle node of `type` on `target`, naming `signer`, carrying exactly
 *  `payload`, signed by `seed`: the shape withdraw prints. */
function carriedNode(type: string, seed: Uint8Array, target: string, signer: SignerIdentity, payload: Record<string, unknown>): CarriedNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4f', createdAt: '2026-09-27T12:00:00.000Z', signingKeyId: KID },
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

/** Sign the golden platform-signer input with a fresh seed; view it carrying one
 *  node, signed by the record's own key and naming its signer, or with
 *  `thirdParty` signed by another key and naming another signer; verify the view. */
function run(type: string, payload: Record<string, unknown>, thirdParty = false) {
  const dir = scratch();
  try {
    const seed = newSeed();
    const env = { [SEED_VARIABLE]: seed.b64 };
    const input = golden.envelopeCases.find((x) => x.name === 'v01-signer-producer-capture')!.input;
    const s = cli(['sign', '--input', dir.write('platform.json', JSON.stringify(input))], { env });
    assert.equal(s.code, 0, s.err);
    const signed = s.json() as { envelopeHash: string; package: { signer: SignerIdentity } };
    const carried = thirdParty
      ? carriedNode(type, newSeed().bytes, signed.envelopeHash, THIRD_PARTY, payload)
      : carriedNode(type, seed.bytes, signed.envelopeHash, signed.package.signer, payload);
    const view = cli([
      'view', '--signed', dir.write('signed.json', s.out), '--visibility', 'public',
      '--trust-registry-url', REGISTRY_URL, '--attestation', dir.write('node.json', JSON.stringify(carried)),
    ]);
    assert.equal(view.code, 0, view.err);
    const verify = cli(['verify', '--input', dir.write('view.json', view.out), '--json']);
    return { view, verify };
  } finally {
    dir.cleanup();
  }
}

const lifecycleOf = (r: { json(): Record<string, unknown> }) => r.json()['lifecycle'] as { status: string };

test('verify: a withdraws with no reason, signed by the record\'s own key, reads attention naming reason, exits 0, and moves no status', () => {
  const { view, verify } = run('attestation/withdraws/v1', {});
  assert.equal(lifecycleOf(view).status, 'active', 'the view does not carry it as withdrawn');
  assert.equal(verify.code, 0, verify.err);
  assert.equal((verify.json() as { ok: boolean }).ok, true);
  assert.equal(lifecycleOf(verify).status, 'active');
  assert.match(verify.err, /typedstandards verify: #10 lifecycleAttestations\[0\]\.reason: missing_required_field \(attention\)/);
  assert.doesNotMatch(verify.err, /\(alarm\)/);
});

test('verify: a supersedes with no successorNodeId reads attention naming successorNodeId, and moves no status', () => {
  const { verify } = run('attestation/supersedes/v1', {});
  assert.equal(verify.code, 0, verify.err);
  assert.equal(lifecycleOf(verify).status, 'active');
  assert.match(verify.err, /typedstandards verify: #10 lifecycleAttestations\[0\]\.successorNodeId: missing_required_field \(attention\)/);
});

test('verify: the same nodes with the field present print no such reading and move status as before', () => {
  const withdrawn = run('attestation/withdraws/v1', { reason: 'a stated reason' }).verify;
  assert.equal(withdrawn.code, 0, withdrawn.err);
  assert.equal(lifecycleOf(withdrawn).status, 'withdrawn');
  assert.doesNotMatch(withdrawn.err, /missing_required_field/);
  const superseded = run('attestation/supersedes/v1', { successorNodeId: SUCCESSOR }).verify;
  assert.equal(lifecycleOf(superseded).status, 'superseded');
  assert.doesNotMatch(superseded.err, /missing_required_field/);
});

test('verify: a third party\'s withdraws with no reason prints no missing-field reading, exits 0, and moves no status', () => {
  const { verify } = run('attestation/withdraws/v1', {}, true);
  assert.equal(verify.code, 0, verify.err);
  assert.equal(lifecycleOf(verify).status, 'active');
  assert.doesNotMatch(verify.err, /missing_required_field/);
});

test('readingsOf: the missing field is named on both nodes, at attention for the publisher\'s and normal for a third party\'s', async () => {
  const target = 'a'.repeat(64);
  const seed = newSeed().bytes;
  const publisher: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
  const { publicKey } = signEnvelopeHash(target, seed, KID);
  const carried = [
    carriedNode('attestation/withdraws/v1', seed, target, publisher, {}),
    carriedNode('attestation/withdraws/v1', newSeed().bytes, target, THIRD_PARTY, {}),
  ];
  const lifecycleResolution = verifyLifecycleChain(carried, target, publisher.identifier, { targetPublicKey: publicKey });
  const result = await verifyRecord({ package: null, packageHash: target }, { registry: undefined, lifecycleResolution });
  const readings = readingsOf(result, carried, target, { signerIdentifier: publisher.identifier, publicKey })
    .filter((r) => r.status === 'missing_required_field');
  assert.deepEqual(readings, [
    { check: '#10', field: 'lifecycleAttestations[0].reason', status: 'missing_required_field', tier: 'attention' },
    { check: '#10', field: 'lifecycleAttestations[1].reason', status: 'missing_required_field', tier: 'normal' },
  ]);
});

test('the tiers are the ones copied from the site\'s table, which readings.test.ts holds equal', () => {
  const tables = SITE_TABLES as Record<string, unknown>;
  assert.deepEqual(tables['LIFECYCLE_ATTESTATION_MISSING_FIELD_SIGNALS'], { names_publisher: 'attention', other_signer: 'normal' });
});
