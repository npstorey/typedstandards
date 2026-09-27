// A carried lifecycle node that lacks a required §8.12.1 payload field (spec §8.12.3:
// a conformant `attestation/*` node "MUST carry the sub-type's required payload
// fields per the §8.12.1 table") stays in the chain, never moves status, and names
// the fields it lacks on its view (typedstandards#113, the P5 ruling on F1).
//
// This applies to `verifyLifecycleChain` only: `resolveLifecycleFromChain`, the
// shared resolver, is unchanged, and reads a view's `signerMatchesTarget` as given.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  verifyLifecycleChain,
  resolveLifecycleFromChain,
  computeEnvelopeHash,
  computeContentHashSha256,
  LEGACY_JSON_CANONICALIZATION,
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
  ATTESTATION_REVISES,
  type CarriedLifecycleNode,
  type LifecycleAttestationView,
} from './index.ts';

const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
function spkiOf(seed: Uint8Array): string {
  const raw = ed25519.getPublicKey(seed);
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(raw, ED25519_SPKI_PREFIX.length);
  return b64(der);
}
const seedOf = (k: number) => Uint8Array.from(Array.from({ length: 32 }, (_u, i) => (i * k + 5) & 0xff));

const CONTENT_NODE_ID = 'e'.repeat(64);
const SUCCESSOR = 'f'.repeat(64);
/** The key that signed the target record. */
const RECORD_SEED = seedOf(17);
const RECORD_KEY = spkiOf(RECORD_SEED);
const THIRD_PARTY_SEED = seedOf(31);
const PUBLISHER = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
const THIRD_PARTY = { bindingTier: 'platform', identifier: 'platform:another-party', displayName: 'Another party' };

/** A node of `type` on the content node, carrying exactly `payload`, signed by `seed`
 *  (the record's own key unless given). */
function carried(
  type: string,
  payload: Record<string, unknown>,
  opts: { createdAt?: string; seed?: Uint8Array; signer?: typeof PUBLISHER } = {},
): CarriedLifecycleNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '00000000-0000-4000-8000-00000000000c', createdAt: opts.createdAt ?? '2026-06-02T00:00:00.000Z' },
    type,
    signer: opts.signer ?? PUBLISHER,
    targetNodeId: CONTENT_NODE_ID,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...payload,
  };
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  const seed = opts.seed ?? RECORD_SEED;
  const sig = ed25519ph.sign(new TextEncoder().encode(nodeId), seed);
  return { node, nodeId, signature: { signature: b64(sig), publicKey: spkiOf(seed), algorithm: 'Ed25519ph' } };
}

const resolve = (nodes: CarriedLifecycleNode[]) =>
  verifyLifecycleChain(nodes, CONTENT_NODE_ID, PUBLISHER.identifier, { targetPublicKey: RECORD_KEY });

/** The view's missing fields, read without naming the field in the type. */
const missingOf = (v: LifecycleAttestationView | undefined): unknown =>
  v ? (v as unknown as Record<string, unknown>)['missingFields'] : undefined;

const WITHDRAWAL = { reason: 'a stated reason' };
const SUPERSESSION = { successorNodeId: SUCCESSOR };

test('a withdraws with no reason, signed by the record\'s own key, stays in the chain and leaves the status active', () => {
  const r = resolve([carried(ATTESTATION_WITHDRAWS, {})]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 1, 'kept in the chain');
  assert.deepEqual(missingOf(r.chain[0]), ['reason']);
  assert.equal(r.chain[0].signerMatchesTarget, false);
  assert.equal(r.chain[0].keyBound, true, 'the key is bound; the node still does not count');
  assert.equal(r.chain[0].namesTarget, true);
  assert.equal(r.withdrawnAt, undefined);
});

test('a withdraws whose reason is null or the empty string reads the same', () => {
  for (const reason of [null, '']) {
    const r = resolve([carried(ATTESTATION_WITHDRAWS, { reason })]);
    assert.equal(r.status, 'active', JSON.stringify(reason));
    assert.deepEqual(missingOf(r.chain[0]), ['reason'], JSON.stringify(reason));
  }
});

test('a supersedes with no successorNodeId stays in the chain and leaves the status active', () => {
  const r = resolve([carried(ATTESTATION_SUPERSEDES, {})]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 1, 'kept in the chain');
  assert.deepEqual(missingOf(r.chain[0]), ['successorNodeId']);
  assert.equal(r.supersededAt, undefined);
});

test('a reinstates with no priorWithdrawalNodeId after a counting withdraws leaves the status withdrawn', () => {
  const r = resolve([
    carried(ATTESTATION_WITHDRAWS, WITHDRAWAL, { createdAt: '2026-06-02T00:00:00.000Z' }),
    carried(ATTESTATION_REINSTATES, { reason: 'restored' }, { createdAt: '2026-06-03T00:00:00.000Z' }),
  ]);
  assert.equal(r.status, 'withdrawn');
  assert.equal(r.chain.length, 2, 'both kept in the chain');
  assert.deepEqual(missingOf(r.chain[0]), []);
  assert.deepEqual(missingOf(r.chain[1]), ['priorWithdrawalNodeId']);
  assert.equal(r.reinstatedAt, undefined);
});

test('a revises with no successorNodeId names the field; it moved no status before and moves none now', () => {
  const r = resolve([carried(ATTESTATION_REVISES, {})]);
  assert.equal(r.status, 'active');
  assert.deepEqual(missingOf(r.chain[0]), ['successorNodeId']);
});

test('a third party\'s node that lacks a field names it too, and moves nothing', () => {
  const r = resolve([carried(ATTESTATION_WITHDRAWS, {}, { seed: THIRD_PARTY_SEED, signer: THIRD_PARTY })]);
  assert.equal(r.status, 'active');
  assert.deepEqual(missingOf(r.chain[0]), ['reason']);
  assert.equal(r.chain[0].namesTarget, false);
});

test('controls: the same nodes with the field present move status as before, and name no field', () => {
  const withdrawn = resolve([carried(ATTESTATION_WITHDRAWS, WITHDRAWAL)]);
  assert.equal(withdrawn.status, 'withdrawn');
  assert.equal(withdrawn.chain[0].signerMatchesTarget, true);
  assert.deepEqual(missingOf(withdrawn.chain[0]), []);

  const superseded = resolve([carried(ATTESTATION_SUPERSEDES, SUPERSESSION)]);
  assert.equal(superseded.status, 'superseded');
  assert.equal(superseded.successorNodeId, SUCCESSOR);
  assert.deepEqual(missingOf(superseded.chain[0]), []);

  const withdrawal = carried(ATTESTATION_WITHDRAWS, WITHDRAWAL, { createdAt: '2026-06-02T00:00:00.000Z' });
  const reinstated = resolve([
    withdrawal,
    carried(ATTESTATION_REINSTATES, { priorWithdrawalNodeId: withdrawal.nodeId }, { createdAt: '2026-06-03T00:00:00.000Z' }),
  ]);
  assert.equal(reinstated.status, 'active');
  assert.equal(reinstated.chain[1].signerMatchesTarget, true);
  assert.deepEqual(missingOf(reinstated.chain[1]), []);
});

test('resolveLifecycleFromChain is unchanged: a view marked signer-matched counts, whatever its payload', () => {
  const r = resolveLifecycleFromChain([
    {
      nodeId: 'a'.repeat(64),
      type: ATTESTATION_WITHDRAWS,
      createdAt: '2026-06-02T00:00:00.000Z',
      signatureValid: true,
      nodeIdMatches: true,
      hasTimestamp: false,
      hasRekor: false,
      signerMatchesTarget: true,
    },
  ]);
  assert.equal(r.status, 'withdrawn');
});
