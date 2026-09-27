// `superseded` as a lifecycle status (typedstandards#113, G0 D2).
//
//   - Status comes from the latest signer-matched (and so key-bound) node among
//     `withdraws`, `reinstates` and `supersedes`; `revises` never moves it.
//   - A `reinstates` returns the record to `superseded` when a signer-matched
//     `supersedes` precedes it in chain order, and to `active` otherwise; a later
//     `withdraws` reads `withdrawn`.
//   - The resolution names the successor and the supersession time.
//   - The legacy-columns path never derives `superseded`.
//
// Nodes are built and signed here (Ed25519ph), the way lifecycle-chain.test.ts
// builds them, and resolved through `verifyLifecycleChain`, the carried path the
// site and the CLI run.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  verifyLifecycleChain,
  resolveLifecycleFromChain,
  resolveLifecycleFromLegacyColumns,
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

const SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const spkiOf = (seed: Uint8Array) => {
  const raw = ed25519.getPublicKey(seed);
  const der = new Uint8Array(SPKI_PREFIX.length + raw.length);
  der.set(SPKI_PREFIX, 0);
  der.set(raw, SPKI_PREFIX.length);
  return b64(der);
};

const TARGET = 'a'.repeat(64);
const SUCCESSOR = 'b'.repeat(64);
const LATER_SUCCESSOR = 'c'.repeat(64);
const PUBLISHER = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
const OUTSIDER = { bindingTier: 'platform', identifier: 'platform:another-party', displayName: 'Another party' };
const SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 13 + 3) & 0xff);
const OTHER_SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 5 + 9) & 0xff);

let counter = 0;
function node(
  type: string,
  createdAt: string,
  extra: Record<string, unknown> = {},
  opts: { signer?: typeof PUBLISHER; seed?: Uint8Array } = {},
): CarriedLifecycleNode {
  counter += 1;
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: `0a1b2c3d-0000-4000-8000-${String(counter).padStart(12, '0')}`, createdAt },
    type,
    signer: opts.signer ?? PUBLISHER,
    targetNodeId: TARGET,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...extra,
  };
  const full = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(full);
  const seed = opts.seed ?? SEED;
  return {
    node: full,
    nodeId,
    signature: { signature: b64(ed25519ph.sign(new TextEncoder().encode(nodeId), seed)), publicKey: spkiOf(seed), algorithm: 'Ed25519ph' },
  };
}

const resolve = (nodes: CarriedLifecycleNode[]) =>
  verifyLifecycleChain(nodes, TARGET, PUBLISHER.identifier, { targetPublicKey: spkiOf(SEED) });

const T1 = '2026-09-01T00:00:00.000Z';
const T2 = '2026-09-02T00:00:00.000Z';
const T3 = '2026-09-03T00:00:00.000Z';

test('a signer-matched supersedes makes the target superseded and names the successor', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR });
  const r = resolve([s]);
  assert.equal(r.source, 'attestation-chain');
  assert.equal(r.status, 'superseded');
  assert.equal(r.successorNodeId, SUCCESSOR);
  assert.equal(r.supersededAt, T1);
  assert.equal(r.chain.length, 1);
  assert.equal(r.chain[0].successorNodeId, SUCCESSOR);
});

test('a supersedes by another signer does not move the status', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR }, { signer: OUTSIDER, seed: OTHER_SEED });
  const r = resolve([s]);
  assert.equal(r.status, 'active');
  assert.equal(r.successorNodeId, undefined);
  assert.equal(r.chain.length, 1, 'surfaced in the chain');
  assert.equal(r.chain[0].signerMatchesTarget, false);
  assert.equal(r.chain[0].namesTarget, false);
});

test('a supersedes naming the publisher but signed by an unbound key does not move the status', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR }, { seed: OTHER_SEED });
  const r = resolve([s]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain[0].namesTarget, true);
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.chain[0].signerMatchesTarget, false);
});

test('withdraws → supersedes → reinstates reads superseded', () => {
  const w = node(ATTESTATION_WITHDRAWS, T1, { reason: 'a stated reason' });
  const s = node(ATTESTATION_SUPERSEDES, T2, { successorNodeId: SUCCESSOR });
  const re = node(ATTESTATION_REINSTATES, T3, { priorWithdrawalNodeId: w.nodeId });
  const r = resolve([re, s, w]);
  assert.equal(r.status, 'superseded');
  assert.equal(r.successorNodeId, SUCCESSOR);
  assert.equal(r.supersededAt, T2);
  assert.equal(r.reinstatedAt, T3);
});

test('supersedes → withdraws reads withdrawn', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR });
  const w = node(ATTESTATION_WITHDRAWS, T2, { reason: 'a stated reason' });
  const r = resolve([w, s]);
  assert.equal(r.status, 'withdrawn');
  assert.equal(r.withdrawnAt, T2);
});

test('supersedes → withdraws → reinstates reads superseded', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR });
  const w = node(ATTESTATION_WITHDRAWS, T2, { reason: 'a stated reason' });
  const re = node(ATTESTATION_REINSTATES, T3, { priorWithdrawalNodeId: w.nodeId });
  assert.equal(resolve([s, w, re]).status, 'superseded');
});

test('withdraws → reinstates, with no supersedes, reads active', () => {
  const w = node(ATTESTATION_WITHDRAWS, T1, { reason: 'a stated reason' });
  const re = node(ATTESTATION_REINSTATES, T2, { priorWithdrawalNodeId: w.nodeId });
  const r = resolve([w, re]);
  assert.equal(r.status, 'active');
  assert.equal(r.successorNodeId, undefined);
  assert.equal(r.supersededAt, undefined);
});

test('a reinstates preceded only by an unbound supersedes reads active', () => {
  const s = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR }, { seed: OTHER_SEED });
  const w = node(ATTESTATION_WITHDRAWS, T2, { reason: 'a stated reason' });
  const re = node(ATTESTATION_REINSTATES, T3, { priorWithdrawalNodeId: w.nodeId });
  assert.equal(resolve([s, w, re]).status, 'active');
});

test('the latest counting supersedes names the successor', () => {
  const s1 = node(ATTESTATION_SUPERSEDES, T1, { successorNodeId: SUCCESSOR });
  const s2 = node(ATTESTATION_SUPERSEDES, T2, { successorNodeId: LATER_SUCCESSOR });
  const r = resolve([s2, s1]);
  assert.equal(r.status, 'superseded');
  assert.equal(r.successorNodeId, LATER_SUCCESSOR);
  assert.equal(r.supersededAt, T2);
});

test('a revises changes no status, alone, before a withdraws, or after one', () => {
  const rev = (at: string) => node(ATTESTATION_REVISES, at, { successorNodeId: SUCCESSOR });
  const w = (at: string) => node(ATTESTATION_WITHDRAWS, at, { reason: 'a stated reason' });

  const alone = resolve([rev(T1)]);
  assert.equal(alone.status, 'active');
  assert.equal(alone.successorNodeId, undefined, 'a revises names no successor of the record');

  assert.equal(resolve([rev(T1), w(T2)]).status, 'withdrawn', 'revises before a withdraws');
  const after = resolve([w(T1), rev(T2)]);
  assert.equal(after.status, 'withdrawn', 'revises after a withdraws');
  assert.equal(after.chain.length, 2, 'the revises is surfaced in the chain');
  assert.equal(after.chain[1].type, ATTESTATION_REVISES);
  assert.equal(after.chain[1].signerMatchesTarget, true);
});

test('resolveLifecycleFromChain (the server route\'s entry): a signer-matched supersedes view reads superseded', () => {
  const view: LifecycleAttestationView = {
    nodeId: 'd'.repeat(64),
    type: ATTESTATION_SUPERSEDES,
    createdAt: T1,
    successorNodeId: SUCCESSOR,
    signatureValid: true,
    nodeIdMatches: true,
    hasTimestamp: false,
    hasRekor: false,
    signerMatchesTarget: true,
  };
  const r = resolveLifecycleFromChain([view]);
  assert.equal(r.status, 'superseded');
  assert.equal(r.successorNodeId, SUCCESSOR);
});

test('the legacy-columns path never derives superseded', () => {
  const columns = [
    {},
    { withdrawnAt: T1 },
    { withdrawnAt: T1, withdrawnReason: 'a stated reason' },
    { withdrawnAt: T1, reinstatedAt: T2 },
    { withdrawnAt: T1, reinstatedAt: T2, reinstatedReason: 'restored' },
    { withdrawnAt: null, reinstatedAt: T2 },
  ];
  for (const c of columns) {
    const r = resolveLifecycleFromLegacyColumns(c);
    assert.notEqual(r.status, 'superseded', JSON.stringify(c));
    assert.ok(['active', 'withdrawn'].includes(r.status), JSON.stringify(c));
    assert.equal(r.successorNodeId, undefined);
  }
});

test('verifyRecord at STATE depth: a sidecar reading superseded does not reach #10 without the signed chain', async () => {
  const { verifyRecord } = await import('./index.ts');
  const r = await verifyRecord(
    { package: null, packageHash: TARGET, lifecycle: { status: 'superseded', supersededAt: T1, successorNodeId: SUCCESSOR } },
    { registry: undefined },
  );
  assert.equal(r.lifecycle.source, 'none');
  assert.equal(r.lifecycle.status, 'active');
  assert.equal(r.lifecycle.successorNodeId, undefined);
});
