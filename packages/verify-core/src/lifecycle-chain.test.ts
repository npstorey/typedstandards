// Independent lifecycle-chain verification tests (civic-ai-tools-website#119 P3).
//
// `verifyLifecycleChain` is the browser/offline path that resolves #10 from carried
// signed attestation nodes with no reference-implementation dependency. Because it
// must NOT trust the carrier, each node is gated on reachability + integrity +
// signature before it can move the publisher's status. These build synthetic signed
// nodes (Ed25519ph) and prove: a valid chain resolves the state; a forged signature,
// a hash≠nodeId, and an attestation targeting a different node are all EXCLUDED; the
// §8.10.3 retention asymmetry holds; and withdrawn→reinstated resolves correctly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  verifyLifecycleChain,
  computeEnvelopeHash,
  computeContentHashSha256,
  LEGACY_JSON_CANONICALIZATION,
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  type CarriedLifecycleNode,
} from './index.ts';

const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
function rawToSpkiB64(rawPub: Uint8Array): string {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + rawPub.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(rawPub, ED25519_SPKI_PREFIX.length);
  return b64(der);
}

const CONTENT_NODE_ID = 'a'.repeat(64);
const PUBLISHER = { bindingTier: 'platform', identifier: 'platform:civic-ai-tools', displayName: 'Platform' };
const OUTSIDER = { bindingTier: 'platform', identifier: 'someone:else', displayName: 'Outsider' };
const SEED = Uint8Array.from(Array.from({ length: 32 }, (_u, i) => (i * 11 + 5) & 0xff));

/** Build a signed attestation node (mirrors the server's buildAttestationNode shape). */
function buildAttestation(opts: {
  type: string;
  targetNodeId?: string;
  createdAt: string;
  signer?: typeof PUBLISHER;
  seed?: Uint8Array;
  reason?: string;
  effectiveAt?: string;
  priorWithdrawalNodeId?: string;
}): CarriedLifecycleNode {
  const seed = opts.seed ?? SEED;
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '00000000-0000-4000-8000-000000000001', createdAt: opts.createdAt },
    type: opts.type,
    signer: opts.signer ?? PUBLISHER,
    targetNodeId: opts.targetNodeId ?? CONTENT_NODE_ID,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...(opts.reason !== undefined ? { reason: opts.reason } : {}),
    ...(opts.effectiveAt !== undefined ? { effectiveAt: opts.effectiveAt } : {}),
    ...(opts.priorWithdrawalNodeId !== undefined ? { priorWithdrawalNodeId: opts.priorWithdrawalNodeId } : {}),
  };
  const contentHash = { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) };
  const node = { ...base, contentHash };
  const nodeId = computeEnvelopeHash(node);
  const sig = ed25519ph.sign(new TextEncoder().encode(nodeId), seed);
  return {
    node,
    nodeId,
    signature: { signature: b64(sig), publicKey: rawToSpkiB64(ed25519.getPublicKey(seed)), algorithm: 'Ed25519ph' },
  };
}

const resolve = (nodes: CarriedLifecycleNode[]) =>
  verifyLifecycleChain(nodes, CONTENT_NODE_ID, PUBLISHER.identifier);

test('a valid signed withdrawal resolves to withdrawn via the attestation chain', () => {
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z', reason: 'superseded', effectiveAt: '2026-06-02T00:00:00.000Z' });
  const r = resolve([w]);
  assert.equal(r.status, 'withdrawn');
  assert.equal(r.source, 'attestation-chain');
  assert.equal(r.chain.length, 1);
  assert.equal(r.withdrawnReason, 'superseded');
});

test('a FORGED signature is excluded (cannot move status)', () => {
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z' });
  const forged: CarriedLifecycleNode = {
    ...w,
    signature: { ...w.signature!, signature: b64(Uint8Array.from({ length: 64 }, () => 0)) },
  };
  const r = resolve([forged]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 0, 'a forged node does not enter the chain');
});

test('a node whose hash ≠ stored nodeId is excluded', () => {
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z' });
  const tampered: CarriedLifecycleNode = { ...w, nodeId: 'b' + w.nodeId.slice(1) };
  const r = resolve([tampered]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 0);
});

test('an attestation targeting a DIFFERENT node is not reachable', () => {
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z', targetNodeId: 'c'.repeat(64) });
  const r = resolve([w]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 0);
});

test('retention asymmetry (§8.10.3): a non-signer-matched withdrawal is surfaced but does NOT move status', () => {
  // Validly signed by a DIFFERENT key/identity than the content node's publisher.
  const outsiderSeed = Uint8Array.from(Array.from({ length: 32 }, (_u, i) => (i * 7 + 1) & 0xff));
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z', signer: OUTSIDER, seed: outsiderSeed });
  const r = resolve([w]);
  assert.equal(r.chain.length, 1, 'surfaced for transparency');
  assert.equal(r.chain[0].signerMatchesTarget, false);
  assert.equal(r.status, 'active', 'a non-publisher attestation cannot withdraw');
});

test('withdrawn → reinstated resolves to active (latest signer-matched transition wins)', () => {
  const w = buildAttestation({ type: ATTESTATION_WITHDRAWS, createdAt: '2026-06-02T00:00:00.000Z', reason: 'mistake' });
  const re = buildAttestation({ type: ATTESTATION_REINSTATES, createdAt: '2026-06-03T00:00:00.000Z', reason: 'restored', priorWithdrawalNodeId: w.nodeId });
  const r = resolve([re, w]); // order-independent: the resolver sorts by createdAt
  assert.equal(r.status, 'active');
  assert.equal(r.source, 'attestation-chain');
  assert.equal(r.chain.length, 2);
  assert.equal(r.reinstatedReason, 'restored');
});

test('no carried nodes ⇒ an empty active chain (caller falls back to STATE/legacy)', () => {
  const r = resolve([]);
  assert.equal(r.status, 'active');
  assert.equal(r.chain.length, 0);
});
