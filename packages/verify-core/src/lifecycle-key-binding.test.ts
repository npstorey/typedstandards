// A carried lifecycle attestation moves the target record's status only when its
// `signer.identifier` equals the target's AND its signing key is bound to that
// identifier (typedstandards#113, G0 D5):
//   - a key-derived identifier (`did:key:`) binds by derivation from the node's own
//     public key, the rule check #14 applies to a record;
//   - any other identifier binds by the target record's own signing key, or by a
//     trust registry fetched from its declared URL that lists the node's key under
//     that identifier, read by the rules of checks #5 and #14;
//   - a registry carried in a bundle, or one with no stated provenance, never binds.
// An unbound node stays in the surfaced chain and never moves status.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  verifyLifecycleChain,
  computeEnvelopeHash,
  computeContentHashSha256,
  deriveKeyDerivedIdentifier,
  LEGACY_JSON_CANONICALIZATION,
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  type CarriedLifecycleNode,
  type TrustRegistry,
  type TrustRegistryKey,
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
const seedOf = (k: number) => Uint8Array.from(Array.from({ length: 32 }, (_u, i) => (i * k + 3) & 0xff));

const CONTENT_NODE_ID = 'e'.repeat(64);
/** The key that signed the target record. */
const RECORD_SEED = seedOf(13);
const RECORD_KEY = spkiOf(RECORD_SEED);
/** A second, valid key. */
const OTHER_SEED = seedOf(29);
const OTHER_KEY = spkiOf(OTHER_SEED);
const OTHER_KID = 'example:key-b';

const REGISTRY_SIGNER = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
const DID_SIGNER = { bindingTier: 'pseudonymous', identifier: deriveKeyDerivedIdentifier(RECORD_KEY), displayName: 'Example signer' };

function attestation(opts: {
  signer: { bindingTier: string; identifier: string; displayName: string };
  seed: Uint8Array;
  kid?: string;
  type?: string;
  createdAt?: string;
}): CarriedLifecycleNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '00000000-0000-4000-8000-00000000000b', createdAt: opts.createdAt ?? '2026-06-02T00:00:00.000Z' },
    type: opts.type ?? ATTESTATION_WITHDRAWS,
    signer: opts.signer,
    targetNodeId: CONTENT_NODE_ID,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    reason: 'a stated reason',
  };
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  const sig = ed25519ph.sign(new TextEncoder().encode(nodeId), opts.seed);
  return {
    node,
    nodeId,
    signature: {
      signature: b64(sig),
      publicKey: spkiOf(opts.seed),
      algorithm: 'Ed25519ph',
      ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    },
  };
}

function registryListing(entry: Partial<TrustRegistryKey> = {}): TrustRegistry {
  return {
    keys: [
      {
        kid: OTHER_KID,
        publicKey: OTHER_KEY,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: REGISTRY_SIGNER,
        ...entry,
      },
    ],
  };
}

// --- A key-derived identifier binds by derivation ---------------------------

test('key-derived identifier: a node signed by a key that does not derive it is surfaced unbound and leaves status active', () => {
  const w = attestation({ signer: DID_SIGNER, seed: OTHER_SEED, kid: DID_SIGNER.identifier });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, DID_SIGNER.identifier);
  assert.equal(r.chain.length, 1, 'surfaced in the chain');
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.chain[0].signerMatchesTarget, false);
  assert.equal(r.status, 'active');
});

test('key-derived identifier: neither the target key nor a declared-url registry binds a key that does not derive it', () => {
  const w = attestation({ signer: DID_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const registry = registryListing({ signerIdentity: DID_SIGNER });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, DID_SIGNER.identifier, {
    targetPublicKey: OTHER_KEY,
    registry,
    registryProvenance: 'declared-url',
  });
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('key-derived identifier: a node signed by the key that derives it binds and reads withdrawn', () => {
  const w = attestation({ signer: DID_SIGNER, seed: RECORD_SEED, kid: DID_SIGNER.identifier });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, DID_SIGNER.identifier);
  assert.equal(r.chain[0].keyBound, true);
  assert.equal(r.chain[0].signerMatchesTarget, true);
  assert.equal(r.status, 'withdrawn');
});

test('key-derived identifier: a registry entry for the kid naming another identifier leaves the node unbound (check #14)', () => {
  const w = attestation({ signer: DID_SIGNER, seed: RECORD_SEED, kid: OTHER_KID });
  const registry = registryListing({ publicKey: RECORD_KEY });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, DID_SIGNER.identifier, { registry, registryProvenance: 'declared-url' });
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

// --- Any other identifier: the target's own key, or a declared-url registry --

test('non-key-derived identifier: a node signed by the target record\'s own key binds', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: RECORD_SEED, kid: 'example:key-a' });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, { targetPublicKey: RECORD_KEY });
  assert.equal(r.chain[0].keyBound, true);
  assert.equal(r.status, 'withdrawn');
});

test('non-key-derived identifier: another key binds when a declared-url registry lists it under the identifier', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, {
    targetPublicKey: RECORD_KEY,
    registry: registryListing(),
    registryProvenance: 'declared-url',
  });
  assert.equal(r.chain[0].keyBound, true);
  assert.equal(r.status, 'withdrawn');
});

test('non-key-derived identifier: the same registry carried in a bundle does not bind', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, {
    targetPublicKey: RECORD_KEY,
    registry: registryListing(),
    registryProvenance: 'bundle',
  });
  assert.equal(r.chain.length, 1);
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('non-key-derived identifier: the same registry with no stated provenance does not bind', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, {
    targetPublicKey: RECORD_KEY,
    registry: registryListing(),
  });
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('non-key-derived identifier: with neither a target key nor a registry, nothing binds', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: RECORD_SEED, kid: 'example:key-a' });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier);
  assert.equal(r.chain.length, 1, 'surfaced in the chain');
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('non-key-derived identifier: a declared-url registry that lists the key under another identifier does not bind (check #14)', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const registry = registryListing({ signerIdentity: { bindingTier: 'platform', identifier: 'platform:another-publisher', displayName: 'Another publisher' } });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, { registry, registryProvenance: 'declared-url' });
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('non-key-derived identifier: a declared-url registry that lists the key as revoked does not bind (check #5)', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID });
  const registry = registryListing({ status: 'revoked', revokedAt: '2026-03-01T00:00:00.000Z' });
  const r = verifyLifecycleChain([w], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, { registry, registryProvenance: 'declared-url' });
  assert.equal(r.chain[0].keyBound, false);
  assert.equal(r.status, 'active');
});

test('only a bound node moves status: an unbound reinstatement after a bound withdrawal leaves the record withdrawn', () => {
  const w = attestation({ signer: REGISTRY_SIGNER, seed: RECORD_SEED, kid: 'example:key-a', createdAt: '2026-06-02T00:00:00.000Z' });
  const re = attestation({ signer: REGISTRY_SIGNER, seed: OTHER_SEED, kid: OTHER_KID, type: ATTESTATION_REINSTATES, createdAt: '2026-06-03T00:00:00.000Z' });
  const r = verifyLifecycleChain([w, re], CONTENT_NODE_ID, REGISTRY_SIGNER.identifier, { targetPublicKey: RECORD_KEY });
  assert.equal(r.chain.length, 2, 'both surfaced');
  assert.deepEqual(r.chain.map((v) => v.keyBound), [true, false]);
  assert.equal(r.status, 'withdrawn');
  assert.equal(r.reinstatedAt, undefined);
});
