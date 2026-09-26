// The per-node attestation check (typedstandards#113, G0 D6 as corrected, and D4).
//
// One pure check for `withdraws`, `reinstates`, `supersedes`, `revises`,
// `corroborates` and `contradicts`, in order: integrity and signature, the key
// binding (as `verifyLifecycleChain` binds a key), then the sub-type's
// authorization rule (spec §8.12.3):
//   - publisher-only (the four lifecycle sub-types) runs when the attested
//     record's signer and signing key are supplied, and otherwise reads
//     `not_checked`. A node naming another signer is a third party's
//     (`other_signer`); one naming the record's signer with a key not bound to it
//     is `publisher_key_unbound`;
//   - any-with-binding (`corroborates`, `contradicts`) needs the node's key bound
//     to its own identifier (a did:key by derivation; any other identifier only by
//     a registry fetched from its declared URL) and a `signer.bindingTier` on the
//     §8.5 ladder.
// It also names each required §8.12.1 payload field the node lacks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  checkAttestationNode,
  deriveKeyDerivedIdentifier,
  computeEnvelopeHash,
  computeContentHashSha256,
  LEGACY_JSON_CANONICALIZATION,
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
  ATTESTATION_REVISES,
  ATTESTATION_CORROBORATES,
  ATTESTATION_CONTRADICTS,
  type CarriedLifecycleNode,
  type SignerIdentity,
  type TrustRegistry,
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
const PRIOR = 'c'.repeat(64);
const PUBLISHER_SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 17 + 1) & 0xff);
const OTHER_SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 3 + 7) & 0xff);
const PUBLISHER: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
const OUTSIDER: SignerIdentity = { bindingTier: 'platform', identifier: 'platform:another-party', displayName: 'Another party' };
const SELF_CERTIFYING: SignerIdentity = {
  bindingTier: 'pseudonymous',
  identifier: deriveKeyDerivedIdentifier(spkiOf(OTHER_SEED)),
  displayName: 'A self-certifying reviewer',
};
const TARGET_CONTEXT = { target: { signerIdentifier: PUBLISHER.identifier, publicKey: spkiOf(PUBLISHER_SEED) } };
const KID = 'example:reviewer-key';

/** The §8.12.1 payload beyond `targetNodeId` that satisfies each sub-type's row. */
const PAYLOAD: Record<string, Record<string, unknown>> = {
  [ATTESTATION_WITHDRAWS]: { reason: 'a stated reason' },
  [ATTESTATION_REINSTATES]: { priorWithdrawalNodeId: PRIOR },
  [ATTESTATION_SUPERSEDES]: { successorNodeId: SUCCESSOR },
  [ATTESTATION_REVISES]: { successorNodeId: SUCCESSOR },
  [ATTESTATION_CORROBORATES]: { scope: 'the headline figure' },
  [ATTESTATION_CONTRADICTS]: { scope: 'the headline figure', reasoning: 'a recount differs' },
};

function build(
  type: string,
  opts: { signer?: SignerIdentity; seed?: Uint8Array; payload?: Record<string, unknown>; kid?: string } = {},
): CarriedLifecycleNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '0a1b2c3d-0000-4000-8000-0000000000aa', createdAt: '2026-09-26T00:00:00.000Z' },
    type,
    signer: opts.signer ?? PUBLISHER,
    targetNodeId: TARGET,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...(opts.payload ?? PAYLOAD[type]),
  };
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  const seed = opts.seed ?? PUBLISHER_SEED;
  return {
    node,
    nodeId,
    signature: {
      signature: b64(ed25519ph.sign(new TextEncoder().encode(nodeId), seed)),
      publicKey: spkiOf(seed),
      algorithm: 'Ed25519ph',
      ...(opts.kid ? { kid: opts.kid } : {}),
    },
  };
}

const PUBLISHER_ONLY = [ATTESTATION_WITHDRAWS, ATTESTATION_REINSTATES, ATTESTATION_SUPERSEDES, ATTESTATION_REVISES];
const ANY_WITH_BINDING = [ATTESTATION_CORROBORATES, ATTESTATION_CONTRADICTS];

for (const type of PUBLISHER_ONLY) {
  test(`${type}: publisher-only — signed by the record's key under its signer, authorized`, () => {
    const c = checkAttestationNode(build(type), TARGET_CONTEXT);
    assert.equal(c.rule, 'publisher-only');
    assert.equal(c.nodeIdMatches, true);
    assert.equal(c.signatureValid, true);
    assert.equal(c.keyBound, true);
    assert.equal(c.status, 'authorized');
    assert.deepEqual(c.missingFields, []);
  });

  test(`${type}: publisher-only — no target supplied reads not checked`, () => {
    const c = checkAttestationNode(build(type));
    assert.equal(c.rule, 'publisher-only');
    assert.equal(c.status, 'not_checked');
  });

  test(`${type}: publisher-only — a third party's node reads other_signer`, () => {
    const c = checkAttestationNode(build(type, { signer: OUTSIDER, seed: OTHER_SEED }), TARGET_CONTEXT);
    assert.equal(c.status, 'other_signer');
  });

  test(`${type}: publisher-only — naming the publisher with an unbound key reads publisher_key_unbound`, () => {
    const c = checkAttestationNode(build(type, { seed: OTHER_SEED }), TARGET_CONTEXT);
    assert.equal(c.keyBound, false);
    assert.equal(c.status, 'publisher_key_unbound');
  });
}

for (const type of ANY_WITH_BINDING) {
  test(`${type}: any-with-binding — a did:key bound by derivation, at a ladder tier, authorized`, () => {
    const c = checkAttestationNode(build(type, { signer: SELF_CERTIFYING, seed: OTHER_SEED }));
    assert.equal(c.rule, 'any-with-binding');
    assert.equal(c.keyBound, true);
    assert.equal(c.status, 'authorized');
    assert.deepEqual(c.missingFields, []);
  });

  test(`${type}: any-with-binding — a did:key its signing key does not derive is not authorized`, () => {
    const c = checkAttestationNode(build(type, { signer: SELF_CERTIFYING, seed: PUBLISHER_SEED }));
    assert.equal(c.keyBound, false);
    assert.equal(c.status, 'key_unbound');
  });

  test(`${type}: any-with-binding — a registry-bound identifier binds only by a registry fetched from its declared URL`, () => {
    const registry: TrustRegistry = {
      keys: [
        {
          kid: KID,
          publicKey: spkiOf(OTHER_SEED),
          status: 'active',
          activatedAt: '2026-01-01T00:00:00.000Z',
          deprecatedAt: null,
          revokedAt: null,
          signerIdentity: OUTSIDER,
        },
      ],
    };
    const n = build(type, { signer: OUTSIDER, seed: OTHER_SEED, kid: KID });
    assert.equal(checkAttestationNode(n).status, 'key_unbound', 'no registry');
    assert.equal(checkAttestationNode(n, { registry, registryProvenance: 'bundle' }).status, 'key_unbound', 'a bundle registry never binds');
    assert.equal(checkAttestationNode(n, { registry }).status, 'key_unbound', 'a registry with no stated provenance never binds');
    assert.equal(
      checkAttestationNode(n, { target: { signerIdentifier: OUTSIDER.identifier, publicKey: spkiOf(OTHER_SEED) } }).status,
      'key_unbound',
      'the attested record\'s key binds nothing under any-with-binding',
    );
    const fetched = checkAttestationNode(n, { registry, registryProvenance: 'declared-url' });
    assert.equal(fetched.keyBound, true);
    assert.equal(fetched.status, 'authorized');
  });

  test(`${type}: any-with-binding — a bindingTier off the §8.5 ladder is not authorized`, () => {
    for (const bindingTier of ['legacy_embedded', 'github', 'Pseudonymous', '']) {
      const signer = { ...SELF_CERTIFYING, bindingTier };
      const c = checkAttestationNode(build(type, { signer, seed: OTHER_SEED }));
      assert.equal(c.keyBound, true, bindingTier);
      assert.equal(c.status, 'binding_tier_off_ladder', bindingTier);
    }
    for (const bindingTier of ['pseudonymous', 'oauth', 'orcid', 'did-web', 'notarized', 'platform']) {
      const signer = { ...SELF_CERTIFYING, bindingTier };
      assert.equal(checkAttestationNode(build(type, { signer, seed: OTHER_SEED })).status, 'authorized', bindingTier);
    }
  });
}

test('a missing required payload field is reported by name, per the §8.12.1 row', () => {
  const cases: Array<[string, Record<string, unknown>, string[]]> = [
    [ATTESTATION_WITHDRAWS, {}, ['reason']],
    [ATTESTATION_WITHDRAWS, { reason: '' }, ['reason']],
    [ATTESTATION_REINSTATES, { reason: 'optional' }, ['priorWithdrawalNodeId']],
    [ATTESTATION_SUPERSEDES, {}, ['successorNodeId']],
    [ATTESTATION_REVISES, {}, ['successorNodeId']],
    [ATTESTATION_CORROBORATES, { reasoning: 'optional' }, ['scope']],
    [ATTESTATION_CONTRADICTS, {}, ['scope']],
  ];
  for (const [type, payload, missing] of cases) {
    const c = checkAttestationNode(build(type, { payload }), TARGET_CONTEXT);
    assert.deepEqual(c.missingFields, missing, type);
  }
  // targetNodeId is required of every row.
  const n = build(ATTESTATION_SUPERSEDES);
  const { targetNodeId: _dropped, ...rest } = n.node;
  const base = { ...rest };
  delete base['contentHash'];
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  const signed: CarriedLifecycleNode = {
    node,
    nodeId,
    signature: { signature: b64(ed25519ph.sign(new TextEncoder().encode(nodeId), PUBLISHER_SEED)), publicKey: spkiOf(PUBLISHER_SEED), algorithm: 'Ed25519ph' },
  };
  assert.deepEqual(checkAttestationNode(signed, TARGET_CONTEXT).missingFields, ['targetNodeId']);
});

test('a missing payload field does not change the authorization reading', () => {
  const c = checkAttestationNode(build(ATTESTATION_SUPERSEDES, { payload: {} }), TARGET_CONTEXT);
  assert.equal(c.status, 'authorized');
  assert.deepEqual(c.missingFields, ['successorNodeId']);
});

test('integrity and signature come first: an altered node, a forged signature, an unsigned node', () => {
  const n = build(ATTESTATION_CORROBORATES, { signer: SELF_CERTIFYING, seed: OTHER_SEED });
  const altered = checkAttestationNode({ ...n, nodeId: 'f' + n.nodeId.slice(1) });
  assert.equal(altered.nodeIdMatches, false);
  assert.equal(altered.status, 'node_id_mismatch');
  const forged = checkAttestationNode({ ...n, signature: { ...n.signature!, signature: b64(new Uint8Array(64)) } });
  assert.equal(forged.signatureValid, false);
  assert.equal(forged.status, 'signature_invalid');
  const unsigned = checkAttestationNode({ ...n, signature: null });
  assert.equal(unsigned.signatureValid, null);
  assert.equal(unsigned.status, 'unsigned');
});

test('a sub-type outside the six has no rule here and reads not checked', () => {
  const c = checkAttestationNode(build('attestation/publishes/v1', { payload: { publicationHost: 'h', releasedAt: 't' } }), TARGET_CONTEXT);
  assert.equal(c.rule, null);
  assert.equal(c.status, 'not_checked');
  assert.deepEqual(c.missingFields, []);
});
