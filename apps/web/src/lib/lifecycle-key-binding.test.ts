// The site's lifecycle resolution passes what binds a carried attestation's
// signing key to the signer it names (typedstandards#113, G0 D5): the target
// record's own signing key, and a trust registry only when it was fetched from
// the declared URL. A registry carried in the bundle is not passed. A carried
// node whose key is not bound stays in the chain and does not move status.
//
// Exercised through `resolveCarriedLifecycle` and `verifyResolved`, the code the
// /verify page runs, in Node.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { recomputePackageHash, type TrustRegistry, type TrustRegistryProvenance } from '@typedstandards/verify-core';
import { resolveCarriedLifecycle, verifyResolved, type Commitment, type ResolvedInput } from './verify-flow.ts';

const SIGNER = { bindingTier: 'platform', identifier: 'platform:example-publisher', displayName: 'Example publisher' };
const PACKAGE_HASH = 'd'.repeat(64);

interface Key {
  publicKey: string;
  kid: string;
  sign(hashHex: string): { algorithm: string; publicKey: string; signature: string; kid: string };
}

function newKey(kid: string): Key {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const sk: KeyObject = privateKey;
  return {
    publicKey: spki,
    kid,
    sign: (hashHex) => ({
      algorithm: 'Ed25519',
      publicKey: spki,
      signature: Buffer.from(nodeSign(null, Buffer.from(hashHex, 'utf8'), sk)).toString('base64'),
      kid,
    }),
  };
}

const RECORD_KEY = newKey('example:record-key');
const OTHER_KEY = newKey('example:other-key');

/** A commitment signed by RECORD_KEY, carrying one withdrawal signed by `by` that
 *  names the record's own signer identifier. */
function commitmentWithdrawnBy(by: Key): Commitment {
  const node: Record<string, unknown> = {
    type: 'attestation/withdraws/v1',
    targetNodeId: PACKAGE_HASH,
    signer: SIGNER,
    metadata: { createdAt: '2026-06-08T00:00:00.000Z' },
    effectiveAt: '2026-06-08T00:00:00.000Z',
    reason: 'a stated reason',
  };
  const nodeId = recomputePackageHash(node);
  return {
    protocolVersion: '0.1.0',
    packageHash: PACKAGE_HASH,
    signer: SIGNER,
    signature: RECORD_KEY.sign(PACKAGE_HASH),
    lifecycleAttestations: [{ node, nodeId, signature: by.sign(nodeId) }],
  };
}

const REGISTRY_LISTING_OTHER_KEY: TrustRegistry = {
  keys: [
    {
      kid: OTHER_KEY.kid,
      publicKey: OTHER_KEY.publicKey,
      status: 'active',
      activatedAt: '2026-01-01T00:00:00.000Z',
      deprecatedAt: null,
      revokedAt: null,
      signerIdentity: SIGNER,
    },
  ],
};

function resolvedWith(commitment: Commitment, registryProvenance: TrustRegistryProvenance): ResolvedInput {
  return {
    commitment,
    pkg: null,
    registry: REGISTRY_LISTING_OTHER_KEY,
    directory: 'not_fetched',
    sources: {
      commitment: { kind: 'inline' },
      pkg: { kind: 'inline' },
      registry: { kind: registryProvenance === 'declared-url' ? 'fetched' : 'inline' },
    },
    registryProvenance,
    fullyOffline: true,
  };
}

test('resolveCarriedLifecycle: a withdrawal signed by the record\'s own key reads withdrawn', () => {
  const r = resolveCarriedLifecycle(commitmentWithdrawnBy(RECORD_KEY));
  assert.equal(r?.status, 'withdrawn');
  assert.equal(r?.chain[0].keyBound, true);
});

test('resolveCarriedLifecycle: a withdrawal signed by an unbound key naming the record\'s identifier reads active', () => {
  const r = resolveCarriedLifecycle(commitmentWithdrawnBy(OTHER_KEY));
  assert.equal(r?.chain.length, 1, 'surfaced in the chain');
  assert.equal(r?.chain[0].keyBound, false);
  assert.equal(r?.status, 'active');
});

test('verifyResolved passes a registry fetched from the declared URL: a key it lists under the identifier binds', async () => {
  const { result } = await verifyResolved(resolvedWith(commitmentWithdrawnBy(OTHER_KEY), 'declared-url'));
  assert.equal(result.lifecycle.source, 'attestation-chain');
  assert.equal(result.lifecycle.chain[0].keyBound, true);
  assert.equal(result.lifecycle.status, 'withdrawn');
});

test('verifyResolved does not pass a registry carried in the bundle: the same key stays unbound', async () => {
  const { result } = await verifyResolved(resolvedWith(commitmentWithdrawnBy(OTHER_KEY), 'bundle'));
  assert.equal(result.lifecycle.source, 'attestation-chain');
  assert.equal(result.lifecycle.chain[0].keyBound, false);
  assert.equal(result.lifecycle.status, 'active');
});
