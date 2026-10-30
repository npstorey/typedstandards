// A verify-core table read by a value a record or bundle supplies resolves only
// the table's own entries: any other value reads as an unknown one does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  checkAttestationNode,
  verifyLifecycleChain,
  verifyRekorEntry,
  verifyCertSignatureRsa,
  rekorHashForPackage,
  deriveKeyDerivedIdentifier,
  computeEnvelopeHash,
  computeContentHashSha256,
  LEGACY_JSON_CANONICALIZATION,
  ATTESTATION_WITHDRAWS,
  ATTESTATION_CORROBORATES,
  type CarriedLifecycleNode,
  type FetchLike,
  type SignerIdentity,
  type X509Cert,
} from './index.ts';

const NAMES = Object.getOwnPropertyNames(Object.prototype);
const UNKNOWN_TYPE = 'attestation/not-a-sub-type/v1';

const SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 5 + 3) & 0xff);
const SPKI = (() => {
  const raw = ed25519.getPublicKey(SEED);
  const der = new Uint8Array(SPKI_PREFIX.length + raw.length);
  der.set(SPKI_PREFIX, 0);
  der.set(raw, SPKI_PREFIX.length);
  return b64(der);
})();
const SIGNER: SignerIdentity = {
  bindingTier: 'pseudonymous',
  identifier: deriveKeyDerivedIdentifier(SPKI),
  displayName: 'A self-certifying signer',
};
const TARGET = 'a'.repeat(64);
const CONTEXT = { target: { signerIdentifier: SIGNER.identifier, publicKey: SPKI } };

/** A signed carried node of `type`, its key bound to its signer by derivation. */
function carried(type: string, payload: Record<string, unknown> = {}): CarriedLifecycleNode {
  const base: Record<string, unknown> = {
    metadata: { schemaVersion: '0.1.0', packageId: '0a1b2c3d-0000-4000-8000-0000000000bb', createdAt: '2026-10-30T00:00:00.000Z' },
    type,
    signer: SIGNER,
    targetNodeId: TARGET,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...payload,
  };
  const node = { ...base, contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) } };
  const nodeId = computeEnvelopeHash(node);
  return {
    node,
    nodeId,
    signature: {
      signature: b64(ed25519ph.sign(new TextEncoder().encode(nodeId), SEED)),
      publicKey: SPKI,
      algorithm: 'Ed25519ph',
    },
  };
}

/** A check's reading with the fields that name the node itself left out. */
function reading(c: ReturnType<typeof checkAttestationNode>) {
  const { nodeId: _n, type: _t, ...rest } = c;
  return rest;
}

test('check 10 resolves only the tables\' own attestation types', () => {
  const unknownCheck = reading(checkAttestationNode(carried(UNKNOWN_TYPE), CONTEXT));
  assert.equal(unknownCheck.rule, null);
  assert.deepEqual(unknownCheck.missingFields, []);
  const unknownChain = verifyLifecycleChain([carried(UNKNOWN_TYPE)], TARGET, SIGNER.identifier);
  for (const name of NAMES) {
    let check: ReturnType<typeof checkAttestationNode> | undefined;
    assert.doesNotThrow(() => {
      check = checkAttestationNode(carried(name), CONTEXT);
    }, name);
    assert.deepEqual(reading(check!), unknownCheck, name);
    let chain: ReturnType<typeof verifyLifecycleChain> | undefined;
    assert.doesNotThrow(() => {
      chain = verifyLifecycleChain([carried(name)], TARGET, SIGNER.identifier);
    }, name);
    assert.equal(chain!.status, unknownChain.status, name);
    assert.deepEqual(
      chain!.chain.map((v) => v.missingFields),
      unknownChain.chain.map((v) => v.missingFields),
      name,
    );
  }
});

test('check 10: the real attestation types read their rows as before', () => {
  const withdraws = checkAttestationNode(carried(ATTESTATION_WITHDRAWS), CONTEXT);
  assert.equal(withdraws.rule, 'publisher-only');
  assert.deepEqual(withdraws.missingFields, ['reason']);
  assert.equal(withdraws.status, 'authorized');
  const corroborates = checkAttestationNode(carried(ATTESTATION_CORROBORATES, { scope: 'a figure' }));
  assert.equal(corroborates.rule, 'any-with-binding');
  assert.deepEqual(corroborates.missingFields, []);
  assert.equal(corroborates.status, 'authorized');
});

/** A log response holding one entry, under an id the caller does not ask for. */
function rekorResponse(packageHash: string): FetchLike {
  const body = btoa(JSON.stringify({ spec: { data: { hash: { algorithm: 'sha512', value: rekorHashForPackage(packageHash) } } } }));
  const json = { 'c0ffee0000000000aa': { body, logIndex: 7, integratedTime: 1700000000 } };
  return async () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(json)).buffer as ArrayBuffer,
    text: async () => JSON.stringify(json),
    json: async () => json,
  });
}

test('check 8 reads only the log response\'s own entries', async () => {
  const packageHash = 'd'.repeat(64);
  const fetch = rekorResponse(packageHash);
  const unknown = await verifyRekorEntry('not-an-entry-id', packageHash, { fetch });
  assert.equal(unknown.verified, true);
  for (const name of NAMES) {
    assert.deepEqual(await verifyRekorEntry(name, packageHash, { fetch }), unknown, name);
  }
  assert.deepEqual(await verifyRekorEntry('c0ffee0000000000aa', packageHash, { fetch }), unknown);
});

test('an RSA certificate signature resolves only the table\'s own algorithms', async () => {
  const cert = { sigAlgOid: '', signature: new Uint8Array(1), tbsBytes: new Uint8Array(1) } as unknown as X509Cert;
  for (const name of NAMES) {
    assert.equal(await verifyCertSignatureRsa({ ...cert, sigAlgOid: name }, new Uint8Array(1)), false, name);
  }
});
