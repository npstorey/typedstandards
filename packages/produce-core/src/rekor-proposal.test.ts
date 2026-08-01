// Rekor hashedrekord codec tests: the proposal body's pinned invariants
// (sha512 prehash via verify-core's shared rekorHashForPackage, PEM-wrapped
// public key, verbatim signature content) and the tolerant-but-strict
// response parser.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { rekorHashForPackage } from '@typedstandards/verify-core';
import { signEnvelopeHash } from './signing.ts';
import { buildRekorProposal, parseRekorResponse } from './rekor-proposal.ts';

const SAMPLE_HASH =
  'acdb56712cc0e735589e39d485dcd2c3d34a611b6752ab2f8b703e13008a3004';

function makeSignedSample() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = Uint8Array.from(Buffer.from(jwk.d as string, 'base64url'));
  return signEnvelopeHash(SAMPLE_HASH, seed, 'adopter:test-key');
}

test('buildRekorProposal: hashedrekord v0.0.1 body with the sha512 prehash', () => {
  const signed = makeSignedSample();
  const body = buildRekorProposal(SAMPLE_HASH, signed.signature, signed.publicKey);

  assert.equal(body.apiVersion, '0.0.1');
  assert.equal(body.kind, 'hashedrekord');
  assert.equal(body.spec.data.hash.algorithm, 'sha512');
  // The recorded value is SHA-512 over the UTF-8 bytes of the hex envelope
  // hash — the Ed25519ph prehash of the signed message. Cross-checked against
  // node:crypto independently of verify-core.
  const expected = crypto
    .createHash('sha512')
    .update(Buffer.from(SAMPLE_HASH, 'utf-8'))
    .digest('hex');
  assert.equal(body.spec.data.hash.value, expected);
  assert.equal(body.spec.data.hash.value, rekorHashForPackage(SAMPLE_HASH));
  // Signature content is carried verbatim.
  assert.equal(body.spec.signature.content, signed.signature);
});

test('buildRekorProposal: publicKey.content is base64 of a PEM wrapping the SPKI DER', () => {
  const signed = makeSignedSample();
  const body = buildRekorProposal(SAMPLE_HASH, signed.signature, signed.publicKey);
  const pem = Buffer.from(body.spec.signature.publicKey.content, 'base64').toString('utf-8');
  assert.ok(pem.startsWith('-----BEGIN PUBLIC KEY-----\n'));
  assert.ok(pem.endsWith('-----END PUBLIC KEY-----\n'));
  assert.equal(
    pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\n/g, ''),
    signed.publicKey,
  );
});

test('buildRekorProposal: deterministic for identical inputs', () => {
  const signed = makeSignedSample();
  const a = buildRekorProposal(SAMPLE_HASH, signed.signature, signed.publicKey);
  const b = buildRekorProposal(SAMPLE_HASH, signed.signature, signed.publicKey);
  assert.deepEqual(a, b);
});

// --- Response parsing ---

const ENTRY_ID =
  '24296fb24b8ad77a71b3c37e23eab7a502ec7f8ffac0b7af1a537d2a264cbf012bcb2b42878b6b32';

function sampleResponse(): Record<string, unknown> {
  return {
    [ENTRY_ID]: {
      body: Buffer.from('{"kind":"hashedrekord"}').toString('base64'),
      integratedTime: 1767355200,
      logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 987654321,
      verification: {
        inclusionProof: {
          // Tree id kept short and obviously fake — long digit runs read as
          // account-shaped numbers to sensitivity scanners.
          checkpoint: 'rekor.example.org - 20260731\n…',
          hashes: ['deadbeef'],
          logIndex: 865830538,
          rootHash: 'cafe0123',
          treeSize: 865830539,
        },
      },
    },
  };
}

test('parseRekorResponse: extracts entryId, logIndex, inclusion proof, and canonical body', () => {
  const response = sampleResponse();
  const result = parseRekorResponse(response);
  assert.equal(result.entryId, ENTRY_ID);
  assert.equal(result.logIndex, 987654321);
  const entry = response[ENTRY_ID] as { verification: { inclusionProof: unknown }; body: string };
  assert.deepEqual(JSON.parse(result.inclusionProof), entry.verification.inclusionProof);
  assert.equal(result.entryBody, entry.body);
});

test('parseRekorResponse: missing verification degrades to an empty proof; non-string body to null', () => {
  const response = sampleResponse();
  const entry = response[ENTRY_ID] as Record<string, unknown>;
  delete entry.verification;
  delete entry.body;
  const result = parseRekorResponse(response);
  assert.equal(result.inclusionProof, '{}');
  assert.equal(result.entryBody, null);
});

test('parseRekorResponse: malformed responses throw', () => {
  assert.throws(() => parseRekorResponse(null), /object/);
  assert.throws(() => parseRekorResponse('nope'), /object/);
  assert.throws(() => parseRekorResponse([]), /object/);
  assert.throws(() => parseRekorResponse({}), /no entries/);
  assert.throws(() => parseRekorResponse({ [ENTRY_ID]: 'nope' }), /entry must be an object/);
  assert.throws(() => parseRekorResponse({ [ENTRY_ID]: { body: 'x' } }), /logIndex/);
});
