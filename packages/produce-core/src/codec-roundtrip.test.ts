// External-proof codec round-trips against verify-core's parsers — the
// offline stand-in for §9.2 checks #7/#8 (submission itself is
// implementation-side by design; no fetch ships in this package).
//
// Rekor leg: the `hashedrekord` proposal built by produce-core is served back
// through verify-core's `verifyRekorEntry` via an INJECTED fetcher (no
// network) — hash parity must hold, and the proposal's signature must be one
// the log's Ed25519ph verifier would accept. `parseRekorResponse` round-trips
// the same synthetic creation response.
//
// RFC 3161 leg: the producer's `TimeStampReq` message imprint is compared,
// byte-for-byte, against the imprint inside a REAL TSA token (the fixture
// copied from verify-core, captured from a public TSA) that
// `verifyRfc3161Timestamp` chain-verifies fully offline — proving request and
// token attest the SAME hash, on both sides of the codec.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  verifyRekorEntry,
  verifyRfc3161Timestamp,
  verifySignature,
  rekorHashForPackage,
  bytesToHex,
  children,
  content,
  expectTag,
  readNode,
  type FetchLike,
} from '@typedstandards/verify-core';
import {
  buildEnvelope,
  signEnvelopeHash,
  buildRekorProposal,
  parseRekorResponse,
  buildTimestampRequest,
  DEFAULT_CONTENT_TYPE,
  type EnvelopeInput,
} from './index.ts';

// --- A signed envelope produced entirely through the public API ---

function minimalInput(): EnvelopeInput {
  return {
    packageId: '11111111-2222-4333-8444-555555555555',
    createdAt: '2026-01-02T03:04:05.000Z',
    signingKeyId: 'adopter:test-key-1',
    prompt: 'How many service requests were filed last year?',
    promptVisibility: 'full_text',
    queries: [],
    dataSources: [],
    cost: { model: 'example/model-1' },
    skillMetadata: {},
    output: 'Around 400,000.',
    trace: { resourceSpans: [] },
    type: DEFAULT_CONTENT_TYPE,
  };
}

function makeSigned() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = Uint8Array.from(Buffer.from(jwk.d as string, 'base64url'));
  const { envelopeHash } = buildEnvelope(minimalInput());
  const signed = signEnvelopeHash(envelopeHash, seed, 'adopter:test-key-1');
  return { envelopeHash, signed };
}

// --- Rekor: proposal → (synthetic log entry) → verify-core hash parity ---

const ENTRY_ID = 'c0ffee'.repeat(13) + 'a1'; // 80-hex entry id
const LOG_INDEX = 987654321;
const INTEGRATED_TIME = 1767355200; // epoch seconds

/** Wrap a proposal body as the log-entry response `verifyRekorEntry` fetches:
 *  the entry's canonical `body` is the base64 of the entry JSON, which for
 *  `hashedrekord` carries the same spec fields as the submitted proposal. */
function syntheticLogResponse(proposal: unknown): Record<string, unknown> {
  return {
    [ENTRY_ID]: {
      body: Buffer.from(JSON.stringify(proposal)).toString('base64'),
      integratedTime: INTEGRATED_TIME,
      logIndex: LOG_INDEX,
    },
  };
}

function fetchServing(response: unknown): FetchLike {
  return async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => response,
    text: async () => JSON.stringify(response),
    arrayBuffer: async () => new ArrayBuffer(0),
  });
}

test('rekor round-trip: the built proposal passes verify-core hash parity via an injected fetcher', async () => {
  const { envelopeHash, signed } = makeSigned();
  const proposal = buildRekorProposal(envelopeHash, signed.signature, signed.publicKey);
  const response = syntheticLogResponse(proposal);

  const result = await verifyRekorEntry(ENTRY_ID, envelopeHash, {
    fetch: fetchServing(response),
  });
  assert.equal(result.verified, true, 'recorded sha512 prehash must match the package');
  assert.equal(result.logIndex, LOG_INDEX);
  assert.equal(result.integratedTime, INTEGRATED_TIME);

  // Parity fails closed for a DIFFERENT package's hash.
  const otherHash = envelopeHash.replace(/[0-9a-f]/, (c) => (c === 'f' ? '0' : 'f'));
  const mismatch = await verifyRekorEntry(ENTRY_ID, otherHash, {
    fetch: fetchServing(response),
  });
  assert.equal(mismatch.verified, false);
});

test('rekor round-trip: the proposal signature is one the log’s Ed25519ph verifier accepts', () => {
  const { envelopeHash, signed } = makeSigned();
  const proposal = buildRekorProposal(envelopeHash, signed.signature, signed.publicKey);

  // Pinned body invariants (rekor rejects anything else for bare Ed25519).
  assert.equal(proposal.spec.data.hash.algorithm, 'sha512');
  assert.equal(proposal.spec.data.hash.value, rekorHashForPackage(envelopeHash));
  // The carried signature verifies as Ed25519ph over the envelope-hash hex
  // string — verify-core's #2 verifier standing in for the log's.
  assert.equal(
    verifySignature(envelopeHash, proposal.spec.signature.content, signed.publicKey),
    true,
  );
});

test('parseRekorResponse round-trips the synthetic creation response', () => {
  const { envelopeHash, signed } = makeSigned();
  const proposal = buildRekorProposal(envelopeHash, signed.signature, signed.publicKey);
  const response = syntheticLogResponse(proposal);

  const parsed = parseRekorResponse(response);
  assert.equal(parsed.entryId, ENTRY_ID);
  assert.equal(parsed.logIndex, LOG_INDEX);
  assert.equal(parsed.inclusionProof, '{}'); // none carried on this response
  assert.ok(parsed.entryBody, 'canonical leaf body is captured for offline use');

  // The captured body decodes back to the proposal — the prehash the log
  // stores is the one the producer computed.
  const decoded = JSON.parse(Buffer.from(parsed.entryBody as string, 'base64').toString('utf8')) as {
    spec: { data: { hash: { algorithm: string; value: string } } };
  };
  assert.equal(decoded.spec.data.hash.algorithm, 'sha512');
  assert.equal(decoded.spec.data.hash.value, rekorHashForPackage(envelopeHash));
});

// --- RFC 3161: TimeStampReq imprint ↔ a real TSA token's imprint ---

const tokenFixture = JSON.parse(
  readFileSync(new URL('./__fixtures__/rfc3161-token.json', import.meta.url), 'utf8'),
) as { tokenB64: string; expectedHashHex: string };

/** Extract the MessageImprint hashedMessage from a built TimeStampReq. */
function requestImprintHex(der: Uint8Array): string {
  const root = expectTag(readNode(der, 0), 0x30, 'TimeStampReq');
  const [, messageImprint] = children(der, root);
  const [, hashOctets] = children(der, expectTag(messageImprint, 0x30, 'MessageImprint'));
  return bytesToHex(content(der, expectTag(hashOctets, 0x04, 'hashedMessage')));
}

test('rfc3161 round-trip: the request imprint equals the imprint a real, chain-verified token attests', async () => {
  // Producer side: the TimeStampReq a caller would POST to its TSA.
  const request = buildTimestampRequest(tokenFixture.expectedHashHex);
  assert.equal(requestImprintHex(request), tokenFixture.expectedHashHex);

  // Verifier side: the REAL token for that hash chain-verifies fully offline,
  // and the imprint it attests matches the request's imprint byte-for-byte.
  const verdict = await verifyRfc3161Timestamp(
    tokenFixture.tokenB64,
    tokenFixture.expectedHashHex,
  );
  assert.equal(verdict.imprintMatches, true, 'token attests the request’s imprint');
  assert.equal(verdict.verified, true, 'token chain-verifies against the pinned TSA root');
});

test('rfc3161 round-trip: a request over a different hash does not match the token', async () => {
  const otherHash = tokenFixture.expectedHashHex.replace(/^../, 'ff');
  const request = buildTimestampRequest(otherHash);
  assert.notEqual(requestImprintHex(request), tokenFixture.expectedHashHex);

  const verdict = await verifyRfc3161Timestamp(tokenFixture.tokenB64, otherHash);
  assert.equal(verdict.imprintMatches, false);
  assert.equal(verdict.verified, false);
  assert.equal(verdict.reason, 'imprint_mismatch');
});
