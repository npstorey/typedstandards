// RFC 3161 TSA verification tests (civic-ai-tools-website#119 P2a + P2b).
//
// Fixtures are REAL freetsa.org tokens with their embedded EC P-384 signing cert +
// RSA-4096 root: `rfc3161-token.json` (low-S) and `rfc3161-token-highs.json` (the
// prod da9246 high-S token). The clean case proves a token verifies fully OFFLINE —
// the signing cert chains to the PINNED FreeTSA root, EKU + validity come from the
// cert, and the TSA ECDSA-P384 signature verifies under the chain-derived key. The
// negatives prove wrong hash, forged signature, an untrusted root, and garbage all
// fail closed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyRfc3161Timestamp } from './index.ts';

const load = (f: string) =>
  JSON.parse(readFileSync(new URL(`./__fixtures__/${f}`, import.meta.url), 'utf8')) as {
    tokenB64: string;
    expectedHashHex: string;
  };
const fx = load('rfc3161-token.json');
const highS = load('rfc3161-token-highs.json');

test('verifyRfc3161Timestamp: a real token verifies fully OFFLINE (chain to pinned root)', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex);
  assert.equal(r.verified, true);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, true, 'embedded signing cert must chain to the pinned root');
  assert.equal(r.ekuTimestamping, true);
  assert.equal(r.withinValidity, true);
  assert.equal(r.signatureValid, true);
  assert.equal(r.tsa, 'freetsa.org');
  assert.equal(r.reason, undefined);
});

test('a real HIGH-S TSA signature verifies (lowS:false — regression for da9246)', async () => {
  const r = await verifyRfc3161Timestamp(highS.tokenB64, highS.expectedHashHex);
  assert.equal(r.signatureValid, true, 'a high-S TSA signature must verify');
  assert.equal(r.chainVerified, true);
  assert.equal(r.verified, true);
});

test('a token over a DIFFERENT hash fails the message imprint', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, 'f'.repeat(64));
  assert.equal(r.verified, false);
  assert.equal(r.imprintMatches, false);
  assert.equal(r.reason, 'imprint_mismatch');
});

test('a FORGED TSA signature fails closed (chain + binding still hold)', async () => {
  const raw = Buffer.from(fx.tokenB64, 'base64');
  raw[raw.length - 1] ^= 0xff; // flip a byte inside the trailing ECDSA signature
  const r = await verifyRfc3161Timestamp(raw.toString('base64'), fx.expectedHashHex);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, true);
  assert.equal(r.signatureValid, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'signature_invalid');
});

test('a chain that does not reach a PINNED root fails (untrusted_root)', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, []);
  assert.equal(r.chainVerified, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'untrusted_root');
  // imprint + binding still computed before the chain step.
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
});

test('garbage input reports parse_error, never throws', async () => {
  const r = await verifyRfc3161Timestamp('bm90LWEtdG9rZW4=', fx.expectedHashHex);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'parse_error');
});
