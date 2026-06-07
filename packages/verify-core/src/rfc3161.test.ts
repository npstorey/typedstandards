// RFC 3161 TSA verification tests (civic-ai-tools-website#119 P2a).
//
// The fixture (`__fixtures__/rfc3161-token.json`) is a REAL freetsa.org token over a
// known SHA-256, captured with its EC P-384 signing cert. The clean case proves the
// token verifies fully OFFLINE against the pinned FreeTSA anchor (the property #7 is
// about). The negatives prove a wrong package hash, a forged signature, an
// out-of-validity genTime, an unknown anchor, and garbage all fail closed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  verifyRfc3161Timestamp,
  FREETSA_TSA_ANCHORS,
  type TsaAnchor,
} from './index.ts';

const fx = JSON.parse(
  readFileSync(new URL('./__fixtures__/rfc3161-token.json', import.meta.url), 'utf8'),
) as { tokenB64: string; expectedHashHex: string };
const highS = JSON.parse(
  readFileSync(new URL('./__fixtures__/rfc3161-token-highs.json', import.meta.url), 'utf8'),
) as { tokenB64: string; expectedHashHex: string };

test('verifyRfc3161Timestamp: a real FreeTSA token verifies fully OFFLINE', () => {
  const r = verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex);
  assert.equal(r.verified, true);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.signatureValid, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.withinValidity, true);
  assert.equal(r.tsa, 'freetsa.org');
  assert.equal(typeof r.genTime, 'number');
  assert.equal(r.reason, undefined);
});

test('a real HIGH-S TSA signature verifies (lowS:false — regression for da9246)', () => {
  // FreeTSA legitimately emits high-S ECDSA signatures; `@noble`'s default
  // lowS:true would false-negative them. This is the real prod token that exposed it.
  const r = verifyRfc3161Timestamp(highS.tokenB64, highS.expectedHashHex);
  assert.equal(r.signatureValid, true, 'a high-S TSA signature must verify');
  assert.equal(r.verified, true);
  assert.equal(r.tsa, 'freetsa.org');
});

test('a token over a DIFFERENT hash fails the message imprint', () => {
  const otherHash = 'f'.repeat(64);
  const r = verifyRfc3161Timestamp(fx.tokenB64, otherHash);
  assert.equal(r.verified, false);
  assert.equal(r.imprintMatches, false);
  assert.equal(r.reason, 'imprint_mismatch');
});

test('a FORGED TSA signature fails closed (imprint + binding still hold)', () => {
  // Flip the last byte — inside the trailing ECDSA signature, leaving the DER
  // structure (and the TSTInfo) intact. The signature no longer verifies.
  const raw = Buffer.from(fx.tokenB64, 'base64');
  raw[raw.length - 1] ^= 0xff;
  const r = verifyRfc3161Timestamp(raw.toString('base64'), fx.expectedHashHex);
  assert.equal(r.verified, false);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.signatureValid, false);
});

test('an UNKNOWN anchor set fails (no pinned TSA vouches)', () => {
  const r = verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, []);
  assert.equal(r.verified, false);
  assert.equal(r.signatureValid, false);
  assert.equal(r.reason, 'no_anchor');
});

test('genTime outside the anchor validity window fails closed', () => {
  // Same pinned key, but a validity window that ends before the token's genTime.
  const expired: TsaAnchor = {
    ...FREETSA_TSA_ANCHORS[0],
    notBefore: '2000-01-01T00:00:00Z',
    notAfter: '2000-01-02T00:00:00Z',
  };
  const r = verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, [expired]);
  assert.equal(r.signatureValid, true);
  assert.equal(r.withinValidity, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'genTime_outside_validity');
});

test('garbage input reports parse_error, never throws', () => {
  const r = verifyRfc3161Timestamp('bm90LWEtdG9rZW4=', fx.expectedHashHex);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'parse_error');
});
