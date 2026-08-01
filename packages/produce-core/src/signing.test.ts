// Signing-mechanism tests: Ed25519ph over the UTF-8 bytes of the envelope-
// hash hex string (spec §8.3.1), caller-supplied key + kid (no environment
// probe, no default identity), and the no-node:crypto key handling — raw
// 32-byte seed and PKCS8 DER inputs must agree with each other and with
// Node's own crypto (the interop bar for keys generated elsewhere).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifySignature } from '@typedstandards/verify-core';
import {
  SIGNING_ALGORITHM,
  derPublicKeyToPemBase64,
  derivePublicKeySpki,
  signEnvelopeHash,
} from './signing.ts';

const SAMPLE_HASH =
  'acdb56712cc0e735589e39d485dcd2c3d34a611b6752ab2f8b703e13008a3004';

/** A fixed 32-byte seed for deterministic vectors. */
const FIXED_SEED = Uint8Array.from(
  Buffer.from(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'hex',
  ),
);

interface TestKey {
  seed: Uint8Array;
  pkcs8Der: Uint8Array;
  pkcs8B64: string;
  spkiB64: string;
}

function generateTestKey(): TestKey {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pkcs8Der = new Uint8Array(
    privateKey.export({ format: 'der', type: 'pkcs8' }),
  );
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = Uint8Array.from(Buffer.from(jwk.d as string, 'base64url'));
  return {
    seed,
    pkcs8Der,
    pkcs8B64: Buffer.from(pkcs8Der).toString('base64'),
    spkiB64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  };
}

// --- SignResult shape + determinism ---

test('signEnvelopeHash: Ed25519ph SignResult with caller-supplied kid, 64-byte signature, SPKI public key', () => {
  const result = signEnvelopeHash(SAMPLE_HASH, FIXED_SEED, 'adopter:test-key');
  assert.equal(result.algorithm, SIGNING_ALGORITHM);
  assert.equal(result.algorithm, 'Ed25519ph');
  assert.equal(result.kid, 'adopter:test-key');
  assert.equal(Buffer.from(result.signature, 'base64').length, 64);
  assert.equal(Buffer.from(result.publicKey, 'base64').length, 44); // fixed Ed25519 SPKI
});

test('signEnvelopeHash: deterministic (Ed25519 is deterministic; no RNG in the core)', () => {
  const a = signEnvelopeHash(SAMPLE_HASH, FIXED_SEED, 'adopter:test-key');
  const b = signEnvelopeHash(SAMPLE_HASH, FIXED_SEED, 'adopter:test-key');
  assert.deepEqual(a, b);
});

// --- Round-trip with the verification core ---

test('round-trip: verify-core verifySignature accepts the signature', () => {
  const key = generateTestKey();
  const result = signEnvelopeHash(SAMPLE_HASH, key.seed, 'adopter:test-key');
  assert.equal(verifySignature(SAMPLE_HASH, result.signature, result.publicKey), true);
});

test('round-trip: a tampered hash fails verification', () => {
  const key = generateTestKey();
  const result = signEnvelopeHash(SAMPLE_HASH, key.seed, 'adopter:test-key');
  const tampered = SAMPLE_HASH.replace(/a/g, 'b');
  assert.equal(verifySignature(tampered, result.signature, result.publicKey), false);
});

test('cross-check: the signature verifies as Ed25519ph via @noble/curves directly', async () => {
  // Catches a silent switch back to pure Ed25519 — a pure signature would NOT
  // verify under Ed25519ph, and a transparency log would reject it.
  const key = generateTestKey();
  const result = signEnvelopeHash(SAMPLE_HASH, key.seed, 'adopter:test-key');
  const { ed25519ph } = await import('@noble/curves/ed25519.js');
  const rawPub = Uint8Array.from(Buffer.from(key.spkiB64, 'base64')).slice(12);
  const sigBytes = Uint8Array.from(Buffer.from(result.signature, 'base64'));
  const messageBytes = Uint8Array.from(Buffer.from(SAMPLE_HASH, 'utf-8'));
  assert.equal(ed25519ph.verify(sigBytes, messageBytes, rawPub), true);
});

// --- Key-input forms agree (raw seed | PKCS8 DER | base64 of either) ---

test('key inputs: raw seed, PKCS8 DER bytes, and base64 PKCS8 all produce the identical SignResult', () => {
  const key = generateTestKey();
  const fromSeed = signEnvelopeHash(SAMPLE_HASH, key.seed, 'k');
  const fromDer = signEnvelopeHash(SAMPLE_HASH, key.pkcs8Der, 'k');
  const fromB64 = signEnvelopeHash(SAMPLE_HASH, key.pkcs8B64, 'k');
  const fromSeedB64 = signEnvelopeHash(
    SAMPLE_HASH,
    Buffer.from(key.seed).toString('base64'),
    'k',
  );
  assert.deepEqual(fromDer, fromSeed);
  assert.deepEqual(fromB64, fromSeed);
  assert.deepEqual(fromSeedB64, fromSeed);
});

test('derivePublicKeySpki matches node:crypto SPKI export (interop bar)', () => {
  const key = generateTestKey();
  assert.equal(derivePublicKeySpki(key.seed), key.spkiB64);
  assert.equal(derivePublicKeySpki(key.pkcs8Der), key.spkiB64);
  assert.equal(derivePublicKeySpki(key.pkcs8B64), key.spkiB64);
});

// --- Caller-supplied configuration: no env probe, no defaults ---

test('signEnvelopeHash requires a kid — no default key identifier in the core', () => {
  assert.throws(() => signEnvelopeHash(SAMPLE_HASH, FIXED_SEED, ''), /kid/);
});

test('invalid keys throw: wrong seed length', () => {
  assert.throws(() => signEnvelopeHash(SAMPLE_HASH, FIXED_SEED.slice(0, 31), 'k'));
});

test('invalid keys throw: malformed DER', () => {
  const garbage = new Uint8Array(48).fill(0xab);
  assert.throws(() => signEnvelopeHash(SAMPLE_HASH, garbage, 'k'));
});

test('invalid keys throw: a non-Ed25519 PKCS8 key (wrong algorithm OID)', () => {
  const { privateKey } = crypto.generateKeyPairSync('x25519');
  const der = new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }));
  assert.throws(() => signEnvelopeHash(SAMPLE_HASH, der, 'k'), /not an Ed25519 key/);
});

// --- PEM helper ---

test('derPublicKeyToPemBase64: base64 of a PEM wrapping the DER base64, 64-char lines', () => {
  const key = generateTestKey();
  const pemB64 = derPublicKeyToPemBase64(key.spkiB64);
  const pem = Buffer.from(pemB64, 'base64').toString('utf-8');
  assert.ok(pem.startsWith('-----BEGIN PUBLIC KEY-----\n'));
  assert.ok(pem.endsWith('-----END PUBLIC KEY-----\n'));
  const body = pem
    .replace('-----BEGIN PUBLIC KEY-----\n', '')
    .replace('\n-----END PUBLIC KEY-----\n', '');
  for (const line of body.split('\n')) {
    assert.ok(line.length <= 64, 'PEM lines must wrap at 64 chars');
  }
  assert.equal(body.split('\n').join(''), key.spkiB64);
});
