// Tests for the browser-safe verify-core (civic-ai-tools-website#116 WS2):
//   1. SPKI-extraction fixture — the DER-slice key extraction returns the exact
//      bytes the old `node:crypto` JWK path produced.
//   2. Algorithm dispatch (#111) — plain Ed25519 vs Ed25519ph verify under their
//      own labels; a mislabeled signature fails.
//   3. Parity — a clean package passes the verify-core orchestrator and a manual,
//      route-style composition of the same checks IDENTICALLY; a tampered package
//      fails BOTH identically. This is the no-drift guarantee.
//
// Run with: npm test  (Node 22; `nvm use 22`)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  extractRawPublicKey,
  verifySignature,
  verifyEvidence,
  verifyKeyTrust,
  recomputePackageHash,
  resolveContentCanonicalization,
  verifyContentHash,
  resolvePackageType,
  checkSignerIdentity,
  checkCaptureMethodVocab,
  computeEnvelopeHash,
  computeContentHashSha256,
  LEGACY_JSON_CANONICALIZATION,
  type TrustRegistry,
  type VerifyInput,
  type VerifySignatureEnvelope,
  type FetchLike,
} from './index.ts';

// A 12-byte Ed25519 SPKI prefix (SEQUENCE → AlgorithmIdentifier{OID 1.3.101.112}
// → BIT STRING). Used to assemble SPKI DER from a raw noble public key.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** The pre-WS2 extraction: Node's `createPublicKey(spki)→JWK→raw`. The fixture
 *  test asserts verify-core's DER-slice returns the identical bytes. */
function oldJwkExtract(pubB64Der: string): Uint8Array {
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(pubB64Der, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const jwk = publicKey.export({ format: 'jwk' });
  return Uint8Array.from(Buffer.from(jwk.x as string, 'base64url'));
}

/** Assemble a base64 SPKI DER public key from a raw 32-byte noble key. */
function rawToSpkiB64(rawPub: Uint8Array): string {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + rawPub.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(rawPub, ED25519_SPKI_PREFIX.length);
  return Buffer.from(der).toString('base64');
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

// A fetcher that throws if invoked — proves the clean/tampered cases verify
// fully OFFLINE (no rekor entry, no blob refs ⇒ no network).
const failFetch = (() => {
  throw new Error('verify-core touched the network when it should not have');
}) as unknown as FetchLike;

// --- 1. SPKI-extraction fixture -------------------------------------------

test('extractRawPublicKey: matches the old node:crypto JWK path on a real key', () => {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const spkiB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  const fromNoble = extractRawPublicKey(spkiB64);
  const fromNodeJwk = oldJwkExtract(spkiB64);

  assert.equal(fromNoble.length, 32);
  assert.deepEqual(Array.from(fromNoble), Array.from(fromNodeJwk));
});

test('extractRawPublicKey: rejects a non-Ed25519 / malformed SPKI', () => {
  assert.throws(() => extractRawPublicKey(b64(Uint8Array.from([0x30, 0x01, 0x00]))));
});

// --- 2. Algorithm dispatch (#111) -----------------------------------------

test('verifySignature: dispatches on algorithm — plain Ed25519 vs Ed25519ph', () => {
  // One keypair serves both schemes (same Ed25519 key derivation).
  const seed = Uint8Array.from(
    Array.from({ length: 32 }, (_unused, i) => (i * 7 + 3) & 0xff),
  );
  const rawPub = ed25519.getPublicKey(seed);
  const pubB64 = rawToSpkiB64(rawPub);
  const message = 'deadbeef'.repeat(8); // stand-in hex package hash
  const messageBytes = new TextEncoder().encode(message);

  const plainSig = b64(ed25519.sign(messageBytes, seed));
  const phSig = b64(ed25519ph.sign(messageBytes, seed));

  // Plain Ed25519 (the da9246 legacy case): verifies under its own label, fails
  // when mislabeled as Ed25519ph (the exact #111 false-negative).
  assert.equal(verifySignature(message, plainSig, pubB64, 'Ed25519'), true);
  assert.equal(verifySignature(message, plainSig, pubB64, 'Ed25519ph'), false);

  // Ed25519ph (the modern default): verifies under its label and with no label
  // (ph is the default), fails when mislabeled as plain Ed25519.
  assert.equal(verifySignature(message, phSig, pubB64, 'Ed25519ph'), true);
  assert.equal(verifySignature(message, phSig, pubB64), true);
  assert.equal(verifySignature(message, phSig, pubB64, 'Ed25519'), false);

  // A forgery fails under either scheme.
  const forged = b64(Uint8Array.from({ length: 64 }, () => 0));
  assert.equal(verifySignature(message, forged, pubB64, 'Ed25519'), false);
  assert.equal(verifySignature(message, forged, pubB64, 'Ed25519ph'), false);
});

// --- 3. Parity: orchestrator ↔ manual route-style composition --------------

const KID = 'platform:evidence-2026-04';
const SIGNER = {
  bindingTier: 'platform',
  identifier: 'platform:civic-ai-tools',
  displayName: 'Civic AI Tools Platform',
};

/** Build a signed, v0.1 (JCS-chain) package + its proofs + a trust registry. */
function buildSignedFixture() {
  const seed = Uint8Array.from(
    Array.from({ length: 32 }, (_unused, i) => (i * 11 + 5) & 0xff),
  );
  const rawPub = ed25519.getPublicKey(seed);
  const pubB64 = rawToSpkiB64(rawPub);

  const base: Record<string, unknown> = {
    metadata: {
      schemaVersion: '0.1.0',
      packageId: '00000000-0000-4000-8000-000000000000',
      createdAt: '2026-06-01T00:00:00.000Z',
      captureMethod: 'claude-code-jsonl-readback',
    },
    type: 'content/analysis/v1',
    producerProfile: 'ai-assisted-analysis/datHere',
    signer: SIGNER,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    output: 'The answer is 42.',
  };
  const contentHash = {
    sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION),
  };
  const pkg = { ...base, contentHash };
  const packageHash = computeEnvelopeHash(pkg);

  const signature: VerifySignatureEnvelope = {
    signature: b64(ed25519ph.sign(new TextEncoder().encode(packageHash), seed)),
    publicKey: pubB64,
    algorithm: 'Ed25519ph',
    kid: KID,
  };

  const registry: TrustRegistry = {
    keys: [
      {
        kid: KID,
        publicKey: pubB64,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: SIGNER,
      },
    ],
  };

  return { pkg, packageHash, signature, registry };
}

/** The route-style hand-composition of the same checks (the pre-verifyEvidence
 *  orchestration) — the independent path the orchestrator must agree with. */
function manualVerify(
  pkg: Record<string, unknown> | null,
  packageHash: string,
  signature: VerifySignatureEnvelope,
  registry: TrustRegistry,
) {
  const recomputedHash = pkg ? recomputePackageHash(pkg) : null;
  const hashMatch = recomputedHash === packageHash;
  const signatureValid = packageHash
    ? verifySignature(packageHash, signature.signature, signature.publicKey, signature.algorithm)
    : null;
  const keyTrust =
    signature.publicKey && signature.kid
      ? verifyKeyTrust(signature.publicKey, signature.kid, undefined, registry)
      : null;
  const contentCanonicalization = pkg ? resolveContentCanonicalization(pkg) : null;
  const contentHash =
    pkg && contentCanonicalization
      ? verifyContentHash(pkg, contentCanonicalization, packageHash)
      : null;
  const typeResolution = pkg ? resolvePackageType(pkg) : null;
  const signerIdentity = pkg ? checkSignerIdentity(pkg, signature.kid, registry) : null;
  const captureMethodVocab = pkg ? checkCaptureMethodVocab(pkg) : null;
  return {
    hashMatch,
    nodeId: recomputedHash,
    signatureValid,
    keyTrust,
    contentCanonicalization,
    contentHash,
    typeResolution,
    signerIdentity,
    captureMethodVocab,
  };
}

/** Slice the orchestrator result down to the fields the manual path produces. */
function coreSlice(r: Awaited<ReturnType<typeof verifyEvidence>>) {
  return {
    hashMatch: r.hashMatch,
    nodeId: r.nodeId,
    signatureValid: r.signatureValid,
    keyTrust: r.keyTrust,
    contentCanonicalization: r.contentCanonicalization,
    contentHash: r.contentHash,
    typeResolution: r.typeResolution,
    signerIdentity: r.signerIdentity,
    captureMethodVocab: r.captureMethodVocab,
  };
}

test('parity: a clean package passes the orchestrator and manual path identically', async () => {
  const { pkg, packageHash, signature, registry } = buildSignedFixture();

  const input: VerifyInput = {
    package: pkg,
    packageHash,
    signature,
    rfc3161Timestamp: 'dGltZXN0YW1w',
    rekorEntryId: null,
    lifecycle: null,
  };
  const core = await verifyEvidence(input, { registry, fetch: failFetch });
  const manual = manualVerify(pkg, packageHash, signature, registry);

  // The clean package is fully green on both paths.
  assert.equal(core.hashMatch, true);
  assert.equal(core.signatureValid, true);
  assert.equal(core.keyTrust?.status, 'active');
  assert.equal(core.contentHash?.status, 'ok');
  assert.equal(core.contentCanonicalization?.status, 'ok');
  assert.equal(core.typeResolution?.status, 'ok');
  assert.equal(core.signerIdentity?.status, 'ok');
  assert.equal(core.captureMethodVocab?.status, 'ok');
  // Presence-only #7 surfaced honestly.
  assert.equal(core.hasTimestamp, true);

  // And the two independent paths agree field-for-field.
  assert.deepEqual(coreSlice(core), manual);
});

test('parity: tampered CONTENT fails both paths identically (hash + content-hash)', async () => {
  const { pkg, packageHash, signature, registry } = buildSignedFixture();
  // Mutate the off-log content without updating contentHash or the claimed hash.
  const tampered = { ...pkg, output: 'The answer is 9000.' };

  const core = await verifyEvidence(
    { package: tampered, packageHash, signature, rekorEntryId: null, lifecycle: null },
    { registry, fetch: failFetch },
  );
  const manual = manualVerify(tampered, packageHash, signature, registry);

  // Envelope integrity breaks; content-hash recompute breaks; the signature over
  // the ORIGINAL claimed hash still validates (the tamper is caught by #1/#4).
  assert.equal(core.hashMatch, false);
  assert.equal(core.contentHash?.status, 'content_hash_mismatch');
  assert.equal(core.signatureValid, true);
  assert.deepEqual(coreSlice(core), manual);
});

test('parity: tampered CLAIMED HASH fails both paths identically (signature)', async () => {
  const { pkg, packageHash, signature, registry } = buildSignedFixture();
  // Flip the last hex char of the claimed package hash.
  const lastChar = packageHash.slice(-1);
  const badHash = packageHash.slice(0, -1) + (lastChar === '0' ? '1' : '0');

  const core = await verifyEvidence(
    { package: pkg, packageHash: badHash, signature, rekorEntryId: null, lifecycle: null },
    { registry, fetch: failFetch },
  );
  const manual = manualVerify(pkg, badHash, signature, registry);

  // The recomputed hash no longer equals the (altered) claim, and the signature
  // no longer verifies against it.
  assert.equal(core.hashMatch, false);
  assert.equal(core.signatureValid, false);
  assert.deepEqual(coreSlice(core), manual);
});

test('verifyEvidence: surfaces lifecycle STATE from the sidecar (portable depth)', async () => {
  const { pkg, packageHash, signature, registry } = buildSignedFixture();

  const withdrawn = await verifyEvidence(
    {
      package: pkg,
      packageHash,
      signature,
      rekorEntryId: null,
      lifecycle: {
        status: 'withdrawn',
        withdrawnAt: '2026-06-02T00:00:00.000Z',
        withdrawnReason: 'superseded',
      },
    },
    { registry, fetch: failFetch },
  );
  assert.equal(withdrawn.lifecycle.status, 'withdrawn');
  assert.equal(withdrawn.lifecycle.source, 'legacy-columns');
  assert.equal(withdrawn.lifecycle.withdrawnReason, 'superseded');

  // No lifecycle history → active / none.
  const active = await verifyEvidence(
    { package: pkg, packageHash, signature, rekorEntryId: null, lifecycle: null },
    { registry, fetch: failFetch },
  );
  assert.equal(active.lifecycle.status, 'active');
  assert.equal(active.lifecycle.source, 'none');
});
