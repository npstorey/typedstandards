// Produce→verify round-trip — the independent-emission bar (the §9.2 leg of
// Q59(a)): a package built and signed with produce-core's PUBLIC API, carried
// through the §8.8.1 commitment view, passes verify-core's §9.2 check suite
// OFFLINE — checks #1–#6 and #11–#15 — against a test key and a test trust
// registry. (#7–#9 need live TSA / transparency-log / blob responses;
// submission is implementation-side by design, and the codec round-trip suite
// is the offline stand-in.)
//
// The injected fetcher THROWS, so any network dependence in the asserted
// checks would fail the test — offline is enforced, not assumed.
//
// Also asserted: the ADR-0020 unsigned tier — not signing yields a complete
// package + envelope hash (byte-identical to the signed run's package), and
// nothing in the result reads as a `sealed`/`public` status.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  verifyEvidence,
  LEGACY_JSON_CANONICALIZATION,
  type TrustRegistry,
  type VerifySignatureEnvelope,
} from '@typedstandards/verify-core';
import {
  buildEnvelope,
  signEnvelopeHash,
  buildCommitmentView,
  DEFAULT_CONTENT_TYPE,
  type EnvelopeInput,
} from './index.ts';

const KID = 'adopter:test-key-1';
const TRUST_REGISTRY_URL =
  'https://registry.example.org/.well-known/evidence-keys.json';
const SIGNER = {
  bindingTier: 'organization',
  identifier: 'adopter:example-publisher',
  displayName: 'Example Publisher',
};

/** A test Ed25519 seed (caller-supplied key custody, per the extraction). */
function makeSeed(): Uint8Array {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return Uint8Array.from(Buffer.from(jwk.d as string, 'base64url'));
}

/** A v0.1 envelope input a prospective adopter's pipeline would assemble. */
function envelopeInput(): EnvelopeInput {
  return {
    packageId: '11111111-2222-4333-8444-555555555555',
    createdAt: '2026-01-02T03:04:05.000Z',
    signingKeyId: KID,
    prompt: 'How many service requests were filed last year?',
    promptVisibility: 'full_text',
    queries: [
      {
        tool: 'get_data',
        operationType: 'query',
        arguments: { select: 'count(*)', dataset_id: 'abcd-1234' },
        datasetId: 'abcd-1234',
        portal: 'data.example.gov',
        resultRows: 1,
        resultColumns: 1,
      },
    ],
    dataSources: [
      {
        sourceId: 'open-data-portal',
        catalogType: 'catalog',
        portalUrl: 'https://data.example.gov',
        datasetId: 'abcd-1234',
        datasetUrl: 'https://data.example.gov/d/abcd-1234',
        accessTimestamp: '2026-01-02T03:04:00.000Z',
      },
    ],
    cost: { promptTokens: 100, completionTokens: 20, totalTokens: 120, model: 'example/model-1' },
    skillMetadata: {},
    output: 'Around 400,000.',
    trace: { resourceSpans: [] },
    captureMethod: 'chat-flow-stream',
    producerProfile: 'ai-assisted-analysis/example-adopter',
    type: DEFAULT_CONTENT_TYPE,
    signer: SIGNER,
  };
}

/** The production storage round-trip: stringify then parse. */
function storageRoundTrip(pkg: unknown): Record<string, unknown> {
  return JSON.parse(JSON.stringify(pkg)) as Record<string, unknown>;
}

/** Offline is ENFORCED: any fetch call fails the test. */
const offlineFetch = async (): Promise<never> => {
  throw new Error('offline round-trip: no network access is permitted');
};

/** Build + sign + carry through the sidecar, returning everything the
 *  verifier leg needs. */
function produceSignedPackage() {
  const seed = makeSeed();
  const { pkg, envelopeHash } = buildEnvelope(envelopeInput());
  const signed = signEnvelopeHash(envelopeHash, seed, KID);
  const registry: TrustRegistry = {
    keys: [
      {
        kid: KID,
        publicKey: signed.publicKey,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: SIGNER,
      },
    ],
  };
  const sidecar = buildCommitmentView({
    packageHash: envelopeHash,
    packageUrl: 'https://packages.example.org/evidence/example.json',
    visibility: 'public',
    captureMethod: 'chat-flow-stream',
    producerProfile: pkg.producerProfile,
    type: pkg.type,
    signer: pkg.signer,
    contentHash: pkg.contentHash,
    contentCanonicalization: pkg.contentCanonicalization,
    signature: { ...signed } as unknown as Record<string, unknown>,
    trustRegistryUrl: TRUST_REGISTRY_URL,
    subjectTitle: 'Example analysis',
    subjectSummary: 'A short summary.',
  });
  return { pkg, envelopeHash, signed, registry, sidecar };
}

test('round-trip: a produce-core package passes §9.2 checks #1–#6 and #11–#15 offline', async () => {
  const { pkg, envelopeHash, registry, sidecar } = produceSignedPackage();

  const result = await verifyEvidence(
    {
      package: storageRoundTrip(pkg),
      packageHash: sidecar.packageHash as string,
      signature: sidecar.signature as VerifySignatureEnvelope,
    },
    { registry, fetch: offlineFetch },
  );

  // #1 envelope integrity — recomputed hash matches the signed hash.
  assert.equal(result.hashMatch, true, '#1 hashMatch');
  assert.deepEqual(result.envelopeIntegrity, { status: 'verified' }, '#1 envelopeIntegrity');
  assert.equal(result.recomputedHash, envelopeHash, '#1 recomputedHash');

  // #2 signature mathematics — Ed25519ph over the envelope-hash hex string.
  assert.equal(result.hasSigning, true, '#2 hasSigning');
  assert.equal(result.signatureValid, true, '#2 signatureValid');

  // #3 content-canonicalization rule resolution — explicit v0.1 rule, known.
  assert.deepEqual(
    result.contentCanonicalization,
    { status: 'ok', rule: LEGACY_JSON_CANONICALIZATION },
    '#3 contentCanonicalization',
  );

  // #4 content-hash verification — recomputed under the resolved rule.
  assert.equal(result.contentHash?.status, 'ok', '#4 contentHash status');
  assert.equal(result.contentHash?.matched, 'sha256', '#4 matched algorithm');

  // #5 trust-registry verdict — the (kid, publicKey) pair is active.
  assert.equal(result.keyTrust?.status, 'active', '#5 keyTrust status');
  assert.equal(result.keyTrust?.verified, true, '#5 keyTrust verified');

  // #6 metadata.signingKeyId consistency — the signature envelope's kid equals
  // the key id inside the signed canonical JSON (rules out an envelope swap).
  assert.equal(result.kid, pkg.metadata.signingKeyId, '#6 kid ↔ metadata.signingKeyId');
  assert.equal((sidecar.signature as VerifySignatureEnvelope).kid, pkg.metadata.signingKeyId, '#6 sidecar kid');

  // #11 captureMethod label — read from the verified canonical JSON (the
  // signature-covered property is asserted by the tamper test below).
  assert.equal(result.captureMethodVocab?.captureMethod, 'chat-flow-stream', '#11 label');

  // #12 type resolution — a ratified v0.1 type URI.
  assert.deepEqual(result.typeResolution, { status: 'ok', type: DEFAULT_CONTENT_TYPE }, '#12 type');

  // #13 nodeId cross-check — the recomputed envelope hash IS the nodeId.
  assert.equal(result.nodeId, envelopeHash, '#13 nodeId');

  // #14 signer.identifier ↔ registry signerIdentity cross-check.
  assert.equal(result.signerIdentity?.status, 'ok', '#14 signerIdentity');
  assert.equal(result.signerIdentity?.claimed, SIGNER.identifier, '#14 claimed');
  assert.equal(result.signerIdentity?.registered, SIGNER.identifier, '#14 registered');

  // #15 captureMethod per-profile vocabulary conformance.
  assert.equal(result.captureMethodVocab?.status, 'ok', '#15 vocab');
  assert.equal(result.captureMethodVocab?.profileType, 'ai-assisted-analysis', '#15 profile type');
});

test('round-trip: tampering fails #1, including a silent captureMethod re-label (#11 is signature-covered)', async () => {
  const { pkg, registry, sidecar } = produceSignedPackage();

  // Tampered output bytes → altered.
  const tamperedOutput = storageRoundTrip(pkg);
  tamperedOutput['output'] = 'Around 500,000.';
  const r1 = await verifyEvidence(
    {
      package: tamperedOutput,
      packageHash: sidecar.packageHash as string,
      signature: sidecar.signature as VerifySignatureEnvelope,
    },
    { registry, fetch: offlineFetch },
  );
  assert.equal(r1.hashMatch, false);
  assert.deepEqual(r1.envelopeIntegrity, { status: 'altered' });

  // Flipped captureMethod label → altered (the label cannot be re-described
  // in storage without invalidating the envelope hash the signature covers).
  const relabeled = storageRoundTrip(pkg);
  (relabeled['metadata'] as Record<string, unknown>)['captureMethod'] =
    'claude-code-self-report';
  const r2 = await verifyEvidence(
    {
      package: relabeled,
      packageHash: sidecar.packageHash as string,
      signature: sidecar.signature as VerifySignatureEnvelope,
    },
    { registry, fetch: offlineFetch },
  );
  assert.equal(r2.hashMatch, false);
  assert.deepEqual(r2.envelopeIntegrity, { status: 'altered' });
});

test('round-trip: a mismatched registry identity fails #14; an unknown kid fails #5', async () => {
  const { pkg, registry, sidecar } = produceSignedPackage();

  const mismatchedRegistry: TrustRegistry = {
    keys: [
      {
        ...registry.keys[0],
        signerIdentity: { ...SIGNER, identifier: 'adopter:someone-else' },
      },
    ],
  };
  const r1 = await verifyEvidence(
    {
      package: storageRoundTrip(pkg),
      packageHash: sidecar.packageHash as string,
      signature: sidecar.signature as VerifySignatureEnvelope,
    },
    { registry: mismatchedRegistry, fetch: offlineFetch },
  );
  assert.equal(r1.signerIdentity?.status, 'signer_identity_mismatch', '#14 rejects a kid swap');

  const emptyRegistry: TrustRegistry = { keys: [] };
  const r2 = await verifyEvidence(
    {
      package: storageRoundTrip(pkg),
      packageHash: sidecar.packageHash as string,
      signature: sidecar.signature as VerifySignatureEnvelope,
    },
    { registry: emptyRegistry, fetch: offlineFetch },
  );
  assert.equal(r2.keyTrust?.status, 'unknown_key', '#5 rejects an unregistered key');
});

test('unsigned tier (ADR-0020): not signing yields a complete package + envelope hash and no status label', async () => {
  const unsigned = buildEnvelope(envelopeInput());

  // Complete, first-class result: exactly the package and its hash.
  assert.deepEqual(Object.keys(unsigned), ['pkg', 'envelopeHash']);
  assert.equal(unsigned.envelopeHash.length, 64);

  // Nothing that could read as a sealed/public tier — and no signature at all.
  const serialized = JSON.stringify(unsigned.pkg);
  assert.ok(!/sealed/i.test(serialized), 'no sealed label');
  assert.ok(!serialized.includes('"public"'), 'no public visibility label');
  assert.ok(!serialized.includes('"signature"'), 'no signature field');

  // Signing is detached: the signed run's package bytes and hash are
  // IDENTICAL — a signature adds proof material beside the package, never
  // mutates it.
  const { pkg: signedPkg, envelopeHash: signedHash } = buildEnvelope(envelopeInput());
  assert.equal(JSON.stringify(unsigned.pkg), JSON.stringify(signedPkg));
  assert.equal(unsigned.envelopeHash, signedHash);

  // The verifier reports the unsigned state honestly: envelope integrity (#1)
  // verifies, and the signature-dependent checks are null/absent — not failed,
  // not relabeled.
  const result = await verifyEvidence(
    {
      package: storageRoundTrip(unsigned.pkg),
      packageHash: unsigned.envelopeHash,
      signature: null,
    },
    { registry: undefined, fetch: offlineFetch },
  );
  assert.equal(result.hashMatch, true, '#1 verifies without a signature');
  assert.deepEqual(result.envelopeIntegrity, { status: 'verified' });
  assert.equal(result.hasSigning, false);
  assert.equal(result.signatureValid, null);
  assert.equal(result.keyTrust, null);
});
