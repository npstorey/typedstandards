// Commitment-view builder tests: the §8.8.1 shape from neutral caller-
// supplied proof fields — emission order, conditional spreads (absent proofs
// omitted, never null), sealed-record redaction, the verbatim signature
// envelope, and the two inputs the core refuses to supply on the caller's
// behalf (trustRegistryUrl as per-publisher configuration, visibility as the
// asserted disclosure state).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildCommitmentView, type CommitmentViewInput } from './commitment.ts';

function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const PACKAGE_HASH = sha256Hex('a package');
const TRUST_REGISTRY_URL = 'https://evidence.example.org/.well-known/typed-publisher.json';

function fullInput(overrides: Partial<CommitmentViewInput> = {}): CommitmentViewInput {
  return {
    packageHash: PACKAGE_HASH,
    packageUrl: 'https://blobs.example.org/packages/abc.json',
    visibility: 'public',
    captureMethod: 'chat-flow-stream',
    contentProfile: 'adopter-profile',
    producerProfile: 'ai-assisted-analysis/adopter-profile',
    type: 'content/analysis/v1',
    signer: {
      bindingTier: 'organization',
      identifier: 'adopter:example-publisher',
      displayName: 'Example Publisher',
    },
    contentHash: { sha256: sha256Hex('content') },
    contentCanonicalization: 'https://typedstandards.org/canonicalization/legacy-json/v1',
    signature: {
      signature: 'c2ln',
      publicKey: 'cHVi',
      algorithm: 'Ed25519ph',
      kid: 'adopter:test-key-1',
    },
    signerIdentity: {
      provider: 'example-oauth',
      providerId: '12345',
      displayName: 'A Creator',
    },
    rfc3161Timestamp: 'dGltZXN0YW1w',
    rekorEntryId: '2429abcd',
    rekorInclusionProof: '{"logIndex":1}',
    rekorEntryBody: 'Ym9keQ==',
    lifecycle: { status: 'withdrawn', withdrawnAt: '2026-03-01T00:00:00.000Z' },
    lifecycleAttestations: [
      { node: { type: 'attestation/withdraws/v1' }, nodeId: sha256Hex('n') },
    ],
    trustRegistryUrl: TRUST_REGISTRY_URL,
    trustRegistryUrlLegacy: 'https://evidence.example.org/.well-known/evidence-public-keys.json',
    subjectTitle: 'A public title',
    subjectSummary: 'A public summary.',
    ...overrides,
  };
}

test('buildCommitmentView: full input emits the §8.8.1 shape in reference order', () => {
  const view = buildCommitmentView(fullInput());
  assert.deepEqual(Object.keys(view), [
    'evidenceProtocolVersion',
    'packageHash',
    'packageUrl',
    'visibility',
    'captureMethod',
    'contentProfile',
    'producerProfile',
    'type',
    'signer',
    'contentHash',
    'contentCanonicalization',
    'signature',
    'signerIdentity',
    'rfc3161Timestamp',
    'rekorEntryId',
    'rekorInclusionProof',
    'rekorEntryBody',
    'lifecycle',
    'lifecycleAttestations',
    'trustRegistryUrl',
    'trustRegistryUrlLegacy',
    'subjectTitle',
    'subjectSummary',
  ]);
  assert.equal(view.evidenceProtocolVersion, '0.1.0');
  assert.equal(view.packageHash, PACKAGE_HASH);
  assert.equal(view.trustRegistryUrl, TRUST_REGISTRY_URL);
});

test('signature envelope is carried VERBATIM (algorithm + kid intact)', () => {
  const input = fullInput();
  const view = buildCommitmentView(input);
  assert.deepEqual(view.signature, input.signature);
  // A pre-kid / plain-Ed25519 envelope is also carried as-is — the verifier
  // dispatches on whatever the envelope says.
  const legacySig = { signature: 'c2ln', publicKey: 'cHVi', algorithm: 'Ed25519' };
  const legacyView = buildCommitmentView(fullInput({ signature: legacySig }));
  assert.deepEqual(legacyView.signature, legacySig);
});

test('minimal input: absent proofs are OMITTED, defaults fill the base fields', () => {
  const view = buildCommitmentView({
    packageHash: PACKAGE_HASH,
    visibility: 'public',
    trustRegistryUrl: TRUST_REGISTRY_URL,
  });
  assert.deepEqual(Object.keys(view), [
    'evidenceProtocolVersion',
    'packageHash',
    'visibility',
    'captureMethod',
    'contentProfile',
    'trustRegistryUrl',
    'subjectTitle',
    'subjectSummary',
  ]);
  assert.equal(view.visibility, 'public');
  assert.equal(view.captureMethod, null);
  // The two remaining defaults are honest absences, not assertions about the
  // record: `null` claims nothing, and §8.8.1 defines `"default"` as the
  // profile of a package that carries none.
  assert.equal(view.contentProfile, 'default');
  // Absent proof fields never appear as nulls.
  assert.ok(!('signature' in view));
  assert.ok(!('rfc3161Timestamp' in view));
  assert.ok(!('rekorEntryId' in view));
  assert.ok(!('lifecycle' in view));
  assert.ok(!('lifecycleAttestations' in view));
});

test('redaction: packageUrl and content-derived strings are withheld; proofs are served', () => {
  const view = buildCommitmentView(
    fullInput({ visibility: 'sealed', redactContentSurface: true }),
  );
  assert.ok(!('packageUrl' in view));
  assert.ok(!('subjectTitle' in view));
  assert.ok(!('subjectSummary' in view));
  assert.equal(view.visibility, 'sealed');
  // Proof-side fields ARE the commitment — always served.
  assert.equal(view.packageHash, PACKAGE_HASH);
  assert.ok('signature' in view);
  assert.ok('rfc3161Timestamp' in view);
  assert.ok('rekorEntryId' in view);
  assert.ok('rekorInclusionProof' in view);
  assert.ok('rekorEntryBody' in view);
  assert.ok('lifecycle' in view);
  assert.equal(view.trustRegistryUrl, TRUST_REGISTRY_URL);
});

test('empty lifecycleAttestations array is omitted (chain absent ⇒ field absent)', () => {
  const view = buildCommitmentView(fullInput({ lifecycleAttestations: [] }));
  assert.ok(!('lifecycleAttestations' in view));
});

test('trustRegistryUrl is required configuration — never defaulted by the core', () => {
  assert.throws(
    () =>
      buildCommitmentView({
        packageHash: PACKAGE_HASH,
        visibility: 'public',
        trustRegistryUrl: '',
      }),
    /trustRegistryUrl/,
  );
});

// --- visibility: absent is an error, never a default (ADR-0024) ---

test('visibility is REQUIRED — an absent disclosure state throws, never defaults', () => {
  // The view is what a third party resolves while verifying, so a default
  // here would assert a disclosure state the producer never supplied — and
  // the removed default failed OPEN, claiming public disclosure of content a
  // producer may have meant to seal.
  assert.throws(
    () =>
      buildCommitmentView({
        packageHash: PACKAGE_HASH,
        trustRegistryUrl: TRUST_REGISTRY_URL,
      } as CommitmentViewInput),
    /buildCommitmentView requires visibility/,
  );
  // Empty string is absence too — matching the trustRegistryUrl guard.
  assert.throws(
    () => buildCommitmentView(fullInput({ visibility: '' })),
    /buildCommitmentView requires visibility/,
  );
});

test('visibility: both values of record are carried through verbatim', () => {
  assert.equal(buildCommitmentView(fullInput({ visibility: 'public' })).visibility, 'public');
  assert.equal(buildCommitmentView(fullInput({ visibility: 'sealed' })).visibility, 'sealed');
});

test('visibility: pre-ADR-0016 spellings stay accepted and are NOT normalized here', () => {
  // The core carries whatever string it is given; mapping the legacy input
  // aliases onto the vocabulary of record is caller-side adapter work.
  assert.equal(
    buildCommitmentView(fullInput({ visibility: 'published' })).visibility,
    'published',
  );
  assert.equal(
    buildCommitmentView(fullInput({ visibility: 'committed' })).visibility,
    'committed',
  );
});

test('trustRegistryUrlLegacy is emitted only when the publisher has one', () => {
  const withLegacy = buildCommitmentView(fullInput());
  assert.ok('trustRegistryUrlLegacy' in withLegacy);
  const withoutLegacy = buildCommitmentView(
    fullInput({ trustRegistryUrlLegacy: undefined }),
  );
  assert.ok(!('trustRegistryUrlLegacy' in withoutLegacy));
});

test('subject strings: explicit nulls serialize as JSON null (record has none)', () => {
  const view = buildCommitmentView(
    fullInput({ subjectTitle: null, subjectSummary: null }),
  );
  const parsed = JSON.parse(JSON.stringify(view)) as Record<string, unknown>;
  assert.equal(parsed.subjectTitle, null);
  assert.equal(parsed.subjectSummary, null);
});
