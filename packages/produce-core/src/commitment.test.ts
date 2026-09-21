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
    'protocolVersion',
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
  assert.equal(view.protocolVersion, '0.1.0');
  assert.equal(view.packageHash, PACKAGE_HASH);
  assert.equal(view.trustRegistryUrl, TRUST_REGISTRY_URL);
});

// The 2026-08-19 vocabulary settlement (spec §8.8.1, Appendix J): the wire key
// is `frozen-in-signed-artifacts`, so already-published views keep
// `evidenceProtocolVersion` forever and verifiers MUST accept both keys — but
// a NEW emission mints the new key ONLY. Emitting both would put a second,
// redundant assertion inside every freshly signed artifact and give the old
// key an indefinite life on the producing side, which is the outcome the
// settlement exists to end.
test('wire key: new emissions carry `protocolVersion` alone, never the prior-era key', () => {
  for (const view of [
    buildCommitmentView(fullInput()),
    buildCommitmentView({
      packageHash: PACKAGE_HASH,
      visibility: 'public',
      trustRegistryUrl: TRUST_REGISTRY_URL,
    }),
  ]) {
    assert.equal(view.protocolVersion, '0.1.0', 'the settlement-era key carries the version');
    assert.ok(
      !('evidenceProtocolVersion' in view),
      'the prior-era key `evidenceProtocolVersion` must NOT appear in a new emission',
    );
  }
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
    'protocolVersion',
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

// --- The self-certifying signer: the one case with no trustRegistryUrl ---
// (hub ADR-0030 §6). Absent `trustRegistryUrl` is accepted ONLY when
// `signer.identifier` is key-derived (`did:key:`) AND `bindingTier` is
// `pseudonymous`, and the identifier derived from `signature.publicKey`
// equals it. Every other case keeps the ADR-0024 throw, message unchanged.

/** The ADR-0024 message, verbatim — the other cases must still see exactly it. */
const ADR_0024_MESSAGE =
  'buildCommitmentView requires trustRegistryUrl — per-publisher configuration is caller-supplied, never a core constant';

/** RFC 8032 §7.1 TEST 1's published public key, as the envelope's base64 SPKI
 *  (the 12-byte Ed25519 SPKI prefix + the 32 raw bytes). */
const RFC8032_T1_SPKI = Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'),
  Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex'),
]).toString('base64');
/** Its did:key (the value verify-core's P4 tests assert). */
const DID_RFC8032_T1 = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';

/** A second, unrelated Ed25519 public key (base64 SPKI). */
function otherSpki(): string {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

function selfCertifiedInput(
  overrides: Partial<CommitmentViewInput> = {},
): CommitmentViewInput {
  const input = fullInput({
    signer: {
      bindingTier: 'pseudonymous',
      identifier: DID_RFC8032_T1,
      displayName: 'Example Self-Certifying Signer',
    },
    signature: {
      signature: 'c2ln',
      publicKey: RFC8032_T1_SPKI,
      algorithm: 'Ed25519ph',
      kid: DID_RFC8032_T1,
    },
    signerIdentity: undefined,
    trustRegistryUrl: undefined,
    trustRegistryUrlLegacy: undefined,
    ...overrides,
  });
  return input;
}

test('self-certifying signer: no trustRegistryUrl → the view OMITS the key (not null)', () => {
  const view = buildCommitmentView(selfCertifiedInput());
  assert.ok(!('trustRegistryUrl' in view), 'trustRegistryUrl must be omitted, not emitted');
  assert.ok(!JSON.stringify(view).includes('trustRegistryUrl'), 'no trustRegistryUrl key on the wire');
  assert.deepEqual(view.signer, selfCertifiedInput().signer, 'the signer claim is carried verbatim');
  assert.deepEqual(view.signature, selfCertifiedInput().signature, 'the signature envelope is carried verbatim');
  // Emission order is otherwise unchanged: the key's slot is simply absent.
  assert.deepEqual(Object.keys(view), [
    'protocolVersion',
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
    'rfc3161Timestamp',
    'rekorEntryId',
    'rekorInclusionProof',
    'rekorEntryBody',
    'lifecycle',
    'lifecycleAttestations',
    'subjectTitle',
    'subjectSummary',
  ]);
});

test('self-certifying signer: a supplied trustRegistryUrl is still emitted as given', () => {
  const view = buildCommitmentView(selfCertifiedInput({ trustRegistryUrl: TRUST_REGISTRY_URL }));
  assert.equal(view.trustRegistryUrl, TRUST_REGISTRY_URL);
});

test('ADR-0024 throw, unchanged: no signer and no trustRegistryUrl', () => {
  assert.throws(
    () => buildCommitmentView(selfCertifiedInput({ signer: undefined })),
    { message: ADR_0024_MESSAGE },
  );
});

test('ADR-0024 throw, unchanged: a non-key-derived identifier at pseudonymous (the ADR-0028 shape)', () => {
  assert.throws(
    () =>
      buildCommitmentView(
        selfCertifiedInput({
          signer: {
            bindingTier: 'pseudonymous',
            identifier: 'https://github.com/example-signer',
            displayName: 'Example Signer',
          },
        }),
      ),
    { message: ADR_0024_MESSAGE },
  );
});

for (const tier of ['oauth', 'orcid', 'did-web', 'notarized', 'platform', 'organization']) {
  test(`ADR-0024 throw, unchanged: a key-derived identifier at bindingTier "${tier}"`, () => {
    assert.throws(
      () =>
        buildCommitmentView(
          selfCertifiedInput({
            signer: {
              bindingTier: tier,
              identifier: DID_RFC8032_T1,
              displayName: 'Example Self-Certifying Signer',
            },
          }),
        ),
      { message: ADR_0024_MESSAGE },
    );
  });
}

test('self-certifying signer: an identifier the envelope key does not derive throws, with its own message', () => {
  // The identifier names RFC 8032 test 1's key; the envelope carries another.
  const swappedKey = selfCertifiedInput({
    signature: { signature: 'c2ln', publicKey: otherSpki(), algorithm: 'Ed25519ph', kid: DID_RFC8032_T1 },
  });
  assert.throws(
    () => buildCommitmentView(swappedKey),
    (err: Error) =>
      err.message !== ADR_0024_MESSAGE &&
      /is not the identifier derived from signature\.publicKey/.test(err.message) &&
      /check #14/.test(err.message),
  );
  // The did:key `u` (base64url) spelling is key-derived by prefix and never
  // equals the `z` derivation (ADR-0030 §3): also a mismatch.
  assert.throws(
    () =>
      buildCommitmentView(
        selfCertifiedInput({
          signer: {
            bindingTier: 'pseudonymous',
            // Built at run time: multibase `u` over `ed 01` + the same raw key.
            identifier: `did:key:u${Buffer.concat([
              Buffer.from([0xed, 0x01]),
              Buffer.from(RFC8032_T1_SPKI, 'base64').subarray(12),
            ]).toString('base64url')}`,
            displayName: 'Example Self-Certifying Signer',
          },
        }),
      ),
    /is not the identifier derived from signature\.publicKey/,
  );
});

test('self-certifying signer: no signature.publicKey, or a malformed one, throws with its own message', () => {
  for (const signature of [undefined, null, { signature: 'c2ln', algorithm: 'Ed25519ph' }]) {
    assert.throws(
      () => buildCommitmentView(selfCertifiedInput({ signature })),
      (err: Error) =>
        err.message !== ADR_0024_MESSAGE && /requires signature\.publicKey/.test(err.message),
    );
  }
  assert.throws(
    () =>
      buildCommitmentView(
        selfCertifiedInput({
          signature: { signature: 'c2ln', publicKey: 'cHVi', algorithm: 'Ed25519ph' },
        }),
      ),
    (err: Error) =>
      err.message !== ADR_0024_MESSAGE && /not an Ed25519 SPKI key/.test(err.message),
  );
});
