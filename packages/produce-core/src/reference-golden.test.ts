// Byte-golden fixture suite — the refactor-safety bar for re-pointing the
// reference application at produce-core.
//
// `__fixtures__/reference-golden.json` was captured from the REFERENCE
// implementation (`civic-ai-tools-website` `src/lib/evidence/packager.ts` /
// `attestation.ts`, read-only) with its clock, RNG, and key-id environment
// read stubbed to fixed values; each case names the reference test(s) whose
// input it replicates, and carries the reference implementation's exact
// serialized JSON, content hash, and envelope hash for that input.
//
// The contract under test: for equivalent inputs, `buildEnvelope` /
// `buildAttestationNode` emit BYTE-IDENTICAL output — same serialized
// canonical JSON (on the legacy chain the `JSON.stringify` bytes ARE the
// hashed bytes; on the v0.1 chain they pin emission order), same multihash
// content hash, same envelope hash / nodeId. Values the reference packager
// derives inline (dataSources, provenance, the environment extension,
// producerProfile auto-derivation, the summary gate, the canonicalization
// rule) arrive here as caller-supplied envelope fields — the extraction's
// harness-derives / core-assembles division — carried verbatim in each
// fixture input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deriveKeyDerivedIdentifier, isKeyDerivedIdentifier } from '@typedstandards/verify-core';
import {
  buildEnvelope,
  buildAttestationNode,
  type AttestationInput,
  type EnvelopeInput,
} from './index.ts';

interface GoldenExpected {
  serializedJson: string;
  contentHashSha256: string | null;
  envelopeHash?: string;
  nodeId?: string;
}

interface GoldenCase {
  name: string;
  sourceTests: string[];
  /** How the case was captured, where it differs from `_meta`'s description. */
  capture?: string;
  /** For a key-derived signer: where its key comes from. */
  signerKeySource?: string;
  input: Record<string, unknown>;
  expected: GoldenExpected;
}

const fixture = JSON.parse(
  readFileSync(new URL('./__fixtures__/reference-golden.json', import.meta.url), 'utf8'),
) as {
  _meta: { referenceRepo: string; referenceCommit: string };
  envelopeCases: GoldenCase[];
  attestationCases: GoldenCase[];
};

const sha256Hex = (s: string) => createHash('sha256').update(s).digest('hex');

// --- Fixture discipline: every case is attributed and self-consistent ---

test('golden fixture: every case names its reference source test(s)', () => {
  assert.ok(fixture.envelopeCases.length >= 8, 'expected the captured envelope cases');
  assert.ok(fixture.attestationCases.length >= 6, 'expected the captured attestation cases');
  for (const c of [...fixture.envelopeCases, ...fixture.attestationCases]) {
    assert.ok(c.sourceTests.length > 0, `${c.name}: missing source-test attribution`);
    for (const s of c.sourceTests) {
      assert.match(s, /\.test\.ts :: /, `${c.name}: attribution must name file + test title`);
    }
  }
});

test('golden fixture: legacy-chain expectations are internally consistent (hash = SHA-256 of the serialized bytes)', () => {
  for (const c of fixture.envelopeCases) {
    if (c.expected.contentHashSha256 === null) {
      assert.equal(
        c.expected.envelopeHash,
        sha256Hex(c.expected.serializedJson),
        `${c.name}: captured legacy envelope hash must equal SHA-256 of the captured JSON bytes`,
      );
    }
  }
});

// --- Envelope cases: three byte-equal assertions per case ---

for (const c of fixture.envelopeCases) {
  test(`golden envelope [${c.name}]: byte-identical serialized JSON, content hash, envelope hash`, () => {
    const { pkg, envelopeHash } = buildEnvelope(c.input as unknown as EnvelopeInput);

    // 1. Serialized canonical JSON is byte-identical (insertion order and all).
    assert.equal(JSON.stringify(pkg), c.expected.serializedJson, `${c.name}: serialized JSON diverged`);

    // 2. The multihash content hash is identical (v0.1 cases) / absent (legacy).
    if (c.expected.contentHashSha256 === null) {
      assert.ok(!('contentHash' in pkg), `${c.name}: legacy case must not emit contentHash`);
    } else {
      assert.equal(pkg.contentHash?.sha256, c.expected.contentHashSha256, `${c.name}: contentHash diverged`);
    }

    // 3. The envelope hash is identical.
    assert.equal(envelopeHash, c.expected.envelopeHash, `${c.name}: envelope hash diverged`);
  });
}

// --- Attestation cases: the same three assertions for attestation/* nodes ---

for (const c of fixture.attestationCases) {
  test(`golden attestation [${c.name}]: byte-identical serialized JSON, content hash, nodeId`, () => {
    const { node, nodeId } = buildAttestationNode(c.input as unknown as AttestationInput);

    assert.equal(JSON.stringify(node), c.expected.serializedJson, `${c.name}: serialized JSON diverged`);
    assert.equal(node.contentHash?.sha256, c.expected.contentHashSha256, `${c.name}: contentHash diverged`);
    assert.equal(nodeId, c.expected.nodeId, `${c.name}: nodeId diverged`);
  });
}

// --- The self-certifying signer case (hub ADR-0030; Wave N14 P5) ---
//
// Byte identity is asserted by the envelope loop above, like every other case.
// This test pins what makes the case the self-certifying one, and that it
// names its source and its key's source.

/** RFC 8032 §7.1 TEST 1's published public key, as a base64 Ed25519 SPKI. */
const RFC8032_T1_SPKI = Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'),
  Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex'),
]).toString('base64');

test('golden envelope [v01-self-certified-signer]: a pseudonymous did:key signer, captured from the reference, naming its key', () => {
  const c = fixture.envelopeCases.find((x) => x.name === 'v01-self-certified-signer');
  assert.ok(c, 'the self-certified-signer case is in the fixture');

  // Its source and its key's source are named in the case itself.
  assert.match(c.capture ?? '', /reference implementation/);
  assert.match(c.capture ?? '', new RegExp(fixture._meta.referenceCommit));
  assert.match(c.signerKeySource ?? '', /RFC 8032 §7\.1 TEST 1/);

  // The signer is the self-certifying shape, and its identifier is the one
  // derived from RFC 8032 test 1's public key.
  const signer = c.input.signer as { bindingTier: string; identifier: string; displayName: string };
  assert.equal(signer.bindingTier, 'pseudonymous');
  assert.equal(isKeyDerivedIdentifier(signer.identifier), true);
  assert.equal(signer.identifier, deriveKeyDerivedIdentifier(RFC8032_T1_SPKI));
  // kid = metadata.signingKeyId = the identifier (ADR-0030 §5), so check #6
  // holds for a package signed with kid = the identifier.
  assert.equal(c.input.signingKeyId, signer.identifier);

  // The captured bytes carry that signer and key id verbatim.
  const captured = JSON.parse(c.expected.serializedJson) as {
    signer: unknown;
    metadata: { signingKeyId: string };
  };
  assert.deepEqual(captured.signer, signer);
  assert.equal(captured.metadata.signingKeyId, signer.identifier);

  // And produce-core emits exactly those bytes.
  const { pkg, envelopeHash } = buildEnvelope(c.input as unknown as EnvelopeInput);
  assert.equal(JSON.stringify(pkg), c.expected.serializedJson);
  assert.equal(pkg.contentHash?.sha256, c.expected.contentHashSha256);
  assert.equal(envelopeHash, c.expected.envelopeHash);
});
