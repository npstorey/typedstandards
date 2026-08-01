// Envelope-assembly tests: determinism, dual-chain hashing parity with
// verify-core, conditional-spread byte discipline, and key-order discipline
// (the legacy chain hashes JSON.stringify output, so insertion order IS the
// byte contract). These are the P1 unit bar; the byte-golden fixture harness
// and the produce→verify round-trip land with the fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  jcs,
  LEGACY_JSON_CANONICALIZATION,
  computeEnvelopeHash,
  type BlobRef,
} from '@typedstandards/verify-core';
import {
  buildEnvelope,
  DEFAULT_CONTENT_TYPE,
  type EnvelopeInput,
  type EnvelopeQuery,
} from './envelope.ts';

function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function makeBlobRef(content: string, contentType = 'text/plain'): BlobRef {
  return {
    ref: `blob:sha256:${sha256Hex(content)}`,
    url: `https://blobs.example.org/evidence-refs/${sha256Hex(content)}.bin`,
    contentType,
    size: new TextEncoder().encode(content).byteLength,
  };
}

function baseInput(overrides: Partial<EnvelopeInput> = {}): EnvelopeInput {
  return {
    packageId: '11111111-2222-4333-8444-555555555555',
    createdAt: '2026-01-02T03:04:05.000Z',
    signingKeyId: 'adopter:test-key-1',
    prompt: 'How many service requests were filed last year?',
    promptVisibility: 'full_text',
    queries: [
      {
        tool: 'get_data',
        operationType: 'query',
        arguments: {
          type: 'query',
          portal: 'data.example.gov',
          dataset_id: 'abcd-1234',
          select: 'count(*)',
        },
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
    cost: {
      promptTokens: 100,
      completionTokens: 20,
      totalTokens: 120,
      model: 'example/model-1',
    },
    skillMetadata: {},
    output: 'Around 400,000.',
    trace: { resourceSpans: [] },
    ...overrides,
  };
}

// --- Determinism (the byte-golden precondition) ---

test('buildEnvelope: identical inputs produce identical packages and hashes', () => {
  const a = buildEnvelope(baseInput());
  const b = buildEnvelope(baseInput());
  assert.deepEqual(a.pkg, b.pkg);
  assert.equal(a.envelopeHash, b.envelopeHash);
  // Canonical JSON is byte-identical too, not merely deep-equal.
  assert.equal(JSON.stringify(a.pkg), JSON.stringify(b.pkg));
});

test('buildEnvelope: determinism inputs land verbatim in metadata', () => {
  const { pkg } = buildEnvelope(baseInput());
  assert.equal(pkg.metadata.schemaVersion, '0.1.0');
  assert.equal(pkg.metadata.packageId, '11111111-2222-4333-8444-555555555555');
  assert.equal(pkg.metadata.createdAt, '2026-01-02T03:04:05.000Z');
  assert.equal(pkg.metadata.signingKeyId, 'adopter:test-key-1');
});

// --- Legacy chain (no `type`): JSON.stringify hashing, no §8.2 fields ---

test('legacy chain: no contentHash/contentCanonicalization; hash is SHA-256(JSON.stringify)', () => {
  const { pkg, envelopeHash } = buildEnvelope(baseInput());
  assert.ok(!('contentHash' in pkg));
  assert.ok(!('contentCanonicalization' in pkg));
  assert.equal(envelopeHash, sha256Hex(JSON.stringify(pkg)));
  // Parity with the shared verify-side recompute.
  assert.equal(
    envelopeHash,
    computeEnvelopeHash(pkg as unknown as Record<string, unknown>),
  );
});

// --- v0.1 chain (`type` present): JCS hashing + §8.2 fields ---

test('v0.1 chain: type triggers contentCanonicalization + contentHash + JCS hashing', () => {
  const { pkg, envelopeHash } = buildEnvelope(
    baseInput({ type: DEFAULT_CONTENT_TYPE }),
  );
  assert.equal(pkg.type, DEFAULT_CONTENT_TYPE);
  assert.equal(pkg.contentCanonicalization, LEGACY_JSON_CANONICALIZATION);
  // contentHash is computed from the package minus itself (spread on last).
  const rest = { ...pkg } as Record<string, unknown>;
  delete rest['contentHash'];
  assert.deepEqual(pkg.contentHash, { sha256: sha256Hex(jcs(rest)) });
  // Envelope hash is SHA-256 of the JCS canonicalization of the full package.
  assert.equal(envelopeHash, sha256Hex(jcs(pkg)));
  assert.equal(
    envelopeHash,
    computeEnvelopeHash(pkg as unknown as Record<string, unknown>),
  );
});

test('v0.1 chain: caller-supplied canonicalization rule URI is carried opaquely', () => {
  const rule = 'https://standards.example.org/canonicalization/custom/v1';
  const { pkg } = buildEnvelope(
    baseInput({ type: DEFAULT_CONTENT_TYPE, contentCanonicalization: rule }),
  );
  assert.equal(pkg.contentCanonicalization, rule);
  // The digest is delegated to verify-core's rule dispatch (shared produce/
  // verify implementation) — for a non-notebook rule that is the
  // package-minus-contentHash fingerprint.
  const rest = { ...pkg } as Record<string, unknown>;
  delete rest['contentHash'];
  assert.deepEqual(pkg.contentHash, { sha256: sha256Hex(jcs(rest)) });
});

// --- Conditional-spread byte discipline ---

test('conditional spreads: absent labels emit no keys (pre-label byte shape)', () => {
  const { pkg } = buildEnvelope(baseInput());
  assert.ok(!('captureMethod' in pkg.metadata));
  assert.ok(!('contentProfile' in pkg.metadata));
  assert.ok(!('producerProfile' in pkg));
  assert.ok(!('type' in pkg));
  assert.ok(!('signer' in pkg));
  assert.ok(!('summary' in pkg));
  assert.ok(!('extensions' in pkg));
  assert.ok(!('provenance' in pkg));
});

test('captureMethod is covered by the envelope hash (tamper evidence)', () => {
  const without = buildEnvelope(baseInput());
  const withLabel = buildEnvelope(baseInput({ captureMethod: 'chat-flow-stream' }));
  assert.equal(withLabel.pkg.metadata.captureMethod, 'chat-flow-stream');
  assert.notEqual(without.envelopeHash, withLabel.envelopeHash);
});

test('opaque labels and signer are emitted verbatim when supplied', () => {
  const signer = {
    bindingTier: 'organization',
    identifier: 'adopter:example-publisher',
    displayName: 'Example Publisher',
  };
  const { pkg } = buildEnvelope(
    baseInput({
      captureMethod: 'adopter-capture/v2',
      contentProfile: 'adopter-profile',
      producerProfile: 'ai-assisted-analysis/adopter-profile',
      type: DEFAULT_CONTENT_TYPE,
      signer,
    }),
  );
  // Opaque strings: the core encodes no vocabulary, it carries what it is given.
  assert.equal(pkg.metadata.captureMethod, 'adopter-capture/v2');
  assert.equal(pkg.metadata.contentProfile, 'adopter-profile');
  assert.equal(pkg.producerProfile, 'ai-assisted-analysis/adopter-profile');
  assert.deepEqual(pkg.signer, signer);
});

test('summary is emitted only when supplied; extensions only when non-empty', () => {
  const withSummary = buildEnvelope(baseInput({ summary: 'A short summary.' }));
  assert.equal(withSummary.pkg.summary, 'A short summary.');

  const emptyExt = buildEnvelope(baseInput({ extensions: {} }));
  assert.ok(!('extensions' in emptyExt.pkg));
  // …and an empty extensions object is byte-identical to no extensions at all.
  assert.equal(emptyExt.envelopeHash, buildEnvelope(baseInput()).envelopeHash);

  const ext = { 'org.example.artifact': { kind: 'notebook' } };
  const withExt = buildEnvelope(baseInput({ extensions: ext }));
  assert.deepEqual(withExt.pkg.extensions, ext);
});

// --- Prompt visibility ---

test('prompt: full_text embeds the text; hash_only carries the hash alone', () => {
  const full = buildEnvelope(baseInput());
  assert.equal(full.pkg.prompt.text, 'How many service requests were filed last year?');
  assert.equal(full.pkg.prompt.hash, sha256Hex('How many service requests were filed last year?'));

  const hashed = buildEnvelope(baseInput({ promptVisibility: 'hash_only' }));
  assert.equal(hashed.pkg.prompt.visibility, 'hash_only');
  assert.ok(!('text' in hashed.pkg.prompt));
  assert.equal(hashed.pkg.prompt.hash, full.pkg.prompt.hash);
});

// --- BlobRef passthrough ---

test('BlobRef output and trace are passed through unchanged and covered by the hash', () => {
  const outRef = makeBlobRef('Long synthesized output…');
  const traceRef = makeBlobRef('{"resourceSpans":[]}', 'application/json');
  const a = buildEnvelope(baseInput({ output: outRef, trace: traceRef }));
  assert.deepEqual(a.pkg.output, outRef);
  assert.deepEqual(a.pkg.trace, traceRef);

  const b = buildEnvelope(baseInput({ output: makeBlobRef('Different content') }));
  assert.notEqual(a.envelopeHash, b.envelopeHash);
});

// --- Caller-supplied structures are re-emitted, not spread through ---

test('queries: entries are rebuilt in envelope key order; extra caller keys are dropped', () => {
  const withExtra = {
    tool: 'get_data',
    operationType: 'query',
    arguments: { select: 'count(*)' },
    internalRowId: 42, // an implementation-side leak the envelope must not carry
  } as unknown as EnvelopeQuery;
  const { pkg } = buildEnvelope(baseInput({ queries: [withExtra] }));
  assert.ok(!('internalRowId' in pkg.queries[0]));
  // JSON serialization drops the undefined-valued optional keys, leaving the
  // reference byte shape.
  assert.equal(
    JSON.stringify(pkg.queries[0]),
    '{"tool":"get_data","operationType":"query","arguments":{"select":"count(*)"}}',
  );
});

test('cost and skillMetadata are re-emitted in the envelope key order', () => {
  const { pkg } = buildEnvelope(
    baseInput({
      cost: { model: 'example/model-1', totalTokens: 120, promptTokens: 100, completionTokens: 20, durationMs: 900 },
      skillMetadata: { skillText: 'guidance text', systemPromptHash: sha256Hex('guidance text'), mcpServerUrl: 'https://mcp.example.org' },
    }),
  );
  assert.equal(
    JSON.stringify(pkg.cost),
    '{"promptTokens":100,"completionTokens":20,"totalTokens":120,"model":"example/model-1","durationMs":900}',
  );
  assert.equal(
    JSON.stringify(pkg.skillMetadata),
    `{"systemPromptHash":"${sha256Hex('guidance text')}","mcpServerUrl":"https://mcp.example.org","skillText":"guidance text"}`,
  );
});

// --- Provenance passthrough ---

test('provenance: caller-supplied graph is carried verbatim', () => {
  const provenance = {
    '@context': { prov: 'http://www.w3.org/ns/prov#' },
    '@graph': [{ '@id': 'urn:example:1', '@type': 'prov:Entity' }],
  };
  const { pkg } = buildEnvelope(baseInput({ provenance }));
  assert.deepEqual(pkg.provenance, provenance);
});

// --- Key-order discipline (the legacy-chain byte contract) ---

test('key order: fully-loaded envelope matches the reference emission order', () => {
  const { pkg } = buildEnvelope(
    baseInput({
      captureMethod: 'chat-flow-stream',
      contentProfile: 'adopter-profile',
      producerProfile: 'ai-assisted-analysis/adopter-profile',
      type: DEFAULT_CONTENT_TYPE,
      signer: { bindingTier: 'organization', identifier: 'adopter:x', displayName: 'X' },
      summary: 'A short summary.',
      provenance: { '@context': { prov: 'http://www.w3.org/ns/prov#' }, '@graph': [] },
      extensions: { 'org.example.artifact': {} },
    }),
  );
  assert.deepEqual(Object.keys(pkg), [
    'metadata',
    'producerProfile',
    'type',
    'signer',
    'contentCanonicalization',
    'prompt',
    'queries',
    'dataSources',
    'cost',
    'skillMetadata',
    'output',
    'trace',
    'summary',
    'provenance',
    'extensions',
    'contentHash', // computed from the base and spread on LAST
  ]);
  assert.deepEqual(Object.keys(pkg.metadata), [
    'schemaVersion',
    'packageId',
    'createdAt',
    'signingKeyId',
    'captureMethod',
    'contentProfile',
  ]);
});

// --- Signing status is explicit (first-class unsigned tier) ---

test('unsigned tier: the result is a complete package + hash with no signature and no status label', () => {
  const result = buildEnvelope(baseInput({ type: DEFAULT_CONTENT_TYPE }));
  assert.deepEqual(Object.keys(result), ['pkg', 'envelopeHash']);
  const serialized = JSON.stringify(result.pkg);
  assert.ok(!serialized.includes('"signature"'));
  assert.ok(!serialized.includes('"sealed"'));
  assert.equal(result.envelopeHash.length, 64);
});
