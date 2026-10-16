// Attestation-builder tests: determinism, sub-type payload discipline (only
// supplied fields are emitted), §8.12.1 timestamp defaults resolved from the
// caller-supplied envelope timestamp, and nodeId parity with verify-core's
// shared envelope-hash recompute (attestation nodes always carry a multihash
// contentHash, so they ride the JCS chain).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  jcs,
  LEGACY_JSON_CANONICALIZATION,
  computeContentHashSha256,
  computeEnvelopeHash,
} from '@typedstandards/verify-core';
import {
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_PUBLISHES,
  ATTESTATION_LOCATED_AT,
  ATTESTATION_EVALUATES,
  buildAttestationNode,
  type AttestationInput,
} from './attestation.ts';

function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const TARGET_NODE_ID = sha256Hex('a content node');

function baseInput(overrides: Partial<AttestationInput> = {}): AttestationInput {
  return {
    packageId: '99999999-8888-4777-8666-555555555555',
    createdAt: '2026-02-03T04:05:06.000Z',
    signingKeyId: 'adopter:test-key-1',
    type: ATTESTATION_WITHDRAWS,
    targetNodeId: TARGET_NODE_ID,
    signer: {
      bindingTier: 'organization',
      identifier: 'adopter:example-publisher',
      displayName: 'Example Publisher',
    },
    ...overrides,
  };
}

test('buildAttestationNode: deterministic — identical inputs, identical node and nodeId', () => {
  const a = buildAttestationNode(baseInput({ reason: 'superseded analysis' }));
  const b = buildAttestationNode(baseInput({ reason: 'superseded analysis' }));
  assert.deepEqual(a.node, b.node);
  assert.equal(a.nodeId, b.nodeId);
  assert.equal(JSON.stringify(a.node), JSON.stringify(b.node));
});

test('withdraws: effectiveAt defaults to the caller-supplied envelope timestamp', () => {
  const { node } = buildAttestationNode(baseInput({ reason: 'error found' }));
  assert.equal(node.type, ATTESTATION_WITHDRAWS);
  assert.equal(node.reason, 'error found');
  assert.equal(node.effectiveAt, '2026-02-03T04:05:06.000Z');
  assert.equal(node.metadata.createdAt, '2026-02-03T04:05:06.000Z');
  assert.equal(node.metadata.packageId, '99999999-8888-4777-8666-555555555555');
  assert.equal(node.metadata.signingKeyId, 'adopter:test-key-1');
});

test('withdraws: an explicit effectiveAt wins over the default', () => {
  const { node } = buildAttestationNode(
    baseInput({ reason: 'error found', effectiveAt: '2026-02-04T00:00:00.000Z' }),
  );
  assert.equal(node.effectiveAt, '2026-02-04T00:00:00.000Z');
});

test('reinstates: no effectiveAt default; priorWithdrawalNodeId is emitted', () => {
  const prior = sha256Hex('a withdrawal node');
  const { node } = buildAttestationNode(
    baseInput({
      type: ATTESTATION_REINSTATES,
      priorWithdrawalNodeId: prior,
      reason: 'figure corrected',
    }),
  );
  assert.equal(node.type, ATTESTATION_REINSTATES);
  assert.ok(!('effectiveAt' in node));
  assert.equal(node.priorWithdrawalNodeId, prior);
});

test('publishes: publicationHost is emitted and releasedAt defaults to the envelope timestamp', () => {
  const { node } = buildAttestationNode(
    baseInput({ type: ATTESTATION_PUBLISHES, publicationHost: 'evidence.example.org' }),
  );
  assert.equal(node.publicationHost, 'evidence.example.org');
  assert.equal(node.releasedAt, '2026-02-03T04:05:06.000Z');
  assert.ok(!('effectiveAt' in node));
});

// --- publishes: the 0.8.0 bytes (hub ADR-0034 Consequences) ---
//
// `__fixtures__/publishes-0.8.0-reference.node.json` holds the publishes node
// that the published @typedstandards/produce-core 0.8.0 builds from the
// `publishes` inputs in `__fixtures__/layout-golden-inputs.json`, serialized
// as `JSON.stringify(node, null, 2) + '\n'` (provenance:
// `__fixtures__/README.md`). A node built without `layoutNodeId` stays
// byte-identical to it.

const fixtureText = (name: string): string =>
  readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf8');
const serialize = (node: unknown): string => JSON.stringify(node, null, 2) + '\n';
const layoutGoldenInputs = JSON.parse(fixtureText('layout-golden-inputs.json')) as {
  publishes: AttestationInput;
};
const PUBLISHES_080_BYTES = fixtureText('publishes-0.8.0-reference.node.json');

test('publishes: the 0.8.0 inputs build the published 0.8.0 node byte for byte', () => {
  const { node, nodeId } = buildAttestationNode(layoutGoldenInputs.publishes);
  assert.equal(serialize(node), PUBLISHES_080_BYTES);
  assert.equal(nodeId, computeEnvelopeHash(JSON.parse(PUBLISHES_080_BYTES) as Record<string, unknown>));
  assert.ok(!('layoutNodeId' in node));
});

// --- publishes: the optional layoutNodeId (spec §8.10.1, hub ADR-0034 §C) ---
//
// `__fixtures__/publishes-layout-golden.node.json` is the same publishes node
// with `layoutNodeId` set to the nodeId of `__fixtures__/layout-golden.node.json`.

const PUBLISHES_LAYOUT_BYTES = fixtureText('publishes-layout-golden.node.json');
const LAYOUT_GOLDEN_NODE_ID = computeEnvelopeHash(
  JSON.parse(fixtureText('layout-golden.node.json')) as Record<string, unknown>,
);

test('publishes: layoutNodeId is emitted directly after releasedAt, before contentHash, and builds the committed bytes', () => {
  const { node } = buildAttestationNode({
    ...layoutGoldenInputs.publishes,
    layoutNodeId: LAYOUT_GOLDEN_NODE_ID,
  });
  const keys = Object.keys(node);
  assert.equal(keys.indexOf('layoutNodeId'), keys.indexOf('releasedAt') + 1);
  assert.equal(keys.indexOf('contentHash'), keys.indexOf('layoutNodeId') + 1);
  assert.equal(keys.at(-1), 'contentHash');
  assert.equal(node.layoutNodeId, LAYOUT_GOLDEN_NODE_ID);
  assert.equal(serialize(node), PUBLISHES_LAYOUT_BYTES);
});

test('publishes: deleting layoutNodeId and recomputing contentHash yields the 0.8.0 bytes', () => {
  const withLayout = JSON.parse(PUBLISHES_LAYOUT_BYTES) as Record<string, unknown>;
  const { layoutNodeId, contentHash: _contentHash, ...rest } = withLayout;
  assert.equal(layoutNodeId, LAYOUT_GOLDEN_NODE_ID);
  const reverted = {
    ...rest,
    contentHash: { sha256: computeContentHashSha256(rest, LEGACY_JSON_CANONICALIZATION) },
  };
  assert.equal(serialize(reverted), PUBLISHES_080_BYTES);
  assert.equal(
    computeEnvelopeHash(reverted),
    computeEnvelopeHash(JSON.parse(PUBLISHES_080_BYTES) as Record<string, unknown>),
  );
  // The key changes contentHash and nodeId too (legacy-json/v1 covers it).
  assert.notDeepEqual(withLayout['contentHash'], reverted.contentHash);
});

test('a sub-type other than publishes, given layoutNodeId, emits none', () => {
  const others: Partial<AttestationInput>[] = [
    { type: ATTESTATION_WITHDRAWS, reason: 'error found' },
    { type: ATTESTATION_REINSTATES, reason: 'figure corrected' },
    { type: ATTESTATION_LOCATED_AT, uri: 'https://evidence.example.org/p.json' },
    { type: ATTESTATION_EVALUATES, scoringRubric: 'example-rubric' },
  ];
  for (const fields of others) {
    const without = buildAttestationNode(baseInput(fields));
    const withId = buildAttestationNode(baseInput({ ...fields, layoutNodeId: LAYOUT_GOLDEN_NODE_ID }));
    assert.ok(!('layoutNodeId' in withId.node), String(fields.type));
    assert.equal(serialize(withId.node), serialize(without.node), String(fields.type));
    assert.equal(withId.nodeId, without.nodeId, String(fields.type));
  }
});

test('locatedAt: uri, target fingerprint, and length are emitted when supplied', () => {
  const targetContentHash = { sha256: sha256Hex('the target content') };
  const { node } = buildAttestationNode(
    baseInput({
      type: ATTESTATION_LOCATED_AT,
      uri: 'https://evidence.example.org/packages/abc.json',
      targetContentHash,
      contentLength: 1234,
    }),
  );
  assert.equal(node.uri, 'https://evidence.example.org/packages/abc.json');
  assert.deepEqual(node.targetContentHash, targetContentHash);
  assert.equal(node.contentLength, 1234);
});

test('evaluates: methodology, scoringRubric, and results are emitted when supplied', () => {
  const methodology = {
    testSet: 'example-adversarial-rubric',
    promptSetVersion: sha256Hex('rubric text v1'),
    evaluatorModel: 'example/eval-model-1',
  };
  const results = {
    perCriterion: { grounding: { score: 4, comment: 'well grounded' } },
    overallScore: 4,
    assessment: 'passes',
  };
  const { node } = buildAttestationNode(
    baseInput({
      type: ATTESTATION_EVALUATES,
      methodology,
      scoringRubric: 'example-adversarial-rubric',
      results,
    }),
  );
  assert.deepEqual(node.methodology, methodology);
  assert.equal(node.scoringRubric, 'example-adversarial-rubric');
  assert.deepEqual(node.results, results);
});

test('payload discipline: only supplied sub-type fields appear in canonical JSON', () => {
  const { node } = buildAttestationNode(
    baseInput({ type: ATTESTATION_REINSTATES }),
  );
  assert.deepEqual(Object.keys(node), [
    'metadata',
    'type',
    'signer',
    'targetNodeId',
    'contentCanonicalization',
    'contentHash', // computed from the base and spread on last
  ]);
});

test('nodeId parity: RFC 8785 JCS envelope hash, shared with verify-core', () => {
  const { node, nodeId } = buildAttestationNode(baseInput({ reason: 'x' }));
  // Always a v0.1-style envelope: legacy-json/v1 rule + multihash contentHash.
  assert.equal(node.contentCanonicalization, LEGACY_JSON_CANONICALIZATION);
  const rest = { ...node } as Record<string, unknown>;
  delete rest['contentHash'];
  assert.deepEqual(node.contentHash, { sha256: sha256Hex(jcs(rest)) });
  assert.equal(nodeId, sha256Hex(jcs(node)));
  assert.equal(nodeId, computeEnvelopeHash(node as unknown as Record<string, unknown>));
});

test('unsigned tier: a built node carries no signature and no status label', () => {
  const result = buildAttestationNode(baseInput({ reason: 'x' }));
  assert.deepEqual(Object.keys(result), ['node', 'nodeId']);
  const serialized = JSON.stringify(result.node);
  assert.ok(!serialized.includes('"signature"'));
  assert.ok(!serialized.includes('"sealed"'));
});
