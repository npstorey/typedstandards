// Attestation-builder tests: determinism, sub-type payload discipline (only
// supplied fields are emitted), §8.12.1 timestamp defaults resolved from the
// caller-supplied envelope timestamp, and nodeId parity with verify-core's
// shared envelope-hash recompute (attestation nodes always carry a multihash
// contentHash, so they ride the JCS chain).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  jcs,
  LEGACY_JSON_CANONICALIZATION,
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
