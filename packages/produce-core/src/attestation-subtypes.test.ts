// The four ruled sub-types `buildAttestationNode` emits (typedstandards#113,
// G0 D1-D4): `supersedes`, `revises`, `corroborates` and `contradicts`, with the
// payload fields of their spec §8.12.1 rows. `endorses` stays reserved (D1).
//
// Each payload field is a conditional spread, as the existing sub-types' are:
// emitted when supplied, absent otherwise, so every existing input's bytes are
// unchanged (asserted by the unedited `reference-golden.test.ts`). produce-core
// does not enforce the required fields; the caller does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as verifyCore from '@typedstandards/verify-core';
import {
  buildAttestationNode,
  type AttestationInput,
  type EmittableAttestationType,
} from './index.ts';

const TARGET = 'a'.repeat(64);
const SUCCESSOR = 'b'.repeat(64);

function input(type: EmittableAttestationType, payload: Partial<AttestationInput> = {}): AttestationInput {
  return {
    packageId: '0a1b2c3d-0000-4000-8000-0000000000aa',
    createdAt: '2026-09-27T00:00:00.000Z',
    signingKeyId: 'example:test-key',
    type,
    targetNodeId: TARGET,
    signer: { bindingTier: 'pseudonymous', identifier: 'example:publisher', displayName: 'Example publisher' },
    ...payload,
  };
}

/** The keys every built node carries, whatever its sub-type. */
const STRUCTURAL = ['metadata', 'type', 'signer', 'targetNodeId', 'contentCanonicalization', 'contentHash'];

const keysOf = (o: object) => Object.keys(o).sort();

const ROWS: Array<{ type: EmittableAttestationType; uri: string; payload: Partial<AttestationInput> }> = [
  { type: 'attestation/supersedes/v1', uri: verifyCore.ATTESTATION_SUPERSEDES, payload: { successorNodeId: SUCCESSOR } },
  { type: 'attestation/revises/v1', uri: verifyCore.ATTESTATION_REVISES, payload: { successorNodeId: SUCCESSOR } },
  { type: 'attestation/corroborates/v1', uri: verifyCore.ATTESTATION_CORROBORATES, payload: { scope: 'the headline figure', reasoning: 'a repeat run agrees' } },
  { type: 'attestation/contradicts/v1', uri: verifyCore.ATTESTATION_CONTRADICTS, payload: { scope: 'the headline figure', reasoning: 'a recount differs' } },
];

for (const row of ROWS) {
  test(`${row.type}: emits exactly the §8.12.1 payload fields supplied, and no others`, () => {
    assert.equal(row.type, row.uri, 'the URI is verify-core\'s constant');
    const { node, nodeId } = buildAttestationNode(input(row.type, row.payload));
    assert.equal(node.type, row.type);
    for (const [field, value] of Object.entries(row.payload)) {
      assert.deepEqual((node as unknown as Record<string, unknown>)[field], value, `${row.type}: ${field}`);
    }
    assert.deepEqual(keysOf(node), [...STRUCTURAL, ...Object.keys(row.payload)].sort(), `${row.type}: key set`);
    assert.equal(nodeId, verifyCore.computeEnvelopeHash(node as unknown as Record<string, unknown>));
  });
}

test('corroborates / contradicts: reasoning is optional, and absent when not supplied', () => {
  for (const type of ['attestation/corroborates/v1', 'attestation/contradicts/v1'] as const) {
    const { node } = buildAttestationNode(input(type, { scope: 'the headline figure' }));
    assert.equal(node.scope, 'the headline figure', `${type}: scope`);
    assert.ok(!('reasoning' in node), `${type}: no reasoning key`);
    assert.deepEqual(keysOf(node), [...STRUCTURAL, 'scope'].sort(), `${type}: key set`);
  }
});

test('reasoning as a JSON object is emitted verbatim (spec §8.12.2: a variance methodology and a result delta)', () => {
  const reasoning = { methodology: 'a repeat run of the same prompt', resultDelta: 0, runs: [{ id: 'r1' }] };
  const { node } = buildAttestationNode(input('attestation/corroborates/v1', { scope: 'the headline figure', reasoning }));
  assert.deepEqual(node.reasoning, reasoning);
  // It is in the canonical JSON, so the content hash and nodeId cover it.
  const other = buildAttestationNode(input('attestation/corroborates/v1', { scope: 'the headline figure', reasoning: { ...reasoning, resultDelta: 1 } }));
  assert.notEqual(other.node.contentHash?.sha256, node.contentHash?.sha256);
  assert.notEqual(other.nodeId, buildAttestationNode(input('attestation/corroborates/v1', { scope: 'the headline figure', reasoning })).nodeId);
});

test('produce-core does not enforce required fields: a supersedes without successorNodeId builds, with none emitted', () => {
  const { node } = buildAttestationNode(input('attestation/supersedes/v1'));
  assert.ok(!('successorNodeId' in node));
  assert.deepEqual(keysOf(node), [...STRUCTURAL].sort());
});

test('the four URIs are re-exported with verify-core\'s values', async () => {
  const api = (await import('./index.ts')) as Record<string, unknown>;
  for (const name of ['ATTESTATION_SUPERSEDES', 'ATTESTATION_REVISES', 'ATTESTATION_CORROBORATES', 'ATTESTATION_CONTRADICTS']) {
    assert.equal(typeof api[name], 'string', name);
    assert.equal(api[name], (verifyCore as Record<string, unknown>)[name], name);
  }
});

test('endorses stays reserved: it is not an emittable type (G0 D1)', () => {
  // A compile-time check: `npm run typecheck` fails if endorses becomes emittable.
  // @ts-expect-error attestation/endorses/v1 is reserved until the spec defines its role check.
  const reserved: EmittableAttestationType = 'attestation/endorses/v1';
  assert.equal(reserved, 'attestation/endorses/v1');
  assert.ok(!('ATTESTATION_ENDORSES' in verifyCore));
});
