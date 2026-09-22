// Check #12 (`type` resolution) against the specification's ratified set
// (typedstandards#96; hub civic-ai-tools#230, owner ruling D3: sixteen
// attestation sub-types, `attestation/revises/v1` among them).
//
// The expected list below is copied from the Typed Standards specification,
// docs/architecture/typed-standards-specification.md at hub commit cfdb210:
// the §8.12.1 sub-type table, lines 1418-1433 (sixteen rows), which the
// normative namespace paragraph at line 205 lists in the same order.
// It cannot be derived from this repository: the specification lives in the
// hub, and this repository holds no other copy of the sub-type table.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolvePackageType, TYPE_RESOLUTION_STATUSES } from './index.ts';

/** Spec §8.12.1, lines 1418-1433 at hub cfdb210, in table order. */
const RATIFIED_ATTESTATION_SUB_TYPES = [
  'attestation/withdraws/v1',
  'attestation/reinstates/v1',
  'attestation/supersedes/v1',
  'attestation/revises/v1',
  'attestation/publishes/v1',
  'attestation/locatedAt/v1',
  'attestation/corroborates/v1',
  'attestation/contradicts/v1',
  'attestation/endorses/v1',
  'attestation/wasDerivedFrom/v1',
  'attestation/answersQuestion/v1',
  'attestation/supportedBy/v1',
  'attestation/opposedBy/v1',
  'attestation/certifies/v1',
  'attestation/evaluates/v1',
  'attestation/conforms/v1',
] as const;

test('#96: a node typed attestation/revises/v1 reads check #12 ok', () => {
  assert.deepEqual(resolvePackageType({ type: 'attestation/revises/v1' }), {
    status: 'ok',
    type: 'attestation/revises/v1',
  });
});

test('#96: the copied ratified set holds sixteen distinct attestation sub-types', () => {
  assert.equal(RATIFIED_ATTESTATION_SUB_TYPES.length, 16);
  assert.equal(new Set(RATIFIED_ATTESTATION_SUB_TYPES).size, 16);
});

test('#96: every ratified type URI, and content/analysis/v1, reads check #12 ok', () => {
  const notOk = ['content/analysis/v1', ...RATIFIED_ATTESTATION_SUB_TYPES]
    .map((type) => ({ type, status: resolvePackageType({ type }).status }))
    .filter((r) => r.status !== 'ok');
  assert.deepEqual(notOk, [], 'every ratified type URI must resolve ok');
});

test('#96: a type outside the ratified set still reads unknown_type', () => {
  assert.ok((TYPE_RESOLUTION_STATUSES as readonly string[]).includes('unknown_type'));
  for (const type of ['attestation/revises/v2', 'attestation/revise/v1', 'content/revises/v1']) {
    assert.equal(resolvePackageType({ type }).status, 'unknown_type', type);
  }
});
