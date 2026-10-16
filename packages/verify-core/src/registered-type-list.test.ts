// The registered type list verify-core exports (sprint typedstandards#98, phase P1b):
// KNOWN_TYPE_URIS, the type URIs check #12 resolves `ok`, so a check outside this
// package can compare it with the specification's ratified list (#96; hub
// civic-ai-tools#230). Frozen: a consumer that reads it cannot change what check #12
// accepts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KNOWN_TYPE_URIS, resolvePackageType } from './index.ts';

// --- The registered type list (check #12) ---------------------------------------

test('KNOWN_TYPE_URIS is exported, frozen, and holds the two content sub-types plus sixteen attestation sub-types', () => {
  assert.ok(Array.isArray(KNOWN_TYPE_URIS));
  assert.ok(Object.isFrozen(KNOWN_TYPE_URIS), 'the registered list must be read-only at runtime');
  assert.throws(() => (KNOWN_TYPE_URIS as string[]).push('attestation/example/v1'), TypeError);
  assert.equal(KNOWN_TYPE_URIS.length, 18);
  assert.equal(new Set(KNOWN_TYPE_URIS).size, 18, 'no duplicates');
  assert.equal(KNOWN_TYPE_URIS[0], 'content/analysis/v1');
  assert.equal(KNOWN_TYPE_URIS[1], 'content/layout/v1');
  assert.deepEqual(
    KNOWN_TYPE_URIS.filter((t) => t.startsWith('content/')),
    ['content/analysis/v1', 'content/layout/v1'],
  );
  assert.equal(KNOWN_TYPE_URIS.filter((t) => t.startsWith('attestation/')).length, 16);
  assert.ok(KNOWN_TYPE_URIS.includes('attestation/revises/v1'));
});

// The sixteen attestation members keep the order of the spec §8.12.1 table,
// unchanged by the content/layout/v1 registration (hub ADR-0034, spec §8.14).
test('the attestation members of KNOWN_TYPE_URIS keep the §8.12.1 table order', () => {
  assert.deepEqual(
    KNOWN_TYPE_URIS.slice(2),
    [
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
    ],
  );
});

// Check #12 reads `ok` for a layout node (spec §8.14.5); before its
// registration it read `unknown_type`.
test('check #12 reads ok for content/layout/v1', () => {
  assert.deepEqual(resolvePackageType({ type: 'content/layout/v1' }), {
    status: 'ok',
    type: 'content/layout/v1',
  });
});

test('check #12 reads ok for every entry of KNOWN_TYPE_URIS', () => {
  const notOk = KNOWN_TYPE_URIS.map((type) => ({ type, r: resolvePackageType({ type }) })).filter(
    ({ type, r }) => r.status !== 'ok' || r.type !== type,
  );
  assert.deepEqual(notOk, []);
});

test('check #12 reads unknown_type for a URI outside KNOWN_TYPE_URIS', () => {
  for (const type of ['attestation/revises/v2', 'attestation/example/v1', 'content/other/v1']) {
    assert.ok(!KNOWN_TYPE_URIS.includes(type), type);
    assert.deepEqual(resolvePackageType({ type }), { status: 'unknown_type', type });
  }
});
