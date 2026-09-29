// Acceptance 3 (typedstandards#125 G0 D5): the display seam.
//
// Fixture provenance: fixtures/core-satellite/display-policy.json, the generic part
// of the example's docs/host-policy.yaml at b40c30f written as JSON by hand, with
// each rule's roles under extensions.role; and fixtures/core-satellite/expected/
// records.json, the fixture's index v1.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { displayOf, parsePolicy, type HostIndex, type IndexRecord } from './index.ts';
import { EXPECTED, FIXTURE, readJson } from './harness.test.ts';

const policy = () => parsePolicy(readJson(join(FIXTURE, 'display-policy.json')));
const index = readJson(join(EXPECTED, 'records.json')) as HostIndex;
const core = index.records[0];

test('displayOf: the example\'s display list places all 52 fixture records', () => {
  const p = policy();
  const placed: Record<string, number> = {};
  for (const r of index.records) {
    const d = displayOf(r, p);
    placed[d.as] = (placed[d.as] ?? 0) + 1;
  }
  assert.deepEqual(placed, { current: 36, 'version 1': 1, withdrawn: 15 });
  assert.deepEqual(displayOf(core, p), { as: 'current', rule: 0 });
  assert.deepEqual(displayOf(index.records[1], p), { as: 'version 1', rule: 1 });
});

test('displayOf refuses a status outside verify-core\'s LIFECYCLE_STATUSES', () => {
  const revoked = { ...core, status: 'revoked' } as unknown as IndexRecord;
  assert.throws(() => displayOf(revoked, policy()), /status revoked is not one of verify-core's LIFECYCLE_STATUSES \(active, withdrawn, superseded\)/);
});

test('displayOf refuses a record no rule matches (unmatched: refuse)', () => {
  const p = policy();
  assert.throws(() => displayOf({ ...core, extensions: { ...core.extensions, role: 'appendix' } }, p), /no rule displays core .*unmatched: refuse/);
  assert.throws(() => displayOf({ ...core, extensions: undefined }, p), /no rule displays core/);
  assert.throws(() => displayOf({ ...core, signer: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }, p), /no rule displays core/);
  assert.throws(() => displayOf({ ...core, type: 'content/other/v1' }, p), /no rule displays core/);
});

test('displayOf displays superseded only when a rule names it', () => {
  const superseded: IndexRecord = { ...core, status: 'superseded', superseded: { at: '2026-09-25T00:00:00.000Z', successorNodeId: 'ab'.repeat(32) } };
  assert.throws(() => displayOf(superseded, policy()), /no rule displays core/);
  const named = parsePolicy({
    ...(readJson(join(FIXTURE, 'display-policy.json')) as object),
    display: [{ status: ['withdrawn', 'superseded'], extensions: { role: ['core'] }, as: 'past' }],
  });
  assert.deepEqual(displayOf(superseded, named), { as: 'past', rule: 0 });
  assert.throws(() => displayOf(core, named), /no rule displays core/);
});

test('parsePolicy refuses a rule with no status, an unknown status, and any unmatched but refuse', () => {
  const base = readJson(join(FIXTURE, 'display-policy.json')) as Record<string, unknown>;
  assert.throws(() => parsePolicy({ ...base, display: [{ as: 'all' }] }), /display\[0\]\.status is required/);
  assert.throws(() => parsePolicy({ ...base, display: [{ status: 'revoked', as: 'x' }] }), /display\[0\]\.status: revoked is not one of verify-core's LIFECYCLE_STATUSES/);
  assert.throws(() => parsePolicy({ ...base, unmatched: 'hide' }), /unmatched must be "refuse"/);
  assert.throws(() => parsePolicy({ ...base, map: { from: [] } }), /map: not a field/);
});
