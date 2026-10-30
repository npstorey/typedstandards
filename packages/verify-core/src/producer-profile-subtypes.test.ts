// The subtype table (spec §8.1.1 and §8.6; hub ADR-0038 §3 and §5): its rows,
// the consistency predicate over it, and the civicaitools-v1 bundle pin, read
// against a committed local copy of the bundle and never the network.
//
// __fixtures__/civicaitools-v1-guidance-bundle.json is byte-identical to the
// hub's docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json at tree
// 7060f5e32b2a4e429c8b6df317153bc4fc7c57c6 (the merge commit b2bb304 that
// tag v0.1.13-typed-standards-spec names); its provenance is in
// __fixtures__/README.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  PRODUCER_PROFILE_SUBTYPES,
  PROFILE_CAPTURE_VOCAB,
  captureVocabForProfile,
  isContentProfileConsistent,
  sha256Hex,
} from './index.ts';

const BUNDLE_BYTES = readFileSync(new URL('./__fixtures__/civicaitools-v1-guidance-bundle.json', import.meta.url));
const ADR_0038_URL =
  'https://raw.githubusercontent.com/npstorey/civic-ai-tools/v0.1.13-typed-standards-spec/docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json';
const ADR_0038_SHA256 = '724e399e02db8993041b64982eec731505084bec2ec5e6ca58fda2de8087a281';

test('the table has exactly the two rows spec §8.6 states, in its order', () => {
  assert.deepEqual(Object.keys(PRODUCER_PROFILE_SUBTYPES), [
    'ai-assisted-analysis/datHere',
    'ai-assisted-analysis/civicaitools-v1',
  ]);
  assert.deepEqual(PRODUCER_PROFILE_SUBTYPES['ai-assisted-analysis/datHere'], { admits: ['datHere'] });
  assert.deepEqual(PRODUCER_PROFILE_SUBTYPES['ai-assisted-analysis/civicaitools-v1'], {
    admits: ['datHere', 'default'],
    bundle: { url: ADR_0038_URL, sha256: ADR_0038_SHA256 },
  });
});

test('the table cannot be changed by a caller', () => {
  assert.ok(Object.isFrozen(PRODUCER_PROFILE_SUBTYPES));
  for (const row of Object.values(PRODUCER_PROFILE_SUBTYPES)) {
    assert.ok(Object.isFrozen(row));
    assert.ok(Object.isFrozen(row.admits));
    if (row.bundle) assert.ok(Object.isFrozen(row.bundle));
  }
});

test('the civicaitools-v1 pin: the local copy hashes to the row, and the row to ADR-0038 §5', () => {
  const row = PRODUCER_PROFILE_SUBTYPES['ai-assisted-analysis/civicaitools-v1'];
  assert.equal(row.bundle?.url, ADR_0038_URL);
  assert.equal(row.bundle?.sha256, ADR_0038_SHA256);
  assert.equal(sha256Hex(new Uint8Array(BUNDLE_BYTES)), row.bundle?.sha256);
});

test('the civicaitools-v1 bundle names its subtype, its URL and the content profiles the row admits', () => {
  const bundle = JSON.parse(BUNDLE_BYTES.toString('utf8')) as {
    subtype: string;
    url: string;
    contentProfiles: { admits: string[] };
  };
  const row = PRODUCER_PROFILE_SUBTYPES['ai-assisted-analysis/civicaitools-v1'];
  assert.equal(bundle.subtype, 'ai-assisted-analysis/civicaitools-v1');
  assert.equal(bundle.url, row.bundle?.url);
  assert.deepEqual(bundle.contentProfiles.admits, [...row.admits]);
});

test('isContentProfileConsistent: a row admits exactly what it lists', () => {
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/datHere', 'datHere'), true);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/datHere', 'default'), false);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/civicaitools-v1', 'datHere'), true);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/civicaitools-v1', 'default'), true);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/civicaitools-v1', 'adopter-profile'), false);
});

test('isContentProfileConsistent: a subtype with no row reads by its prefix, as before', () => {
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/datHere-x', 'datHere'), true);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/datHere-x', 'default'), false);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/civicaitools-default', 'default'), true);
  assert.equal(isContentProfileConsistent('ai-assisted-analysis/civicaitools-default', 'datHere'), false);
  assert.equal(isContentProfileConsistent('scripted-recomputation/eval-run', 'default'), true);
  assert.equal(isContentProfileConsistent('scripted-recomputation/eval-run', 'datHere'), false);
  // Only the table's own keys are rows: an inherited property name is no row.
  assert.equal(isContentProfileConsistent('constructor', 'default'), true);
  assert.equal(isContentProfileConsistent('constructor', 'datHere'), false);
});

test('check #15 is unchanged: the profile-type table and the vocabulary lookup read as before', () => {
  assert.deepEqual(Object.keys(PROFILE_CAPTURE_VOCAB), ['ai-assisted-analysis', 'scripted-recomputation']);
  // The subtype row does not change the capture vocabulary (spec §8.6).
  assert.deepEqual(
    captureVocabForProfile('ai-assisted-analysis/civicaitools-v1', 'default'),
    PROFILE_CAPTURE_VOCAB['ai-assisted-analysis'],
  );
  assert.deepEqual(
    captureVocabForProfile('ai-assisted-analysis/civicaitools-v1', 'datHere'),
    captureVocabForProfile('ai-assisted-analysis/datHere', 'datHere'),
  );
});
