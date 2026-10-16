// The negative vector of typedstandards#145: a signed bundle whose package's text
// repeats one member name (specification §8.2, §9.2 check #1; hub ADR-0035).
//
// Fixture: `__fixtures__/repeated-member-name.bundle.json` is
// `apps/web/src/lib/__fixtures__/q15-self-certified.json` with one line inserted
// before its line 66: a second, earlier `summary` member in the package. Its
// provenance is in `__fixtures__/README.md`. The byte-equal checks are load-bearing:
// the vector is the source plus that one line, and `JSON.parse` of it gives the
// source's value, so its package gives the source's envelope hash and content hash.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  computeContentHashSha256,
  computeEnvelopeHash,
  parseStrictJson,
  RepeatedMemberNameError,
  sha256Hex,
} from './index.ts';

const read = (url: URL): Uint8Array => new Uint8Array(readFileSync(url));

const SOURCE_BYTES = read(new URL('../../../apps/web/src/lib/__fixtures__/q15-self-certified.json', import.meta.url));
const VECTOR_BYTES = read(new URL('./__fixtures__/repeated-member-name.bundle.json', import.meta.url));
const SOURCE_TEXT = new TextDecoder().decode(SOURCE_BYTES);
const VECTOR_TEXT = new TextDecoder().decode(VECTOR_BYTES);

/** `shasum -a 256` of the vector as committed. */
const VECTOR_FILE_SHA256 = '71a77c4c3201a207c27998a7cd149bf0f2c01cae4a0b984aadb56dba100b8457';
/** The source's `packageHash`: the envelope hash its signature covers. */
const SOURCE_ENVELOPE_HASH = '9a53cd8ee701f2361cdcf353604bbcde43679f9a55c7cd3759db64d2b7e31dde';

type Bundle = { packageHash: string; package: Record<string, unknown> & { contentHash: { sha256: string } } };

test('vector: the file is pinned', () => {
  assert.equal(sha256Hex(VECTOR_BYTES), VECTOR_FILE_SHA256);
});

test('vector: it is the source with one line inserted before line 66, a second summary member', () => {
  const source = SOURCE_TEXT.split('\n');
  const vector = VECTOR_TEXT.split('\n');
  assert.equal(vector.length, source.length + 1);
  assert.deepEqual([...vector.slice(0, 65), ...vector.slice(66)], source);
  assert.match(vector[65]!, /^ {4}"summary": "/);
  assert.match(source[65]!, /^ {4}"summary": "/);
  assert.notEqual(vector[65], source[65]);
});

test('vector: JSON.parse keeps the last summary, so the package keeps both of the source\'s hashes', () => {
  const source = JSON.parse(SOURCE_TEXT) as Bundle;
  const vector = JSON.parse(VECTOR_TEXT) as Bundle;
  assert.deepEqual(vector, source);
  assert.equal(source.packageHash, SOURCE_ENVELOPE_HASH);
  assert.equal(computeEnvelopeHash(vector.package), SOURCE_ENVELOPE_HASH);
  assert.equal(computeEnvelopeHash(vector.package), computeEnvelopeHash(source.package));
  const rule = vector.package['contentCanonicalization'] as string;
  assert.equal(computeContentHashSha256(vector.package, rule), computeContentHashSha256(source.package, rule));
  assert.equal(computeContentHashSha256(vector.package, rule), source.package.contentHash.sha256);
});

test('vector: parseStrictJson refuses it, naming summary in the package object', () => {
  for (const input of [VECTOR_BYTES, VECTOR_TEXT]) {
    assert.throws(
      () => parseStrictJson(input),
      (err: unknown) =>
        err instanceof RepeatedMemberNameError &&
        err.name === 'RepeatedMemberNameError' &&
        err.memberName === 'summary' &&
        err.pointer === '/package' &&
        err.message === 'JSON text is not I-JSON (RFC 7493): the member name "summary" is repeated in the object at JSON Pointer "/package"',
    );
  }
});

test('vector: its source parses strictly, to what JSON.parse gives', () => {
  assert.deepEqual(parseStrictJson(SOURCE_BYTES), JSON.parse(SOURCE_TEXT));
});
