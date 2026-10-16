// A JSON text that repeats a member name within an object is not I-JSON (RFC 7493),
// and the CLI refuses it before any hash is computed (specification §8.2, §9.2
// check #1; typedstandards#145). `readJson` is the CLI's one JSON reader, so the
// refusal covers every file it reads: the record `verify` checks, and each producer
// input, whose values would otherwise be signed with one occurrence dropped.
//
// Fixture: verify-core's negative vector,
// `packages/verify-core/src/__fixtures__/repeated-member-name.bundle.json`
// (provenance in that directory's README.md): a signed bundle, minted for interop,
// with a second, earlier `summary` member in its package. `verify` reads it as it
// reads what `view` prints.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { SEED_VARIABLE, golden, memoryIo, newSeed } from './harness.test.ts';

const VECTOR_TEXT = readFileSync(
  new URL('../../verify-core/src/__fixtures__/repeated-member-name.bundle.json', import.meta.url),
  'utf8',
);

/** The refusal, as the CLI words it: the flag, the path, the member name and its pointer. */
const notIJson = (where: string, name: string, pointer: string): string =>
  `${where} is not I-JSON (RFC 7493): the member name "${name}" is repeated in the object at JSON Pointer "${pointer}"`;

test('PREMISE: the vector parses under JSON.parse, keeping the signed summary', () => {
  const bundle = JSON.parse(VECTOR_TEXT) as { package: { summary: string } };
  assert.match(bundle.package.summary, /^A four-row CSV /);
});

test('verify --input: a record whose text repeats a member name is refused, not reported altered', async () => {
  const io = memoryIo({ 'record.json': VECTOR_TEXT });
  const code = await run(['verify', '--input', 'record.json'], io);
  const err = io.err.join('');
  assert.equal(code, EXIT.usage, err);
  assert.equal(io.out.join(''), '', 'no verdict is printed');
  assert.ok(err.includes(notIJson('--input record.json', 'summary', '/package')), err);
  assert.doesNotMatch(err, /altered/);
});

test('sign --input: a producer input that repeats a member name is refused, and nothing is signed', async () => {
  const input = golden.envelopeCases.find((c) => c.name === 'v01-default')!.input;
  const text = `{"summary":"an earlier summary",${JSON.stringify({ ...input, summary: 'the later summary' }).slice(1)}`;
  const io = memoryIo({ 'input.json': text }, { [SEED_VARIABLE]: newSeed().b64 });
  const code = await run(['sign', '--input', 'input.json'], io);
  assert.equal(code, EXIT.usage, io.err.join(''));
  assert.equal(io.out.join(''), '');
  assert.ok(io.err.join('').includes(notIJson('--input input.json', 'summary', '')), io.err.join(''));
});
