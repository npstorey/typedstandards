// A JSON text that repeats a member name within an object is not I-JSON (RFC 7493),
// and host-core refuses it before any hash is computed (specification §8.2, §9.2
// check #1; typedstandards#145). `parseJsonFile` is host-core's one JSON reader, so
// the refusal covers each served bundle `verify` reads and each input `build` reads.
//
// Fixtures:
// - verify-core's negative vector,
//   `packages/verify-core/src/__fixtures__/repeated-member-name.bundle.json`
//   (provenance in that directory's README.md), a signed bundle with a second,
//   earlier `summary` member in its package, served in place of `core`'s bundle;
// - fixtures/core-satellite/, with one line inserted in a copy of `core`'s served
//   bundle and of its signed input: a second, earlier `summary` member in the
//   package. `JSON.parse` keeps the later, signed one, so the record verifies under it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HostError, buildHost, verifyServed } from './index.ts';
import { EXPECTED, INPUT, loadDir, readJson, text } from './harness.test.ts';

const VECTOR_TEXT = readFileSync(
  new URL('../../verify-core/src/__fixtures__/repeated-member-name.bundle.json', import.meta.url),
  'utf8',
);

const CORE_BUNDLE = 'bundles/core.bundle.json';
const encode = (s: string): Uint8Array => new TextEncoder().encode(s);

/** The refusal, as host-core words it: the file, the member name and its pointer. */
const notIJson = (where: string, name: string, pointer: string): string =>
  `${where} is not I-JSON (RFC 7493): the member name "${name}" is repeated in the object at JSON Pointer "${pointer}"`;

/** `source` with `line` inserted before its first line that opens with `"summary": ` at four spaces (the package's). */
function withEarlierSummary(source: string, line: string): string {
  const at = source.indexOf('\n    "summary": ');
  assert.ok(at > 0, 'the package carries a summary');
  return `${source.slice(0, at + 1)}${line}\n${source.slice(at + 1)}`;
}

const coreLine = (lines: readonly string[]): string => lines.find((l) => / core(: |$)/.test(l)) ?? '<no line for core>';

test('verify: the negative vector served as a bundle fails that record with the refusal', async () => {
  const served = loadDir(EXPECTED);
  const report = await verifyServed(new Map([...served, [CORE_BUNDLE, encode(VECTOR_TEXT)]]));
  assert.equal(report.ok, false);
  assert.equal(report.totals.failed, 1);
  const line = coreLine(report.lines);
  assert.equal(line, `  FAIL  active     core: ${notIJson(CORE_BUNDLE, 'summary', '/package')}`);
  assert.doesNotMatch(line, /altered/);
});

test('verify: a served bundle whose package repeats a member name fails that record, though it would verify', async () => {
  const served = loadDir(EXPECTED);
  const repeated = withEarlierSummary(text(served.get(CORE_BUNDLE)), '    "summary": "An earlier summary member, not the signed one.",');
  const report = await verifyServed(new Map([...served, [CORE_BUNDLE, encode(repeated)]]));
  assert.equal(report.ok, false);
  assert.equal(report.totals.failed, 1);
  assert.equal(coreLine(report.lines), `  FAIL  active     core: ${notIJson(CORE_BUNDLE, 'summary', '/package')}`);
});

test('build: a signed input whose text repeats a member name is refused', () => {
  const inputs = loadDir(INPUT);
  const path = 'signed/core.signed.json';
  const repeated = withEarlierSummary(text(inputs.get(path)), '    "summary": "An earlier summary member, not the signed one.",');
  const manifest = readJson(join(INPUT, 'host.json'));
  assert.throws(
    () => buildHost(manifest, new Map([...inputs, [path, encode(repeated)]])),
    (err: unknown) => err instanceof HostError && err.message === notIJson(`record core: ${path}`, 'summary', '/package'),
  );
});
