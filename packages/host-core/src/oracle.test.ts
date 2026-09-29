// Acceptance 1 (typedstandards#125 G0 D4, as restated): the byte oracle.
//
// Fixture provenance: fixtures/core-satellite/, captured from the worked example's
// served docs/ at b40c30f (fixtures/core-satellite/README.md says how). The inputs
// are what the CLI's `sign` and `withdraw` print, taken from each served bundle: a
// signed document's `envelopeHash` is its bundle's `packageHash`. The expected
// outputs are the 52 served bundles and the served registry, byte for byte, and an
// index v1 reshaped from the example's records.json by the capture script, not by
// host-core.
//
// The load-bearing comparisons: each built bundle and the registry byte-equal the
// served copies, and every index field outside `extensions` equals the example's
// records.json, record by record. The `extensions` mapping (file, role, edgeId,
// step) is this fixture's choice, not the example's.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { buildHost } from './index.ts';
import { EXPECTED, FIXTURE, INPUT, loadDir, readJson, text } from './harness.test.ts';

type Rec = Record<string, unknown>;

const inputs = loadDir(INPUT);
const expected = loadDir(EXPECTED);
const manifest = readJson(join(INPUT, 'host.json')) as { records: Array<{ name: string; signed: string; attestations: string[] }> };
const exampleIndex = readJson(join(FIXTURE, 'example-records.json')) as { records: Rec[] };
const EXAMPLE_ONLY = ['file', 'role', 'edgeId', 'step'];

test('oracle premise: the fixture holds 52 records, 15 withdrawals and 52 served bundles', () => {
  assert.equal(manifest.records.length, 52);
  assert.equal(manifest.records.reduce((n, r) => n + r.attestations.length, 0), 15);
  assert.equal([...expected.keys()].filter((p) => p.startsWith('bundles/')).length, 52);
  assert.equal(exampleIndex.records.length, 52);
});

test('oracle premise: each signed input\'s envelopeHash is its served bundle\'s packageHash', () => {
  for (const r of manifest.records) {
    const signed = JSON.parse(text(inputs.get(r.signed))) as { envelopeHash: string };
    const bundle = JSON.parse(text(expected.get(`bundles/${r.name}.bundle.json`))) as { packageHash: string };
    assert.match(signed.envelopeHash, /^[0-9a-f]{64}$/, r.name);
    assert.equal(signed.envelopeHash, bundle.packageHash, `${r.name}: the input's envelopeHash is not the bundle's packageHash`);
  }
});

test('oracle: 52 of 52 built bundles byte-equal their served copies', () => {
  const built = buildHost(JSON.parse(text(inputs.get('host.json'))), inputs);
  const differ = manifest.records
    .map((r) => `bundles/${r.name}.bundle.json`)
    .filter((p) => built.files.get(p) === undefined || text(built.files.get(p)) !== text(expected.get(p)));
  assert.deepEqual(differ, [], `${52 - differ.length} of 52 bundles byte-equal their served copies`);
});

test('oracle: the built registry byte-equals the served typed-publisher.json', () => {
  const built = buildHost(JSON.parse(text(inputs.get('host.json'))), inputs);
  assert.equal(text(built.files.get('.well-known/typed-publisher.json')), text(expected.get('.well-known/typed-publisher.json')));
});

test('oracle: the built index equals the expected v1 file, byte for byte', () => {
  const built = buildHost(JSON.parse(text(inputs.get('host.json'))), inputs);
  assert.equal(text(built.files.get('records.json')), text(expected.get('records.json')));
});

test('oracle (load-bearing): every index field outside extensions equals the example\'s records.json, record by record', () => {
  const built = buildHost(JSON.parse(text(inputs.get('host.json'))), inputs);
  assert.equal(built.index.records.length, exampleIndex.records.length, 'record count');
  built.index.records.forEach((r, i) => {
    const { extensions: _ours, ...generic } = r as unknown as Rec;
    const theirs = Object.fromEntries(Object.entries(exampleIndex.records[i]).filter(([k]) => !EXAMPLE_ONLY.includes(k)));
    assert.deepEqual(generic, theirs, `record ${i} (${String(exampleIndex.records[i]['name'])})`);
  });
  assert.equal(built.index.host, 'https://core-satellite.typedstandards.org/');
  assert.equal(built.index.trustRegistryUrl, 'https://core-satellite.typedstandards.org/.well-known/typed-publisher.json');
});

test('oracle: the build serves exactly the 52 bundles, the registry and the index', () => {
  const built = buildHost(JSON.parse(text(inputs.get('host.json'))), inputs);
  assert.deepEqual([...built.files.keys()].sort(), [...expected.keys()].sort());
});
