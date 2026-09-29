// Acceptance 2 (typedstandards#125 G0 D4, D7 + D10): `verify` on the fixture's
// served directory prints one line per record and the totals, 52 ok, 37 active,
// 15 withdrawn and no fetch, exits 0, and prints exactly the committed golden.
//
// Fixture provenance: fixtures/core-satellite/expected/ (the example's served
// bundles and registry at b40c30f, byte for byte, and the expected index v1), and
// fixtures/core-satellite/verify-output.txt, written from expected/records.json's
// names and statuses in the specified format, before verify was implemented.
//
// The golden names no Node and no core version (the D7 + D10 constraint): CI's
// node-version floats, so a golden that named one would break on the next patch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyRecord } from '@typedstandards/verify-core';
import { verifyServed } from './index.ts';
import { EXPECTED, FIXTURE, host, loadDir, text } from './harness.test.ts';

const GOLDEN = readFileSync(join(FIXTURE, 'verify-output.txt'), 'utf8');

/**
 * Flip the low bit of one byte of `core`'s signed output, in a copy of the served
 * files: the first ASCII letter of the output string that is not part of an escape,
 * so the bundle stays JSON and only the signed bytes change.
 */
function withFlippedSignedByte(served: Map<string, Uint8Array>): Map<string, Uint8Array> {
  const path = 'bundles/core.bundle.json';
  const bytes = Buffer.from(served.get(path)!);
  let at = bytes.indexOf('"output": "') + '"output": "'.length;
  const letter = (b: number): boolean => (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
  while (!letter(bytes[at]) || bytes[at - 1] === 0x5c) at += 1;
  bytes[at] ^= 0x01;
  return new Map([...served, [path, new Uint8Array(bytes)]]);
}

test('verify (bin): the fixture prints the committed golden and exits 0', () => {
  const r = host(['verify', '--out', EXPECTED]);
  assert.equal(r.err, '');
  assert.equal(r.out, GOLDEN);
  assert.equal(r.code, 0);
});

test('verify: 52 ok, 37 active, 15 withdrawn, and no global or injected fetch', async () => {
  const report = await verifyServed(loadDir(EXPECTED));
  assert.deepEqual(report.totals, { records: 52, ok: 52, failed: 0, active: 37, withdrawn: 15, superseded: 0 });
  assert.deepEqual(report.fetch, { global: 0, injected: 0 });
  assert.equal(report.ok, true);
});

test('verify: the golden\'s first line names no Node or core version', () => {
  const first = GOLDEN.split('\n')[0];
  assert.doesNotMatch(first, /\d+\.\d+\.\d+/);
  assert.doesNotMatch(GOLDEN, /\bnode \d/);
});

test('verify: one flipped byte of a signed output fails that record and the run', async () => {
  const report = await verifyServed(withFlippedSignedByte(loadDir(EXPECTED)));
  assert.equal(report.ok, false);
  const line = report.lines.find((l) => l.endsWith(' core') || l.includes(' core: '));
  assert.ok(line, `no line for core in:\n${report.lines.join('\n')}`);
  assert.match(line, /^ {2}FAIL {2}active {5}core: .*#1 envelopeIntegrity altered/);
  assert.equal(report.totals.failed, 1);
  assert.equal(report.lines.at(-1), 'result: FAILED (records)');
});

test('verify (bin): one flipped byte of a signed output exits non-zero with a failing line', () => {
  const dir = mkdtempSync(join(tmpdir(), 'host-core-verify-'));
  try {
    cpSync(EXPECTED, dir, { recursive: true });
    const flipped = withFlippedSignedByte(loadDir(dir));
    writeFileSync(join(dir, 'bundles', 'core.bundle.json'), flipped.get('bundles/core.bundle.json')!);
    const r = host(['verify', '--out', dir]);
    assert.equal(r.code, 1);
    assert.match(r.out, /^ {2}FAIL {2}active {5}core: /m);
    assert.match(r.out, /\nresult: FAILED \(records\)\n$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify: a fetch through the injected fetcher is counted and fails the run', async () => {
  const report = await verifyServed(loadDir(EXPECTED), {
    verifyRecord: async (input, deps) => {
      await deps.fetch?.('https://example.invalid/counted').catch(() => undefined);
      return verifyRecord(input, deps);
    },
  });
  assert.equal(report.fetch.injected, 52);
  assert.equal(report.ok, false);
  assert.equal(report.lines.at(-2), 'network: global fetch calls 0; injected fetch calls 52');
  assert.equal(report.lines.at(-1), 'result: FAILED (network)');
});

test('verify: a global fetch is counted and fails the run, and the global fetch is restored', async () => {
  const before = globalThis.fetch;
  const report = await verifyServed(loadDir(EXPECTED), {
    verifyRecord: async (input, deps) => {
      await globalThis.fetch('https://example.invalid/counted').catch(() => undefined);
      return verifyRecord(input, deps);
    },
  });
  assert.equal(report.fetch.global, 52);
  assert.equal(report.ok, false);
  assert.equal(report.lines.at(-1), 'result: FAILED (network)');
  assert.equal(globalThis.fetch, before);
});

test('verify: an altered carried attestation fails its record', async () => {
  const served = loadDir(EXPECTED);
  const path = 'bundles/map/header.bundle.json';
  const altered = text(served.get(path)).replace('"reason": "Restated', '"reason": "Rewritten');
  const report = await verifyServed(new Map([...served, [path, new TextEncoder().encode(altered)]]));
  assert.equal(report.ok, false);
  const line = report.lines.find((l) => l.includes(' map/header'));
  assert.match(line ?? '', /^ {2}FAIL {2}active {5}map\/header: /);
});
