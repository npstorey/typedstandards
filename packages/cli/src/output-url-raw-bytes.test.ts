// `sign --output-file <path> --output-url <url>` under raw-bytes/v1
// (typedstandards#113, G0 D8): a file signed by reference may name raw-bytes/v1,
// or leave the rule unnamed on a v0.1 input and have it default to raw-bytes/v1,
// as the file signed inline does. The BlobRef's `ref` is the file's SHA-256, and
// `contentHash.sha256` is its hex (spec §8.2). `verify --blob` with the file
// passes; with other bytes it exits 1. Replaces the 0.1.0 refusal of raw-bytes/v1
// by reference (G0 D13 (4)).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EXIT } from './errors.ts';
import { SEED_VARIABLE, cli, fileInput, golden, newSeed, scratch } from './harness.test.ts';

const RAW_BYTES = 'https://typedstandards.org/canonicalization/raw-bytes/v1';
const LEGACY_JSON = 'https://typedstandards.org/canonicalization/legacy-json/v1';
const OUTPUT_URL = 'https://files.example.com/analysis.bin';
// Bytes that are not UTF-8, so they could only ever be signed by reference.
const BYTES = new Uint8Array([0x00, 0xff, 0xfe, 0x10, 0x80, 0x41, 0x0a]);
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

for (const [label, extra] of [
  ['raw-bytes/v1 named', { contentCanonicalization: RAW_BYTES }],
  ['no rule named, so raw-bytes/v1 by default', {}],
] as const) {
  test(`sign --output-file --output-url, ${label}: signs, verify --blob passes with the file and exits 1 with other bytes`, () => {
    const dir = scratch();
    try {
      const s = cli(
        ['sign', '--input', dir.write('input.json', JSON.stringify(fileInput(extra))), '--output-file', dir.write('file.bin', BYTES), '--output-url', OUTPUT_URL],
        { env: { [SEED_VARIABLE]: newSeed().b64 } },
      );
      assert.equal(s.code, EXIT.ok, s.err);
      const pkg = (s.json() as { package: Record<string, unknown> }).package;
      assert.equal(pkg['contentCanonicalization'], RAW_BYTES);
      assert.deepEqual(pkg['output'], { ref: `blob:sha256:${sha256(BYTES)}`, url: OUTPUT_URL, contentType: 'application/octet-stream', size: BYTES.length });
      assert.equal((pkg['contentHash'] as { sha256: string }).sha256, sha256(BYTES));
      const signed = dir.write('signed.json', s.out);

      const good = cli(['verify', '--input', signed, '--blob', dir.write('same.bin', BYTES), '--json']);
      assert.equal(good.code, EXIT.ok, good.err);
      const checks = good.json()['checks'] as { contentHash: { status: string }; blobRefs: Array<{ ok: boolean }> };
      assert.equal(checks.contentHash.status, 'ok');
      assert.deepEqual(checks.blobRefs.map((b) => b.ok), [true]);

      const other = BYTES.slice();
      other[0] = 0x01;
      const bad = cli(['verify', '--input', signed, '--blob', dir.write('other.bin', other)]);
      assert.equal(bad.code, EXIT.verificationFailed, bad.err);
      const failures = bad.json()['failures'] as Array<{ check: string; status: string }>;
      assert.ok(failures.some((f) => f.check === '#9' && f.status === 'hash_mismatch'), JSON.stringify(failures));
    } finally {
      dir.cleanup();
    }
  });
}

test('sign --output-file --output-url: an input naming another rule keeps it, and a legacy input stays on the legacy chain', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const named = cli(
      ['sign', '--input', dir.write('a.json', JSON.stringify(fileInput({ contentCanonicalization: LEGACY_JSON }))), '--output-file', dir.write('f.bin', BYTES), '--output-url', OUTPUT_URL],
      { env },
    );
    assert.equal(named.code, EXIT.ok, named.err);
    assert.equal((named.json() as { package: Record<string, unknown> }).package['contentCanonicalization'], LEGACY_JSON);

    const { output: _output, ...legacy } = golden.envelopeCases.find((c) => c.name === 'legacy-inline')!.input;
    const l = cli(['sign', '--input', dir.write('l.json', JSON.stringify(legacy)), '--output-file', dir.write('g.bin', BYTES), '--output-url', OUTPUT_URL], { env });
    assert.equal(l.code, EXIT.ok, l.err);
    const pkg = (l.json() as { package: Record<string, unknown> }).package;
    assert.ok(!('contentCanonicalization' in pkg), 'a legacy package carries no rule');
    assert.ok(!('contentHash' in pkg), 'a legacy package carries no contentHash');
  } finally {
    dir.cleanup();
  }
});
