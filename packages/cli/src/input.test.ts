// The input rules of G0 D3 (typedstandards#109): a key produce-core would drop is
// refused, not signed around; vcsRef is answered by name; a file is signed inline
// only as exact UTF-8.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildEnvelope, type EnvelopeInput } from '@typedstandards/produce-core';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { SEED_VARIABLE, fileInput, golden, memoryIo, newSeed } from './harness.test.ts';

const base = golden.envelopeCases.find((c) => c.name === 'v01-default')!.input;

async function sign(input: unknown, files: Record<string, string | Uint8Array> = {}, flags: string[] = []) {
  const io = memoryIo({ 'input.json': JSON.stringify(input), ...files }, { [SEED_VARIABLE]: newSeed().b64 });
  const code = await run(['sign', '--input', 'input.json', ...flags], io);
  return { code, out: io.out.join(''), err: io.err.join('') };
}

test('PREMISE: produce-core drops an unknown key from what it signs, with no error', () => {
  const { pkg } = buildEnvelope({ ...base, vcsRef: { commitSha: 'abc' } } as unknown as EnvelopeInput);
  assert.ok(!('vcsRef' in pkg));
  const { pkg: q } = buildEnvelope({ ...base, queries: [{ ...(base['queries'] as object[])[0], extra: 1 }] } as unknown as EnvelopeInput);
  assert.ok(!('extra' in (q.queries[0] as object)));
});

test('an unknown key exits 2 naming it: at the top level and in queries[], cost and skillMetadata', async () => {
  const queries = base['queries'] as Array<Record<string, unknown>>;
  const cases: Array<[unknown, RegExp]> = [
    [{ ...base, notAField: 1 }, /^typedstandards sign: notAField is not a field of the envelope input/],
    [{ ...base, queries: [{ ...queries[0], extra: 1 }] }, /queries\[0\]\.extra is not a field of a query/],
    [{ ...base, cost: { ...(base['cost'] as object), currency: 'USD' } }, /cost\.currency is not a field of cost/],
    [{ ...base, skillMetadata: { ...(base['skillMetadata'] as object), version: '1' } }, /skillMetadata\.version is not a field of skillMetadata/],
  ];
  for (const [input, message] of cases) {
    const r = await sign(input);
    assert.equal(r.code, EXIT.usage, r.err);
    assert.equal(r.out, '');
    assert.match(r.err, message);
  }
});

test('vcsRef exits 2 with its own message, pointing at the core minor', async () => {
  const r = await sign({ ...base, vcsRef: { repoUrl: 'https://git.example/r', commitSha: 'abc' } });
  assert.equal(r.code, EXIT.usage);
  assert.match(r.err, /vcsRef is not supported yet: produce-core 0\.7\.0 has no vcsRef field/);
  assert.match(r.err, /do not carry it in extensions/);
});

test('extensions stay opaque: whatever they hold is signed as given', async () => {
  const r = await sign({ ...base, extensions: { 'org.example.tool': { anything: [1, { vcsRef: 'not inspected' }] } } });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual((JSON.parse(r.out).package as Record<string, unknown>)['extensions'], { 'org.example.tool': { anything: [1, { vcsRef: 'not inspected' }] } });
});

test('a wrong kind, null included, and a missing required field exit 2', async () => {
  const { prompt: _prompt, ...noPrompt } = base;
  const cases: Array<[unknown, RegExp]> = [
    [{ ...base, type: null }, /type must be a string/],
    [{ ...base, summary: 3 }, /summary must be a string/],
    [{ ...base, queries: {} }, /queries must be an array/],
    [{ ...base, promptVisibility: 'partial' }, /promptVisibility must be "full_text" or "hash_only"/],
    [noPrompt, /prompt is required/],
    [{ ...base, signingKeyId: '' }, /signingKeyId must not be empty/],
    [[], /the input must be a JSON object/],
  ];
  for (const [input, message] of cases) {
    const r = await sign(input);
    assert.equal(r.code, EXIT.usage, `${String(message)}: ${r.err}`);
    assert.match(r.err, message);
  }
});

test('--output-file: exact UTF-8 inline under raw-bytes/v1, a byte-order mark kept; the file\'s SHA-256 is the content hash', async () => {
  const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('a byte-order mark, then text\n', 'utf8')]);
  const r = await sign(fileInput(), { 'f.txt': new Uint8Array(bytes) }, ['--output-file', 'f.txt']);
  assert.equal(r.code, 0, r.err);
  const pkg = JSON.parse(r.out).package as Record<string, unknown>;
  assert.equal(pkg['contentCanonicalization'], 'https://typedstandards.org/canonicalization/raw-bytes/v1');
  assert.equal((pkg['contentHash'] as { sha256: string }).sha256, createHash('sha256').update(bytes).digest('hex'));
});

test('--output-file refuses: bytes that are not UTF-8, an input with no type, another rule, raw-bytes/v1 by reference, an output already given', async () => {
  const cases: Array<[unknown, Record<string, string | Uint8Array>, string[], RegExp]> = [
    [fileInput(), { 'f.bin': new Uint8Array([0xff, 0xfe, 0x00]) }, ['--output-file', 'f.bin'], /is not UTF-8 text, so it cannot be signed inline/],
    [{ ...fileInput(), type: undefined }, { 'f.txt': 'x' }, ['--output-file', 'f.txt'], /needs a v0\.1 envelope, and the input has no type/],
    [fileInput({ contentCanonicalization: 'https://typedstandards.org/canonicalization/legacy-json/v1' }), { 'f.txt': 'x' }, ['--output-file', 'f.txt'], /and the input names .*legacy-json/],
    [fileInput({ output: 'inline' }), { 'f.txt': 'x' }, ['--output-file', 'f.txt'], /the input has an output and --output-file supplies another/],
    [fileInput({ contentCanonicalization: 'https://typedstandards.org/canonicalization/raw-bytes/v1' }), { 'f.txt': 'x' }, ['--output-file', 'f.txt', '--output-url', 'https://x.example/f'], /by reference with --output-url cannot use .*raw-bytes\/v1/],
    [fileInput(), {}, ['--output-url', 'https://x.example/f'], /give --output-file too/],
    [fileInput(), { 'f.txt': 'x' }, ['--output-file', 'f.txt', '--content-type', 'text/plain'], /give --output-url too/],
  ];
  for (const [input, files, flags, message] of cases) {
    const r = await sign(JSON.parse(JSON.stringify(input)), files, flags);
    assert.equal(r.code, EXIT.usage, `${String(message)}: ${r.err}`);
    assert.match(r.err, message);
  }
});

test('usage: no command, an unknown command and an unknown flag exit 2; --help and --version exit 0 on stdout', async () => {
  for (const argv of [[], ['attest'], ['verify', '--input', 'x', '--strict']]) {
    const io = memoryIo();
    assert.equal(await run(argv, io), EXIT.usage, argv.join(' '));
    assert.deepEqual(io.out, []);
  }
  const help = memoryIo();
  assert.equal(await run(['--help'], help), EXIT.ok);
  assert.match(help.out.join(''), /Usage: typedstandards <command>/);
  const version = memoryIo();
  assert.equal(await run(['--version'], version), EXIT.ok);
  assert.deepEqual(JSON.parse(version.out.join('')), { name: '@typedstandards/cli', version: '0.0.0-test' });
});

test('verify refuses input that sign and view do not print', async () => {
  const cases: Array<[unknown, RegExp]> = [
    [{ package: {}, envelopeHash: 'a'.repeat(64), signature: { signature: 's', publicKey: 'k' }, extra: 1 }, /extra: not part of/],
    [{ packageHash: 'a'.repeat(64), signature: { signature: 's', publicKey: 'k' }, package: {}, rfc3161Timestamp: 't' }, /rfc3161Timestamp: verify reads what sign and view print/],
    [{ packageHash: 'a'.repeat(64), signature: { signature: 's', publicKey: 'k' } }, /carries no package/],
    [{ something: 1 }, /must be what sign prints/],
  ];
  for (const [input, message] of cases) {
    const io = memoryIo({ 'in.json': JSON.stringify(input) });
    assert.equal(await run(['verify', '--input', 'in.json'], io), EXIT.usage, io.err.join(''));
    assert.match(io.err.join(''), message);
  }
});
