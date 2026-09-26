// Acceptance 2 (typedstandards#109): with a seed generated in the test, `sign`
// then `verify` passes; a one-byte change to the signed file, or another key,
// makes `verify` exit non-zero; and `sign` exits non-zero with nothing on stdout
// when its own offline verification fails.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signEnvelopeHash } from '@typedstandards/produce-core';
import { verifyRecord } from '@typedstandards/verify-core';
import { run } from './run.ts';
import { SEED_VARIABLE, cli, fileInput, memoryIo, newSeed, scratch } from './harness.test.ts';

const FILE = 'A signed file.\nIts second line.\n';

function signFile(dir: ReturnType<typeof scratch>, seed: string, extra: string[] = []) {
  const r = cli(
    ['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE), ...extra],
    { env: { [SEED_VARIABLE]: seed } },
  );
  assert.equal(r.code, 0, `sign exited ${r.code}: ${r.err}`);
  return r.json() as { package: Record<string, unknown>; envelopeHash: string; signature: Record<string, string> };
}

test('sign then verify passes (inline, raw-bytes/v1)', () => {
  const dir = scratch();
  try {
    const signed = signFile(dir, newSeed().b64);
    assert.equal(signed.package['output'], FILE);
    const r = cli(['verify', '--input', dir.write('signed.json', JSON.stringify(signed))]);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json(), { ok: true, nodeId: signed.envelopeHash, failures: [] });
  } finally {
    dir.cleanup();
  }
});

test('a one-byte change to the signed file makes verify exit 1 (inline: #1 altered)', () => {
  const dir = scratch();
  try {
    const signed = signFile(dir, newSeed().b64);
    signed.package['output'] = FILE.replace('A signed', 'A signef');
    const r = cli(['verify', '--input', dir.write('signed.json', JSON.stringify(signed))]);
    assert.equal(r.code, 1);
    const failures = r.json()['failures'] as Array<{ check: string; status: string }>;
    assert.ok(failures.some((f) => f.check === '#1' && f.status === 'altered'), JSON.stringify(failures));
  } finally {
    dir.cleanup();
  }
});

test('by reference: sign then verify --blob passes; a one-byte change to the file makes verify exit 1 (#9)', () => {
  const dir = scratch();
  try {
    const signed = signFile(dir, newSeed().b64, ['--output-url', 'https://files.example/file.txt', '--content-type', 'text/plain']);
    const ref = signed.package['output'] as { ref: string; size: number; contentType: string };
    assert.equal(ref.size, Buffer.byteLength(FILE));
    assert.equal(ref.contentType, 'text/plain');
    const input = dir.write('signed.json', JSON.stringify(signed));

    const good = cli(['verify', '--input', input, '--blob', dir.write('same.txt', FILE)]);
    assert.equal(good.code, 0, good.err);

    const changed = cli(['verify', '--input', input, '--blob', dir.write('changed.txt', FILE.replace('second', 'secone'))]);
    assert.equal(changed.code, 1);
    const failures = changed.json()['failures'] as Array<{ check: string; status: string }>;
    assert.ok(failures.some((f) => f.check === '#9' && f.status === 'hash_mismatch'), JSON.stringify(failures));
  } finally {
    dir.cleanup();
  }
});

test('another key makes verify exit 1: its signature under the record\'s key (#2), or its own key (#14)', () => {
  const dir = scratch();
  try {
    const signed = signFile(dir, newSeed().b64);
    const other = signEnvelopeHash(signed.envelopeHash, newSeed().bytes, signed.signature['kid']);

    const wrongSignature = { ...signed, signature: { ...signed.signature, signature: other.signature } };
    const r1 = cli(['verify', '--input', dir.write('a.json', JSON.stringify(wrongSignature))]);
    assert.equal(r1.code, 1);
    assert.ok((r1.json()['failures'] as Array<{ check: string }>).some((f) => f.check === '#2'), r1.out);

    const otherKey = { ...signed, signature: { ...other } };
    const r2 = cli(['verify', '--input', dir.write('b.json', JSON.stringify(otherKey))]);
    assert.equal(r2.code, 1);
    const failures = r2.json()['failures'] as Array<{ check: string; status: string }>;
    assert.ok(failures.some((f) => f.check === '#14' && f.status === 'key_derived_mismatch'), JSON.stringify(failures));
  } finally {
    dir.cleanup();
  }
});

test('sign exits 1 with nothing on stdout when its own offline verification fails (stubbed verifier)', async () => {
  const io = memoryIo(
    { 'input.json': JSON.stringify(fileInput()), 'file.txt': FILE },
    { [SEED_VARIABLE]: newSeed().b64 },
    { verifyRecord: async (input, deps) => ({ ...(await verifyRecord(input, deps)), signatureValid: false }) },
  );
  const code = await run(['sign', '--input', 'input.json', '--output-file', 'file.txt'], io);
  assert.equal(code, 1);
  assert.deepEqual(io.out, []);
  assert.match(io.err.join(''), /did not verify offline, so nothing was printed/);
});

test('sign exits 1 with nothing on stdout when a signer names another key (a real failing check, #14)', () => {
  const dir = scratch();
  try {
    const signer = { bindingTier: 'pseudonymous', displayName: 'Example signer', identifier: 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' };
    const r = cli(
      ['sign', '--input', dir.write('input.json', JSON.stringify(fileInput({ signer }))), '--output-file', dir.write('file.txt', FILE)],
      { env: { [SEED_VARIABLE]: newSeed().b64 } },
    );
    assert.equal(r.code, 1);
    assert.equal(r.stdout.length, 0);
    assert.match(r.err, /#14 signerIdentity: key_derived_mismatch \(alarm\)/);
  } finally {
    dir.cleanup();
  }
});

test('the filled fields: signingKeyId, the kid and signer.identifier are one did:key, and omitted ids are generated', async () => {
  const io = memoryIo({ 'input.json': JSON.stringify(fileInput()), 'file.txt': FILE }, { [SEED_VARIABLE]: newSeed().b64 });
  assert.equal(await run(['sign', '--input', 'input.json', '--output-file', 'file.txt'], io), 0, io.err.join(''));
  const printed = JSON.parse(io.out.join('')) as { package: { metadata: Record<string, string>; signer: Record<string, string> }; signature: Record<string, string> };
  const id = printed.package.signer['identifier'];
  assert.match(id, /^did:key:z/);
  assert.equal(printed.package.metadata['signingKeyId'], id);
  assert.equal(printed.signature['kid'], id);
  assert.equal(printed.package.metadata['packageId'], '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d');
  assert.equal(printed.package.metadata['createdAt'], '2026-09-26T12:00:00.000Z');
});

test('the same input, ids and seed reproduce the output byte for byte', () => {
  const dir = scratch();
  try {
    const seed = newSeed().b64;
    const input = dir.write('input.json', JSON.stringify(fileInput({ packageId: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', createdAt: '2026-09-26T00:00:00.000Z' })));
    const file = dir.write('file.txt', FILE);
    const a = cli(['sign', '--input', input, '--output-file', file], { env: { [SEED_VARIABLE]: seed } });
    const b = cli(['sign', '--input', input, '--output-file', file], { env: { [SEED_VARIABLE]: seed } });
    assert.equal(a.code, 0, a.err);
    assert.equal(a.out, b.out);
  } finally {
    dir.cleanup();
  }
});
