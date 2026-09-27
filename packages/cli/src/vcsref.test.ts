// `vcsRef` in `sign` (typedstandards#113, G0 D7): signed verbatim on a v0.1 input,
// with its shape checked by the CLI: `repoUrl` and `commitSha` required, non-empty
// strings; `path` and `ref` optional strings; no other key. A `vcsRef` on an input
// with no `type` (the legacy chain) exits 2 naming the v0.1-only rule. Replaces
// the 0.1.0 refusal of `vcsRef` by name (G0 D13 (3)).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildEnvelope, type EnvelopeInput } from '@typedstandards/produce-core';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { SEED_VARIABLE, golden, memoryIo, newSeed } from './harness.test.ts';

const V01 = golden.envelopeCases.find((c) => c.name === 'v01-default')!.input;
const LEGACY = golden.envelopeCases.find((c) => c.name === 'legacy-inline')!.input;

const VCS_REF = {
  repoUrl: 'https://git.example.com/example/analysis',
  commitSha: '0123456789abcdef0123456789abcdef01234567',
  path: 'notebooks/analysis.ipynb',
  ref: 'refs/heads/main',
};

async function signThenVerify(input: unknown) {
  const env = { [SEED_VARIABLE]: newSeed().b64 };
  const files: Record<string, string> = { 'input.json': JSON.stringify(input) };
  const sign = memoryIo(files, env);
  const code = await run(['sign', '--input', 'input.json'], sign);
  const out = sign.out.join('');
  let verify: { code: number; out: string; err: string } | undefined;
  if (code === EXIT.ok) {
    files['signed.json'] = out;
    const io = memoryIo(files);
    verify = { code: await run(['verify', '--input', 'signed.json', '--json'], io), out: io.out.join(''), err: io.err.join('') };
  }
  return { code, out, err: sign.err.join(''), verify };
}

test('PREMISE: the golden cases this file uses are a v0.1 input and a legacy input', () => {
  assert.equal(typeof V01['type'], 'string');
  assert.ok(!('type' in LEGACY));
});

for (const [label, vcsRef] of [
  ['all four fields', VCS_REF],
  ['the two required fields', { repoUrl: VCS_REF.repoUrl, commitSha: VCS_REF.commitSha }],
] as const) {
  test(`sign with vcsRef (${label}): signed verbatim on a v0.1 input, the bytes produce-core builds, and verify reads it ok`, async () => {
    const input = { ...V01, vcsRef };
    const r = await signThenVerify(input);
    assert.equal(r.code, EXIT.ok, r.err);
    const printed = JSON.parse(r.out) as { package: Record<string, unknown>; envelopeHash: string };
    assert.deepEqual(printed.package['vcsRef'], vcsRef);
    // The given ids make the input complete, so produce-core builds the same bytes.
    const built = buildEnvelope(input as unknown as EnvelopeInput);
    assert.equal(JSON.stringify(printed.package), JSON.stringify(built.pkg));
    assert.equal(printed.envelopeHash, built.envelopeHash);
    assert.ok(r.verify, 'verify ran');
    assert.equal(r.verify.code, EXIT.ok, r.verify.err);
    const verdict = JSON.parse(r.verify.out) as { ok: boolean; nodeId: string };
    assert.equal(verdict.ok, true);
    assert.equal(verdict.nodeId, printed.envelopeHash);
  });
}

test('sign with vcsRef: each shape error exits 2 naming the field, nothing on stdout', async () => {
  const cases: Array<[unknown, RegExp]> = [
    ['https://git.example.com/r', /vcsRef must be an object/],
    [{ commitSha: VCS_REF.commitSha }, /vcsRef\.repoUrl is required/],
    [{ repoUrl: VCS_REF.repoUrl }, /vcsRef\.commitSha is required/],
    [{ ...VCS_REF, repoUrl: '' }, /vcsRef\.repoUrl must not be empty/],
    [{ ...VCS_REF, commitSha: ' ' }, /vcsRef\.commitSha must not be empty/],
    [{ ...VCS_REF, commitSha: 7 }, /vcsRef\.commitSha must be a string/],
    [{ ...VCS_REF, path: null }, /vcsRef\.path must be a string/],
    [{ ...VCS_REF, ref: ['main'] }, /vcsRef\.ref must be a string/],
    [{ ...VCS_REF, branch: 'main' }, /vcsRef\.branch is not a field of vcsRef/],
  ];
  for (const [vcsRef, message] of cases) {
    const r = await signThenVerify({ ...V01, vcsRef });
    assert.equal(r.code, EXIT.usage, `${String(message)}: ${r.err}`);
    assert.equal(r.out, '');
    assert.match(r.err, message);
  }
});

test('sign with vcsRef on a legacy input (no type) exits 2 naming the v0.1-only rule', async () => {
  const r = await signThenVerify({ ...LEGACY, vcsRef: VCS_REF });
  assert.equal(r.code, EXIT.usage, r.err);
  assert.equal(r.out, '');
  assert.match(r.err, /^typedstandards sign: vcsRef is signed on v0\.1 envelopes only, and the input has no type/m);
  assert.doesNotMatch(r.err, /produce-core could not build the envelope/, 'the CLI refuses it before produce-core would throw');
});
