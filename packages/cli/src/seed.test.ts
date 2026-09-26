// Acceptance 3 (typedstandards#109): the seed's bytes and its base64 appear in
// neither stdout nor stderr, on success and on every failure path; a missing or
// malformed variable exits non-zero with a message naming the variable, not its
// value.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readSeed } from './seed.ts';
import { EXIT } from './errors.ts';
import { SEED_VARIABLE, cli, fileInput, newSeed, scratch, type CliResult } from './harness.test.ts';

const FILE = 'A signed file.\n';

/** Every spelling of the seed a leak could take. */
function spellings(bytes: Buffer): Buffer[] {
  return [bytes, Buffer.from(bytes.toString('base64')), Buffer.from(bytes.toString('base64url')), Buffer.from(bytes.toString('hex'))];
}

function assertNoLeak(r: CliResult, secrets: Buffer[], label: string): void {
  for (const stream of [r.stdout, r.stderr]) {
    for (const s of secrets) assert.equal(stream.indexOf(s), -1, `${label}: the seed appears in the output`);
  }
}

test('the seed does not appear on any path, success or failure', () => {
  const dir = scratch();
  try {
    const seed = newSeed();
    const secrets = spellings(seed.bytes);
    const env = { [SEED_VARIABLE]: seed.b64 };
    const input = dir.write('input.json', JSON.stringify(fileInput()));
    const file = dir.write('file.txt', FILE);

    const signed = cli(['sign', '--input', input, '--output-file', file], { env });
    assert.equal(signed.code, 0, signed.err);
    const signedPath = dir.write('signed.json', signed.out);
    const envelopeHash = signed.json()['envelopeHash'] as string;
    const withdrawal = cli(['withdraw', '--input', '-'], {
      env,
      stdin: JSON.stringify({ targetNodeId: envelopeHash, reason: 'replaced', signer: { bindingTier: 'pseudonymous', displayName: 'Example signer' } }),
    });
    assert.equal(withdrawal.code, 0, withdrawal.err);
    const withdrawalPath = dir.write('withdrawal.json', withdrawal.out);
    const view = cli(['view', '--signed', signedPath, '--withdrawal', withdrawalPath, '--visibility', 'public'], { env });
    assert.equal(view.code, 0, view.err);

    const paths: Array<[string, CliResult, number]> = [
      ['sign', signed, 0],
      ['withdraw', withdrawal, 0],
      ['view', view, 0],
      ['verify', cli(['verify', '--input', signedPath, '--json'], { env }), 0],
      // Failure paths with the seed set.
      ['sign, a self-check failure', cli(['sign', '--input', dir.write('bad-signer.json', JSON.stringify(fileInput({ signer: { bindingTier: 'pseudonymous', displayName: 'x', identifier: 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' } }))), '--output-file', file], { env }), EXIT.verificationFailed],
      ['sign, an unknown key', cli(['sign', '--input', dir.write('unknown.json', JSON.stringify(fileInput({ notAField: 1 }))), '--output-file', file], { env }), EXIT.usage],
      ['sign, an unreadable file', cli(['sign', '--input', input, '--output-file', dir.dir + '/absent.txt'], { env }), EXIT.usage],
      ['sign, no input', cli(['sign'], { env }), EXIT.usage],
      ['sign, an unknown flag', cli(['sign', '--input', input, '--seed', seed.b64], { env }), EXIT.usage],
      ['withdraw, an empty reason', cli(['withdraw', '--input', '-'], { env, stdin: JSON.stringify({ targetNodeId: envelopeHash, reason: ' ', signer: { bindingTier: 'p', displayName: 'x' } }) }), EXIT.usage],
      ['verify, a tampered record', cli(['verify', '--input', dir.write('t.json', signed.out.replace('A signed file', 'A signed filf'))], { env }), EXIT.verificationFailed],
      ['an unknown command', cli(['publish'], { env }), EXIT.usage],
    ];
    for (const [label, r, code] of paths) {
      assert.equal(r.code, code, `${label}: exited ${r.code}: ${r.err}`);
      assertNoLeak(r, secrets, label);
    }
  } finally {
    dir.cleanup();
  }
});

test('a missing or malformed variable exits 3, names the variable, and does not echo the value', () => {
  const dir = scratch();
  try {
    const input = dir.write('input.json', JSON.stringify(fileInput()));
    const file = dir.write('file.txt', FILE);
    // Leading 0xff bytes make the base64url spelling differ from the standard one
    // ("_" for "/"), so the base64url case below is malformed on every run.
    const bytes = Buffer.concat([Buffer.from([0xff, 0xff, 0xff]), newSeed().bytes.subarray(3)]);
    const seed = { bytes, b64: bytes.toString('base64') };
    const b64 = seed.b64;
    // A canonical final character ends in 0 bits for 32 bytes; this one decodes to the same bytes.
    const lastBits = 'AEIMQUYcgkosw048'.includes(b64[42]) ? b64.slice(0, 42) + String.fromCharCode(b64.charCodeAt(42) + 1) + '=' : null;
    const cases: Array<[string, Record<string, string>]> = [
      ['unset', {}],
      ['empty', { [SEED_VARIABLE]: '' }],
      ['whitespace', { [SEED_VARIABLE]: '   ' }],
      ['not base64', { [SEED_VARIABLE]: 'this is not a seed: not base64 at all!!' }],
      ['31 bytes', { [SEED_VARIABLE]: seed.bytes.subarray(0, 31).toString('base64') }],
      ['33 bytes', { [SEED_VARIABLE]: Buffer.concat([seed.bytes, Buffer.from([7])]).toString('base64') }],
      ['unpadded', { [SEED_VARIABLE]: b64.replace(/=$/, '') }],
      ['base64url', { [SEED_VARIABLE]: seed.bytes.toString('base64url') + '=' }],
      ['hex', { [SEED_VARIABLE]: seed.bytes.toString('hex') }],
      ...(lastBits ? [['non-canonical final character', { [SEED_VARIABLE]: lastBits }] as [string, Record<string, string>]] : []),
    ];
    for (const command of [
      ['sign', '--input', input, '--output-file', file],
      ['withdraw', '--input', dir.write('w.json', JSON.stringify({ targetNodeId: 'a'.repeat(64), reason: 'r', signer: { bindingTier: 'p', displayName: 'x' } }))],
    ]) {
      for (const [label, env] of cases) {
        const r = cli(command, { env });
        assert.equal(r.code, EXIT.seed, `${command[0]}, ${label}: exited ${r.code}: ${r.err}`);
        assert.equal(r.stdout.length, 0, `${command[0]}, ${label}: printed on stdout`);
        assert.match(r.err, new RegExp(SEED_VARIABLE), `${command[0]}, ${label}: the message does not name the variable`);
        const value = env[SEED_VARIABLE];
        if (value && value.trim()) {
          assert.equal(r.err.indexOf(value.trim()), -1, `${command[0]}, ${label}: the value is echoed`);
          assertNoLeak(r, spellings(seed.bytes), `${command[0]}, ${label}`);
        }
      }
    }
  } finally {
    dir.cleanup();
  }
});

test('readSeed: the standard base64 of 32 bytes, surrounding whitespace ignored', () => {
  const seed = newSeed();
  assert.deepEqual(Buffer.from(readSeed({ [SEED_VARIABLE]: seed.b64 })), seed.bytes);
  assert.deepEqual(Buffer.from(readSeed({ [SEED_VARIABLE]: `  ${seed.b64}\n` })), seed.bytes);
});

test('view and verify never read the seed: they succeed with it unset', () => {
  const dir = scratch();
  try {
    const signed = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('f.txt', FILE)], {
      env: { [SEED_VARIABLE]: newSeed().b64 },
    });
    const signedPath = dir.write('signed.json', signed.out);
    assert.equal(cli(['view', '--signed', signedPath, '--visibility', 'public']).code, 0);
    assert.equal(cli(['verify', '--input', signedPath]).code, 0);
  } finally {
    dir.cleanup();
  }
});
