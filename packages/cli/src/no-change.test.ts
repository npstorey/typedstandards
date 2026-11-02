// The no-change guard of typedstandards#166's fix: every input 0.2.2's `verify`
// accepts gives the same stdout, the same stderr and the same exit code after the
// CLI also reads what a host serves. The inputs are what `sign` and `view` print
// (with and without a carried attestation), the publish script's fixture, a
// website layout node document, and host-core bundles served without a registry.
//
// fixtures/no-change/verify-0.2.2.json holds, per case, the SHA-256 of what
// 0.2.2's source printed and the exit code, written at the base of that change by
// running this file with UPDATE_NO_CHANGE_GOLDEN=1. Inputs are deterministic: the
// public RFC 8032 test seed and the harness's fixed clock and identifier.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { RFC8032_TEST_1_B64, SEED_VARIABLE, fileInput, memoryIo } from './harness.test.ts';

const GOLDEN = fileURLToPath(new URL('../fixtures/no-change/verify-0.2.2.json', import.meta.url));
const read = (relative: string) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

interface Outcome {
  code: number;
  stdoutSha256: string;
  stderrSha256: string;
}

/** Every input 0.2.2 accepts that this guard holds, by name: the file's text. */
async function inputs(): Promise<Record<string, string>> {
  const files: Record<string, string | Uint8Array> = { 'input.json': JSON.stringify(fileInput()), 'file.txt': 'A signed file.\nIts second line.\n' };
  const env = { [SEED_VARIABLE]: RFC8032_TEST_1_B64 };
  const step = async (argv: string[], to: string) => {
    const io = memoryIo(files, env);
    assert.equal(await run(argv, io), EXIT.ok, io.err.join(''));
    files[to] = io.out.join('');
  };
  await step(['sign', '--input', 'input.json', '--output-file', 'file.txt'], 'signed.json');
  const target = (JSON.parse(files['signed.json'] as string) as { envelopeHash: string }).envelopeHash;
  files['w-in.json'] = JSON.stringify({ targetNodeId: target, reason: 'replaced', signer: { bindingTier: 'pseudonymous', displayName: 'Example signer' } });
  await step(['withdraw', '--input', 'w-in.json'], 'w.json');
  await step(['view', '--signed', 'signed.json', '--visibility', 'public'], 'view.json');
  await step(['view', '--signed', 'signed.json', '--visibility', 'public', '--attestation', 'w.json'], 'view-withdrawn.json');

  // host-core with `registry: null` serves the view with neither trustRegistryUrl nor
  // trustRegistry (host-core build.ts:126-150; its cli.test.ts asserts both absent).
  const registryLess = (relative: string) => {
    const { trustRegistry: _r, trustRegistryUrl: _u, ...bundle } = JSON.parse(read(relative)) as Record<string, unknown>;
    return JSON.stringify(bundle);
  };
  return {
    sign: files['signed.json'] as string,
    view: files['view.json'] as string,
    'view-withdrawn': files['view-withdrawn.json'] as string,
    'published-verify': read('../scripts/fixtures/published-verify.bundle.json'),
    'website-layout-node': read('../fixtures/host-served/770ed52e2abfc0c7d4626953c9f715c11a50e63bd911fa2bed56b77a76fe0ee7.json'),
    'host-core-core-registry-less': registryLess('../../host-core/fixtures/core-satellite/expected/bundles/core.bundle.json'),
    'host-core-header-registry-less': registryLess('../../host-core/fixtures/core-satellite/expected/bundles/map/header.bundle.json'),
  };
}

async function outcomes(): Promise<Record<string, Outcome>> {
  const out: Record<string, Outcome> = {};
  for (const [name, text] of Object.entries(await inputs())) {
    for (const flags of [[], ['--json']]) {
      const io = memoryIo({ 'in.json': text });
      const code = await run(['verify', '--input', 'in.json', ...flags], io);
      out[[name, ...flags].join(' ')] = { code, stdoutSha256: sha256(io.out.join('')), stderrSha256: sha256(io.err.join('')) };
    }
  }
  return out;
}

test('every input 0.2.2 verifies gives the same stdout, stderr and exit code', async () => {
  const actual = await outcomes();
  if (process.env['UPDATE_NO_CHANGE_GOLDEN'] === '1') writeFileSync(GOLDEN, `${JSON.stringify(actual, null, 2)}\n`);
  const expected = JSON.parse(readFileSync(GOLDEN, 'utf8')) as Record<string, Outcome>;
  assert.equal(Object.keys(expected).length, 14);
  assert.deepEqual(actual, expected);
  // Each case 0.2.2 accepted: none of them exits 2.
  for (const [name, o] of Object.entries(expected)) assert.notEqual(o.code, EXIT.usage, name);
});
