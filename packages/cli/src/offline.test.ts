// No command makes a network request (typedstandards#109 G0 D3): verify-core gets
// only the offline fetcher, and the global fetch is never called.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run } from './run.ts';
import { SEED_VARIABLE, fileInput, golden, memoryIo, newSeed } from './harness.test.ts';

test('sign, withdraw, view and verify call no global fetch; a referenced file not supplied is refused, not fetched', async () => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    throw new Error('network');
  }) as typeof fetch;
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const blobCase = golden.envelopeCases.find((c) => c.name === 'legacy-blobref-output')!;
    const io = memoryIo({ 'blob.json': JSON.stringify(blobCase.input), 'input.json': JSON.stringify(fileInput()), 'f.txt': 'text\n' }, env);

    assert.equal(await run(['sign', '--input', 'blob.json'], io), 0, io.err.join(''));
    assert.match(io.err.join(''), /not checked offline: https:\/\//);

    const fileIo = memoryIo({ 'input.json': JSON.stringify(fileInput()), 'f.txt': 'text\n' }, env);
    assert.equal(await run(['sign', '--input', 'input.json', '--output-file', 'f.txt', '--output-url', 'https://files.example/f.txt'], fileIo), 0);
    const signed = fileIo.out.join('');
    const hash = JSON.parse(signed).envelopeHash as string;

    const next = memoryIo(
      {
        'signed.json': signed,
        'f.txt': 'text\n',
        'w.json': JSON.stringify({ targetNodeId: hash, reason: 'r', signer: { bindingTier: 'pseudonymous', displayName: 'Example signer' } }),
      },
      env,
    );
    assert.equal(await run(['withdraw', '--input', 'w.json'], next), 0, next.err.join(''));
    assert.equal(await run(['view', '--signed', 'signed.json', '--visibility', 'public'], next), 0, next.err.join(''));
    assert.equal(await run(['verify', '--input', 'signed.json', '--blob', 'f.txt'], next), 0, next.err.join(''));
    assert.equal(calls, 0, 'a command called the global fetch');
  } finally {
    globalThis.fetch = realFetch;
  }
});
