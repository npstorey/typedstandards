// `view --attestation <file>...` (typedstandards#113, G0 D10): any lifecycle node
// (`withdraws`, `reinstates`, `supersedes`, `revises`) is carried into the view's
// `lifecycleAttestations`, and the view's `lifecycle` and `verify --json` read the
// status it resolves to. `--withdrawal` stays as an alias, and both may be given
// together. A claim-to-claim node passed to either flag exits 2 (G0 D6): this
// version carries none in a view.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAttestationNode, signEnvelopeHash, type AttestationInput } from '@typedstandards/produce-core';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { SEED_VARIABLE, cli, fileInput, memoryIo, newSeed, scratch } from './harness.test.ts';

const FILE = 'A signed file.\n';
const SIGNER = { bindingTier: 'pseudonymous', displayName: 'Example signer' };
const SUCCESSOR = 'e'.repeat(64);

interface Lifecycle {
  status: string;
  successorNodeId?: string;
  supersededAt?: string;
  chain: Array<{ type: string; successorNodeId?: string }>;
}

/** One in-memory session: files written by one command are read by the next. */
function session(seedB64: string) {
  const files: Record<string, string | Uint8Array> = { 'input.json': JSON.stringify(fileInput()), 'file.txt': FILE };
  const env = { [SEED_VARIABLE]: seedB64 };
  return {
    files,
    async run(argv: string[], stdoutTo?: string) {
      const io = memoryIo(files, env);
      const code = await run(argv, io);
      const out = io.out.join('');
      if (stdoutTo !== undefined) files[stdoutTo] = out;
      return { code, out, err: io.err.join('') };
    },
  };
}

/** Sign the record, then view it carrying the given node files under the given flags, then verify the view. */
async function signViewVerify(
  nodes: (s: ReturnType<typeof session>, target: string) => Promise<string[]>,
): Promise<{ view: { code: number; out: string; err: string }; verify: { code: number; out: string; err: string }; target: string }> {
  const s = session(newSeed().b64);
  const signed = await s.run(['sign', '--input', 'input.json', '--output-file', 'file.txt'], 'signed.json');
  assert.equal(signed.code, EXIT.ok, signed.err);
  const target = (JSON.parse(signed.out) as { envelopeHash: string }).envelopeHash;
  const flags = await nodes(s, target);
  const view = await s.run(['view', '--signed', 'signed.json', '--visibility', 'public', ...flags], 'view.json');
  const verify = view.code === EXIT.ok ? await s.run(['verify', '--input', 'view.json', '--json']) : { code: -1, out: '', err: '' };
  return { view, verify, target };
}

test('withdraw, then view --attestation: the view and verify --json read withdrawn', async () => {
  const { view, verify } = await signViewVerify(async (s, target) => {
    s.files['w-in.json'] = JSON.stringify({ targetNodeId: target, reason: 'replaced', signer: SIGNER });
    const r = await s.run(['withdraw', '--input', 'w-in.json'], 'w.json');
    assert.equal(r.code, EXIT.ok, r.err);
    return ['--attestation', 'w.json'];
  });
  assert.equal(view.code, EXIT.ok, view.err);
  assert.equal((JSON.parse(view.out) as { lifecycle: Lifecycle }).lifecycle.status, 'withdrawn');
  assert.equal((JSON.parse(view.out) as { lifecycleAttestations: unknown[] }).lifecycleAttestations.length, 1);
  assert.equal(verify.code, EXIT.ok, verify.err);
  assert.equal((JSON.parse(verify.out) as { lifecycle: Lifecycle }).lifecycle.status, 'withdrawn');
});

test('attest a supersedes signed by the record\'s seed, then view --attestation: verify --json reads superseded and names the successor', async () => {
  const { view, verify } = await signViewVerify(async (s, target) => {
    s.files['a-in.json'] = JSON.stringify({ type: 'attestation/supersedes/v1', targetNodeId: target, successorNodeId: SUCCESSOR, signer: SIGNER });
    const r = await s.run(['attest', '--input', 'a-in.json'], 'a.json');
    assert.equal(r.code, EXIT.ok, r.err);
    return ['--attestation', 'a.json'];
  });
  assert.equal(view.code, EXIT.ok, view.err);
  const viewLifecycle = (JSON.parse(view.out) as { lifecycle: Lifecycle }).lifecycle;
  assert.equal(viewLifecycle.status, 'superseded');
  assert.equal(viewLifecycle.successorNodeId, SUCCESSOR);
  assert.equal(verify.code, EXIT.ok, verify.err);
  const lifecycle = (JSON.parse(verify.out) as { lifecycle: Lifecycle }).lifecycle;
  assert.equal(lifecycle.status, 'superseded');
  assert.equal(lifecycle.successorNodeId, SUCCESSOR);
  assert.equal(lifecycle.supersededAt, '2026-09-26T12:00:00.000Z');
});

test('attest a revises, then view --attestation: verify --json reads active, with the revises in the chain', async () => {
  const { view, verify } = await signViewVerify(async (s, target) => {
    s.files['a-in.json'] = JSON.stringify({ type: 'attestation/revises/v1', targetNodeId: target, successorNodeId: SUCCESSOR, signer: SIGNER });
    const r = await s.run(['attest', '--input', 'a-in.json'], 'a.json');
    assert.equal(r.code, EXIT.ok, r.err);
    return ['--attestation', 'a.json'];
  });
  assert.equal(view.code, EXIT.ok, view.err);
  assert.equal((JSON.parse(view.out) as { lifecycle: Lifecycle }).lifecycle.status, 'active');
  assert.equal(verify.code, EXIT.ok, verify.err);
  const lifecycle = (JSON.parse(verify.out) as { lifecycle: Lifecycle }).lifecycle;
  assert.equal(lifecycle.status, 'active');
  assert.deepEqual(lifecycle.chain.map((v) => v.type), ['attestation/revises/v1']);
});

test('--withdrawal and --attestation together: both nodes are carried, and the latest counting one sets the status', async () => {
  const { view, verify } = await signViewVerify(async (s, target) => {
    s.files['w-in.json'] = JSON.stringify({ targetNodeId: target, reason: 'replaced', signer: SIGNER, createdAt: '2026-09-26T12:00:00.000Z' });
    s.files['a-in.json'] = JSON.stringify({ type: 'attestation/supersedes/v1', targetNodeId: target, successorNodeId: SUCCESSOR, signer: SIGNER, createdAt: '2026-09-26T13:00:00.000Z' });
    assert.equal((await s.run(['withdraw', '--input', 'w-in.json'], 'w.json')).code, EXIT.ok);
    assert.equal((await s.run(['attest', '--input', 'a-in.json'], 'a.json')).code, EXIT.ok);
    return ['--withdrawal', 'w.json', '--attestation', 'a.json'];
  });
  assert.equal(view.code, EXIT.ok, view.err);
  assert.equal((JSON.parse(view.out) as { lifecycleAttestations: unknown[] }).lifecycleAttestations.length, 2);
  assert.equal((JSON.parse(view.out) as { lifecycle: Lifecycle }).lifecycle.status, 'superseded');
  const lifecycle = (JSON.parse(verify.out) as { lifecycle: Lifecycle }).lifecycle;
  assert.equal(lifecycle.status, 'superseded');
  assert.equal(lifecycle.chain.length, 2);
});

/** A claim-to-claim node on `target`, signed by `seed`, built without the CLI. */
function claimToClaim(type: string, seed: Uint8Array, target: string): string {
  const kid = 'example:claim-key';
  const { node, nodeId } = buildAttestationNode({
    type,
    packageId: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4f',
    createdAt: '2026-09-26T12:00:00.000Z',
    signingKeyId: kid,
    targetNodeId: target,
    signer: { bindingTier: 'platform', identifier: 'platform:example-reviewer', displayName: 'Example reviewer' },
    scope: 'the reported totals',
  } as AttestationInput);
  return JSON.stringify({ node, nodeId, signature: signEnvelopeHash(nodeId, seed, kid) });
}

for (const flag of ['--attestation', '--withdrawal']) {
  for (const type of ['attestation/corroborates/v1', 'attestation/contradicts/v1']) {
    test(`view ${flag}: a ${type} node exits 2 naming G0 D6, nothing on stdout`, async () => {
      const { view } = await signViewVerify(async (s, target) => {
        s.files['c.json'] = claimToClaim(type, newSeed().bytes, target);
        return [flag, 'c.json'];
      });
      assert.equal(view.code, EXIT.usage, view.err);
      assert.equal(view.out, '');
      assert.match(view.err, new RegExp(`${flag} c\\.json is an ${type.replace(/\//g, '\\/')}, a claim-to-claim node: this version carries none in a view \\(typedstandards#113 G0 D6\\)`));
    });
  }
}

test('view --attestation: a node about another record exits 2 naming the flag', async () => {
  const { view } = await signViewVerify(async (s) => {
    s.files['a-in.json'] = JSON.stringify({ type: 'attestation/supersedes/v1', targetNodeId: 'b'.repeat(64), successorNodeId: SUCCESSOR, signer: SIGNER });
    assert.equal((await s.run(['attest', '--input', 'a-in.json'], 'a.json')).code, EXIT.ok);
    return ['--attestation', 'a.json'];
  });
  assert.equal(view.code, EXIT.usage, view.err);
  assert.match(view.err, /a --attestation targets b{64}, not this record/);
});

test('the built bin: attest, view --attestation, verify --json read superseded', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const s = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE)], { env });
    assert.equal(s.code, 0, s.err);
    const target = (s.json() as { envelopeHash: string }).envelopeHash;
    const a = cli(['attest', '--input', '-'], { env, stdin: JSON.stringify({ type: 'attestation/supersedes/v1', targetNodeId: target, successorNodeId: SUCCESSOR, signer: SIGNER }) });
    assert.equal(a.code, 0, a.err);
    const view = cli(['view', '--signed', dir.write('signed.json', s.out), '--visibility', 'public', '--attestation', dir.write('a.json', a.out)]);
    assert.equal(view.code, 0, view.err);
    const v = cli(['verify', '--input', dir.write('view.json', view.out), '--json']);
    assert.equal(v.code, 0, v.err);
    const lifecycle = v.json()['lifecycle'] as Lifecycle;
    assert.equal(lifecycle.status, 'superseded');
    assert.equal(lifecycle.successorNodeId, SUCCESSOR);
  } finally {
    dir.cleanup();
  }
});
