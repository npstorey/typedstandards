// `attest --input <file|->` (typedstandards#113, G0 D10 as corrected): one JSON
// object naming `type`, `targetNodeId`, `signer` and that type's §8.12.1 payload,
// with strict per-type fields. It signs `supersedes`, `revises`, `corroborates` and
// `contradicts` on `withdraw`'s key path and verifies the node before printing
// `{node, nodeId, signature}`:
//   - integrity and signature must hold;
//   - a did:key signer identifier must be derived from the seed, or it exits 1 with
//     nothing on stdout;
//   - any other identifier prints; a reading other than `authorized` prints on
//     stderr at its tier (G0 D6 as corrected) and exits 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveKeyDerivedIdentifierFromKey } from '@typedstandards/produce-core';
import { checkAttestationNode, verifyAttestationNode, type CarriedLifecycleNode } from '@typedstandards/verify-core';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { SEED_VARIABLE, cli, fileInput, memoryIo, newSeed, scratch, type CliResult } from './harness.test.ts';

const FILE = 'A signed file.\n';
const SIGNER = { bindingTier: 'pseudonymous', displayName: 'Example signer' };
const PLATFORM_SIGNER = { bindingTier: 'platform', displayName: 'Example platform', identifier: 'platform:example-publisher' };
const SUCCESSOR = 'e'.repeat(64);
const TARGET = 'a'.repeat(64);

const SUPERSEDES = 'attestation/supersedes/v1';
const REVISES = 'attestation/revises/v1';
const CORROBORATES = 'attestation/corroborates/v1';
const CONTRADICTS = 'attestation/contradicts/v1';

/** The envelope keys every attestation node carries (spec §8.12.3). */
const STRUCTURAL = ['contentCanonicalization', 'contentHash', 'metadata', 'signer', 'targetNodeId', 'type'];

/** Each type's input payload and the node keys it must print: exactly its §8.12.1 fields. */
const CASES = [
  { type: SUPERSEDES, payload: { successorNodeId: SUCCESSOR }, keys: ['successorNodeId'] },
  { type: REVISES, payload: { successorNodeId: SUCCESSOR }, keys: ['successorNodeId'] },
  { type: CORROBORATES, payload: { scope: 'the reported totals', reasoning: 'recomputed from the same sources' }, keys: ['reasoning', 'scope'] },
  { type: CONTRADICTS, payload: { scope: 'the reported totals', reasoning: { method: 'recomputation', delta: 3 } }, keys: ['reasoning', 'scope'] },
  { type: CORROBORATES, payload: { scope: 'the reported totals' }, keys: ['scope'] },
] as const;

interface Printed {
  node: Record<string, unknown>;
  nodeId: string;
  signature: { signature: string; publicKey: string; algorithm?: string; kid?: string };
}

/** Run `attest` in process on one input, with the seed given, or none for null. */
async function attest(input: unknown, seedB64: string | null = newSeed().b64) {
  const io = memoryIo({ 'attest.json': JSON.stringify(input) }, seedB64 === null ? {} : { [SEED_VARIABLE]: seedB64 });
  const code = await run(['attest', '--input', 'attest.json'], io);
  return { code, out: io.out.join(''), err: io.err.join('') };
}

for (const c of CASES) {
  test(`attest ${c.type} (${c.keys.join(', ')}): signs, verifies, and prints exactly the §8.12.1 payload fields`, async () => {
    const seed = newSeed();
    const r = await attest({ type: c.type, targetNodeId: TARGET, signer: SIGNER, ...c.payload }, seed.b64);
    assert.equal(r.code, EXIT.ok, r.err);
    assert.equal(r.err, '', 'an authorized node prints nothing on stderr');
    const printed = JSON.parse(r.out) as Printed;
    assert.deepEqual(Object.keys(printed).sort(), ['node', 'nodeId', 'signature']);
    assert.deepEqual(Object.keys(printed.node).sort(), [...STRUCTURAL, ...c.keys].sort());
    assert.equal(printed.node['type'], c.type);
    assert.equal(printed.node['targetNodeId'], TARGET);
    for (const [key, value] of Object.entries(c.payload)) assert.deepEqual(printed.node[key], value, key);

    // Filled as withdraw fills them.
    const identifier = deriveKeyDerivedIdentifierFromKey(seed.bytes);
    assert.deepEqual(printed.node['signer'], { ...SIGNER, identifier });
    const metadata = printed.node['metadata'] as Record<string, string>;
    assert.equal(metadata['signingKeyId'], identifier);
    assert.equal(metadata['packageId'], '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d');
    assert.equal(metadata['createdAt'], '2026-09-26T12:00:00.000Z');
    assert.equal(printed.signature.kid, identifier);

    // What was printed verifies, independently of the CLI.
    const verdict = verifyAttestationNode(printed.node, printed.nodeId, printed.signature);
    assert.equal(verdict.nodeIdMatches, true);
    assert.equal(verdict.signatureValid, true);
    const check = checkAttestationNode(printed as CarriedLifecycleNode, {
      target: { signerIdentifier: identifier, publicKey: printed.signature.publicKey },
    });
    assert.equal(check.status, 'authorized');
    assert.deepEqual(check.missingFields, []);
  });
}

test('attest: the same input, ids and seed reproduce the output byte for byte; given ids are kept', async () => {
  const seed = newSeed().b64;
  const input = { type: SUPERSEDES, targetNodeId: TARGET, successorNodeId: SUCCESSOR, signer: SIGNER, packageId: 'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e', createdAt: '2026-09-27T00:00:00.000Z' };
  const a = await attest(input, seed);
  const b = await attest(input, seed);
  assert.equal(a.code, EXIT.ok, a.err);
  assert.equal(a.out, b.out);
  const metadata = (JSON.parse(a.out) as Printed).node['metadata'] as Record<string, string>;
  assert.equal(metadata['packageId'], input.packageId);
  assert.equal(metadata['createdAt'], input.createdAt);
});

for (const type of [SUPERSEDES, REVISES, CORROBORATES, CONTRADICTS]) {
  test(`attest ${type}: a did:key signer identifier the seed does not derive exits 1 with nothing on stdout`, async () => {
    const other = deriveKeyDerivedIdentifierFromKey(newSeed().bytes);
    const payload = type === SUPERSEDES || type === REVISES ? { successorNodeId: SUCCESSOR } : { scope: 'the reported totals' };
    const r = await attest({ type, targetNodeId: TARGET, signer: { ...SIGNER, identifier: other }, ...payload });
    assert.equal(r.code, EXIT.verificationFailed, r.err);
    assert.equal(r.out, '');
    assert.match(r.err, /^typedstandards attest: the signed attestation did not verify offline, so nothing was printed/m);
  });
}

test('attest: a platform-style identifier prints; publisher-only reads authorized, any-with-binding reads key_unbound (attention) on stderr', async () => {
  const supersedes = await attest({ type: SUPERSEDES, targetNodeId: TARGET, successorNodeId: SUCCESSOR, signer: PLATFORM_SIGNER });
  assert.equal(supersedes.code, EXIT.ok, supersedes.err);
  assert.equal(supersedes.err, '');
  assert.deepEqual((JSON.parse(supersedes.out) as Printed).node['signer'], PLATFORM_SIGNER);

  const corroborates = await attest({ type: CORROBORATES, targetNodeId: TARGET, scope: 'the reported totals', signer: PLATFORM_SIGNER });
  assert.equal(corroborates.code, EXIT.ok, corroborates.err);
  assert.deepEqual((JSON.parse(corroborates.out) as Printed).node['signer'], PLATFORM_SIGNER);
  assert.match(corroborates.err, /^typedstandards attest: authorization: key_unbound \(attention\)/m);
});

test('attest refuses, exit 2, naming it: a missing required field, an unknown key, an off-list type, withdraws and endorses', async () => {
  const supersedes = { type: SUPERSEDES, targetNodeId: TARGET, successorNodeId: SUCCESSOR, signer: SIGNER };
  const corroborates = { type: CORROBORATES, targetNodeId: TARGET, scope: 'the reported totals', signer: SIGNER };
  const without = (o: Record<string, unknown>, key: string) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== key));
  const cases: Array<[unknown, RegExp]> = [
    [without(supersedes, 'type'), /type is required: one of attestation\/supersedes\/v1/],
    [without(supersedes, 'targetNodeId'), /targetNodeId is required/],
    [without(supersedes, 'signer'), /signer is required/],
    [without(supersedes, 'successorNodeId'), /successorNodeId is required/],
    [{ ...supersedes, type: REVISES, successorNodeId: undefined }, /successorNodeId is required/],
    [without(corroborates, 'scope'), /scope is required/],
    [{ ...supersedes, reason: 'r' }, /reason is not a field of attestation\/supersedes\/v1/],
    [{ ...supersedes, scope: 's' }, /scope is not a field of attestation\/supersedes\/v1/],
    [{ ...corroborates, successorNodeId: SUCCESSOR }, /successorNodeId is not a field of attestation\/corroborates\/v1/],
    [{ ...corroborates, type: CONTRADICTS, notAField: 1 }, /notAField is not a field of attestation\/contradicts\/v1/],
    [{ ...supersedes, type: 'attestation/reinstates/v1' }, /type attestation\/reinstates\/v1 is not one attest signs/],
    [{ ...supersedes, type: 'attestation/publishes/v1' }, /type attestation\/publishes\/v1 is not one attest signs/],
    [{ ...supersedes, type: 'attestation/withdraws/v1' }, /attestation\/withdraws\/v1 is signed by withdraw/],
    [{ ...corroborates, type: 'attestation/endorses/v1' }, /attestation\/endorses\/v1 stays reserved.*G0 D1/],
    [{ ...supersedes, targetNodeId: 'A'.repeat(64) }, /targetNodeId must be .*64 lowercase hex/],
    [{ ...supersedes, successorNodeId: 'abc' }, /successorNodeId must be .*64 lowercase hex/],
    [{ ...corroborates, scope: ' ' }, /scope must not be empty/],
    [{ ...corroborates, reasoning: 3 }, /reasoning must be a string or an object/],
    [{ ...supersedes, signer: { displayName: 'x' } }, /signer\.bindingTier must be a string/],
    [{ ...supersedes, signingKeyId: '' }, /signingKeyId must not be empty/],
    [[], /the input must be a JSON object/],
  ];
  for (const [input, message] of cases) {
    const r = await attest(JSON.parse(JSON.stringify(input)));
    assert.equal(r.code, EXIT.usage, `${String(message)}: ${r.err}`);
    assert.equal(r.out, '');
    assert.match(r.err, message);
  }
  const io = memoryIo({}, { [SEED_VARIABLE]: newSeed().b64 });
  assert.equal(await run(['attest'], io), EXIT.usage);
  assert.match(io.err.join(''), /^typedstandards attest: --input is required/);
});

test('attest reads the seed only from its variable: missing or malformed exits 3 naming the variable, nothing on stdout, the value never echoed', async () => {
  const input = { type: SUPERSEDES, targetNodeId: TARGET, successorNodeId: SUCCESSOR, signer: SIGNER };
  const missing = await attest(input, null);
  assert.equal(missing.code, EXIT.seed, missing.err);
  assert.equal(missing.out, '');
  assert.match(missing.err, new RegExp(SEED_VARIABLE));
  const seed = newSeed();
  const malformed = await attest(input, seed.bytes.toString('hex'));
  assert.equal(malformed.code, EXIT.seed, malformed.err);
  assert.equal(malformed.out, '');
  assert.equal(malformed.err.indexOf(seed.bytes.toString('hex')), -1);
  // No flag carries a seed.
  const io = memoryIo({ 'attest.json': JSON.stringify(input) }, { [SEED_VARIABLE]: seed.b64 });
  assert.equal(await run(['attest', '--input', 'attest.json', '--seed', seed.b64], io), EXIT.usage);
  assert.deepEqual(io.out, []);
});

/** The seed's spellings a leak could take. */
function assertNoLeak(r: CliResult, bytes: Buffer): void {
  for (const s of [bytes, Buffer.from(bytes.toString('base64')), Buffer.from(bytes.toString('base64url')), Buffer.from(bytes.toString('hex'))]) {
    assert.equal(r.stdout.indexOf(s), -1, 'the seed appears on stdout');
    assert.equal(r.stderr.indexOf(s), -1, 'the seed appears on stderr');
  }
}

test('the built bin: attest from standard input prints JSON only on success, and the seed appears on no path', () => {
  const dir = scratch();
  try {
    const seed = newSeed();
    const env = { [SEED_VARIABLE]: seed.b64 };
    const s = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE)], { env });
    assert.equal(s.code, 0, s.err);
    const target = (s.json() as { envelopeHash: string }).envelopeHash;
    const ok = cli(['attest', '--input', '-'], { env, stdin: JSON.stringify({ type: CONTRADICTS, targetNodeId: target, scope: 'the totals', signer: SIGNER }) });
    assert.equal(ok.code, 0, ok.err);
    assert.equal((ok.json() as unknown as Printed).node['targetNodeId'], target);
    assertNoLeak(ok, seed.bytes);
    const bad = cli(['attest', '--input', '-'], { env, stdin: JSON.stringify({ type: CONTRADICTS, targetNodeId: target, signer: SIGNER }) });
    assert.equal(bad.code, EXIT.usage);
    assert.equal(bad.stdout.length, 0);
    assertNoLeak(bad, seed.bytes);
  } finally {
    dir.cleanup();
  }
});
