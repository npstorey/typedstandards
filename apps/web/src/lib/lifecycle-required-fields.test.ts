// The site's reading of a carried lifecycle event that lacks a field the standard
// requires of its sub-type (spec §8.12.1, §8.12.3; typedstandards#113, the P5 ruling
// on F1):
//   - it stays in the chain and does not move the status;
//   - it adds one #10 line at `attention` whose detail names the field, and the
//     headline then reads not affirmed;
//   - the #10 row lists the event under the field it lacks;
//   - a carried chain with no such event adds nothing.
//
// Exercised through `verifyResolved` and `presentVerification`, the code the /verify
// page runs, in Node: a record minted here is served from a stubbed URL with its
// trust registry, so the key is confirmed and the control reads "Verified".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { recomputePackageHash } from '@typedstandards/verify-core';
import {
  resolveInput,
  verifyResolved,
  presentVerification,
  checkSignalsOf,
  registryMetaOf,
  HOST_DIRECTORY,
  type CheckRow,
  type Commitment,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

const REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const COMMITMENT_URL = 'https://registry-host.test/api/records/p5-required-fields/commitment';
const KID = 'test:record-key-2026';
const SIGNER = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:synthetic-publisher', displayName: 'Synthetic publisher' };
const SUCCESSOR = 'e'.repeat(64);

interface Key {
  publicKey: string;
  sign(hashHex: string): { algorithm: string; publicKey: string; signature: string; kid: string };
}

function newKey(kid: string): Key {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const sk: KeyObject = privateKey;
  return {
    publicKey: spki,
    sign: (hashHex) => ({
      algorithm: 'Ed25519',
      publicKey: spki,
      signature: Buffer.from(nodeSign(null, Buffer.from(hashHex, 'utf8'), sk)).toString('base64'),
      kid,
    }),
  };
}

const RECORD_KEY = newKey(KID);

const PKG: Record<string, unknown> = {
  protocolVersion: '0.1.0',
  type: 'content/analysis/v1',
  signer: SIGNER,
  metadata: { signingKeyId: KID },
  output: 'A minted record package for the required-field tests.',
};
const PACKAGE_HASH = recomputePackageHash(PKG);

const REGISTRY = {
  generatedAt: '2026-09-21T00:00:00.000Z',
  keys: [
    { kid: KID, publicKey: RECORD_KEY.publicKey, status: 'active', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: null, revokedAt: null, signerIdentity: SIGNER },
  ],
};

interface Event {
  type: string;
  payload: Record<string, unknown>;
  createdAt?: string;
}

/** A lifecycle event naming the record's signer, signed by the record's own key. */
function carried(e: Event) {
  const node: Record<string, unknown> = {
    type: e.type,
    targetNodeId: PACKAGE_HASH,
    signer: SIGNER,
    metadata: { createdAt: e.createdAt ?? '2026-09-10T00:00:00.000Z' },
    ...e.payload,
  };
  const nodeId = recomputePackageHash(node);
  return { node, nodeId, signature: RECORD_KEY.sign(nodeId) };
}

function commitmentWith(events: Event[]): Commitment {
  return {
    protocolVersion: '0.1.0',
    packageHash: PACKAGE_HASH,
    package: PKG,
    signer: SIGNER,
    signature: RECORD_KEY.sign(PACKAGE_HASH),
    trustRegistryUrl: REGISTRY_URL,
    lifecycleAttestations: events.map(carried),
  };
}

async function page(commitment: Commitment) {
  const routes: Record<string, unknown> = { [COMMITMENT_URL]: commitment, [REGISTRY_URL]: REGISTRY, [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    return Promise.resolve(
      u in routes
        ? new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }),
    );
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('url', COMMITMENT_URL);
    const { input, result } = await verifyResolved(resolved);
    const shown = presentVerification(resolved, input, result);
    const tenSignals = checkSignalsOf(result, registryMetaOf(resolved), false).filter((c) => c.num === '10');
    return { result, rows: shown.rows, verdict: shown.verdict, tenSignals };
  } finally {
    globalThis.fetch = real;
  }
}

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

const WITHDRAWAL = { type: 'attestation/withdraws/v1', payload: { reason: 'a stated reason' } };
const WITHDRAWAL_NO_REASON = { type: 'attestation/withdraws/v1', payload: {} };
const SUPERSESSION_NO_SUCCESSOR = { type: 'attestation/supersedes/v1', payload: {} };

test('a withdrawal with no reason, signed by the record\'s key, does not move the status and adds one #10 attention line naming the field', async () => {
  const p = await page(commitmentWith([WITHDRAWAL_NO_REASON]));
  assert.equal(p.result.lifecycle.status, 'active', 'it does not move the status');
  assert.equal(p.result.lifecycle.chain.length, 1, 'it stays in the chain');
  assert.deepEqual(
    p.tenSignals.map((c) => c.signal.tier),
    ['normal', 'attention'],
    'the state line, then one attention line',
  );
  const line = p.tenSignals[1].signal;
  assert.match(line.detail ?? '', /lacks `reason`/);
  assert.match(line.detail ?? '', /withdrawal/);
  assert.match(line.detail ?? '', /does not change the status/);
  assert.equal(rowOf(p.rows, '10').signal.tier, 'attention', 'the #10 row reads the line the headline reads');
  assert.equal(p.rows.filter((r) => r.num === '10').length, 1, 'still one #10 row');
  assert.equal(p.verdict.headline, 'Verified, with caveats');
  assert.match(p.verdict.detail, /Not affirmed: #10 Lifecycle/);
});

test('the #10 row lists the event under the field it lacks', async () => {
  const commitment = commitmentWith([WITHDRAWAL_NO_REASON]);
  const nodeId = commitment.lifecycleAttestations![0].nodeId;
  const p = await page(commitment);
  const line = rowOf(p.rows, '10').math.find((m) => /reason/.test(m.label));
  assert.ok(line, 'the #10 row has a line naming reason');
  assert.equal(line.full ?? line.value, nodeId);
  assert.equal(line.mono, true);
});

test('a supersession with no successor does not move the status and names successorNodeId', async () => {
  const p = await page(commitmentWith([SUPERSESSION_NO_SUCCESSOR]));
  assert.equal(p.result.lifecycle.status, 'active');
  assert.deepEqual(p.tenSignals.map((c) => c.signal.tier), ['normal', 'attention']);
  assert.match(p.tenSignals[1].signal.detail ?? '', /lacks `successorNodeId`/);
  assert.match(p.tenSignals[1].signal.detail ?? '', /supersession/);
  assert.equal(p.verdict.headline, 'Verified, with caveats');
});

test('two events lacking fields still add one line, and it names both fields', async () => {
  const p = await page(
    commitmentWith([WITHDRAWAL_NO_REASON, { ...SUPERSESSION_NO_SUCCESSOR, createdAt: '2026-09-11T00:00:00.000Z' }]),
  );
  assert.deepEqual(p.tenSignals.map((c) => c.signal.tier), ['normal', 'attention']);
  assert.match(p.tenSignals[1].signal.detail ?? '', /`reason`/);
  assert.match(p.tenSignals[1].signal.detail ?? '', /`successorNodeId`/);
});

test('control: a carried chain with no such event adds nothing', async () => {
  const p = await page(commitmentWith([WITHDRAWAL]));
  assert.equal(p.result.lifecycle.status, 'withdrawn');
  assert.deepEqual(p.tenSignals.map((c) => c.signal.tier), ['normal']);
  assert.equal(p.verdict.headline, 'Verified');
});
