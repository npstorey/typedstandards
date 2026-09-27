// The site's reading of #10 under typedstandards#113 (G0 D3, and D6 as corrected):
//   - `superseded` reads `normal` ("Superseded by the publisher"), and the #10 row
//     names the successor;
//   - a carried lifecycle event that names the record's signer, but whose signing key
//     is not bound to it, adds one #10 line at `attention`, and the headline then
//     reads not affirmed;
//   - a third party's lifecycle event adds nothing.
//
// Exercised through `verifyResolved` and `presentVerification`, the code the /verify
// page runs, in Node: a record minted here is served from a stubbed URL with its
// trust registry, so the key is confirmed and the control reads "Verified".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { recomputePackageHash } from '@typedstandards/verify-core';
import * as signals from './trust-signal.ts';
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
const COMMITMENT_URL = 'https://registry-host.test/api/records/p1b-lifecycle/commitment';
const KID = 'test:record-key-2026';
const SIGNER = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:synthetic-publisher', displayName: 'Synthetic publisher' };
const THIRD_PARTY = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:another-party', displayName: 'Another party' };
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
const OTHER_KEY = newKey('test:other-key');

const PKG: Record<string, unknown> = {
  protocolVersion: '0.1.0',
  type: 'content/analysis/v1',
  signer: SIGNER,
  metadata: { signingKeyId: KID },
  output: 'A minted record package for the lifecycle tests.',
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
  by: Key;
  signer?: typeof SIGNER;
  payload?: Record<string, unknown>;
  createdAt?: string;
}

function carried(e: Event) {
  const node: Record<string, unknown> = {
    type: e.type,
    targetNodeId: PACKAGE_HASH,
    signer: e.signer ?? SIGNER,
    metadata: { createdAt: e.createdAt ?? '2026-09-10T00:00:00.000Z' },
    ...(e.payload ?? {}),
  };
  const nodeId = recomputePackageHash(node);
  return { node, nodeId, signature: e.by.sign(nodeId) };
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
const SUPERSESSION = { type: 'attestation/supersedes/v1', payload: { successorNodeId: SUCCESSOR } };
const REVISION = { type: 'attestation/revises/v1', payload: { successorNodeId: SUCCESSOR } };

test('D3: superseded has a defined tier, normal, and its label says the publisher superseded it', () => {
  const table = signals.LIFECYCLE_STATE_SIGNALS as Record<string, { tier: string; label: string; detail?: string }>;
  assert.ok(table['superseded'], 'LIFECYCLE_STATE_SIGNALS has a superseded entry');
  assert.equal(table['superseded'].tier, 'normal');
  assert.equal(table['superseded'].label, 'Superseded by the publisher');
  assert.ok(table['superseded'].detail, 'with a detail');
});

test('control: a withdrawal signed by the record\'s key reads withdrawn, one #10 line, and the record reads Verified', async () => {
  const p = await page(commitmentWith([{ ...WITHDRAWAL, by: RECORD_KEY }]));
  assert.equal(p.result.lifecycle.status, 'withdrawn');
  assert.equal(p.tenSignals.length, 1);
  assert.equal(rowOf(p.rows, '10').signal.tier, 'normal');
  assert.equal(p.verdict.headline, 'Verified');
});

test('D3: a supersedes signed by the record\'s key reads superseded at normal, and the #10 row names the successor', async () => {
  const p = await page(commitmentWith([{ ...SUPERSESSION, by: RECORD_KEY }]));
  assert.equal(p.result.lifecycle.status, 'superseded');
  const row = rowOf(p.rows, '10');
  assert.equal(row.signal.tier, 'normal');
  assert.equal(row.signal.label, 'Superseded by the publisher');
  const successor = row.math.find((m) => m.label === 'Successor');
  assert.ok(successor, 'the #10 row has a Successor line');
  assert.equal(successor.full ?? successor.value, SUCCESSOR);
  assert.equal(successor.mono, true);
  assert.equal(p.verdict.headline, 'Verified', 'a supersession is not a caveat');
});

test('D6: a withdrawal naming the record\'s signer, signed by an unbound key, adds one #10 attention line; the headline reads not affirmed', async () => {
  const p = await page(commitmentWith([{ ...WITHDRAWAL, by: OTHER_KEY }]));
  assert.equal(p.result.lifecycle.status, 'active', 'it does not move the status');
  assert.deepEqual(
    p.tenSignals.map((c) => c.signal.tier),
    ['normal', 'attention'],
    'the state line, then one attention line',
  );
  const line = p.tenSignals[1].signal;
  assert.match(line.label + ' ' + (line.detail ?? ''), /names the publisher, but its signing key is not bound to the publisher/);
  assert.equal(rowOf(p.rows, '10').signal.tier, 'attention', 'the #10 row reads the line the headline reads');
  assert.equal(p.rows.filter((r) => r.num === '10').length, 1, 'still one #10 row');
  assert.equal(p.verdict.headline, 'Verified, with caveats');
  assert.match(p.verdict.detail, /Not affirmed: #10 Lifecycle/);
});

test('D6: two unbound events naming the publisher still add one line', async () => {
  const p = await page(
    commitmentWith([
      { ...WITHDRAWAL, by: OTHER_KEY },
      { ...SUPERSESSION, by: OTHER_KEY, createdAt: '2026-09-11T00:00:00.000Z' },
    ]),
  );
  assert.deepEqual(p.tenSignals.map((c) => c.signal.tier), ['normal', 'attention']);
});

test('D6: an unbound revises naming the publisher adds the line too; a bound one adds nothing and moves no status', async () => {
  const unbound = await page(commitmentWith([{ ...REVISION, by: OTHER_KEY }]));
  assert.deepEqual(unbound.tenSignals.map((c) => c.signal.tier), ['normal', 'attention']);
  const bound = await page(commitmentWith([{ ...REVISION, by: RECORD_KEY }]));
  assert.equal(bound.result.lifecycle.status, 'active');
  assert.deepEqual(bound.tenSignals.map((c) => c.signal.tier), ['normal']);
  assert.equal(bound.verdict.headline, 'Verified');
});

test('D6: a third party\'s lifecycle event adds nothing', async () => {
  const p = await page(commitmentWith([{ ...WITHDRAWAL, by: OTHER_KEY, signer: THIRD_PARTY }]));
  assert.equal(p.result.lifecycle.status, 'active');
  assert.deepEqual(p.tenSignals.map((c) => c.signal.tier), ['normal']);
  assert.equal(rowOf(p.rows, '10').signal.tier, 'normal');
  assert.equal(p.verdict.headline, 'Verified');
});
