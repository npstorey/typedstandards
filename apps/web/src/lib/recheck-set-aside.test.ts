// #97 (sprint #98): the live re-check is offered for a signer whose identifier is
// derived from its key, when verify-core set aside the registry its offline bundle
// carries and the bundle declares an `https:` registry URL — the shape a
// self-certified publisher's offline bundle takes. Before this, the re-check was
// offered only for a status some registry had backed, which excludes the
// `registry_unavailable` a set-aside registry leaves.
//
// The fixture is the pinned set-aside test's shape (verify-flow.test.ts, 'registry_
// unavailable under a SET-ASIDE bundle registry'): a key-derived identifier at the
// `platform` tier, the registry carried in the bundle listing the key active, and a
// declared https: registry URL. Keys are minted at test time (Ed25519 via
// node:crypto), the identifier derived by verify-core's `deriveKeyDerivedIdentifier`;
// no key or identifier is committed.
//
// Running the re-check behaves as #93 item 3 ruled: a confirmation re-reads #5, #14,
// the headline and recognition with their provenance line, the same as URL mode
// reads the record; a re-check that cannot complete changes no reading. Bundle mode
// makes no request until the reader asks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import {
  recomputePackageHash,
  deriveKeyDerivedIdentifier,
  type VerifyResult,
} from '@typedstandards/verify-core';
import { KEY_TRUST_BUNDLE_REGISTRY_NOT_USED, KEY_TRUST_SIGNALS } from './trust-signal.ts';
import {
  resolveInput,
  buildVerifyInput,
  runVerify,
  presentVerification,
  recheckKeyTrustLive,
  canRecheckKeyTrust,
  registryMetaOf,
  HOST_DIRECTORY,
  VerifyFlowError,
  type CheckRow,
  type Commitment,
  type KeyTrustRecheck,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

/** An https: registry URL on an origin the typedstandards.org directory lists. */
const LISTED_REGISTRY_URL = `${HOST_DIRECTORY.publishers[0].registryOrigin}/.well-known/typed-publisher.json`;
const LISTED_HOST = new URL(LISTED_REGISTRY_URL).host;
const HTTP_REGISTRY_URL = 'http://registry-host.test/trust-registry.json';
const COMMITMENT_URL = 'https://registry-host.test/api/records/p2-recheck/commitment';
const EMPTY_REGISTRY = { generatedAt: '2026-09-21T00:00:00.000Z', keys: [] };
const DIRECTORY_ROUTE = { [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };

/** A package signed by a key-derived signer at `bindingTier`, its commitment carrying
 *  a registry that lists the key active and, when given, declaring `registryUrl`. */
function mintKeyDerived(bindingTier: string, registryUrl: string | undefined) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const identifier = deriveKeyDerivedIdentifier(publicKeyB64);
  const signer = { bindingTier, identifier, displayName: 'Self Described Name' };
  const pkg: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    type: 'content/analysis/v1',
    signer,
    metadata: { signingKeyId: identifier },
    subject: { title: 'Synthetic set-aside fixture' },
    output: 'A minted record package for the set-aside re-check tests.',
  };
  const packageHash = recomputePackageHash(pkg);
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      {
        kid: identifier,
        publicKey: publicKeyB64,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: signer,
      },
    ],
  };
  const commitment: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    packageHash,
    package: pkg,
    signer,
    signature: {
      algorithm: 'Ed25519',
      publicKey: publicKeyB64,
      signature: Buffer.from(nodeSign(null, Buffer.from(packageHash, 'utf8'), privateKey)).toString('base64'),
      kid: identifier,
    },
    trustRegistry: registry,
    ...(registryUrl ? { trustRegistryUrl: registryUrl } : {}),
  };
  return { commitment, registry };
}

/** Install a fetch stub that records every URL and serves `routes`; anything else 404s. */
function recordFetch(routes: Record<string, unknown>): { calls: string[]; restore: () => void } {
  const calls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    calls.push(u);
    return Promise.resolve(
      u in routes
        ? new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }),
    );
  }) as typeof globalThis.fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = real;
    },
  };
}

/** Verify `commitment` as a bundle (or by URL), recording every request. */
async function run(commitment: Record<string, unknown>, mode: 'bundle' | 'url' = 'bundle', routes: Record<string, unknown> = {}) {
  const { calls, restore } = recordFetch({ ...routes, [COMMITMENT_URL]: commitment });
  try {
    const resolved =
      mode === 'bundle' ? await resolveInput('bundle', JSON.stringify(commitment)) : await resolveInput('url', COMMITMENT_URL);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    const shown = presentVerification(resolved, vinput, result);
    const offered = canRecheckKeyTrust(registryMetaOf(resolved), result);
    return { resolved, vinput, result, shown, offered, calls: [...calls] };
  } finally {
    restore();
  }
}

/** Run the live re-check with `routes` served, recording every request. */
async function recheck(r: Awaited<ReturnType<typeof run>>, routes: Record<string, unknown>) {
  const { calls, restore } = recordFetch(routes);
  try {
    const live: KeyTrustRecheck = await recheckKeyTrustLive(r.resolved.commitment as Commitment, r.result, r.vinput);
    return { live, calls };
  } finally {
    restore();
  }
}

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const row = rows.find((x) => x.num === num);
  assert.ok(row, `row #${num} is rendered`);
  return row;
};

const fmtCheckedAt = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

test('#97: a key-derived signer whose bundle registry was set aside, with a declared https: registry URL, is offered the re-check', async () => {
  const m = mintKeyDerived('platform', LISTED_REGISTRY_URL);
  const r = await run(m.commitment);
  assert.equal(r.result.keyTrust?.status, 'registry_unavailable');
  assert.equal(rowOf(r.shown.rows, '5').signal.detail, KEY_TRUST_BUNDLE_REGISTRY_NOT_USED.detail);
  assert.equal(r.offered, true, 'the re-check is offered');
  // The #5 row says the declared registry can establish what the bundle's could not.
  assert.match(rowOf(r.shown.rows, '5').depthNote ?? '', new RegExp(`Re-check against the live registry at ${LISTED_HOST.replace(/\./g, '\\.')}`));
  // Bundle mode made no request to get here.
  assert.deepEqual(r.calls, [], 'no request before the reader asks');
});

test('#97: a key-derived signer with no declared https: registry URL is still offered nothing', async () => {
  for (const url of [undefined, HTTP_REGISTRY_URL]) {
    const r = await run(mintKeyDerived('platform', url).commitment);
    assert.equal(r.result.keyTrust?.status, 'registry_unavailable', String(url));
    assert.equal(r.offered, false, `${url ?? 'no URL'}: nothing offered`);
    assert.equal(rowOf(r.shown.rows, '5').depthNote, undefined, `${url ?? 'no URL'}: no invitation`);
    assert.deepEqual(r.calls, [], `${url ?? 'no URL'}: no request`);
  }
});

test('#97: a confirmed re-check re-reads #5, #14, the headline and recognition with their provenance line, as URL mode reads the record', async () => {
  const m = mintKeyDerived('platform', LISTED_REGISTRY_URL);
  const r = await run(m.commitment);
  const before = r.shown;
  assert.equal(before.verdict.headline, 'Verified, with caveats', 'control: the bundle’s reading');
  assert.equal(before.recognition.status, 'directory_unavailable', 'control');

  const { live, calls } = await recheck(r, { [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE });
  assert.deepEqual(calls, [LISTED_REGISTRY_URL, HOST_DIRECTORY_PATH], 'the declared registry and the directory, nothing else');
  assert.equal(live.provenance, 'declared-url');
  const shown = presentVerification(r.resolved, r.vinput, r.result, live);
  const when = `Re-checked live against ${LISTED_HOST} at ${fmtCheckedAt(live.checkedAt)}, registry as of 2026-09-21.`;
  assert.equal(rowOf(shown.rows, '5').depthNote, when);
  assert.equal(shown.verdict.provenance, when);
  assert.equal(shown.recognition.provenance, when);
  assert.notEqual(rowOf(shown.rows, '5').signal.label, KEY_TRUST_BUNDLE_REGISTRY_NOT_USED.label);
  // Every row but #5 and #14 keeps the bundle's reading.
  assert.deepEqual(
    shown.rows.filter((x) => x.num !== '5' && x.num !== '14'),
    before.rows.filter((x) => x.num !== '5' && x.num !== '14'),
  );

  // URL mode reads the same record the same way.
  const hosted: Record<string, unknown> = { ...m.commitment };
  delete hosted['trustRegistry'];
  const byUrl = await run(hosted, 'url', { [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE });
  assert.equal(byUrl.resolved.registryProvenance, 'declared-url');
  assert.equal(live.status, byUrl.result.keyTrust?.status);
  assert.equal(rowOf(shown.rows, '5').signal.label, rowOf(byUrl.shown.rows, '5').signal.label);
  assert.equal(rowOf(shown.rows, '14').signal.label, rowOf(byUrl.shown.rows, '14').signal.label);
  assert.equal(shown.verdict.headline, byUrl.shown.verdict.headline);
  assert.equal(shown.verdict.tier, byUrl.shown.verdict.tier);
  assert.equal(shown.recognition.status, byUrl.shown.recognition.status);
  assert.equal(live.status, 'active', 'the declared registry lists the key active');
  assert.equal(rowOf(shown.rows, '5').signal.label, KEY_TRUST_SIGNALS.active.label);
});

test('#97: a re-check that finds the key unlisted reads as URL mode does; one that cannot complete changes no reading', async () => {
  const m = mintKeyDerived('platform', LISTED_REGISTRY_URL);
  const r = await run(m.commitment);
  const unlisted = await recheck(r, { [LISTED_REGISTRY_URL]: EMPTY_REGISTRY, ...DIRECTORY_ROUTE });
  const u = presentVerification(r.resolved, r.vinput, r.result, unlisted.live);
  const hosted: Record<string, unknown> = { ...m.commitment };
  delete hosted['trustRegistry'];
  const byUrl = await run(hosted, 'url', { [LISTED_REGISTRY_URL]: EMPTY_REGISTRY, ...DIRECTORY_ROUTE });
  assert.equal(unlisted.live.status, byUrl.result.keyTrust?.status);
  assert.equal(u.verdict.headline, byUrl.shown.verdict.headline);
  assert.equal(u.recognition.status, byUrl.shown.recognition.status);
  assert.notEqual(u.verdict.headline, 'Verified');

  const blocked: { label: string; routes: Record<string, unknown> | 'reject' }[] = [
    { label: 'network blocked', routes: 'reject' },
    { label: 'registry not found', routes: DIRECTORY_ROUTE },
    { label: 'registry not valid', routes: { [LISTED_REGISTRY_URL]: { keys: 'not a list' }, ...DIRECTORY_ROUTE } },
    { label: 'directory not loaded', routes: { [LISTED_REGISTRY_URL]: m.registry } },
  ];
  for (const c of blocked) {
    const real = globalThis.fetch;
    const { restore } = c.routes === 'reject' ? { restore: () => {} } : recordFetch(c.routes);
    if (c.routes === 'reject') globalThis.fetch = (() => Promise.reject(new TypeError('network blocked'))) as typeof globalThis.fetch;
    try {
      // It rejects, so the page keeps the reading it has: no live result reaches it.
      await assert.rejects(recheckKeyTrustLive(r.resolved.commitment as Commitment, r.result, r.vinput), VerifyFlowError, c.label);
    } finally {
      restore();
      globalThis.fetch = real;
    }
  }
  assert.deepEqual(presentVerification(r.resolved, r.vinput, r.result), r.shown, 'the page reads as before');
});

test('#97: bundle mode stays offline for the set-aside bundle — no request until the reader asks for the re-check', async () => {
  const m = mintKeyDerived('platform', LISTED_REGISTRY_URL);
  const { calls, restore } = recordFetch({ [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE });
  let resolved: Awaited<ReturnType<typeof resolveInput>>;
  let result: VerifyResult;
  let vinput: ReturnType<typeof buildVerifyInput>;
  try {
    resolved = await resolveInput('bundle', JSON.stringify(m.commitment));
    vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    presentVerification(resolved, vinput, result);
    assert.equal(resolved.fullyOffline, true);
    assert.equal(canRecheckKeyTrust(registryMetaOf(resolved), result), true);
    assert.deepEqual(calls, [], 'no request in bundle mode');
    // The reader asks: only then the declared registry and the directory.
    await recheckKeyTrustLive(resolved.commitment, result, vinput);
    assert.deepEqual(calls, [LISTED_REGISTRY_URL, HOST_DIRECTORY_PATH]);
  } finally {
    restore();
  }
});
