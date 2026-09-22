// Check #6 — the envelope `kid` against `metadata.signingKeyId`
// (typedstandards#88; spec §9.2 check #6 and §8.3.1, hub cfdb210 lines 1511
// and 616).
//
//   - §8.3.1: `metadata.signingKeyId` MUST equal the envelope's `kid`. A `kid`
//     swapped on the envelope after signing leaves the signature valid, so only
//     this comparison detects it ("envelope-vs-canonical drift").
//   - Under a key-derived `signer.identifier` (§8.5.1) `kid` is optional; when
//     present it MUST equal `metadata.signingKeyId` and SHOULD be the identifier.
//     The SHOULD is not a failure, and for a registry signer `kid` and
//     `signer.identifier` differ by design.
//
// Only `signingKeyId_mismatch` is a failing status, and only it carries the two
// values.
//
// Inputs:
//   - `__fixtures__/adr-0028-recomputation.package.json` (the ADR-0028 eval-run
//     example repository, `package/recomputation.package.json` at commit
//     9031a94, byte for byte; its SHA-256 is pinned in
//     scripted-recomputation.test.ts) with the signature envelope of
//     `package/recomputation.commitment.json` at the same commit. The signature
//     is load-bearing: it verifies over the fixture's envelope hash.
//   - `__fixtures__/adr-0028-trust-registry.json` (same repository and commit),
//     for the envelope's public key.
//   - A synthetic key-derived signer whose Ed25519 seed is the SHA-256 of a
//     label written below; the identifier is derived from its public key.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import * as core from './index.ts';
import {
  ED25519_SPKI_PREFIX,
  computeEnvelopeHash,
  deriveKeyDerivedIdentifier,
  sha256Hex,
  utf8ToBytes,
  verifyRecord,
  type FetchLike,
  type TrustRegistry,
  type VerifyResult,
} from './index.ts';

/** The check #6 fields of a verify result, read without assuming they exist. */
type Check6 = { status: string; kid?: string; signingKeyId?: string } | null | undefined;
const check6 = (r: VerifyResult): Check6 =>
  (r as unknown as { signingKeyIdConsistency?: Check6 }).signingKeyIdConsistency;

const FAILING = ['signingKeyId_mismatch'];

const failFetch = (() => {
  throw new Error('check #6 must not touch the network');
}) as unknown as FetchLike;

// --- The ADR-0028 package: a registry signer --------------------------------

const ADR0028_PACKAGE = JSON.parse(
  readFileSync(new URL('./__fixtures__/adr-0028-recomputation.package.json', import.meta.url), 'utf8'),
) as Record<string, unknown>;
const ADR0028_REGISTRY = JSON.parse(
  readFileSync(new URL('./__fixtures__/adr-0028-trust-registry.json', import.meta.url), 'utf8'),
) as TrustRegistry;
const ADR0028_ENVELOPE_HASH = 'abb93f781ae71480bf8075474facbb272f3dcc38d50eeecda79be33427924a9c';
const ADR0028_KID = 'eval-run-example:ed25519-2026-09';
const ADR0028_SIGNATURE = {
  signature: 'RbjeWhO1oj+G5He60jRwKrg0tv+4t3Uzpuw4ALOPxnUcT1pXIRRZzerhqzsH47BgfDwv9x8OmLan518d6zrkCA==',
  publicKey: ADR0028_REGISTRY.keys[0]!.publicKey,
  algorithm: 'Ed25519ph',
  kid: ADR0028_KID,
};

function verifyAdr0028(kid: string | undefined) {
  const { kid: _omit, ...rest } = ADR0028_SIGNATURE;
  return verifyRecord(
    {
      package: ADR0028_PACKAGE,
      packageHash: ADR0028_ENVELOPE_HASH,
      signature: kid === undefined ? rest : { ...rest, kid },
    },
    { registry: ADR0028_REGISTRY, fetch: failFetch },
  );
}

// --- A synthetic key-derived signer -----------------------------------------

const SEED = Uint8Array.from(
  sha256Hex(utf8ToBytes('typedstandards/tests/check-6/v1')).match(/../g)!.map((h) => parseInt(h, 16)),
);
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const SPKI = (() => {
  const raw = ed25519.getPublicKey(SEED);
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(raw, ED25519_SPKI_PREFIX.length);
  return b64(der);
})();
const DID = deriveKeyDerivedIdentifier(SPKI);

function keyDerivedPkg(signingKeyId: string | undefined): Record<string, unknown> {
  return {
    metadata: {
      schemaVersion: '0.1.0',
      packageId: 'abcdefab-cdef-4abc-8def-abcdefab0006',
      createdAt: '2026-09-22T00:00:00.000Z',
      captureMethod: 'script-run',
      ...(signingKeyId !== undefined ? { signingKeyId } : {}),
    },
    type: 'content/analysis/v1',
    producerProfile: 'scripted-recomputation/check-6',
    signer: { bindingTier: 'pseudonymous', identifier: DID, displayName: 'check #6 test key' },
    output: 'a,b\n1,2\n',
  };
}

/** Sign `pkg` with the synthetic key and verify it with the given envelope `kid`. */
function verifyKeyDerived(pkg: Record<string, unknown>, kid: string | undefined) {
  const packageHash = computeEnvelopeHash(pkg);
  return verifyRecord(
    {
      package: pkg,
      packageHash,
      signature: {
        signature: b64(ed25519ph.sign(utf8ToBytes(packageHash), SEED)),
        publicKey: SPKI,
        algorithm: 'Ed25519ph',
        ...(kid !== undefined ? { kid } : {}),
      },
    },
    { registry: undefined, fetch: failFetch },
  );
}

// --- The status list --------------------------------------------------------

test('#88: check #6 exports its status list', () => {
  assert.deepEqual((core as Record<string, unknown>)['SIGNING_KEY_ID_CONSISTENCY_STATUSES'], [
    'ok',
    'signingKeyId_mismatch',
    'kid_absent',
    'signingKeyId_absent',
  ]);
});

// --- Registry signer --------------------------------------------------------

test('#88: an envelope kid that differs from metadata.signingKeyId reads signingKeyId_mismatch', async () => {
  const r = await verifyAdr0028('eval-run-example:ed25519-2099-01');
  // The swap leaves the signature valid: only check #6 sees it.
  assert.equal(r.hashMatch, true);
  assert.equal(r.signatureValid, true);
  assert.deepEqual(check6(r), {
    status: 'signingKeyId_mismatch',
    kid: 'eval-run-example:ed25519-2099-01',
    signingKeyId: ADR0028_KID,
  });
});

test('#88: the ADR-0028 package with its own envelope reads ok (kid differs from signer.identifier by design)', async () => {
  const r = await verifyAdr0028(ADR0028_KID);
  assert.equal(r.signatureValid, true);
  assert.equal(r.signerIdentity?.status, 'ok');
  assert.notEqual((ADR0028_PACKAGE['signer'] as { identifier: string }).identifier, ADR0028_KID);
  assert.deepEqual(check6(r), { status: 'ok' });
});

test('#88: an envelope with no kid reads kid_absent, not a failure', async () => {
  const r = await verifyAdr0028(undefined);
  assert.deepEqual(check6(r), { status: 'kid_absent' });
  assert.ok(!FAILING.includes(check6(r)!.status));
});

test('#88: a legacy package with neither field reads kid_absent', async () => {
  const pkg = { metadata: { schemaVersion: '0.0.1', packageId: 'abcdefab-0000-4000-8000-00000000abcd' } };
  const packageHash = computeEnvelopeHash(pkg);
  const r = await verifyRecord(
    {
      package: pkg,
      packageHash,
      signature: { signature: b64(ed25519ph.sign(utf8ToBytes(packageHash), SEED)), publicKey: SPKI },
    },
    { registry: undefined, fetch: failFetch },
  );
  assert.equal(r.signatureValid, true);
  assert.deepEqual(check6(r), { status: 'kid_absent' });
});

// --- Key-derived signer -----------------------------------------------------

test('#88: key-derived signer, kid absent: kid_absent, not a failure', async () => {
  const r = await verifyKeyDerived(keyDerivedPkg(DID), undefined);
  assert.equal(r.signatureValid, true);
  assert.equal(r.signerIdentity?.status, 'key_derived_match');
  assert.deepEqual(check6(r), { status: 'kid_absent' });
  assert.ok(!FAILING.includes(check6(r)!.status));
});

test('#88: key-derived signer, kid equal to signingKeyId but not the identifier: ok (the SHOULD does not fail)', async () => {
  const kid = 'publisher:key-2026-09';
  const r = await verifyKeyDerived(keyDerivedPkg(kid), kid);
  assert.equal(r.signerIdentity?.status, 'key_derived_match');
  assert.notEqual(kid, DID);
  assert.deepEqual(check6(r), { status: 'ok' });
});

test('#88: key-derived signer, kid and signingKeyId the identifier: ok', async () => {
  const r = await verifyKeyDerived(keyDerivedPkg(DID), DID);
  assert.deepEqual(check6(r), { status: 'ok' });
});

test('#88: key-derived signer, kid differs from signingKeyId: signingKeyId_mismatch', async () => {
  const r = await verifyKeyDerived(keyDerivedPkg('publisher:key-2026-09'), DID);
  assert.deepEqual(check6(r), {
    status: 'signingKeyId_mismatch',
    kid: DID,
    signingKeyId: 'publisher:key-2026-09',
  });
});

test('#88: a kid with no metadata.signingKeyId reads signingKeyId_absent', async () => {
  const r = await verifyKeyDerived(keyDerivedPkg(undefined), DID);
  assert.deepEqual(check6(r), { status: 'signingKeyId_absent' });
});

// --- When check #6 does not run ---------------------------------------------

test('#88: check #6 reports null without a package, without a signature, or with a malformed one', async () => {
  const deps = { registry: undefined, fetch: failFetch };
  const noPackage = await verifyRecord(
    { package: null, packageHash: ADR0028_ENVELOPE_HASH, signature: ADR0028_SIGNATURE },
    deps,
  );
  const noSignature = await verifyRecord(
    { package: ADR0028_PACKAGE, packageHash: ADR0028_ENVELOPE_HASH },
    deps,
  );
  const malformed = await verifyRecord(
    { package: ADR0028_PACKAGE, packageHash: ADR0028_ENVELOPE_HASH, signatureMalformed: true },
    deps,
  );
  for (const r of [noPackage, noSignature, malformed]) {
    assert.ok('signingKeyIdConsistency' in r, 'the result carries the check #6 field');
    assert.equal(check6(r), null);
  }
});

// --- The pure check ---------------------------------------------------------

test('#88: checkSigningKeyIdConsistency compares the kid it is given with the package', () => {
  const check = (core as Record<string, unknown>)['checkSigningKeyIdConsistency'] as (
    pkg: Record<string, unknown>,
    kid: string | undefined,
  ) => Check6;
  assert.equal(typeof check, 'function');
  const pkg = { metadata: { signingKeyId: 'k1' } };
  assert.deepEqual(check(pkg, 'k1'), { status: 'ok' });
  assert.deepEqual(check(pkg, 'k2'), { status: 'signingKeyId_mismatch', kid: 'k2', signingKeyId: 'k1' });
  assert.deepEqual(check(pkg, undefined), { status: 'kid_absent' });
  assert.deepEqual(check(pkg, ''), { status: 'kid_absent' });
  assert.deepEqual(check({}, undefined), { status: 'kid_absent' });
  assert.deepEqual(check({}, 'k1'), { status: 'signingKeyId_absent' });
  assert.deepEqual(check({ metadata: { signingKeyId: null } }, 'k1'), { status: 'signingKeyId_absent' });
  assert.deepEqual(check({ metadata: { signingKeyId: '' } }, 'k1'), { status: 'signingKeyId_absent' });
  // A present value that is not the kid string is a mismatch, whatever its type.
  assert.deepEqual(check({ metadata: { signingKeyId: 7 } }, 'k1'), {
    status: 'signingKeyId_mismatch',
    kid: 'k1',
  });
  // Case and whitespace are not normalized: the comparison is exact.
  assert.equal(check(pkg, 'K1')!.status, 'signingKeyId_mismatch');
  assert.equal(check(pkg, 'k1 ')!.status, 'signingKeyId_mismatch');
});
