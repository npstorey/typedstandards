// The self-certifying signer (hub ADR-0030): the key-derived identifier, the
// eighth key-trust status `self_certified`, check #14's `key_derived_match` /
// `key_derived_mismatch`, and §4's registry rules as amended at gate G2
// (only a registry from a declared `trustRegistryUrl` can raise a
// self-certified signer's status; a bundle-carried one can only lower it).
//
// The derivation's vectors are in `did-key.test.ts`. Inputs here:
//   - The eval-run example repository (ADR-0028), `package/trust-registry.json`
//     at commit 9031a94, copied byte for byte to
//     `__fixtures__/adr-0028-trust-registry.json` (its SHA-256 is pinned in did-key.test.ts).
//     A registry that does not list the canary key.
//   - RFC 8032 §7.1 TEST 1 and TEST 2: published secret and public keys; they
//     sign the canary packages (key A and key B).
//   - `__fixtures__/adr-0028-recomputation.package.json` (P3's fixture, the
//     same repository and commit) with its signature envelope from
//     `package/recomputation.commitment.json`: the ADR-0028 package, whose
//     identifier is not key-derived, is unaffected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import {
  KEY_TRUST_STATUSES,
  SIGNER_IDENTITY_CHECK_STATUSES,
  TRUST_REGISTRY_PROVENANCES,
  ED25519_SPKI_PREFIX,
  deriveKeyDerivedIdentifier,
  isKeyDerivedIdentifier,
  checkSignerIdentity,
  computeContentHashSha256,
  computeEnvelopeHash,
  verifyRecord,
  LEGACY_JSON_CANONICALIZATION,
  type FetchLike,
  type KeyTrustResult,
  type TrustRegistry,
  type TrustRegistryProvenance,
  type VerifyResult,
} from './index.ts';
import { applySelfCertifiedKeyTrust } from './self-certifying.ts';

const hexToBytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const utf8 = (s: string) => new TextEncoder().encode(s);

/** Assemble base64 SPKI DER from a raw 32-byte Ed25519 public key. */
function rawToSpkiB64(raw: Uint8Array): string {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(raw, ED25519_SPKI_PREFIX.length);
  return b64(der);
}

const failFetch = (() => {
  throw new Error('verify-core touched the network when it should not have');
}) as unknown as FetchLike;

// --- Published inputs ------------------------------------------------------

/** RFC 8032 §7.1 TEST 1 (published test key). */
const RFC8032_T1_SECRET = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
/** RFC 8032 §7.1 TEST 2 (published test key). */
const RFC8032_T2_SECRET = hexToBytes('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
const RFC8032_T2_PUBLIC_HEX = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';

/** ADR-0030 §9's string for RFC 8032 TEST 1's key (re-derived in did-key.test.ts). */
const DID_RFC8032_T1 = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';

const REGISTRY_FIXTURE_BYTES = new Uint8Array(
  readFileSync(new URL('./__fixtures__/adr-0028-trust-registry.json', import.meta.url)),
);
const adr0028Registry = JSON.parse(new TextDecoder().decode(REGISTRY_FIXTURE_BYTES)) as TrustRegistry;

// --- 1. The eighth status ---------------------------------------------------

test('KEY_TRUST_STATUSES has eight values, self_certified last', () => {
  assert.deepEqual(KEY_TRUST_STATUSES, [
    'active',
    'deprecated_valid',
    'deprecated_invalid',
    'revoked',
    'unknown_key',
    'registry_unavailable',
    'legacy_embedded',
    'self_certified',
  ]);
});

test('check #14 has six statuses; registry provenance has two values', () => {
  assert.deepEqual(SIGNER_IDENTITY_CHECK_STATUSES, [
    'ok',
    'signer_identity_mismatch',
    'no_signer',
    'no_registry_identity',
    'key_derived_match',
    'key_derived_mismatch',
  ]);
  assert.deepEqual(TRUST_REGISTRY_PROVENANCES, ['declared-url', 'bundle']);
});

// --- 2. Signed packages under a key-derived identifier ---------------------

const KEY_A = { secret: RFC8032_T1_SECRET, spki: rawToSpkiB64(ed25519.getPublicKey(RFC8032_T1_SECRET)) };
const KEY_B = { secret: RFC8032_T2_SECRET, spki: rawToSpkiB64(ed25519.getPublicKey(RFC8032_T2_SECRET)) };

test('the second canary key is RFC 8032 §7.1 TEST 2', () => {
  assert.equal(
    Buffer.from(ed25519.getPublicKey(RFC8032_T2_SECRET)).toString('hex'),
    RFC8032_T2_PUBLIC_HEX,
  );
});

interface CanaryOptions {
  /** The key whose derived identifier the package claims. */
  identifierKey: { spki: string };
  /** The key that signs and whose SPKI goes in the envelope. */
  signingKey: { secret: Uint8Array; spki: string };
  identifier?: string;
  bindingTier?: string;
  kid?: string | null;
}

/** A signed v0.1 package whose `signer.identifier` is key-derived. */
function buildCanary(opts: CanaryOptions) {
  const identifier = opts.identifier ?? deriveKeyDerivedIdentifier(opts.identifierKey.spki);
  const kid = opts.kid === undefined ? identifier : opts.kid;
  const base: Record<string, unknown> = {
    metadata: {
      schemaVersion: '0.1.0',
      packageId: '00000000-0000-4000-8000-00000000abcd',
      createdAt: '2026-09-21T00:00:00.000Z',
      captureMethod: 'script-run',
      ...(kid !== null ? { signingKeyId: kid } : {}),
    },
    type: 'content/analysis/v1',
    producerProfile: 'scripted-recomputation/canary',
    signer: {
      bindingTier: opts.bindingTier ?? 'pseudonymous',
      identifier,
      displayName: 'Canary signer',
    },
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    output: 'canary',
  };
  const pkg = {
    ...base,
    contentHash: { sha256: computeContentHashSha256(base, LEGACY_JSON_CANONICALIZATION) },
  };
  const packageHash = computeEnvelopeHash(pkg);
  const signature = {
    signature: b64(ed25519ph.sign(utf8(packageHash), opts.signingKey.secret)),
    publicKey: opts.signingKey.spki,
    algorithm: 'Ed25519ph',
    ...(kid !== null ? { kid } : {}),
  };
  return { pkg, packageHash, signature, identifier, kid };
}

type Canary = ReturnType<typeof buildCanary>;

function verifyCanary(
  c: Canary,
  registry?: TrustRegistry,
  registryProvenance?: TrustRegistryProvenance,
): Promise<VerifyResult> {
  return verifyRecord(
    { package: c.pkg, packageHash: c.packageHash, signature: c.signature },
    {
      registry,
      fetch: failFetch,
      ...(registryProvenance ? { registryProvenance } : {}),
    },
  );
}

/** A registry listing the canary's `(kid, publicKey)`. */
function registryFor(
  c: Canary,
  status: 'active' | 'deprecated' | 'revoked',
  identity: string = c.identifier,
): TrustRegistry {
  return {
    keys: [
      {
        kid: c.kid as string,
        publicKey: c.signature.publicKey,
        status,
        activatedAt: '2026-09-01T00:00:00Z',
        deprecatedAt: null,
        revokedAt: status === 'revoked' ? '2026-09-10T00:00:00Z' : null,
        signerIdentity: { bindingTier: 'pseudonymous', identifier: identity, displayName: 'x' },
      },
    ],
  };
}

test('canary: identifier derived from the envelope key → self_certified, #14 key_derived_match', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  assert.equal(c.identifier, DID_RFC8032_T1);
  const r = await verifyCanary(c);
  assert.equal(r.hashMatch, true);
  assert.equal(r.signatureValid, true);
  assert.deepEqual(r.keyTrust, { status: 'self_certified', verified: false, kid: DID_RFC8032_T1 });
  assert.deepEqual(r.signerIdentity, {
    status: 'key_derived_match',
    claimed: DID_RFC8032_T1,
    derived: DID_RFC8032_T1,
  });
});

test('canary: identifier from key A, envelope key B → #14 key_derived_mismatch with claimed and derived', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_B });
  const r = await verifyCanary(c);
  // The signature itself verifies under key B: only the identifier is false.
  assert.equal(r.signatureValid, true);
  assert.deepEqual(r.signerIdentity, {
    status: 'key_derived_mismatch',
    claimed: DID_RFC8032_T1,
    derived: deriveKeyDerivedIdentifier(KEY_B.spki),
  });
  // Rule 1: key trust follows the registry path unchanged — never self_certified.
  assert.equal(r.keyTrust?.status, 'registry_unavailable');
  assert.equal(r.keyTrust?.verified, false);
});

test('canary: a mismatch is fatal under any tier and with a registry that lists the key', async () => {
  for (const bindingTier of ['pseudonymous', 'oauth', 'did-web']) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_B, bindingTier });
    for (const provenance of [undefined, 'bundle', 'declared-url'] as const) {
      const r = await verifyCanary(c, registryFor(c, 'active'), provenance);
      assert.equal(r.signerIdentity?.status, 'key_derived_mismatch', `${bindingTier}/${provenance}`);
      assert.notEqual(r.keyTrust?.status, 'self_certified');
    }
  }
});

test('a key-derived identifier under a tier other than pseudonymous is never self_certified', async () => {
  for (const bindingTier of ['oauth', 'orcid', 'did-web', 'notarized', 'platform', 'organization']) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, bindingTier });
    const none = await verifyCanary(c);
    assert.equal(none.keyTrust?.status, 'registry_unavailable', bindingTier);
    assert.equal(none.signerIdentity?.status, 'key_derived_match', bindingTier);
    const noKid = await verifyCanary(buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, bindingTier, kid: null }));
    assert.equal(noKid.keyTrust?.status, 'legacy_embedded', bindingTier);
  }
});

test('a did:key:u… identifier is a fatal mismatch', async () => {
  const raw = ed25519.getPublicKey(RFC8032_T1_SECRET);
  const mc = new Uint8Array([0xed, 0x01, ...raw]);
  const uForm = `did:key:u${Buffer.from(mc).toString('base64url')}`;
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, identifier: uForm });
  const r = await verifyCanary(c);
  assert.deepEqual(r.signerIdentity, {
    status: 'key_derived_mismatch',
    claimed: uForm,
    derived: DID_RFC8032_T1,
  });
  assert.equal(r.keyTrust?.status, 'registry_unavailable');
});

test('any other key-derived spelling of the same key is a fatal mismatch', async () => {
  for (const identifier of [
    DID_RFC8032_T1.toLowerCase(),
    `${DID_RFC8032_T1} `,
    'did:key:',
    'did:key:z6MkNotAKeyAtAll',
  ]) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, identifier });
    const r = await verifyCanary(c);
    assert.equal(r.signerIdentity?.status, 'key_derived_mismatch', identifier);
    assert.equal(r.signerIdentity?.derived, DID_RFC8032_T1);
  }
});

test('kid (§5): optional, and one that resolves nowhere is not an error', async () => {
  const noKid = await verifyCanary(buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, kid: null }));
  assert.deepEqual(noKid.keyTrust, { status: 'self_certified', verified: false });
  assert.equal(noKid.signerIdentity?.status, 'key_derived_match');
  const otherKid = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, kid: 'label-with-no-registry' });
  const r = await verifyCanary(otherKid, adr0028Registry);
  assert.deepEqual(r.keyTrust, { status: 'self_certified', verified: false, kid: 'label-with-no-registry' });
  assert.equal(r.signerIdentity?.status, 'key_derived_match');
});

// --- 3. G2-B: a registry's provenance ------------------------------------

test('G2-B: a bundle-carried or provenance-less registry listing the key active leaves self_certified', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  for (const provenance of [undefined, 'bundle'] as const) {
    const r = await verifyCanary(c, registryFor(c, 'active'), provenance);
    assert.deepEqual(r.keyTrust, { status: 'self_certified', verified: false, kid: c.kid }, String(provenance));
    assert.equal(r.signerIdentity?.status, 'key_derived_match');
  }
});

test('G2-B: a bundle-carried or provenance-less registry listing the key revoked yields revoked', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  for (const provenance of [undefined, 'bundle'] as const) {
    const r = await verifyCanary(c, registryFor(c, 'revoked'), provenance);
    assert.equal(r.keyTrust?.status, 'revoked', String(provenance));
    assert.equal(r.keyTrust?.verified, false);
    assert.equal(r.signerIdentity?.status, 'key_derived_match');
  }
});

test('G2-B: a bundle-carried registry listing the key deprecated with no date yields deprecated_invalid', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  const r = await verifyCanary(c, registryFor(c, 'deprecated'), 'bundle');
  assert.equal(r.keyTrust?.status, 'deprecated_invalid');
});

test('G2-B: a registry fetched from the declared URL listing the key active yields active', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  const r = await verifyCanary(c, registryFor(c, 'active'), 'declared-url');
  assert.equal(r.keyTrust?.status, 'active');
  assert.equal(r.keyTrust?.verified, true);
  assert.equal(r.signerIdentity?.status, 'key_derived_match');
  const revoked = await verifyCanary(c, registryFor(c, 'revoked'), 'declared-url');
  assert.equal(revoked.keyTrust?.status, 'revoked');
});

test('G2-B: a registry that does not list the key changes nothing, from either source', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  for (const provenance of [undefined, 'bundle', 'declared-url'] as const) {
    const r = await verifyCanary(c, adr0028Registry, provenance);
    assert.deepEqual(r.keyTrust, { status: 'self_certified', verified: false, kid: c.kid }, String(provenance));
  }
});

test('G2-B: a registry recording a different identity for the kid is signer_identity_mismatch, from either source', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  for (const provenance of [undefined, 'bundle', 'declared-url'] as const) {
    const r = await verifyCanary(c, registryFor(c, 'active', 'https://example.org/someone-else'), provenance);
    assert.deepEqual(r.signerIdentity, {
      status: 'signer_identity_mismatch',
      claimed: c.identifier,
      registered: 'https://example.org/someone-else',
    });
  }
});

test('check #14 never reports ok under a key-derived identifier', async () => {
  const match = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  const swap = buildCanary({ identifierKey: KEY_A, signingKey: KEY_B });
  const registries = (c: Canary) => [
    undefined,
    adr0028Registry,
    registryFor(c, 'active'),
    registryFor(c, 'revoked'),
    registryFor(c, 'deprecated'),
    registryFor(c, 'active', 'https://example.org/someone-else'),
  ];
  for (const c of [match, swap]) {
    for (const registry of registries(c)) {
      for (const provenance of [undefined, 'bundle', 'declared-url'] as const) {
        const r = await verifyCanary(c, registry, provenance);
        assert.notEqual(r.signerIdentity?.status, 'ok');
      }
    }
  }
  // Called directly with no envelope key, the registry's agreeing identity is
  // not reported as `ok` either: nothing established the identifier.
  const direct = checkSignerIdentity(match.pkg, match.kid ?? undefined, registryFor(match, 'active'));
  assert.deepEqual(direct, { status: 'no_registry_identity', claimed: match.identifier });
});

test('check #14: a key that cannot be decoded is a key_derived_mismatch with no derived value', () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  const r = checkSignerIdentity(c.pkg, undefined, undefined, b64(Uint8Array.from([1, 2, 3])));
  assert.deepEqual(r, { status: 'key_derived_mismatch', claimed: c.identifier });
});

test('without the package, no key-derived check runs: key trust is the envelope-alone verdict', async () => {
  const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A });
  const r = await verifyRecord(
    { package: null, packageHash: c.packageHash, signature: c.signature, contentUnavailableReason: 'private' },
    { registry: undefined, fetch: failFetch },
  );
  assert.equal(r.keyTrust?.status, 'registry_unavailable');
  assert.equal(r.signerIdentity, null);
});

test('rules 2-3 as a table over every registry-path verdict', () => {
  const base = (status: KeyTrustResult['status']): KeyTrustResult => ({
    status,
    verified: status === 'active' || status === 'deprecated_valid',
    kid: 'k',
  });
  const expectFor: Record<string, { bundle: string; declared: string }> = {
    active: { bundle: 'self_certified', declared: 'active' },
    deprecated_valid: { bundle: 'self_certified', declared: 'deprecated_valid' },
    deprecated_invalid: { bundle: 'deprecated_invalid', declared: 'deprecated_invalid' },
    revoked: { bundle: 'revoked', declared: 'revoked' },
    unknown_key: { bundle: 'self_certified', declared: 'self_certified' },
    registry_unavailable: { bundle: 'self_certified', declared: 'self_certified' },
    legacy_embedded: { bundle: 'self_certified', declared: 'self_certified' },
  };
  for (const [status, want] of Object.entries(expectFor)) {
    const b = base(status as KeyTrustResult['status']);
    assert.equal(applySelfCertifiedKeyTrust(b, 'pseudonymous', undefined).status, want.bundle, status);
    assert.equal(applySelfCertifiedKeyTrust(b, 'pseudonymous', 'bundle').status, want.bundle, status);
    assert.equal(applySelfCertifiedKeyTrust(b, 'pseudonymous', 'declared-url').status, want.declared, status);
    // Any other tier (G2-B at any tier): a declared-URL registry decides; a
    // bundle-carried or provenance-less one may only lower, and a raising
    // verdict from it reads as the envelope alone (`registry_unavailable`).
    const otherTier = { ...want, bundle: want.bundle === 'self_certified' ? status : want.bundle };
    if (status === 'active' || status === 'deprecated_valid') otherTier.bundle = 'registry_unavailable';
    for (const provenance of [undefined, 'bundle'] as const) {
      const o = applySelfCertifiedKeyTrust(b, 'oauth', provenance);
      assert.equal(o.status, otherTier.bundle, `oauth/${provenance}/${status}`);
      if (o.status !== status) assert.deepEqual(o, { status: 'registry_unavailable', verified: false, kid: 'k' });
      else assert.equal(o, b);
    }
    assert.equal(applySelfCertifiedKeyTrust(b, 'oauth', 'declared-url'), b, status);
    const out = applySelfCertifiedKeyTrust(b, 'pseudonymous', 'bundle');
    if (out.status === 'self_certified') assert.equal(out.verified, false);
  }
  // A raising verdict with no kid (not reachable from verifyRecord, which only
  // consults a registry with a kid) reads as legacy_embedded.
  assert.deepEqual(
    applySelfCertifiedKeyTrust({ status: 'active', verified: true }, 'oauth', 'bundle'),
    { status: 'legacy_embedded', verified: false },
  );
});

const OTHER_TIERS = ['oauth', 'orcid', 'did-web', 'notarized', 'platform', 'organization'];

test('G2-B at any tier: a bundle-carried or provenance-less registry listing the key active is ignored (not active, verified: false)', async () => {
  for (const bindingTier of OTHER_TIERS) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, bindingTier });
    for (const provenance of [undefined, 'bundle'] as const) {
      const r = await verifyCanary(c, registryFor(c, 'active'), provenance);
      assert.deepEqual(
        r.keyTrust,
        { status: 'registry_unavailable', verified: false, kid: c.kid },
        `${bindingTier}/${provenance}`,
      );
      assert.equal(r.signerIdentity?.status, 'key_derived_match');
    }
  }
});

test('G2-B at any tier: a bundle-carried or provenance-less registry listing the key revoked yields revoked', async () => {
  for (const bindingTier of OTHER_TIERS) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, bindingTier });
    for (const provenance of [undefined, 'bundle'] as const) {
      const r = await verifyCanary(c, registryFor(c, 'revoked'), provenance);
      assert.equal(r.keyTrust?.status, 'revoked', `${bindingTier}/${provenance}`);
      assert.equal(r.keyTrust?.verified, false);
    }
  }
});

test('G2-B at any tier: a registry fetched from the declared URL listing the key active yields active', async () => {
  for (const bindingTier of OTHER_TIERS) {
    const c = buildCanary({ identifierKey: KEY_A, signingKey: KEY_A, bindingTier });
    const r = await verifyCanary(c, registryFor(c, 'active'), 'declared-url');
    assert.equal(r.keyTrust?.status, 'active', bindingTier);
    assert.equal(r.keyTrust?.verified, true);
    assert.equal(r.signerIdentity?.status, 'key_derived_match');
  }
});

// --- 4. The ADR-0028 package is unaffected ---------------------------------

const ADR0028_PACKAGE = JSON.parse(
  readFileSync(new URL('./__fixtures__/adr-0028-recomputation.package.json', import.meta.url), 'utf8'),
) as Record<string, unknown>;
/** The signature envelope of `package/recomputation.commitment.json` at 9031a94. */
const ADR0028_ENVELOPE_HASH = 'abb93f781ae71480bf8075474facbb272f3dcc38d50eeecda79be33427924a9c';
const ADR0028_SIGNATURE = {
  signature: 'RbjeWhO1oj+G5He60jRwKrg0tv+4t3Uzpuw4ALOPxnUcT1pXIRRZzerhqzsH47BgfDwv9x8OmLan518d6zrkCA==',
  publicKey: adr0028Registry.keys[0]!.publicKey,
  algorithm: 'Ed25519ph',
  kid: 'eval-run-example:ed25519-2026-09',
};

test('ADR-0028 package: not key-derived, so its key trust and #14 are unchanged by any provenance', async () => {
  const signer = ADR0028_PACKAGE['signer'] as { identifier: string; bindingTier: string };
  assert.equal(signer.bindingTier, 'pseudonymous');
  assert.equal(isKeyDerivedIdentifier(signer.identifier), false);
  const results: VerifyResult[] = [];
  for (const provenance of [undefined, 'bundle', 'declared-url'] as const) {
    const r = await verifyRecord(
      { package: ADR0028_PACKAGE, packageHash: ADR0028_ENVELOPE_HASH, signature: ADR0028_SIGNATURE },
      { registry: adr0028Registry, fetch: failFetch, ...(provenance ? { registryProvenance: provenance } : {}) },
    );
    assert.equal(r.hashMatch, true);
    assert.equal(r.signatureValid, true);
    assert.equal(r.keyTrust?.status, 'active');
    assert.equal(r.keyTrust?.verified, true);
    assert.deepEqual(r.signerIdentity, {
      status: 'ok',
      claimed: 'https://github.com/npstorey',
      registered: 'https://github.com/npstorey',
    });
    results.push(r);
  }
  assert.deepEqual(results[1], results[0]);
  assert.deepEqual(results[2], results[0]);
});
