// Trust registry types + key-trust evaluation (spec §8.3.3, §9.2 check #5) —
// browser-safe.
//
// The platform publishes its authorized signing keys at a `/.well-known/*`
// registry. Verification treats it as the source of truth for which
// `(kid, publicKey)` pairs are allowed and their rotation state: keys absent or
// revoked fail verification regardless of cryptographic correctness — a locally
// valid signature from an unrecognised key is still not "trusted evidence".
//
// These functions are pure (registry passed IN as data). The server `verify.ts`
// keeps the registry LOADER (build-time embedded import + fs + fetch fallback,
// all server-only); WS3's browser client fetches the registry from the sidecar's
// `trustRegistryUrl`. Both then hand the parsed registry to `verifyKeyTrust`.

import type { SignerIdentity } from './types.ts';

export type KeyLifecycleStatus = 'active' | 'deprecated' | 'revoked';

export interface TrustRegistryKey {
  kid: string;
  publicKey: string;
  status: KeyLifecycleStatus;
  activatedAt: string;
  deprecatedAt: string | null;
  revokedAt: string | null;
  /** Identity the `kid` is bound to (spec §8.3.3). Verify check #14 cross-checks
   *  a package's envelope-side `signer.identifier` against this. Optional:
   *  legacy registries omit it, and verifiers then skip the cross-check (treating
   *  the binding as `legacy_embedded`). */
  signerIdentity?: SignerIdentity;
}

export interface TrustRegistry {
  keys: TrustRegistryKey[];
}

export const KEY_TRUST_STATUSES = [
  'active',                // active key — package is trusted
  'deprecated_valid',      // deprecated key, but package was signed before deprecation
  'deprecated_invalid',    // deprecated key, but package was signed after deprecation
  'revoked',               // revoked key — package is never trusted
  'unknown_key',           // (kid, publicKey) pair not found in registry
  'registry_unavailable',  // registry could not be loaded
  'legacy_embedded',       // signed with an embedded key, no registry kid stored
] as const;
export type KeyTrustStatus = (typeof KEY_TRUST_STATUSES)[number];

export interface KeyTrustResult {
  status: KeyTrustStatus;
  /** `true` iff the status is `active` or `deprecated_valid`. Legacy-embedded
   *  signatures are intentionally surfaced as `verified: false` because the
   *  trust registry cannot vouch for them — the UI renders them as neutral
   *  rather than failed. */
  verified: boolean;
  /** The registry `kid` when available. Omitted for `legacy_embedded` /
   *  pre-registry packages because the signature has no kid to report. */
  kid?: string;
  activatedAt?: string;
  deprecatedAt?: string | null;
  revokedAt?: string | null;
}

/**
 * Build a `KeyTrustResult` for a package whose signature predates the trust
 * registry — i.e. has a valid public key but no `kid`. We accept that the
 * embedded key verified the signature mathematically while making clear in the
 * UI that no registry check was performed.
 */
export function legacyEmbeddedKeyTrust(): KeyTrustResult {
  return { status: 'legacy_embedded', verified: false };
}

/**
 * Verify that a `(kid, publicKey)` pair is trusted by the platform registry,
 * applying the rotation semantics documented in the P5 plan:
 *   - `active` → trusted.
 *   - `deprecated` → trusted only when `packageIntegratedTime` precedes
 *     `deprecatedAt` (preventive rotation — pre-deprecation signatures remain
 *     valid, signatures after the rotation point do not).
 *   - `revoked` → never trusted (compromise — any signature during the exposure
 *     window is treated as suspect).
 *   - unknown pair → never trusted.
 *
 * The registry is passed in rather than fetched here so the caller can cache it
 * and so the function stays pure for unit testing.
 */
export function verifyKeyTrust(
  publicKey: string,
  kid: string,
  /** Rekor `integratedTime`, seconds since epoch. `undefined` when the package
   *  has no Rekor entry or when Rekor verification failed. */
  packageIntegratedTime: number | undefined,
  registry: TrustRegistry | undefined,
): KeyTrustResult {
  if (!registry) {
    return { status: 'registry_unavailable', verified: false, kid };
  }

  const match = registry.keys.find(
    (k) => k.kid === kid && k.publicKey === publicKey,
  );
  if (!match) {
    return { status: 'unknown_key', verified: false, kid };
  }

  if (match.status === 'revoked') {
    return {
      status: 'revoked',
      verified: false,
      kid,
      activatedAt: match.activatedAt,
      revokedAt: match.revokedAt,
    };
  }

  if (match.status === 'deprecated') {
    // Without a deprecation timestamp we cannot evaluate the time-bounded rule,
    // so fail closed.
    if (!match.deprecatedAt) {
      return { status: 'deprecated_invalid', verified: false, kid };
    }
    // Without a Rekor integratedTime we cannot prove the package was signed
    // before deprecation either — fail closed.
    if (packageIntegratedTime === undefined) {
      return {
        status: 'deprecated_invalid',
        verified: false,
        kid,
        activatedAt: match.activatedAt,
        deprecatedAt: match.deprecatedAt,
      };
    }
    const deprecationMs = new Date(match.deprecatedAt).getTime();
    const integratedMs = packageIntegratedTime * 1000;
    if (integratedMs < deprecationMs) {
      return {
        status: 'deprecated_valid',
        verified: true,
        kid,
        activatedAt: match.activatedAt,
        deprecatedAt: match.deprecatedAt,
      };
    }
    return {
      status: 'deprecated_invalid',
      verified: false,
      kid,
      activatedAt: match.activatedAt,
      deprecatedAt: match.deprecatedAt,
    };
  }

  return {
    status: 'active',
    verified: true,
    kid,
    activatedAt: match.activatedAt,
  };
}

/**
 * Structural validation of a parsed trust-registry document. Pure, so both the
 * server loader and WS3's browser fetch can validate before trusting the keys.
 * Mirrors the shape the server loader enforced inline.
 */
export function validateRegistry(data: unknown): TrustRegistry | undefined {
  if (
    typeof data === 'object' &&
    data !== null &&
    Array.isArray((data as { keys?: unknown[] }).keys) &&
    (data as { keys: TrustRegistryKey[] }).keys.every(
      (k) => typeof k?.kid === 'string' && typeof k?.publicKey === 'string',
    )
  ) {
    return data as TrustRegistry;
  }
  return undefined;
}
