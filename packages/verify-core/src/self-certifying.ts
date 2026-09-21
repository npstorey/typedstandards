// The self-certifying signer's key-trust rule (hub ADR-0030 §3, §4) —
// browser-safe. Internal to verify-core: `verifyRecord` applies it; the
// package entry point does not re-export it.

import type { SignerIdentity } from './types.ts';
import type { KeyTrustResult, TrustRegistryProvenance } from './trust-registry.ts';
import { deriveKeyDerivedIdentifier, isKeyDerivedIdentifier } from './did-key.ts';

/** The one `bindingTier` under which a derived match is `self_certified`. */
const SELF_CERTIFYING_TIER = 'pseudonymous';

/** Verdicts that say the key must not be trusted for this signature. A
 *  bundle-carried registry may report these about a self-certified signer. */
const LOWERING_STATUSES: ReadonlySet<string> = new Set(['revoked', 'deprecated_invalid']);

/** Verdicts that mean no registry listed the envelope's `(kid, publicKey)`. */
const UNLISTED_STATUSES: ReadonlySet<string> = new Set([
  'registry_unavailable',
  'unknown_key',
  'legacy_embedded',
]);

/** The outcome of comparing a key-derived `signer.identifier` with the
 *  identifier derived from the envelope's `publicKey` (ADR-0030 §2). */
export interface KeyDerivedComparison {
  claimed: string;
  /** Absent when the derivation failed (a malformed key). */
  derived?: string;
  match: boolean;
}

/**
 * Compare the package's `signer.identifier` with the identifier derived from
 * the envelope's `publicKey`. Returns `null` when the self-certifying check
 * does not run: no signer, an identifier that is not key-derived, or no
 * envelope key. A failed derivation is a mismatch with no `derived` value.
 */
export function compareKeyDerivedIdentifier(
  signer: unknown,
  publicKey: string | undefined,
): KeyDerivedComparison | null {
  if (!signer || typeof signer !== 'object') return null;
  const claimed = (signer as SignerIdentity).identifier;
  if (!isKeyDerivedIdentifier(claimed) || !publicKey) return null;
  let derived: string;
  try {
    derived = deriveKeyDerivedIdentifier(publicKey);
  } catch {
    return { claimed, match: false };
  }
  return { claimed, derived, match: derived === claimed };
}

/**
 * G2-B for a key-derived identifier, whether or not it matched its envelope
 * key (ADR-0030 §4 rule 3 as amended; spec v0.1.9 §9.4): only a registry
 * fetched from the declared `trustRegistryUrl` can raise the status. Returns
 * `base` unless it is a raising verdict (`active`, `deprecated_valid`) from a
 * bundle-carried or provenance-less registry; that verdict is ignored and the
 * status is what the envelope alone yields with no registry supplied
 * (`registry_unavailable` with a `kid`, `legacy_embedded` without),
 * `verified: false`. Lowering and unlisted verdicts pass through.
 */
export function applyKeyDerivedRegistryRule(
  base: KeyTrustResult,
  provenance: TrustRegistryProvenance | undefined,
): KeyTrustResult {
  if (provenance === 'declared-url') return base;
  if (UNLISTED_STATUSES.has(base.status) || LOWERING_STATUSES.has(base.status)) return base;
  return base.kid !== undefined
    ? { status: 'registry_unavailable', verified: false, kid: base.kid }
    : { status: 'legacy_embedded', verified: false };
}

/**
 * Apply ADR-0030 §4 rules 2-3, as amended at gate G2, to the registry-path
 * verdict `base`, for a package whose key-derived identifier MATCHED its
 * envelope key. (A mismatch takes `applyKeyDerivedRegistryRule` alone.)
 *
 * For a key-derived identifier, at any `bindingTier`:
 *   - A registry from the declared `trustRegistryUrl` that lists the
 *     envelope's `(kid, publicKey)` decides: its verdict stands.
 *   - Any other registry (bundle-carried, or no stated provenance)
 *     contributes only a lowering verdict (`revoked`, `deprecated_invalid`).
 *     A raising one (`active`, `deprecated_valid`) is ignored.
 *   - With no registry listing the key, or a raising verdict ignored, the
 *     status is `self_certified` at `pseudonymous`; at any other tier it is
 *     what the envelope alone yields with no registry supplied
 *     (`registry_unavailable` with a `kid`, `legacy_embedded` without) — never
 *     `active`, never `verified: true`. `self_certified` is reserved for the
 *     `pseudonymous` rung (§3).
 */
export function applySelfCertifiedKeyTrust(
  base: KeyTrustResult,
  bindingTier: unknown,
  provenance: TrustRegistryProvenance | undefined,
): KeyTrustResult {
  const listed = !UNLISTED_STATUSES.has(base.status);
  if (listed && (provenance === 'declared-url' || LOWERING_STATUSES.has(base.status))) {
    return base;
  }
  if (bindingTier !== SELF_CERTIFYING_TIER) {
    // Unlisted: the registry path's own verdict is unchanged. Listed with a
    // raising verdict from a registry that may not raise: the envelope alone.
    return applyKeyDerivedRegistryRule(base, provenance);
  }
  return {
    status: 'self_certified',
    verified: false,
    ...(base.kid !== undefined ? { kid: base.kid } : {}),
  };
}
