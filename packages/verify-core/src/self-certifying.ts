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
 * Apply ADR-0030 §4 rules 2-3 to the registry-path verdict `base`, for a
 * package whose key-derived identifier MATCHED its envelope key (rule 1 —
 * a mismatch — leaves `base` unchanged, and the caller does not call this).
 *
 *   - Under any `bindingTier` other than `pseudonymous`, `base` stands: the
 *     status `self_certified` is reserved for that rung (§3).
 *   - No registry lists the envelope's `(kid, publicKey)` → `self_certified`.
 *   - A registry from the declared `trustRegistryUrl` lists it → its verdict
 *     stands.
 *   - Any other registry (bundle-carried, or no stated provenance) lists it →
 *     a lowering verdict (`revoked`, `deprecated_invalid`) stands; a raising
 *     one (`active`, `deprecated_valid`) leaves `self_certified`.
 */
export function applySelfCertifiedKeyTrust(
  base: KeyTrustResult,
  bindingTier: unknown,
  provenance: TrustRegistryProvenance | undefined,
): KeyTrustResult {
  if (bindingTier !== SELF_CERTIFYING_TIER) return base;
  const selfCertified: KeyTrustResult = {
    status: 'self_certified',
    verified: false,
    ...(base.kid !== undefined ? { kid: base.kid } : {}),
  };
  if (UNLISTED_STATUSES.has(base.status)) return selfCertified;
  if (provenance === 'declared-url') return base;
  if (LOWERING_STATUSES.has(base.status)) return base;
  return selfCertified;
}
