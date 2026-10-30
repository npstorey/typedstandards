// Producer Profile → captureMethod vocabulary (spec §8.6, ADR-0011) —
// browser-safe. Already pure on the server; factored into verify-core (WS2) so
// the §8.6 vocabulary resolution (verify check #15) runs identically off-platform.
// The server `profiles.ts` re-exports this. The hardcoded fallback table is the
// Q32 stand-in until versioned, content-addressed guidance bundles ship.

import type { CaptureMethod } from './types.ts';

/** Hardcoded per-profile-type captureMethod vocabulary (Q32 fallback). */
export const PROFILE_CAPTURE_VOCAB: Record<string, readonly CaptureMethod[]> = {
  'ai-assisted-analysis': [
    'chat-flow-stream',
    'claude-code-jsonl-readback',
    'claude-code-self-report',
  ],
  // Status note, 2026-09-21 (hub ADR-0029 §2, Q32 still open): a second
  // stand-in entry. A program computed the content from inputs pinned by hash;
  // `script-run` = a packaging program read files already on disk, `tool-emitted`
  // = the computing program wrote the package itself. The guidance-bundle routing
  // convention that replaces this table is not settled by this entry.
  'scripted-recomputation': ['script-run', 'tool-emitted'],
};

/**
 * Resolve a package's Producer Profile *type* (the segment before the first `/`
 * of the compound `<profile-type>/<profile-subtype>` value) from its
 * `producerProfile`, applying the spec §8.6 step-1 fallbacks:
 *   - `producerProfile` present            → its profile-type segment.
 *   - absent + contentProfile==='datHere'  → legacy alias
 *     `ai-assisted-analysis/datHere` → `ai-assisted-analysis`.
 *   - both absent (pre-v0.1)               → implicit `ai-assisted-analysis`
 *     (every pre-existing package was AI-mediated by construction).
 */
export function resolveProfileType(
  producerProfile?: string | null,
  contentProfile?: string | null,
): string {
  const profile =
    producerProfile ??
    (contentProfile === 'datHere'
      ? 'ai-assisted-analysis/datHere'
      : 'ai-assisted-analysis');
  return profile.split('/')[0];
}

/**
 * The captureMethod vocabulary declared by a package's Producer Profile, or
 * `undefined` when the profile type has no resolvable bundle (verify check #15's
 * `producerProfile_bundle_unresolved` degraded case).
 */
export function captureVocabForProfile(
  producerProfile?: string | null,
  contentProfile?: string | null,
): readonly CaptureMethod[] | undefined {
  const profileType = resolveProfileType(producerProfile, contentProfile);
  return Object.hasOwn(PROFILE_CAPTURE_VOCAB, profileType) ? PROFILE_CAPTURE_VOCAB[profileType] : undefined;
}

// --- The subtype table (spec §8.1.1 and §8.6; hub ADR-0038 §3 and §5) ---
//
// Beside the profile-type table above: one row per built subtype of
// `ai-assisted-analysis`, naming the `metadata.contentProfile` values the
// subtype admits and, where one is pinned, its guidance bundle by URL and
// SHA-256. The specification states the rows; this table mirrors them. The row
// does not change the capture vocabulary, which stays the profile type's (check
// #15 reads the table above, not this one).

/** A guidance bundle pinned by its address and the SHA-256 of its bytes. */
export interface ProducerProfileBundleRef {
  readonly url: string;
  /** Lowercase hex SHA-256 of the bundle file's bytes. */
  readonly sha256: string;
}

/** One built subtype's row. */
export interface ProducerProfileSubtypeRow {
  /** The `metadata.contentProfile` values the subtype admits. */
  readonly admits: readonly string[];
  /** The subtype's guidance bundle, when one is pinned. */
  readonly bundle?: ProducerProfileBundleRef;
}

/**
 * The subtype table, keyed by the full `producerProfile` value. The
 * `ai-assisted-analysis/civicaitools-v1` bundle is revision 1 (2026-10-30), as
 * hub ADR-0038 §5 records its address and digest; a later revision moves the
 * digest and this pin, and nothing else.
 */
export const PRODUCER_PROFILE_SUBTYPES: Readonly<Record<string, ProducerProfileSubtypeRow>> = Object.freeze({
  // No bundle pinned: the integration partner's, not this table's to name.
  'ai-assisted-analysis/datHere': Object.freeze({ admits: Object.freeze(['datHere']) }),
  'ai-assisted-analysis/civicaitools-v1': Object.freeze({
    admits: Object.freeze(['datHere', 'default']),
    bundle: Object.freeze({
      url: 'https://raw.githubusercontent.com/npstorey/civic-ai-tools/v0.1.13-typed-standards-spec/docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json',
      sha256: '724e399e02db8993041b64982eec731505084bec2ec5e6ca58fda2de8087a281',
    }),
  }),
});

const DATHERE_PREFIX = 'ai-assisted-analysis/datHere';

/**
 * The §8.1.1 consistency invariant, for a package that carries both
 * `producerProfile` and `metadata.contentProfile`: whether the content profile is
 * one the subtype's row admits. A subtype with no row admits `"datHere"` exactly
 * when it begins with `ai-assisted-analysis/datHere`, and `"default"` exactly when
 * it does not: the reading every earlier release applied, so a record whose
 * subtype has no row reads as before. Check #16 reads it.
 */
export function isContentProfileConsistent(producerProfile: string, contentProfile: string): boolean {
  if (Object.hasOwn(PRODUCER_PROFILE_SUBTYPES, producerProfile)) {
    return PRODUCER_PROFILE_SUBTYPES[producerProfile].admits.includes(contentProfile);
  }
  return producerProfile.startsWith(DATHERE_PREFIX) ? contentProfile === 'datHere' : contentProfile === 'default';
}
