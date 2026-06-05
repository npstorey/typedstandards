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
  return PROFILE_CAPTURE_VOCAB[resolveProfileType(producerProfile, contentProfile)];
}
