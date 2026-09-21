// Trust-signal vocabulary — the severity taxonomy that turns each verify-core
// status into a calm, plain-language signal. Ported from civic-ai-tools-website
// (#110) for the typedstandards.org verifier (#116 WS3 Phase C).
//
// One idea threads the trust-communication surface: every verification status
// renders as `{ tier, icon, plain-language one-liner }`, defined once here and
// reused. The load-bearing requirement is that a pre-v0.1 (legacy) package — which
// produces many "not ok but expected" statuses — reads CALM, never as a string of
// failures.
//
// Total coverage holds *by construction*: each status space is keyed with
// `Record<Status, ...>`, so a status added upstream grows the union type and the
// compiler then demands a tier here. The status TYPES are imported from the
// published @typedstandards/verify-core — the single source of the check verdicts
// — so this copy of the vocabulary is structurally pinned to the package's status
// unions and cannot silently drift from the checks it describes. The imports are
// TYPE-ONLY, so this module carries no runtime dependency on the verify core: it is
// pure data, safe to import from a client component.
//
// Design principles cited by number: P1 disclosure ≠ validation, P3 no false
// precision, P5 narrative bridge, P9 user language.

import type {
  EnvelopeIntegrityResult,
  ContentCanonicalizationStatus,
  ContentHashStatus,
  KeyTrustStatus,
  TypeResolutionStatus,
  SignerIdentityCheckStatus,
  CaptureMethodVocabStatus,
  LifecycleStatus,
  LifecycleSource,
  BlobRefVerifyReason,
  CaptureMethod,
  ContentProfileStatus,
} from '@typedstandards/verify-core';

// --- Tiers ---------------------------------------------------------------

/**
 * The four severity tiers. "Not `ok`" does not mean "broken":
 *   - `verified`  — green; an affirmative check passed.
 *   - `normal`    — neutral/calm/informational. "Not ok" but EXPECTED (every
 *                   pre-v0.1 legacy status lands here). NOT a warning.
 *   - `attention` — amber; something UNCONFIRMED / unrecognized, not proven-bad.
 *   - `alarm`     — red; a genuine integrity failure.
 */
export type TrustTier = 'verified' | 'normal' | 'attention' | 'alarm';

/** The four in-house glyphs, one per tier. Names only — the SVGs live in the
 *  presentational `<TrustSignal>` component (client-side). */
export type TrustIconName = 'check' | 'info' | 'warning' | 'error';

export interface TrustSignalDescriptor {
  tier: TrustTier;
  /** The glanceable plain-language one-liner (P5 glance layer, P9 user
   *  language). Disclosure, never validation (P1). */
  label: string;
  /** Optional expand-on-demand sentence (P5 narrative bridge / P8). */
  detail?: string;
}

export interface TierMeta {
  /** The tier's default glyph (overridable per-instance in the component). */
  icon: TrustIconName;
  /** CSS custom-property reference for the tier color (globals.css). */
  colorVar: string;
  /** aria-label applied to the tier glyph. */
  ariaLabel: string;
}

/**
 * Canonical tier → { icon, color, aria } mapping. The single source of truth for
 * tier visuals: the `<TrustSignalBadge>` component consumes this directly (it is a
 * client-safe value because this module is pure data). The color tokens are the
 * typedstandards.org `--trust-*` design tokens defined in globals.css.
 */
export const TIER_META: Record<TrustTier, TierMeta> = {
  verified: { icon: 'check', colorVar: 'var(--trust-verified)', ariaLabel: 'Verified' },
  normal: { icon: 'info', colorVar: 'var(--trust-normal)', ariaLabel: 'Informational' },
  attention: { icon: 'warning', colorVar: 'var(--trust-attention)', ariaLabel: 'Attention' },
  alarm: { icon: 'error', colorVar: 'var(--trust-alarm)', ariaLabel: 'Alarm' },
};

/** A descriptor plus the icon its tier resolves to — the full `status →
 *  { tier, icon, copy }` shape. */
export interface ResolvedTrustSignal extends TrustSignalDescriptor {
  icon: TrustIconName;
}

/** Attach the tier's default icon to a descriptor. */
export function toResolvedSignal(d: TrustSignalDescriptor): ResolvedTrustSignal {
  return { ...d, icon: TIER_META[d.tier].icon };
}

// --- Boolean-state normalizers -------------------------------------------
//
// Several verify checks are tri-state booleans (true / false / null) or
// bi-state (true / false). We key their signal maps on string forms so the
// maps stay plain data and the coverage test can enumerate them.

export type BiStateKey = 'true' | 'false';
export type TriStateKey = 'true' | 'false' | 'null';

export const BI_STATE_KEYS: readonly BiStateKey[] = ['true', 'false'];
export const TRI_STATE_KEYS: readonly TriStateKey[] = ['true', 'false', 'null'];

export function biKey(v: boolean): BiStateKey {
  return v ? 'true' : 'false';
}
export function triKey(v: boolean | null | undefined): TriStateKey {
  return v === null || v === undefined ? 'null' : v ? 'true' : 'false';
}

// =========================================================================
// Per-check status → descriptor maps, ordered by spec §9.2 check number.
// =========================================================================

// --- #1 Envelope integrity (TRI-STATE: verified / altered / unavailable) --
//
// The boolean conflation is gone (verify-core 0.7.0 / #21). A package whose content
// is UNAVAILABLE — a content-private record whose commitment omits the location, or
// a stated location whose bytes couldn't be fetched — cannot have its envelope hash
// recomputed, and that is NOT tampering. verify-core reports `envelopeIntegrity` as
// `{ status, reason }`; this resolver maps the FOUR readings onto tiers:
//   - verified                  → green     (bytes present, hash matches)
//   - altered                   → ALARM     (bytes present, hash MISMATCHES — real tampering)
//   - unavailable + private     → NEUTRAL   (content private — N/A; same calm family as
//                                            "no timestamp"; never amber/red)
//   - unavailable + unfetchable → attention (an availability problem — unconfirmed, not bad)

export const ENVELOPE_INTEGRITY_VERIFIED: TrustSignalDescriptor = {
  tier: 'verified',
  label: 'Contents unchanged since signing',
  detail: 'The bytes of this package match the hash that was signed.',
};
// Load-bearing twin of VERIFIED, opposite tier — the bytes were fetched and do NOT
// hash to the signed value. This is the only envelope-integrity case that alarms.
export const ENVELOPE_INTEGRITY_ALTERED: TrustSignalDescriptor = {
  tier: 'alarm',
  label: 'Contents changed since signing',
  detail:
    'The recomputed hash does not match the signed package — it may have been altered.',
};
// Content private by design (the commitment redacted the location). NEUTRAL, never a
// failure. Vocabulary-NEUTRAL copy on purpose: it says "content private", NOT "sealed"
// — the committed→sealed UI rename (ADR-0016) is a separate post-demo sweep.
export const ENVELOPE_INTEGRITY_CONTENT_PRIVATE: TrustSignalDescriptor = {
  tier: 'normal',
  label: 'Content is private — integrity can’t be recomputed here',
  detail:
    'This package’s content is private, so its bytes can’t be fetched and the envelope hash can’t be recomputed here. The public commitment — signature, signing key, timestamp, and transparency-log entry — is still fully verifiable.',
};
// A present location whose bytes couldn't be retrieved (404 / network). Attention, not
// alarm: an availability gap is unconfirmed, not proof of alteration.
export const ENVELOPE_INTEGRITY_UNAVAILABLE: TrustSignalDescriptor = {
  tier: 'attention',
  label: 'Content could not be retrieved',
  detail:
    'This package names a content location, but its bytes could not be fetched, so the envelope hash was not recomputed. This is an availability problem, not proof of alteration.',
};

/** Resolve the tri-state envelope-integrity verdict (#1). The `unavailable` status
 *  splits on `reason`: a by-design `private` redaction is the calm NEUTRAL reading,
 *  an `unfetchable` location is the Attention reading. Only `altered` alarms. */
export function resolveEnvelopeIntegrity(
  integrity: EnvelopeIntegrityResult,
): TrustSignalDescriptor {
  switch (integrity.status) {
    case 'verified':
      return ENVELOPE_INTEGRITY_VERIFIED;
    case 'altered':
      return ENVELOPE_INTEGRITY_ALTERED;
    case 'unavailable':
      return integrity.reason === 'private'
        ? ENVELOPE_INTEGRITY_CONTENT_PRIVATE
        : ENVELOPE_INTEGRITY_UNAVAILABLE;
  }
}

// --- #2 Signature mathematics (signatureValid: boolean | null) -----------

export const SIGNATURE_SIGNALS: Record<TriStateKey, TrustSignalDescriptor> = {
  true: {
    tier: 'verified',
    label: 'Valid cryptographic signature',
    detail: 'The signature verifies against the signing key.',
  },
  false: {
    tier: 'alarm',
    label: 'Signature does not verify',
    detail: 'The signature could not be validated against the signing key.',
  },
  null: {
    tier: 'normal',
    label: 'Not signed',
    detail: 'This package carries no cryptographic signature.',
  },
};
export const resolveSignature = (v: boolean | null): TrustSignalDescriptor =>
  SIGNATURE_SIGNALS[triKey(v)];

// --- #3 Content canonicalization rule resolution -------------------------

export const CONTENT_CANONICALIZATION_SIGNALS: Record<
  ContentCanonicalizationStatus,
  TrustSignalDescriptor
> = {
  ok: { tier: 'verified', label: 'Canonicalization rule recognized' },
  implicit: {
    tier: 'normal',
    label: 'Canonicalization inferred (earlier-format package)',
    detail:
      'This package predates explicit canonicalization labeling; the rule was inferred from its content profile.',
  },
  unknown_canonicalization_rule: {
    tier: 'attention',
    label: 'Unrecognized canonicalization rule',
    detail:
      'This package names a canonicalization rule this verifier does not recognize, so its content hash cannot be recomputed.',
  },
};

// --- #4 Content hash verification (THE load-bearing split) ---------------

export const CONTENT_HASH_SIGNALS: Record<ContentHashStatus, TrustSignalDescriptor> = {
  ok: {
    tier: 'verified',
    label: 'Content matches its fingerprint',
    detail: 'The off-log content hashes to the value the signature covers.',
  },
  // Load-bearing: applies to EVERY pre-v0.1 package. Must read calm.
  legacy_relabeled: {
    tier: 'normal',
    label: 'Earlier-format content fingerprint',
    detail:
      'This package predates multi-hash content fingerprints; its original single hash is shown as-is, and its integrity is established by the envelope check.',
  },
  // Load-bearing: the same check as legacy_relabeled, opposite tier — off-log
  // content was altered after signing.
  content_hash_mismatch: {
    tier: 'alarm',
    label: 'Content does not match its fingerprint',
    detail:
      'The off-log content does not hash to the signed value — it may have been altered.',
  },
  unresolved_rule: {
    tier: 'attention',
    label: 'Content hash not recomputed (unknown rule)',
    detail:
      'The canonicalization rule could not be resolved, so the content hash was not recomputed.',
  },
  contentHash_no_supported_algorithm: {
    tier: 'attention',
    label: 'Content hash uses an unsupported algorithm',
    detail:
      'The content fingerprint lists only hash algorithms this verifier cannot compute, so it could not be confirmed.',
  },
  // raw-bytes/v1 with a BlobRef output: the file could not be obtained, so its
  // bytes were not hashed. Unconfirmed, not altered — the tier the envelope check
  // gives an unfetchable content location.
  content_bytes_unavailable: {
    tier: 'attention',
    label: 'Content file not checked',
    detail:
      'The file this package fingerprints could not be obtained, so its bytes were not hashed and the content fingerprint was not checked.',
  },
};

// --- #5 Trust-registry verdict (keyTrust) --------------------------------

export const KEY_TRUST_SIGNALS: Record<KeyTrustStatus, TrustSignalDescriptor> = {
  active: {
    tier: 'verified',
    label: 'Signed with an active registered key',
    detail: 'The signing key is listed and active in the publisher’s trust registry.',
  },
  deprecated_valid: {
    tier: 'normal',
    label: 'Signed before the key was rotated out',
    detail:
      'The signing key has since been rotated out, but this package was signed while it was still valid.',
  },
  deprecated_invalid: {
    tier: 'alarm',
    label: 'Signed after the key was rotated out',
    detail: 'This package was signed after its key was deprecated — it is not trusted.',
  },
  revoked: {
    tier: 'alarm',
    label: 'Signed with a revoked key',
    detail: 'The signing key has been revoked — this package is not trusted.',
  },
  unknown_key: {
    tier: 'attention',
    label: 'Signing key not in the trust registry',
    detail:
      'The signing key is not listed in the publisher’s trust registry, so it cannot vouch for it.',
  },
  registry_unavailable: {
    tier: 'attention',
    label: 'Trust registry could not be reached',
    detail: 'The trust registry could not be loaded, so the key status was not checked.',
  },
  // Load-bearing: any package signed with an embedded key that carries no
  // registry kid — genuinely-old packages AND recent ones signed before kid
  // storage. Must read calm. Speaks ONLY to key trust (P7): the signature
  // itself is check #2 and is never asserted here (older copy claimed "its
  // signature verified against its embedded key", which contradicted a #2
  // failure on any no-kid package whose signature did not verify).
  legacy_embedded: {
    tier: 'normal',
    label: 'Signed with an embedded key (not in the trust registry)',
    detail:
      'The signature uses an embedded public key that is not listed in the publisher’s trust registry, so it cannot vouch for it.',
  },
  // Hub ADR-0030 §10: calm, never `verified` — the identifier proves the same
  // key signed, not who holds it.
  self_certified: {
    tier: 'normal',
    label: 'Signed with a self-certifying key',
    detail:
      "The signer's identifier is derived from the signing key, so it proves that the same key signed everything under this identifier — not who holds the key. No registry vouches for it, and the key cannot be rotated or revoked.",
  },
};

/**
 * #5 under a key-derived signer identifier (hub ADR-0030 §4 rule 3, as amended
 * at G2): a registry carried in the bundle listed the key with a verdict that
 * would raise the status, and verify-core set that verdict aside, returning
 * `registry_unavailable`. That status's own sentence ("could not be loaded")
 * under-describes this case, so the site renders this descriptor in its place
 * when it knows both facts: the identifier is key-derived and the registry was
 * read from the bundle. Same tier as `registry_unavailable`; no new status.
 */
export const KEY_TRUST_BUNDLE_REGISTRY_NOT_USED: TrustSignalDescriptor = {
  tier: 'attention',
  label: 'Key status not established — the bundle’s registry was not used',
  detail:
    'A trust registry came with this bundle and lists the signing key, but a registry carried in the bundle cannot raise the key status of a signer whose identifier is derived from its key. Only a registry fetched from the URL the record declares can. The key status was not established.',
};

/**
 * Calm reading for a package with NO signing key at all. The verify route emits
 * `keyTrust: null` only for an unsigned package (it co-occurs with
 * `signatureValid: null`), so "no key to check" is an expected, Normal state —
 * never a failure. Defined here, not hand-rolled in the component, so the tier
 * decision keeps a single source of truth.
 */
export const NO_SIGNING_KEY_SIGNAL: TrustSignalDescriptor = {
  tier: 'normal',
  label: 'No signing key',
  detail:
    'This package carries no signing key, so there is nothing to check against the trust registry.',
};

/** Resolve the trust-registry verdict, folding the unsigned (`null`) case into
 *  the calm `NO_SIGNING_KEY_SIGNAL` so consumers never branch on a missing key. */
export function resolveKeyTrust(
  keyTrust: { status: KeyTrustStatus } | null | undefined,
): TrustSignalDescriptor {
  return keyTrust ? KEY_TRUST_SIGNALS[keyTrust.status] : NO_SIGNING_KEY_SIGNAL;
}

// --- #7 RFC 3161 timestamp (DEEP: chain-verified to a pinned TSA root) ----
// As of verify-core 0.6.0 (#119 P2b) the token is cryptographically verified
// offline — TSA signature + embedded cert chain to the pinned FreeTSA root — not
// merely detected. So the signal is driven by that verdict, not presence: a present-
// but-unverified (e.g. forged) token reads as alarm, an absent one stays calm.

export const TIMESTAMP_SIGNALS = {
  verified: {
    tier: 'verified',
    label: 'Timestamped',
    detail:
      'Carries an RFC 3161 timestamp token, cryptographically chain-verified to the pinned FreeTSA root — fixing when these bytes existed.',
  },
  failed: {
    tier: 'alarm',
    label: 'Timestamp did not verify',
    detail:
      'A timestamp token is present, but its TSA signature or certificate chain did not verify against the pinned root.',
  },
  absent: {
    tier: 'normal',
    label: 'No timestamp',
    detail: 'This package carries no timestamp token (common for earlier-format packages).',
  },
} as const satisfies Record<string, TrustSignalDescriptor>;
export const resolveTimestamp = (
  hasTimestamp: boolean,
  rfc3161Verified: boolean | null,
): TrustSignalDescriptor =>
  !hasTimestamp
    ? TIMESTAMP_SIGNALS.absent
    : rfc3161Verified === true
      ? TIMESTAMP_SIGNALS.verified
      : TIMESTAMP_SIGNALS.failed;

// --- #8 Transparency-log inclusion (DEEP: offline Merkle inclusion) -------
// As of verify-core 0.6.0 (#119 P1), when an inclusion proof is carried the entry's
// RFC 6962 Merkle path is recomputed and the signed checkpoint is verified against a
// pinned Rekor log key — offline, no network. `included` is that strong verdict.
// Packages without a carried proof fall back to `matched` (online hash-parity); an
// unreachable / unconfirmed log is `unconfirmed` (Attention, not Alarm — a transient
// outage is the common cause and the log is not the package's content).

export const REKOR_SIGNALS = {
  included: {
    tier: 'verified',
    label: 'Recorded in a public transparency log',
    detail:
      'Merkle inclusion verified offline against the log’s signed checkpoint — this entry is in a log the Sigstore key vouches for.',
  },
  matched: {
    tier: 'verified',
    label: 'Recorded in a public transparency log',
    detail:
      'A matching entry was confirmed in the Sigstore Rekor transparency log (entry-hash parity; no inclusion proof was carried for offline recomputation).',
  },
  unconfirmed: {
    tier: 'attention',
    label: 'Transparency-log entry not confirmed',
    detail:
      'This package references a transparency-log entry that could not be confirmed — the log may be unreachable.',
  },
  absent: {
    tier: 'normal',
    label: 'Not in a transparency log',
    detail: 'This package was not recorded in a public transparency log.',
  },
} as const satisfies Record<string, TrustSignalDescriptor>;
export const resolveRekor = (
  hasRekor: boolean,
  inclusionVerifiedOffline: boolean,
  rekorVerified: boolean | null,
): TrustSignalDescriptor => {
  if (inclusionVerifiedOffline) return REKOR_SIGNALS.included;
  if (!hasRekor) return REKOR_SIGNALS.absent;
  if (rekorVerified === true) return REKOR_SIGNALS.matched;
  return REKOR_SIGNALS.unconfirmed;
};

// --- #9 BlobRef integrity (blobRefsVerified: boolean | null) -------------

export const BLOB_REFS_SIGNALS: Record<TriStateKey, TrustSignalDescriptor> = {
  true: {
    tier: 'verified',
    label: 'Referenced content verified',
    detail: 'Every externally-stored field matched its embedded fingerprint.',
  },
  false: {
    tier: 'alarm',
    label: 'Referenced content failed verification',
    detail: 'At least one externally-stored field did not match its fingerprint.',
  },
  null: {
    tier: 'normal',
    label: 'No referenced content',
    detail: 'This package stores all fields inline; there is nothing to fetch.',
  },
};
export const resolveBlobRefs = (v: boolean | null): TrustSignalDescriptor =>
  BLOB_REFS_SIGNALS[triKey(v)];

/**
 * #9 BlobRef per-reference failure reasons. Each is a sub-explanation of a
 * failed (Alarm-tier) BlobRef check — surfaced beneath the summary signal when a
 * reference fails. `fetch_failed` is the softest (a transient retrieval failure
 * is possible, paralleling rekor=false); it is tiered Alarm here because a
 * BlobRef is a PRIMARY content carrier whose unavailability breaks the package's
 * content-integrity guarantee, unlike the supplementary Rekor log. See the note.
 */
export const BLOB_REF_REASON_SIGNALS: Record<BlobRefVerifyReason, TrustSignalDescriptor> = {
  invalid_ref: {
    tier: 'alarm',
    label: 'Malformed content reference',
    detail: 'A referenced field does not carry a valid blob reference.',
  },
  fetch_failed: {
    tier: 'alarm',
    label: 'Referenced content could not be retrieved',
    detail: 'A referenced blob could not be fetched to confirm its integrity.',
  },
  size_mismatch: {
    tier: 'alarm',
    label: 'Referenced content is the wrong size',
    detail: 'A referenced blob does not match the size the package commits to.',
  },
  hash_mismatch: {
    tier: 'alarm',
    label: 'Referenced content does not match its fingerprint',
    detail: 'A referenced blob does not hash to the value the package commits to.',
  },
};

// --- #10 Lifecycle state -------------------------------------------------
//
// Lifecycle is a separate axis from cryptographic integrity (P7). Neither state
// is an integrity verdict, so both are calm. Whether lifecycle renders in the
// verify panel at all is left to #111 (the note explains the reasoning).

export const LIFECYCLE_STATE_SIGNALS: Record<LifecycleStatus, TrustSignalDescriptor> = {
  active: {
    tier: 'normal',
    label: 'Active',
    detail: 'This package has not been withdrawn.',
  },
  // NOT alarm — a withdrawal is a legitimate signed action. Prominence (a banner)
  // is the detail page's job, not the tier's.
  withdrawn: {
    tier: 'normal',
    label: 'Withdrawn by the publisher',
    detail:
      'The publisher has withdrawn this package — a legitimate signed action. The reason is shown with the package.',
  },
};

export const LIFECYCLE_SOURCE_SIGNALS: Record<LifecycleSource, TrustSignalDescriptor> = {
  'attestation-chain': {
    tier: 'verified',
    label: 'Lifecycle confirmed from signed transitions',
    detail: 'Status was derived from independently-verified, signed lifecycle events.',
  },
  'legacy-columns': {
    tier: 'normal',
    label: 'Lifecycle from earlier-format records',
    detail: 'Status was derived from pre-attestation lifecycle records.',
  },
  none: {
    tier: 'normal',
    label: 'No lifecycle changes',
    detail: 'No withdrawal or reinstatement has been recorded.',
  },
};

// #10 per-attestation signals. Integrity of a lifecycle event (signature,
// node-id) alarms when false — a forged or altered transition. The signer-match,
// timestamp, and Rekor checks are NOT failures when false: a non-signer-matched
// attestation is a legitimately-surfaced third-party event (§8.10.3 retention
// asymmetry — it is shown but does not move the publisher's status), and the
// timestamp / Rekor checks are supplementary. (See the note's deviation log: the
// brief grouped signer-match with the integrity checks; the retention-asymmetry
// semantics and the existing verify.ts test place it at Normal.)
export const LIFECYCLE_ATTESTATION_SIGNATURE_SIGNALS: Record<
  TriStateKey,
  TrustSignalDescriptor
> = {
  true: { tier: 'verified', label: 'Lifecycle event signature verifies' },
  false: {
    tier: 'alarm',
    label: 'Lifecycle event signature does not verify',
    detail:
      'A withdrawal or reinstatement claims a signature that does not validate — a forged transition.',
  },
  null: { tier: 'normal', label: 'Lifecycle event unsigned' },
};
export const LIFECYCLE_ATTESTATION_NODE_ID_SIGNALS: Record<BiStateKey, TrustSignalDescriptor> = {
  true: { tier: 'verified', label: 'Lifecycle event intact' },
  false: {
    tier: 'alarm',
    label: 'Lifecycle event has been altered',
    detail: 'A lifecycle event does not hash to its recorded id — it may have been tampered with.',
  },
};
export const LIFECYCLE_ATTESTATION_SIGNER_MATCH_SIGNALS: Record<
  BiStateKey,
  TrustSignalDescriptor
> = {
  true: { tier: 'verified', label: 'Lifecycle event from the publisher' },
  false: {
    tier: 'normal',
    label: 'Lifecycle event from a different signer',
    detail:
      'A third party attested this transition; per the standard it is shown but does not change the status the publisher sets.',
  },
};
export const LIFECYCLE_ATTESTATION_TIMESTAMP_SIGNALS: Record<BiStateKey, TrustSignalDescriptor> = {
  true: { tier: 'verified', label: 'Lifecycle event timestamped' },
  false: {
    tier: 'normal',
    label: 'Lifecycle event not timestamped',
    detail: 'A supplementary check; its absence does not affect the transition.',
  },
};
export const LIFECYCLE_ATTESTATION_REKOR_SIGNALS: Record<BiStateKey, TrustSignalDescriptor> = {
  true: { tier: 'verified', label: 'Lifecycle event in a transparency log' },
  false: {
    tier: 'normal',
    label: 'Lifecycle event not in a transparency log',
    detail: 'A supplementary check; its absence does not affect the transition.',
  },
};

// --- #11 captureMethod LABEL (informational — NO tier) -------------------
//
// Check #11 is not a pass/fail signal: `metadata.captureMethod` is a
// signature-covered LABEL describing HOW the bytes were captured (spec §8.6 /
// §9.2 #11 — "signed ≠ verbatim"). It is rendered as a neutral informational
// label adjacent to the signature verdict (#111's job), never assigned a tier.
// These strings give each captureMethod value a plain-language reading (P9).
export const CAPTURE_METHOD_LABELS: Record<CaptureMethod, string> = {
  'chat-flow-stream': 'Captured from the live chat as the analysis was generated.',
  'claude-code-jsonl-readback': 'Reconstructed from the Claude Code session transcript.',
  'claude-code-self-report':
    'Summarized by the AI from its own session memory (deprecated capture method).',
  'script-run': 'Read into the package by a packaging program from files that already existed on disk.',
  'tool-emitted': 'Written into the package by the program that computed the content.',
};

/**
 * Resolve the plain-language capture-method reading rendered as a neutral label
 * beside the signature verdict (#111). Returns `null` when there is nothing to
 * show — a pre-ADR-0003 package with no captureMethod, or an unrecognized value
 * — so the consumer simply omits the line (no noise on legacy packages).
 *
 * `datHere` is a preserved special case (ADR-0004): the 2026-05-19 reframe moved
 * datHere out of captureMethod into a separate contentProfile column, but legacy
 * pre-reframe records may still carry it here. It is surfaced as a legacy value
 * with an ADR-0004 annotation, never treated as a real capture method.
 */
export function resolveCaptureMethodLabel(method: string | null | undefined): string | null {
  if (!method) return null;
  const known = (CAPTURE_METHOD_LABELS as Record<string, string | undefined>)[method];
  if (known) return known;
  if (method === 'datHere') {
    return 'Recorded with a legacy datHere capture method (pre-ADR-0004 reframe); the content profile now carries this distinction.';
  }
  return null;
}

// --- #12 type resolution -------------------------------------------------

export const TYPE_RESOLUTION_SIGNALS: Record<TypeResolutionStatus, TrustSignalDescriptor> = {
  ok: { tier: 'verified', label: 'Node type recognized' },
  implicit: {
    tier: 'normal',
    label: 'Node type inferred (earlier-format package)',
    detail: 'This package predates explicit type labeling; it is read as a standard analysis.',
  },
  unknown_type: {
    tier: 'attention',
    label: 'Unrecognized node type',
    detail: 'This package declares a type this verifier does not recognize. It is shown, not rejected.',
  },
};

// --- #14 signer identity ↔ registry cross-check --------------------------

export const SIGNER_IDENTITY_SIGNALS: Record<SignerIdentityCheckStatus, TrustSignalDescriptor> = {
  ok: {
    tier: 'verified',
    label: 'Signer identity matches the registry',
    detail:
      'The stated signer matches the identity the publisher’s trust registry records for the signing key.',
  },
  signer_identity_mismatch: {
    tier: 'alarm',
    label: 'Signer identity does not match the registry',
    detail:
      'The stated signer does not match the identity bound to the signing key — do not trust.',
  },
  no_signer: {
    tier: 'normal',
    label: 'No stated signer (earlier-format package)',
    detail:
      'This package predates identity binding; the signer is derived from the registry and the cross-check is skipped.',
  },
  no_registry_identity: {
    tier: 'normal',
    label: 'Registry has no identity for this key',
    detail: 'The registry entry for this key predates identity binding, so the cross-check is skipped.',
  },
  // Hub ADR-0030 §10: a derived match has its own row; `ok` ("matches the
  // registry") is never reported under a key-derived identifier.
  key_derived_match: {
    tier: 'normal',
    label: 'Signer identifier matches the signing key',
    detail:
      'The identifier is derived from the key that signed this package. This shows the same key signed anything else under this identifier, and nothing about who holds it.',
  },
  // Hub ADR-0030 §3: fatal.
  key_derived_mismatch: {
    tier: 'alarm',
    label: 'Signer identifier does not match the signing key',
    detail:
      'The stated signer’s identifier is not the one derived from the key that signed this package — do not trust.',
  },
};

// --- #15 captureMethod per-profile vocabulary conformance ----------------

export const CAPTURE_METHOD_VOCAB_SIGNALS: Record<
  CaptureMethodVocabStatus,
  TrustSignalDescriptor
> = {
  ok: { tier: 'verified', label: 'Capture method recognized for this profile' },
  // The sharpest call. The spec says #15 "rejects the node," but the tier governs
  // how the SIGNAL reads, not conformance (#110 changes no behavior). The
  // captureMethod label is signature-covered, so an unrecognized value is not an
  // alteration — it is an unrecognized identifier, like #3 / #12. → Attention.
  captureMethod_unknown: {
    tier: 'attention',
    label: 'Capture method not recognized for this profile',
    detail:
      'The capture-method label is not in the vocabulary that this profile declares. The label is signature-covered, so this is an unrecognized value, not an alteration.',
  },
  producerProfile_bundle_unresolved: {
    tier: 'normal',
    label: 'Producer profile not resolved',
    detail:
      'The producer profile could not be resolved, so its capture-method vocabulary was not checked. The label is preserved.',
  },
  no_capture_method: {
    tier: 'normal',
    label: 'No capture method (earlier-format package)',
    detail: 'This package predates capture-method labeling.',
  },
};

// --- #16 metadata.contentProfile (hub ADR-0029 §5) ------------------------
//
// Tiers exactly as ADR-0029 §5 sets them. No status is `alarm`: both labels are
// inside the signed bytes, so an unknown value is an unrecognized identifier and
// a contradiction is a producer error — neither is evidence of alteration.

export const CONTENT_PROFILE_SIGNALS: Record<ContentProfileStatus, TrustSignalDescriptor> = {
  ok: {
    tier: 'verified',
    label: 'Content profile recognized',
    detail: 'The content profile is a known value and agrees with the producer profile.',
  },
  // Load-bearing: the signed eval-run packages carry no contentProfile key. Calm.
  contentProfile_absent: {
    tier: 'normal',
    label: 'No content profile stated (read as default)',
    detail: 'This package carries no content-profile label, which the standard reads as “default”.',
  },
  contentProfile_unknown: {
    tier: 'attention',
    label: 'Unrecognized content profile',
    detail:
      'This package names a content profile this verifier does not recognize. The label is signature-covered, so this is an unrecognized value, not an alteration. It is shown, not rejected.',
  },
  contentProfile_inconsistent: {
    tier: 'attention',
    label: 'Content profile contradicts the producer profile',
    detail:
      'The content-profile label and the producer profile disagree, so this package is malformed. Both labels are signature-covered, so this is a producer error, not evidence of alteration; the envelope and signature checks are unaffected.',
  },
};

// --- notebookProvenance (honest execution label) -------------------------
//
// Not a verify-library status: `metadata.extensions["org.civicaitools.notebook"]
// .provenance` distinguishes a notebook executed in a signed sandbox from a
// skeleton that reproduces the steps without running them (per open-questions
// Q31). Both readings are honest and calm — neither is a failure. Both values
// are written by the reference producer: its executed pipeline stamps
// `'executed'`, and its skeleton notebook generator has stamped `'skeleton'`
// since civic-ai-tools-website#401. This site reads the value and writes
// neither. Canonical list kept here because the value is a notebook-author
// concept, not a verify.ts type.
export const NOTEBOOK_PROVENANCE_VALUES = ['executed', 'skeleton'] as const;
export type NotebookProvenance = (typeof NOTEBOOK_PROVENANCE_VALUES)[number];

export const NOTEBOOK_PROVENANCE_SIGNALS: Record<NotebookProvenance, TrustSignalDescriptor> = {
  executed: {
    tier: 'normal',
    label: 'Executed in a signed sandbox',
    detail:
      'The notebook was run end-to-end in a signed sandbox; its outputs are the executed results.',
  },
  // The label is in the reader's words, not the code path's (ruling D7 = B,
  // civic-ai-tools-website#434). "Skeleton" names the generator that writes the
  // notebook without running it, which a reader has no reason to know. The
  // VALUE `skeleton` is what a package carries and is unchanged; the label
  // reaches no signed byte. `notebook-provenance-copy.test.ts` pins the words.
  skeleton: {
    tier: 'normal',
    label: 'Analysis notebook (not executed)',
    detail:
      'The notebook reproduces the steps but was not executed; its outputs were not regenerated.',
  },
};

// --- Checks not emitted as discrete status fields today ------------------
//
// Spec checks #6 (metadata.signingKeyId consistency) and #13 (nodeId
// cross-check) are NOT surfaced by today's verify route as discrete status
// codes — it returns `nodeId` only as a recomputed hash string. Their tiers are
// RESERVED in the design note (a mismatch on either → Alarm) but intentionally
// have no runtime map here, and the coverage test asserts only the codes the
// route actually emits. When #6/#13 gain discrete statuses, add their maps here.
