// Content-canonicalization, content-hash, and typed-standards envelope checks
// (spec §9.2 checks #3, #4, #12, #13, #14, #15, #16) + the package-level
// blob-ref walker (#9) — browser-safe.
//
// Factored verbatim from the server `verify.ts` (WS2); these functions were
// already pure JS over the package object. The only environmental change is the
// blob-ref walker now threads an injected fetcher. Each check degrades gracefully
// for pre-v0.1 packages that omit the corresponding field.

import {
  computeEnvelopeHash,
  computeContentHashSha256,
  isMultihashContentHash,
  KNOWN_CANONICALIZATION_RULES,
  LEGACY_JSON_CANONICALIZATION,
  DATHERE_AG_JUPYTER_CANONICALIZATION,
  RAW_BYTES_CANONICALIZATION,
} from './canonicalization.ts';
import { sha256Hex } from './primitives.ts';
import { captureVocabForProfile, resolveProfileType } from './profiles.ts';
import {
  isBlobRef,
  parseBlobRef,
  verifyBlobRef,
  type BlobRef,
  type BlobRefVerifyReason,
  type BlobFetchOptions,
} from './blob-ref.ts';
import type { CaptureMethod, FetchLike, SignerIdentity } from './types.ts';
import type { TrustRegistry } from './trust-registry.ts';
import { isKeyDerivedIdentifier } from './did-key.ts';
import { compareKeyDerivedIdentifier } from './self-certifying.ts';

/**
 * Recompute a package's envelope hash, routed by the §8.2 detection rule: v0.1
 * packages (multihash `contentHash` present) hash via RFC 8785 JCS; pre-v0.1
 * packages hash via the legacy insertion-order `JSON.stringify`. Drives both
 * check #1 (envelope integrity / `hashMatch`) and check #13 (`nodeId`).
 */
export function recomputePackageHash(pkg: Record<string, unknown>): string {
  return computeEnvelopeHash(pkg);
}

// --- Content canonicalization & hashing checks (spec §9.2 checks #3, #4) ---

export const CONTENT_CANONICALIZATION_STATUSES = [
  'ok',
  'implicit',
  'unknown_canonicalization_rule',
] as const;
export type ContentCanonicalizationStatus =
  (typeof CONTENT_CANONICALIZATION_STATUSES)[number];

export interface ContentCanonicalizationResolution {
  status: ContentCanonicalizationStatus;
  /** The resolved canonicalization-rule URI — the explicit field value, or the
   *  rule inferred from the content profile for pre-v0.1 packages. */
  rule: string;
}

/**
 * Check #3 — content-canonicalization rule resolution (spec §9.2). Reads the
 * package's `contentCanonicalization` URI and resolves it against the local rule
 * registry. A known URI → `ok`. An unrecognized URI →
 * `unknown_canonicalization_rule` (renders; check #4 then cannot recompute). An
 * absent field on a pre-v0.1 package → `implicit`, inferring the rule from
 * contentProfile / producerProfile (datHere → dathere-ag-jupyter/v1; otherwise
 * legacy-json/v1).
 */
export function resolveContentCanonicalization(
  pkg: Record<string, unknown>,
): ContentCanonicalizationResolution {
  const raw = pkg['contentCanonicalization'];
  if (typeof raw === 'string' && raw.length > 0) {
    if (KNOWN_CANONICALIZATION_RULES.includes(raw)) {
      return { status: 'ok', rule: raw };
    }
    return { status: 'unknown_canonicalization_rule', rule: raw };
  }
  // Pre-v0.1: infer the rule from the content profile (the same datHere
  // legacy-alias logic the captureMethod resolver uses).
  const metadata = pkg['metadata'] as Record<string, unknown> | undefined;
  const contentProfile =
    typeof metadata?.['contentProfile'] === 'string'
      ? (metadata['contentProfile'] as string)
      : undefined;
  const producerProfile =
    typeof pkg['producerProfile'] === 'string'
      ? (pkg['producerProfile'] as string)
      : undefined;
  const isDatHere =
    contentProfile === 'datHere' ||
    (producerProfile?.startsWith('ai-assisted-analysis/datHere') ?? false);
  return {
    status: 'implicit',
    rule: isDatHere
      ? DATHERE_AG_JUPYTER_CANONICALIZATION
      : LEGACY_JSON_CANONICALIZATION,
  };
}

export const CONTENT_HASH_STATUSES = [
  'ok',
  'content_hash_mismatch',
  'contentHash_no_supported_algorithm',
  'unresolved_rule',
  'legacy_relabeled',
  'content_bytes_unavailable',
] as const;
export type ContentHashStatus = (typeof CONTENT_HASH_STATUSES)[number];

export interface ContentHashCheck {
  status: ContentHashStatus;
  /** Algorithm names listed in the package's multihash `contentHash`. */
  algorithms?: string[];
  /** The algorithm whose recomputed digest matched (status === 'ok'). */
  matched?: string;
  /** The multihash digest set the verifier reports for the package. For pre-v0.1
   *  packages this is the legacy external single-SHA-256 relabeled as
   *  `{ sha256: <hex> }` per §8.2. */
  contentHash?: Record<string, string>;
}

/** Multihash algorithms this verifier can recompute today (spec §8.2 lists
 *  sha256 required + sha3-256 / blake3 as registered alternates). */
const SUPPORTED_CONTENT_HASH_ALGORITHMS: readonly string[] = ['sha256'];

/**
 * Check #4 — content-hash verification (spec §9.2, §8.2).
 *
 * v0.1 packages (multihash `contentHash` present): recompute the off-log
 * content's digest under the resolved canonicalization rule for every listed
 * algorithm this verifier supports, and confirm at least one matches.
 *   - at least one supported algorithm matches → `ok`.
 *   - a supported algorithm is present but none match → `content_hash_mismatch`.
 *   - none of the listed algorithms are ones this verifier can compute →
 *     `contentHash_no_supported_algorithm` (degrades; the value is preserved).
 *   - the canonicalization rule could not be resolved (check #3 unknown) →
 *     `unresolved_rule` (cannot recompute).
 *
 * pre-v0.1 packages (no multihash `contentHash`): the historical external
 * single-SHA-256 is RELABELED as `{ sha256: <hex> }` per §8.2 rather than
 * recomputed; its integrity is established by check #1, so check #4 reports
 * `legacy_relabeled`.
 *
 * raw-bytes/v1 with a BlobRef `output` (hub ADR-0029 §4): the fingerprinted
 * bytes live outside the package. `outputBytes` are those bytes when the caller
 * holds them.
 *   - `contentHash.sha256` differs from the hex of `output.ref` →
 *     `content_hash_mismatch`, decided from the package alone.
 *   - no `outputBytes` → `content_bytes_unavailable`: the bytes were not
 *     checked. Never `ok` without hashing.
 *   - otherwise the SHA-256 of `outputBytes` is compared with
 *     `contentHash.sha256` → `ok` / `content_hash_mismatch`.
 * This function does no I/O; `verifyContentHashWithFetch` obtains the bytes
 * through the injected fetcher and passes them here.
 */
export function verifyContentHash(
  pkg: Record<string, unknown>,
  resolution: ContentCanonicalizationResolution,
  legacyExternalHash?: string,
  outputBytes?: Uint8Array,
): ContentHashCheck {
  const contentHash = pkg['contentHash'];
  if (!isMultihashContentHash(contentHash)) {
    return {
      status: 'legacy_relabeled',
      ...(legacyExternalHash ? { contentHash: { sha256: legacyExternalHash } } : {}),
    };
  }

  const algorithms = Object.keys(contentHash);
  if (resolution.status === 'unknown_canonicalization_rule') {
    return { status: 'unresolved_rule', algorithms, contentHash };
  }

  const checkable = algorithms.filter((a) =>
    SUPPORTED_CONTENT_HASH_ALGORITHMS.includes(a),
  );
  if (checkable.length === 0) {
    return {
      status: 'contentHash_no_supported_algorithm',
      algorithms,
      contentHash,
    };
  }

  const output = pkg['output'];
  if (resolution.rule === RAW_BYTES_CANONICALIZATION && isBlobRef(output)) {
    // sha256 is the only supported algorithm, so `checkable` is ['sha256'] here.
    const signed = contentHash['sha256'];
    if (signed !== parseBlobRef(output.ref).hash) {
      // No file can hash to two different signed digests.
      return { status: 'content_hash_mismatch', algorithms, contentHash };
    }
    if (outputBytes === undefined) {
      return { status: 'content_bytes_unavailable', algorithms, contentHash };
    }
    return sha256Hex(outputBytes) === signed
      ? { status: 'ok', algorithms, matched: 'sha256', contentHash }
      : { status: 'content_hash_mismatch', algorithms, contentHash };
  }

  for (const algo of checkable) {
    let recomputed: string | undefined;
    try {
      // sha256 is the only supported algorithm today; the off-log content is
      // recomputed under the resolved rule (legacy-json/v1 → package minus
      // contentHash; dathere-ag-jupyter/v1 → the executed notebook).
      recomputed =
        algo === 'sha256'
          ? computeContentHashSha256(pkg, resolution.rule)
          : undefined;
    } catch {
      // A structurally malformed package (e.g. a datHere package missing its
      // notebook extension) can't be recomputed — treat as non-matching rather
      // than throwing out of the whole verify pass.
      recomputed = undefined;
    }
    if (recomputed !== undefined && recomputed === contentHash[algo]) {
      return { status: 'ok', algorithms, matched: algo, contentHash };
    }
  }
  return { status: 'content_hash_mismatch', algorithms, contentHash };
}

/** Fetch a BlobRef's bytes through the injected fetcher (defaulting to
 *  `globalThis.fetch`, the same default check #9 uses). `undefined` on any
 *  failure. */
async function fetchBlobRefBytes(
  ref: BlobRef,
  options: BlobFetchOptions,
): Promise<Uint8Array | undefined> {
  try {
    const fetcher = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    const response = await fetcher(ref.url, {
      signal: options.signal ?? AbortSignal.timeout(15_000),
    });
    if (!response.ok) return undefined;
    return new Uint8Array(await response.arrayBuffer());
  } catch {
    return undefined;
  }
}

/**
 * Check #4 with the raw-bytes/v1 BlobRef path wired to the injected fetcher
 * (hub ADR-0029 §4). Identical to `verifyContentHash` for every other rule and
 * shape. For a raw-bytes/v1 package whose `output` is a BlobRef, it obtains the
 * file's bytes through `options.fetch` (an offline verifier supplies a local
 * copy through that fetcher) and hashes them; bytes it cannot obtain leave the
 * status at `content_bytes_unavailable`.
 */
export async function verifyContentHashWithFetch(
  pkg: Record<string, unknown>,
  resolution: ContentCanonicalizationResolution,
  legacyExternalHash?: string,
  options: BlobFetchOptions = {},
): Promise<ContentHashCheck> {
  const first = verifyContentHash(pkg, resolution, legacyExternalHash);
  const output = pkg['output'];
  if (first.status !== 'content_bytes_unavailable' || !isBlobRef(output)) {
    return first;
  }
  const bytes = await fetchBlobRefBytes(output, options);
  if (bytes === undefined) return first;
  return verifyContentHash(pkg, resolution, legacyExternalHash, bytes);
}

// --- Content-profile check (spec §9.2 check #16; hub ADR-0029 §5) ---

/** The known `metadata.contentProfile` values (spec §8.1.2). */
export const KNOWN_CONTENT_PROFILES: readonly string[] = ['default', 'datHere'];

export const CONTENT_PROFILE_STATUSES = [
  'ok',
  'contentProfile_absent',
  'contentProfile_unknown',
  'contentProfile_inconsistent',
] as const;
export type ContentProfileStatus = (typeof CONTENT_PROFILE_STATUSES)[number];

export interface ContentProfileCheck {
  status: ContentProfileStatus;
  /** `metadata.contentProfile` as carried, when it is a string. */
  contentProfile?: string;
  /** `producerProfile` as carried, when present. */
  producerProfile?: string;
}

/**
 * Check #16 — `metadata.contentProfile` (hub ADR-0029 §5).
 *   - key absent → `contentProfile_absent` (read as `"default"`, spec §8.1.2).
 *   - present and neither `"default"` nor `"datHere"` → `contentProfile_unknown`
 *     (reported, not passed; consistency is not judged).
 *   - present, known, `producerProfile` present, and the ADR-0006 §2 invariant
 *     fails (`contentProfile === "datHere"` iff `producerProfile` starts with
 *     `ai-assisted-analysis/datHere`) → `contentProfile_inconsistent`.
 *   - otherwise → `ok`.
 * The invariant is compared only when both fields are present. No status is an
 * integrity failure: both labels are signature-covered.
 */
export function checkContentProfile(pkg: Record<string, unknown>): ContentProfileCheck {
  const metadata = pkg['metadata'];
  const raw =
    typeof metadata === 'object' && metadata !== null && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)['contentProfile']
      : undefined;
  const producerProfile =
    typeof pkg['producerProfile'] === 'string' ? (pkg['producerProfile'] as string) : undefined;
  const base = {
    ...(typeof raw === 'string' ? { contentProfile: raw } : {}),
    ...(producerProfile !== undefined ? { producerProfile } : {}),
  };

  if (raw === undefined) {
    return { status: 'contentProfile_absent', ...base };
  }
  if (typeof raw !== 'string' || !KNOWN_CONTENT_PROFILES.includes(raw)) {
    return { status: 'contentProfile_unknown', ...base };
  }
  if (producerProfile !== undefined) {
    const isDatHere = raw === 'datHere';
    const profileIsDatHere = producerProfile.startsWith('ai-assisted-analysis/datHere');
    if (isDatHere !== profileIsDatHere) {
      return { status: 'contentProfile_inconsistent', ...base };
    }
  }
  return { status: 'ok', ...base };
}

// --- Typed-standards envelope checks (spec §9.2 checks #12, #14, #15) ---

// v0.1 ratified node type URIs (spec §8.12.1). Recognized so check #12 resolves
// them; only `content/analysis/v1` (+ the lifecycle sub-types) are operationalized
// today, but the full ratified set is registered so conformant packages don't
// render as `unknown_type`.
const KNOWN_TYPE_URIS: readonly string[] = [
  'content/analysis/v1',
  'attestation/withdraws/v1',
  'attestation/reinstates/v1',
  'attestation/supersedes/v1',
  'attestation/publishes/v1',
  'attestation/locatedAt/v1',
  'attestation/corroborates/v1',
  'attestation/contradicts/v1',
  'attestation/endorses/v1',
  'attestation/wasDerivedFrom/v1',
  'attestation/answersQuestion/v1',
  'attestation/supportedBy/v1',
  'attestation/opposedBy/v1',
  'attestation/certifies/v1',
  'attestation/evaluates/v1',
  'attestation/conforms/v1',
];

export const TYPE_RESOLUTION_STATUSES = ['ok', 'implicit', 'unknown_type'] as const;
export type TypeResolutionStatus = (typeof TYPE_RESOLUTION_STATUSES)[number];

export interface TypeResolution {
  status: TypeResolutionStatus;
  /** The resolved type URI (the implicit `content/analysis/v1` when omitted). */
  type: string;
}

/**
 * Check #12 — `type` resolution. An absent field resolves to the implicit
 * `content/analysis/v1` (pre-v0.1). An unrecognized URI reports `unknown_type`
 * and renders as such — it does NOT fail verification.
 */
export function resolvePackageType(pkg: Record<string, unknown>): TypeResolution {
  const raw = pkg['type'];
  if (typeof raw !== 'string' || raw.length === 0) {
    return { status: 'implicit', type: 'content/analysis/v1' };
  }
  if (KNOWN_TYPE_URIS.includes(raw)) {
    return { status: 'ok', type: raw };
  }
  return { status: 'unknown_type', type: raw };
}

export const SIGNER_IDENTITY_CHECK_STATUSES = [
  'ok',
  'signer_identity_mismatch',
  'no_signer',
  'no_registry_identity',
  'key_derived_match',
  'key_derived_mismatch',
] as const;
export type SignerIdentityCheckStatus =
  (typeof SIGNER_IDENTITY_CHECK_STATUSES)[number];

export interface SignerIdentityCheck {
  status: SignerIdentityCheckStatus;
  /** The `signer.identifier` claimed in the envelope, when present. */
  claimed?: string;
  /** The identifier the registry records for the signing `kid`, when present. */
  registered?: string;
  /** The identifier derived from the envelope's `publicKey`, under a
   *  key-derived `signer.identifier` (hub ADR-0030 §2). Absent on a
   *  `key_derived_mismatch` whose key could not be decoded. */
  derived?: string;
}

/**
 * Check #14 — `signer.identifier` ↔ trust-registry `signerIdentity` cross-check
 * (rules out a kid-swap-with-mismatched-identity attack). `signer_identity_mismatch`
 * is fatal. Pre-v0.1 packages carry no envelope-side `signer` (`no_signer`) — the
 * verifier derives the signer from the registry and skips the cross-check. A
 * registry entry without a `signerIdentity` (legacy registry) yields
 * `no_registry_identity`.
 *
 * A key-derived `signer.identifier` (one beginning `did:key:`, hub ADR-0030 §3)
 * is checked against the envelope's `publicKey` instead, whatever the
 * `bindingTier` and whatever the registry's source:
 *   - the identifier derived from `publicKey` differs → `key_derived_mismatch`,
 *     fatal, carrying `claimed` and `derived`;
 *   - it matches, and a registry entry for the `kid` records a different
 *     identifier → `signer_identity_mismatch`, fatal (a contradiction only
 *     lowers, so any registry may report it);
 *   - it matches otherwise → `key_derived_match`.
 * `ok` ("matches the registry") is never reported under a key-derived
 * identifier. Without `publicKey` the derivation cannot run; the registry
 * cross-check runs as for any signer, except that its `ok` reads
 * `no_registry_identity`, since nothing established the identifier.
 */
export function checkSignerIdentity(
  pkg: Record<string, unknown>,
  kid: string | undefined,
  registry: TrustRegistry | undefined,
  /** The signature envelope's base64 SPKI `publicKey`. Read only when the
   *  signer's identifier is key-derived. */
  publicKey?: string,
): SignerIdentityCheck {
  const signer = pkg['signer'] as SignerIdentity | undefined;
  if (!signer || typeof signer !== 'object' || typeof signer.identifier !== 'string') {
    return { status: 'no_signer' };
  }
  const entry = kid && registry ? registry.keys.find((k) => k.kid === kid) : undefined;
  const registered = entry?.signerIdentity?.identifier;

  if (isKeyDerivedIdentifier(signer.identifier)) {
    const comparison = compareKeyDerivedIdentifier(signer, publicKey);
    if (comparison && !comparison.match) {
      return {
        status: 'key_derived_mismatch',
        claimed: comparison.claimed,
        ...(comparison.derived !== undefined ? { derived: comparison.derived } : {}),
      };
    }
    if (registered && registered !== signer.identifier) {
      return { status: 'signer_identity_mismatch', claimed: signer.identifier, registered };
    }
    if (comparison) {
      return {
        status: 'key_derived_match',
        claimed: signer.identifier,
        derived: comparison.derived,
        ...(registered ? { registered } : {}),
      };
    }
    return { status: 'no_registry_identity', claimed: signer.identifier };
  }

  if (!registered) {
    return { status: 'no_registry_identity', claimed: signer.identifier };
  }
  if (registered !== signer.identifier) {
    return { status: 'signer_identity_mismatch', claimed: signer.identifier, registered };
  }
  return { status: 'ok', claimed: signer.identifier, registered };
}

export const CAPTURE_METHOD_VOCAB_STATUSES = [
  'ok',
  'captureMethod_unknown',
  'producerProfile_bundle_unresolved',
  'no_capture_method',
] as const;
export type CaptureMethodVocabStatus =
  (typeof CAPTURE_METHOD_VOCAB_STATUSES)[number];

export interface CaptureMethodVocabCheck {
  status: CaptureMethodVocabStatus;
  captureMethod?: string;
  /** The resolved Producer Profile type whose vocabulary was consulted. */
  profileType: string;
}

/**
 * Check #15 — `captureMethod` per-profile vocabulary conformance. Resolves the
 * package's Producer Profile (or its legacy-alias / pre-v0.1 fallback) and
 * confirms `metadata.captureMethod` is in the declared vocabulary. A value not in
 * the vocabulary reports `captureMethod_unknown` (rejects). An unresolvable
 * profile bundle reports `producerProfile_bundle_unresolved` and degrades
 * gracefully. A null captureMethod (pre-v0.1) is neutral (`no_capture_method`).
 */
export function checkCaptureMethodVocab(pkg: Record<string, unknown>): CaptureMethodVocabCheck {
  const metadata = pkg['metadata'] as Record<string, unknown> | undefined;
  const captureMethod =
    typeof metadata?.['captureMethod'] === 'string'
      ? (metadata['captureMethod'] as string)
      : undefined;
  const producerProfile =
    typeof pkg['producerProfile'] === 'string' ? (pkg['producerProfile'] as string) : undefined;
  const contentProfile =
    typeof metadata?.['contentProfile'] === 'string'
      ? (metadata['contentProfile'] as string)
      : undefined;
  const profileType = resolveProfileType(producerProfile, contentProfile);

  if (!captureMethod) {
    return { status: 'no_capture_method', profileType };
  }
  const vocab = captureVocabForProfile(producerProfile, contentProfile);
  if (!vocab) {
    return { status: 'producerProfile_bundle_unresolved', captureMethod, profileType };
  }
  return {
    status: vocab.includes(captureMethod as CaptureMethod) ? 'ok' : 'captureMethod_unknown',
    captureMethod,
    profileType,
  };
}

// --- Blob references (spec §9.2 check #9) ---

/** Field paths that the core verifier scans for BlobRef objects. */
const BLOB_REF_FIELDS = [
  'output',
  'trace',
  'skillMetadata.skillText',
] as const;

export type BlobRefField = (typeof BLOB_REF_FIELDS)[number];

export interface BlobRefVerification {
  field: BlobRefField;
  ref: string;
  url: string;
  size: number;
  contentType: string;
  ok: boolean;
  reason?: BlobRefVerifyReason;
}

function pickBlobRef(pkg: Record<string, unknown>, path: BlobRefField): BlobRef | null {
  const segments = path.split('.');
  let current: unknown = pkg;
  for (const segment of segments) {
    if (current == null || typeof current !== 'object') return null;
    current = (current as Record<string, unknown>)[segment];
  }
  return isBlobRef(current) ? current : null;
}

/**
 * Walk the package JSON for BlobRef fields, fetch each referenced blob, and
 * confirm the bytes hash to the advertised ref. Returns per-field verification
 * results. Runs fetches in parallel with a per-blob 15 s timeout; failures are
 * reported in the result rather than thrown. The fetcher is injected (defaults to
 * `globalThis.fetch`).
 */
export async function verifyPackageBlobRefs(
  pkg: Record<string, unknown>,
  options: BlobFetchOptions = {},
): Promise<BlobRefVerification[]> {
  const refs = BLOB_REF_FIELDS
    .map((field) => {
      const ref = pickBlobRef(pkg, field);
      return ref ? { field, ref } : null;
    })
    .filter((x): x is { field: BlobRefField; ref: BlobRef } => x !== null);

  return Promise.all(
    refs.map(async ({ field, ref }) => {
      const result = await verifyBlobRef(ref, options);
      return {
        field,
        ref: ref.ref,
        url: ref.url,
        size: ref.size,
        contentType: ref.contentType,
        ok: result.ok,
        reason: result.reason,
      };
    }),
  );
}
