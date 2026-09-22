// Verification flow for the typedstandards.org client-side verifier (#116 WS3
// Phase C). Pure helpers the <Verifier> client component sequences:
//
//   detect input  →  resolve the WS1 commitment  →  fetch package + registry
//   →  verifyRecord (the SAME @typedstandards/verify-core both sites run)
//   →  build the per-check "show the math" rows + the rolled-up verdict.
//
// Vocabulary eras (spec Appendix J, the 2026-08-19 settlement). The commitment
// endpoint's canonical path segment is `/api/records/`; `/api/evidence/` is a
// PERMANENT alias, because links minted under it are published in the wild.
// This module therefore RECOGNIZES both segments everywhere it parses, and
// RESOLVES new-then-old everywhere it constructs — see COMMITMENT_API_SEGMENTS.
//
// All network I/O is a plain GET with no custom request headers — a custom header
// makes the request non-simple and triggers a CORS preflight; a preflight `OPTIONS`
// against a host that redirects can be rejected there, so a plain GET avoids that
// failure mode — e.g. civicaitools.org's site-wide 307 to its canonical host. In a
// browser that's necessary but not sufficient: a cross-origin redirect response
// must itself carry CORS headers, or the fetch fails regardless of the request's
// simplicity. Server-side/Node fetches follow redirects without that constraint.
// Verification depth MATCHES verify-core / the civicaitools.org
// server: full client-side crypto for #1–#6/#9/#12–#16; #7 (RFC 3161) is the TSA
// signature + cert chain verified offline to the pinned FreeTSA root; #8 (Rekor) is
// the RFC 6962 Merkle inclusion proof recomputed against a signed checkpoint when one
// is carried (else online hash-parity); #10 (lifecycle) resolves from the carried
// signed attestation chain when present (#119 P1/P2b/P3).

import {
  verifyRecord,
  validateRegistry,
  verifyLifecycleChain,
  verifyKeyTrust,
  legacyEmbeddedKeyTrust,
  parseInclusionProof,
  isKeyDerivedIdentifier,
  type VerifyInput,
  type VerifyResult,
  type VerifySignatureEnvelope,
  type CommitmentLifecycleState,
  type CarriedLifecycleNode,
  type LifecycleResolution,
  type TrustRegistry,
  type KeyTrustResult,
  type KeyTrustStatus,
  type TrustRegistryProvenance,
} from '@typedstandards/verify-core';
import {
  type TrustTier,
  type ResolvedTrustSignal,
  type TrustSignalDescriptor,
  toResolvedSignal,
  resolveEnvelopeIntegrity,
  resolveSignature,
  resolveKeyTrust,
  resolveTimestamp,
  classifyTimestamp,
  resolveRekor,
  resolveBlobRefs,
  resolveCaptureMethodLabel,
  CONTENT_CANONICALIZATION_SIGNALS,
  CONTENT_HASH_SIGNALS,
  TYPE_RESOLUTION_SIGNALS,
  SIGNER_IDENTITY_SIGNALS,
  CAPTURE_METHOD_VOCAB_SIGNALS,
  CONTENT_PROFILE_SIGNALS,
  TIMESTAMP_FAILURE_NOTES,
  KEY_TRUST_BUNDLE_REGISTRY_NOT_USED,
  KEY_TRUST_SUPPLIED_REGISTRY,
  SIGNER_IDENTITY_SUPPLIED_REGISTRY,
  LIFECYCLE_STATE_SIGNALS,
  LIFECYCLE_SOURCE_SIGNALS,
} from './trust-signal.ts';
import {
  BARE_ID_ANCHOR,
  HOST_DIRECTORY_PATH,
  canonicalPublisherOrigin,
  fetchHostDirectory,
  isPublisherHostname,
  parseHostSegment,
  resolveHostRecognition,
  type HostDirectory,
  type HostRecognition,
} from './host-directory.ts';

// Re-export the host-recognition surface (Phase D / Q47) so the verifier UI pulls
// the whole verification flow — cryptographic checks AND publisher recognition —
// from this one module. `HOST_DIRECTORY` comes along so the UI can render the
// roster-driven "try another host" affordance from the same source of truth the
// well-known route serves.
export { resolveHostRecognition, HOST_DIRECTORY } from './host-directory.ts';
// The publisher-origin grammar the two `/verify` entry points share. It is DEFINED
// in host-directory — beside `canonicalPublisherOrigin`, the normalization it
// applies, and out of reach of this module's verify-core imports so the /badge page
// can validate an origin without pulling the verification core into its bundle
// (typedstandards#58). Re-exported here because a caller reasoning about a `/verify`
// link reads this module, and because every existing importer keeps its import path.
export { parseHostSegment, parseHostHint } from './host-directory.ts';
export type {
  HostDirectory,
  HostDirectoryEntry,
  HostRecognition,
  HostRecognitionStatus,
} from './host-directory.ts';

/** The host a bare hash / slug is resolved against when the caller names none —
 *  there is no origin in a bare identifier, so it is looked up on the anchor the
 *  published host directory DECLARES (`bareIdentifierHost`), not on whichever
 *  publisher happens to be listed first. Recognition is directory-driven (see
 *  resolveHostRecognition) and never keyed off this constant, so being the anchor
 *  confers nothing. A share link or picker choice that names a host overrides it —
 *  see {@link bareIdCommitmentUrl}. */
export const DEFAULT_HOST = BARE_ID_ANCHOR;

/** The §9.2.1 commitment sidecar shape (what the WS1 endpoint returns). A bundle
 *  may additionally carry `package` / `trustRegistry` inline for offline use. */
export interface Commitment {
  /** The schema version this view was published against (spec §8.8.1). The
   *  DUAL-ERA key pair of the 2026-08-19 settlement (Appendix J,
   *  `frozen-in-signed-artifacts`): views minted after a publisher's cutover
   *  carry `protocolVersion`; views minted before it carry the same value
   *  under `evidenceProtocolVersion`, which stays valid FOREVER — the key is
   *  frozen inside already-signed artifacts and rewriting it would invalidate
   *  the signature. Both are optional and neither is read by this flow (the
   *  verification depth comes from the proofs, not from a declared version),
   *  so era is not a trust signal here in the strongest possible sense: there
   *  is no code path that can branch on it. */
  protocolVersion?: string;
  /** Prior-era spelling of {@link Commitment.protocolVersion}. Accepted
   *  forever; see the note there. */
  evidenceProtocolVersion?: string;
  packageHash: string;
  packageUrl?: string;
  captureMethod?: string | null;
  contentProfile?: string;
  producerProfile?: string;
  type?: string;
  signer?: { bindingTier?: string; identifier?: string; displayName?: string };
  contentHash?: Record<string, string>;
  contentCanonicalization?: string;
  signature?: VerifySignatureEnvelope | null;
  signerIdentity?: {
    provider?: string;
    providerId?: string;
    displayName?: string;
    profileUrl?: string;
  } | null;
  rfc3161Timestamp?: string | null;
  rekorEntryId?: string | null;
  rekorInclusionProof?: string | null;
  /** The Rekor entry's canonical leaf bytes (base64), carried so the browser can
   *  verify Merkle inclusion OFFLINE from the carried proof — no re-fetch (#119 P1). */
  rekorEntryBody?: string | null;
  lifecycle?: CommitmentLifecycleState | null;
  /** Signed lifecycle attestation envelopes (#119 P3), carried so the browser
   *  resolves #10 to `source: 'attestation-chain'` offline — independently verifying
   *  each node (hash, signature, reachability). Absent ⇒ resolve at STATE depth. */
  lifecycleAttestations?: CarriedLifecycleNode[];
  trustRegistryUrl?: string;
  trustRegistryUrlLegacy?: string;
  subjectTitle?: string;
  subjectSummary?: string;
  /** Offline bundle extensions (not emitted by the endpoint). A `trustRegistry`
   *  carried here is supplied by whoever made the record: it can lower a key
   *  status, and never earns what the declared https: registry earns (#78). */
  package?: Record<string, unknown> | null;
  trustRegistry?: unknown;
  /** A publisher directory a record may carry. Never read: recognition uses only
   *  the typedstandards.org directory, and the page says this one was not used
   *  (#78). */
  hostDirectory?: unknown;
}

export type InputMode = 'hash' | 'url' | 'bundle';

export class VerifyFlowError extends Error {}

// --- Input detection ------------------------------------------------------

const HASH_RE = /^[0-9a-f]{64}$/i;

/**
 * Auto-detect the input kind. A 64-hex string is a package hash; an http(s) URL
 * is a hosted reference; a string starting with `{` is a pasted bundle/commitment
 * JSON; anything else is treated as a record slug (resolved like a hash).
 */
export function detectInputMode(raw: string): InputMode {
  const s = raw.trim();
  if (!s) return 'hash';
  if (s.startsWith('{')) return 'bundle';
  if (/^https?:\/\//i.test(s)) return 'url';
  return 'hash'; // 64-hex hash OR a record slug — both resolve by identifier
}

/** A glanceable label for the detected mode. */
export function describeMode(mode: InputMode, raw: string): string {
  if (mode === 'bundle') return 'Uploaded bundle';
  if (mode === 'url') return 'Hosted URL';
  return HASH_RE.test(raw.trim()) ? 'Package hash' : 'Record slug';
}

// --- Resolution -----------------------------------------------------------

/** How a piece of the verification input was obtained — drives the honest
 *  per-mode independence guarantee shown in the UI. */
export type SourceKind = 'fetched' | 'inline';

export interface ResolvedInput {
  commitment: Commitment;
  pkg: Record<string, unknown> | null;
  registry: TrustRegistry | undefined;
  /** The host directory used for publisher recognition (Phase D): `'unavailable'`
   *  when an online fetch of it failed, `'not_fetched'` in bundle mode, which does
   *  not fetch it. Distinct from the publisher sources below: it is only ever the
   *  verifier's curator's (typedstandards.org), never one the record carries, so
   *  it is tracked separately. */
  directory: HostDirectory | 'unavailable' | 'not_fetched';
  /** Where each piece came from, for the independence disclosure. */
  sources: {
    commitment: { kind: SourceKind; url?: string };
    pkg: { kind: SourceKind; url?: string };
    registry: { kind: SourceKind; url?: string };
  };
  /** Where `registry` came from, in verify-core's terms (hub ADR-0030 §4 rule 3):
   *  `bundle` when it was supplied with the record — read inline, or from a URL
   *  that is not https: — and `declared-url` when it was fetched from the view's
   *  https: `trustRegistryUrl` / `trustRegistryUrlLegacy`. Absent when no registry
   *  was loaded — no provenance is claimed for nothing. verify-core reads it only
   *  for a signer whose identifier is key-derived; the site reads it for every
   *  signer (#78). */
  registryProvenance?: TrustRegistryProvenance;
  /** True only when EVERYTHING was read from the bundle — i.e. a true offline
   *  verification, fetching nothing. */
  fullyOffline: boolean;
}

async function getJson(url: string, signal?: AbortSignal): Promise<unknown> {
  let res: Awaited<ReturnType<typeof fetch>>;
  try {
    // Plain GET, no custom headers (see the module header re: CORS — preflight and,
    // in a browser, the redirect response's own headers).
    res = await fetch(url, { signal });
  } catch (err) {
    throw new VerifyFlowError(
      `Could not reach ${shortUrl(url)} — the host may be unreachable or block cross-origin reads. (${
        err instanceof Error ? err.message : 'network error'
      })`,
    );
  }
  if (!res.ok) {
    if (res.status === 404) {
      throw new VerifyFlowError(
        `Nothing found at ${shortUrl(url)} (404). For a hash, paste the full 64-character hash or the package's slug.`,
      );
    }
    throw new VerifyFlowError(`Request to ${shortUrl(url)} failed (HTTP ${res.status}).`);
  }
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) {
    throw new VerifyFlowError(
      `${shortUrl(url)} did not return JSON (content-type "${ct || 'unknown'}") — it may be an auth wall or a wrong URL.`,
    );
  }
  return res.json();
}

// --- Vocabulary eras: the commitment path segment -------------------------
//
// The 2026-08-19 vocabulary settlement (spec Appendix J) makes `records` the
// canonical route/page segment and keeps `evidence` as a PERMANENT alias — not
// a deprecation window, because links minted under the old segment are already
// published. Two asymmetric rules follow, and this module implements both:
//
//   RECOGNITION is symmetric and immediate. Every parse accepts either segment,
//   with no preference: an `/evidence/<id>` page URL and a `/records/<id>` page
//   URL are the same input, and a commitment URL under either segment collapses
//   to the same clean share link. Era is not a trust signal.
//
//   CONSTRUCTION is ordered: NEW FIRST, OLD AS FALLBACK. The verifier is
//   neutral infrastructure that must keep working against publishers at BOTH
//   stages of their own cutover, and today that is every publisher — including
//   the reference one, whose new segments deploy in a later phase. Emitting the
//   new form ONLY would break verification for every publisher in the world on
//   the day this ships; emitting the old form only would never adopt the
//   canonical name. So resolution TRIES the canonical form and falls back to
//   the prior-era form when it does not answer (see `resolveCommitment`). The
//   cost is one extra 404 per hosted resolution until publishers cut over, and
//   the guarantee is spec Appendix J rule 4: nothing stops resolving.
//
// Order is load-bearing — `COMMITMENT_API_SEGMENTS[0]` is the canonical form.

/** The settlement-era canonical API/page path segment (spec Appendix J). */
const CANONICAL_PATH_SEGMENT = 'records';
/** The prior-era segment, served as a permanent alias. */
const PRIOR_ERA_PATH_SEGMENT = 'evidence';

/** Commitment-endpoint path segments in RESOLUTION ORDER: canonical first,
 *  prior-era as the fallback. Never reorder — see the note above. */
const COMMITMENT_API_SEGMENTS = [CANONICAL_PATH_SEGMENT, PRIOR_ERA_PATH_SEGMENT] as const;

/** Matches a publisher's own record-page URL under EITHER era's segment. */
const RECORD_PAGE_RE = new RegExp(
  `/(?:${CANONICAL_PATH_SEGMENT}|${PRIOR_ERA_PATH_SEGMENT})/([^/]+)`,
);

/** Matches a canonical commitment-endpoint pathname under EITHER era's segment. */
const COMMITMENT_PATH_RE = new RegExp(
  `^/api/(?:${CANONICAL_PATH_SEGMENT}|${PRIOR_ERA_PATH_SEGMENT})/([^/]+)/commitment$`,
);

/** How a hosted URL names the commitment to fetch. One classifier, used by BOTH
 *  `deriveCommitmentUrl` (which resolves) and `identifierResolutionKind` (which tells
 *  the UI whether to disclose an anchor), so the two cannot disagree about whether an
 *  input carries a publisher origin. */
type HostedUrlKind =
  | { kind: 'commitment' }
  | { kind: 'record-id'; id: string }
  | { kind: 'package-blob'; hash: string }
  | { kind: 'opaque' };

function classifyHostedUrl(u: URL): HostedUrlKind {
  if (u.pathname.endsWith('/commitment')) return { kind: 'commitment' };
  // PACKAGE-BLOB IS TESTED BEFORE the record-page probe, and the order is
  // load-bearing. A `<64-hex>.json` FILENAME is an unambiguous package blob wherever
  // it sits, while the record-page probe matches any `/records/` or `/evidence/` path
  // SEGMENT — so a storage URL that merely happens to contain one (`…/evidence/
  // <hash>.json`, a real bucket layout) was previously captured as a record id of
  // literally `<hash>.json` and produced the nonsense `…/api/evidence/<hash>.json
  // /commitment`. The more specific signal must win. No publisher's `/records/<id>`
  // or `/evidence/<id>` page URL ends in `<64-hex>.json`, so nothing that genuinely
  // carries a publisher origin is diverted by this. The settlement widened the probe
  // to both segments, which makes this ordering MORE load-bearing, not less: there
  // are now two bucket-layout segment names that can collide with a blob path.
  const blobHash = u.pathname.match(/([0-9a-f]{64})\.json$/i);
  if (blobHash) return { kind: 'package-blob', hash: blobHash[1] };
  const idMatch = u.pathname.match(RECORD_PAGE_RE);
  if (idMatch) return { kind: 'record-id', id: idMatch[1] };
  return { kind: 'opaque' };
}

/**
 * Build the commitment-endpoint URL for a hosted URL input — the CANONICAL
 * (settlement-era) form. For the ordered candidate list a fetch should actually
 * walk, use {@link deriveCommitmentUrlCandidates}; this returns its first entry,
 * which is what a caller wants when it needs one URL to display or compare.
 *
 * Three shapes carry a PUBLISHER ORIGIN and keep it:
 *   - a direct `…/commitment` URL — already the resource;
 *   - a publisher's own `…/records/<id>…` (or prior-era `…/evidence/<id>…`) URL —
 *     the origin serving that page IS the publisher, so
 *     `${u.origin}/api/records/<id>/commitment` is its commitment;
 *   - anything else, used as-is.
 *
 * The PAGE segment a publisher happens to use says nothing about which API
 * segment it serves — a publisher can cut over its pages and routes at
 * different times, and the reference publisher will. So the page URL's own
 * segment is deliberately NOT copied into the API URL: the id is extracted and
 * re-resolved new-then-old like any other identifier.
 *
 * One shape does NOT, and this is the B5 correction (#44). A PACKAGE-BLOB URL — the
 * badge deep-link's `?url=<package-url>`, whose filename is the 64-hex package hash —
 * names a STORAGE location, not a publisher. Detached object storage is the common
 * pattern (Vercel Blob, S3, R2, GCS) and is the reference publisher's own setup, so
 * the blob's origin routinely has no commitment API at all. Preserving that origin 404s
 * there; re-pointing every blob at the anchor 404s for a self-hosting publisher.
 * Neither is right, because a bare blob URL does not determine its publisher.
 *
 * So the filename hash is treated as exactly what it is — an ORIGIN-LESS IDENTIFIER —
 * and resolved through the same path a bare hash takes: against `host` (the declared
 * anchor unless a link or the picker named one). The UI discloses which host answered
 * and offers the roster to correct it in one click — the same under-determination
 * honesty B6 established. `identifierResolutionKind` is what tells it to.
 *
 * Every origin that IS kept is re-spelled canonically first (#50): `www.` is
 * normalized off (directory-aware — see canonicalPublisherOrigin) so the verifier
 * fetches the canonical origin directly and never rides a publisher's own domain
 * redirect, which a browser fetch cannot follow when the redirect response carries
 * no CORS headers.
 */
export function deriveCommitmentUrl(input: string, host: string = DEFAULT_HOST): string {
  return deriveCommitmentUrlCandidates(input, host)[0];
}

/**
 * The commitment URLs a hosted input resolves to, in RESOLUTION ORDER —
 * canonical (settlement-era) first, prior-era second. `resolveCommitment` walks
 * this list and takes the first that answers with a commitment.
 *
 * Two of the four shapes produce a single candidate rather than two, and the
 * distinction is exact: a list is emitted only where THIS module builds the
 * path, never where it merely passes one through.
 *   - `commitment` / `opaque` — the caller handed us a complete resource URL.
 *     Rewriting its path to a different segment would be inventing a resource
 *     the caller did not name, so it is used exactly as given (one candidate).
 *     Both segments are already RECOGNIZED here, so a prior-era commitment URL
 *     is not second-class — it is simply already resolved.
 *   - `record-id` / `package-blob` — we hold an identifier and mint the path
 *     ourselves, so both eras are minted and tried in order (two candidates).
 *
 * Always non-empty; `[0]` is the canonical form.
 */
export function deriveCommitmentUrlCandidates(
  input: string,
  host: string = DEFAULT_HOST,
): string[] {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new VerifyFlowError(`"${input}" is not a valid URL.`);
  }
  const hosted = classifyHostedUrl(u);
  switch (hosted.kind) {
    case 'commitment':
      return [withCanonicalOrigin(u)];
    case 'record-id':
      // The id is taken verbatim from a URL pathname — already percent-encoded,
      // so it is NOT re-encoded here (that would double-encode it).
      return COMMITMENT_API_SEGMENTS.map(
        (segment) => `${canonicalPublisherOrigin(u.origin)}/api/${segment}/${hosted.id}/commitment`,
      );
    case 'package-blob':
      return bareIdCommitmentUrlCandidates(hosted.hash, host);
    default:
      // Last resort: treat the URL itself as the commitment resource.
      return [withCanonicalOrigin(u)];
  }
}

/** The URL re-spelled on its canonical publisher origin (#50) — path, query, and
 *  fragment untouched. (Userinfo is dropped with the origin rebuild; `fetch`
 *  rejects credentialed URLs anyway.) */
function withCanonicalOrigin(u: URL): string {
  return `${canonicalPublisherOrigin(u.origin)}${u.pathname}${u.search}${u.hash}`;
}

/** Why an input needs an anchor: it is a bare hash/slug, or it is a package-blob URL
 *  whose origin names storage rather than a publisher. Both are origin-less. */
export type IdentifierResolution = 'bare' | 'package-blob';

/**
 * Whether this input resolves BY IDENTIFIER rather than by an origin it carries, and
 * which kind — `undefined` when the input names its own publisher.
 *
 * The verifier's disclosure line renders exactly on this predicate. A package-blob
 * URL looks like it carries an origin and does not, which is precisely why the
 * disclosure has to cover it: the user is owed the name of the host that answered and
 * a way to change it, in the case where the input's own appearance is misleading.
 */
export function identifierResolutionKind(
  mode: InputMode,
  raw: string,
): IdentifierResolution | undefined {
  const s = raw.trim();
  if (!s) return undefined;
  if (mode === 'hash') return 'bare';
  if (mode !== 'url') return undefined;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return undefined;
  }
  return classifyHostedUrl(u).kind === 'package-blob' ? 'package-blob' : undefined;
}

// --- Share links + the /verify/… route shape ------------------------------
//
// One identifier, two link depths, one round-trip:
//
//   /verify/<id>          → resolve <id> against the directory's declared anchor
//   /verify/<host>/<id>   → resolve <id> against https://<host>
//
// `deriveShareTarget` mints these and `parseVerifyTarget` reads them back; the pair
// is closed by `commitmentUrlOn`, the one template both sides build the commitment
// path from — and which `deriveCommitmentUrlCandidates` also routes package-blob
// URLs through, so every origin-less input takes one path. The two-segment form is
// what gives EVERY publisher the clean short link: it used to be earned only by a
// commitment URL on the anchor origin, so a second publisher's result could only ever
// be shared as an opaque `?url=<encoded>` blob.
//
// The round-trip survives the vocabulary settlement in BOTH directions. A commitment
// URL that answered under EITHER era's segment collapses to the same short link
// (`deriveShareTarget` recognizes both), and re-resolving that short link goes back
// through the canonical-first candidate list — so a link shared today from a
// prior-era publisher keeps working after that publisher cuts over, and vice versa.
// The share link carries the IDENTIFIER, never the era.

/** The single place the `/api/<segment>/<id>/commitment` shape is built, for BOTH
 *  eras — so a minted share link and the request it later re-issues cannot drift,
 *  and so widening the vocabulary could not fork the shape. The host is
 *  www-normalized (#50) before the URL is minted — a no-op for the anchor and the
 *  roster's picker origins, which are canonical already; it matters for a host a
 *  link named. */
function commitmentUrlOn(segment: string, id: string, host: string): string {
  return `${canonicalPublisherOrigin(host)}/api/${segment}/${encodeURIComponent(id)}/commitment`;
}

/** The CANONICAL commitment URL a bare identifier resolves to on `host` — the
 *  settlement-era `/api/records/<id>/commitment` form. `host` defaults to the
 *  anchor. This is the form a share link round-trips through and the form the
 *  UI displays; for the ordered list a fetch walks, see
 *  {@link bareIdCommitmentUrlCandidates}. */
export function bareIdCommitmentUrl(id: string, host: string = DEFAULT_HOST): string {
  return commitmentUrlOn(CANONICAL_PATH_SEGMENT, id, host);
}

/** The commitment URLs a bare identifier resolves to on `host`, in RESOLUTION
 *  ORDER: canonical first, prior-era second. Both are the same identifier on the
 *  same host — only the path segment differs — so trying them in order costs one
 *  extra request against a publisher that has not cut over yet, and costs nothing
 *  against one that has. */
export function bareIdCommitmentUrlCandidates(
  id: string,
  host: string = DEFAULT_HOST,
): string[] {
  return COMMITMENT_API_SEGMENTS.map((segment) => commitmentUrlOn(segment, id, host));
}

/** What a `/verify/…` path resolves: an identifier, plus the origin to resolve it
 *  against when the link named one. `host` absent ⇒ the anchor (`DEFAULT_HOST`). */
export interface VerifyTarget {
  id: string;
  host?: string;
}

/**
 * Read a `/verify/…` path back into the identifier it names. `segments` is the
 * DECODED catch-all param.
 *
 *   ['<id>']          → { id }                    — resolved against the anchor
 *   ['<host>','<id>'] → { id, host: origin }      — resolved against that origin
 *
 * `undefined` for anything else: no segments, more than two, an empty id, or a first
 * segment that is not a well-formed host. BACK-COMPAT IS THE POINT of the
 * one-segment branch — every `/verify/<id>` link minted before the two-segment form
 * existed still resolves exactly as it did, against the declared anchor.
 */
export function parseVerifyTarget(segments: string[]): VerifyTarget | undefined {
  if (segments.length === 1) {
    const id = segments[0];
    return id ? { id } : undefined;
  }
  if (segments.length === 2) {
    const host = parseHostSegment(segments[0]);
    const id = segments[1];
    return host && id ? { id, host } : undefined;
  }
  return undefined;
}

/**
 * Build the root-relative share link that re-resolves the SAME commitment that just
 * verified. It is rebuilt from `sources.commitment.url` — the exact request URL that
 * returned 200 — never from `commitment.packageHash`. The URL that answered is the
 * resolved FACT; `packageHash` is an inference about how a publisher indexes its
 * commitment endpoint, which nothing requires. (An earlier version of this comment
 * justified the rule by claiming the endpoint does not resolve a raw hash at all.
 * That premise was wrong — the reference publisher's endpoint resolves both a slug
 * and a 64-hex hash — but it is one publisher's implementation detail either way,
 * which is exactly why the link cannot be built on it. The rule stands; only its
 * reason changed.)
 *
 * - `null` when no commitment URL exists (inline / bundle — nothing hosted to link to).
 * - A commitment-endpoint URL under EITHER era's segment
 *   (`^/api/(?:records|evidence)/<id>/commitment$`) collapses to a clean short link:
 *   `/verify/<id>` on the anchor origin, `/verify/<host>/<id>` anywhere else. Both
 *   path segments are `encodeURIComponent`'d; the id is decoded first so it survives
 *   the extra encode the rebuild applies.
 *
 *   The collapse is ERA-BLIND on purpose. A prior-era commitment URL is what a
 *   not-yet-cut-over publisher answers with TODAY (see `resolveCommitment`), so
 *   refusing to collapse it would deny every current publisher's result the clean
 *   short link and hand the user an opaque `?url=` blob instead. What round-trips is
 *   the IDENTIFIER: re-resolving the short link walks the canonical-first candidate
 *   list afresh, which lands on whichever segment that publisher serves at that
 *   moment — so a link minted before a publisher's cutover keeps working after it.
 * - Falls back to `/verify?url=<encoded>` — which re-resolves against the ORIGINAL
 *   origin via 'url' mode (`deriveCommitmentUrl` is idempotent for a
 *   `/commitment`-terminated URL) — for an unusual path, a decoded `/` in the id
 *   (which no single path segment can carry), or an origin a host segment cannot
 *   express: non-https, or carrying an explicit port.
 *
 * The only residual risk — a backend slug alias that later expires — is outside the
 * verifier's control and no worse than the id the user just verified with.
 */
export function deriveShareTarget(resolved: ResolvedInput): string | null {
  const commitmentUrl = resolved.sources.commitment.url;
  if (!commitmentUrl) return null; // inline (bundle) — nothing to re-resolve.

  let u: URL;
  try {
    u = new URL(commitmentUrl);
  } catch {
    return null;
  }

  const m = u.pathname.match(COMMITMENT_PATH_RE);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (!id.includes('/')) {
      if (u.origin === DEFAULT_HOST) return `/verify/${encodeURIComponent(id)}`;
      // Any other publisher gets the same clean link, with its origin carried in the
      // first segment. Roster membership is NOT consulted — see parseHostSegment.
      if (u.protocol === 'https:' && !u.port && isPublisherHostname(u.hostname)) {
        return `/verify/${encodeURIComponent(u.host)}/${encodeURIComponent(id)}`;
      }
    }
  }

  return `/verify?url=${encodeURIComponent(commitmentUrl)}`;
}

/** Options shared by the resolution entry points. `host` names the origin a BARE
 *  IDENTIFIER resolves against, overriding the declared anchor — set by a
 *  `/verify/<host>/<id>` link or the host picker. Ignored for 'url' and 'bundle'
 *  input, which carry their own origin (or none at all). */
export interface ResolveOptions {
  host?: string;
}

/**
 * Step 1 — resolve the commitment for hash / URL / bundle input.
 *
 * NEW-THEN-OLD RESOLUTION (spec Appendix J). For hosted input the candidate list
 * is walked in order — canonical segment first, prior-era second — and the FIRST
 * candidate that answers with a real commitment wins. A candidate that does not
 * is not a user-facing failure; it is simply not that publisher's segment.
 *
 * "Does not answer" deliberately covers every way a candidate can fail to be a
 * commitment, not just 404: an unreachable host, a non-JSON body, any non-2xx,
 * and a 200 that parses but carries no `packageHash`. The last one matters more
 * than it looks — `/api/records/…` is a plausible path for an unrelated
 * records API on some publisher, and a JSON 200 from it must fall through to the
 * prior-era segment rather than abort a verification that would have succeeded.
 * The rule is the settlement's fourth normative dual-era rule: no migration step
 * may create a state where something that resolved before stops resolving.
 *
 * When EVERY candidate fails, the LAST candidate's error surfaces. That is the
 * prior-era one, which is the segment every publisher serves today — so the
 * message a user sees for a genuinely bad identifier names a URL that really
 * exists, and is byte-for-byte the message they saw before this change. The
 * canonical-form 404 that precedes it is expected traffic during the migration
 * and is never shown.
 *
 * The returned `url` is the one that ANSWERED, not the one first tried: it feeds
 * `sources.commitment.url`, the independence disclosure, and `deriveShareTarget`,
 * all of which must reflect the resolved fact rather than an attempt.
 */
export async function resolveCommitment(
  mode: InputMode,
  raw: string,
  signal?: AbortSignal,
  opts: ResolveOptions = {},
): Promise<{ commitment: Commitment; url?: string }> {
  const s = raw.trim();
  if (mode === 'bundle') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(s);
    } catch {
      throw new VerifyFlowError('That bundle is not valid JSON.');
    }
    const commitment = parsed as Commitment;
    if (!commitment || typeof commitment !== 'object' || !commitment.packageHash) {
      throw new VerifyFlowError(
        'That JSON is not a commitment bundle (it has no `packageHash`). Paste a §9.2.1 commitment sidecar — for example, what a publisher’s `/api/records/<id>/commitment` endpoint returns (the prior-era `/api/evidence/` path is still accepted).',
      );
    }
    return { commitment };
  }
  // `host` reaches BOTH branches: a bare identifier carries no origin, and a
  // package-blob URL's origin is storage rather than a publisher (see
  // deriveCommitmentUrlCandidates), so each resolves against it.
  const host = opts.host ?? DEFAULT_HOST;
  const candidates =
    mode === 'hash'
      ? bareIdCommitmentUrlCandidates(s, host)
      : deriveCommitmentUrlCandidates(s, host);

  let lastError: unknown;
  for (const url of candidates) {
    try {
      const commitment = (await getJson(url, signal)) as Commitment;
      if (!commitment?.packageHash) {
        throw new VerifyFlowError(
          `${shortUrl(url)} did not return a commitment (no \`packageHash\`).`,
        );
      }
      return { commitment, url };
    } catch (err) {
      // A caller-cancelled verification is not a failed candidate — trying the
      // next one would issue a request the user already asked us to stop making.
      if (signal?.aborted) throw err;
      lastError = err;
    }
  }
  throw lastError;
}

/** A resolution step, emitted as each piece is obtained (drives the live UI). */
export interface ResolveStep {
  /** `bundle-directory` is the directory a record carries, which is never used. */
  key: 'commitment' | 'package' | 'registry' | 'directory' | 'bundle-directory';
  label: string;
  kind: SourceKind;
  url?: string;
  /** `done` (default) → the step retrieved/read its piece (rendered with a ✓).
   *  `skipped` → the step intentionally retrieved NOTHING: the package content was
   *  private (no location to fetch) or its location couldn't be reached. A ✓ would
   *  misrepresent that, so the UI renders a neutral marker instead. */
  state?: 'done' | 'skipped';
}

/** Steps 2 + 3 — fetch (or read inline) the package blob and the trust registry.
 *  `onStep` fires as each piece resolves so the UI can show it happening live. */
export async function resolveInput(
  mode: InputMode,
  raw: string,
  signal?: AbortSignal,
  onStep?: (step: ResolveStep) => void,
  opts: ResolveOptions = {},
): Promise<ResolvedInput> {
  const { commitment, url: commitmentUrl } = await resolveCommitment(mode, raw, signal, opts);
  const commitmentKind: SourceKind = mode === 'bundle' ? 'inline' : 'fetched';
  onStep?.({
    key: 'commitment',
    label: commitmentKind === 'inline' ? 'Read commitment from bundle' : 'Fetched commitment sidecar',
    kind: commitmentKind,
    ...(commitmentUrl ? { url: commitmentUrl } : {}),
  });

  // Package blob. Three outcomes when the bytes aren't read inline:
  //   - a location is present and fetches            → pkg set (normal path);
  //   - NO location (the commitment redacted it)     → content is private by design,
  //                                                     pkg null, step `skipped`;
  //   - a location is present but its fetch FAILS    → content unfetchable (404 /
  //                                                     network), pkg null, step
  //                                                     `skipped` — do NOT abort the
  //                                                     whole verification: the
  //                                                     commitment is still checkable
  //                                                     and an availability gap is not
  //                                                     tampering.
  // verify-core's `envelopeIntegrity` distinguishes private vs. unfetchable from the
  // commitment shape (see buildVerifyInput); here we only fork the live step label.
  let pkg: Record<string, unknown> | null;
  let pkgSource: { kind: SourceKind; url?: string };
  let pkgStep: { label: string; state: 'done' | 'skipped' };
  if (commitment.package) {
    pkg = commitment.package;
    pkgSource = { kind: 'inline' };
    pkgStep = { label: 'Read package from bundle', state: 'done' };
  } else if (commitment.packageUrl) {
    try {
      pkg = (await getJson(commitment.packageUrl, signal)) as Record<string, unknown>;
      pkgSource = { kind: 'fetched', url: commitment.packageUrl };
      pkgStep = { label: 'Fetched package blob', state: 'done' };
    } catch (err) {
      if (signal?.aborted) throw err; // a real cancellation still aborts.
      pkg = null;
      pkgSource = { kind: 'fetched', url: commitment.packageUrl };
      pkgStep = { label: 'Content could not be fetched', state: 'skipped' };
    }
  } else {
    pkg = null;
    pkgSource = { kind: 'fetched' };
    pkgStep = { label: 'Content is private — not fetched', state: 'skipped' };
  }
  onStep?.({
    key: 'package',
    label: pkgStep.label,
    kind: pkgSource.kind,
    state: pkgStep.state,
    ...(pkgSource.url ? { url: pkgSource.url } : {}),
  });

  // Trust registry. A registry the record carries is its own statement (#78). Online,
  // when the record also declares an https: registry, that one is fetched and the
  // carried copy is not read (#93): only the declared registry can confirm the key,
  // and it can also disavow it. The carried copy is read in bundle mode, which stays
  // offline; online when no https: registry is declared; and online when the
  // declared one cannot be fetched or is not valid. It can then only lower.
  const registryUrl = commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy;
  const carriesRegistry = commitment.trustRegistry !== undefined;
  let registry: TrustRegistry | undefined;
  let registrySource: { kind: SourceKind; url?: string };
  let declaredRegistryUnreachable = false;
  if (carriesRegistry && (mode === 'bundle' || !isHttpsUrl(registryUrl))) {
    registry = validateRegistry(commitment.trustRegistry);
    registrySource = { kind: 'inline' };
  } else if (carriesRegistry && registryUrl) {
    let declared: TrustRegistry | undefined;
    try {
      declared = validateRegistry(await getJson(registryUrl, signal));
    } catch (err) {
      if (signal?.aborted) throw err;
    }
    if (declared) {
      registry = declared;
      registrySource = { kind: 'fetched', url: registryUrl };
    } else {
      registry = validateRegistry(commitment.trustRegistry);
      registrySource = { kind: 'inline' };
      declaredRegistryUnreachable = true;
    }
  } else if (registryUrl) {
    registry = validateRegistry(await getJson(registryUrl, signal));
    registrySource = { kind: 'fetched', url: registryUrl };
  } else {
    registry = undefined;
    registrySource = { kind: 'fetched' };
  }
  const registryProvenance = registryProvenanceOf(registry, registrySource);
  // The step says where the registry came from, for every signer (hub ADR-0030 §10;
  // #78): none declared; a bundle registry that is not valid; or a registry URL that
  // is not https:, which counts as carried in the bundle; or a declared registry that
  // could not be fetched, so the carried one was read (#93).
  const registryStep: ResolveStep =
    registrySource.kind === 'inline'
      ? registry === undefined
        ? { key: 'registry', label: 'Trust registry in bundle is not valid — not used', kind: 'inline', state: 'skipped' }
        : declaredRegistryUnreachable
          ? {
              key: 'registry',
              label:
                'The declared trust registry could not be fetched — read the one in the record, which can lower key trust, never raise it',
              kind: 'inline',
            }
          : { key: 'registry', label: 'Read trust registry from bundle', kind: 'inline' }
      : !registrySource.url
        ? { key: 'registry', label: 'No trust registry declared — none fetched', kind: 'fetched', state: 'skipped' }
        : isHttpsUrl(registrySource.url)
          ? { key: 'registry', label: 'Fetched publisher trust registry', kind: 'fetched', url: registrySource.url }
          : {
              key: 'registry',
              label: 'Read trust registry from a URL that is not https: — it can lower key trust, never raise it',
              kind: 'fetched',
              url: registrySource.url,
            };
  onStep?.(registryStep);

  // Host directory (Phase D recognition dimension). It is the verifier's curator
  // data, not the package's, so it is resolved separately from the publisher
  // sources above, and a directory the record carries is never read (#78): it is
  // the signer's own statement. Bundle mode honours the offline intent and does NOT
  // touch the network: the directory is `'not_fetched'`, and recognition says so (#93).
  // Online modes fetch the canonical same-origin directory; any failure degrades to
  // 'unavailable' without affecting the cryptographic verdict.
  if (commitment.hostDirectory !== undefined) {
    onStep?.({
      key: 'bundle-directory',
      label: 'Publisher directory in the bundle — not used',
      kind: 'inline',
      state: 'skipped',
    });
  }
  let directory: HostDirectory | 'unavailable' | 'not_fetched';
  if (mode === 'bundle') {
    directory = 'not_fetched';
  } else {
    directory = await fetchHostDirectory(globalThis.fetch, HOST_DIRECTORY_PATH, signal);
    if (directory !== 'unavailable') {
      onStep?.({ key: 'directory', label: 'Loaded the typedstandards.org publisher directory', kind: 'fetched' });
    }
  }

  // A self-certified signer needs no registry (hub ADR-0030 §6): a bundle whose inline
  // package names a key-derived signer and that declares no registry URL has read
  // everything it verifies against from the bundle. Every other case is unchanged.
  const selfCertifiedNoRegistry =
    isKeyDerivedIdentifier(signerIdentifierOf(pkg)) &&
    commitment.trustRegistryUrl === undefined &&
    commitment.trustRegistryUrlLegacy === undefined;
  const fullyOffline =
    mode === 'bundle' &&
    pkgSource.kind === 'inline' &&
    (registrySource.kind === 'inline' || selfCertifiedNoRegistry);

  return {
    commitment,
    pkg,
    registry,
    directory,
    sources: {
      commitment: { kind: mode === 'bundle' ? 'inline' : 'fetched', url: commitmentUrl },
      pkg: pkgSource,
      registry: registrySource,
    },
    ...(registryProvenance ? { registryProvenance } : {}),
    fullyOffline,
  };
}

/** Whether `url` is an absolute `https:` URL. */
export function isHttpsUrl(url: string | undefined): boolean {
  if (!url) return false;
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * The registry's provenance for verify-core's `VerifyDeps.registryProvenance`
 * (hub ADR-0030 §4 rule 3): read from the bundle → `bundle`; fetched from the
 * view's declared `https:` URL → `declared-url`. A trust registry counts as
 * declared only when fetched from an `https:` URL: one read from any other URL
 * (`data:`, `blob:`, `http:`, a relative URL) is `bundle`, so it can lower the
 * status and never raise it. `undefined` when no registry was loaded. A `fetched`
 * source with no URL means nothing was fetched. verify-core reads the provenance
 * only for a key-derived signer; the site's #5 and #14 rows, headline and
 * recognition read it for every signer (#78).
 */
export function registryProvenanceOf(
  registry: TrustRegistry | undefined,
  source: { kind: SourceKind; url?: string },
): TrustRegistryProvenance | undefined {
  if (registry === undefined) return undefined;
  if (source.kind === 'inline') return 'bundle';
  if (!source.url) return undefined;
  return isHttpsUrl(source.url) ? 'declared-url' : 'bundle';
}

/** The package's `signer.identifier`, when it is a string. */
function signerIdentifierOf(pkg: Record<string, unknown> | null | undefined): string | undefined {
  const signer = pkg?.['signer'];
  if (!signer || typeof signer !== 'object') return undefined;
  const id = (signer as { identifier?: unknown }).identifier;
  return typeof id === 'string' ? id : undefined;
}

/** Whether the package's signer identifier is key-derived (hub ADR-0030 §3:
 *  it begins `did:key:`). The site's ADR-0030 §10 display rules key on this,
 *  never on `bindingTier`. */
export function hasKeyDerivedSigner(pkg: Record<string, unknown> | null | undefined): boolean {
  return isKeyDerivedIdentifier(signerIdentifierOf(pkg));
}

/** Map the resolved commitment + package to the verify-core input. The carried Rekor
 *  inclusion proof is parsed with verify-core's shared `parseInclusionProof` — the one
 *  guard the server route, this flow, and the backfill all share (#119 P4).
 *
 *  `opts.offline` (set for a fully self-contained bundle) makes verification
 *  OFFLINE-FIRST (#119 Q15): when the bundle carries the Rekor inclusion proof + entry
 *  body — which verify #8 cryptographically with no network — we drop `rekorEntryId` so
 *  `verifyRecord` skips its redundant online hash-parity re-fetch (verify.ts:212).
 *  The carried Merkle inclusion is strictly stronger than the online parity, and the
 *  `integratedTime` that fetch would yield isn't available offline anyway, so #5 bounds
 *  on the carried, verified RFC 3161 genTime instead. This is what makes a self-contained
 *  bundle verify with TRULY zero network. Online (hosted/URL) verification is unchanged —
 *  `rekorEntryId` is kept, so the online parity + its integratedTime still apply. */
export function buildVerifyInput(
  commitment: Commitment,
  pkg: Record<string, unknown> | null,
  opts: { offline?: boolean } = {},
): VerifyInput {
  const rekorInclusionProof = parseInclusionProof(commitment.rekorInclusionProof);
  const carriedInclusion = !!(rekorInclusionProof && commitment.rekorEntryBody);
  const dropOnlineRekor = !!opts.offline && carriedInclusion;
  return {
    package: pkg,
    packageHash: commitment.packageHash,
    signature: commitment.signature ?? null,
    rfc3161Timestamp: commitment.rfc3161Timestamp ?? null,
    rekorEntryId: dropOnlineRekor ? null : (commitment.rekorEntryId ?? null),
    rekorInclusionProof,
    rekorEntryBody: commitment.rekorEntryBody ?? null,
    lifecycle: commitment.lifecycle ?? null,
    // When the content is unavailable, tell verify-core WHY so #1 reads N/A (private)
    // vs. unconfirmed (unfetchable) rather than a false "altered". The signal is the
    // commitment shape: a redacted location (no `packageUrl`) ⇒ private by design; a
    // present location that nonetheless yielded no package ⇒ a fetch failure.
    ...(pkg === null
      ? { contentUnavailableReason: commitment.packageUrl ? 'unfetchable' : 'private' }
      : {}),
  };
}

/**
 * Independently resolve #10 from the commitment's carried signed attestation chain
 * (#119 P3), or `undefined` when none is carried (the verifier then resolves at STATE
 * depth). The result is injected as `deps.lifecycleResolution` — the same mechanism
 * the civicaitools.org server uses for its DB-resolved chain — so the browser reaches
 * `source: 'attestation-chain'` having verified each node itself (hash, signature,
 * reachability). The target signer is the content node's `signer.identifier`; with
 * none, no attestation can signer-match, so the status honestly stays active.
 */
export function resolveCarriedLifecycle(commitment: Commitment): LifecycleResolution | undefined {
  const carried = commitment.lifecycleAttestations;
  if (!carried || carried.length === 0) return undefined;
  return verifyLifecycleChain(carried, commitment.packageHash, commitment.signer?.identifier ?? '');
}

/** Run the §9.2 check suite in the browser. A browser-resolved lifecycle chain (from
 *  `resolveCarriedLifecycle`) is injected as the deeper #10 resolution when present.
 *  `registryProvenance` (from `ResolvedInput.registryProvenance`) tells verify-core
 *  where the registry came from; omitted, verify-core treats a registry as carried
 *  in the bundle, which is the conservative reading. */
export function runVerify(
  input: VerifyInput,
  registry: TrustRegistry | undefined,
  lifecycleResolution?: LifecycleResolution,
  registryProvenance?: TrustRegistryProvenance,
): Promise<VerifyResult> {
  return verifyRecord(input, {
    registry,
    fetch: globalThis.fetch,
    ...(registryProvenance ? { registryProvenance } : {}),
    ...(lifecycleResolution ? { lifecycleResolution } : {}),
  });
}

// --- "Show the math" rows -------------------------------------------------

export interface MathLine {
  label: string;
  value: string;
  /** Render value in monospace (hashes, keys, ids). */
  mono?: boolean;
  /** The full value, when `value` is truncated for display. */
  full?: string;
}

export interface CheckRow {
  num: string;
  name: string;
  signal: ResolvedTrustSignal;
  math: MathLine[];
  /** Optional honest depth caveat for a row whose verdict is shallower than its
   *  signal might imply. (#7/#8 are now full offline crypto, so neither sets one.) */
  depthNote?: string;
}

function truncMiddle(s: string, head = 10, tail = 8): string {
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

function row(
  num: string,
  name: string,
  descriptor: TrustSignalDescriptor,
  math: MathLine[],
  depthNote?: string,
): CheckRow {
  return { num, name, signal: toResolvedSignal(descriptor), math, ...(depthNote ? { depthNote } : {}) };
}

// --- Registry freshness (#119 P4 PR-C: revocation-staleness honesty) -------

/** The registry document's self-declared as-of date (`generatedAt`, the CRL
 *  `thisUpdate` precedent). Read defensively: verify-core's `TrustRegistry` type
 *  doesn't yet declare the field, but `validateRegistry` passes it through, so it
 *  is present at runtime on a stamped registry. */
export function registryGeneratedAt(registry: TrustRegistry | undefined): string | undefined {
  const g = (registry as { generatedAt?: unknown } | undefined)?.generatedAt;
  return typeof g === 'string' ? g : undefined;
}

/** Render an ISO timestamp as a plain YYYY-MM-DD, or pass the raw value through if
 *  it isn't a parseable date (honest-but-imprecise, never a throw). */
function fmtAsOf(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10);
}

/** Where the registry the verdict relied on came from, for the #5 staleness note
 *  and the online-recheck affordance. */
export interface RegistryMeta {
  /** 'inline' = a snapshot carried in the bundle; 'fetched' = pulled live. */
  kind: SourceKind;
  /** The live registry URL, when one is known (drives the recheck affordance even
   *  for an inline snapshot whose commitment also names a URL). */
  url?: string;
  /** The registry document's `generatedAt`, when stamped. */
  generatedAt?: string;
  /** Whether a registry was actually loaded (vs. unavailable). */
  available: boolean;
  /** The registry's provenance as passed to verify-core (see
   *  `registryProvenanceOf`), when a registry was loaded. */
  provenance?: TrustRegistryProvenance;
}

// Key-trust statuses whose verdict actually CONSULTED the registry — the only ones
// for which a snapshot/liveness caveat is meaningful. `legacy_embedded` was never
// registry-vouched, and `registry_unavailable` had no registry to be stale.
const REGISTRY_BACKED_STATUSES = new Set<KeyTrustStatus>([
  'active',
  'deprecated_valid',
  'deprecated_invalid',
  'revoked',
  'unknown_key',
]);

// Key-trust statuses by which a registry CONFIRMS the key (verify-core's
// `verified: true`). From a registry the record supplied, these are the ones the
// site never renders as registered (#78); every other status only lowers.
const REGISTRY_CONFIRMED_STATUSES = new Set<KeyTrustStatus>(['active', 'deprecated_valid']);

/** Whether `keyTrust` is a status a registry the record supplied confirmed — the
 *  reading that does not establish whose key signed (#78). */
function confirmedOnlyBySuppliedRegistry(
  keyTrust: { status: KeyTrustStatus } | null | undefined,
  registry: RegistryMeta | undefined,
): boolean {
  return !!keyTrust && REGISTRY_CONFIRMED_STATUSES.has(keyTrust.status) && registry?.provenance === 'bundle';
}

/** The honest staleness note for the #5 row, or `undefined` when none applies
 *  (verdict didn't rely on the registry). 'fetched' from the declared https: URL is
 *  current; one read from a URL that is not https: is not the live declared registry,
 *  so it gets no note. 'inline' says the snapshot was not checked against the
 *  publisher's domain (#78) and carries the offline-revocation caveat. A missing
 *  `generatedAt` degrades to a dateless but honest note. */
export function keyTrustStalenessNote(
  status: KeyTrustStatus,
  meta: RegistryMeta | undefined,
): string | undefined {
  if (!meta || !meta.available || !REGISTRY_BACKED_STATUSES.has(status)) return undefined;
  const asOf = meta.generatedAt ? ` (as of ${fmtAsOf(meta.generatedAt)})` : '';
  if (meta.kind === 'fetched') {
    return meta.provenance === 'bundle' ? undefined : `Checked against the live registry${asOf}.`;
  }
  const asOfInline = meta.generatedAt ? `, as of ${fmtAsOf(meta.generatedAt)}` : ' (date not stated)';
  const recheck = isHttpsUrl(meta.url) ? ' Re-check against the live registry to close both gaps.' : '';
  return `Read from the registry snapshot carried in this bundle${asOfInline}. It was not checked against the publisher’s domain, and a key revoked after that date cannot be reflected offline.${recheck}`;
}

/** The earliest verified "signed before" time the #5 check is bounded by — the min
 *  of the Rekor integratedTime and a verified RFC 3161 genTime (#119 P2a). Mirrors
 *  the derivation inside verify-core's `verifyRecord`, so a re-check reproduces
 *  the original #5 verdict exactly. Both are seconds since epoch. */
function signedBeforeTimeOf(result: VerifyResult): number | undefined {
  let t = result.rekorIntegratedTime;
  if (result.rfc3161?.verified && result.rfc3161.genTime !== undefined) {
    const genTimeSec = Math.floor(result.rfc3161.genTime / 1000);
    t = t === undefined ? genTimeSec : Math.min(t, genTimeSec);
  }
  return t;
}

export interface KeyTrustRecheck {
  status: KeyTrustStatus;
  verified: boolean;
  /** The live status differs from the snapshot verdict — e.g. now revoked. */
  changed: boolean;
  /** The live registry's `generatedAt`, when stamped. */
  generatedAt?: string;
  /** The registry URL the re-check fetched. */
  url: string;
  /** When the re-check completed (ISO 8601). */
  checkedAt: string;
  /** The live registry, and its provenance as passed to verify-core. */
  registry: TrustRegistry;
  provenance: TrustRegistryProvenance;
  /** The typedstandards.org directory, loaded for recognition. */
  directory: HostDirectory;
  /** The verdict with the registry-dependent checks (#5, #14) read from the live
   *  registry; every other check is the bundle's. */
  result: VerifyResult;
}

/**
 * Re-run the registry-dependent checks (#5, #14) against the LIVE registry,
 * closing the offline-revocation gap when the verifier is connected, and load the
 * typedstandards.org directory so recognition can be read too (#93 item 3, ruling
 * C). The rest of the verdict is offline-complete and registry-independent, so it
 * keeps the bundle's reading. #5 reproduces verify-core's inputs (public key, kid,
 * earliest attested time) so a `changed` result reflects a real registry change —
 * e.g. a key revoked AFTER the snapshot's `generatedAt`.
 *
 * Throws, and so changes no reading, when the re-check cannot complete: no
 * registry URL, a registry that cannot be fetched or is not valid, or a directory
 * that cannot be loaded. Only a completed re-check reaches the page (see
 * `presentVerification`), so a blocked fetch never lowers a reading; an unlisted or
 * revoked key does.
 *
 * `input` is the verify-core input the verdict was computed from. Under a
 * key-derived signer (hub ADR-0030 §3-§4) the check is re-run through
 * `verifyRecord` with the live registry, so the key-derived rule applies, and the
 * registry counts as declared only when the URL is `https:`; from any other URL
 * it can lower the status, never raise it. Every other signer is re-checked only
 * against an `https:` URL: any other URL is part of the record, so it could only
 * confirm the record against itself, and the re-check refuses it (#78).
 */
export async function recheckKeyTrustLive(
  commitment: Commitment,
  result: VerifyResult,
  input: VerifyInput,
  signal?: AbortSignal,
): Promise<KeyTrustRecheck> {
  const url = commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy;
  if (!url) throw new VerifyFlowError('This bundle names no trust-registry URL to re-check against.');
  const keyDerived = hasKeyDerivedSigner(input.package);
  if (!keyDerived && !isHttpsUrl(url)) {
    throw new VerifyFlowError(
      'This record’s trust-registry URL is not https:, so it cannot confirm key trust against the publisher’s domain.',
    );
  }
  const liveRegistry = validateRegistry(await getJson(url, signal));
  if (!liveRegistry) {
    throw new VerifyFlowError(`The live registry at ${shortUrl(url)} is not a valid trust registry.`);
  }
  const directory = await fetchHostDirectory(globalThis.fetch, HOST_DIRECTORY_PATH, signal);
  if (directory === 'unavailable') {
    throw new VerifyFlowError('The typedstandards.org publisher directory could not be loaded.');
  }
  const provenance: TrustRegistryProvenance = isHttpsUrl(url) ? 'declared-url' : 'bundle';
  // #14 is read from a full re-run; verify-core does not export it alone.
  const rerun = await verifyRecord(input, {
    registry: liveRegistry,
    fetch: globalThis.fetch,
    registryProvenance: provenance,
  });
  const publicKey = commitment.signature?.publicKey;
  const kid = result.kid;
  const live: KeyTrustResult = keyDerived
    ? (rerun.keyTrust ?? legacyEmbeddedKeyTrust())
    : publicKey && kid
      ? verifyKeyTrust(publicKey, kid, signedBeforeTimeOf(result), liveRegistry)
      : legacyEmbeddedKeyTrust();
  const generatedAt = registryGeneratedAt(liveRegistry);
  return {
    status: live.status,
    verified: live.verified,
    changed: live.status !== result.keyTrust?.status,
    ...(generatedAt ? { generatedAt } : {}),
    url,
    checkedAt: new Date().toISOString(),
    registry: liveRegistry,
    provenance,
    directory,
    result: { ...result, keyTrust: live, signerIdentity: rerun.signerIdentity },
  };
}

/** The line each re-checked reading carries: where, when, and the registry's date. */
function recheckedLine(recheck: KeyTrustRecheck): string {
  const when = new Date(recheck.checkedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const asOf = recheck.generatedAt ? `registry as of ${fmtAsOf(recheck.generatedAt)}` : 'registry date not stated';
  return `Re-checked live against ${hostOf(recheck.url)} at ${when}, ${asOf}.`;
}

/** The URL's host, or the URL itself when it has none (a `data:` URL). */
function hostOf(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

/** Build the #5 registry meta from a resolved input. The recheck URL falls back to
 *  the commitment's declared registry URL, so an inline snapshot whose bundle also
 *  names a URL can still be re-checked live. */
export function registryMetaOf(resolved: ResolvedInput): RegistryMeta {
  const url =
    resolved.sources.registry.url ??
    resolved.commitment.trustRegistryUrl ??
    resolved.commitment.trustRegistryUrlLegacy;
  const generatedAt = registryGeneratedAt(resolved.registry);
  return {
    kind: resolved.sources.registry.kind,
    available: !!resolved.registry,
    ...(url ? { url } : {}),
    ...(generatedAt ? { generatedAt } : {}),
    ...(resolved.registryProvenance ? { provenance: resolved.registryProvenance } : {}),
  };
}

/** The online recheck is offered only when an inline SNAPSHOT backed a
 *  registry-dependent verdict AND a live `https:` URL is known — i.e. exactly when
 *  the snapshot could be stale or not the publisher's, and that is closeable. The
 *  URL must be `https:` for every signer: only a registry fetched from an `https:`
 *  URL is the declared registry (hub ADR-0030 §4 rule 3; #78). */
export function canRecheckKeyTrust(meta: RegistryMeta, result: VerifyResult): boolean {
  return (
    meta.kind === 'inline' &&
    isHttpsUrl(meta.url) &&
    !!result.keyTrust &&
    REGISTRY_BACKED_STATUSES.has(result.keyTrust.status)
  );
}

/** A check's number, name and trust signal. */
export interface CheckSignal {
  num: string;
  name: string;
  signal: TrustSignalDescriptor;
}

/**
 * The trust signal of every check but #2, in row order: the one place the rows and
 * the headline read a check's tier from (#86). #2 cannot be non-green without
 * alarming the headline first. A check the result does not carry is
 * left out, as its row is. #2 is left out because its row also reads the input, and
 * the headline reads the signature itself.
 *
 * `keyDerived` is whether the signer's identifier is key-derived. It chooses #5's
 * descriptor, not its tier: the one it adds, KEY_TRUST_BUNDLE_REGISTRY_NOT_USED,
 * has the tier of the `registry_unavailable` it replaces.
 */
export function checkSignalsOf(
  result: VerifyResult,
  registryMeta: RegistryMeta | undefined,
  keyDerived: boolean,
): CheckSignal[] {
  const out: CheckSignal[] = [];
  const add = (num: string, name: string, signal: TrustSignalDescriptor) => out.push({ num, name, signal });

  add('1', 'Envelope integrity', resolveEnvelopeIntegrity(result.envelopeIntegrity));
  if (result.contentCanonicalization) {
    add('3', 'Canonicalization', CONTENT_CANONICALIZATION_SIGNALS[result.contentCanonicalization.status]);
  }
  if (result.contentHash) add('4', 'Content fingerprint', CONTENT_HASH_SIGNALS[result.contentHash.status]);

  // #5: under a key-derived signer, a bundle registry verify-core set aside is said
  // so; for every other signer, a status only a supplied registry confirmed reads as
  // supplied (#78).
  const keyTrust = result.keyTrust;
  add(
    '5',
    'Key trust',
    keyTrust && keyDerived
      ? keyTrust.status === 'registry_unavailable' && registryMeta?.kind === 'inline' && registryMeta.available
        ? KEY_TRUST_BUNDLE_REGISTRY_NOT_USED
        : resolveKeyTrust(keyTrust)
      : keyTrust && confirmedOnlyBySuppliedRegistry(keyTrust, registryMeta)
        ? KEY_TRUST_SUPPLIED_REGISTRY
        : resolveKeyTrust(keyTrust),
  );

  // #7: the row reads the same whatever the reason (#94, D1); `rollupVerdict` reads
  // the reason for the headline.
  add('7', 'Timestamp', resolveTimestamp(result.hasTimestamp, result.rfc3161?.verified ?? null));
  if (result.hasRekor || result.rekorInclusion) {
    add('8', 'Transparency log', resolveRekor(result.hasRekor, rekorInclusionVerifiedOffline(result), result.rekorVerified));
  }
  if (result.blobRefsVerified !== null) add('9', 'Referenced content', resolveBlobRefs(result.blobRefsVerified));
  add('10', 'Lifecycle', LIFECYCLE_STATE_SIGNALS[result.lifecycle.status]);
  if (result.typeResolution) add('12', 'Node type', TYPE_RESOLUTION_SIGNALS[result.typeResolution.status]);
  // #14: a match against a registry the record supplied establishes nothing (#78); a
  // mismatch against it still alarms.
  if (result.signerIdentity) {
    const si = result.signerIdentity;
    add(
      '14',
      'Signer identity',
      si.status === 'ok' && registryMeta?.provenance === 'bundle' ? SIGNER_IDENTITY_SUPPLIED_REGISTRY : SIGNER_IDENTITY_SIGNALS[si.status],
    );
  }
  if (result.captureMethodVocab) {
    add('15', 'Capture method', CAPTURE_METHOD_VOCAB_SIGNALS[result.captureMethodVocab.status]);
  }
  if (result.contentProfile) add('16', 'Content profile', CONTENT_PROFILE_SIGNALS[result.contentProfile.status]);
  return out;
}

/** Whether #8's Merkle inclusion and signed checkpoint both verified offline. */
function rekorInclusionVerifiedOffline(result: VerifyResult): boolean {
  const incl = result.rekorInclusion;
  return !!(incl && incl.inclusionVerified && incl.checkpointVerified);
}

/**
 * Build the per-check rows from the verdict + input. Each row carries the trust
 * signal (tier/label) AND the computed values the verifier saw — the "math".
 * Ordered by spec §9.2 check number. Null checks (e.g. on a missing package) are
 * skipped rather than rendered as failures.
 */
export function buildCheckRows(
  result: VerifyResult,
  input: VerifyInput,
  commitment: Commitment,
  registryMeta?: RegistryMeta,
): CheckRow[] {
  const rows: CheckRow[] = [];
  const keyDerived = hasKeyDerivedSigner(input.package);
  const signals = new Map(checkSignalsOf(result, registryMeta, keyDerived).map((c) => [c.num, c]));
  /** The row for check `num`, its name and signal read from `checkSignalsOf`. */
  const checkRow = (num: string, math: MathLine[], depthNote?: string): CheckRow => {
    const c = signals.get(num);
    if (!c) throw new Error(`no signal for check #${num}`);
    return row(num, c.name, c.signal, math, depthNote);
  };

  // #1 — envelope integrity (TRI-STATE, #21). When the content is unavailable there is
  // nothing to recompute, so the "Recomputed SHA-256" line reads as prose (why it
  // wasn't recomputed), not a misleading blank "—" beside an alarm.
  const integrity = result.envelopeIntegrity;
  const recomputed: MathLine =
    integrity.status === 'unavailable'
      ? {
          label: 'Recomputed SHA-256',
          value:
            integrity.reason === 'private'
              ? 'not recomputed — content private'
              : 'not recomputed — content unavailable',
        }
      : {
          label: 'Recomputed SHA-256',
          value: result.recomputedHash ? truncMiddle(result.recomputedHash) : '—',
          mono: true,
          ...(result.recomputedHash ? { full: result.recomputedHash } : {}),
        };
  rows.push(
    checkRow('1', [
      recomputed,
      { label: 'Claimed hash', value: truncMiddle(input.packageHash), mono: true, full: input.packageHash },
    ]),
  );

  // #2 — signature.
  if (result.hasSigning || input.signature) {
    const sig = commitment.signature ?? input.signature ?? undefined;
    rows.push(
      row('2', 'Signature', resolveSignature(result.signatureValid), [
        { label: 'Algorithm', value: sig?.algorithm ?? 'Ed25519ph (default)' },
        {
          label: 'Public key',
          value: sig?.publicKey ? truncMiddle(sig.publicKey, 12, 6) : '—',
          mono: true,
          ...(sig?.publicKey ? { full: sig.publicKey } : {}),
        },
        { label: 'Signs', value: 'the package hash' },
      ]),
    );
  } else {
    rows.push(row('2', 'Signature', resolveSignature(null), [{ label: 'Status', value: 'no signature present' }]));
  }

  // #3 — content canonicalization.
  if (result.contentCanonicalization) {
    rows.push(
      checkRow('3', [
        { label: 'Rule', value: result.contentCanonicalization.rule, mono: true },
      ]),
    );
  }

  // #4 — content hash.
  if (result.contentHash) {
    const ch = result.contentHash;
    const math: MathLine[] = [];
    if (ch.algorithms?.length) math.push({ label: 'Algorithms', value: ch.algorithms.join(', ') });
    if (ch.matched) math.push({ label: 'Matched', value: ch.matched });
    if (ch.contentHash?.sha256)
      math.push({
        label: 'contentHash.sha256',
        value: truncMiddle(ch.contentHash.sha256),
        mono: true,
        full: ch.contentHash.sha256,
      });
    rows.push(checkRow('4', math));
  }

  // #5 — key trust (trust-registry lookup). The staleness note (#119 P4) makes the
  // offline-revocation limit legible: a snapshot can't reflect a key revoked after
  // its `generatedAt`; the recheck affordance closes that gap when connected.
  // Under a key-derived signer identifier (hub ADR-0030 §10) the row labels `kid`
  // as the envelope's key label only, and says what happened when a bundle-carried
  // registry was set aside. For every signer it states the registry's source beside
  // the status (#78). A registry the record supplied — carried in it, or read from a
  // URL that is not https: — can lower a status but not raise one: verify-core
  // applies that for a key-derived signer, and for every other signer a status such
  // a registry confirms is rendered as supplied, never as registered.
  if (result.keyTrust && keyDerived) {
    const status = result.keyTrust.status;
    rows.push(
      checkRow(
        '5',
        [
          { label: 'Envelope key label (kid)', value: result.kid ?? '—', mono: true },
          { label: 'Key-trust status', value: status },
          { label: 'Registry source', value: registrySourceOf(registryMeta) },
        ],
        keyTrustStalenessNote(status, registryMeta),
      ),
    );
  } else if (result.keyTrust) {
    rows.push(
      checkRow(
        '5',
        [
          { label: 'kid', value: result.kid ?? '—', mono: true },
          { label: 'Registry status', value: result.keyTrust.status },
          ...(registryMeta ? [{ label: 'Registry source', value: registrySourceOf(registryMeta) }] : []),
        ],
        keyTrustStalenessNote(result.keyTrust.status, registryMeta),
      ),
    );
  } else {
    rows.push(checkRow('5', [{ label: 'Status', value: 'no signing key to check' }]));
  }

  // #7 — RFC 3161 timestamp (DEEP: TSA signature + cert chain to the pinned root,
  // verified offline by verify-core — #119 P2b). The row reflects that verdict, not
  // mere presence. A token that did not verify also shows its reason and what it
  // does to the verdict (#94).
  {
    const ts = result.rfc3161;
    const tsMath: MathLine[] = [
      { label: 'RFC 3161 token', value: result.hasTimestamp ? 'present' : 'absent' },
    ];
    if (ts) {
      if (ts.tsa) tsMath.push({ label: 'Timestamp authority', value: ts.tsa });
      if (ts.genTime !== undefined)
        tsMath.push({ label: 'Signed at (genTime)', value: new Date(ts.genTime).toISOString(), mono: true });
      tsMath.push({
        label: 'Certificate chain',
        value: ts.chainVerified ? 'verified to the pinned FreeTSA root' : 'not verified',
      });
      const reading = classifyTimestamp(result.hasTimestamp, ts);
      if (!ts.verified && ts.reason && (reading === 'fails' || reading === 'caveats')) {
        tsMath.push({ label: 'Reason', value: `${ts.reason} — ${TIMESTAMP_FAILURE_NOTES[reading]}` });
      }
    }
    rows.push(checkRow('7', tsMath));
  }

  // #8 — Rekor transparency log (DEEP: offline Merkle inclusion + signed checkpoint
  // when a proof is carried — #119 P1; otherwise online hash-parity). The row reflects
  // whichever depth was actually reached.
  if (result.hasRekor || result.rekorInclusion) {
    const incl = result.rekorInclusion;
    const inclusionVerifiedOffline = rekorInclusionVerifiedOffline(result);
    const math: MathLine[] = [];
    if (result.rekorDetails?.logIndex !== undefined)
      math.push({ label: 'Log index', value: String(result.rekorDetails.logIndex), mono: true });
    if (input.rekorEntryId) math.push({ label: 'Entry', value: truncMiddle(input.rekorEntryId, 12, 6), mono: true, full: input.rekorEntryId });
    if (incl) {
      if (incl.treeSize !== undefined) math.push({ label: 'Tree size', value: String(incl.treeSize), mono: true });
      if (incl.origin) math.push({ label: 'Checkpoint origin', value: incl.origin });
      math.push({
        label: 'Inclusion proof',
        value: inclusionVerifiedOffline ? 'verified offline against the signed checkpoint' : 'not verified',
      });
    }
    rows.push(checkRow('8', math.length ? math : [{ label: 'Status', value: 'checked' }]));
  }

  // #9 — blob references.
  if (result.blobRefsVerified !== null) {
    rows.push(
      checkRow('9', [
        { label: 'References', value: String(result.blobRefs.length) },
        { label: 'All verified', value: result.blobRefsVerified ? 'yes' : 'no' },
      ]),
    );
  }

  // #10 — lifecycle state.
  {
    const source = LIFECYCLE_SOURCE_SIGNALS[result.lifecycle.source];
    rows.push(
      checkRow('10', [
        { label: 'State', value: result.lifecycle.status },
        { label: 'Derived from', value: source.label },
      ]),
    );
  }

  // #12 — type resolution.
  if (result.typeResolution) {
    rows.push(
      checkRow('12', [
        { label: 'type', value: result.typeResolution.type, mono: true },
      ]),
    );
  }

  // #14 — signer identity cross-check.
  if (result.signerIdentity) {
    const si = result.signerIdentity;
    const math: MathLine[] = [];
    if (si.claimed) math.push({ label: 'Claimed signer', value: si.claimed, mono: true });
    if (si.derived) math.push({ label: 'Derived from the signing key', value: si.derived, mono: true });
    if (si.registered) math.push({ label: 'Registry identity', value: si.registered, mono: true });
    rows.push(checkRow('14', math.length ? math : [{ label: 'Status', value: si.status }]));
  }

  // #15 — captureMethod vocabulary (+ the P1 captureMethod disclosure label).
  if (result.captureMethodVocab) {
    const cm = result.captureMethodVocab;
    const math: MathLine[] = [{ label: 'captureMethod', value: cm.captureMethod ?? '—', mono: true }];
    const label = resolveCaptureMethodLabel(cm.captureMethod ?? commitment.captureMethod ?? null);
    if (label) math.push({ label: 'How it was captured', value: label });
    rows.push(checkRow('15', math));
  }

  // #16 — metadata.contentProfile (hub ADR-0029 §5).
  if (result.contentProfile) {
    const cp = result.contentProfile;
    const math: MathLine[] = [
      { label: 'contentProfile', value: cp.contentProfile ?? 'absent (read as default)', mono: !!cp.contentProfile },
    ];
    if (cp.producerProfile) math.push({ label: 'producerProfile', value: cp.producerProfile, mono: true });
    rows.push(checkRow('16', math));
  }

  return rows;
}

/** The registry's source, stated beside every signer's key-trust status (hub
 *  ADR-0030 §10; #78). */
function registrySourceOf(meta: RegistryMeta | undefined): string {
  if (meta && !meta.available && meta.kind === 'inline') return 'carried in the bundle, not valid — not used';
  if (!meta || !meta.available) return 'none supplied';
  if (meta.kind === 'inline') return 'carried in the bundle (can lower this signer’s key status, never raise it)';
  return meta.provenance === 'declared-url'
    ? 'fetched from the registry URL the record declares'
    : 'read from a registry URL that is not https: (can lower this signer’s key status, never raise it)';
}

// --- Verdict roll-up ------------------------------------------------------

export interface Verdict {
  tier: TrustTier;
  headline: string;
  detail: string;
  /** Set after a live re-check: where and when the reading was confirmed. */
  provenance?: string;
}

/**
 * Roll the per-check verdicts into one headline (P5 glance layer). An alarm on any
 * load-bearing integrity check fails the package; a fully-green signed core
 * verifies; a signed-but-intact package with unconfirmed elements reads as
 * "verified, with caveats"; an unsigned package reads calm.
 *
 * Envelope integrity is TRI-STATE (#21): only `altered` (bytes present, hash
 * MISMATCHES) alarms. Content that is `unavailable` — private by design, or simply
 * unfetchable — is NOT a failure: the public commitment still verifies on its own,
 * and the verdict surfaces that the content hash merely couldn't be recomputed here.
 *
 * `registry` is the #5 registry meta (see `registryMetaOf`). A key status confirmed
 * by a registry the record supplied — carried in it, or read from a URL that is not
 * https: — does not establish whose key signed, so it never earns the verified
 * headline (#78). Omitted, the registry is read as carried in the bundle, as
 * verify-core reads an unstated provenance (#93); the page always passes it (see
 * `presentVerification`).
 *
 * A check that is not green — attention or alarm tier (see `checkSignalsOf`) —
 * withholds every unqualified headline: "Verified", "Commitment verified — content
 * private" and the self-certified reading alike. The caveated headline names the
 * checks (#86). The alarm set below alone decides "Verification failed"; an
 * alarm-tier row outside it reads caveated — a timestamp whose only fault is this
 * verifier's policy (#94).
 *
 * The alarm set reads reasons, not only verdicts (sprint #98):
 *   - #7: a timestamp token that does not verify for this package fails it; one whose
 *     only fault is an authority this verifier does not pin, intermediates it lacks
 *     or an algorithm it does not check caveats (`classifyTimestamp`, #94 D1).
 */
export function rollupVerdict(result: VerifyResult, registry: RegistryMeta = UNSTATED_REGISTRY): Verdict {
  const integrity = result.envelopeIntegrity;
  const contentUnavailable = integrity.status === 'unavailable';
  const keySuppliedOnly = confirmedOnlyBySuppliedRegistry(result.keyTrust, registry);
  const keyConfirmed = result.keyTrust?.status === 'active' && !keySuppliedOnly;
  const notGreen = checkSignalsOf(result, registry, false).filter(
    (c) => c.signal.tier === 'attention' || c.signal.tier === 'alarm',
  );
  const allGreen = notGreen.length === 0;
  /** The checks that are not green, named, for the detail of a caveated headline. */
  const named = allGreen ? '' : ` Not affirmed: ${notGreen.map((c) => `#${c.num} ${c.name}`).join(', ')}.`;

  const alarm =
    integrity.status === 'altered' || // bytes present + hash mismatch — real tampering
    result.signatureValid === false ||
    result.contentHash?.status === 'content_hash_mismatch' ||
    result.blobRefsVerified === false ||
    // A timestamp token that does not verify for this package (#94).
    classifyTimestamp(result.hasTimestamp, result.rfc3161) === 'fails' ||
    result.signerIdentity?.status === 'signer_identity_mismatch' ||
    // Hub ADR-0030 §3: the identifier does not name the key that signed — fatal.
    result.signerIdentity?.status === 'key_derived_mismatch' ||
    result.keyTrust?.status === 'revoked' ||
    result.keyTrust?.status === 'deprecated_invalid';

  if (alarm) {
    return {
      tier: 'alarm',
      headline: 'Verification failed',
      detail:
        'A load-bearing integrity or identity check did not pass — this package may have been altered or is signed by an untrusted key. See the checks below.',
    };
  }

  if (result.signatureValid === null && !result.hasSigning) {
    return {
      tier: 'normal',
      headline: 'Not signed',
      detail: 'This package carries no signature, so there is nothing to verify cryptographically.',
    };
  }

  // Content unavailable, but no commitment-level check alarmed. The public commitment
  // (signature, key trust, timestamp, transparency log) is the thing being verified
  // here; the content hash simply couldn't be recomputed. This is the sealed/committed
  // value proposition — a publicly verifiable commitment without disclosing content —
  // so it must read CALM, never as "Verification failed".
  if (contentUnavailable) {
    const commitmentGreen = result.signatureValid === true && keyConfirmed && allGreen;
    if (integrity.reason === 'private') {
      return commitmentGreen
        ? {
            tier: 'verified',
            headline: 'Commitment verified — content private',
            detail:
              'The public commitment fully verifies: the signature, signing key, timestamp, and transparency-log entry all check out. The content itself is private, so its bytes were not retrieved and the envelope hash was not recomputed here. This confirms the commitment’s integrity and identity, not the content.',
          }
        : {
            tier: 'attention',
            headline: 'Commitment verified, with caveats — content private',
            detail: `The content is private, so the envelope hash was not recomputed here. The commitment checks ran, but something in them is unconfirmed or unrecognized — not proven bad.${named}`,
          };
    }
    // unfetchable
    return {
      tier: 'attention',
      headline: 'Content could not be retrieved',
      detail: `The commitment’s signature and proofs were checked, but the package’s content could not be fetched from its stated location, so the envelope hash was not recomputed. This is an availability problem, not proof of alteration.${named}`,
    };
  }

  const fullyGreen = integrity.status === 'verified' && result.signatureValid === true && keyConfirmed;

  // Hub ADR-0030 §10: a self-certified signer never reads `verified` overall.
  // `self_certified` is tier `normal` with `verified: false` — no registry vouched
  // for the key — so a package that is intact and validly signed by one reads at
  // most `normal`, and the headline says what was and was not established. A check
  // that is not green lowers it as it lowers "Verified" (#86).
  if (
    integrity.status === 'verified' &&
    result.signatureValid === true &&
    result.keyTrust?.status === 'self_certified'
  ) {
    return allGreen
      ? {
          tier: 'normal',
          headline: 'Signature valid — self-certified signer',
          detail:
            'The bytes are intact and the signature verifies. The signer’s identifier is derived from the signing key, so this shows the same key signed this package — not who holds the key. No registry vouches for the key. This confirms integrity, not identity, and not whether the content is correct.',
        }
      : {
          tier: 'attention',
          headline: 'Signature valid, with caveats — self-certified signer',
          detail: `The bytes are intact and the signature verifies. The signer’s identifier is derived from the signing key, so this shows the same key signed this package — not who holds the key. No registry vouches for the key.${named}`,
        };
  }

  if (integrity.status === 'verified' && result.signatureValid === true && keySuppliedOnly) {
    return {
      tier: 'attention',
      headline: 'Verified, with caveats',
      detail: `The bytes are intact and the signature verifies. The signing key is listed in a trust registry supplied with the record, which was not checked against the publisher’s domain, so the key is not confirmed as the publisher’s. See the key-trust check below.${named}`,
    };
  }

  if (fullyGreen && allGreen) {
    return {
      tier: 'verified',
      headline: 'Verified',
      detail:
        'The bytes are intact, the signature verifies, and the signing key is active in the publisher’s trust registry. This confirms integrity and identity — not whether the content is correct.',
    };
  }

  return {
    tier: 'attention',
    headline: 'Verified, with caveats',
    detail: allGreen
      ? 'The core signature and integrity checks pass, but something is unconfirmed or unrecognized (see the checks below). Not proven bad — just not fully affirmed.'
      : `The core signature and integrity checks pass, but not every check is affirmed. Not proven bad — just not fully affirmed.${named}`,
  };
}

/** The registry `rollupVerdict` reads when none is passed: carried in the bundle,
 *  the reading that can lower a key status and never raise one (#93). */
const UNSTATED_REGISTRY: RegistryMeta = { kind: 'inline', available: true, provenance: 'bundle' };

// --- What the page shows --------------------------------------------------

export interface Presentation {
  rows: CheckRow[];
  verdict: Verdict;
  recognition: HostRecognition;
  independence: IndependenceNote;
}

/**
 * The check rows, the rolled-up verdict, the recognition card and the independence
 * note for one run — what the <Verifier> renders. One place computes them from the
 * same resolved input and result, so the registry's provenance reaches each (#78).
 *
 * With a completed live re-check (`recheckKeyTrustLive`), #5, #14, the headline and
 * recognition read as URL mode would, from the live registry and the directory, and
 * #5, the headline and recognition each say when (#93 item 3, ruling C).
 */
export function presentVerification(
  resolved: ResolvedInput,
  input: VerifyInput,
  result: VerifyResult,
  recheck?: KeyTrustRecheck,
): Presentation {
  if (!recheck) {
    const registryMeta = registryMetaOf(resolved);
    return {
      rows: buildCheckRows(result, input, resolved.commitment, registryMeta),
      verdict: rollupVerdict(result, registryMeta),
      recognition: resolveHostRecognition(
        resolved.commitment,
        result.keyTrust,
        resolved.directory,
        resolved.registryProvenance,
      ),
      independence: independenceNoteOf(resolved),
    };
  }
  const live: ResolvedInput = {
    ...resolved,
    registry: recheck.registry,
    directory: recheck.directory,
    sources: { ...resolved.sources, registry: { kind: 'fetched', url: recheck.url } },
    registryProvenance: recheck.provenance,
  };
  const registryMeta = registryMetaOf(live);
  const provenance = recheckedLine(recheck);
  return {
    rows: buildCheckRows(recheck.result, input, resolved.commitment, registryMeta).map((r) =>
      r.num === '5' ? { ...r, depthNote: provenance } : r,
    ),
    verdict: { ...rollupVerdict(recheck.result, registryMeta), provenance },
    recognition: {
      ...resolveHostRecognition(resolved.commitment, recheck.result.keyTrust, recheck.directory, recheck.provenance),
      provenance,
    },
    independence: independenceNoteOf(resolved, recheck),
  };
}

/** The independence note: a lead, then text, with hosts set in monospace. */
export interface IndependenceNote {
  lead: string;
  parts: { text: string; mono?: boolean }[];
}

/**
 * What the run did and did not trust. An offline bundle leaves the signing key
 * unconfirmed until it is re-checked (#93 item 4); after a re-check the note says
 * the session went online (#93 item 3).
 */
export function independenceNoteOf(resolved: ResolvedInput, recheck?: KeyTrustRecheck): IndependenceNote {
  // A registry the record supplied — carried in it, or read from a URL that is not
  // https: — was not checked against the publisher's domain (#78).
  const supplied =
    !recheck && resolved.registryProvenance === 'bundle'
      ? ' The trust registry was supplied with the record, so the signing key was not checked against the publisher’s domain.'
      : '';
  const rechecked: IndependenceNote['parts'] = recheck
    ? [
        { text: ' Key trust was then re-checked live against ' },
        { text: hostOf(recheck.url), mono: true },
        {
          text: ` at ${new Date(recheck.checkedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}, and publisher recognition read the typedstandards.org directory.`,
        },
      ]
    : [];
  if (resolved.fullyOffline) {
    return recheck
      ? {
          lead: 'Verified offline, then re-checked online.',
          parts: [{ text: 'Every proof was read from your bundle and verified in your browser.' }, ...rechecked],
        }
      : {
          lead: 'Fully offline.',
          parts: [
            {
              text: `Every proof was read from your bundle and verified in your browser — nothing was fetched.${supplied} Publisher recognition was skipped: it reads only the typedstandards.org directory, which an offline check does not fetch.`,
            },
          ],
        };
  }
  const host = hostOfOptional(resolved.sources.pkg.url) || hostOfOptional(resolved.sources.commitment.url) || 'the publisher';
  return {
    lead: 'Verified in your browser.',
    parts: [
      { text: 'The checks ran client-side here — but the package and proofs were fetched from ' },
      { text: host, mono: true },
      {
        text: `. Publisher recognition was a separate lookup in typedstandards.org’s curated host directory, independent of that host.${supplied} To verify the package and proofs without trusting the host, download and verify an offline bundle. Its signing key stays unconfirmed until you re-check it against the publisher’s live registry.`,
      },
      ...rechecked,
    ],
  };
}

/** The host of `url`, or '' when there is none. */
function hostOfOptional(url?: string): string {
  if (!url) return '';
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

// --- Page preview (from the VERIFIED package bytes) -----------------------

export interface PagePreview {
  /** Whether the package bytes were available to render. */
  available: boolean;
  /** When `available` is false, why — so the empty-preview copy reads honestly:
   *  `private` (content withheld by design) vs. `unfetchable` (a location that
   *  couldn't be retrieved). Mirrors the commitment-shape signal buildVerifyInput
   *  uses for `contentUnavailableReason`. */
  unavailableReason?: 'private' | 'unfetchable';
  type?: string;
  /** The signer's `displayName`, shown in the signer byline. Set only when the
   *  signer's identifier is NOT key-derived. */
  signerDisplayName?: string;
  /** Under a key-derived signer identifier (hub ADR-0030 §10), `displayName` is
   *  unverified text the signer wrote about itself. It is carried here instead of
   *  `signerDisplayName`, so it never takes the byline position, and it is
   *  rendered as self-description ("calls itself …"). */
  signerSelfDescribedName?: string;
  captureMethod?: string;
  summary?: string;
  answer?: string;
  /** The publisher's listing title (from the commitment — NOT signed). */
  listingTitle?: string;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * Build the page preview from the VERIFIED package JSON, so "what you see" is
 * "what was signed". `summary` and `answer` (the package's `output`) are signed
 * envelope fields. The listing title comes from the commitment (publisher's DB
 * record, NOT signed) and is shown only as context, clearly labeled.
 */
export function buildPreview(
  pkg: Record<string, unknown> | null,
  commitment: Commitment,
): PagePreview {
  if (!pkg) {
    return {
      available: false,
      unavailableReason: commitment.packageUrl ? 'unfetchable' : 'private',
      ...(str(commitment.subjectTitle) ? { listingTitle: commitment.subjectTitle } : {}),
    };
  }
  const signer = pkg['signer'] as { displayName?: string } | undefined;
  const metadata = pkg['metadata'] as { captureMethod?: string } | undefined;
  const displayName = str(signer?.displayName);
  return {
    available: true,
    ...(str(pkg['type']) ? { type: pkg['type'] as string } : {}),
    ...(displayName
      ? hasKeyDerivedSigner(pkg)
        ? { signerSelfDescribedName: displayName }
        : { signerDisplayName: displayName }
      : {}),
    ...(str(metadata?.captureMethod) ? { captureMethod: metadata!.captureMethod } : {}),
    ...(str(pkg['summary']) ? { summary: pkg['summary'] as string } : {}),
    ...(str(pkg['output']) ? { answer: pkg['output'] as string } : {}),
    ...(str(commitment.subjectTitle) ? { listingTitle: commitment.subjectTitle } : {}),
  };
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.host + u.pathname;
  } catch {
    return url;
  }
}
