// Verification flow for the typedstandards.org client-side verifier (#116 WS3
// Phase C). Pure helpers the <Verifier> client component sequences:
//
//   detect input  →  resolve the WS1 commitment  →  fetch package + registry
//   →  verifyEvidence (the SAME @typedstandards/verify-core both sites run)
//   →  build the per-check "show the math" rows + the rolled-up verdict.
//
// All network I/O is a plain GET with no custom request headers — a custom header
// makes the request non-simple and triggers a CORS preflight; a preflight `OPTIONS`
// against a host that redirects can be rejected there, so a plain GET is what
// follows a redirect transparently — e.g. civicaitools.org's site-wide 307 to its
// canonical host. Verification depth MATCHES verify-core / the civicaitools.org
// server: full client-side crypto for #1–#6/#9/#12–#15; #7 (RFC 3161) is the TSA
// signature + cert chain verified offline to the pinned FreeTSA root; #8 (Rekor) is
// the RFC 6962 Merkle inclusion proof recomputed against a signed checkpoint when one
// is carried (else online hash-parity); #10 (lifecycle) resolves from the carried
// signed attestation chain when present (#119 P1/P2b/P3).

import {
  verifyEvidence,
  validateRegistry,
  verifyLifecycleChain,
  verifyKeyTrust,
  legacyEmbeddedKeyTrust,
  parseInclusionProof,
  type VerifyInput,
  type VerifyResult,
  type VerifySignatureEnvelope,
  type CommitmentLifecycleState,
  type CarriedLifecycleNode,
  type LifecycleResolution,
  type TrustRegistry,
  type KeyTrustStatus,
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
  resolveRekor,
  resolveBlobRefs,
  resolveCaptureMethodLabel,
  CONTENT_CANONICALIZATION_SIGNALS,
  CONTENT_HASH_SIGNALS,
  TYPE_RESOLUTION_SIGNALS,
  SIGNER_IDENTITY_SIGNALS,
  CAPTURE_METHOD_VOCAB_SIGNALS,
  LIFECYCLE_STATE_SIGNALS,
  LIFECYCLE_SOURCE_SIGNALS,
} from './trust-signal.ts';
import {
  BARE_ID_ANCHOR,
  HOST_DIRECTORY_PATH,
  fetchHostDirectory,
  validateHostDirectory,
  type HostDirectory,
} from './host-directory.ts';

// Re-export the host-recognition surface (Phase D / Q47) so the verifier UI pulls
// the whole verification flow — cryptographic checks AND publisher recognition —
// from this one module. `HOST_DIRECTORY` comes along so the UI can render the
// roster-driven "try another host" affordance from the same source of truth the
// well-known route serves.
export { resolveHostRecognition, HOST_DIRECTORY } from './host-directory.ts';
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
  /** Offline bundle extensions (not emitted by the endpoint). */
  package?: Record<string, unknown> | null;
  trustRegistry?: unknown;
  /** Offline snapshot of the typedstandards.org host directory, so a bundle can
   *  resolve publisher recognition without a network fetch (same staleness caveat
   *  as the registry snapshot — Q47 / #119). */
  hostDirectory?: unknown;
}

export type InputMode = 'hash' | 'url' | 'bundle';

export class VerifyFlowError extends Error {}

// --- Input detection ------------------------------------------------------

const HASH_RE = /^[0-9a-f]{64}$/i;

/**
 * Auto-detect the input kind. A 64-hex string is a package hash; an http(s) URL
 * is a hosted reference; a string starting with `{` is a pasted bundle/commitment
 * JSON; anything else is treated as an evidence slug (resolved like a hash).
 */
export function detectInputMode(raw: string): InputMode {
  const s = raw.trim();
  if (!s) return 'hash';
  if (s.startsWith('{')) return 'bundle';
  if (/^https?:\/\//i.test(s)) return 'url';
  return 'hash'; // 64-hex hash OR an evidence slug — both resolve by identifier
}

/** A glanceable label for the detected mode. */
export function describeMode(mode: InputMode, raw: string): string {
  if (mode === 'bundle') return 'Uploaded bundle';
  if (mode === 'url') return 'Hosted URL';
  return HASH_RE.test(raw.trim()) ? 'Package hash' : 'Evidence slug';
}

// --- Resolution -----------------------------------------------------------

/** How a piece of the verification input was obtained — drives the honest
 *  per-mode independence guarantee shown in the UI. */
export type SourceKind = 'fetched' | 'inline';

export interface ResolvedInput {
  commitment: Commitment;
  pkg: Record<string, unknown> | null;
  registry: TrustRegistry | undefined;
  /** The host directory used for publisher recognition (Phase D), or
   *  `'unavailable'` when it could not be loaded. Distinct from the publisher
   *  sources below: it comes from the verifier's curator (typedstandards.org),
   *  not from the package's host, so it is tracked separately. */
  directory: HostDirectory | 'unavailable';
  /** Where each piece came from, for the independence disclosure. */
  sources: {
    commitment: { kind: SourceKind; url?: string };
    pkg: { kind: SourceKind; url?: string };
    registry: { kind: SourceKind; url?: string };
  };
  /** True only when EVERYTHING was read from the bundle — i.e. a true offline
   *  verification, fetching nothing. */
  fullyOffline: boolean;
}

async function getJson(url: string, signal?: AbortSignal): Promise<unknown> {
  let res: Awaited<ReturnType<typeof fetch>>;
  try {
    // Plain GET, no custom headers (see the module header re: the CORS preflight).
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

/** How a hosted URL names the commitment to fetch. One classifier, used by BOTH
 *  `deriveCommitmentUrl` (which resolves) and `identifierResolutionKind` (which tells
 *  the UI whether to disclose an anchor), so the two cannot disagree about whether an
 *  input carries a publisher origin. */
type HostedUrlKind =
  | { kind: 'commitment' }
  | { kind: 'evidence-id'; id: string }
  | { kind: 'package-blob'; hash: string }
  | { kind: 'opaque' };

function classifyHostedUrl(u: URL): HostedUrlKind {
  if (u.pathname.endsWith('/commitment')) return { kind: 'commitment' };
  // PACKAGE-BLOB IS TESTED BEFORE `/evidence/<id>`, and the order is load-bearing.
  // A `<64-hex>.json` FILENAME is an unambiguous package blob wherever it sits, while
  // the `/evidence/` probe matches any path SEGMENT — so a storage URL that merely
  // happens to contain that segment (`…/evidence/<hash>.json`, a real bucket layout)
  // was previously captured as an evidence id of literally `<hash>.json` and produced
  // the nonsense `…/api/evidence/<hash>.json/commitment`. The more specific signal
  // must win. No publisher's `/evidence/<id>` page URL ends in `<64-hex>.json`, so
  // nothing that genuinely carries a publisher origin is diverted by this.
  const blobHash = u.pathname.match(/([0-9a-f]{64})\.json$/i);
  if (blobHash) return { kind: 'package-blob', hash: blobHash[1] };
  const idMatch = u.pathname.match(/\/evidence\/([^/]+)/);
  if (idMatch) return { kind: 'evidence-id', id: idMatch[1] };
  return { kind: 'opaque' };
}

/**
 * Build the commitment-endpoint URL for a hosted URL input.
 *
 * Three shapes carry a PUBLISHER ORIGIN and keep it:
 *   - a direct `…/commitment` URL — already the resource;
 *   - a publisher's own `…/evidence/<id>…` URL — the origin serving that page IS the
 *     publisher, so `${u.origin}/api/evidence/<id>/commitment` is its commitment;
 *   - anything else, used as-is.
 *
 * One shape does NOT, and this is the B5 correction (#44). A PACKAGE-BLOB URL — the
 * badge deep-link's `?url=<package-url>`, whose filename is the 64-hex package hash —
 * names a STORAGE location, not a publisher. Detached object storage is the common
 * pattern (Vercel Blob, S3, R2, GCS) and is the reference publisher's own setup, so
 * the blob's origin routinely has no evidence API at all. Preserving that origin 404s
 * there; re-pointing every blob at the anchor 404s for a self-hosting publisher.
 * Neither is right, because a bare blob URL does not determine its publisher.
 *
 * So the filename hash is treated as exactly what it is — an ORIGIN-LESS IDENTIFIER —
 * and resolved through the same path a bare hash takes: against `host` (the declared
 * anchor unless a link or the picker named one). The UI discloses which host answered
 * and offers the roster to correct it in one click — the same under-determination
 * honesty B6 established. `identifierResolutionKind` is what tells it to.
 */
export function deriveCommitmentUrl(input: string, host: string = DEFAULT_HOST): string {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new VerifyFlowError(`"${input}" is not a valid URL.`);
  }
  const hosted = classifyHostedUrl(u);
  switch (hosted.kind) {
    case 'commitment':
      return u.toString();
    case 'evidence-id':
      return `${u.origin}/api/evidence/${hosted.id}/commitment`;
    case 'package-blob':
      return bareIdCommitmentUrl(hosted.hash, host);
    default:
      // Last resort: treat the URL itself as the commitment resource.
      return u.toString();
  }
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
// is closed by `bareIdCommitmentUrl`, which both sides use to build the one URL an
// identifier resolves to — and which `deriveCommitmentUrl` also routes package-blob
// URLs through, so every origin-less input takes one path. The two-segment form is
// what gives EVERY publisher the clean short link: it used to be earned only by a
// commitment URL on the anchor origin, so a second publisher's result could only ever
// be shared as an opaque `?url=<encoded>` blob.

/** The commitment URL a bare identifier resolves to on `host` — the single place the
 *  `/api/evidence/<id>/commitment` shape is built, so a minted share link and the
 *  request it later re-issues cannot drift. `host` defaults to the anchor. */
export function bareIdCommitmentUrl(id: string, host: string = DEFAULT_HOST): string {
  return `${host}/api/evidence/${encodeURIComponent(id)}/commitment`;
}

/** Hostname shape: dot-separated LDH labels (1–63 chars, no leading/trailing `-`),
 *  253 chars max. Rejects the shapes `new URL()` accepts but no publisher can have —
 *  bare `.`/`..`, a leading-hyphen label, a trailing-dot FQDN, an IPv6 literal. */
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/**
 * Canonical `https://<host>` origin for a `/verify/<host>/<id>` host segment, or
 * `undefined` when the segment is not a well-formed host.
 *
 * SHAPE ONLY — never roster membership. Resolution and recognition are orthogonal
 * dimensions (host-directory.ts), and gating the LINK SHAPE on the directory would
 * rebuild the very privilege this removes: an unlisted publisher would be back to
 * the opaque `?url=` form. An unlisted host resolves normally here and the
 * recognition banner does its job on the result. The shape is deliberately narrow
 * — https, no port, no userinfo, no path/query/fragment — so the segment can carry
 * an origin and nothing else; anything richer stays in the `?url=` form, which is
 * where a full URL belongs.
 *
 * `segment` is the DECODED value (Next.js decodes route params), so `%2F`-style
 * smuggling has already collapsed into characters these checks see.
 */
export function parseHostSegment(segment: string): string | undefined {
  if (!segment) return undefined;
  let u: URL;
  try {
    u = new URL(`https://${segment}`);
  } catch {
    return undefined;
  }
  // `new URL` silently absorbs userinfo (`a@b.com` → host b.com), a port, and a
  // path (`x/y` → host x), so each is rejected explicitly rather than trusted away.
  if (u.username || u.password || u.port) return undefined;
  if (u.pathname !== '/' || u.search || u.hash) return undefined;
  if (!HOSTNAME_RE.test(u.hostname)) return undefined;
  return u.origin;
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
 * - A canonical `^/api/evidence/<id>/commitment$` URL collapses to a clean short
 *   link, which round-trips through `parseVerifyTarget` + `bareIdCommitmentUrl` back
 *   to this exact URL: `/verify/<id>` on the anchor origin, `/verify/<host>/<id>`
 *   anywhere else. Both segments are `encodeURIComponent`'d; the id is decoded first
 *   so it survives the extra encode the rebuild applies.
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

  const m = u.pathname.match(/^\/api\/evidence\/([^/]+)\/commitment$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (!id.includes('/')) {
      if (u.origin === DEFAULT_HOST) return `/verify/${encodeURIComponent(id)}`;
      // Any other publisher gets the same clean link, with its origin carried in the
      // first segment. Roster membership is NOT consulted — see parseHostSegment.
      if (u.protocol === 'https:' && !u.port && HOSTNAME_RE.test(u.hostname)) {
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

/** Step 1 — resolve the commitment for hash / URL / bundle input. */
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
        'That JSON is not a commitment bundle (it has no `packageHash`). Paste a §9.2.1 commitment sidecar — for example, what a publisher’s `/api/evidence/<id>/commitment` endpoint returns.',
      );
    }
    return { commitment };
  }
  // `host` reaches BOTH branches: a bare identifier carries no origin, and a
  // package-blob URL's origin is storage rather than a publisher (see
  // deriveCommitmentUrl), so each resolves against it.
  const host = opts.host ?? DEFAULT_HOST;
  const url = mode === 'hash' ? bareIdCommitmentUrl(s, host) : deriveCommitmentUrl(s, host);
  const commitment = (await getJson(url, signal)) as Commitment;
  if (!commitment?.packageHash) {
    throw new VerifyFlowError(`${shortUrl(url)} did not return a commitment (no \`packageHash\`).`);
  }
  return { commitment, url };
}

/** A resolution step, emitted as each piece is obtained (drives the live UI). */
export interface ResolveStep {
  key: 'commitment' | 'package' | 'registry' | 'directory';
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

  // Trust registry.
  let registry: TrustRegistry | undefined;
  let registrySource: { kind: SourceKind; url?: string };
  if (commitment.trustRegistry !== undefined) {
    registry = validateRegistry(commitment.trustRegistry);
    registrySource = { kind: 'inline' };
  } else {
    const registryUrl = commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy;
    if (registryUrl) {
      registry = validateRegistry(await getJson(registryUrl, signal));
      registrySource = { kind: 'fetched', url: registryUrl };
    } else {
      registry = undefined;
      registrySource = { kind: 'fetched' };
    }
  }
  onStep?.({
    key: 'registry',
    label: registrySource.kind === 'inline' ? 'Read trust registry from bundle' : 'Fetched publisher trust registry',
    kind: registrySource.kind,
    ...(registrySource.url ? { url: registrySource.url } : {}),
  });

  // Host directory (Phase D recognition dimension). It is the verifier's curator
  // data, not the package's, so it is resolved separately from the publisher
  // sources above. Bundle mode honours the offline intent: an embedded snapshot is
  // used if present, otherwise the network is NOT touched (recognition then reads
  // a calm "directory unavailable"). Online modes fetch the canonical same-origin
  // directory; any failure degrades to 'unavailable' without affecting the
  // cryptographic verdict.
  let directory: HostDirectory | 'unavailable';
  let directoryStep: SourceKind | null = null;
  if (commitment.hostDirectory !== undefined) {
    directory = validateHostDirectory(commitment.hostDirectory) ?? 'unavailable';
    if (directory !== 'unavailable') directoryStep = 'inline';
  } else if (mode === 'bundle') {
    directory = 'unavailable';
  } else {
    directory = await fetchHostDirectory(globalThis.fetch, HOST_DIRECTORY_PATH, signal);
    if (directory !== 'unavailable') directoryStep = 'fetched';
  }
  if (directoryStep) {
    onStep?.({
      key: 'directory',
      label:
        directoryStep === 'inline'
          ? 'Read publisher directory from bundle'
          : 'Loaded the typedstandards.org publisher directory',
      kind: directoryStep,
    });
  }

  const fullyOffline =
    mode === 'bundle' && pkgSource.kind === 'inline' && registrySource.kind === 'inline';

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
    fullyOffline,
  };
}

/** Map the resolved commitment + package to the verify-core input. The carried Rekor
 *  inclusion proof is parsed with verify-core's shared `parseInclusionProof` — the one
 *  guard the server route, this flow, and the backfill all share (#119 P4).
 *
 *  `opts.offline` (set for a fully self-contained bundle) makes verification
 *  OFFLINE-FIRST (#119 Q15): when the bundle carries the Rekor inclusion proof + entry
 *  body — which verify #8 cryptographically with no network — we drop `rekorEntryId` so
 *  `verifyEvidence` skips its redundant online hash-parity re-fetch (verify.ts:212).
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
 *  `resolveCarriedLifecycle`) is injected as the deeper #10 resolution when present. */
export function runVerify(
  input: VerifyInput,
  registry: TrustRegistry | undefined,
  lifecycleResolution?: LifecycleResolution,
): Promise<VerifyResult> {
  return verifyEvidence(input, {
    registry,
    fetch: globalThis.fetch,
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

/** The honest staleness note for the #5 row, or `undefined` when none applies
 *  (verdict didn't rely on the registry). 'fetched' is current; 'inline' carries
 *  the offline-revocation caveat. A missing `generatedAt` degrades to a dateless
 *  but honest note. */
export function keyTrustStalenessNote(
  status: KeyTrustStatus,
  meta: RegistryMeta | undefined,
): string | undefined {
  if (!meta || !meta.available || !REGISTRY_BACKED_STATUSES.has(status)) return undefined;
  const asOf = meta.generatedAt ? ` (as of ${fmtAsOf(meta.generatedAt)})` : '';
  if (meta.kind === 'fetched') {
    return `Checked against the live registry${asOf}.`;
  }
  const asOfInline = meta.generatedAt ? `, as of ${fmtAsOf(meta.generatedAt)}` : ' (date not stated)';
  return `Verified against the registry snapshot carried in this bundle${asOfInline} — a key revoked after that date cannot be reflected offline. Re-check against the live registry to close the gap.`;
}

/** The earliest verified "signed before" time the #5 check is bounded by — the min
 *  of the Rekor integratedTime and a verified RFC 3161 genTime (#119 P2a). Mirrors
 *  the derivation inside verify-core's `verifyEvidence`, so a re-check reproduces
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
}

/**
 * Re-run ONLY the registry-dependent key-trust check (#5) against the LIVE
 * registry, closing the offline-revocation gap when the verifier is connected. The
 * rest of the verdict is offline-complete and registry-independent, so it is not
 * recomputed. Reproduces verify-core's #5 inputs (public key, kid, earliest
 * attested time) so a `changed` result reflects a real registry change — e.g. a key
 * revoked AFTER the snapshot's `generatedAt`. Throws (not a silent pass) when the
 * commitment names no registry URL or the live registry can't be fetched/validated.
 */
export async function recheckKeyTrustLive(
  commitment: Commitment,
  result: VerifyResult,
  signal?: AbortSignal,
): Promise<KeyTrustRecheck> {
  const url = commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy;
  if (!url) throw new VerifyFlowError('This bundle names no trust-registry URL to re-check against.');
  const liveRegistry = validateRegistry(await getJson(url, signal));
  const publicKey = commitment.signature?.publicKey;
  const kid = result.kid;
  const live =
    publicKey && kid
      ? verifyKeyTrust(publicKey, kid, signedBeforeTimeOf(result), liveRegistry)
      : legacyEmbeddedKeyTrust();
  return {
    status: live.status,
    verified: live.verified,
    changed: live.status !== result.keyTrust?.status,
    ...(registryGeneratedAt(liveRegistry) ? { generatedAt: registryGeneratedAt(liveRegistry) } : {}),
  };
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
  };
}

/** The online recheck is offered only when an inline SNAPSHOT backed a
 *  registry-dependent verdict AND a live URL is known — i.e. exactly when an
 *  offline-revocation gap could exist and is closeable. */
export function canRecheckKeyTrust(meta: RegistryMeta, result: VerifyResult): boolean {
  return (
    meta.kind === 'inline' &&
    !!meta.url &&
    !!result.keyTrust &&
    REGISTRY_BACKED_STATUSES.has(result.keyTrust.status)
  );
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
    row('1', 'Envelope integrity', resolveEnvelopeIntegrity(integrity), [
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
      row('3', 'Canonicalization', CONTENT_CANONICALIZATION_SIGNALS[result.contentCanonicalization.status], [
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
    rows.push(row('4', 'Content fingerprint', CONTENT_HASH_SIGNALS[ch.status], math));
  }

  // #5 — key trust (trust-registry lookup). The staleness note (#119 P4) makes the
  // offline-revocation limit legible: a snapshot can't reflect a key revoked after
  // its `generatedAt`; the recheck affordance closes that gap when connected.
  if (result.keyTrust) {
    const stalenessNote = keyTrustStalenessNote(result.keyTrust.status, registryMeta);
    rows.push(
      row(
        '5',
        'Key trust',
        resolveKeyTrust(result.keyTrust),
        [
          { label: 'kid', value: result.kid ?? '—', mono: true },
          { label: 'Registry status', value: result.keyTrust.status },
        ],
        stalenessNote,
      ),
    );
  } else {
    rows.push(row('5', 'Key trust', resolveKeyTrust(null), [{ label: 'Status', value: 'no signing key to check' }]));
  }

  // #7 — RFC 3161 timestamp (DEEP: TSA signature + cert chain to the pinned root,
  // verified offline by verify-core — #119 P2b). The row reflects that verdict, not
  // mere presence.
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
    }
    rows.push(row('7', 'Timestamp', resolveTimestamp(result.hasTimestamp, ts?.verified ?? null), tsMath));
  }

  // #8 — Rekor transparency log (DEEP: offline Merkle inclusion + signed checkpoint
  // when a proof is carried — #119 P1; otherwise online hash-parity). The row reflects
  // whichever depth was actually reached.
  if (result.hasRekor || result.rekorInclusion) {
    const incl = result.rekorInclusion;
    const inclusionVerifiedOffline = !!(incl && incl.inclusionVerified && incl.checkpointVerified);
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
    rows.push(
      row(
        '8',
        'Transparency log',
        resolveRekor(result.hasRekor, inclusionVerifiedOffline, result.rekorVerified),
        math.length ? math : [{ label: 'Status', value: 'checked' }],
      ),
    );
  }

  // #9 — blob references.
  if (result.blobRefsVerified !== null) {
    rows.push(
      row('9', 'Referenced content', resolveBlobRefs(result.blobRefsVerified), [
        { label: 'References', value: String(result.blobRefs.length) },
        { label: 'All verified', value: result.blobRefsVerified ? 'yes' : 'no' },
      ]),
    );
  }

  // #10 — lifecycle state.
  {
    const state = LIFECYCLE_STATE_SIGNALS[result.lifecycle.status];
    const source = LIFECYCLE_SOURCE_SIGNALS[result.lifecycle.source];
    rows.push(
      row('10', 'Lifecycle', state, [
        { label: 'State', value: result.lifecycle.status },
        { label: 'Derived from', value: source.label },
      ]),
    );
  }

  // #12 — type resolution.
  if (result.typeResolution) {
    rows.push(
      row('12', 'Node type', TYPE_RESOLUTION_SIGNALS[result.typeResolution.status], [
        { label: 'type', value: result.typeResolution.type, mono: true },
      ]),
    );
  }

  // #14 — signer identity cross-check.
  if (result.signerIdentity) {
    const si = result.signerIdentity;
    const math: MathLine[] = [];
    if (si.claimed) math.push({ label: 'Claimed signer', value: si.claimed, mono: true });
    if (si.registered) math.push({ label: 'Registry identity', value: si.registered, mono: true });
    rows.push(row('14', 'Signer identity', SIGNER_IDENTITY_SIGNALS[si.status], math.length ? math : [{ label: 'Status', value: si.status }]));
  }

  // #15 — captureMethod vocabulary (+ the P1 captureMethod disclosure label).
  if (result.captureMethodVocab) {
    const cm = result.captureMethodVocab;
    const math: MathLine[] = [{ label: 'captureMethod', value: cm.captureMethod ?? '—', mono: true }];
    const label = resolveCaptureMethodLabel(cm.captureMethod ?? commitment.captureMethod ?? null);
    if (label) math.push({ label: 'How it was captured', value: label });
    rows.push(row('15', 'Capture method', CAPTURE_METHOD_VOCAB_SIGNALS[cm.status], math));
  }

  return rows;
}

// --- Verdict roll-up ------------------------------------------------------

export interface Verdict {
  tier: TrustTier;
  headline: string;
  detail: string;
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
 */
export function rollupVerdict(result: VerifyResult): Verdict {
  const integrity = result.envelopeIntegrity;
  const contentUnavailable = integrity.status === 'unavailable';

  const alarm =
    integrity.status === 'altered' || // bytes present + hash mismatch — real tampering
    result.signatureValid === false ||
    result.contentHash?.status === 'content_hash_mismatch' ||
    result.blobRefsVerified === false ||
    result.signerIdentity?.status === 'signer_identity_mismatch' ||
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
    const commitmentGreen =
      result.signatureValid === true && result.keyTrust?.status === 'active';
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
            detail:
              'The content is private, so the envelope hash was not recomputed here. The commitment checks ran, but something in them is unconfirmed or unrecognized (see the amber checks) — not proven bad.',
          };
    }
    // unfetchable
    return {
      tier: 'attention',
      headline: 'Content could not be retrieved',
      detail:
        'The commitment’s signature and proofs were checked, but the package’s content could not be fetched from its stated location, so the envelope hash was not recomputed. This is an availability problem, not proof of alteration.',
    };
  }

  const fullyGreen =
    integrity.status === 'verified' &&
    result.signatureValid === true &&
    result.keyTrust?.status === 'active';

  if (fullyGreen) {
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
    detail:
      'The core signature and integrity checks pass, but something is unconfirmed or unrecognized (see the amber checks). Not proven bad — just not fully affirmed.',
  };
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
  signerDisplayName?: string;
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
  return {
    available: true,
    ...(str(pkg['type']) ? { type: pkg['type'] as string } : {}),
    ...(str(signer?.displayName) ? { signerDisplayName: signer!.displayName } : {}),
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
