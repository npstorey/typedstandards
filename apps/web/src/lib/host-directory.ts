// Host directory + publisher recognition — the SECOND, independent verdict
// dimension for the typedstandards.org verifier (#116 WS3 Phase D, open-questions
// Q47).
//
// Two orthogonal dimensions verify an evidence package:
//
//   1. CRYPTOGRAPHIC VALIDITY — universal. Anyone can mint a standard-conformant,
//      validly-signed envelope and the §9.2 checks confirm the math. This is the
//      open, decentralized property; it lives in verify-core + rollupVerdict.
//   2. HOST RECOGNITION (this module) — curated. A package's `trustRegistryUrl`
//      ORIGIN is the publisher identity. typedstandards.org publishes a host
//      directory mapping registry-origin → publisher display-name; the verifier
//      looks the origin up there.
//
// Recognition is ORTHOGONAL to validity: an unknown publisher does NOT downgrade a
// cryptographically-valid verdict, and a known publisher does NOT upgrade a failed
// one. The two are rendered as separate, clearly-labelled lines (P1: disclosure ≠
// validation).
//
// IMPERSONATION-SAFETY (the load-bearing invariant). The green "✓ known publisher"
// is awarded ONLY when BOTH hold:
//   (a) the declared `trustRegistryUrl` origin is listed in the directory, AND
//   (b) keyTrust confirms the signature against a key IN that registry
//       (keyTrust.verified — i.e. status `active` or `deprecated_valid`).
// A lookalike that declares a recognized origin but signs with its own key fails
// (b): if it carries a kid, the registry it points to is fetched and the kid is
// absent → `unknown_key` → "unknown publisher"; if it omits the kid it lands at
// `legacy_embedded` → the amber "host recognized, key not registry-confirmed" —
// which still withholds the green badge. Either way the publisher's good name is
// never conferred without (a)+(b). The only attack surfaces are key-compromise or
// directory-compromise (Q47).

import {
  type TrustTier,
  type TrustSignalDescriptor,
  type ResolvedTrustSignal,
  toResolvedSignal,
  // Explicit `.ts` extension (allowed by tsconfig `allowImportingTsExtensions`)
  // so the runtime import chain resolves under `node --test --experimental-strip-
  // types` for host-directory.test.ts. trust-signal's own imports are type-only,
  // so this is the chain's only runtime relative import. (The verify-core import
  // below is type-only and strips away entirely.)
} from './trust-signal.ts';
import type { KeyTrustResult, FetchLike } from '@typedstandards/verify-core';

// --- Directory shape ------------------------------------------------------

/** One recognized publisher: its trust-registry ORIGIN is the identity key. */
export interface HostDirectoryEntry {
  /** The canonical origin (scheme + host [+ port]) of the publisher's
   *  `trustRegistryUrl`. This — not the registry path — is the identity. */
  registryOrigin: string;
  /** Plain-language publisher name shown in the "known publisher" badge. */
  displayName: string;
  /** Optional link to the publisher's profile/home (rendered, never trusted). */
  profileUrl?: string;
}

export interface HostDirectory {
  /** Schema version of this directory document. */
  version: number;
  /** ISO date the roster was last edited (editorial provenance, not a proof). */
  updated: string;
  /**
   * The origin a BARE IDENTIFIER (a package hash or an evidence slug, which carries
   * no origin of its own) is resolved against — a DECLARED editorial choice by
   * whoever publishes this directory, not a property of any listed publisher.
   *
   * OPTIONAL by design. A fork's roster or a stale cached copy predating this field
   * simply omits it; such a document still validates, and consumers fall back to
   * their OWN anchor (see {@link bareIdentifierHostOf}). The fallback is deliberately
   * NOT `publishers[0]` — resolving by array position is the exact defect this field
   * replaces, so re-deriving it on a document's behalf would re-mint it.
   *
   * Distinct from every `publishers[].registryOrigin`: those identify publishers by
   * where their TRUST REGISTRY lives; this names where an origin-less identifier is
   * LOOKED UP. They coincide for the current anchor, but nothing requires it.
   *
   * Additive to the public well-known schema: a consumer that does not know the
   * field ignores it (it is JSON), and a consumer that does gets a stated answer
   * instead of an inferred one.
   */
  bareIdentifierHost?: string;
  publishers: HostDirectoryEntry[];
}

/** The stable, well-known path the directory is served at on typedstandards.org.
 *  Fetched same-origin by the verifier (so preview deployments see their own
 *  roster) and CORS-enabled so forks / the embeddable badge can read it too. */
export const HOST_DIRECTORY_PATH = '/.well-known/typed-host-directory.json';

/**
 * THE canonical host directory — the single source of truth for recognized hosts.
 * The route handler at {@link HOST_DIRECTORY_PATH} serves exactly this object, and
 * the verifier fetches it at runtime (so the roster can change without redeploying
 * the verifier code, and forks read the same shared roster).
 *
 * Two entries today: civicaitools.org (the platform's own registry) and datHere
 * Data Concierge — the first external publisher, listed once its trust registry went
 * live (the "real second publisher" Q47 anticipated as the trigger to move past a
 * single self-entry). New publishers are added editorially here; a written, fair
 * listing criterion + editorial process is tracked in civic-ai-tools#95 (Q47
 * governance-at-scale), to land before the RFC. Until then, listing stays a curated,
 * hand-reviewed JSON roster (a directory entry grants only condition (a) of the
 * impersonation-safety rule above; the green badge still requires (b)).
 *
 * `publishers` ORDER CARRIES NO MEANING. It is a roster, not a ranking: nothing in
 * the verifier reads a position, and the bare-identifier anchor is the declared
 * `bareIdentifierHost` below. Typed so that field cannot be dropped from the
 * published document without a compile error, while parsed documents may omit it.
 */
export const HOST_DIRECTORY: HostDirectory & { bareIdentifierHost: string } = {
  version: 1,
  // Unchanged: `updated` is defined above as the date the ROSTER was last edited,
  // and this phase edits no roster entry — only the document's anchor declaration.
  updated: '2026-06-16',
  bareIdentifierHost: 'https://civicaitools.org',
  publishers: [
    {
      registryOrigin: 'https://civicaitools.org',
      displayName: 'Civic AI Tools',
      profileUrl: 'https://civicaitools.org',
    },
    {
      registryOrigin: 'https://data-concierge.dathere.com',
      displayName: 'datHere Data Concierge',
      profileUrl: 'https://dathere.com',
    },
  ],
};

/**
 * The verifier's bare-identifier RESOLUTION anchor. A bare hash / slug has no origin
 * of its own, so it is resolved against this host's commitment endpoint.
 *
 * Read from the directory's DECLARED {@link HostDirectory.bareIdentifierHost}. It
 * was previously `publishers[0].registryOrigin` — selected by array position at
 * build time, which made "the default host" an accident of roster ordering rather
 * than a stated decision, and quietly re-used a publisher's trust-registry origin as
 * a commitment-API origin. Both are gone: the anchor is now an editorial choice the
 * published directory states out loud, and roster order carries no meaning.
 *
 * Anchoring is ORTHOGONAL to recognition, exactly as recognition is orthogonal to
 * validity: being the anchor confers no trust, and recognition never consults this
 * constant (see resolveHostRecognition). Any publisher's package verifies the same
 * whether or not its origin is the anchor — the anchor only answers "resolve this
 * origin-less identifier where?".
 */
export const BARE_ID_ANCHOR: string = HOST_DIRECTORY.bareIdentifierHost;

/**
 * The bare-identifier anchor DECLARED by a parsed directory document, or `undefined`
 * when it declares none (a fork's roster, or a copy cached before the field existed).
 *
 * `undefined` is the honest answer, not a bug: a document that states no anchor has
 * made no editorial choice, and inventing one for it — `publishers[0]`, say — is the
 * positional default this charter removed. A caller that needs an anchor anyway
 * falls back to its own {@link BARE_ID_ANCHOR}, which is what the verifier does: the
 * fetched directory drives recognition, while resolution stays anchored to the
 * directory this deployment ships and serves.
 */
export function bareIdentifierHostOf(directory: HostDirectory): string | undefined {
  return directory.bareIdentifierHost;
}

// --- Validation + lookup --------------------------------------------------

/** Normalize a URL/origin string to its canonical origin, or `undefined` if it
 *  is not a valid absolute URL. `URL.origin` lower-cases the host and drops any
 *  path/trailing slash, so two spellings of the same origin compare equal. */
export function originOf(url: string | undefined | null): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/**
 * Structural validation of a parsed directory document (fetched JSON or an
 * offline bundle snapshot — never trust either blindly). Drops entries that are
 * not well-formed and canonicalizes each `registryOrigin` so lookups are exact.
 * Returns `undefined` when the document is not a directory at all.
 *
 * `bareIdentifierHost` is OPTIONAL here and its absence is not a validation failure:
 * a fork's roster or a copy cached before the field existed still validates in full,
 * just without a declared anchor (see {@link bareIdentifierHostOf} for what callers
 * do then). Present-but-unparseable is treated the same as absent — a malformed
 * declaration states nothing, and a document is not rejected wholesale over a field
 * no existing consumer reads. When it IS a valid absolute URL it is canonicalized
 * with {@link originOf}, so it compares equal to a `registryOrigin` spelled
 * differently.
 */
export function validateHostDirectory(data: unknown): HostDirectory | undefined {
  if (typeof data !== 'object' || data === null) return undefined;
  const d = data as {
    version?: unknown;
    updated?: unknown;
    bareIdentifierHost?: unknown;
    publishers?: unknown;
  };
  if (!Array.isArray(d.publishers)) return undefined;
  const anchor =
    typeof d.bareIdentifierHost === 'string' ? originOf(d.bareIdentifierHost) : undefined;
  const publishers: HostDirectoryEntry[] = [];
  for (const raw of d.publishers) {
    if (typeof raw !== 'object' || raw === null) continue;
    const e = raw as { registryOrigin?: unknown; displayName?: unknown; profileUrl?: unknown };
    const origin = typeof e.registryOrigin === 'string' ? originOf(e.registryOrigin) : undefined;
    if (!origin || typeof e.displayName !== 'string' || !e.displayName) continue;
    publishers.push({
      registryOrigin: origin,
      displayName: e.displayName,
      ...(typeof e.profileUrl === 'string' && e.profileUrl ? { profileUrl: e.profileUrl } : {}),
    });
  }
  return {
    version: typeof d.version === 'number' ? d.version : 1,
    updated: typeof d.updated === 'string' ? d.updated : '',
    ...(anchor ? { bareIdentifierHost: anchor } : {}),
    publishers,
  };
}

/** Find the publisher whose registry origin matches `origin` (already canonical
 *  via {@link originOf}). */
export function lookupPublisher(
  directory: HostDirectory,
  origin: string,
): HostDirectoryEntry | undefined {
  return directory.publishers.find((p) => p.registryOrigin === origin);
}

/**
 * Fetch the host directory from `url` (default: same-origin {@link
 * HOST_DIRECTORY_PATH}). Returns `'unavailable'` on any failure — a missing or
 * unreachable directory degrades to a calm "recognition unavailable", never an
 * error, so the cryptographic verdict is unaffected (Q47 / #119 staleness
 * caveat). Plain GET, no custom headers (same CORS-preflight reasoning as the
 * other verifier fetches).
 */
export async function fetchHostDirectory(
  fetchImpl: FetchLike,
  url: string = HOST_DIRECTORY_PATH,
  signal?: AbortSignal,
): Promise<HostDirectory | 'unavailable'> {
  try {
    const res = await fetchImpl(url, signal ? { signal } : undefined);
    if (!res.ok) return 'unavailable';
    const directory = validateHostDirectory(await res.json());
    return directory ?? 'unavailable';
  } catch {
    return 'unavailable';
  }
}

// --- Recognition resolution ----------------------------------------------

/**
 * The host-recognition outcome — a dimension PARALLEL to the cryptographic
 * verdict, never folded into it.
 *
 *   - `known_publisher`                   (a)+(b) → verified (green).
 *   - `host_recognized_key_unconfirmed`   (a) yes, (b) no because the key cannot
 *                                          be tied to the registry (legacy
 *                                          embedded key / registry unreachable /
 *                                          rotated-out key) → attention (amber).
 *   - `unknown_publisher`                 origin not listed, OR the named registry
 *                                          actively disavows the key (`unknown_key`)
 *                                          → normal (calm). NOT a failure — minting
 *                                          a valid envelope is the open property.
 *   - `directory_unavailable`             directory could not be loaded → normal.
 *   - `no_publisher_declared`             no `trustRegistryUrl` to look up → normal.
 */
export type HostRecognitionStatus =
  | 'known_publisher'
  | 'host_recognized_key_unconfirmed'
  | 'unknown_publisher'
  | 'directory_unavailable'
  | 'no_publisher_declared';

export interface HostRecognition {
  status: HostRecognitionStatus;
  /** The registry origin extracted from the commitment, when one was declared. */
  origin?: string;
  /** The matched directory entry — set ONLY for `known_publisher`, the one earned
   *  state. Every non-green outcome leaves this unset so the UI literally cannot
   *  render the curated brand (or its profile link) for an unconfirmed signer; the
   *  copy in those states refers to the raw declared origin instead. */
  publisher?: HostDirectoryEntry;
  /** The trust signal (tier + glance label + detail) for this recognition,
   *  reusing the shared #110 trust-signal tiers. */
  signal: ResolvedTrustSignal;
}

function descriptor(tier: TrustTier, label: string, detail: string): TrustSignalDescriptor {
  return { tier, label, detail };
}

/**
 * Resolve host recognition from the commitment's declared registry origin, the
 * fetched directory, and the cryptographic key-trust result. This is the only
 * place the (a)+(b) impersonation rule lives.
 *
 * `keyTrust` is read from the SAME verify run whose registry was fetched from the
 * declared `trustRegistryUrl`, so (a) "origin is listed" and (b) "key is in that
 * origin's registry" reference one and the same publisher.
 */
export function resolveHostRecognition(
  commitment: { trustRegistryUrl?: string; trustRegistryUrlLegacy?: string },
  keyTrust: KeyTrustResult | null | undefined,
  directory: HostDirectory | 'unavailable' | undefined,
): HostRecognition {
  const origin = originOf(commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy);

  if (!origin) {
    return {
      status: 'no_publisher_declared',
      signal: toResolvedSignal(
        descriptor(
          'normal',
          'No publisher declared',
          'This package declares no trust-registry URL, so there is no publisher origin to look up in the host directory. Its cryptographic checks stand on their own.',
        ),
      ),
    };
  }

  if (directory === undefined || directory === 'unavailable') {
    return {
      status: 'directory_unavailable',
      origin,
      signal: toResolvedSignal(
        descriptor(
          'normal',
          'Publisher recognition unavailable',
          `The typedstandards.org host directory could not be loaded, so publisher recognition was skipped. This package declares the registry origin ${origin}. The cryptographic checks above are unaffected.`,
        ),
      ),
    };
  }

  const entry = lookupPublisher(directory, origin);

  // (a) fails — origin not in the directory. The decentralized-open case: anyone
  // may mint a valid envelope, so an unlisted publisher is expected, not a fault.
  if (!entry) {
    return {
      status: 'unknown_publisher',
      origin,
      signal: toResolvedSignal(
        descriptor(
          'normal',
          'Unknown publisher',
          `This package's registry origin (${origin}) is not listed in the typedstandards.org host directory. Anyone can mint a standard-conformant, validly-signed package, so an unlisted publisher is expected — not a failure. Whether the cryptography checks out is shown separately.`,
        ),
      ),
    };
  }

  // (a) holds. Now (b): is the signing key confirmed against THAT registry?
  if (keyTrust?.verified === true) {
    return {
      status: 'known_publisher',
      origin,
      publisher: entry,
      signal: toResolvedSignal(
        descriptor(
          'verified',
          `Known publisher: ${entry.displayName}`,
          `${origin} is listed in the typedstandards.org host directory as ${entry.displayName}, and this package's signing key is confirmed in that registry. Recognition says who published this — not whether the content is correct.`,
        ),
      ),
    };
  }

  // (a) holds but the named registry actively DISAVOWS the key: a kid was present,
  // looked up in that registry, and not found. This is the impersonation signal —
  // treat as an unknown publisher. Deliberately refer ONLY to the raw declared
  // origin, never the curated display-name: the green badge is the one earned place
  // for the brand, so a disavowed signer must not borrow "Civic AI Tools".
  if (keyTrust?.status === 'unknown_key') {
    return {
      status: 'unknown_publisher',
      origin,
      signal: toResolvedSignal(
        descriptor(
          'normal',
          'Unknown publisher',
          `This package points to the registry origin ${origin}, but its signing key is not in that registry — the registry it names does not vouch for this signer. It is treated as an unknown publisher.`,
        ),
      ),
    };
  }

  // (a) holds but (b) cannot be established: a legacy embedded key with no kid to
  // look up, an unreachable registry, or a rotated-out key. The host origin is
  // recognized but the key is not registry-confirmed, so the green badge is
  // withheld — the same calm "verified, with caveats" reading as the crypto side.
  // The origin IS listed, but we deliberately do NOT expose the curated entry
  // (no `publisher`, only the raw origin in the copy): the display-name is earned
  // only when the key is confirmed, so a lookalike that reaches this state by
  // omitting its kid cannot borrow the brand.
  return {
    status: 'host_recognized_key_unconfirmed',
    origin,
    signal: toResolvedSignal(
      descriptor(
        'attention',
        'Host recognized — signing key not registry-confirmed',
        `This package's registry origin (${origin}) is listed in the host directory, but its signing key could not be confirmed against that registry (see the key-trust check below) — so the publisher is recognized by origin but not affirmed.`,
      ),
    ),
  };
}
