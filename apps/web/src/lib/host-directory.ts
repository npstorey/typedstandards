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
} from './trust-signal';
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
 * First and only entry today: civicaitools.org. The roster language stays generic
 * — no other adopter is named until a real host commitment exists (Q47
 * stakeholder-boundary discipline; datHere stays generic per ADR-0004). New
 * publishers are added editorially here; governance-at-scale is deferred (Q47:
 * static curated JSON + editorial listing until a real second publisher arrives).
 */
export const HOST_DIRECTORY: HostDirectory = {
  version: 1,
  updated: '2026-06-06',
  publishers: [
    {
      registryOrigin: 'https://civicaitools.org',
      displayName: 'Civic AI Tools',
      profileUrl: 'https://civicaitools.org',
    },
  ],
};

/** The verifier's bare-hash RESOLUTION anchor — the directory's first listed host.
 *  A bare hash / slug has no origin of its own, so it is resolved against this
 *  host's commitment endpoint. Derived from {@link HOST_DIRECTORY} rather than a
 *  separate hardcoded constant, so the directory is the one source of truth for
 *  which host is "the default". */
export const PRIMARY_HOST: string = HOST_DIRECTORY.publishers[0].registryOrigin;

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
 */
export function validateHostDirectory(data: unknown): HostDirectory | undefined {
  if (typeof data !== 'object' || data === null) return undefined;
  const d = data as { version?: unknown; updated?: unknown; publishers?: unknown };
  if (!Array.isArray(d.publishers)) return undefined;
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
 * caveat). Plain GET, no custom headers (same 307/preflight reasoning as the
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
  /** The matched directory entry — set only when the origin is listed AND the
   *  recognition meaningfully attributes the package to that host (i.e. NOT for
   *  the `unknown_key`/disavowed case, where naming the publisher would imply a
   *  recognition the registry itself refuses). */
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
  // treat as an unknown publisher (do not attribute it to the recognized host).
  if (keyTrust?.status === 'unknown_key') {
    return {
      status: 'unknown_publisher',
      origin,
      signal: toResolvedSignal(
        descriptor(
          'normal',
          'Unknown publisher',
          `This package points to ${entry.displayName}'s registry origin (${origin}), but its signing key is not in that registry — the registry it names does not vouch for this signer. It is treated as an unknown publisher.`,
        ),
      ),
    };
  }

  // (a) holds but (b) cannot be established: a legacy embedded key with no kid to
  // look up, an unreachable registry, or a rotated-out key. The host origin is
  // recognized but the key is not registry-confirmed, so the green badge is
  // withheld — the same calm "verified, with caveats" reading as the crypto side.
  return {
    status: 'host_recognized_key_unconfirmed',
    origin,
    publisher: entry,
    signal: toResolvedSignal(
      descriptor(
        'attention',
        'Host recognized — signing key not registry-confirmed',
        `This package points to the registry origin listed for ${entry.displayName} (${origin}), but its signing key could not be confirmed against that registry (see the key-trust check below). The publisher identity is recognized but not affirmed.`,
      ),
    ),
  };
}
