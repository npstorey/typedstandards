// Rekor transparency-log check (spec §9.2 check #8) — browser-safe.
//
// Factored from the server `verify.ts`. This module does hash-PARITY: re-fetch the
// entry and compare the stored SHA-512 hash. When the fetched entry carries an
// inclusion proof it ALSO runs cryptographic Merkle-inclusion verification against
// the pinned log key (`rekor-inclusion.ts`, civic-ai-tools-website#119 P1) — the
// same offline check a carried bundle runs. Node swaps: the SHA-512 prehash uses `@noble/hashes`
// (via `rekorHashForPackage`), the base64 body decode uses `atob` + `TextDecoder`
// instead of `Buffer`, and the network fetch is injected.

import { rekorHashForPackage } from './signature.ts';
import { base64ToBytes } from './primitives.ts';
import {
  verifyRekorInclusion,
  type RekorInclusionProof,
  type RekorInclusionResult,
} from './rekor-inclusion.ts';
import type { FetchLike } from './types.ts';

export interface RekorVerifyResult {
  /** Hash-parity: the entry's recorded SHA-512 prehash matches the package. */
  verified: boolean;
  logIndex?: number;
  integratedTime?: number;
  logEntryUrl?: string;
  /** Cryptographic Merkle-inclusion verdict (#119), when the fetched entry carries
   *  an inclusion proof. Additive — `verified` (hash-parity) is unchanged. */
  inclusion?: RekorInclusionResult;
}

/**
 * Verify that a Rekor transparency log entry is consistent with a published
 * package.
 *
 * The `packageHash` argument is the SHA-256 hash our system stores as
 * `basePackageHash`. Rekor's entry does NOT store that value directly — it stores
 * the SHA-512 prehash of the signed message (see `rekorHashForPackage`), because
 * the submission uses Ed25519ph. We derive the expected Rekor hash here and
 * compare.
 *
 * The fetcher is injected (defaults to `globalThis.fetch`); the GET carries no
 * custom headers so it is CORS-preflight-free.
 */
export async function verifyRekorEntry(
  entryId: string,
  packageHash: string,
  options: { fetch?: FetchLike; signal?: AbortSignal } = {},
): Promise<RekorVerifyResult> {
  const fetcher = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
  try {
    const response = await fetcher(
      `https://rekor.sigstore.dev/api/v1/log/entries/${entryId}`,
      { signal: options.signal ?? AbortSignal.timeout(10_000) },
    );

    if (!response.ok) {
      return { verified: false };
    }

    const result = (await response.json()) as Record<string, RekorLogEntry>;
    const entry = result[entryId] || Object.values(result)[0];
    if (!entry) return { verified: false };

    // Decode the base64 body and cross-check both hash algorithm and value.
    const bodyJson = new TextDecoder().decode(base64ToBytes(entry.body));
    const body = JSON.parse(bodyJson);
    const recordedHash: string | undefined = body?.spec?.data?.hash?.value;
    const recordedAlgo: string | undefined = body?.spec?.data?.hash?.algorithm;
    const expectedHash = rekorHashForPackage(packageHash);
    const verified = recordedAlgo === 'sha512' && recordedHash === expectedHash;

    // Deepen #8 (civic-ai-tools-website#119): when the entry carries an inclusion
    // proof, cryptographically verify Merkle inclusion against the pinned log key —
    // the same offline check a carried bundle runs, here over the fetched entry.
    const proof = entry.verification?.inclusionProof;
    const inclusion =
      proof && entry.body ? verifyRekorInclusion(entry.body, proof) : undefined;

    return {
      verified,
      logIndex: entry.logIndex,
      integratedTime: entry.integratedTime,
      logEntryUrl: `https://search.sigstore.dev/?logIndex=${entry.logIndex}`,
      ...(inclusion ? { inclusion } : {}),
    };
  } catch (err) {
    console.error('[verify] Rekor verification error:', err);
    return { verified: false };
  }
}

interface RekorLogEntry {
  body: string;
  logIndex?: number;
  integratedTime?: number;
  verification?: { inclusionProof?: RekorInclusionProof };
}
