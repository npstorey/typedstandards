// Rekor transparency-log check (spec §9.2 check #8) — browser-safe.
//
// Factored from the server `verify.ts`. The check depth is unchanged from what
// the server does today: re-fetch the entry and compare the stored SHA-512 hash
// (hash-PARITY). It does NOT cryptographically verify the Merkle inclusion proof
// — that, and full offline verification against the log checkpoint, is
// civic-ai-tools-website#119. Node swaps: the SHA-512 prehash uses `@noble/hashes`
// (via `rekorHashForPackage`), the base64 body decode uses `atob` + `TextDecoder`
// instead of `Buffer`, and the network fetch is injected.

import { rekorHashForPackage } from './signature.ts';
import { base64ToBytes } from './primitives.ts';
import type { FetchLike } from './types.ts';

export interface RekorVerifyResult {
  verified: boolean;
  logIndex?: number;
  integratedTime?: number;
  logEntryUrl?: string;
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

    return {
      verified,
      logIndex: entry.logIndex,
      integratedTime: entry.integratedTime,
      logEntryUrl: `https://search.sigstore.dev/?logIndex=${entry.logIndex}`,
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
}
