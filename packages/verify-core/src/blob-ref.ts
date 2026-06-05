// Content-addressable blob references for evidence package fields (spec §9.2
// check #9) — browser-safe.
//
// Large fields (full output text, trace JSON, composed skill guidance) can be
// stored as a separate blob and referenced from the package JSON rather than
// inlined. The package hash still binds the reference (the BlobRef object is part
// of the canonical JSON), and the referenced content has its own SHA-256 so
// consumers verify each piece independently.
//
// Factored from the server `blob-ref.ts` (WS2): the SHA-256 backend is
// `@noble/hashes` and the network fetch is INJECTED (defaulting to the universal
// `globalThis.fetch`, which the server provides and the browser provides as
// `window.fetch`). No `node:crypto`, no hardcoded transport.

import { sha256Hex } from './primitives.ts';
import type { FetchLike } from './types.ts';

/** Format of `ref`: `blob:sha256:<64 hex chars>`. */
export interface BlobRef {
  ref: string;
  url: string;
  contentType: string;
  size: number;
}

const REF_PATTERN = /^blob:sha256:([0-9a-f]{64})$/;

/**
 * Detect whether a field value is a BlobRef object. Used by the verifier and the
 * detail-page renderer to branch between inline content and blob-referenced
 * content.
 */
export function isBlobRef(value: unknown): value is BlobRef {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.ref === 'string' &&
    REF_PATTERN.test(v.ref) &&
    typeof v.url === 'string' &&
    typeof v.contentType === 'string' &&
    typeof v.size === 'number'
  );
}

export interface ParsedBlobRef {
  algo: 'sha256';
  hash: string;
}

/**
 * Parse a `blob:sha256:<hash>` reference string into its components.
 * Throws if the format is invalid.
 */
export function parseBlobRef(ref: string): ParsedBlobRef {
  const match = REF_PATTERN.exec(ref);
  if (!match) {
    throw new Error(`Invalid blob reference: expected "blob:sha256:<64 hex>", got "${ref}"`);
  }
  return { algo: 'sha256', hash: match[1] };
}

// Source-of-truth array (not just a type) so the trust-signal vocabulary
// (civic-ai-tools-website#110) can enumerate every BlobRef failure reason at
// runtime. Each reason is a sub-explanation of a failed (Alarm-tier) BlobRef
// integrity check (#9).
export const BLOB_REF_VERIFY_REASONS = [
  'invalid_ref',
  'fetch_failed',
  'size_mismatch',
  'hash_mismatch',
] as const;
export type BlobRefVerifyReason = (typeof BLOB_REF_VERIFY_REASONS)[number];

export interface BlobRefVerifyResult {
  ok: boolean;
  reason?: BlobRefVerifyReason;
  /** SHA-256 of the fetched blob content, if fetched. Lets callers surface both
   *  the expected (ref) and actual hash when they mismatch. */
  computedHash?: string;
  /** Byte length of the fetched blob. */
  computedSize?: number;
}

/** Options accepted by the network-touching blob helpers: an injected fetcher
 *  (defaults to `globalThis.fetch`, read at call time so a test stub on the
 *  global is honored) + an optional abort signal. */
export interface BlobFetchOptions {
  fetch?: FetchLike;
  signal?: AbortSignal;
}

function resolveFetch(options: BlobFetchOptions): FetchLike {
  return options.fetch ?? (globalThis.fetch as unknown as FetchLike);
}

/**
 * Fetch a blob and verify that its SHA-256 matches the reference hash and that
 * its byte size matches the metadata. Returns a structured result; never throws.
 *
 * Fetches over HTTPS without auth (Vercel Blob public access is the storage
 * default for evidence content). A plain GET with no custom headers, so it
 * follows civicaitools.org's canonical-host 307 without a CORS preflight.
 */
export async function verifyBlobRef(
  ref: BlobRef,
  options: BlobFetchOptions = {},
): Promise<BlobRefVerifyResult> {
  let parsed: ParsedBlobRef;
  try {
    parsed = parseBlobRef(ref.ref);
  } catch {
    return { ok: false, reason: 'invalid_ref' };
  }

  const fetcher = resolveFetch(options);
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await fetcher(ref.url, {
      signal: options.signal ?? AbortSignal.timeout(15_000),
    });
  } catch {
    return { ok: false, reason: 'fetch_failed' };
  }
  if (!response.ok) {
    return { ok: false, reason: 'fetch_failed' };
  }

  let bytes: Uint8Array;
  try {
    const buffer = await response.arrayBuffer();
    bytes = new Uint8Array(buffer);
  } catch {
    return { ok: false, reason: 'fetch_failed' };
  }

  const computedSize = bytes.byteLength;
  if (computedSize !== ref.size) {
    return { ok: false, reason: 'size_mismatch', computedSize };
  }

  const computedHash = sha256Hex(bytes);
  if (computedHash !== parsed.hash) {
    return { ok: false, reason: 'hash_mismatch', computedHash, computedSize };
  }

  return { ok: true, computedHash, computedSize };
}

/**
 * Compute the canonical `blob:sha256:<hash>` reference hash for content bytes.
 * Used by uploaders constructing a BlobRef object.
 */
export function computeBlobRefHash(content: string | Uint8Array): string {
  return sha256Hex(content);
}

/**
 * Fetch a BlobRef's content as a UTF-8 string. Used by the detail-page renderer
 * to resolve output-level BlobRefs. Returns null on any failure; callers fall
 * back to showing only the reference metadata rather than blocking the render.
 */
export async function fetchBlobRefText(
  ref: BlobRef,
  options: BlobFetchOptions = {},
): Promise<string | null> {
  try {
    const fetcher = resolveFetch(options);
    const response = await fetcher(ref.url, {
      signal: options.signal ?? AbortSignal.timeout(15_000),
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  }
}
