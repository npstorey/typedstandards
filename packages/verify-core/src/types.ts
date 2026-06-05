// Cross-cutting types for the browser-safe verify-core (civic-ai-tools-website#116
// WS2). Kept dependency-free so this module extracts cleanly to a standalone
// npm package (@typedstandards/verify-core) when typedstandards.org's client
// (WS3) becomes the second consumer. Nothing here imports from the app — the
// server modules re-export FROM verify-core, never the reverse.

/**
 * Envelope-side identity claim for the party that signed a node (spec §8.1.1
 * `signer`, §8.5). Independent copy of the server `signing.ts` `SignerIdentity`
 * so verify-core carries no app imports; the two are structurally identical and
 * interchangeable under TypeScript's structural typing.
 */
export interface SignerIdentity {
  bindingTier: string;
  identifier: string;
  displayName: string;
  verifiedAt?: string;
}

/**
 * captureMethod value space (spec §8.6, ADR-0011). Independent copy of the
 * server `packager.ts` `CaptureMethod` union; kept in sync by construction —
 * the per-profile vocabulary table in `profiles.ts` is the single source that
 * enumerates these.
 */
export type CaptureMethod =
  | 'chat-flow-stream'
  | 'claude-code-jsonl-readback'
  | 'claude-code-self-report';

/**
 * The subset of the WHATWG `fetch` signature verify-core depends on. Network
 * I/O is INJECTED rather than imported so the same code runs on the server (its
 * `fetch`), in the browser (`window.fetch`), and under test (a stub). verify-core
 * never reaches for `node:*` or a hardcoded global — see the ESLint
 * `no-restricted-imports` guard scoped to this directory.
 *
 * Per the WS1 prod smoke test: the injected fetcher should issue plain GETs with
 * NO custom request headers (a custom header triggers a CORS preflight, and a
 * preflight OPTIONS hitting civicaitools.org's site-wide 307 to its canonical
 * host can be rejected). A simple GET follows the 307 transparently.
 */
export type FetchLike = (
  input: string,
  init?: { signal?: AbortSignal },
) => Promise<{
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}>;
