// @typedstandards/verify-core (in-repo) — the portable, browser-safe evidence
// verification core (civic-ai-tools-website#116 WS2).
//
// Pure functions over provided data: no `node:crypto` / `fs` / `path` / `process`
// (an ESLint `no-restricted-imports` rule scoped to this directory enforces it),
// no app imports. Hashing is `@noble/hashes`, signatures are `@noble/curves`, JCS
// is `canonicalize`, and all network I/O is injected (`FetchLike`). The same code
// runs in the civicaitools.org server route and the typedstandards.org browser
// client (WS3); structured for trivial extraction to a standalone npm package
// when that second consumer lands.
//
// The server modules (`verify.ts`, `canonicalization.ts`, `profiles.ts`,
// `blob-ref.ts`, `signing.ts`, `attestation.ts`) re-export FROM here — never the
// reverse — so there is one implementation of every check and it cannot drift.

export * from './types.ts';
export * from './primitives.ts';
export * from './canonicalization.ts';
export * from './profiles.ts';
export * from './attestation.ts';
export * from './blob-ref.ts';
export * from './signature.ts';
export * from './trust-registry.ts';
export * from './checks.ts';
export * from './lifecycle.ts';
export * from './rekor.ts';
export * from './rekor-inclusion.ts';
export * from './asn1.ts';
export * from './x509.ts';
export * from './rfc3161.ts';
export * from './verify.ts';
