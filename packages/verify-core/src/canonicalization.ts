// Canonicalization + hashing core (spec §8.2, §8.3.1, §12.3) — browser-safe.
//
// Factored from the server `src/lib/evidence/canonicalization.ts` (WS2) with one
// change: the SHA-256 backend is `@noble/hashes` instead of `node:crypto`, so the
// same code hashes in the browser. The `canonicalize` (RFC 8785 JCS) reference
// implementation was already pure and is reused verbatim. The server module now
// re-exports everything here, so producer and verifier — across both runtimes —
// remain on a single implementation; a package re-verifies to the exact hash it
// was published under regardless of where the check runs.
//
// The §8.2 detection rule routes each package to its chain: a package whose
// `contentHash` is a multihash object is a v0.1 package on the JCS chain;
// absence marks a pre-v0.1 package on the legacy `JSON.stringify` chain.

import canonicalize from 'canonicalize';
import { sha256Hex } from './primitives.ts';

// Content-canonicalization rule URIs (spec §8.2, §12.3). Identifiers, not fetch
// targets — verifiers resolve them via the local registry below.
export const LEGACY_JSON_CANONICALIZATION =
  'https://typedstandards.org/canonicalization/legacy-json/v1';
export const DATHERE_AG_JUPYTER_CANONICALIZATION =
  'https://typedstandards.org/canonicalization/dathere-ag-jupyter/v1';

/** Canonicalization-rule URIs this implementation knows how to apply. An
 *  unknown URI fails verify check #3 (`unknown_canonicalization_rule`). */
export const KNOWN_CANONICALIZATION_RULES: readonly string[] = [
  LEGACY_JSON_CANONICALIZATION,
  DATHERE_AG_JUPYTER_CANONICALIZATION,
];

/** Notebook extension whose object the dathere-ag-jupyter/v1 rule fingerprints
 *  (spec §8.2, §8.7.2). */
const NOTEBOOK_EXTENSION_KEY = 'org.civicaitools.notebook';

/**
 * RFC 8785 JSON Canonicalization Scheme. Wraps the `canonicalize` reference
 * implementation (by the RFC 8785 author); its return type is
 * `string | undefined`, undefined when the input isn't JSON-canonicalizable
 * (e.g. `undefined`). We throw in that case so a malformed package fails loudly
 * rather than silently producing a wrong hash.
 */
export function jcs(value: unknown): string {
  const out = canonicalize(value);
  if (typeof out !== 'string') {
    throw new Error('JCS canonicalization produced no output (non-JSON value)');
  }
  return out;
}

/**
 * §8.2 detection rule: a package whose `contentHash` is embedded as a multihash
 * OBJECT (keyed by lowercase algorithm name, hex-string values) is a v0.1
 * package on the JCS chain. Absence — or an external single-SHA-256 hex string
 * carried out of band on the DB row — marks a pre-v0.1 package on the legacy
 * `JSON.stringify` chain.
 */
export function isMultihashContentHash(
  value: unknown,
): value is Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  return entries.length > 0 && entries.every(([, v]) => typeof v === 'string');
}

/**
 * The envelope hash for a package, routed by the §8.2 detection rule:
 *   - v0.1 (multihash `contentHash` present) → SHA-256 of the RFC 8785 JCS
 *     canonicalization of the unsigned envelope.
 *   - pre-v0.1 (no multihash `contentHash`) → SHA-256 of the legacy
 *     insertion-order `JSON.stringify`, preserving byte-identical verification
 *     of every package published before the JCS switch.
 *
 * The signature envelope is persisted on the database row, not inside the
 * package object, so the package object already IS the unsigned envelope — there
 * is no `sig` field to strip here. Used by BOTH the packager and the verifier so
 * producer and verifier agree.
 */
export function computeEnvelopeHash(pkg: Record<string, unknown>): string {
  if (isMultihashContentHash(pkg['contentHash'])) {
    return sha256Hex(jcs(pkg));
  }
  return sha256Hex(JSON.stringify(pkg));
}

/**
 * SHA-256 of a package's off-log content, canonicalized per the named rule
 * (spec §8.2). Symmetric across produce/verify: `contentHash` is stripped before
 * hashing, so the result is identical whether the package already carries
 * `contentHash` (verify) or does not yet (packager).
 *
 *   - legacy-json/v1        → the canonical-JSON package with `contentHash`
 *     (and the sig envelope, which lives off-package here) omitted.
 *   - dathere-ag-jupyter/v1 → the executed notebook object
 *     (`extensions["org.civicaitools.notebook"]` and its rendered outputs).
 */
export function computeContentHashSha256(
  pkg: Record<string, unknown>,
  rule: string,
): string {
  if (rule === DATHERE_AG_JUPYTER_CANONICALIZATION) {
    const extensions = pkg['extensions'] as Record<string, unknown> | undefined;
    const notebook = extensions?.[NOTEBOOK_EXTENSION_KEY];
    if (notebook === undefined) {
      throw new Error(
        `dathere-ag-jupyter/v1 content hash requires the ${NOTEBOOK_EXTENSION_KEY} extension`,
      );
    }
    return sha256Hex(jcs(notebook));
  }
  // legacy-json/v1 (default): fingerprint the package minus contentHash.
  const rest: Record<string, unknown> = { ...pkg };
  delete rest['contentHash'];
  return sha256Hex(jcs(rest));
}
