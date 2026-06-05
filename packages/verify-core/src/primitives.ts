// Browser-safe crypto primitives for verify-core (civic-ai-tools-website#116 WS2).
//
// The server modules these were factored out of used Node's `crypto`
// (`createHash`) and `Buffer`. Here the same digests are produced with
// `@noble/hashes` — the sibling library of the `@noble/curves` already used for
// Ed25519 — so the module runs unchanged in a browser. The digests are
// byte-identical to Node's, which is what lets the server keep re-exporting
// these without altering any published hash (guarded by packager/canonicalization
// tests).

import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, utf8ToBytes };

/** SHA-256 of a UTF-8 string (or raw bytes), hex-encoded. Replaces
 *  `crypto.createHash('sha256').update(x).digest('hex')`. */
export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return bytesToHex(sha256(bytes));
}

/** SHA-512 of a UTF-8 string (or raw bytes), hex-encoded. Replaces
 *  `crypto.createHash('sha512').update(x).digest('hex')` (the Rekor prehash). */
export function sha512Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return bytesToHex(sha512(bytes));
}

/**
 * Decode standard base64 (the encoding `signing.ts` produces for signatures and
 * SPKI public keys) into raw bytes. Browser-safe: `atob` is a WHATWG global
 * present in both browsers and Node ≥16, avoiding Node's `Buffer`.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
