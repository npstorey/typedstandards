// Ed25519 signature verification (spec §9.2 check #2, §8.3.1) — browser-safe.
//
// Factored from the server `verify.ts`. Two Node dependencies were swapped out:
//   - `crypto.createPublicKey(spki)→JWK→raw` for the raw key bytes → a fixed
//     SPKI-prefix check + a 32-byte tail slice (see `extractRawPublicKey`).
//   - `crypto.createHash('sha512')` for the Rekor prehash → `@noble/hashes`.
// The Ed25519 / Ed25519ph verify itself (`@noble/curves`) was already pure and is
// reused as-is, INCLUDING the #111 algorithm dispatch.

import { ed25519, ed25519ph } from '@noble/curves/ed25519.js';
import { base64ToBytes, sha512Hex, utf8ToBytes } from './primitives.ts';

// An Ed25519 public key in SPKI DER is a fixed 44-byte structure: a 12-byte
// prefix (SEQUENCE → AlgorithmIdentifier{ OID 1.3.101.112 } → BIT STRING, 0
// unused bits) followed by the 32-byte raw key. Asserting the prefix + length
// before slicing the tail makes a malformed key throw rather than yield 32
// arbitrary bytes — matching the old JWK path, which threw on a bad key.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_SPKI_LENGTH = 44;

/**
 * Extract the raw 32-byte Ed25519 public key from a base64 SPKI DER encoding.
 * Browser-safe replacement for Node's `crypto.createPublicKey(...).export({jwk})`:
 * the SPKI structure is fixed for Ed25519, so the raw key is the trailing 32
 * bytes once the standard prefix is confirmed. A `verify-core` SPKI-extraction
 * fixture test asserts this returns the identical bytes the old JWK path did.
 */
export function extractRawPublicKey(publicKeyB64Der: string): Uint8Array {
  const der = base64ToBytes(publicKeyB64Der);
  if (der.length !== ED25519_SPKI_LENGTH) {
    throw new Error(
      `Unexpected Ed25519 SPKI length ${der.length}; expected ${ED25519_SPKI_LENGTH}`,
    );
  }
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
    if (der[i] !== ED25519_SPKI_PREFIX[i]) {
      throw new Error('Unexpected Ed25519 SPKI prefix; not a bare Ed25519 public key');
    }
  }
  return der.slice(ED25519_SPKI_LENGTH - 32);
}

/**
 * Verify an evidence signature against the package hash.
 *
 * The signed message is the UTF-8 bytes of the package hex hash — the same
 * convention used by `signPackage` in `signing.ts`. The signature is verified
 * under the algorithm it was actually created with (`algorithm`):
 *   - `Ed25519ph` — the current scheme (SHA-512 prehash, matching what Rekor
 *     validates). The default when no label is given.
 *   - `Ed25519`  — plain Ed25519, used by pre-switch legacy packages whose
 *     stored signature is labeled `'Ed25519'` (these carry no kid and predate
 *     the Ed25519→Ed25519ph migration).
 *
 * Dispatching on the stored label (the #111 fix, commit aa784d3) fixes a false
 * negative where a valid plain-Ed25519 signature was checked with Ed25519ph and
 * read as invalid. It does not weaken verification: the label only selects the
 * verifier, the signature math must still hold, so a forgery fails under both.
 * WS2 carries this dispatch forward so the identical false-negative does not
 * reappear off-platform.
 */
export function verifySignature(
  packageHash: string,
  signatureB64: string,
  publicKeyB64: string,
  algorithm?: string,
): boolean {
  try {
    const pubBytes = extractRawPublicKey(publicKeyB64);
    const sigBytes = base64ToBytes(signatureB64);
    const messageBytes = utf8ToBytes(packageHash);
    const verifier = algorithm === 'Ed25519' ? ed25519 : ed25519ph;
    return verifier.verify(sigBytes, messageBytes, pubBytes);
  } catch (err) {
    console.error('[verify] Signature verification error:', err);
    return false;
  }
}

/**
 * Derive the hex value that Rekor stores in `spec.data.hash.value` for a given
 * package. Rekor's hashedrekord Ed25519ph verifier treats this as the SHA-512
 * prehash of the signed message, so we mirror that: SHA-512 over the UTF-8 bytes
 * of the hex package hash. The raw SHA-256 `packageHash` does NOT match what
 * Rekor stores. Re-exported by the server `signing.ts` so producer and verifier
 * compute one value.
 */
export function rekorHashForPackage(packageHash: string): string {
  return sha512Hex(utf8ToBytes(packageHash));
}
