// Signing MECHANISM for evidence envelopes (spec §8.3.1, §8.5) — I/O-free,
// browser-safe, no key custody.
//
// The scheme is Ed25519ph (pre-hashed Ed25519, SHA-512) over the UTF-8 bytes
// of the envelope-hash hex string — the exact chain verify-core's
// `verifySignature` dispatches on, and the one Rekor's hashedrekord verifier
// requires for bare Ed25519 public keys (sigstore/rekor#1945). Ed25519ph
// prehashes the message internally with SHA-512, producing the digest the
// signature commits to — the same value a transparency log stores.
//
// KEY CUSTODY IS THE CALLER'S: there is no environment probe, no default key
// identifier, and no platform identity constant in this module — the caller
// supplies the private key and the kid. NOT signing is a first-class outcome:
// `buildEnvelope` already returned a complete package + envelope hash, and
// nothing in this package labels an unsigned result as anything else.
//
// Key handling is re-implemented off `node:crypto`: a raw 32-byte seed is
// used directly; PKCS8 DER (RFC 5958/8410) is parsed with verify-core's
// strict, bounds-checked ASN.1 reader; the public key is derived via
// `@noble/curves` and wrapped in the fixed 44-byte Ed25519 SPKI structure.

import { ed25519ph } from '@noble/curves/ed25519.js';
import {
  base64ToBytes,
  children,
  content,
  expectTag,
  oidToString,
  readNode,
  utf8ToBytes,
} from '@typedstandards/verify-core';

/** Signature algorithm identifier embedded in every `SignResult` and stored
 *  alongside each signature. Verifiers dispatch on it (spec §8.3.1). */
export const SIGNING_ALGORITHM = 'Ed25519ph';

/**
 * Ed25519 private-key input (the caller's key, per the no-custody rule):
 *   - a raw 32-byte seed (`Uint8Array`);
 *   - PKCS8 DER bytes (`Uint8Array`, RFC 5958 wrapping an RFC 8410
 *     CurvePrivateKey);
 *   - a base64 string of either of the above.
 */
export type Ed25519KeyInput = Uint8Array | string;

export interface SignResult {
  signature: string; // base64, 64-byte Ed25519ph signature
  publicKey: string; // base64 SPKI DER (the registry-entry encoding)
  algorithm: string; // SIGNING_ALGORITHM
  /** Caller-supplied stable key identifier — the trust-registry lookup
   *  handle. Not secret. */
  kid: string;
}

// --- key handling (no node:crypto) ---

const ED25519_OID = '1.3.101.112';

// An Ed25519 public key in SPKI DER is a fixed 44-byte structure: this
// 12-byte prefix (SEQUENCE → AlgorithmIdentifier{ OID 1.3.101.112 } → BIT
// STRING, 0 unused bits) followed by the 32-byte raw key. Mirrors the prefix
// verify-core's `extractRawPublicKey` asserts before slicing the tail.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** Base64-encode raw bytes without `Buffer` (browser-safe: `btoa` is a WHATWG
 *  global in browsers and Node ≥16). */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Extract the raw 32-byte Ed25519 seed from PKCS8 DER bytes using
 * verify-core's strict ASN.1 reader (every read bounds-checked; malformed
 * input throws rather than yielding arbitrary bytes):
 *
 *   PrivateKeyInfo ::= SEQUENCE {
 *     version                 INTEGER,
 *     privateKeyAlgorithm     SEQUENCE { OID 1.3.101.112 },
 *     privateKey              OCTET STRING (containing the RFC 8410
 *                             CurvePrivateKey ::= OCTET STRING (32 bytes)) }
 *
 * Trailing PKCS8 fields (attributes [0], publicKey [1]) are tolerated and
 * ignored — the seed fully determines the keypair.
 */
function extractSeedFromPkcs8(der: Uint8Array): Uint8Array {
  const root = expectTag(readNode(der, 0), 0x30, 'PrivateKeyInfo');
  if (root.end !== der.length) {
    throw new Error('PKCS8: trailing bytes after PrivateKeyInfo');
  }
  const fields = children(der, root);
  if (fields.length < 3) {
    throw new Error('PKCS8: expected version, algorithm, privateKey');
  }
  expectTag(fields[0], 0x02, 'version');
  const alg = expectTag(fields[1], 0x30, 'AlgorithmIdentifier');
  const algFields = children(der, alg);
  if (algFields.length < 1) {
    throw new Error('PKCS8: empty AlgorithmIdentifier');
  }
  const oid = oidToString(der, algFields[0]);
  if (oid !== ED25519_OID) {
    throw new Error(`PKCS8: not an Ed25519 key (algorithm OID ${oid})`);
  }
  const privateKeyOctets = content(der, expectTag(fields[2], 0x04, 'privateKey'));
  const curveKey = expectTag(
    readNode(privateKeyOctets, 0),
    0x04,
    'CurvePrivateKey',
  );
  if (curveKey.end !== privateKeyOctets.length) {
    throw new Error('PKCS8: trailing bytes in CurvePrivateKey');
  }
  const seed = content(privateKeyOctets, curveKey);
  if (seed.length !== 32) {
    throw new Error(`PKCS8: Ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  return new Uint8Array(seed); // copy out of the DER view
}

/** Normalize any accepted key input to the raw 32-byte seed. */
function toRawSeed(key: Ed25519KeyInput): Uint8Array {
  const bytes = typeof key === 'string' ? base64ToBytes(key) : key;
  if (bytes.length === 32) return new Uint8Array(bytes);
  return extractSeedFromPkcs8(bytes);
}

/**
 * Derive the base64 SPKI DER public key for a private key — the stable
 * on-registry encoding (spec §8.3.3): fixed 12-byte Ed25519 SPKI prefix +
 * the 32-byte raw public key from `@noble/curves`.
 */
export function derivePublicKeySpki(key: Ed25519KeyInput): string {
  const seed = toRawSeed(key);
  const publicKey = ed25519ph.getPublicKey(seed);
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + publicKey.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(publicKey, ED25519_SPKI_PREFIX.length);
  return bytesToBase64(der);
}

/**
 * Sign an envelope hash with the CALLER'S Ed25519 key using Ed25519ph.
 *
 * The signed message is the UTF-8 bytes of the envelope-hash hex string —
 * the exact convention verify-core's `verifySignature` checks (spec §8.3.1).
 * Ed25519ph prehashes this internally with SHA-512, which is also the value a
 * hashedrekord transparency-log entry stores as `spec.data.hash`.
 *
 * There is no null path here and no environment fallback: signing requires a
 * key and a kid, both caller-supplied. The unsigned tier is expressed by NOT
 * calling this function — the envelope + hash from `buildEnvelope` are
 * already complete.
 */
export function signEnvelopeHash(
  envelopeHashHex: string,
  key: Ed25519KeyInput,
  kid: string,
): SignResult {
  if (!kid) {
    throw new Error(
      'signEnvelopeHash requires a key identifier (kid) — configuration is caller-supplied',
    );
  }
  const seed = toRawSeed(key);
  const message = utf8ToBytes(envelopeHashHex);
  const signature = ed25519ph.sign(message, seed);

  return {
    signature: bytesToBase64(signature),
    publicKey: derivePublicKeySpki(seed),
    algorithm: SIGNING_ALGORITHM,
    kid,
  };
}

/**
 * Re-encode a base64 SPKI-DER public key as a base64-wrapped PEM block.
 * Transparency-log submission requires PEM — raw base64 DER is rejected with
 * "invalid public key: failure decoding PEM". PEM is the DER base64
 * line-wrapped to 64 chars between BEGIN/END banners; the result is base64 of
 * the PEM because every other `content` field in the proposal body is
 * base64-encoded.
 */
export function derPublicKeyToPemBase64(pubKeyDerB64: string): string {
  const pemBody = pubKeyDerB64.match(/.{1,64}/g)?.join('\n') ?? pubKeyDerB64;
  const pem = `-----BEGIN PUBLIC KEY-----\n${pemBody}\n-----END PUBLIC KEY-----\n`;
  return btoa(pem); // PEM is ASCII, so btoa is safe here
}
