// The key-derived signer identifier (hub ADR-0030 §2, §3) — browser-safe.
//
// A signer with no domain names itself by its public key: `did:key` in its
// base58btc (`z`) form for an Ed25519 key (The did:key Method v0.9, W3C CCG
// draft; multicodec `ed25519-pub` 0xed; multibase `z`). A verifier recomputes
// the identifier from the envelope's `publicKey` and compares it with the
// package's `signer.identifier` byte for byte. It never decodes the claimed
// string, so this module has an encoder and no decoder.
//
// The base-58 encoder is written in place (ADR-0030 §6): no runtime
// dependency, no `Buffer`, no Node built-in.

import { extractRawPublicKey } from './signature.ts';

/** The Bitcoin base-58 alphabet (draft-msporny-base58-03). */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base-58 encoding, Bitcoin alphabet: big-endian base conversion, one leading
 * `1` per leading zero byte (draft-msporny-base58-03). Not exported from the
 * package entry point; the derivation below is its one shipped caller.
 */
export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // Base-58 digits, least significant first.
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = '1'.repeat(zeros);
  for (let k = digits.length - 1; k >= 0; k--) out += BASE58_ALPHABET[digits[k]];
  return out;
}

/** The prefix that makes a `signer.identifier` key-derived (ADR-0030 §3). */
export const KEY_DERIVED_IDENTIFIER_PREFIX = 'did:key:';

/** The unsigned-varint encoding of multicodec `ed25519-pub` (0xed). */
const ED25519_PUB_MULTICODEC = Uint8Array.from([0xed, 0x01]);

/**
 * Derive the key-derived identifier from a base64 SPKI DER Ed25519 public key
 * (the signature envelope's `publicKey`), per ADR-0030 §2:
 *   1. base64-decode to 44 bytes whose first 12 are the Ed25519 SPKI prefix;
 *   2. take the trailing 32 bytes (the raw RFC 8032 public key);
 *   3. prepend `ed 01`;
 *   4. base58btc-encode;
 *   5. prefix `did:key:z`.
 * Steps 1-2 are `extractRawPublicKey`, which throws on a malformed key; so
 * does this function.
 */
export function deriveKeyDerivedIdentifier(publicKeyB64Der: string): string {
  const raw = extractRawPublicKey(publicKeyB64Der);
  const mc = new Uint8Array(ED25519_PUB_MULTICODEC.length + raw.length);
  mc.set(ED25519_PUB_MULTICODEC, 0);
  mc.set(raw, ED25519_PUB_MULTICODEC.length);
  return `${KEY_DERIVED_IDENTIFIER_PREFIX}z${base58btcEncode(mc)}`;
}

/**
 * Whether a `signer.identifier` is key-derived: it begins `did:key:`
 * (ADR-0030 §3). The prefix alone decides — a `did:key:u…` spelling, or a
 * `did:key:z…` for another key type, is key-derived and can never equal an
 * Ed25519 derivation, so it is a fatal mismatch. `bindingTier` does not enter
 * this decision.
 */
export function isKeyDerivedIdentifier(identifier: unknown): identifier is string {
  return typeof identifier === 'string' && identifier.startsWith(KEY_DERIVED_IDENTIFIER_PREFIX);
}
