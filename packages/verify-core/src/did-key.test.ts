// The key-derived identifier (hub ADR-0030 §2, §3): the base-58 encoder
// written in place, the derivation from a base64 SPKI `publicKey` to
// `did:key:z…`, and the prefix predicate.
//
// Vector sources, each re-derived here by the shipped encoder, never copied
// from a computed output:
//   - draft-msporny-base58-03, §Test Vectors: three input/output pairs.
//   - The eval-run example repository (ADR-0028), `package/trust-registry.json`
//     at commit 9031a94, copied byte for byte to
//     `__fixtures__/adr-0028-trust-registry.json` (file SHA-256 pinned below).
//     Its `publicKey` equals that commit's `package/public-key.txt`; ADR-0030 §2
//     gives the identifier it derives to.
//   - RFC 8032 §7.1 TEST 1: the published public key (checked against the
//     published secret key); it gives the first of ADR-0030 §9's two strings.
//   - RFC 8410 §10.1: the example Ed25519 public key (SPKI, as printed in the
//     RFC); it gives the second of ADR-0030 §9's strings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  ED25519_SPKI_PREFIX,
  KEY_DERIVED_IDENTIFIER_PREFIX,
  deriveKeyDerivedIdentifier,
  isKeyDerivedIdentifier,
  sha256Hex,
  type TrustRegistry,
} from './index.ts';
import { base58btcEncode } from './did-key.ts';

const hexToBytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const utf8 = (s: string) => new TextEncoder().encode(s);

/** Assemble base64 SPKI DER from a raw 32-byte Ed25519 public key. */
function rawToSpkiB64(raw: Uint8Array): string {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(raw, ED25519_SPKI_PREFIX.length);
  return b64(der);
}

/** RFC 8032 §7.1 TEST 1 (published test key). */
const RFC8032_T1_SECRET = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const RFC8032_T1_PUBLIC_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
/** RFC 8410 §10.1, the example public key's SPKI as printed in the RFC. */
const RFC8410_EXAMPLE_SPKI_B64 = 'MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=';

/** Expected identifiers: ADR-0030 §2 (eval-run key) and §9 (the two RFC keys). */
const DID_EVAL_RUN = 'did:key:z6MktZfoG3M2Navo8Pvbn8DXZAQrYTHk95QbZ7W5gnU9sK1u';
const DID_RFC8032_T1 = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const DID_RFC8410 = 'did:key:z6MkgBmPpouQ9ecfde8g8oyJyhdgxfuTB2mqsd7A8QnEu3ZA';

const REGISTRY_FIXTURE_BYTES = new Uint8Array(
  readFileSync(new URL('./__fixtures__/adr-0028-trust-registry.json', import.meta.url)),
);
/** `shasum -a 256 package/trust-registry.json` at the source commit. */
const REGISTRY_FIXTURE_SHA256 = 'd29c1880c3c66765843b618793050b1acb362ad671c14169965b67240f3560e1';
const adr0028Registry = JSON.parse(new TextDecoder().decode(REGISTRY_FIXTURE_BYTES)) as TrustRegistry;

// --- The encoder and the derivation (vectors) -----------------------------

test('base58btc: the three draft-msporny-base58-03 test vectors', () => {
  assert.equal(base58btcEncode(utf8('Hello World!')), '2NEpo7TZRRrLZSi2U');
  assert.equal(
    base58btcEncode(utf8('The quick brown fox jumps over the lazy dog.')),
    'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z',
  );
  assert.equal(base58btcEncode(hexToBytes('0000287fb4cd')), '11233QC4');
});

test('base58btc: empty input and all-zero input', () => {
  assert.equal(base58btcEncode(new Uint8Array(0)), '');
  assert.equal(base58btcEncode(new Uint8Array(3)), '111');
});

test('derivation: the eval-run example key gives ADR-0030 §2 identifier', () => {
  assert.equal(sha256Hex(REGISTRY_FIXTURE_BYTES), REGISTRY_FIXTURE_SHA256);
  const [entry] = adr0028Registry.keys;
  assert.ok(entry);
  const raw = Buffer.from(entry.publicKey, 'base64').subarray(12);
  assert.equal(
    Buffer.from(raw).toString('hex'),
    'd1a7f59666e0fa9f8e4037105237bef5fe821355aae6115b3df0cd06fb1d39ac',
  );
  assert.equal(deriveKeyDerivedIdentifier(entry.publicKey), DID_EVAL_RUN);
});

test('derivation: RFC 8032 §7.1 TEST 1 public key gives ADR-0030 §9 first string', () => {
  const raw = ed25519.getPublicKey(RFC8032_T1_SECRET);
  assert.equal(Buffer.from(raw).toString('hex'), RFC8032_T1_PUBLIC_HEX);
  assert.equal(deriveKeyDerivedIdentifier(rawToSpkiB64(raw)), DID_RFC8032_T1);
});

test('derivation: RFC 8410 §10.1 example key gives ADR-0030 §9 second string', () => {
  const raw = Buffer.from(RFC8410_EXAMPLE_SPKI_B64, 'base64').subarray(12);
  assert.equal(
    Buffer.from(raw).toString('hex'),
    '19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1',
  );
  assert.equal(deriveKeyDerivedIdentifier(RFC8410_EXAMPLE_SPKI_B64), DID_RFC8410);
});

test('derivation: every Ed25519 identifier is did:key:z6Mk plus 44 characters', () => {
  for (const id of [DID_EVAL_RUN, DID_RFC8032_T1, DID_RFC8410]) {
    assert.match(id, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  }
});

test('derivation: a malformed key throws', () => {
  assert.throws(() => deriveKeyDerivedIdentifier(b64(Uint8Array.from([0x30, 0x01, 0x00]))));
  const wrongPrefix = new Uint8Array(44);
  assert.throws(() => deriveKeyDerivedIdentifier(b64(wrongPrefix)));
});

test('predicate: the did:key: prefix alone makes an identifier key-derived', () => {
  assert.equal(KEY_DERIVED_IDENTIFIER_PREFIX, 'did:key:');
  assert.equal(isKeyDerivedIdentifier(DID_RFC8032_T1), true);
  assert.equal(isKeyDerivedIdentifier('did:key:uAe0B'), true);
  assert.equal(isKeyDerivedIdentifier('did:key:'), true);
  assert.equal(isKeyDerivedIdentifier('https://github.com/npstorey'), false);
  assert.equal(isKeyDerivedIdentifier('did:web:example.org'), false);
  assert.equal(isKeyDerivedIdentifier('DID:KEY:z6Mk'), false);
  assert.equal(isKeyDerivedIdentifier(undefined), false);
  assert.equal(isKeyDerivedIdentifier(42), false);
});

