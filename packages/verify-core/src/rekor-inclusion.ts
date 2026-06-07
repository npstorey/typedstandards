// Rekor transparency-log MERKLE-INCLUSION verification (spec §9.2 check #8, deep)
// — browser-safe, OFFLINE-capable (civic-ai-tools-website#119 P1).
//
// `rekor.ts` does hash-PARITY: re-fetch the entry and compare the stored SHA-512
// prehash. This module closes the cryptographic gap — it verifies, with no trust
// in civicaitools.org and no network, that a Rekor entry is *included* in a log
// the sigstore log key vouches for:
//
//   1. RFC 6962 §2.1.1 inclusion proof: leaf = SHA-256(0x00 ‖ entry-body); fold the
//      audit path to a root; that root MUST equal the proof's `rootHash`.
//   2. Checkpoint (a Go signed-note / "checkpoint" per the transparency-dev format):
//      its committed root + tree size MUST equal the proof's, and its signature MUST
//      verify against a PINNED Rekor log public key (the trust anchor) — selected by
//      the note's 4-byte key hint, which is the first 4 bytes of the log id
//      (SHA-256 of the key's DER).
//
// Everything is pure `@noble/hashes` (SHA-256 Merkle hashing) + `@noble/curves`
// (ECDSA P-256 checkpoint signature). No `node:*`, no `Buffer`, no fetch — the
// proof + checkpoint + entry body are supplied by the caller (carried in the
// offline bundle per D2). The recipe here was validated byte-for-byte against a
// real `rekor.sigstore.dev` entry (and cross-checked with OpenSSL) before shipping;
// `__fixtures__/rekor-inclusion.json` is that entry, and the tests reproduce it.

import { sha256 } from '@noble/hashes/sha2.js';
import { p256 } from '@noble/curves/nist.js';
import { base64ToBytes, hexToBytes, bytesToHex, utf8ToBytes } from './primitives.ts';

/**
 * A pinned Rekor transparency-log public key — the OFFLINE trust anchor for
 * check #8. A verifier with this key (and the carried proof + checkpoint) needs no
 * network and no reference-implementation dependency to confirm log inclusion.
 */
export interface RekorLogAnchor {
  /** The checkpoint/note signer name (the note's signature-line identity). */
  origin: string;
  /** The log id: hex SHA-256 of `publicKeyDer`. The note's 4-byte key hint is its
   *  first 4 bytes; we match anchors on that. */
  logId: string;
  /** The log public key, base64 SPKI DER (as `/api/v1/log/publicKey` returns). */
  publicKeyDer: string;
  /** Signature curve. Only P-256 is used by the public-good instance today. */
  curve: 'p256';
}

// PROVENANCE (anchor pinning — spec §10.3). The active public-good Rekor shard
// (`rekor.sigstore.dev`, tree id 1193050959916656506) signs its checkpoints with
// this ECDSA P-256 key. Captured 2026-06-06 from
// `https://rekor.sigstore.dev/api/v1/log/publicKey`; the SHA-256 of its DER is the
// log id `c0d23d6a…`, which equals the `logID` every entry reports and the note's
// key-hint prefix (independently corroborated by sigstore's TUF `trusted_root.json`,
// which is the authoritative, rotation-aware source of this key set). Our packages
// are all published to this active shard; older inactive shards carry their own
// keys (their public keys are NOT served by `/api/v1/log` and must come from
// `trusted_root.json`) — pinning those is a documented extension point, added here
// when a package that predates the active shard needs offline check #8.
export const REKOR_LOG_ANCHORS: readonly RekorLogAnchor[] = [
  {
    origin: 'rekor.sigstore.dev',
    logId: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
    publicKeyDer:
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    curve: 'p256',
  },
];

/** A Rekor inclusion proof, as carried in `verification.inclusionProof`. */
export interface RekorInclusionProof {
  /** The leaf index WITHIN the shard tree of size `treeSize` (NOT the global
   *  `logIndex` of the entry). This is the index RFC 6962 folds the path against. */
  logIndex: number;
  /** The tree size the proof (and checkpoint) are relative to. */
  treeSize: number;
  /** The Merkle root the proof folds to, hex. */
  rootHash: string;
  /** The audit path: sibling hashes from leaf to root, hex. */
  hashes: string[];
  /** The signed checkpoint (Go note) committing to `rootHash` at `treeSize`. */
  checkpoint: string;
}

/**
 * Parse the carried Rekor inclusion proof — the JSON string in
 * `verification.inclusionProof` (or the stored DB column) — into the structured proof
 * `verifyRekorInclusion` folds. Only a REAL proof is usable: it must carry an audit
 * path (`hashes`) AND a signed `checkpoint`. The empty `{}` some early packages carry,
 * any value missing those fields, and malformed JSON all resolve to null — inclusion
 * is then simply not verified, never thrown. This is the SINGLE guard the server
 * route, the browser verify-flow, and the backfill script share (#119 P4), so "what
 * counts as a real proof" is defined and tested in exactly one place.
 */
export function parseInclusionProof(
  raw: string | null | undefined,
): RekorInclusionProof | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      Array.isArray((parsed as RekorInclusionProof).hashes) &&
      typeof (parsed as RekorInclusionProof).checkpoint === 'string'
    ) {
      return parsed as RekorInclusionProof;
    }
  } catch {
    // malformed proof string ⇒ null
  }
  return null;
}

export type RekorInclusionFailReason =
  | 'leaf_index_out_of_range'
  | 'proof_wrong_length'
  | 'root_mismatch'
  | 'checkpoint_unparseable'
  | 'checkpoint_root_mismatch'
  | 'checkpoint_unknown_anchor'
  | 'checkpoint_signature_invalid';

export interface RekorInclusionResult {
  /** The entry body + audit path reproduce the proof's `rootHash` (RFC 6962). */
  inclusionVerified: boolean;
  /** The checkpoint commits to that same root/size AND its signature verifies
   *  against a pinned anchor — i.e. a vouched-for log head, offline. */
  checkpointVerified: boolean;
  treeSize?: number;
  leafIndex?: number;
  /** The checkpoint origin whose pinned key verified the signature. */
  origin?: string;
  /** The matched anchor's key hint (hex), for display / provenance. */
  keyHint?: string;
  /** The first thing that failed, when not fully verified. */
  reason?: RekorInclusionFailReason;
}

// --- RFC 6962 Merkle hashing ----------------------------------------------

/** Leaf hash: `SHA-256(0x00 ‖ leaf)` (RFC 6962 §2.1). */
function leafHash(leaf: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + leaf.length);
  buf[0] = 0x00;
  buf.set(leaf, 1);
  return sha256(buf);
}

/** Interior node hash: `SHA-256(0x01 ‖ left ‖ right)` (RFC 6962 §2.1). */
function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = 0x01;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Fold an inclusion path to a root per RFC 6962 §2.1.1, verbatim. Returns the
 * computed root, or `null` if the index is out of range or the path is the wrong
 * length for the tree. Arithmetic is Number `%`/`Math.floor` (NOT 32-bit bitwise)
 * so leaf indices and tree sizes above 2³¹ fold correctly.
 */
export function computeInclusionRoot(
  leafIndex: number,
  treeSize: number,
  leaf: Uint8Array,
  path: Uint8Array[],
): Uint8Array | null {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return null;
  if (leafIndex < 0 || leafIndex >= treeSize) return null;
  let fn = leafIndex; // node index of the running hash, within its tree level
  let sn = treeSize - 1; // index of the last node at that level
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return null; // path longer than the tree is deep — reject
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        // ascend past the all-right edge until the running node is a left child
        do {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        } while (fn % 2 === 0 && fn !== 0);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : null; // leftover path ⇒ wrong length
}

// --- Checkpoint (Go signed note) -------------------------------------------

interface CheckpointSignature {
  name: string;
  keyHint: Uint8Array; // 4 bytes
  sig: Uint8Array; // DER ECDSA
}

interface ParsedCheckpoint {
  origin: string;
  treeSize: number;
  rootHash: Uint8Array;
  /** The exact bytes the signature covers: the note body + its trailing newline.
   *  The blank-line separator before the signature lines is NOT signed (verified
   *  against OpenSSL). */
  signedBody: Uint8Array;
  signatures: CheckpointSignature[];
}

/**
 * Parse a Rekor checkpoint. Body = the lines before the first blank line:
 * `<origin>\n<treeSize>\n<base64 rootHash>\n`. Signature lines follow the blank
 * separator: `— <name> <base64(keyHint[4] ‖ DER-sig)>`. Returns `null` if the
 * structure is not a parseable note.
 */
export function parseRekorCheckpoint(text: string): ParsedCheckpoint | null {
  const sep = text.indexOf('\n\n');
  if (sep < 0) return null;
  const body = text.slice(0, sep);
  const lines = body.split('\n');
  if (lines.length < 3) return null;

  // line 0 is "<origin> - <treeId>"; the note signer name is the origin token.
  const origin = lines[0].split(' - ')[0];
  const treeSize = Number(lines[1]);
  if (!Number.isInteger(treeSize)) return null;

  let rootHash: Uint8Array;
  try {
    rootHash = base64ToBytes(lines[2]);
  } catch {
    return null;
  }
  if (rootHash.length !== 32) return null;

  const signatures: CheckpointSignature[] = [];
  for (const line of text.slice(sep + 2).split('\n')) {
    if (!line.startsWith('— ')) continue; // em-dash + space
    const parts = line.split(' ');
    if (parts.length < 3) continue;
    let blob: Uint8Array;
    try {
      blob = base64ToBytes(parts[parts.length - 1]);
    } catch {
      continue;
    }
    if (blob.length < 5) continue;
    signatures.push({
      name: parts.slice(1, -1).join(' '),
      keyHint: blob.slice(0, 4),
      sig: blob.slice(4),
    });
  }
  return { origin, treeSize, rootHash, signedBody: utf8ToBytes(body + '\n'), signatures };
}

// An ECDSA P-256 public key in SPKI DER is a fixed 91-byte structure: a 26-byte
// prefix (SEQUENCE → AlgorithmIdentifier{ id-ecPublicKey, prime256v1 } → BIT
// STRING) then the 65-byte uncompressed point (0x04 ‖ X ‖ Y). Asserting the prefix
// before slicing makes a malformed/foreign key throw rather than yield 65 arbitrary
// bytes.
const EC_P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);
const EC_P256_SPKI_LENGTH = 91;

function extractP256Point(publicKeyB64Der: string): Uint8Array {
  const der = base64ToBytes(publicKeyB64Der);
  if (der.length !== EC_P256_SPKI_LENGTH) {
    throw new Error(`Unexpected P-256 SPKI length ${der.length}; expected ${EC_P256_SPKI_LENGTH}`);
  }
  for (let i = 0; i < EC_P256_SPKI_PREFIX.length; i++) {
    if (der[i] !== EC_P256_SPKI_PREFIX[i]) {
      throw new Error('Unexpected P-256 SPKI prefix; not a bare prime256v1 public key');
    }
  }
  return der.slice(EC_P256_SPKI_LENGTH - 65);
}

/**
 * Verify a checkpoint's signature against the pinned anchors. The note signs the
 * SHA-256 of `signedBody`; the signature is DER ECDSA P-256. We select the anchor
 * by the note's key hint (= log-id prefix) and signer name. `@noble`'s `verify`
 * prehashes by default — we pass the message bytes and let it hash, equivalently
 * to `{ prehash: false }` over `sha256(signedBody)` (both validated against OpenSSL).
 */
export function verifyCheckpointSignature(
  checkpoint: ParsedCheckpoint,
  anchors: readonly RekorLogAnchor[],
): { verified: boolean; origin?: string; keyHint?: string } {
  for (const sig of checkpoint.signatures) {
    const hint = bytesToHex(sig.keyHint);
    const anchor = anchors.find((a) => a.logId.startsWith(hint) && a.origin === sig.name);
    if (!anchor) continue;
    try {
      const point = extractP256Point(anchor.publicKeyDer);
      // `lowS: false`: the log signer may emit a high-S checkpoint signature; low-S
      // is a signing-side malleability convention, not a verification rule, so a
      // verifier must accept both S and n−S (see the rfc3161.ts note — a real high-S
      // TSA token exposed this default). We only ask "did this log key sign this
      // checkpoint". (`@noble` prehashes with the curve hash by default, so the note
      // body is passed as the message.)
      if (p256.verify(sig.sig, checkpoint.signedBody, point, { format: 'der', lowS: false })) {
        return { verified: true, origin: anchor.origin, keyHint: hint };
      }
    } catch {
      // malformed anchor key or signature ⇒ this anchor doesn't verify; try next.
    }
  }
  return { verified: false };
}

/**
 * Verify Rekor log inclusion for an entry, OFFLINE. `entryBody` is the entry's
 * canonical leaf bytes — Rekor's base64 `body`, or the raw bytes. `inclusionProof`
 * is the carried `verification.inclusionProof`. Returns a graded verdict:
 * `inclusionVerified` (the proof folds to its root) and `checkpointVerified` (that
 * root is in a checkpoint a pinned log key signed). The strong property — "this
 * entry is in a log the sigstore key vouches for" — is both being true.
 */
export function verifyRekorInclusion(
  entryBody: string | Uint8Array,
  inclusionProof: RekorInclusionProof,
  anchors: readonly RekorLogAnchor[] = REKOR_LOG_ANCHORS,
): RekorInclusionResult {
  const base: RekorInclusionResult = {
    inclusionVerified: false,
    checkpointVerified: false,
    treeSize: inclusionProof.treeSize,
    leafIndex: inclusionProof.logIndex,
  };

  let body: Uint8Array;
  let proofRoot: Uint8Array;
  let path: Uint8Array[];
  try {
    body = typeof entryBody === 'string' ? base64ToBytes(entryBody) : entryBody;
    proofRoot = hexToBytes(inclusionProof.rootHash);
    path = inclusionProof.hashes.map((h) => hexToBytes(h));
  } catch {
    return { ...base, reason: 'proof_wrong_length' };
  }

  const computed = computeInclusionRoot(
    inclusionProof.logIndex,
    inclusionProof.treeSize,
    leafHash(body),
    path,
  );
  if (computed === null) {
    const inRange =
      inclusionProof.logIndex >= 0 && inclusionProof.logIndex < inclusionProof.treeSize;
    return { ...base, reason: inRange ? 'proof_wrong_length' : 'leaf_index_out_of_range' };
  }
  if (!bytesEqual(computed, proofRoot)) {
    return { ...base, reason: 'root_mismatch' };
  }
  base.inclusionVerified = true;

  const checkpoint = parseRekorCheckpoint(inclusionProof.checkpoint);
  if (!checkpoint) return { ...base, reason: 'checkpoint_unparseable' };
  if (!bytesEqual(checkpoint.rootHash, proofRoot) || checkpoint.treeSize !== inclusionProof.treeSize) {
    return { ...base, reason: 'checkpoint_root_mismatch' };
  }
  const sig = verifyCheckpointSignature(checkpoint, anchors);
  if (!sig.verified) {
    const knownAnchor = checkpoint.signatures.some((s) =>
      anchors.some((a) => a.logId.startsWith(bytesToHex(s.keyHint)) && a.origin === s.name),
    );
    return {
      ...base,
      reason: knownAnchor ? 'checkpoint_signature_invalid' : 'checkpoint_unknown_anchor',
    };
  }
  return {
    ...base,
    checkpointVerified: true,
    ...(sig.origin ? { origin: sig.origin } : {}),
    ...(sig.keyHint ? { keyHint: sig.keyHint } : {}),
  };
}
