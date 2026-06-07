// Tests for Rekor Merkle-inclusion verification (civic-ai-tools-website#119 P1).
//
// The fixture (`__fixtures__/rekor-inclusion.json`) is a REAL `hashedrekord` entry
// from `rekor.sigstore.dev` (public transparency-log data), captured with its
// inclusion proof + signed checkpoint. The clean case proves the entry verifies
// fully OFFLINE against the pinned anchor — no network, the property #119 is about.
// The negative cases prove a tampered proof, a tampered leaf, a forged checkpoint
// signature, and an unrecognized anchor all fail (closed, not silently passed).
//
// Run with: npm test  (Node 22)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  verifyRekorInclusion,
  computeInclusionRoot,
  parseRekorCheckpoint,
  parseInclusionProof,
  REKOR_LOG_ANCHORS,
  type RekorInclusionProof,
} from './index.ts';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const bytesToHex = (u: Uint8Array) => Buffer.from(u).toString('hex');
/** Independent (node:crypto) RFC 6962 leaf hash, to check the fold primitive. */
function leafHashIndependently(bodyB64: string): Uint8Array {
  const body = Buffer.from(bodyB64, 'base64');
  return new Uint8Array(createHash('sha256').update(Buffer.concat([Buffer.from([0]), body])).digest());
}

interface Fixture {
  body: string;
  inclusionProof: RekorInclusionProof;
}

const fixture: Fixture = JSON.parse(
  readFileSync(new URL('./__fixtures__/rekor-inclusion.json', import.meta.url), 'utf8'),
);

/** Deep-clone the proof so each negative test mutates an isolated copy. */
function freshProof(): RekorInclusionProof {
  return JSON.parse(JSON.stringify(fixture.inclusionProof));
}

function flipHexNibble(hex: string, at = 0): string {
  const c = hex[at];
  const flipped = c === '0' ? '1' : '0';
  return hex.slice(0, at) + flipped + hex.slice(at + 1);
}

// --- Clean case (the offline property) ------------------------------------

test('verifyRekorInclusion: a real entry verifies fully OFFLINE against the pinned anchor', () => {
  const r = verifyRekorInclusion(fixture.body, fixture.inclusionProof);
  assert.equal(r.inclusionVerified, true, 'RFC 6962 path should fold to the proof root');
  assert.equal(r.checkpointVerified, true, 'checkpoint sig should verify against the pinned key');
  assert.equal(r.origin, 'rekor.sigstore.dev');
  assert.equal(r.keyHint, REKOR_LOG_ANCHORS[0].logId.slice(0, 8));
  assert.equal(r.reason, undefined);
});

test('computeInclusionRoot: folds an independently-hashed leaf to the published root', () => {
  const proof = fixture.inclusionProof;
  const leaf = leafHashIndependently(fixture.body);
  const root = computeInclusionRoot(
    proof.logIndex,
    proof.treeSize,
    leaf,
    proof.hashes.map(hexToBytes),
  );
  assert.ok(root, 'fold should succeed');
  assert.equal(bytesToHex(root!), proof.rootHash);

  // An empty path can only fold a single-leaf tree; this tree is large ⇒ null.
  assert.equal(computeInclusionRoot(proof.logIndex, proof.treeSize, leaf, []), null);
  // Out-of-range index ⇒ null.
  assert.equal(computeInclusionRoot(proof.treeSize, proof.treeSize, leaf, []), null);
});

// --- Inclusion-proof tampering --------------------------------------------

test('a tampered ENTRY BODY breaks inclusion (leaf no longer hashes into the tree)', () => {
  const tampered = 'A' + fixture.body.slice(1); // mutate the first base64 char
  const r = verifyRekorInclusion(tampered, fixture.inclusionProof);
  assert.equal(r.inclusionVerified, false);
  assert.equal(r.reason, 'root_mismatch');
});

test('a tampered SIBLING HASH breaks inclusion', () => {
  const proof = freshProof();
  proof.hashes[0] = flipHexNibble(proof.hashes[0]);
  const r = verifyRekorInclusion(fixture.body, proof);
  assert.equal(r.inclusionVerified, false);
  assert.equal(r.reason, 'root_mismatch');
});

test('a tampered ROOT HASH breaks inclusion', () => {
  const proof = freshProof();
  proof.rootHash = flipHexNibble(proof.rootHash);
  const r = verifyRekorInclusion(fixture.body, proof);
  assert.equal(r.inclusionVerified, false);
  assert.equal(r.reason, 'root_mismatch');
});

test('a wrong LEAF INDEX fails (out of range and in range)', () => {
  const oob = freshProof();
  oob.logIndex = oob.treeSize; // == size ⇒ out of range
  assert.equal(verifyRekorInclusion(fixture.body, oob).reason, 'leaf_index_out_of_range');

  const wrong = freshProof();
  wrong.logIndex = wrong.logIndex === 0 ? 1 : wrong.logIndex - 1; // in range, wrong
  assert.equal(verifyRekorInclusion(fixture.body, wrong).inclusionVerified, false);
});

test('a wrong TREE SIZE is caught by the signed checkpoint binding', () => {
  const proof = freshProof();
  proof.treeSize = proof.treeSize + 1;
  const r = verifyRekorInclusion(fixture.body, proof);
  // The audit path may still fold to the old root (a ±1 size change need not alter
  // this leaf's path), so inclusion alone can be fooled — but the SIGNED checkpoint
  // pins the true tree size, so a size lie cannot pass the checkpoint binding.
  assert.equal(r.checkpointVerified, false);
  assert.equal(r.reason, 'checkpoint_root_mismatch');
});

// --- Checkpoint tampering --------------------------------------------------

test('a forged CHECKPOINT SIGNATURE fails the checkpoint (inclusion still holds)', () => {
  const proof = freshProof();
  const ck = proof.checkpoint;
  const sigStart = ck.indexOf('\n— ') + 1;
  const sigLine = ck.slice(sigStart).split('\n')[0];
  const tokens = sigLine.split(' ');
  const blob = Buffer.from(tokens[tokens.length - 1], 'base64');
  blob[10] ^= 0xff; // flip a byte inside the signature (past the 4-byte key hint)
  tokens[tokens.length - 1] = blob.toString('base64');
  proof.checkpoint = ck.slice(0, sigStart) + tokens.join(' ') + ck.slice(sigStart + sigLine.length);

  const r = verifyRekorInclusion(fixture.body, proof);
  assert.equal(r.inclusionVerified, true, 'the proof itself is untouched');
  assert.equal(r.checkpointVerified, false);
  assert.equal(r.reason, 'checkpoint_signature_invalid');
});

test('a checkpoint whose ROOT disagrees with the proof fails before the signature', () => {
  const proof = freshProof();
  // Re-point the proof root to a different (also-valid-length) value: inclusion
  // breaks first, but force the checkpoint-mismatch branch by tampering inclusion
  // to pass against the new root is impossible — instead tamper the checkpoint's
  // root line so it no longer matches the (valid) proof root.
  const ck = proof.checkpoint;
  const lines = ck.split('\n');
  const orig = lines[2];
  const b = Buffer.from(orig, 'base64');
  b[0] ^= 0xff;
  lines[2] = b.toString('base64');
  proof.checkpoint = lines.join('\n');

  const r = verifyRekorInclusion(fixture.body, proof);
  assert.equal(r.inclusionVerified, true);
  assert.equal(r.checkpointVerified, false);
  assert.equal(r.reason, 'checkpoint_root_mismatch');
});

test('an UNRECOGNIZED anchor set fails the checkpoint (no silent pass)', () => {
  const r = verifyRekorInclusion(fixture.body, fixture.inclusionProof, []);
  assert.equal(r.inclusionVerified, true);
  assert.equal(r.checkpointVerified, false);
  assert.equal(r.reason, 'checkpoint_unknown_anchor');
});

test('parseRekorCheckpoint: extracts origin, size, 32-byte root, and a key hint', () => {
  const c = parseRekorCheckpoint(fixture.inclusionProof.checkpoint);
  assert.ok(c, 'checkpoint should parse');
  assert.equal(c!.origin, 'rekor.sigstore.dev');
  assert.equal(c!.treeSize, fixture.inclusionProof.treeSize);
  assert.equal(c!.rootHash.length, 32);
  assert.ok(c!.signatures.length >= 1);
  assert.equal(c!.signatures[0].keyHint.length, 4);
  // Garbage in ⇒ null, not a throw.
  assert.equal(parseRekorCheckpoint('not a checkpoint'), null);
});

// --- Shared parseInclusionProof guard (#119 P4) ----------------------------

test('parseInclusionProof: accepts a real serialized proof, rejects the non-proofs', () => {
  // A real proof (audit path + signed checkpoint) round-trips through JSON.
  const real = JSON.stringify(fixture.inclusionProof);
  const parsed = parseInclusionProof(real);
  assert.ok(parsed, 'a real proof parses');
  assert.deepEqual(parsed!.hashes, fixture.inclusionProof.hashes);
  assert.equal(parsed!.checkpoint, fixture.inclusionProof.checkpoint);

  // The values the three consumers must all treat as "no usable proof":
  assert.equal(parseInclusionProof(null), null, 'null ⇒ null');
  assert.equal(parseInclusionProof(undefined), null, 'undefined ⇒ null');
  assert.equal(parseInclusionProof(''), null, 'empty string ⇒ null');
  assert.equal(parseInclusionProof('{}'), null, 'the empty {} early packages carry ⇒ null');
  assert.equal(parseInclusionProof('not json'), null, 'malformed JSON ⇒ null (never throws)');
  assert.equal(parseInclusionProof('"5"'), null, 'a JSON primitive ⇒ null');
  assert.equal(parseInclusionProof('null'), null, 'JSON null ⇒ null');
  // Missing the checkpoint, or hashes not an array, are partial/unusable ⇒ null.
  assert.equal(parseInclusionProof(JSON.stringify({ hashes: ['ab'] })), null, 'no checkpoint ⇒ null');
  assert.equal(
    parseInclusionProof(JSON.stringify({ hashes: 'ab', checkpoint: 'x' })),
    null,
    'hashes not an array ⇒ null',
  );
});
