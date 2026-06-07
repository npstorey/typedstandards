// Adversarial + happy-path tests for the DER reader (civic-ai-tools-website#119 P2a).
//
// A hand-rolled parser over attacker-supplied bytes IS an attack surface, so the
// adversarial cases are a hard acceptance criterion: truncation, indefinite/
// over-long/non-minimal lengths, length overflow, trailing garbage, and child
// overrun must all THROW (never read out of bounds, never loop).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readNode,
  children,
  oidToString,
  readTime,
  rawTlv,
  content,
  Asn1Error,
} from './index.ts';

const bytes = (...b: number[]) => Uint8Array.from(b);

// --- Adversarial ----------------------------------------------------------

test('rejects truncated TLVs', () => {
  assert.throws(() => readNode(bytes(), 0), Asn1Error); // empty
  assert.throws(() => readNode(bytes(0x30), 0), Asn1Error); // tag, no length
  assert.throws(() => readNode(bytes(0x04, 0x05, 0x01, 0x02), 0), Asn1Error); // len 5 > 2 bytes
});

test('rejects indefinite length (BER, not DER)', () => {
  assert.throws(() => readNode(bytes(0x30, 0x80, 0x00, 0x00), 0), /indefinite/);
});

test('rejects non-minimal length encodings', () => {
  // 0x81 0x05 should have been the short form 0x05.
  assert.throws(() => readNode(bytes(0x04, 0x81, 0x05, 1, 2, 3, 4, 5), 0), /non-minimal/);
  // leading zero in a long-form length.
  assert.throws(() => readNode(bytes(0x04, 0x82, 0x00, 0x01, 0xaa), 0), /non-minimal/);
});

test('rejects an over-long length-of-length (overflow guard)', () => {
  assert.throws(() => readNode(bytes(0x04, 0x85, 1, 1, 1, 1, 1), 0), /too large/);
});

test('rejects high-tag-number form', () => {
  assert.throws(() => readNode(bytes(0x1f, 0x01, 0x00), 0), /high-tag-number/);
});

test('children() rejects trailing garbage and child overrun', () => {
  // SEQUENCE len 3 wrapping a 2-byte INTEGER, then 1 stray byte ⇒ trailing garbage.
  assert.throws(() => children(bytes(0x02, 0x01, 0x01, 0xff), {
    tag: 0x30, constructed: true, start: 0, contentStart: 0, contentEnd: 4, end: 4,
  }), Asn1Error);
  // A child whose length claims to exceed the parent.
  const buf = bytes(0x30, 0x03, 0x04, 0x05, 0x01); // inner OCTET claims len 5, parent has 3
  assert.throws(() => children(buf, readNode(buf, 0)), Asn1Error);
});

test('children() rejects a primitive node', () => {
  const buf = bytes(0x02, 0x01, 0x07); // INTEGER 7 (primitive)
  assert.throws(() => children(buf, readNode(buf, 0)), /primitive/);
});

// --- Happy path -----------------------------------------------------------

test('parses a SEQUENCE { INTEGER, OID } and slices children', () => {
  // SEQ { INTEGER 1, OID sha256 (2.16.840.1.101.3.4.2.1) }
  const oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
  const seq = bytes(0x30, 3 + oid.length, 0x02, 0x01, 0x01, ...oid);
  const kids = children(seq, readNode(seq, 0));
  assert.equal(kids.length, 2);
  assert.equal(kids[0].tag, 0x02);
  assert.equal(content(seq, kids[0])[0], 1);
  assert.equal(oidToString(seq, kids[1]), '2.16.840.1.101.3.4.2.1');
});

test('oidToString decodes multi-byte arcs and the 2.x first arc', () => {
  // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
  const o = bytes(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b);
  assert.equal(oidToString(o, readNode(o, 0)), '1.2.840.113549.1.1.11');
});

test('readTime parses GeneralizedTime and UTCTime to UTC epoch ms', () => {
  const gt = bytes(0x18, 15, ...[...'20260607154934Z'].map((c) => c.charCodeAt(0)));
  assert.equal(readTime(gt, readNode(gt, 0)), Date.UTC(2026, 5, 7, 15, 49, 34));
  const ut = bytes(0x17, 13, ...[...'260607154934Z'].map((c) => c.charCodeAt(0)));
  assert.equal(readTime(ut, readNode(ut, 0)), Date.UTC(2026, 5, 7, 15, 49, 34));
  // non-UTC / malformed forms are rejected.
  const bad = bytes(0x18, 11, ...[...'2026060715Z'].map((c) => c.charCodeAt(0)));
  assert.throws(() => readTime(bad, readNode(bad, 0)), Asn1Error);
});

test('rawTlv returns the whole TLV including header', () => {
  const buf = bytes(0x02, 0x01, 0x07);
  assert.deepEqual(Array.from(rawTlv(buf, readNode(buf, 0))), [0x02, 0x01, 0x07]);
});
