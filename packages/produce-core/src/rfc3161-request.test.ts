// RFC 3161 TimeStampReq builder tests: a byte-exact reference vector (the
// Buffer-based reference construction, reproduced here in the test where
// node:crypto/Buffer are allowed) plus a structural decode using verify-core's
// strict ASN.1 reader — the same parser that later reads the TSA's token.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  children,
  content,
  expectTag,
  oidToString,
  readNode,
} from '@typedstandards/verify-core';
import { buildTimestampRequest } from './rfc3161-request.ts';

const SAMPLE_HASH =
  'acdb56712cc0e735589e39d485dcd2c3d34a611b6752ab2f8b703e13008a3004';

// --- Reference construction (Buffer-based, as the original producer built it) ---

const SHA256_OID = Buffer.from([
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
]);

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  if (length < 0x100) return Buffer.from([0x81, length]);
  return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
}

function derSequence(...items: Buffer[]): Buffer {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}

function derOctetString(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x04]), derLength(data.length), data]);
}

function referenceTimestampRequest(hashHex: string): Buffer {
  const hashBytes = Buffer.from(hashHex, 'hex');
  const algId = derSequence(SHA256_OID);
  const messageImprint = derSequence(algId, derOctetString(hashBytes));
  return derSequence(
    Buffer.from([0x02, 0x01, 1]), // INTEGER version=1
    messageImprint,
    Buffer.from([0x01, 0x01, 0xff]), // BOOLEAN certReq=true
  );
}

test('buildTimestampRequest: byte-identical to the reference construction', () => {
  const built = buildTimestampRequest(SAMPLE_HASH);
  const reference = referenceTimestampRequest(SAMPLE_HASH);
  assert.equal(Buffer.from(built).toString('hex'), reference.toString('hex'));
});

test('buildTimestampRequest: deterministic', () => {
  const a = buildTimestampRequest(SAMPLE_HASH);
  const b = buildTimestampRequest(SAMPLE_HASH);
  assert.deepEqual(a, b);
});

test('buildTimestampRequest: structurally valid DER (verify-core ASN.1 reader round-trip)', () => {
  const der = buildTimestampRequest(SAMPLE_HASH);
  const root = expectTag(readNode(der, 0), 0x30, 'TimeStampReq');
  assert.equal(root.end, der.length, 'no trailing bytes');

  const [version, messageImprint, certReq] = children(der, root);
  assert.equal(version.tag, 0x02);
  assert.deepEqual(Array.from(content(der, version)), [1]);

  const mi = expectTag(messageImprint, 0x30, 'MessageImprint');
  const [algId, hashOctets] = children(der, mi);
  const oid = children(der, expectTag(algId, 0x30, 'AlgorithmIdentifier'))[0];
  assert.equal(oidToString(der, oid), '2.16.840.1.101.3.4.2.1'); // SHA-256
  assert.equal(
    Buffer.from(content(der, expectTag(hashOctets, 0x04, 'hashedMessage'))).toString('hex'),
    SAMPLE_HASH,
  );

  assert.equal(certReq.tag, 0x01);
  assert.deepEqual(Array.from(content(der, certReq)), [0xff]); // certReq=true
});

test('buildTimestampRequest: rejects a non-SHA-256-length imprint', () => {
  assert.throws(() => buildTimestampRequest('abcd'), /32 bytes/);
  assert.throws(() => buildTimestampRequest(SAMPLE_HASH + 'ff'), /32 bytes/);
});
