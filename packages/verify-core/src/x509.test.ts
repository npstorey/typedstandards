// X.509 cert-parse tests (civic-ai-tools-website#119 P2b). Parses the real signing
// cert embedded in the freetsa.org token fixture, and asserts malformed input throws
// (the parser is built on the strict-DER reader whose adversarial cases live in
// asn1.test.ts; this confirms the cert layer surfaces those as throws, not mis-parses).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  readNode,
  children,
  parseCertificate,
  bytesEqual,
  OID_EKU_TIMESTAMPING,
  base64ToBytes,
  Asn1Error,
} from './index.ts';

const fx = JSON.parse(
  readFileSync(new URL('./__fixtures__/rfc3161-token.json', import.meta.url), 'utf8'),
) as { tokenB64: string };

/** Navigate the token to its embedded certificates. */
function tokenCertNodes() {
  const buf = base64ToBytes(fx.tokenB64);
  const ci = children(buf, children(buf, readNode(buf, 0))[1]);
  const sd = children(buf, children(buf, ci[1])[0]);
  const certsNode = sd.find((c) => c.tag === 0xa0)!;
  return { buf, nodes: children(buf, certsNode) };
}

test('parseCertificate: extracts the signing cert (EKU timestamping, validity, leaf)', () => {
  const { buf, nodes } = tokenCertNodes();
  const certs = nodes.map((n) => parseCertificate(buf, n));
  const leaf = certs.find((c) => c.ekus.includes(OID_EKU_TIMESTAMPING));
  assert.ok(leaf, 'a signing cert with EKU id-kp-timeStamping is present');
  assert.equal(leaf!.isCA, false, 'the leaf is not a CA');
  assert.ok(leaf!.notBefore < leaf!.notAfter, 'validity window is well-ordered');
  assert.equal(leaf!.spkiDer.length, 120, 'EC P-384 SPKI');

  // The root is self-signed (issuer == subject) and a CA.
  const root = certs.find((c) => bytesEqual(c.issuerDer, c.subjectDer));
  assert.ok(root, 'a self-signed root is present');
  assert.equal(root!.isCA, true);
});

test('parseCertificate: rejects a non-certificate / truncated structure', () => {
  // An INTEGER, not a Certificate SEQUENCE.
  const intNode = Uint8Array.from([0x02, 0x01, 0x07]);
  assert.throws(() => parseCertificate(intNode, readNode(intNode, 0)), Asn1Error);
  // A SEQUENCE too short to be a TBSCertificate + algorithm + signature.
  const shortSeq = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);
  assert.throws(() => parseCertificate(shortSeq, readNode(shortSeq, 0)), Asn1Error);
});
