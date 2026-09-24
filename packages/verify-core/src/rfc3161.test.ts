// RFC 3161 TSA verification tests (civic-ai-tools-website#119 P2a + P2b).
//
// Fixtures are REAL freetsa.org tokens with their embedded EC P-384 signing cert +
// RSA-4096 root: `rfc3161-token.json` (low-S) and `rfc3161-token-highs.json` (the
// prod da9246 high-S token). The clean case proves a token verifies fully OFFLINE —
// the signing cert chains to the PINNED FreeTSA root, EKU + validity come from the
// cert, and the TSA ECDSA-P384 signature verifies under the chain-derived key. The
// negatives prove wrong hash, forged signature, an untrusted root, and garbage all
// fail closed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyRfc3161Timestamp } from './index.ts';
import { generateKeyPairSync } from 'node:crypto';
import { readNode, children, parseCertificate, OID_EKU_TIMESTAMPING, type TsaRootAnchor } from './index.ts';

const load = (f: string) =>
  JSON.parse(readFileSync(new URL(`./__fixtures__/${f}`, import.meta.url), 'utf8')) as {
    tokenB64: string;
    expectedHashHex: string;
  };
const fx = load('rfc3161-token.json');
const highS = load('rfc3161-token-highs.json');

test('verifyRfc3161Timestamp: a real token verifies fully OFFLINE (chain to pinned root)', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex);
  assert.equal(r.verified, true);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, true, 'embedded signing cert must chain to the pinned root');
  assert.equal(r.ekuTimestamping, true);
  assert.equal(r.withinValidity, true);
  assert.equal(r.signatureValid, true);
  assert.equal(r.tsa, 'freetsa.org');
  assert.equal(r.reason, undefined);
});

test('a real HIGH-S TSA signature verifies (lowS:false — regression for da9246)', async () => {
  const r = await verifyRfc3161Timestamp(highS.tokenB64, highS.expectedHashHex);
  assert.equal(r.signatureValid, true, 'a high-S TSA signature must verify');
  assert.equal(r.chainVerified, true);
  assert.equal(r.verified, true);
});

test('a token over a DIFFERENT hash fails the message imprint', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, 'f'.repeat(64));
  assert.equal(r.verified, false);
  assert.equal(r.imprintMatches, false);
  assert.equal(r.reason, 'imprint_mismatch');
});

test('a FORGED TSA signature fails closed (chain + binding still hold)', async () => {
  const raw = Buffer.from(fx.tokenB64, 'base64');
  raw[raw.length - 1] ^= 0xff; // flip a byte inside the trailing ECDSA signature
  const r = await verifyRfc3161Timestamp(raw.toString('base64'), fx.expectedHashHex);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, true);
  assert.equal(r.signatureValid, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'signature_invalid');
});

test('a chain that does not reach a PINNED root fails (untrusted_root)', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, []);
  assert.equal(r.chainVerified, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'untrusted_root');
  // imprint + binding still computed before the chain step.
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
});

test('garbage input reports parse_error, never throws', async () => {
  const r = await verifyRfc3161Timestamp('bm90LWEtdG9rZW4=', fx.expectedHashHex);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'parse_error');
});

// --- Signature evaluated whatever the chain reads (typedstandards#94, ruling D1; sprint #98 P1b) ---
//
// A token BOUND to this package (imprint and messageDigest binding pass) whose chain does not
// reach a pinned anchor: before P1b, verifyRfc3161Timestamp returned at the chain step and never
// evaluated the TSA signature, so a broken signature and a genuine one from an unpinned authority
// both read `signatureValid: null`. Every token below is derived at test time from the real
// FreeTSA fixture `rfc3161-token.json`; nothing new is committed as a fixture.
//
// The unpinned chain is driven two ways: `anchors = []`, and a non-empty pinned set holding
// only a key minted here (so the token's root is simply not among the anchors). Both are
// equivalent for the signature step: the anchors are read only by the chain walk, at its
// self-signed terminus, and the TSA signature is checked under the embedded timestamping
// leaf's own key, which the token carries whatever the anchor set holds.

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const tokenBytes = (tokenB64: string): Uint8Array => new Uint8Array(Buffer.from(tokenB64, 'base64'));

/** TimeStampResp -> ContentInfo -> SignedData's children. */
function signedDataKids(buf: Uint8Array) {
  const ci = children(buf, children(buf, readNode(buf, 0))[1]);
  return children(buf, children(buf, ci[1])[0]);
}

/** The same token with the last byte flipped: a byte inside the trailing ECDSA signature,
 *  as the FORGED test above does. */
function withForgedSignature(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  raw[raw.length - 1] ^= 0xff;
  return b64(raw);
}

/** The same token with the timestamping leaf's notBefore rewritten (UTCTime, same length).
 *  The TSA signature covers signedAttrs, not the embedded certificates, so it still verifies;
 *  the leaf's TBS changes, so the root's signature over the leaf no longer does. */
function withLeafNotBefore(tokenB64: string, utcTime: string): string {
  const raw = tokenBytes(tokenB64);
  const certsNode = signedDataKids(raw).find((c) => c.tag === 0xa0)!;
  const leafNode = children(raw, certsNode).find((n) =>
    parseCertificate(raw, n).ekus.includes(OID_EKU_TIMESTAMPING),
  )!;
  const tbs = children(raw, children(raw, leafNode)[0]);
  const validity = tbs.find((k) => {
    if (k.tag !== 0x30) return false;
    const kk = children(raw, k);
    return kk.length === 2 && kk[0].tag === 0x17 && kk[1].tag === 0x17;
  })!;
  const notBefore = children(raw, validity)[0];
  assert.equal(notBefore.contentEnd - notBefore.contentStart, utcTime.length);
  raw.set(Uint8Array.from(utcTime, (c) => c.charCodeAt(0)), notBefore.contentStart);
  return b64(raw);
}

/** The same token with the SignerInfo's signatureAlgorithm moved from ecdsa-with-SHA512
 *  (1.2.840.10045.4.3.4) to ecdsa-with-SHA384 (…4.3.3): outside the set this verifier checks. */
function withSignatureAlgorithmSha384(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const signerInfos = signedDataKids(raw).filter((c) => c.tag === 0x31).pop()!;
  const si = children(raw, children(raw, signerInfos)[0]);
  const signedAttrs = si.find((c) => c.tag === 0xa0)!;
  const sigAlg = si.find((c) => c.tag === 0x30 && c.start >= signedAttrs.end)!;
  const oid = children(raw, sigAlg)[0];
  assert.equal(raw[oid.contentEnd - 1], 0x04);
  raw[oid.contentEnd - 1] = 0x03;
  return b64(raw);
}

/** A non-empty pinned set that does not hold the token's root: one RSA key minted here. */
const unrelatedAnchors: readonly TsaRootAnchor[] = [
  {
    name: 'unrelated-root',
    rootKeyDer: b64(
      new Uint8Array(
        generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }),
      ),
    ),
  },
];

const forged = withForgedSignature(fx.tokenB64);

test('P1b: bound token, chain reaches no pinned anchor (anchors = []), GENUINE TSA signature -> signatureValid true, reason untrusted_root', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, []);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, false);
  assert.equal(r.signatureValid, true, 'the signature is evaluated although the chain failed');
  assert.equal(r.withinValidity, true);
  assert.equal(r.verified, false, 'verified still needs a chain to a pinned anchor');
  assert.equal(r.reason, 'untrusted_root', 'the chain is the only fault');
  assert.equal(r.tsa, undefined);
});

test('P1b: bound token, chain reaches no pinned anchor (anchors = []), BROKEN TSA signature -> signatureValid false, reason signature_invalid', async () => {
  const r = await verifyRfc3161Timestamp(forged, fx.expectedHashHex, []);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.chainVerified, false);
  assert.equal(r.signatureValid, false, 'a broken signature is reported as broken, not left unevaluated');
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'signature_invalid', "the token's own fault outranks the chain fault");
});

test('P1b: the genuine and the broken token are told apart against a non-empty pinned set that omits their root', async () => {
  const genuine = await verifyRfc3161Timestamp(fx.tokenB64, fx.expectedHashHex, unrelatedAnchors);
  const broken = await verifyRfc3161Timestamp(forged, fx.expectedHashHex, unrelatedAnchors);
  for (const r of [genuine, broken]) {
    assert.equal(r.imprintMatches, true);
    assert.equal(r.contentBound, true);
    assert.equal(r.chainVerified, false);
    assert.equal(r.verified, false);
  }
  assert.equal(genuine.signatureValid, true);
  assert.equal(genuine.reason, 'untrusted_root');
  assert.equal(broken.signatureValid, false);
  assert.equal(broken.reason, 'signature_invalid');
});

test('P1b: bound token whose chain fails on a LINK signature (leaf TBS altered), GENUINE TSA signature -> signatureValid true, reason chain_signature_invalid', async () => {
  // One second earlier than the real notBefore: validity still covers genTime, but the root's
  // signature over the leaf no longer verifies.
  const relinked = withLeafNotBefore(fx.tokenB64, '260215194421Z');
  const r = await verifyRfc3161Timestamp(relinked, fx.expectedHashHex);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.withinValidity, true);
  assert.equal(r.chainVerified, false);
  assert.equal(r.signatureValid, true);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'chain_signature_invalid');
});

test('P1b (pin): genTime outside the leaf validity with an unpinned chain reads withinValidity false, genTime_outside_validity', async () => {
  // notBefore moved to 2027-01-01, after the token's genTime (2026-06-07).
  const early = withLeafNotBefore(fx.tokenB64, '270101000000Z');
  for (const anchors of [[], unrelatedAnchors, undefined]) {
    const r = await verifyRfc3161Timestamp(early, fx.expectedHashHex, anchors);
    assert.equal(r.imprintMatches, true);
    assert.equal(r.contentBound, true);
    assert.equal(r.withinValidity, false);
    assert.equal(r.chainVerified, false);
    assert.equal(r.verified, false);
    assert.equal(r.reason, 'genTime_outside_validity');
  }
});

test('P1b (pin): unexpected_algorithm and parse_error return before any signature is evaluated, pinned or not', async () => {
  const sha384 = withSignatureAlgorithmSha384(fx.tokenB64);
  for (const anchors of [undefined, []]) {
    const r = await verifyRfc3161Timestamp(sha384, fx.expectedHashHex, anchors);
    assert.equal(r.reason, 'unexpected_algorithm');
    assert.equal(r.signatureValid, null);
    assert.equal(r.chainVerified, null);
    assert.equal(r.imprintMatches, true, 'the imprint is compared before the SignerInfo algorithms');
    assert.equal(r.verified, false);
    const garbage = await verifyRfc3161Timestamp('bm90LWEtdG9rZW4=', fx.expectedHashHex, anchors);
    assert.equal(garbage.reason, 'parse_error');
    assert.equal(garbage.signatureValid, null);
    assert.equal(garbage.chainVerified, null);
  }
});

test('P1b (pin): a token lifted from another package fails on its imprint before the chain or the signature (anchors = [])', async () => {
  const r = await verifyRfc3161Timestamp(fx.tokenB64, 'f'.repeat(64), []);
  assert.equal(r.reason, 'imprint_mismatch');
  assert.equal(r.imprintMatches, false);
  assert.equal(r.contentBound, null);
  assert.equal(r.chainVerified, null);
  assert.equal(r.signatureValid, null);
  assert.equal(r.verified, false);
});

/** The same token with the timestamping leaf's namedCurve OID moved from secp384r1
 *  (1.3.132.0.34) to secp521r1 (1.3.132.0.35): a leaf key outside the set this verifier
 *  checks. The leaf's TBS changes, so its link signature no longer verifies either. */
function withLeafCurveSecp521r1(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const certsNode = signedDataKids(raw).find((c) => c.tag === 0xa0)!;
  const leaf = children(raw, certsNode)
    .map((n) => parseCertificate(raw, n))
    .find((c) => c.ekus.includes(OID_EKU_TIMESTAMPING))!;
  const spki = leaf.spkiDer;
  let at = -1;
  for (let i = 0; i + spki.length <= raw.length && at < 0; i++) {
    if (spki.every((b, k) => raw[i + k] === b)) at = i;
  }
  assert.ok(at >= 0, 'the leaf SPKI is found in the token');
  // SEQ { SEQ { OID ecPublicKey, OID namedCurve }, BIT STRING }: the curve OID's last
  // content byte is at offset 19 of the 23-byte P-384 SPKI prefix.
  assert.deepEqual([...raw.slice(at + 13, at + 20)], [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
  raw[at + 19] = 0x23;
  return b64(raw);
}

test('P1b: bound token, leaf key on a curve other than P-384 (secp521r1 OID), chain unpinned -> unexpected_algorithm, signatureValid null', async () => {
  const otherCurve = withLeafCurveSecp521r1(fx.tokenB64);
  for (const anchors of [[], undefined]) {
    const r = await verifyRfc3161Timestamp(otherCurve, fx.expectedHashHex, anchors);
    assert.equal(r.imprintMatches, true);
    assert.equal(r.contentBound, true);
    assert.equal(r.ekuTimestamping, true);
    assert.equal(r.withinValidity, true);
    assert.equal(r.chainVerified, false);
    assert.equal(r.signatureValid, null, 'a key this verifier cannot evaluate is not an invalid signature');
    assert.equal(r.verified, false);
    assert.equal(r.reason, 'unexpected_algorithm');
  }
});

// --- Classifiable by the code alone (sprint #98 P1b, second fix) ---
//
// A lapsed intermediate or root is a chain fault with its own code, `chain_outside_validity`;
// `genTime_outside_validity` names only the signing cert. And the message imprint is compared
// before the SignerInfo algorithms are checked, so a token that does not bind this package's
// hash reads `imprint_mismatch` whatever algorithms it uses.

/** The same token with the embedded ROOT's notAfter rewritten (UTCTime, same length). Neither
 *  the TSA signature (over signedAttrs) nor the leaf's link signature (over the leaf's TBS)
 *  covers the root's TBS, and the chain walk does not check the terminus's self-signature. */
function withRootNotAfter(tokenB64: string, utcTime: string): string {
  const raw = tokenBytes(tokenB64);
  const certsNode = signedDataKids(raw).find((c) => c.tag === 0xa0)!;
  const rootNode = children(raw, certsNode).find((n) => {
    const c = parseCertificate(raw, n);
    return c.issuerDer.length === c.subjectDer.length && c.issuerDer.every((b, i) => b === c.subjectDer[i]);
  })!;
  const tbs = children(raw, children(raw, rootNode)[0]);
  const validity = tbs.find((k) => {
    if (k.tag !== 0x30) return false;
    const kk = children(raw, k);
    return kk.length === 2 && kk[0].tag === 0x17 && kk[1].tag === 0x17;
  })!;
  const notAfter = children(raw, validity)[1];
  assert.equal(notAfter.contentEnd - notAfter.contentStart, utcTime.length);
  raw.set(Uint8Array.from(utcTime, (c) => c.charCodeAt(0)), notAfter.contentStart);
  return b64(raw);
}

/** The same token with the TSTInfo messageImprint hash algorithm moved from SHA-256
 *  (2.16.840.1.101.3.4.2.1) to SHA-384 (…2.2). The TSTInfo changes, so the messageDigest
 *  binding no longer holds either. */
function withImprintAlgorithmSha384(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const encap = signedDataKids(raw).find((c) => c.tag === 0x30)!;
  const tstOctet = children(raw, children(raw, encap)[1])[0];
  const tstInfo = readNode(raw, tstOctet.contentStart);
  const messageImprint = children(raw, tstInfo)[2];
  const oid = children(raw, children(raw, messageImprint)[0])[0];
  assert.equal(raw[oid.contentEnd - 1], 0x01);
  raw[oid.contentEnd - 1] = 0x02;
  return b64(raw);
}

test('P1b: leaf valid at genTime, embedded ROOT lapsed before it, genuine TSA signature -> chain_outside_validity', async () => {
  // Root notAfter moved to 2026-01-01, before the token's genTime (2026-06-07); the leaf is
  // valid 2026-02-15 .. 2040-02-02.
  const lapsedRoot = withRootNotAfter(fx.tokenB64, '260101000000Z');
  for (const anchors of [undefined, []]) {
    const r = await verifyRfc3161Timestamp(lapsedRoot, fx.expectedHashHex, anchors);
    assert.equal(r.imprintMatches, true);
    assert.equal(r.contentBound, true);
    assert.equal(r.withinValidity, true, 'the signing cert is valid at genTime');
    assert.equal(r.signatureValid, true, 'the TSA signature is genuine');
    assert.equal(r.chainVerified, false);
    assert.equal(r.verified, false);
    assert.equal(r.reason, 'chain_outside_validity', 'a lapsed root is a chain fault, not the token’s');
  }
});

test('P1b: a token that does not bind this package fails on its imprint whatever its SignerInfo algorithms', async () => {
  const sha384 = withSignatureAlgorithmSha384(fx.tokenB64);
  // A foreign hash under an algorithm outside the checked set.
  const foreign = await verifyRfc3161Timestamp(sha384, 'f'.repeat(64));
  assert.equal(foreign.reason, 'imprint_mismatch');
  assert.equal(foreign.imprintMatches, false);
  assert.equal(foreign.contentBound, null);
  assert.equal(foreign.signatureValid, null);
  assert.equal(foreign.verified, false);
  // A TSTInfo imprint that is not SHA-256 reads imprint_mismatch, with the SignerInfo
  // algorithms checked or not.
  const imprint384 = withImprintAlgorithmSha384(fx.tokenB64);
  for (const token of [imprint384, withSignatureAlgorithmSha384(imprint384)]) {
    const r = await verifyRfc3161Timestamp(token, fx.expectedHashHex);
    assert.equal(r.reason, 'imprint_mismatch');
    assert.equal(r.imprintMatches, false);
    assert.equal(r.signatureValid, null);
  }
});

/** The same token with the timestamping leaf's signature algorithm, inner and outer, moved
 *  from sha512WithRSAEncryption (1.2.840.113549.1.1.13) to sha1WithRSAEncryption (…1.1.5): a
 *  link algorithm the chain validator does not implement (#100). The TSA signature covers
 *  signedAttrs, not the embedded certificates, so it still verifies. */
function withLeafSignatureAlgorithmSha1(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const certsNode = signedDataKids(raw).find((c) => c.tag === 0xa0)!;
  const leafNode = children(raw, certsNode).find((n) =>
    parseCertificate(raw, n).ekus.includes(OID_EKU_TIMESTAMPING),
  )!;
  const [tbs, outerAlg] = children(raw, leafNode);
  const tbsKids = children(raw, tbs);
  const innerAlg = tbsKids[tbsKids[0].tag === 0xa0 ? 2 : 1];
  for (const alg of [innerAlg, outerAlg]) {
    const oid = children(raw, alg)[0];
    assert.equal(raw[oid.contentEnd - 1], 0x0d);
    raw[oid.contentEnd - 1] = 0x05;
  }
  return b64(raw);
}

test('#100: bound token whose chain has a link signed with an algorithm the validator does not implement, GENUINE TSA signature -> reason chain_algorithm_unsupported, not chain_signature_invalid', async () => {
  const sha1 = withLeafSignatureAlgorithmSha1(fx.tokenB64);
  const r = await verifyRfc3161Timestamp(sha1, fx.expectedHashHex);
  assert.equal(r.imprintMatches, true);
  assert.equal(r.contentBound, true);
  assert.equal(r.withinValidity, true);
  assert.equal(r.signatureValid, true);
  assert.equal(r.chainVerified, false);
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'chain_algorithm_unsupported');
  // A link whose RSA signature does not verify keeps chain_signature_invalid.
  const relinked = await verifyRfc3161Timestamp(withLeafNotBefore(fx.tokenB64, '260215194421Z'), fx.expectedHashHex);
  assert.equal(relinked.reason, 'chain_signature_invalid');
});
