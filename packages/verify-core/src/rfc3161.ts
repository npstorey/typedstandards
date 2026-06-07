// RFC 3161 timestamp verification (spec §9.2 check #7, deep) — browser-safe.
//
// `verifyEvidence` today does PRESENCE for #7 (`!!rfc3161Timestamp`). This closes
// the cryptographic gap for the FreeTSA profile our producer uses (#119 P2a): it
// parses the RFC 3161 token (a PKCS#7/CMS SignedData over a TSTInfo) and verifies,
// OFFLINE, that a trusted TSA attested the package hash at a point in time:
//   1. messageImprint.hashedMessage == the package hash (sha256), so the token is
//      ABOUT this package;
//   2. signedAttrs.messageDigest == SHA-512(TSTInfo), so the signature is BOUND to
//      that TSTInfo;
//   3. the TSA's ECDSA-P384 signature over SHA-512(signedAttrs) verifies against the
//      PINNED FreeTSA signing key (the trust anchor);
//   4. genTime falls within that signing cert's validity window.
//
// SCOPE (P2a): FreeTSA uses an EC P-384 signing cert and `ecdsa-with-SHA512`, so the
// TSA-signature check is pure `@noble` ECDSA — no WebCrypto/RSA. The anchor is the
// PINNED signing-cert public key (re-pin on rotation — documented below). P2b adds
// full embedded-cert chain validation to FreeTSA's RSA root (which removes the
// re-pin), and generalizes EKU/validity from the certs themselves. The recipe here
// was validated byte-for-byte against a real freetsa.org token (cross-checked with
// OpenSSL `ts -verify`) before shipping; `__fixtures__/rfc3161-token.json` is that
// token and the tests reproduce it offline.

import { p384 } from '@noble/curves/nist.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { base64ToBytes, bytesToHex } from './primitives.ts';
import {
  Asn1Error,
  readNode,
  children,
  content,
  rawTlv,
  oidToString,
  readTime,
  type DerNode,
} from './asn1.ts';

// --- OIDs ------------------------------------------------------------------
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const OID_ECDSA_SHA512 = '1.2.840.10045.4.3.4';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/**
 * A pinned TSA signing key — the OFFLINE trust anchor for check #7 (spec §10.3).
 * Pinning the SIGNING key (not the long-lived root) is the P2a "acceptable v1":
 * it must be re-pinned if FreeTSA rotates the signing cert. P2b anchors to the RSA
 * root via the token's embedded chain, which removes the re-pin.
 */
export interface TsaAnchor {
  name: string;
  /** EC P-384 signing public key, base64 SPKI DER. */
  signingKeyDer: string;
  /** Signing cert validity window (ISO 8601, UTC). genTime must fall inside it. */
  notBefore: string;
  notAfter: string;
}

// PROVENANCE (anchor pinning — spec §10.3). FreeTSA's online TSA (`freetsa.org/tsr`)
// signs with this EC P-384 key (cert serial C2E986160DA8E9CD, OU=TSA, EKU
// id-kp-timeStamping, valid 2026-02-15 → 2040-02-02). Captured 2026-06-07 from
// `https://freetsa.org/files/tsa.crt`; a live token verified against it with both
// `@noble` (here) and OpenSSL `ts -verify` against FreeTSA's published CA. The cert
// chains to FreeTSA's self-signed RSA-4096 root (OU=Root CA) — pinning that root and
// validating the embedded chain is P2b.
export const FREETSA_TSA_ANCHORS: readonly TsaAnchor[] = [
  {
    name: 'freetsa.org',
    signingKeyDer:
      'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEohXhobLWy4cYsdKOFALpjUsB1FJTntwwb7PH2LOfNMAA1ufaKhkgsdeW6etU0pl5MC5tSVuPF52yy4sz+mbY3L7IVdx/bs9m0ud7IA14YNcC2yIQLa2gvnxwsrR3rlWr',
    notBefore: '2026-02-15T19:44:22Z',
    notAfter: '2040-02-02T19:44:22Z',
  },
];

export type Rfc3161FailReason =
  | 'parse_error'
  | 'not_granted'
  | 'unexpected_content_type'
  | 'unexpected_algorithm'
  | 'no_message_digest'
  | 'content_not_bound'
  | 'no_anchor'
  | 'signature_invalid'
  | 'imprint_mismatch'
  | 'genTime_outside_validity';

export interface Rfc3161VerifyResult {
  /** All checks passed: a pinned TSA's signature binds this package hash to genTime. */
  verified: boolean;
  /** messageImprint.hashedMessage == the expected package hash (sha256). */
  imprintMatches: boolean | null;
  /** The TSA ECDSA-P384 signature over SHA-512(signedAttrs) verifies vs the anchor. */
  signatureValid: boolean | null;
  /** signedAttrs.messageDigest == SHA-512(TSTInfo) — the sig is bound to the TSTInfo. */
  contentBound: boolean | null;
  /** genTime within the pinned signing cert's validity window. */
  withinValidity: boolean | null;
  /** RFC 3161 genTime, epoch ms. */
  genTime?: number;
  /** The matched anchor name (when the signature verified). */
  tsa?: string;
  reason?: Rfc3161FailReason;
}

// EC P-384 SPKI DER is a fixed 120-byte structure: a 23-byte prefix (SEQUENCE →
// AlgorithmIdentifier{ id-ecPublicKey, secp384r1 } → BIT STRING) then the 97-byte
// uncompressed point (0x04 ‖ X ‖ Y).
const EC_P384_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
]);
const EC_P384_SPKI_LENGTH = 120;

function extractP384Point(publicKeyB64Der: string): Uint8Array {
  const der = base64ToBytes(publicKeyB64Der);
  if (der.length !== EC_P384_SPKI_LENGTH) {
    throw new Asn1Error(`Unexpected P-384 SPKI length ${der.length}`);
  }
  for (let i = 0; i < EC_P384_SPKI_PREFIX.length; i++) {
    if (der[i] !== EC_P384_SPKI_PREFIX[i]) throw new Asn1Error('Unexpected P-384 SPKI prefix');
  }
  return der.slice(EC_P384_SPKI_LENGTH - 97);
}

/** The AlgorithmIdentifier's OID (its first child). */
function algorithmOid(buf: Uint8Array, alg: DerNode): string {
  return oidToString(buf, children(buf, alg)[0]);
}

interface ParsedToken {
  tstInfo: Uint8Array; // the TSTInfo eContent bytes (DER)
  signedAttrs: DerNode; // the [0] IMPLICIT signedAttrs node
  digestAlgOid: string;
  signatureAlgOid: string;
  signature: Uint8Array; // the signerInfo signature OCTET STRING content (DER ECDSA)
}

/** Navigate TimeStampResp → ContentInfo → SignedData → { TSTInfo, signerInfo }. */
function parseToken(buf: Uint8Array): ParsedToken {
  const resp = readNode(buf, 0);
  const respKids = children(buf, resp);
  // PKIStatusInfo.status: 0 granted, 1 grantedWithMods; anything else ⇒ no token.
  const status = children(buf, respKids[0])[0];
  const statusVal = content(buf, status);
  if (statusVal.length !== 1 || statusVal[0] > 1) throw new Asn1Error('PKIStatus not granted');
  const contentInfo = respKids[1];
  if (!contentInfo) throw new Asn1Error('no timeStampToken');

  const ciKids = children(buf, contentInfo);
  if (oidToString(buf, ciKids[0]) !== OID_SIGNED_DATA) throw new Asn1Error('not signedData');
  const signedData = children(buf, ciKids[1])[0]; // [0] EXPLICIT → SignedData

  const sd = children(buf, signedData);
  const encap = sd.find((c) => c.tag === 0x30); // first SEQUENCE = encapContentInfo
  const signerInfos = sd.filter((c) => c.tag === 0x31).pop(); // last SET = signerInfos
  if (!encap || !signerInfos) throw new Asn1Error('malformed SignedData');

  const encapKids = children(buf, encap);
  if (oidToString(buf, encapKids[0]) !== OID_CT_TSTINFO) throw new Asn1Error('eContent not TSTInfo');
  const tstOctet = children(buf, encapKids[1])[0]; // [0] EXPLICIT → OCTET STRING
  if (tstOctet.tag !== 0x04) throw new Asn1Error('TSTInfo not an OCTET STRING');
  const tstInfo = buf.slice(tstOctet.contentStart, tstOctet.contentEnd);

  const signerInfo = children(buf, signerInfos)[0];
  const si = children(buf, signerInfo);
  const signedAttrs = si.find((c) => c.tag === 0xa0);
  const signature = si.find((c) => c.tag === 0x04);
  if (!signedAttrs || !signature) throw new Asn1Error('signerInfo missing signedAttrs/signature');
  // SignerInfo has three SEQUENCEs: sid (issuerAndSerialNumber), digestAlgorithm,
  // signatureAlgorithm. The digest alg is the LAST 0x30 before signedAttrs (the sid
  // also precedes it); the signature alg is the first 0x30 after.
  const seqs = si.filter((c) => c.tag === 0x30);
  const digestAlg = seqs.filter((c) => c.end <= signedAttrs.start).pop();
  const signatureAlg = seqs.find((c) => c.start >= signedAttrs.end);
  if (!digestAlg || !signatureAlg) throw new Asn1Error('signerInfo missing algorithm ids');

  return {
    tstInfo,
    signedAttrs,
    digestAlgOid: algorithmOid(buf, digestAlg),
    signatureAlgOid: algorithmOid(buf, signatureAlg),
    signature: content(buf, signature),
  };
}

/** The OCTET STRING value of the messageDigest signed attribute. */
function messageDigestAttr(buf: Uint8Array, signedAttrs: DerNode): Uint8Array | null {
  for (const attr of children(buf, signedAttrs)) {
    const kids = children(buf, attr);
    if (oidToString(buf, kids[0]) === OID_ATTR_MESSAGE_DIGEST) {
      const value = children(buf, kids[1])[0]; // SET OF → OCTET STRING
      return content(buf, value);
    }
  }
  return null;
}

/** Pull { hashedMessage, hashAlgOid, genTime } out of a TSTInfo. */
function parseTstInfo(tst: Uint8Array): {
  hashedMessage: Uint8Array;
  hashAlgOid: string;
  genTime: number;
} {
  const root = readNode(tst, 0);
  const kids = children(tst, root); // version, policy, messageImprint, serial, genTime, …
  const messageImprint = kids[2];
  const miKids = children(tst, messageImprint);
  const hashAlgOid = algorithmOid(tst, miKids[0]);
  const hashedMessage = content(tst, miKids[1]);
  const genTimeNode = kids.find((c) => c.tag === 0x18);
  if (!genTimeNode) throw new Asn1Error('TSTInfo missing genTime');
  return { hashedMessage, hashAlgOid, genTime: readTime(tst, genTimeNode) };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verify an RFC 3161 timestamp token (base64) attests `expectedHashHex` (the package
 * SHA-256), against the pinned TSA anchors. Returns a graded verdict; a parse failure
 * or unknown anchor is reported (not thrown) so the caller can render it calmly,
 * while a real cryptographic failure (`signature_invalid` / `imprint_mismatch` /
 * `content_not_bound`) is the alarm signal.
 */
export function verifyRfc3161Timestamp(
  tokenB64: string,
  expectedHashHex: string,
  anchors: readonly TsaAnchor[] = FREETSA_TSA_ANCHORS,
): Rfc3161VerifyResult {
  let buf: Uint8Array;
  let token: ParsedToken;
  let tst: ReturnType<typeof parseTstInfo>;
  let mdAttr: Uint8Array | null;
  try {
    buf = base64ToBytes(tokenB64);
    token = parseToken(buf);
    tst = parseTstInfo(token.tstInfo);
    mdAttr = messageDigestAttr(buf, token.signedAttrs);
  } catch {
    return {
      verified: false,
      imprintMatches: null,
      signatureValid: null,
      contentBound: null,
      withinValidity: null,
      reason: 'parse_error',
    };
  }

  const base: Rfc3161VerifyResult = {
    verified: false,
    imprintMatches: null,
    signatureValid: null,
    contentBound: null,
    withinValidity: null,
    genTime: tst.genTime,
  };

  // FreeTSA profile (P2a): SHA-512 digest + ECDSA-with-SHA-512 signature.
  if (token.digestAlgOid !== OID_SHA512 || token.signatureAlgOid !== OID_ECDSA_SHA512) {
    return { ...base, reason: 'unexpected_algorithm' };
  }

  // (1) message imprint is about THIS package (sha256).
  const imprintMatches =
    tst.hashAlgOid === OID_SHA256 && bytesToHex(tst.hashedMessage) === expectedHashHex.toLowerCase();
  base.imprintMatches = imprintMatches;
  if (!imprintMatches) return { ...base, reason: 'imprint_mismatch' };

  // (2) the signature is bound to this TSTInfo via the messageDigest attribute.
  if (!mdAttr) return { ...base, reason: 'no_message_digest' };
  const contentBound = bytesEqual(mdAttr, sha512(token.tstInfo));
  base.contentBound = contentBound;
  if (!contentBound) return { ...base, reason: 'content_not_bound' };

  // (3) ECDSA-P384 signature over SHA-512(signedAttrs re-tagged [0] → SET) verifies
  // against a pinned anchor key. (`@noble` prehashes with SHA-384 by default, so we
  // hash with SHA-512 ourselves and pass `prehash: false`.)
  const signedBytes = Uint8Array.from(rawTlv(buf, token.signedAttrs));
  signedBytes[0] = 0x31; // [0] IMPLICIT (0xa0) → SET OF (0x31) for the signature input
  const digest = sha512(signedBytes);

  let matched: TsaAnchor | undefined;
  for (const anchor of anchors) {
    try {
      const point = extractP384Point(anchor.signingKeyDer);
      // `lowS: false` is REQUIRED here: low-S is a signature-malleability convention
      // for SIGNING, not a validity rule. A TSA (like FreeTSA) legitimately emits
      // high-S ECDSA signatures (~half of them); `@noble`'s default `lowS: true`
      // would false-negative those (it rejected the real high-S da9246 token —
      // regression-tested). Accepting high-S is correct: both S and n−S are valid
      // signatures by the same key, and we only ask "did this TSA sign this hash".
      if (p384.verify(token.signature, digest, point, { format: 'der', prehash: false, lowS: false })) {
        matched = anchor;
        break;
      }
    } catch {
      // malformed anchor key ⇒ try the next
    }
  }
  base.signatureValid = !!matched;
  if (!matched) {
    // Distinguish "no pinned key vouches for this token" (calm — unknown TSA) from a
    // signature that fails under a known key. Here, none verified ⇒ no_anchor.
    return { ...base, reason: 'no_anchor' };
  }
  base.tsa = matched.name;

  // (4) genTime within the pinned signing cert's validity window.
  const notBefore = Date.parse(matched.notBefore);
  const notAfter = Date.parse(matched.notAfter);
  const withinValidity = tst.genTime >= notBefore && tst.genTime <= notAfter;
  base.withinValidity = withinValidity;
  if (!withinValidity) return { ...base, reason: 'genTime_outside_validity' };

  return { ...base, verified: true };
}
