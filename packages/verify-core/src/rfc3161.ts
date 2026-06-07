// RFC 3161 timestamp verification (spec §9.2 check #7, deep) — browser-safe.
//
// `verifyEvidence` did PRESENCE for #7. P2a added cryptographic TSA-signature
// verification; P2b (this) closes it to a FULL chain to a pinned trust anchor:
//   1. messageImprint.hashedMessage == the package hash (sha256) — the token is
//      ABOUT this package;
//   2. signedAttrs.messageDigest == SHA-512(TSTInfo) — the signature is BOUND to it;
//   3. the token's EMBEDDED signing cert chains to the PINNED FreeTSA RSA-4096 root
//      (each link's signature verified; CA + validity-vs-genTime checked) — so the
//      signer is trusted WITHOUT pinning the (rotatable) signing key;
//   4. the signing cert carries EKU id-kp-timeStamping and its validity covers
//      genTime;
//   5. the TSA's ECDSA-P384 signature over SHA-512(signedAttrs) verifies under THAT
//      chain-validated leaf key.
//
// Crypto: the leaf TSA signature is `@noble` ECDSA-P384 (the cert key); the cert
// chain is RSASSA-PKCS1-v1.5/SHA-512 via WebCrypto (`globalThis.crypto.subtle`, a
// global — verify-core stays browser-safe). lowS:false on the ECDSA verify (a TSA
// emits high-S; see the #119 lowS fix). Validated byte-for-byte against real
// freetsa.org tokens (low-S + high-S fixtures) cross-checked with OpenSSL.

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
import {
  parseCertificate,
  verifyCertChainToAnchor,
  bytesEqual,
  OID_EKU_TIMESTAMPING,
  type X509Cert,
  type ChainFailReason,
} from './x509.ts';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const OID_ECDSA_SHA512 = '1.2.840.10045.4.3.4';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/**
 * A pinned TSA ROOT — the OFFLINE trust anchor for check #7 (spec §10.3). Pinning the
 * long-lived ROOT (not the signing cert) means a verifier trusts ANY signing cert the
 * root issues: the token's embedded chain is validated up to this anchor, so FreeTSA
 * rotating its signing cert needs no re-pin (the P2a fragility, now removed).
 */
export interface TsaRootAnchor {
  name: string;
  /** Root public key, base64 SPKI DER. */
  rootKeyDer: string;
}

// PROVENANCE (anchor pinning — spec §10.3). FreeTSA's self-signed root CA
// (O=Free TSA/OU=Root CA, RSA-4096, SHA-256 fingerprint
// A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC).
// Captured 2026-06-07 from `https://freetsa.org/files/cacert.pem`; real tokens'
// embedded signing certs chain to it (verified with `@noble`/WebCrypto here and
// OpenSSL `ts -verify`). Adopters changing TSAs document their root here (§10.3).
export const FREETSA_ROOT_ANCHORS: readonly TsaRootAnchor[] = [
  {
    name: 'freetsa.org',
    rootKeyDer:
      'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6qlmQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlelb+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsmq4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7VDYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzdEcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XTFNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYBBF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVqM2ITKentbCMCAwEAAQ==',
  },
];

export type Rfc3161FailReason =
  | 'parse_error'
  | 'unexpected_algorithm'
  | 'no_message_digest'
  | 'content_not_bound'
  | 'imprint_mismatch'
  | 'no_signing_cert'
  | 'eku_not_timestamping'
  | 'genTime_outside_validity'
  | 'chain_incomplete'
  | 'chain_signature_invalid'
  | 'untrusted_root'
  | 'signature_invalid';

export interface Rfc3161VerifyResult {
  /** All checks passed: a chain-trusted TSA signed this package hash at genTime. */
  verified: boolean;
  imprintMatches: boolean | null;
  contentBound: boolean | null;
  /** The embedded signing cert chains to the pinned root (each link verified). */
  chainVerified: boolean | null;
  /** The signing cert carries EKU id-kp-timeStamping. */
  ekuTimestamping: boolean | null;
  /** genTime within the signing cert's validity window. */
  withinValidity: boolean | null;
  /** The TSA ECDSA-P384 signature verifies under the chain-validated leaf key. */
  signatureValid: boolean | null;
  genTime?: number;
  /** The matched root anchor name. */
  tsa?: string;
  reason?: Rfc3161FailReason;
}

// EC P-384 SPKI DER: 23-byte prefix + 97-byte uncompressed point (0x04 ‖ X ‖ Y).
const EC_P384_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
]);
const EC_P384_SPKI_LENGTH = 120;

function extractP384Point(spkiDer: Uint8Array): Uint8Array {
  if (spkiDer.length !== EC_P384_SPKI_LENGTH) throw new Asn1Error('not a P-384 SPKI');
  for (let i = 0; i < EC_P384_SPKI_PREFIX.length; i++) {
    if (spkiDer[i] !== EC_P384_SPKI_PREFIX[i]) throw new Asn1Error('unexpected P-384 SPKI prefix');
  }
  return spkiDer.slice(EC_P384_SPKI_LENGTH - 97);
}

function algorithmOid(buf: Uint8Array, alg: DerNode): string {
  return oidToString(buf, children(buf, alg)[0]);
}

interface ParsedToken {
  tstInfo: Uint8Array;
  signedAttrs: DerNode;
  digestAlgOid: string;
  signatureAlgOid: string;
  signature: Uint8Array;
  certs: X509Cert[];
}

function parseToken(buf: Uint8Array): ParsedToken {
  const resp = readNode(buf, 0);
  const respKids = children(buf, resp);
  const status = content(buf, children(buf, respKids[0])[0]);
  if (status.length !== 1 || status[0] > 1) throw new Asn1Error('PKIStatus not granted');
  const ciKids = children(buf, respKids[1]);
  if (oidToString(buf, ciKids[0]) !== OID_SIGNED_DATA) throw new Asn1Error('not signedData');
  const sd = children(buf, children(buf, ciKids[1])[0]);

  const encap = sd.find((c) => c.tag === 0x30);
  const certsNode = sd.find((c) => c.tag === 0xa0); // certificates [0] IMPLICIT
  const signerInfos = sd.filter((c) => c.tag === 0x31).pop();
  if (!encap || !signerInfos) throw new Asn1Error('malformed SignedData');

  const encapKids = children(buf, encap);
  if (oidToString(buf, encapKids[0]) !== OID_CT_TSTINFO) throw new Asn1Error('eContent not TSTInfo');
  const tstOctet = children(buf, encapKids[1])[0];
  if (tstOctet.tag !== 0x04) throw new Asn1Error('TSTInfo not an OCTET STRING');

  const si = children(buf, children(buf, signerInfos)[0]);
  const signedAttrs = si.find((c) => c.tag === 0xa0);
  const signature = si.find((c) => c.tag === 0x04);
  if (!signedAttrs || !signature) throw new Asn1Error('signerInfo missing signedAttrs/signature');
  const seqs = si.filter((c) => c.tag === 0x30);
  const digestAlg = seqs.filter((c) => c.end <= signedAttrs.start).pop();
  const signatureAlg = seqs.find((c) => c.start >= signedAttrs.end);
  if (!digestAlg || !signatureAlg) throw new Asn1Error('signerInfo missing algorithm ids');

  const certs = certsNode ? children(buf, certsNode).map((n) => parseCertificate(buf, n)) : [];

  return {
    tstInfo: buf.slice(tstOctet.contentStart, tstOctet.contentEnd),
    signedAttrs,
    digestAlgOid: algorithmOid(buf, digestAlg),
    signatureAlgOid: algorithmOid(buf, signatureAlg),
    signature: content(buf, signature),
    certs,
  };
}

function messageDigestAttr(buf: Uint8Array, signedAttrs: DerNode): Uint8Array | null {
  for (const attr of children(buf, signedAttrs)) {
    const kids = children(buf, attr);
    if (oidToString(buf, kids[0]) === OID_ATTR_MESSAGE_DIGEST) {
      return content(buf, children(buf, kids[1])[0]);
    }
  }
  return null;
}

function parseTstInfo(tst: Uint8Array): {
  hashedMessage: Uint8Array;
  hashAlgOid: string;
  genTime: number;
} {
  const kids = children(tst, readNode(tst, 0));
  const miKids = children(tst, kids[2]);
  const genTimeNode = kids.find((c) => c.tag === 0x18);
  if (!genTimeNode) throw new Asn1Error('TSTInfo missing genTime');
  return {
    hashedMessage: content(tst, miKids[1]),
    hashAlgOid: algorithmOid(tst, miKids[0]),
    genTime: readTime(tst, genTimeNode),
  };
}

// Map the X.509 chain verifier's precise reason onto this module's vocabulary. The
// strict-RFC structural/policy rejections (#119 P4) collapse to `chain_incomplete`
// (the chain could not be trusted) and only a real RSA link failure surfaces as
// `chain_signature_invalid`; the chain layer keeps the fine-grained reason.
function toRfc3161ChainReason(reason: ChainFailReason): Rfc3161FailReason {
  switch (reason) {
    case 'genTime_outside_validity':
      return 'genTime_outside_validity';
    case 'untrusted_root':
      return 'untrusted_root';
    case 'link_signature_invalid':
      return 'chain_signature_invalid';
    case 'unsupported_critical_extension':
    case 'algorithm_mismatch':
    case 'issuer_not_found':
    case 'issuer_not_ca':
    case 'path_len_exceeded':
      return 'chain_incomplete';
  }
}

/**
 * Validate the embedded chain from `leaf` up to a pinned root anchor, delegating to
 * the strict RFC 5280 verifier in `x509.ts` (each link's RSA signature; CA + keyUsage
 * keyCertSign on issuers; pathLenConstraint; unknown-critical-extension and inner==
 * outer-algorithm rejection; validity at genTime). Returns the matched anchor or a
 * mapped reason.
 */
async function validateChainToRoot(
  certs: X509Cert[],
  leaf: X509Cert,
  anchors: readonly TsaRootAnchor[],
  genTime: number,
): Promise<{ ok: boolean; tsa?: string; reason?: Rfc3161FailReason }> {
  const result = await verifyCertChainToAnchor(certs, leaf, anchors, genTime);
  if (result.ok) return { ok: true, tsa: result.anchorName };
  return { ok: false, reason: toRfc3161ChainReason(result.reason ?? 'issuer_not_found') };
}

function fail(base: Rfc3161VerifyResult, reason: Rfc3161FailReason): Rfc3161VerifyResult {
  return { ...base, reason };
}

/**
 * Verify an RFC 3161 token (base64) attests `expectedHashHex` (the package SHA-256),
 * chaining the token's embedded signing cert to a pinned TSA root. Async (the cert
 * chain uses WebCrypto RSA). A parse failure / untrusted chain is reported, not
 * thrown; `imprint_mismatch` / `content_not_bound` / `chain_signature_invalid` /
 * `signature_invalid` are the alarm signals.
 */
export async function verifyRfc3161Timestamp(
  tokenB64: string,
  expectedHashHex: string,
  anchors: readonly TsaRootAnchor[] = FREETSA_ROOT_ANCHORS,
): Promise<Rfc3161VerifyResult> {
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
      contentBound: null,
      chainVerified: null,
      ekuTimestamping: null,
      withinValidity: null,
      signatureValid: null,
      reason: 'parse_error',
    };
  }

  const base: Rfc3161VerifyResult = {
    verified: false,
    imprintMatches: null,
    contentBound: null,
    chainVerified: null,
    ekuTimestamping: null,
    withinValidity: null,
    signatureValid: null,
    genTime: tst.genTime,
  };

  if (token.digestAlgOid !== OID_SHA512 || token.signatureAlgOid !== OID_ECDSA_SHA512) {
    return fail(base, 'unexpected_algorithm');
  }

  base.imprintMatches =
    tst.hashAlgOid === OID_SHA256 && bytesToHex(tst.hashedMessage) === expectedHashHex.toLowerCase();
  if (!base.imprintMatches) return fail(base, 'imprint_mismatch');

  if (!mdAttr) return fail(base, 'no_message_digest');
  base.contentBound = bytesEqual(mdAttr, sha512(token.tstInfo));
  if (!base.contentBound) return fail(base, 'content_not_bound');

  // The signing cert is the embedded cert with EKU id-kp-timeStamping.
  const leaf = token.certs.find((c) => c.ekus.includes(OID_EKU_TIMESTAMPING));
  if (!leaf) {
    base.ekuTimestamping = token.certs.length > 0 ? false : null;
    return fail(base, token.certs.length > 0 ? 'eku_not_timestamping' : 'no_signing_cert');
  }
  base.ekuTimestamping = true;
  base.withinValidity = tst.genTime >= leaf.notBefore && tst.genTime <= leaf.notAfter;

  const chain = await validateChainToRoot(token.certs, leaf, anchors, tst.genTime);
  base.chainVerified = chain.ok;
  if (!chain.ok) return fail(base, chain.reason ?? 'untrusted_root');
  base.tsa = chain.tsa;
  if (!base.withinValidity) return fail(base, 'genTime_outside_validity');

  // The TSA signature: ECDSA-P384 over SHA-512(signedAttrs re-tagged [0]→SET),
  // under the chain-validated leaf key. lowS:false — a TSA emits high-S (#119 fix).
  const signedBytes = Uint8Array.from(rawTlv(buf, token.signedAttrs));
  signedBytes[0] = 0x31;
  try {
    const point = extractP384Point(leaf.spkiDer);
    base.signatureValid = p384.verify(token.signature, sha512(signedBytes), point, {
      format: 'der',
      prehash: false,
      lowS: false,
    });
  } catch {
    base.signatureValid = false;
  }
  if (!base.signatureValid) return fail(base, 'signature_invalid');

  return { ...base, verified: true };
}
