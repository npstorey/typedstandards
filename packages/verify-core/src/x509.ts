// Minimal X.509 certificate parsing + chain validation (civic-ai-tools-website#119
// P2b/P4) — browser-safe.
//
// Just enough of RFC 5280 to validate the RFC 3161 token's embedded cert chain: the
// signed TBSCertificate bytes, the outer signature + algorithm, the public key, the
// validity window, issuer/subject (for chain linking), the serial (to match the CMS
// signer), and the extensions we gate on (EKU, basicConstraints, keyUsage). Built on
// the strict-DER `asn1.ts` reader, so malformed certs throw rather than mis-parse.
//
// STRICT RFC 5280 COMPLIANCE (#119 P4). `verifyCertChainToAnchor` is the pinned-root
// chain verifier; it fails CLOSED on four checks that a conforming verifier MUST
// enforce. Under the pinned FreeTSA root these are non-exploitable (the root issues a
// well-formed chain), so they are defence-in-depth / strict-RFC hardening, and each
// has a fail-closed negative test (mint-forged certs) in `x509.test.ts`:
//   (a) UNKNOWN CRITICAL EXTENSIONS are rejected (RFC 5280 §4.2: a system MUST reject
//       a certificate with a critical extension it does not recognize). The recognized
//       set is { basicConstraints, keyUsage, extKeyUsage }; any other critical
//       extension sets `hasUnknownCriticalExt`.
//   (b) An issuer is trusted to sign certificates only if it is a CA (basicConstraints
//       cA:TRUE) AND its keyUsage asserts keyCertSign (RFC 5280 §4.2.1.3) — both, or
//       the link is rejected as `issuer_not_ca`.
//   (c) basicConstraints pathLenConstraint is enforced DOWN the chain (§4.2.1.9): an
//       issuer with pathLen=n may have at most n intermediate CAs beneath it.
//   (d) The inner TBSCertificate.signature AlgorithmIdentifier MUST byte-equal the
//       outer signatureAlgorithm (§4.1.1.2) — an anti algorithm-substitution check;
//       a mismatch sets `sigAlgConsistent=false` and the link is rejected.

import {
  readNode,
  children,
  content,
  rawTlv,
  oidToString,
  readTime,
  Asn1Error,
  type DerNode,
} from './asn1.ts';
import { base64ToBytes } from './primitives.ts';

export const OID_EKU_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const OID_EXT_EKU = '2.5.29.37';
const OID_EXT_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_EXT_KEY_USAGE = '2.5.29.15';

// Critical extensions a conforming verifier recognizes and processes (check (a)).
// A critical extension OUTSIDE this set means the cert MUST be rejected.
const RECOGNIZED_CRITICAL_EXTS = new Set([
  OID_EXT_EKU,
  OID_EXT_BASIC_CONSTRAINTS,
  OID_EXT_KEY_USAGE,
]);

// keyUsage is a DER BIT STRING; keyCertSign is bit 5 (RFC 5280 §4.2.1.3), i.e. the
// 0x04 bit of the first data octet (content is [unusedBits, byte0, …]).
const KEY_CERT_SIGN_BIT = 0x04;

export interface X509Cert {
  /** The signed TBSCertificate (raw TLV) — exactly what the issuer signed. */
  tbsBytes: Uint8Array;
  /** Outer signatureAlgorithm OID. */
  sigAlgOid: string;
  /** Outer signatureAlgorithm AlgorithmIdentifier (raw TLV). */
  sigAlgDer: Uint8Array;
  /** Inner TBSCertificate.signature AlgorithmIdentifier (raw TLV). */
  innerSigAlgDer: Uint8Array;
  /** Inner == outer signature AlgorithmIdentifier, byte-for-byte (check (d)). */
  sigAlgConsistent: boolean;
  /** signatureValue (BIT STRING content, the leading unused-bits octet dropped). */
  signature: Uint8Array;
  /** SubjectPublicKeyInfo (raw TLV) — this cert's public key. */
  spkiDer: Uint8Array;
  /** serialNumber content octets. */
  serial: Uint8Array;
  /** issuer / subject Name (raw TLV) — compared by bytes for chain linking. */
  issuerDer: Uint8Array;
  subjectDer: Uint8Array;
  notBefore: number; // epoch ms
  notAfter: number;
  /** Extended Key Usage OIDs (empty if the extension is absent). */
  ekus: string[];
  /** basicConstraints cA:TRUE. */
  isCA: boolean;
  /** keyUsage asserts keyCertSign (false if keyUsage is absent — check (b)). */
  keyCertSign: boolean;
  /** basicConstraints pathLenConstraint, or null when absent/unconstrained (check (c)). */
  pathLen: number | null;
  /** Carries a critical extension this verifier does not recognize (check (a)). */
  hasUnknownCriticalExt: boolean;
}

/** Read a small non-negative DER INTEGER's content as a Number (used for pathLen). */
function readUint(bytes: Uint8Array): number {
  let n = 0;
  for (const b of bytes) n = n * 256 + b; // *256, not <<8, to avoid 32-bit overflow
  return n;
}

/** Parse a Certificate (SEQUENCE { tbsCertificate, signatureAlgorithm, signature }). */
export function parseCertificate(buf: Uint8Array, node: DerNode): X509Cert {
  const [tbs, sigAlg, sigBits] = children(buf, node);
  if (!tbs || !sigAlg || !sigBits) throw new Asn1Error('malformed Certificate');

  // TBSCertificate: [ version [0] EXPLICIT (optional), serialNumber, signature,
  //   issuer, validity, subject, subjectPublicKeyInfo, ... extensions [3] ]
  const tk = children(buf, tbs);
  let i = 0;
  if (tk[i]?.tag === 0xa0) i++; // optional version [0]
  const serial = content(buf, tk[i++]);
  const innerSigAlg = tk[i++]; // inner signature AlgorithmIdentifier (check (d))
  const issuer = tk[i++];
  const validity = tk[i++];
  const subject = tk[i++];
  const spki = tk[i++];
  if (!innerSigAlg || !issuer || !validity || !subject || !spki) {
    throw new Asn1Error('malformed TBSCertificate');
  }

  const [nb, na] = children(buf, validity);
  if (!nb || !na) throw new Asn1Error('malformed Validity');

  const ekus: string[] = [];
  let isCA = false;
  let keyCertSign = false;
  let pathLen: number | null = null;
  let hasUnknownCriticalExt = false;
  const extsWrap = tk.slice(i).find((c) => c.tag === 0xa3); // extensions [3] EXPLICIT
  if (extsWrap) {
    for (const ext of children(buf, children(buf, extsWrap)[0])) {
      const ec = children(buf, ext); // Extension { extnID OID, critical BOOL?, extnValue OCTET }
      const oid = oidToString(buf, ec[0]);
      // critical BOOLEAN DEFAULT FALSE: present iff a BOOLEAN precedes extnValue.
      const critical = ec.length === 3 && ec[1]?.tag === 0x01 && content(buf, ec[1])[0] === 0xff;
      if (critical && !RECOGNIZED_CRITICAL_EXTS.has(oid)) hasUnknownCriticalExt = true; // (a)
      const value = content(buf, ec[ec.length - 1]); // extnValue OCTET STRING content (nested DER)
      if (oid === OID_EXT_EKU) {
        for (const kp of children(value, readNode(value, 0))) ekus.push(oidToString(value, kp));
      } else if (oid === OID_EXT_BASIC_CONSTRAINTS) {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
        //                                 pathLenConstraint INTEGER (0..MAX) OPTIONAL }
        const bc = children(value, readNode(value, 0));
        let b = 0;
        if (bc[b]?.tag === 0x01) {
          if (content(value, bc[b])[0] === 0xff) isCA = true;
          b++;
        }
        if (bc[b]?.tag === 0x02) pathLen = readUint(content(value, bc[b])); // (c)
      } else if (oid === OID_EXT_KEY_USAGE) {
        const ku = readNode(value, 0); // BIT STRING
        if (ku.tag === 0x03) {
          const bits = content(value, ku); // [unusedBits, byte0, …]
          keyCertSign = bits.length >= 2 && (bits[1] & KEY_CERT_SIGN_BIT) !== 0; // (b)
        }
      }
    }
  }

  const sigAlgDer = rawTlv(buf, sigAlg);
  const innerSigAlgDer = rawTlv(buf, innerSigAlg);

  return {
    tbsBytes: rawTlv(buf, tbs),
    sigAlgOid: oidToString(buf, children(buf, sigAlg)[0]),
    sigAlgDer,
    innerSigAlgDer,
    sigAlgConsistent: bytesEqual(innerSigAlgDer, sigAlgDer), // (d)
    signature: content(buf, sigBits).slice(1),
    spkiDer: rawTlv(buf, spki),
    serial,
    issuerDer: rawTlv(buf, issuer),
    subjectDer: rawTlv(buf, subject),
    notBefore: readTime(buf, nb),
    notAfter: readTime(buf, na),
    ekus,
    isCA,
    keyCertSign,
    pathLen,
    hasUnknownCriticalExt,
  };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// RSA signature-algorithm OID → WebCrypto SHA hash name. Only the SHA-2 RSASSA-
// PKCS1-v1.5 variants a TSA chain uses are accepted.
const RSA_SIG_HASH: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'SHA-256',
  '1.2.840.113549.1.1.12': 'SHA-384',
  '1.2.840.113549.1.1.13': 'SHA-512',
};

/**
 * Verify `cert.signature` over `cert.tbsBytes` using `issuerSpkiDer` (RSA), via
 * WebCrypto (`globalThis.crypto.subtle` — a browser/Node global, not a `node:`
 * import, so verify-core stays browser-safe). Returns false for an unsupported
 * algorithm or any verification error.
 */
export async function verifyCertSignatureRsa(
  cert: X509Cert,
  issuerSpkiDer: Uint8Array,
): Promise<boolean> {
  const hash = RSA_SIG_HASH[cert.sigAlgOid];
  if (!hash) return false;
  try {
    // Copy into fresh ArrayBuffer-backed views: subarray slices are
    // `Uint8Array<ArrayBufferLike>`, which WebCrypto's `BufferSource` rejects.
    const key = await globalThis.crypto.subtle.importKey(
      'spki',
      new Uint8Array(issuerSpkiDer),
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify'],
    );
    return await globalThis.crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      new Uint8Array(cert.signature),
      new Uint8Array(cert.tbsBytes),
    );
  } catch {
    return false;
  }
}

// --- Pinned-root chain validation (RFC 5280, strict — #119 P4) -------------

/** A pinned trust anchor: a root whose public key is trusted by value. */
export interface ChainAnchor {
  name: string;
  /** Root public key, base64 SPKI DER. */
  rootKeyDer: string;
}

export type ChainFailReason =
  | 'unsupported_critical_extension' // (a) a cert carries an unrecognized critical ext
  | 'algorithm_mismatch' // (d) inner != outer signature AlgorithmIdentifier
  | 'genTime_outside_validity' // a cert in the path is not valid at the reference time
  | 'issuer_not_found' // no embedded cert's subject matches the issuer
  | 'issuer_not_ca' // (b) issuer lacks cA:TRUE and/or keyUsage keyCertSign
  | 'path_len_exceeded' // (c) issuer's pathLenConstraint is violated
  | 'link_signature_invalid' // a link's RSA signature does not verify
  | 'untrusted_root'; // the self-signed terminus is not a pinned anchor

export interface ChainResult {
  /** The path links to a pinned anchor and every strict check passed. */
  ok: boolean;
  /** The matched anchor's name, when `ok`. */
  anchorName?: string;
  /** The first check that failed, otherwise. */
  reason?: ChainFailReason;
}

// A self-issued chain deeper than this is rejected (cycle / runaway guard). The real
// TSA chain is depth 1 (leaf → root); 8 is generous headroom for intermediates.
const MAX_CHAIN_DEPTH = 8;

/**
 * Validate the embedded chain from `leaf` up to a self-signed cert whose key is a
 * pinned anchor, applying the strict RFC 5280 checks (a)-(d) documented at the top of
 * this module. `atTime` (epoch ms) is the instant every cert's validity is checked
 * against (the RFC 3161 genTime, for a TSA chain). Each link's RSA signature is
 * verified via WebCrypto. Async; never throws — a structural/policy failure is
 * reported as a `reason`. Bounded against cycles and runaway length.
 */
export async function verifyCertChainToAnchor(
  certs: X509Cert[],
  leaf: X509Cert,
  anchors: readonly ChainAnchor[],
  atTime: number,
): Promise<ChainResult> {
  let current = leaf;
  // `depth` doubles as the count of intermediate CAs between the current issuer and
  // the leaf: at depth 0 the issuer signs the end-entity directly (0 intermediates),
  // at depth k there are k intermediates beneath it — exactly the pathLen budget (c).
  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
    if (current.hasUnknownCriticalExt) {
      return { ok: false, reason: 'unsupported_critical_extension' }; // (a)
    }
    if (!current.sigAlgConsistent) {
      return { ok: false, reason: 'algorithm_mismatch' }; // (d)
    }
    if (atTime < current.notBefore || atTime > current.notAfter) {
      return { ok: false, reason: 'genTime_outside_validity' };
    }
    if (bytesEqual(current.issuerDer, current.subjectDer)) {
      // Self-signed terminus: trusted iff its key is a pinned anchor.
      const anchor = anchors.find((a) => bytesEqual(base64ToBytes(a.rootKeyDer), current.spkiDer));
      return anchor ? { ok: true, anchorName: anchor.name } : { ok: false, reason: 'untrusted_root' };
    }
    const issuer = certs.find((c) => bytesEqual(c.subjectDer, current.issuerDer));
    if (!issuer) return { ok: false, reason: 'issuer_not_found' };
    if (!issuer.isCA || !issuer.keyCertSign) return { ok: false, reason: 'issuer_not_ca' }; // (b)
    if (issuer.pathLen !== null && depth > issuer.pathLen) {
      return { ok: false, reason: 'path_len_exceeded' }; // (c)
    }
    if (!(await verifyCertSignatureRsa(current, issuer.spkiDer))) {
      return { ok: false, reason: 'link_signature_invalid' };
    }
    current = issuer;
  }
  return { ok: false, reason: 'issuer_not_found' };
}
