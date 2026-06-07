// Minimal X.509 certificate parsing (civic-ai-tools-website#119 P2b) — browser-safe.
//
// Just enough of RFC 5280 to validate the RFC 3161 token's embedded cert chain: the
// signed TBSCertificate bytes, the outer signature + algorithm, the public key, the
// validity window, issuer/subject (for chain linking), the serial (to match the CMS
// signer), and the two extensions we gate on (EKU, basicConstraints). Built on the
// strict-DER `asn1.ts` reader, so malformed certs throw rather than mis-parse.

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

export const OID_EKU_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const OID_EXT_EKU = '2.5.29.37';
const OID_EXT_BASIC_CONSTRAINTS = '2.5.29.19';

export interface X509Cert {
  /** The signed TBSCertificate (raw TLV) — exactly what the issuer signed. */
  tbsBytes: Uint8Array;
  /** Outer signatureAlgorithm OID. */
  sigAlgOid: string;
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
  i++; // inner signature AlgorithmIdentifier (redundant; skip)
  const issuer = tk[i++];
  const validity = tk[i++];
  const subject = tk[i++];
  const spki = tk[i++];
  if (!issuer || !validity || !subject || !spki) throw new Asn1Error('malformed TBSCertificate');

  const [nb, na] = children(buf, validity);
  if (!nb || !na) throw new Asn1Error('malformed Validity');

  const ekus: string[] = [];
  let isCA = false;
  const extsWrap = tk.slice(i).find((c) => c.tag === 0xa3); // extensions [3] EXPLICIT
  if (extsWrap) {
    for (const ext of children(buf, children(buf, extsWrap)[0])) {
      const ec = children(buf, ext); // Extension { extnID OID, critical BOOL?, extnValue OCTET }
      const oid = oidToString(buf, ec[0]);
      const value = content(buf, ec[ec.length - 1]); // extnValue OCTET STRING content (nested DER)
      if (oid === OID_EXT_EKU) {
        for (const kp of children(value, readNode(value, 0))) ekus.push(oidToString(value, kp));
      } else if (oid === OID_EXT_BASIC_CONSTRAINTS) {
        const bc = children(value, readNode(value, 0));
        if (bc[0]?.tag === 0x01 && content(value, bc[0])[0] === 0xff) isCA = true;
      }
    }
  }

  return {
    tbsBytes: rawTlv(buf, tbs),
    sigAlgOid: oidToString(buf, children(buf, sigAlg)[0]),
    signature: content(buf, sigBits).slice(1),
    spkiDer: rawTlv(buf, spki),
    serial,
    issuerDer: rawTlv(buf, issuer),
    subjectDer: rawTlv(buf, subject),
    notBefore: readTime(buf, nb),
    notAfter: readTime(buf, na),
    ekus,
    isCA,
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
