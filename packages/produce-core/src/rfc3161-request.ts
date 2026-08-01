// RFC 3161 `TimeStampReq` DER builder — pure external-proof codec.
//
// Builds the timestamp request for a SHA-256 message imprint over the
// envelope hash. SUBMISSION is deliberately out of scope (no `fetch` anywhere
// in this package): the caller POSTs these bytes to its chosen TSA with
// content-type `application/timestamp-query` and stores the returned token
// (base64) as the package's timestamp proof. verify-core's `rfc3161` module
// is the parsing/validating counterpart for the token that comes back.
//
// The DER writers below are the byte-for-byte port of the reference
// implementation's builders, off `Buffer` (Uint8Array only) so they run
// unchanged in a browser.

import { hexToBytes } from '@typedstandards/verify-core';

// SHA-256 OID 2.16.840.1.101.3.4.2.1 as a complete DER TLV.
const SHA256_OID = Uint8Array.from([
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
]);

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.from([length]);
  if (length < 0x100) return Uint8Array.from([0x81, length]);
  return Uint8Array.from([0x82, (length >> 8) & 0xff, length & 0xff]);
}

function derSequence(...items: Uint8Array[]): Uint8Array {
  const body = concatBytes(...items);
  return concatBytes(Uint8Array.from([0x30]), derLength(body.length), body);
}

function derOctetString(data: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.from([0x04]), derLength(data.length), data);
}

function derInteger(value: number): Uint8Array {
  return Uint8Array.from([0x02, 0x01, value]);
}

function derBoolean(value: boolean): Uint8Array {
  return Uint8Array.from([0x01, 0x01, value ? 0xff : 0x00]);
}

/**
 * Build a minimal ASN.1 DER `TimeStampReq` (RFC 3161 §2.4.1) for an envelope
 * hash: version=1, a SHA-256 MessageImprint over the hash bytes, certReq=true
 * (so the TSA embeds its signing certificate in the token, keeping later
 * verification offline).
 */
export function buildTimestampRequest(envelopeHashHex: string): Uint8Array {
  const hashBytes = hexToBytes(envelopeHashHex);
  if (hashBytes.length !== 32) {
    throw new Error(
      `TimeStampReq message imprint must be a SHA-256 hash (32 bytes); got ${hashBytes.length}`,
    );
  }
  // AlgorithmIdentifier for SHA-256
  const algId = derSequence(SHA256_OID);
  // MessageImprint
  const messageImprint = derSequence(algId, derOctetString(hashBytes));
  // TimeStampReq: version=1, messageImprint, certReq=true
  return derSequence(derInteger(1), messageImprint, derBoolean(true));
}
