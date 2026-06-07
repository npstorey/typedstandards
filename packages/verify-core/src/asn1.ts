// Minimal, bounds-checked DER reader (civic-ai-tools-website#119 P2) — browser-safe.
//
// Just enough ASN.1/DER to parse RFC 3161 timestamp tokens (PKCS#7/CMS + TSTInfo)
// and, later, X.509 certs — NOT a general ASN.1 library. A hand-rolled parser over
// attacker-supplied bytes is itself an attack surface, so every read is bounds- and
// shape-checked and the encoding is STRICT DER:
//   - definite lengths only (indefinite `0x80` is rejected — it has no place in DER);
//   - minimal length encoding (no `0x81 0x05`, no leading-zero padding);
//   - lengths may not exceed the buffer; children must exactly tile their parent
//     (no trailing garbage);
//   - high-tag-number form is rejected (none of our structures use it).
// Malformed input throws `Asn1Error` rather than reading out of bounds or looping.
// Pure byte logic — no `node:*`, no `Buffer` (browser-safety guard covers this).

export class Asn1Error extends Error {}

export interface DerNode {
  /** The identifier octet (e.g. 0x30 SEQUENCE, 0x02 INTEGER, 0xa0 [0]). */
  tag: number;
  constructed: boolean;
  /** Offset of the identifier octet. */
  start: number;
  /** Offset where content begins (just past the length octets). */
  contentStart: number;
  /** Offset one past the last content octet. */
  contentEnd: number;
  /** Offset one past the whole TLV (= contentEnd). */
  end: number;
}

// DER tag classes / numbers we accept in the length/tag header. Context tags used
// by CMS/X.509 ([0], [1], …) are low-tag-number (0xa0, 0xa1, 0x80, …) so the
// high-tag-number guard never rejects a well-formed token.
const HIGH_TAG_NUMBER_MASK = 0x1f;
const CONSTRUCTED_BIT = 0x20;
const LONG_FORM_BIT = 0x80;

/** Parse a single TLV at `pos`, with strict-DER bounds checks. */
export function readNode(buf: Uint8Array, pos: number): DerNode {
  if (pos < 0 || pos + 1 > buf.length) throw new Asn1Error('readNode past end of buffer');
  const tag = buf[pos];
  if ((tag & HIGH_TAG_NUMBER_MASK) === HIGH_TAG_NUMBER_MASK) {
    throw new Asn1Error('high-tag-number form unsupported');
  }
  let i = pos + 1;
  if (i >= buf.length) throw new Asn1Error('truncated: missing length octet');
  let len = buf[i++];
  if (len & LONG_FORM_BIT) {
    const n = len & 0x7f;
    if (n === 0) throw new Asn1Error('indefinite length not allowed in DER');
    if (n > 4) throw new Asn1Error('length octet count too large');
    if (i + n > buf.length) throw new Asn1Error('truncated long-form length');
    if (buf[i] === 0x00) throw new Asn1Error('non-minimal length (leading zero)');
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]; // *256 avoids 32-bit overflow
    if (len < 0x80) throw new Asn1Error('non-minimal length (should be short form)');
  }
  const contentStart = i;
  const contentEnd = i + len;
  if (contentEnd > buf.length) throw new Asn1Error('content length exceeds buffer');
  return {
    tag,
    constructed: (tag & CONSTRUCTED_BIT) !== 0,
    start: pos,
    contentStart,
    contentEnd,
    end: contentEnd,
  };
}

/** Parse every child TLV of a constructed node; require they exactly tile it. */
export function children(buf: Uint8Array, node: DerNode): DerNode[] {
  if (!node.constructed) throw new Asn1Error('children() on a primitive node');
  const out: DerNode[] = [];
  let p = node.contentStart;
  while (p < node.contentEnd) {
    const child = readNode(buf, p);
    if (child.end > node.contentEnd) throw new Asn1Error('child overruns parent');
    out.push(child);
    p = child.end;
  }
  if (p !== node.contentEnd) throw new Asn1Error('trailing bytes in constructed value');
  return out;
}

/** The content octets of a node (a view — copy before mutating). */
export function content(buf: Uint8Array, node: DerNode): Uint8Array {
  return buf.subarray(node.contentStart, node.contentEnd);
}

/** The whole TLV (identifier + length + content) of a node (a view). */
export function rawTlv(buf: Uint8Array, node: DerNode): Uint8Array {
  return buf.subarray(node.start, node.end);
}

/** Assert a node's tag, returning it (for fluent parsing). */
export function expectTag(node: DerNode, tag: number, label = 'node'): DerNode {
  if (node.tag !== tag) {
    throw new Asn1Error(`expected ${label} tag 0x${tag.toString(16)}, got 0x${node.tag.toString(16)}`);
  }
  return node;
}

/** Decode an OBJECT IDENTIFIER (tag 0x06) to its dotted-decimal string. */
export function oidToString(buf: Uint8Array, node: DerNode): string {
  expectTag(node, 0x06, 'OID');
  const b = content(buf, node);
  if (b.length === 0) throw new Asn1Error('empty OID');
  if (b[b.length - 1] & 0x80) throw new Asn1Error('truncated OID subidentifier');
  const subids: number[] = [];
  let acc = 0;
  for (const byte of b) {
    acc = acc * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      subids.push(acc);
      acc = 0;
    }
  }
  const first = subids[0];
  const arc0 = Math.min(2, Math.floor(first / 40));
  const arcs = [arc0, first - arc0 * 40, ...subids.slice(1)];
  return arcs.join('.');
}

function asciiOf(bytes: Uint8Array): string {
  let s = '';
  for (const c of bytes) {
    if (c < 0x20 || c > 0x7e) throw new Asn1Error('non-ASCII byte in time string');
    s += String.fromCharCode(c);
  }
  return s;
}

/**
 * Decode a UTCTime (0x17) or GeneralizedTime (0x18) to epoch milliseconds. Only
 * the `Z` (UTC) forms RFC 5280 / RFC 3161 mandate are accepted; local-time and
 * offset forms are rejected. UTCTime two-digit years use the RFC 5280 1950–2049
 * window.
 */
export function readTime(buf: Uint8Array, node: DerNode): number {
  const s = asciiOf(content(buf, node));
  if (node.tag === 0x18) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
    if (!m) throw new Asn1Error('malformed GeneralizedTime');
    const ms = m[7] ? Math.round(parseFloat('0' + m[7]) * 1000) : 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms);
  }
  if (node.tag === 0x17) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Asn1Error('malformed UTCTime');
    const yy = +m[1];
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  throw new Asn1Error(`not a time tag: 0x${node.tag.toString(16)}`);
}

/** First child whose tag matches, or undefined. */
export function findChild(
  buf: Uint8Array,
  node: DerNode,
  tag: number,
): DerNode | undefined {
  return children(buf, node).find((c) => c.tag === tag);
}
