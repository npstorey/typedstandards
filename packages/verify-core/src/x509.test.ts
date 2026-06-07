// X.509 cert-parse + strict-chain tests (civic-ai-tools-website#119 P2b + P4).
//
// Two layers:
//   1. Parsing the REAL freetsa.org signing cert embedded in the token fixture, and
//      asserting malformed input throws (the parser is built on the strict-DER reader
//      whose adversarial cases live in asn1.test.ts; this confirms the cert layer
//      surfaces those as throws, not mis-parses).
//   2. The strict RFC 5280 chain verifier (`verifyCertChainToAnchor`). Each strictness
//      check ships a FAIL-CLOSED negative test built from MINTED forged certs — test
//      files are exempt from browser-safety, so we use `node:crypto` to generate RSA
//      keys and a tiny hand-rolled DER encoder to assemble certs with exactly the
//      (mal)formation each check targets. A POSITIVE minted chain proves the minter is
//      faithful, so a negative result means the check fired, not that minting broke.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import {
  readNode,
  children,
  parseCertificate,
  verifyCertChainToAnchor,
  bytesEqual,
  OID_EKU_TIMESTAMPING,
  base64ToBytes,
  Asn1Error,
  type X509Cert,
  type ChainAnchor,
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

// --- Real-cert parsing -----------------------------------------------------

test('parseCertificate: extracts the signing cert (EKU timestamping, validity, leaf)', () => {
  const { buf, nodes } = tokenCertNodes();
  const certs = nodes.map((n) => parseCertificate(buf, n));
  const leaf = certs.find((c) => c.ekus.includes(OID_EKU_TIMESTAMPING));
  assert.ok(leaf, 'a signing cert with EKU id-kp-timeStamping is present');
  assert.equal(leaf!.isCA, false, 'the leaf is not a CA');
  assert.ok(leaf!.notBefore < leaf!.notAfter, 'validity window is well-ordered');
  assert.equal(leaf!.spkiDer.length, 120, 'EC P-384 SPKI');
  assert.equal(leaf!.keyCertSign, false, 'the leaf does not assert keyCertSign');
  assert.equal(leaf!.sigAlgConsistent, true, 'inner == outer signature algorithm');
  assert.equal(leaf!.hasUnknownCriticalExt, false, 'no unrecognized critical extension');

  // The root is self-signed (issuer == subject), a CA, and asserts keyCertSign.
  const root = certs.find((c) => bytesEqual(c.issuerDer, c.subjectDer));
  assert.ok(root, 'a self-signed root is present');
  assert.equal(root!.isCA, true);
  assert.equal(root!.keyCertSign, true, 'the root asserts keyCertSign');
  assert.equal(root!.pathLen, null, 'the FreeTSA root sets no pathLenConstraint');
});

test('parseCertificate: rejects a non-certificate / truncated structure', () => {
  // An INTEGER, not a Certificate SEQUENCE.
  const intNode = Uint8Array.from([0x02, 0x01, 0x07]);
  assert.throws(() => parseCertificate(intNode, readNode(intNode, 0)), Asn1Error);
  // A SEQUENCE too short to be a TBSCertificate + algorithm + signature.
  const shortSeq = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);
  assert.throws(() => parseCertificate(shortSeq, readNode(shortSeq, 0)), Asn1Error);
});

// --- Minimal DER encoder (test-only) ---------------------------------------

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const lenBytes = (n: number): Uint8Array => {
  if (n < 0x80) return Uint8Array.of(n);
  const b: number[] = [];
  let v = n;
  while (v > 0) {
    b.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Uint8Array.of(0x80 | b.length, ...b);
};
const tlv = (tag: number, body: Uint8Array): Uint8Array => concat(Uint8Array.of(tag), lenBytes(body.length), body);
const seq = (...kids: Uint8Array[]): Uint8Array => tlv(0x30, concat(...kids));
const setOf = (...kids: Uint8Array[]): Uint8Array => tlv(0x31, concat(...kids));
const ctx = (n: number, body: Uint8Array): Uint8Array => tlv(0xa0 | n, body); // [n] EXPLICIT/constructed
const nullDer = (): Uint8Array => tlv(0x05, new Uint8Array(0));
const boolDer = (v: boolean): Uint8Array => tlv(0x01, Uint8Array.of(v ? 0xff : 0x00));
const octet = (body: Uint8Array): Uint8Array => tlv(0x04, body);
const bitStr = (bytes: Uint8Array, unused = 0): Uint8Array => tlv(0x03, concat(Uint8Array.of(unused), bytes));
const intDer = (n: number): Uint8Array => {
  if (n === 0) return tlv(0x02, Uint8Array.of(0));
  const b: number[] = [];
  let v = n;
  while (v > 0) {
    b.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (b[0] & 0x80) b.unshift(0); // keep it non-negative
  return tlv(0x02, Uint8Array.from(b));
};
const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));
const oidDer = (dotted: string): Uint8Array => {
  const parts = dotted.split('.').map(Number);
  const body: number[] = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const groups = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) {
      groups.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    body.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(body));
};
const nameDer = (cn: string): Uint8Array =>
  seq(setOf(seq(oidDer('2.5.4.3'), tlv(0x13, ascii(cn))))); // RDNSequence{ CN PrintableString }
const genTimeDer = (ms: number): Uint8Array => {
  const d = new Date(ms);
  const p = (x: number, n = 2) => String(x).padStart(n, '0');
  const s = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, ascii(s)); // GeneralizedTime
};

const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
const OID_RSA_SHA512 = '1.2.840.113549.1.1.13';
const algId = (oid: string): Uint8Array => seq(oidDer(oid), nullDer());

// keyUsage values (DER BIT STRING content body, with the unused-bit count handled by
// the caller). keyCertSign is bit 5 (0x04); digitalSignature is bit 0 (0x80).
const KU_KEYCERTSIGN = { bytes: Uint8Array.of(0x84), unused: 2 }; // digitalSignature + keyCertSign
const KU_DIGITALSIG_ONLY = { bytes: Uint8Array.of(0x80), unused: 7 }; // digitalSignature only

interface MintOpts {
  subjectCN: string;
  issuerCN: string;
  subjectKey: KeyObject; // public key whose SPKI goes in the cert
  issuerPrivateKey: KeyObject; // key that signs the cert
  notBefore: number;
  notAfter: number;
  isCA?: boolean;
  keyUsage?: { bytes: Uint8Array; unused: number };
  pathLen?: number; // basicConstraints pathLenConstraint
  ekus?: string[];
  ekuCritical?: boolean;
  /** Add an unrecognized CRITICAL extension (check (a)). */
  unknownCriticalExtOid?: string;
  /** Force the inner TBS signature algorithm to differ from the outer (check (d)). */
  innerAlgOid?: string;
}

/** Mint a signed X.509 cert per opts and return it PARSED (DER round-trips through
 *  the production parser, so the test exercises real parse + verify paths). */
function mint(opts: MintOpts): X509Cert {
  const exts: Uint8Array[] = [];
  if (opts.isCA !== undefined || opts.pathLen !== undefined) {
    const bc: Uint8Array[] = [];
    if (opts.isCA) bc.push(boolDer(true));
    if (opts.pathLen !== undefined) bc.push(intDer(opts.pathLen));
    exts.push(seq(oidDer('2.5.29.19'), boolDer(true), octet(seq(...bc)))); // basicConstraints, critical
  }
  if (opts.keyUsage) {
    exts.push(
      seq(oidDer('2.5.29.15'), boolDer(true), octet(bitStr(opts.keyUsage.bytes, opts.keyUsage.unused))),
    );
  }
  if (opts.ekus && opts.ekus.length) {
    const ekuSeq = seq(...opts.ekus.map(oidDer));
    exts.push(
      opts.ekuCritical
        ? seq(oidDer('2.5.29.37'), boolDer(true), octet(ekuSeq))
        : seq(oidDer('2.5.29.37'), octet(ekuSeq)),
    );
  }
  if (opts.unknownCriticalExtOid) {
    exts.push(seq(oidDer(opts.unknownCriticalExtOid), boolDer(true), octet(nullDer())));
  }

  const spki = new Uint8Array(opts.subjectKey.export({ type: 'spki', format: 'der' }));
  const innerAlg = algId(opts.innerAlgOid ?? OID_RSA_SHA256);
  const outerAlg = algId(OID_RSA_SHA256);
  const tbs = seq(
    ctx(0, intDer(2)), // version v3
    intDer(1), // serialNumber
    innerAlg,
    nameDer(opts.issuerCN),
    seq(genTimeDer(opts.notBefore), genTimeDer(opts.notAfter)),
    nameDer(opts.subjectCN),
    spki,
    ctx(3, seq(...exts)), // extensions [3] EXPLICIT
  );
  const sig = new Uint8Array(nodeSign('sha256', tbs, opts.issuerPrivateKey)); // RSASSA-PKCS1-v1.5
  const certDer = seq(tbs, outerAlg, bitStr(sig));
  return parseCertificate(certDer, readNode(certDer, 0));
}

// One RSA keypair pool, generated once (keygen dominates test time otherwise).
const rsa = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const rootKp = rsa();
const intKp = rsa();
const leafKp = rsa();
const strangerKp = rsa();

const NOW = Date.UTC(2026, 0, 1);
const YEAR = 365 * 24 * 60 * 60 * 1000;
const anchorOf = (kp: ReturnType<typeof rsa>, name = 'test-root'): ChainAnchor => ({
  name,
  rootKeyDer: Buffer.from(kp.publicKey.export({ type: 'spki', format: 'der' })).toString('base64'),
});

/** A proper self-signed root: CA, keyCertSign, valid now. */
function makeRoot(over: Partial<MintOpts> = {}): X509Cert {
  return mint({
    subjectCN: 'test-root',
    issuerCN: 'test-root',
    subjectKey: rootKp.publicKey,
    issuerPrivateKey: rootKp.privateKey,
    notBefore: NOW - YEAR,
    notAfter: NOW + YEAR,
    isCA: true,
    keyUsage: KU_KEYCERTSIGN,
    ...over,
  });
}
/** A proper end-entity leaf signed by the root, EKU id-kp-timeStamping. */
function makeLeaf(over: Partial<MintOpts> = {}): X509Cert {
  return mint({
    subjectCN: 'test-leaf',
    issuerCN: 'test-root',
    subjectKey: leafKp.publicKey,
    issuerPrivateKey: rootKp.privateKey,
    notBefore: NOW - YEAR,
    notAfter: NOW + YEAR,
    isCA: false,
    keyUsage: KU_DIGITALSIG_ONLY,
    ekus: [OID_EKU_TIMESTAMPING],
    ekuCritical: true,
    ...over,
  });
}

// --- Strict chain verification: POSITIVE baseline --------------------------

test('verifyCertChainToAnchor: a well-formed minted chain verifies to the pinned root', async () => {
  const root = makeRoot();
  const leaf = makeLeaf();
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.anchorName, 'test-root');
  assert.equal(r.reason, undefined);
});

// --- Strict chain verification: FAIL-CLOSED negatives ----------------------

test('(a) a cert carrying an UNKNOWN CRITICAL extension is rejected', async () => {
  const root = makeRoot();
  const leaf = makeLeaf({ unknownCriticalExtOid: '1.2.3.4.5.6.7.8' });
  assert.equal(leaf.hasUnknownCriticalExt, true, 'parser flags the unknown critical ext');
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unsupported_critical_extension');
});

test('(b) an issuer WITHOUT keyCertSign is not trusted to sign certs', async () => {
  const root = makeRoot({ keyUsage: KU_DIGITALSIG_ONLY }); // CA, but no keyCertSign
  const leaf = makeLeaf();
  assert.equal(root.isCA, true);
  assert.equal(root.keyCertSign, false, 'parser sees no keyCertSign');
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'issuer_not_ca');
});

test('(b) an issuer that is NOT a CA is not trusted to sign certs', async () => {
  const root = makeRoot({ isCA: false }); // keyCertSign present, but cA:FALSE
  const leaf = makeLeaf();
  assert.equal(root.isCA, false);
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'issuer_not_ca');
});

test('(c) basicConstraints pathLenConstraint is enforced down the chain', async () => {
  // root(pathLen=0) -> intermediate(CA) -> leaf : one intermediate beneath a pathLen=0
  // root violates the constraint.
  const root = makeRoot({ pathLen: 0 });
  const intermediate = mint({
    subjectCN: 'test-int',
    issuerCN: 'test-root',
    subjectKey: intKp.publicKey,
    issuerPrivateKey: rootKp.privateKey,
    notBefore: NOW - YEAR,
    notAfter: NOW + YEAR,
    isCA: true,
    keyUsage: KU_KEYCERTSIGN,
  });
  const leaf = makeLeaf({ issuerCN: 'test-int', issuerPrivateKey: intKp.privateKey });
  assert.equal(root.pathLen, 0, 'parser reads pathLenConstraint=0');
  const r = await verifyCertChainToAnchor([leaf, intermediate, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'path_len_exceeded');
});

test('(c) the SAME chain with adequate pathLen=1 verifies (constraint is exact, not blanket)', async () => {
  const root = makeRoot({ pathLen: 1 });
  const intermediate = mint({
    subjectCN: 'test-int',
    issuerCN: 'test-root',
    subjectKey: intKp.publicKey,
    issuerPrivateKey: rootKp.privateKey,
    notBefore: NOW - YEAR,
    notAfter: NOW + YEAR,
    isCA: true,
    keyUsage: KU_KEYCERTSIGN,
  });
  const leaf = makeLeaf({ issuerCN: 'test-int', issuerPrivateKey: intKp.privateKey });
  const r = await verifyCertChainToAnchor([leaf, intermediate, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, true, r.reason);
});

test('(d) inner != outer signature AlgorithmIdentifier is rejected (anti-substitution)', async () => {
  const root = makeRoot();
  const leaf = makeLeaf({ innerAlgOid: OID_RSA_SHA512 }); // outer stays sha256 — the real sig still verifies
  assert.equal(leaf.sigAlgConsistent, false, 'parser detects the inner/outer mismatch');
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'algorithm_mismatch');
});

test('an EXPIRED cert in the path fails closed (genTime outside validity)', async () => {
  const root = makeRoot();
  const leaf = makeLeaf({ notBefore: NOW - 2 * YEAR, notAfter: NOW - YEAR }); // expired before NOW
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'genTime_outside_validity');
});

test('a chain whose root is NOT a pinned anchor fails (untrusted_root)', async () => {
  const root = makeRoot();
  const leaf = makeLeaf();
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [], NOW); // no anchors
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'untrusted_root');
});

test('a link signed by the WRONG key fails closed (link_signature_invalid)', async () => {
  const root = makeRoot();
  const leaf = makeLeaf({ issuerPrivateKey: strangerKp.privateKey }); // signed by a stranger, not the root
  const r = await verifyCertChainToAnchor([leaf, root], leaf, [anchorOf(rootKp)], NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'link_signature_invalid');
});

test('a missing issuer (leaf with no matching CA) fails closed (issuer_not_found)', async () => {
  const root = makeRoot();
  const leaf = makeLeaf();
  const r = await verifyCertChainToAnchor([leaf], leaf, [anchorOf(rootKp)], NOW); // root omitted
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'issuer_not_found');
});

// --- EKU surface the RFC 3161 leaf-selection relies on (non-timestamping) ---

test('parseCertificate: a NON-timestamping leaf does not expose the timestamping EKU', () => {
  const leaf = makeLeaf({ ekus: ['1.3.6.1.5.5.7.3.1'], ekuCritical: true }); // id-kp-serverAuth
  assert.equal(leaf.ekus.includes(OID_EKU_TIMESTAMPING), false);
  assert.deepEqual(leaf.ekus, ['1.3.6.1.5.5.7.3.1']);
  // and the timestamping leaf does expose it (the gate RFC 3161 selection uses).
  assert.equal(makeLeaf().ekus.includes(OID_EKU_TIMESTAMPING), true);
});
