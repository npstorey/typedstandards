// Derived golden cases (typedstandards#113, G0 D11) and their round trip under
// verify-core.
//
// `__fixtures__/derived-golden.json` holds cases no reference implementation
// emits, so none could be captured: the four ruled sub-types, `vcsRef`, and
// raw-bytes/v1 over a BlobRef. Each takes one captured case of
// `reference-golden.json` as its base and changes only what its `change` lists;
// each names the specification row it follows. Its expected bytes were written by
// hand from that row (the fixture's `_meta.derivation` says how), not produced by
// produce-core or by verify-core's canonicalizer.
//
// The load-bearing checks:
//   - every hash in the fixture is recomputed here from the hand-written strings
//     with node:crypto SHA-256 alone;
//   - the hand-written canonical strings of the two base cases hash to the
//     reference implementation's captured content hash and nodeId / envelope hash;
//   - produce-core's output canonicalizes to exactly the hand-written strings and
//     yields exactly those hashes;
//   - `reference-golden.json` is byte-identical: its SHA-256 is pinned below.
// The captured cases themselves are asserted, unedited, by
// `reference-golden.test.ts` and the CLI's `golden.test.ts`, which this file
// keeps the derived cases out of.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  jcs,
  checkAttestationNode,
  verifyLifecycleChain,
  verifyRecord,
  type CarriedLifecycleNode,
  type FetchLike,
  type TrustRegistry,
  type VerifySignatureEnvelope,
} from '@typedstandards/verify-core';
import {
  buildAttestationNode,
  buildEnvelope,
  signEnvelopeHash,
  type AttestationInput,
  type EnvelopeInput,
  type SignerIdentity,
} from './index.ts';

/** SHA-256 of `reference-golden.json` at typedstandards e9d5487 (the P2 base). */
const REFERENCE_GOLDEN_SHA256 = 'd2bcfc2bc017b07502b3b00c3aa16de402df134128a374b4582650b79fb501c1';

const sha256Hex = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');

const referenceBytes = readFileSync(new URL('./__fixtures__/reference-golden.json', import.meta.url));

interface CapturedCase {
  name: string;
  input: Record<string, unknown>;
  expected: { contentHashSha256: string | null; envelopeHash?: string; nodeId?: string };
}
const reference = JSON.parse(referenceBytes.toString('utf8')) as {
  envelopeCases: CapturedCase[];
  attestationCases: CapturedCase[];
};

interface DerivedCase {
  name: string;
  kind: 'attestation' | 'envelope';
  baseCase: string;
  specRow: string;
  change: { set: Record<string, unknown>; remove: string[] };
  expected: {
    jcsWithoutContentHash: string;
    jcsWithContentHash: string;
    contentHashSha256: string;
    contentBytesUtf8?: string;
    nodeId?: string;
    envelopeHash?: string;
  };
}
const derived = JSON.parse(
  readFileSync(new URL('./__fixtures__/derived-golden.json', import.meta.url), 'utf8'),
) as {
  _meta: {
    baseFixture: string;
    baseFixtureSha256: string;
    baseCanonical: Array<{ baseCase: string; jcsWithoutContentHash: string; jcsWithContentHash: string }>;
  };
  derivedCases: DerivedCase[];
};

const capturedCase = (name: string): CapturedCase => {
  const c = [...reference.envelopeCases, ...reference.attestationCases].find((x) => x.name === name);
  assert.ok(c, `captured case ${name}`);
  return c;
};
const byName = (name: string): DerivedCase => {
  const c = derived.derivedCases.find((x) => x.name === name);
  assert.ok(c, `derived case ${name}`);
  return c;
};

/** The derived input: the base case's input with `change` applied, nothing else. */
function derivedInput(c: DerivedCase): Record<string, unknown> {
  const input = structuredClone(capturedCase(c.baseCase).input);
  for (const key of c.change.remove) delete input[key];
  return { ...input, ...structuredClone(c.change.set) };
}

/** Build a derived case with produce-core; a throw fails at an assertion. */
function produce(c: DerivedCase): { built: Record<string, unknown>; hash: string } {
  let out: { built: Record<string, unknown>; hash: string } | undefined;
  assert.doesNotThrow(() => {
    if (c.kind === 'attestation') {
      const { node, nodeId } = buildAttestationNode(derivedInput(c) as unknown as AttestationInput);
      out = { built: node as unknown as Record<string, unknown>, hash: nodeId };
    } else {
      const { pkg, envelopeHash } = buildEnvelope(derivedInput(c) as unknown as EnvelopeInput);
      out = { built: pkg as unknown as Record<string, unknown>, hash: envelopeHash };
    }
  }, `${c.name}: produce-core builds it`);
  return out!;
}

const expectedHash = (c: DerivedCase) => (c.kind === 'attestation' ? c.expected.nodeId : c.expected.envelopeHash);

// --- The captured fixture is untouched ---

test('reference-golden.json is byte-identical to the P2 base', () => {
  assert.equal(sha256Hex(referenceBytes), REFERENCE_GOLDEN_SHA256);
  assert.equal(derived._meta.baseFixture, 'reference-golden.json');
  assert.equal(derived._meta.baseFixtureSha256, REFERENCE_GOLDEN_SHA256);
});

// --- The hand-written base strings reproduce the reference capture ---

for (const b of derived._meta.baseCanonical) {
  test(`hand-written base [${b.baseCase}]: its SHA-256 values are the captured content hash and nodeId / envelope hash`, () => {
    const c = capturedCase(b.baseCase);
    assert.equal(sha256Hex(b.jcsWithoutContentHash), c.expected.contentHashSha256);
    assert.equal(sha256Hex(b.jcsWithContentHash), c.expected.nodeId ?? c.expected.envelopeHash);
  });
}

// --- Fixture discipline: every derived case is attributed and self-consistent ---

test('derived fixture: the minimum set is present, each case naming a captured base and its spec row', () => {
  const names = derived.derivedCases.map((c) => c.name);
  for (const n of ['supersedes', 'revises', 'contradicts', 'corroborates', 'corroborates-minimal', 'v01-vcsref', 'v01-vcsref-minimal', 'v01-raw-bytes-blobref']) {
    assert.ok(names.includes(n), `missing derived case ${n}`);
  }
  assert.equal(new Set(names).size, names.length, 'names are unique');
  for (const c of derived.derivedCases) {
    capturedCase(c.baseCase);
    assert.match(c.specRow, /SPEC|ADR-0016/, `${c.name}: names its spec row`);
  }
});

test('derived fixture: each case changes only the sub-type and payload, vcsRef, or the rule and output', () => {
  const allowed = {
    attestation: { set: ['type', 'successorNodeId', 'scope', 'reasoning'], remove: ['reason'] },
    envelope: { set: ['vcsRef', 'contentCanonicalization', 'output'], remove: [] as string[] },
  };
  for (const c of derived.derivedCases) {
    for (const k of Object.keys(c.change.set)) assert.ok(allowed[c.kind].set.includes(k), `${c.name}: sets ${k}`);
    for (const k of c.change.remove) assert.ok(allowed[c.kind].remove.includes(k), `${c.name}: removes ${k}`);
  }
  // The four sub-types are based on the captured withdraws case; the envelope
  // cases on v01-default, and the BlobRef case takes legacy-blobref-output's BlobRef.
  for (const n of ['supersedes', 'revises', 'contradicts', 'corroborates', 'corroborates-minimal']) {
    assert.equal(byName(n).baseCase, 'withdraws', n);
  }
  for (const n of ['v01-vcsref', 'v01-vcsref-minimal', 'v01-raw-bytes-blobref']) {
    assert.equal(byName(n).baseCase, 'v01-default', n);
  }
  assert.deepEqual(byName('v01-raw-bytes-blobref').change.set['output'], capturedCase('legacy-blobref-output').input['output']);
});

for (const c of derived.derivedCases) {
  test(`derived fixture [${c.name}]: node:crypto recomputes both hashes from the hand-written strings`, () => {
    const e = c.expected;
    const hash = expectedHash(c);
    assert.ok(hash, `${c.name}: names its nodeId or envelopeHash`);
    // The with-contentHash string is the without string plus the contentHash
    // member, inserted after contentCanonicalization (the first key).
    const prefix = e.jcsWithoutContentHash.slice(0, e.jcsWithoutContentHash.indexOf('",') + 2);
    assert.ok(prefix.startsWith('{"contentCanonicalization":"'), `${c.name}: contentCanonicalization sorts first`);
    assert.equal(
      e.jcsWithContentHash,
      `${prefix}"contentHash":{"sha256":"${e.contentHashSha256}"},${e.jcsWithoutContentHash.slice(prefix.length)}`,
      `${c.name}: the two strings differ only by contentHash`,
    );
    if (e.contentBytesUtf8 === undefined) {
      // legacy-json/v1: the content hash is the SHA-256 of the package minus contentHash.
      assert.equal(sha256Hex(e.jcsWithoutContentHash), e.contentHashSha256, `${c.name}: content hash`);
    } else {
      // raw-bytes/v1 over a BlobRef: the SHA-256 of the referenced bytes, which is
      // the hex part of output.ref.
      assert.equal(sha256Hex(Buffer.from(e.contentBytesUtf8, 'utf8')), e.contentHashSha256, `${c.name}: content hash`);
      const ref = (c.change.set['output'] as { ref: string }).ref;
      assert.equal(ref, `blob:sha256:${e.contentHashSha256}`, `${c.name}: the ref's hex`);
    }
    assert.equal(sha256Hex(e.jcsWithContentHash), hash, `${c.name}: nodeId / envelope hash`);
  });
}

// --- produce-core emits exactly the hand-written bytes ---

for (const c of derived.derivedCases) {
  test(`derived golden [${c.name}]: produce-core canonicalizes to the hand-written strings and yields their hashes`, () => {
    const { built, hash } = produce(c);
    const { contentHash, ...withoutContentHash } = built;
    assert.equal(jcs(withoutContentHash), c.expected.jcsWithoutContentHash, `${c.name}: canonical JSON without contentHash`);
    assert.equal(jcs(built), c.expected.jcsWithContentHash, `${c.name}: canonical JSON`);
    assert.equal((contentHash as { sha256?: string } | undefined)?.sha256, c.expected.contentHashSha256, `${c.name}: content hash`);
    assert.equal(hash, expectedHash(c), `${c.name}: nodeId / envelope hash`);
  });
}

// --- Round trip: each derived node or package, signed with a test key, verifies ---

const SEED = Uint8Array.from({ length: 32 }, (_u, i) => (i * 29 + 3) & 0xff);
const KID = 'adopter:test-key-1';
const TARGET = 'a'.repeat(64);

function signedNode(name: string): CarriedLifecycleNode & { signer: SignerIdentity } {
  const c = byName(name);
  const { built, hash } = produce(c);
  const sig = signEnvelopeHash(hash, SEED, KID);
  return { node: built, nodeId: hash, signature: { ...sig }, signer: built['signer'] as SignerIdentity };
}

const publicKey = () => signEnvelopeHash('0'.repeat(64), SEED, KID).publicKey;

/** A registry fetched from its declared URL, listing the test key under the
 *  captured signer: what binds a non-key-derived identifier for any-with-binding. */
function registryFor(signer: SignerIdentity): TrustRegistry {
  return {
    keys: [
      {
        kid: KID,
        publicKey: publicKey(),
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: signer,
      },
    ],
  };
}

for (const name of ['supersedes', 'revises']) {
  test(`round trip [${name}]: checkAttestationNode reads it authorized under publisher-only, every required field present`, () => {
    const n = signedNode(name);
    const check = checkAttestationNode(n, { target: { signerIdentifier: n.signer.identifier as string, publicKey: publicKey() } });
    assert.deepEqual(check.missingFields, [], `${name}: missing fields`);
    assert.equal(check.rule, 'publisher-only');
    assert.equal(check.nodeIdMatches, true);
    assert.equal(check.signatureValid, true);
    assert.equal(check.status, 'authorized');
  });
}

for (const name of ['corroborates', 'corroborates-minimal', 'contradicts']) {
  test(`round trip [${name}]: checkAttestationNode reads it authorized under any-with-binding, every required field present`, () => {
    const n = signedNode(name);
    const check = checkAttestationNode(n, { registry: registryFor(n.signer), registryProvenance: 'declared-url' });
    assert.deepEqual(check.missingFields, [], `${name}: missing fields`);
    assert.equal(check.rule, 'any-with-binding');
    assert.equal(check.keyBound, true);
    assert.equal(check.status, 'authorized');
  });
}

test('round trip [supersedes]: signed by the target\'s own key, it makes the target superseded and names the successor', () => {
  const n = signedNode('supersedes');
  const r = verifyLifecycleChain([n], TARGET, n.signer.identifier as string, { targetPublicKey: publicKey() });
  assert.equal(r.status, 'superseded');
  assert.equal(r.successorNodeId, 'b'.repeat(64));
  assert.equal(r.supersededAt, '2026-01-02T03:04:05.000Z');
  assert.equal(r.chain.length, 1);
  assert.equal(r.chain[0]?.signerMatchesTarget, true);
});

test('round trip [revises]: signed by the target\'s own key, it is in the chain and changes no status', () => {
  const n = signedNode('revises');
  const r = verifyLifecycleChain([n], TARGET, n.signer.identifier as string, { targetPublicKey: publicKey() });
  assert.equal(r.chain.length, 1);
  assert.equal(r.chain[0]?.type, 'attestation/revises/v1');
  assert.equal(r.chain[0]?.successorNodeId, 'c'.repeat(64));
  assert.equal(r.chain[0]?.signerMatchesTarget, true);
  assert.equal(r.status, 'active');
  assert.equal(r.successorNodeId, undefined);
});

test('round trip [claim-to-claim]: corroborates and contradicts move no lifecycle status', () => {
  const nodes = ['corroborates', 'corroborates-minimal', 'contradicts'].map(signedNode);
  const r = verifyLifecycleChain(nodes, TARGET, nodes[0]!.signer.identifier as string, { targetPublicKey: publicKey() });
  assert.deepEqual(r.chain, []);
  assert.equal(r.status, 'active');
});

/** A fetcher that answers one URL with the given bytes and throws on any other. */
function fetchOnly(url: string, body: Uint8Array): FetchLike & { calls: string[] } {
  const calls: string[] = [];
  const f: FetchLike = async (u) => {
    calls.push(u);
    if (u !== url) throw new Error(`offline round trip: no fetch of ${u}`);
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => JSON.parse(new TextDecoder().decode(body)) as unknown,
      text: async () => new TextDecoder().decode(body),
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
    };
  };
  return Object.assign(f, { calls });
}

const offline: FetchLike = async (u) => {
  throw new Error(`offline round trip: no fetch of ${u}`);
};

async function verifyPackage(name: string, fetch: FetchLike) {
  const c = byName(name);
  const { built, hash } = produce(c);
  const sig = signEnvelopeHash(hash, SEED, KID);
  const stored = JSON.parse(JSON.stringify(built)) as Record<string, unknown>;
  const registry: TrustRegistry = {
    keys: [{ kid: KID, publicKey: sig.publicKey, status: 'active', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: null, revokedAt: null }],
  };
  const result = await verifyRecord(
    { package: stored, packageHash: hash, signature: sig as unknown as VerifySignatureEnvelope },
    { registry, fetch },
  );
  return { built, hash, result };
}

for (const name of ['v01-vcsref', 'v01-vcsref-minimal']) {
  test(`round trip [${name}]: verifyRecord verifies the signed package, vcsRef under the envelope hash`, async () => {
    const { built, hash, result } = await verifyPackage(name, offline);
    assert.deepEqual(built['vcsRef'], byName(name).change.set['vcsRef'], `${name}: vcsRef in the package`);
    assert.equal(result.hashMatch, true, '#1');
    assert.deepEqual(result.envelopeIntegrity, { status: 'verified' }, '#1');
    assert.equal(result.signatureValid, true, '#2');
    assert.equal(result.contentHash?.status, 'ok', '#4');
    assert.equal(result.keyTrust?.verified, true, '#5');
    assert.equal(result.nodeId, hash, '#13');
  });
}

test('round trip [v01-raw-bytes-blobref]: verifyRecord verifies it, hashing the referenced bytes from its fetcher', async () => {
  const c = byName('v01-raw-bytes-blobref');
  const blob = c.change.set['output'] as { url: string };
  const bytes = new TextEncoder().encode(c.expected.contentBytesUtf8);
  const fetch = fetchOnly(blob.url, bytes);
  const { result } = await verifyPackage(c.name, fetch);
  assert.equal(result.hashMatch, true, '#1');
  assert.equal(result.signatureValid, true, '#2');
  assert.equal(result.contentCanonicalization?.status, 'ok', '#3');
  assert.equal(result.contentHash?.status, 'ok', '#4');
  assert.equal(result.blobRefsVerified, true, '#9');
  assert.ok(fetch.calls.includes(blob.url), 'the referenced bytes came through the fetcher');

  // Other bytes at the same URL do not verify.
  const wrong = await verifyPackage(c.name, fetchOnly(blob.url, new TextEncoder().encode('Content')));
  assert.notEqual(wrong.result.contentHash?.status, 'ok');
});
