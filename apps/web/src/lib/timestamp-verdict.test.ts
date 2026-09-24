// #94, ruling D1 as amended (sprint #98): a timestamp token that does not verify for
// this package fails the package; a token whose only fault is this verifier's policy
// (an authority it does not pin, intermediates it lacks, an algorithm it does not
// check) is a caveat; a fully verified token stays green; an absent token stays calm.
//
// Every token here is derived at test time from a real FreeTSA token, the way
// verify-core's `rfc3161.test.ts` derives its cases (sprint #98 P1b); nothing new is
// committed as a fixture:
//   - the token captured in `__fixtures__/q15-d67b8e.json`, run through the whole
//     page in URL mode (the Q15 online test's route), so `verifyRecord` itself
//     evaluates the edited token and the page reads it;
//   - verify-core's `__fixtures__/rfc3161-token.json`, under a content-private
//     commitment whose `packageHash` is the hash that token covers.
// A chain that reaches no pinned anchor cannot be driven through `verifyRecord`, which
// always uses the pinned set; that case is `verifyRfc3161Timestamp(token, hash, [])`,
// a real verify-core result, placed in the result of a real run.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import {
  verifyRfc3161Timestamp,
  RFC3161_FAIL_REASONS,
  readNode,
  children,
  parseCertificate,
  OID_EKU_TIMESTAMPING,
  type VerifyResult,
  type EnvelopeIntegrityResult,
} from '@typedstandards/verify-core';
import {
  resolveInput,
  buildVerifyInput,
  runVerify,
  resolveCarriedLifecycle,
  presentVerification,
  rollupVerdict,
  buildCheckRows,
  registryMetaOf,
  HOST_DIRECTORY,
  type CheckRow,
  type RegistryMeta,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

// --- Token derivations (as verify-core's rfc3161.test.ts) ------------------------

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const tokenBytes = (tokenB64: string): Uint8Array => new Uint8Array(Buffer.from(tokenB64, 'base64'));

/** TimeStampResp -> ContentInfo -> SignedData's children. */
function signedDataKids(buf: Uint8Array) {
  const ci = children(buf, children(buf, readNode(buf, 0))[1]);
  return children(buf, children(buf, ci[1])[0]);
}

/** The embedded certificate nodes. */
function certNodes(buf: Uint8Array) {
  return children(buf, signedDataKids(buf).find((c) => c.tag === 0xa0)!);
}

/** The [notBefore, notAfter] UTCTime nodes of a certificate node. */
function validityOf(buf: Uint8Array, certNode: ReturnType<typeof readNode>) {
  const tbs = children(buf, children(buf, certNode)[0]);
  const validity = tbs.find((k) => {
    if (k.tag !== 0x30) return false;
    const kk = children(buf, k);
    return kk.length === 2 && kk[0].tag === 0x17 && kk[1].tag === 0x17;
  })!;
  return children(buf, validity);
}

function writeUtcTime(buf: Uint8Array, node: ReturnType<typeof readNode>, utcTime: string): void {
  assert.equal(node.contentEnd - node.contentStart, utcTime.length);
  buf.set(Uint8Array.from(utcTime, (c) => c.charCodeAt(0)), node.contentStart);
}

/** The last byte flipped: a byte inside the trailing ECDSA signature. */
function withForgedSignature(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  raw[raw.length - 1] ^= 0xff;
  return b64(raw);
}

/** The timestamping leaf's notBefore rewritten. The TSA signature covers signedAttrs,
 *  not the embedded certificates, so it still verifies; the root's signature over the
 *  leaf no longer does. */
function withLeafNotBefore(tokenB64: string, utcTime: string): string {
  const raw = tokenBytes(tokenB64);
  const leaf = certNodes(raw).find((n) => parseCertificate(raw, n).ekus.includes(OID_EKU_TIMESTAMPING))!;
  writeUtcTime(raw, validityOf(raw, leaf)[0], utcTime);
  return b64(raw);
}

/** The embedded root's notAfter rewritten: no signature the verifier checks covers it. */
function withRootNotAfter(tokenB64: string, utcTime: string): string {
  const raw = tokenBytes(tokenB64);
  const root = certNodes(raw).find((n) => {
    const c = parseCertificate(raw, n);
    return c.issuerDer.length === c.subjectDer.length && c.issuerDer.every((b, i) => b === c.subjectDer[i]);
  })!;
  writeUtcTime(raw, validityOf(raw, root)[1], utcTime);
  return b64(raw);
}

/** The leaf's namedCurve OID moved from secp384r1 to secp521r1: a key outside the set
 *  this verifier checks. */
function withLeafCurveSecp521r1(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const leaf = certNodes(raw)
    .map((n) => parseCertificate(raw, n))
    .find((c) => c.ekus.includes(OID_EKU_TIMESTAMPING))!;
  const spki = leaf.spkiDer;
  let at = -1;
  for (let i = 0; i + spki.length <= raw.length && at < 0; i++) {
    if (spki.every((b, k) => raw[i + k] === b)) at = i;
  }
  assert.ok(at >= 0, 'the leaf SPKI is found in the token');
  assert.deepEqual([...raw.slice(at + 13, at + 20)], [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
  raw[at + 19] = 0x23;
  return b64(raw);
}

/** The timestamping leaf's signature algorithm, inner and outer, moved from
 *  sha512WithRSAEncryption to sha1WithRSAEncryption: a link algorithm the chain validator
 *  does not implement (#100). The TSA signature still verifies. */
function withLeafSignatureAlgorithmSha1(tokenB64: string): string {
  const raw = tokenBytes(tokenB64);
  const leaf = certNodes(raw).find((n) => parseCertificate(raw, n).ekus.includes(OID_EKU_TIMESTAMPING))!;
  const [tbs, outerAlg] = children(raw, leaf);
  const tbsKids = children(raw, tbs);
  for (const alg of [tbsKids[tbsKids[0].tag === 0xa0 ? 2 : 1], outerAlg]) {
    const oid = children(raw, alg)[0];
    assert.equal(raw[oid.contentEnd - 1], 0x0d);
    raw[oid.contentEnd - 1] = 0x05;
  }
  return b64(raw);
}

// The captured leaf is valid 2026-02-15 .. 2040-02-02; the d67b8e token's genTime is
// 2026-05-29 and the rfc3161-token.json token's 2026-06-07.
const LEAF_ONE_YEAR_EARLIER = '250215194422Z'; // still valid at genTime; the link breaks
const LEAF_NOT_YET_VALID = '270101000000Z'; // after genTime
const ROOT_LAPSED = '260101000000Z'; // before genTime

// --- The page, for a captured bundle verified by URL ----------------------------

type Bundle = Record<string, unknown> & {
  packageHash: string;
  rfc3161Timestamp: string;
  trustRegistryUrl: string;
  trustRegistry: unknown;
};
const captured = JSON.parse(
  readFileSync(new URL('./__fixtures__/q15-d67b8e.json', import.meta.url), 'utf8'),
) as Bundle;

/** Serve `routes` (URL → JSON body); anything else 404s. Returns the restore function. */
function serve(routes: Record<string, unknown>): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    return Promise.resolve(
      u in routes
        ? new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }),
    );
  }) as typeof globalThis.fetch;
  return () => {
    globalThis.fetch = real;
  };
}

interface Page {
  result: VerifyResult;
  meta: RegistryMeta;
  rows: CheckRow[];
  verdict: ReturnType<typeof rollupVerdict>;
}

/** Verify `commitment` by URL, its registry fetched from the declared https: URL, and
 *  read the page as the <Verifier> does. */
async function pageByUrl(commitment: Record<string, unknown>, registryUrl: string, registry: unknown): Promise<Page> {
  const url = `${new URL(registryUrl).origin}/api/records/p2-timestamp/commitment`;
  const restore = serve({ [url]: commitment, [registryUrl]: registry, [HOST_DIRECTORY_PATH]: HOST_DIRECTORY });
  try {
    const resolved = await resolveInput('url', url);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, resolveCarriedLifecycle(resolved.commitment), resolved.registryProvenance);
    const shown = presentVerification(resolved, vinput, result);
    return { result, meta: registryMetaOf(resolved), rows: shown.rows, verdict: shown.verdict };
  } finally {
    restore();
  }
}

/** The captured record by URL, carrying `token` in place of its own. */
function capturedWith(token: string): Promise<Page> {
  const hosted: Record<string, unknown> = { ...captured, rfc3161Timestamp: token };
  delete hosted['trustRegistry'];
  return pageByUrl(hosted, captured.trustRegistryUrl, captured.trustRegistry);
}

/** The same page with `rfc3161` replaced by another real verify-core result. */
function withTimestampResult(page: Page, rfc3161: VerifyResult['rfc3161']): Page {
  const result = { ...page.result, rfc3161 };
  const rows = buildCheckRows(result, buildVerifyInput({ packageHash: 'ab'.repeat(32) }, null), { packageHash: 'ab'.repeat(32) }, page.meta);
  return { result, meta: page.meta, rows, verdict: rollupVerdict(result, page.meta) };
}

// --- A content-private record over the rfc3161-token.json token -------------------

const tsFixture = JSON.parse(
  readFileSync(new URL('../../../../packages/verify-core/src/__fixtures__/rfc3161-token.json', import.meta.url), 'utf8'),
) as { tokenB64: string; expectedHashHex: string };

const PRIVATE_REGISTRY_URL = 'https://registry-host.test/trust-registry.json';

/** A content-private commitment (no package, no location) whose `packageHash` is the
 *  hash the fixture token covers, signed over that hash with a key minted here. */
function mintPrivate(token: string) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const kid = 'test:synthetic-2026';
  const packageHash = tsFixture.expectedHashHex;
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [{ kid, publicKey: publicKeyB64, status: 'active', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: null, revokedAt: null }],
  };
  const commitment = {
    protocolVersion: '0.1.0',
    packageHash,
    signature: {
      algorithm: 'Ed25519',
      publicKey: publicKeyB64,
      signature: Buffer.from(nodeSign(null, Buffer.from(packageHash, 'utf8'), privateKey)).toString('base64'),
      kid,
    },
    rfc3161Timestamp: token,
    trustRegistryUrl: PRIVATE_REGISTRY_URL,
  };
  return { commitment, registry };
}

async function privateWith(token: string): Promise<Page> {
  const m = mintPrivate(token);
  return pageByUrl(m.commitment, PRIVATE_REGISTRY_URL, m.registry);
}

// --- Assertions ------------------------------------------------------------------

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

/** The non-green rows, as `num:tier`. */
const notGreen = (rows: CheckRow[]) =>
  rows.filter((r) => r.signal.tier === 'attention' || r.signal.tier === 'alarm').map((r) => `${r.num}:${r.signal.tier}`);

function assertFails(page: Page, label: string): void {
  assert.equal(page.verdict.headline, 'Verification failed', label);
  assert.equal(page.verdict.tier, 'alarm', label);
  assert.equal(rowOf(page.rows, '7').signal.tier, 'alarm', `${label}: the #7 row`);
}

function assertCaveats(page: Page, headline: string, label: string): void {
  assert.equal(page.verdict.headline, headline, label);
  assert.equal(page.verdict.tier, 'attention', label);
  assert.ok(page.verdict.detail.includes('#7 Timestamp'), `${label}: the headline names #7 (${page.verdict.detail})`);
  // The #7 row reads as it did (D1): its tier and label are unchanged.
  assert.equal(rowOf(page.rows, '7').signal.label, 'Timestamp did not verify', label);
}

/** The #7 row says why the token did not verify. */
function assertReasonShown(page: Page, reason: string, label: string): void {
  const line = rowOf(page.rows, '7').math.find((m) => m.label === 'Reason');
  assert.ok(line, `${label}: the #7 row carries its reason`);
  assert.ok(line.value.startsWith(reason), `${label}: ${line.value}`);
}

test('#94 control: the captured record by URL, its own token genuine, reads Verified with #7 green', async () => {
  const page = await capturedWith(captured.rfc3161Timestamp);
  assert.equal(page.result.rfc3161?.verified, true);
  assert.equal(rowOf(page.rows, '7').signal.tier, 'verified');
  assert.deepEqual(notGreen(page.rows), []);
  assert.equal(page.verdict.headline, 'Verified');
  const priv = await privateWith(tsFixture.tokenB64);
  assert.equal(priv.result.rfc3161?.verified, true);
  assert.equal(priv.verdict.headline, 'Commitment verified — content private');
  assert.equal(priv.verdict.tier, 'verified');
});

test('#94 fail: a token bound to this package whose TSA signature does not verify, beneath a chain that reaches no pinned anchor, reads "Verification failed"', async () => {
  const genuine = await capturedWith(captured.rfc3161Timestamp);
  const forged = withForgedSignature(captured.rfc3161Timestamp);
  // anchors = []: the chain reaches no pinned anchor, and the signature is broken.
  const unpinned = await verifyRfc3161Timestamp(forged, captured.packageHash, []);
  assert.equal(unpinned.imprintMatches, true, 'bound to this package');
  assert.equal(unpinned.contentBound, true);
  assert.equal(unpinned.chainVerified, false);
  assert.equal(unpinned.signatureValid, false);
  assert.equal(unpinned.reason, 'signature_invalid');
  assertFails(withTimestampResult(genuine, unpinned), 'forged, anchors = []');

  // Through verifyRecord: the signature broken AND the leaf's link broken.
  const both = await capturedWith(withForgedSignature(withLeafNotBefore(captured.rfc3161Timestamp, LEAF_ONE_YEAR_EARLIER)));
  assert.equal(both.result.rfc3161?.chainVerified, false);
  assert.equal(both.result.rfc3161?.signatureValid, false);
  assert.equal(both.result.rfc3161?.reason, 'signature_invalid');
  assertFails(both, 'forged beneath a broken chain, end to end');

  // Through verifyRecord, the pinned chain intact: the forged signature alone.
  const pinned = await capturedWith(forged);
  assert.equal(pinned.result.rfc3161?.chainVerified, true);
  assert.equal(pinned.result.rfc3161?.reason, 'signature_invalid');
  assertFails(pinned, 'forged, end to end');

  // The content-private branch fails the same way.
  const priv = await privateWith(tsFixture.tokenB64);
  const privForged = await verifyRfc3161Timestamp(withForgedSignature(tsFixture.tokenB64), tsFixture.expectedHashHex, []);
  assert.equal(privForged.reason, 'signature_invalid');
  assertFails(withTimestampResult(priv, privForged), 'content private, forged, anchors = []');
  assertFails(await privateWith(withForgedSignature(tsFixture.tokenB64)), 'content private, forged, end to end');
});

test('#94 fail: a signing certificate not valid at genTime, and a token lifted from another package, read "Verification failed"', async () => {
  const early = await capturedWith(withLeafNotBefore(captured.rfc3161Timestamp, LEAF_NOT_YET_VALID));
  assert.equal(early.result.rfc3161?.withinValidity, false);
  assert.equal(early.result.rfc3161?.reason, 'genTime_outside_validity');
  assertFails(early, 'genTime outside the signing certificate');

  // The rfc3161-token.json token is genuine, but it timestamps another hash.
  const lifted = await capturedWith(tsFixture.tokenB64);
  assert.equal(lifted.result.rfc3161?.reason, 'imprint_mismatch');
  assertFails(lifted, 'a token from another package');
});

test('#94 caveat: a token whose only fault is this verifier’s policy reads caveated, never failed, and the #7 row says why', async () => {
  const genuine = await capturedWith(captured.rfc3161Timestamp);
  // anchors = []: a genuine token from an authority this verifier does not pin.
  const unpinned = await verifyRfc3161Timestamp(captured.rfc3161Timestamp, captured.packageHash, []);
  assert.equal(unpinned.signatureValid, true);
  assert.equal(unpinned.reason, 'untrusted_root');
  const cases: { label: string; page: Page; reason: string }[] = [
    { label: 'unpinned root (anchors = [])', page: withTimestampResult(genuine, unpinned), reason: 'untrusted_root' },
    {
      label: 'a chain link signed with an algorithm the validator does not implement (#100), end to end',
      page: await capturedWith(withLeafSignatureAlgorithmSha1(captured.rfc3161Timestamp)),
      reason: 'chain_algorithm_unsupported',
    },
    {
      label: 'a root not valid at genTime, end to end',
      page: await capturedWith(withRootNotAfter(captured.rfc3161Timestamp, ROOT_LAPSED)),
      reason: 'chain_outside_validity',
    },
    {
      label: 'a signing key outside P-384, end to end',
      page: await capturedWith(withLeafCurveSecp521r1(captured.rfc3161Timestamp)),
      reason: 'unexpected_algorithm',
    },
  ];
  for (const c of cases) {
    assert.equal(c.page.result.rfc3161?.reason, c.reason, c.label);
    assert.notEqual(c.page.verdict.headline, 'Verification failed', c.label);
    assertCaveats(c.page, 'Verified, with caveats', c.label);
    assertReasonShown(c.page, c.reason, c.label);
  }
  // Content private: the same token, anchors = [].
  const priv = await privateWith(tsFixture.tokenB64);
  const privUnpinned = withTimestampResult(
    priv,
    await verifyRfc3161Timestamp(tsFixture.tokenB64, tsFixture.expectedHashHex, []),
  );
  assertCaveats(privUnpinned, 'Commitment verified, with caveats — content private', 'content private, unpinned');
  assertReasonShown(privUnpinned, 'untrusted_root', 'content private, unpinned');
});

// --- The classification, code by code -------------------------------------------

/** The seat's classification (issuecomment-5784230955, applied as the P1b re-gate
 *  record lists it): each reason code fails the package or caveats it. */
const EXPECTED: Record<string, 'fails' | 'caveats'> = {
  parse_error: 'fails',
  imprint_mismatch: 'fails',
  no_message_digest: 'fails',
  content_not_bound: 'fails',
  no_signing_cert: 'fails',
  eku_not_timestamping: 'fails',
  genTime_outside_validity: 'fails',
  signature_invalid: 'fails',
  chain_signature_invalid: 'fails',
  unexpected_algorithm: 'caveats',
  untrusted_root: 'caveats',
  chain_incomplete: 'caveats',
  chain_algorithm_unsupported: 'caveats',
  chain_outside_validity: 'caveats',
};

/** A result green in every check but the timestamp, whose token failed with `reason`. */
function failedWith(reason: string | undefined, over: Partial<VerifyResult> = {}): VerifyResult {
  return {
    hashMatch: true,
    envelopeIntegrity: { status: 'verified' } as EnvelopeIntegrityResult,
    recomputedHash: 'a'.repeat(64),
    nodeId: 'a'.repeat(64),
    signatureValid: true,
    hasSigning: true,
    rekorVerified: true,
    rekorDetails: null,
    rekorInclusion: null,
    hasRekor: true,
    hasTimestamp: true,
    rfc3161: { verified: false, chainVerified: false, ...(reason ? { reason } : {}) },
    keyTrust: { status: 'active' },
    blobRefsVerified: null,
    blobRefs: [],
    contentCanonicalization: { status: 'ok', rule: 'x' },
    contentHash: { status: 'ok' },
    typeResolution: { status: 'ok', type: 'content/analysis/v1' },
    signerIdentity: { status: 'ok' },
    captureMethodVocab: { status: 'ok', profileType: 'x' },
    contentProfile: { status: 'ok' },
    lifecycle: { status: 'active', source: 'none' },
    ...over,
  } as unknown as VerifyResult;
}

const DECLARED_META = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;

test('#94 classification: every reason code verify-core reports is read as the seat ruled, in each headline branch', () => {
  assert.deepEqual([...RFC3161_FAIL_REASONS].sort(), Object.keys(EXPECTED).sort(), 'the table covers verify-core’s codes');
  const selfCertified = {
    keyTrust: { status: 'self_certified', verified: false } as VerifyResult['keyTrust'],
    signerIdentity: { status: 'key_derived_match' } as VerifyResult['signerIdentity'],
  };
  const privateContent = { envelopeIntegrity: { status: 'unavailable', reason: 'private' } as EnvelopeIntegrityResult, recomputedHash: null };
  const branches = [
    { label: 'ordinary', over: {}, caveated: 'Verified, with caveats' },
    { label: 'self-certified', over: selfCertified, caveated: 'Signature valid, with caveats — self-certified signer' },
    { label: 'content private', over: privateContent, caveated: 'Commitment verified, with caveats — content private' },
  ];
  for (const reason of RFC3161_FAIL_REASONS) {
    for (const b of branches) {
      const v = rollupVerdict(failedWith(reason, b.over), DECLARED_META);
      const label = `${reason}, ${b.label}`;
      if (EXPECTED[reason] === 'fails') {
        assert.equal(v.headline, 'Verification failed', label);
        assert.equal(v.tier, 'alarm', label);
      } else {
        assert.equal(v.headline, b.caveated, label);
        assert.equal(v.tier, 'attention', label);
        assert.ok(v.detail.includes('#7 Timestamp'), label);
      }
    }
  }
});

test('#94 classification: a failed result with no reason, and a token present but not evaluated, are caveats; an absent token stays calm', () => {
  // verify-core sets a reason on every failed result; a result without one is read as
  // a caveat, which is the reading the pinned #95 test fixes for its fixture.
  const noReason = rollupVerdict(failedWith(undefined), DECLARED_META);
  assert.equal(noReason.headline, 'Verified, with caveats');
  // A token with no package hash to check it against: verify-core leaves rfc3161 null.
  const notEvaluated = rollupVerdict(failedWith(undefined, { rfc3161: null }), DECLARED_META);
  assert.equal(notEvaluated.headline, 'Verified, with caveats');
  const absent = rollupVerdict(failedWith(undefined, { hasTimestamp: false, rfc3161: null }), DECLARED_META);
  assert.equal(absent.headline, 'Verified');
  const rows = buildCheckRows(failedWith(undefined, { hasTimestamp: false, rfc3161: null }), buildVerifyInput({ packageHash: 'ab'.repeat(32) }, null), { packageHash: 'ab'.repeat(32) }, DECLARED_META);
  assert.equal(rowOf(rows, '7').signal.tier, 'normal');
});

test('#100 fail: a chain link whose RSA signature does not verify, beneath a TSA signature that verifies, reads "Verification failed", end to end', async () => {
  const page = await capturedWith(withLeafNotBefore(captured.rfc3161Timestamp, LEAF_ONE_YEAR_EARLIER));
  assert.equal(page.result.rfc3161?.signatureValid, true);
  assert.equal(page.result.rfc3161?.reason, 'chain_signature_invalid');
  assertFails(page, 'a link whose signature does not verify');
  assertReasonShown(page, 'chain_signature_invalid', 'a link whose signature does not verify');
});
