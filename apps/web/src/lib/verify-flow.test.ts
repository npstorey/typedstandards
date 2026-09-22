// Roll-up + reason-derivation contract for the content-unavailable fix (#21). The
// load-bearing guarantees:
//   - a content-private (sealed/committed) package reads CALM, never "Verification
//     failed", while its public commitment still verifies;
//   - a present-but-unfetchable location reads Attention (unconfirmed), not altered;
//   - a fetched, hash-MISMATCHING package STILL alarms (the no-regression guardrail);
//   - buildVerifyInput derives `contentUnavailableReason` from the commitment shape
//     (a redacted location ⇒ private; a present location with no package ⇒ unfetchable).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  recomputePackageHash,
  deriveKeyDerivedIdentifier,
  KEY_DERIVED_IDENTIFIER_PREFIX,
  type VerifyResult,
  type EnvelopeIntegrityResult,
} from '@typedstandards/verify-core';
import {
  KEY_TRUST_SIGNALS,
  KEY_TRUST_BUNDLE_REGISTRY_NOT_USED,
  KEY_TRUST_SUPPLIED_REGISTRY,
  SIGNER_IDENTITY_SIGNALS,
  SIGNER_IDENTITY_SUPPLIED_REGISTRY,
  CONTENT_HASH_SIGNALS,
  CONTENT_PROFILE_SIGNALS,
  CAPTURE_METHOD_LABELS,
} from './trust-signal.ts';
import {
  rollupVerdict,
  presentVerification,
  resolveInput,
  runVerify,
  buildCheckRows,
  registryMetaOf,
  registryProvenanceOf,
  recheckKeyTrustLive,
  canRecheckKeyTrust,
  resolveHostRecognition,
  HOST_DIRECTORY,
  type CheckRow,
  type ResolveStep,
  buildVerifyInput,
  buildPreview,
  deriveShareTarget,
  deriveCommitmentUrl,
  deriveCommitmentUrlCandidates,
  bareIdCommitmentUrl,
  bareIdCommitmentUrlCandidates,
  resolveCommitment,
  VerifyFlowError,
  identifierResolutionKind,
  parseHostHint,
  parseHostSegment,
  parseVerifyTarget,
  DEFAULT_HOST,
  type Commitment,
  type ResolvedInput,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

/** A fully-green VerifyResult; override per case. Cast once — rollupVerdict reads a
 *  well-defined subset, and a focused unit test needn't hand-build all 20+ fields. */
function mkResult(over: Partial<VerifyResult> = {}): VerifyResult {
  const base = {
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
    rfc3161: null,
    keyTrust: { status: 'active' },
    blobRefsVerified: null,
    blobRefs: [],
    contentCanonicalization: { status: 'ok', rule: 'x' },
    contentHash: { status: 'ok' },
    typeResolution: { status: 'ok', type: 'content/analysis/v1' },
    signerIdentity: { status: 'ok' },
    captureMethodVocab: { status: 'ok', profileType: 'x' },
    lifecycle: { status: 'active', source: 'none' },
  };
  return { ...base, ...over } as unknown as VerifyResult;
}

test('rollupVerdict: content-private is a CALM "Commitment verified — content private" (#21)', () => {
  const v = rollupVerdict(
    mkResult({
      hashMatch: false, // back-compat boolean is false…
      envelopeIntegrity: { status: 'unavailable', reason: 'private' }, // …but distinctly unavailable
      recomputedHash: null,
    }),
  );
  assert.equal(v.tier, 'verified', 'calm/green — NOT alarm');
  assert.notEqual(v.headline, 'Verification failed');
  assert.match(v.headline, /content private/i);
  assert.doesNotMatch(v.headline, /sealed/i); // vocabulary-neutral during the demo
});

test('rollupVerdict: content-private with a commitment caveat stays calm (Attention, not alarm)', () => {
  const v = rollupVerdict(
    mkResult({
      hashMatch: false,
      envelopeIntegrity: { status: 'unavailable', reason: 'private' },
      keyTrust: { status: 'unknown_key' } as VerifyResult['keyTrust'],
    }),
  );
  assert.equal(v.tier, 'attention');
  assert.notEqual(v.headline, 'Verification failed');
});

test('rollupVerdict: unfetchable content reads Attention, not a false "altered" (#21 case c)', () => {
  const v = rollupVerdict(
    mkResult({
      hashMatch: false,
      envelopeIntegrity: { status: 'unavailable', reason: 'unfetchable' },
      recomputedHash: null,
    }),
  );
  assert.equal(v.tier, 'attention');
  assert.notEqual(v.headline, 'Verification failed');
});

test('rollupVerdict: GUARDRAIL — a fetched, hash-mismatching package STILL alarms', () => {
  const v = rollupVerdict(
    mkResult({
      hashMatch: false,
      envelopeIntegrity: { status: 'altered' }, // bytes present, hash mismatch
      contentHash: { status: 'content_hash_mismatch' } as VerifyResult['contentHash'],
    }),
  );
  assert.equal(v.tier, 'alarm');
  assert.equal(v.headline, 'Verification failed');
});

test('rollupVerdict: a fully-green public package still verifies cleanly', () => {
  const v = rollupVerdict(mkResult());
  assert.equal(v.tier, 'verified');
  assert.equal(v.headline, 'Verified');
});

test('buildVerifyInput: derives contentUnavailableReason from the commitment shape (#21)', () => {
  const base: Commitment = { packageHash: 'h'.repeat(64) };

  // Redacted location (no packageUrl) + null package ⇒ private by design.
  assert.equal(
    buildVerifyInput({ ...base }, null).contentUnavailableReason,
    'private',
  );
  // Present location + null package (fetch failed) ⇒ unfetchable.
  assert.equal(
    buildVerifyInput({ ...base, packageUrl: 'https://example.com/p.json' }, null)
      .contentUnavailableReason,
    'unfetchable',
  );
  // Package present ⇒ no reason emitted (content is available).
  assert.equal(
    buildVerifyInput({ ...base, packageUrl: 'https://example.com/p.json' }, { ok: 1 })
      .contentUnavailableReason,
    undefined,
  );
});

test('buildPreview: an unavailable preview reports WHY (private vs. unfetchable)', () => {
  const sealed = buildPreview(null, { packageHash: 'h'.repeat(64) });
  assert.equal(sealed.available, false);
  assert.equal(sealed.unavailableReason, 'private');

  const missing = buildPreview(null, {
    packageHash: 'h'.repeat(64),
    packageUrl: 'https://example.com/p.json',
  });
  assert.equal(missing.available, false);
  assert.equal(missing.unavailableReason, 'unfetchable');
});

// deriveCommitmentUrl — B5 (#44), REWRITTEN from the premise these two tests were
// originally written to.
//
// THE ORIGINAL PREMISE, and why it was wrong. The audit read the package-blob branch
// as a neutrality bug — it re-pointed every blob at the anchor host, so P1 was
// contracted to make it "preserve the blob's own origin, exactly like the adjacent
// `/evidence/<id>` branch". These two tests asserted that, with two hosts, to prove
// the behavior independent of roster membership. The neutrality complaint was real.
// The prescribed fix rested on a false premise: that a package blob's origin IS its
// publisher's origin. It is not, wherever object storage is detached from the app —
// Vercel Blob, S3, R2, GCS, and the reference publisher's own setup — where the blob
// origin has no commitment API at all. Measured on the live deployment: the blob itself
// returns 200, `<blob-host>/api/evidence/<hash>/commitment` returns 404, and the
// anchor's returns 200. So origin-preservation 404s for detached storage, while the
// pre-P1 anchor-pinning 404s for a self-hosting publisher. NEITHER is right, because
// a bare blob URL does not determine its publisher.
//
// THE RULING: a blob filename's 64-hex hash is an ORIGIN-LESS IDENTIFIER, resolved
// like any other — against the declared anchor, with the disclosure line and the host
// picker available to correct it. These tests now lock that, so the false premise
// cannot come back. The roster-independence the originals were protecting is intact
// and is asserted directly below.
test('deriveCommitmentUrl: package-blob URL resolves against the ANCHOR, not the blob origin (B5)', () => {
  const hash = 'a1'.repeat(32); // 64 hex chars
  const url = `https://data-concierge.dathere.com/blobs/${hash}.json`;
  assert.equal(deriveCommitmentUrl(url), `${DEFAULT_HOST}/api/records/${hash}/commitment`);
  // The old assertion, now the thing being ruled out: the blob's own origin.
  assert.notEqual(
    deriveCommitmentUrl(url),
    `https://data-concierge.dathere.com/api/records/${hash}/commitment`,
  );
});

test('deriveCommitmentUrl: package-blob resolution does not depend on roster membership (B5)', () => {
  // What the original two-host pair was really protecting. A blob on a host that is
  // in the directory and one on a host that is not resolve identically — the anchor
  // decides, and it consults no roster.
  const listed = 'a1'.repeat(32);
  const unlisted = 'b2'.repeat(32);
  assert.equal(
    deriveCommitmentUrl(`https://data-concierge.dathere.com/blobs/${listed}.json`),
    `${DEFAULT_HOST}/api/records/${listed}/commitment`,
  );
  assert.equal(
    deriveCommitmentUrl(`https://example-publisher.test/blobs/${unlisted}.json`),
    `${DEFAULT_HOST}/api/records/${unlisted}/commitment`,
  );
});

test('deriveCommitmentUrl: DETACHED STORAGE — a blob host with no commitment API resolves to the anchor (B5)', () => {
  // The case the original premise could not survive, and the reference publisher's
  // actual deployment shape: package bytes on third-party object storage whose origin
  // serves no commitment API. Preserving that origin produced a guaranteed 404.
  const hash = 'c3'.repeat(32);
  for (const blobUrl of [
    `https://abcdef0123456789.public.blob.vercel-storage.com/evidence-packages/${hash}.json`,
    // A bucket layout whose path contains an `/evidence/` SEGMENT. This one caught a
    // real branch-ordering hazard: the record-page probe used to match first and
    // captured an id of literally `<hash>.json`, yielding `…/api/evidence/<hash>.json
    // /commitment`. The `<64-hex>.json` filename is the more specific signal and now
    // wins — see classifyHostedUrl.
    `https://packages.s3.amazonaws.com/evidence/${hash}.json`,
    // The same hazard under the settlement-era segment. The 2026-08-19 vocabulary
    // settlement widened the page probe to `/records/` as well, so there are now TWO
    // bucket-layout segment names that can collide with a blob path — which makes the
    // package-blob-first ordering MORE load-bearing, not less. A `records/` bucket
    // prefix is an entirely ordinary storage layout.
    `https://packages.s3.amazonaws.com/records/${hash}.json`,
    `https://cdn.example-storage.test/${hash}.json`,
  ]) {
    assert.equal(
      deriveCommitmentUrl(blobUrl),
      `${DEFAULT_HOST}/api/records/${hash}/commitment`,
      `${blobUrl} must resolve against the anchor, not its storage origin`,
    );
    // …and the UI must DISCLOSE that, exactly as it does for a bare hash: this input
    // looks like it carries an origin and does not.
    assert.equal(identifierResolutionKind('url', blobUrl), 'package-blob');
  }
});

test('deriveCommitmentUrl: a blob URL resolves against a PICKED host when one is named (B5)', () => {
  // The correction path. The anchor is a default, not a verdict — a self-hosting
  // publisher's blob is one picker click (or a /verify/<host>/<id> link) away.
  const hash = 'd4'.repeat(32);
  assert.equal(
    deriveCommitmentUrl(
      `https://cdn.example-storage.test/${hash}.json`,
      'https://example-publisher.test',
    ),
    `https://example-publisher.test/api/records/${hash}/commitment`,
  );
});

test('deriveCommitmentUrl: URLs that DO carry a publisher origin still keep it (B5)', () => {
  // The other three branches are unchanged. A publisher's own record-page URL and an
  // already-resolved commitment URL both name their publisher, so nothing is
  // re-anchored — the fix is scoped to the one shape that does not.
  const commitment = 'https://example-publisher.test/api/records/some-slug/commitment';
  assert.equal(deriveCommitmentUrl(commitment), commitment);
  assert.equal(
    deriveCommitmentUrl('https://example-publisher.test/records/some-slug'),
    'https://example-publisher.test/api/records/some-slug/commitment',
  );
  // Neither is origin-less, so neither triggers the disclosure line.
  assert.equal(identifierResolutionKind('url', commitment), undefined);
  assert.equal(
    identifierResolutionKind('url', 'https://example-publisher.test/records/some-slug'),
    undefined,
  );
});

// --- Vocabulary eras: recognition is symmetric, construction is ordered ----
//
// The 2026-08-19 vocabulary settlement (spec Appendix J) makes `records` canonical
// and keeps `evidence` as a PERMANENT alias. These tests pin the asymmetry that
// makes the migration safe, and they are the ones that fail loudly if a later
// phase "finishes the rename" by dropping prior-era acceptance.

test('eras: a PRIOR-ERA commitment URL is already the resource and is used verbatim', () => {
  // The single most important non-regression in the settlement. Every commitment URL
  // in the wild today carries `/api/evidence/`; the verifier must fetch exactly what
  // it was handed, not rewrite the caller's resource onto a segment the publisher may
  // not serve.
  const priorEra = 'https://example-publisher.test/api/evidence/some-slug/commitment';
  assert.equal(deriveCommitmentUrl(priorEra), priorEra);
  assert.deepEqual(
    deriveCommitmentUrlCandidates(priorEra),
    [priorEra],
    'a complete resource URL is ONE candidate — rewriting it would invent a resource',
  );
});

test('eras: a prior-era record-page URL is recognized and re-resolved canonical-first', () => {
  // A page URL is not a resource URL: we extract the id and mint the endpoint path
  // ourselves. So the page's own era says nothing — a publisher can cut over pages
  // and routes independently, and both candidates are tried in order.
  assert.deepEqual(deriveCommitmentUrlCandidates('https://example-publisher.test/evidence/some-slug'), [
    'https://example-publisher.test/api/records/some-slug/commitment',
    'https://example-publisher.test/api/evidence/some-slug/commitment',
  ]);
  // Same input under the settlement-era page segment ⇒ identical candidate list.
  assert.deepEqual(
    deriveCommitmentUrlCandidates('https://example-publisher.test/records/some-slug'),
    deriveCommitmentUrlCandidates('https://example-publisher.test/evidence/some-slug'),
    'era is not a signal: both page segments resolve identically',
  );
  // And neither is origin-less, so neither triggers the disclosure line.
  assert.equal(
    identifierResolutionKind('url', 'https://example-publisher.test/evidence/some-slug'),
    undefined,
  );
});

test('eras: a bare identifier mints BOTH segments, canonical FIRST', () => {
  // The ordering is the whole phase. Canonical-first is what adopts the new
  // vocabulary; the prior-era fallback is what keeps every publisher that has not
  // cut over — which today is all of them — verifying without interruption.
  assert.deepEqual(bareIdCommitmentUrlCandidates('some-slug'), [
    `${DEFAULT_HOST}/api/records/some-slug/commitment`,
    `${DEFAULT_HOST}/api/evidence/some-slug/commitment`,
  ]);
  assert.equal(
    bareIdCommitmentUrlCandidates('some-slug')[0],
    bareIdCommitmentUrl('some-slug'),
    'the canonical single-URL helper must agree with candidate[0]',
  );
});

test('identifierResolutionKind: bare identifiers disclose, origin-carrying inputs do not', () => {
  assert.equal(identifierResolutionKind('hash', 'e'.repeat(64)), 'bare');
  assert.equal(identifierResolutionKind('hash', 'noise-trends-in-nyc-2026'), 'bare');
  assert.equal(identifierResolutionKind('hash', '   '), undefined, 'empty input discloses nothing');
  assert.equal(identifierResolutionKind('bundle', '{"packageHash":"x"}'), undefined);
  assert.equal(identifierResolutionKind('url', 'not a url'), undefined);
  assert.equal(identifierResolutionKind('url', 'https://example-publisher.test/some/page'), undefined);
});

// deriveShareTarget — the shareable link is rebuilt from the URL that ACTUALLY
// resolved (sources.commitment.url), never from packageHash (a hash the slug-indexed
// endpoint 404s on). Only sources.commitment.url matters here, so build a minimal
// ResolvedInput and cast (mirrors mkResult above).
function mkResolved(commitmentUrl?: string): ResolvedInput {
  return {
    sources: {
      commitment: commitmentUrl ? { kind: 'fetched', url: commitmentUrl } : { kind: 'inline' },
    },
  } as unknown as ResolvedInput;
}

test('deriveShareTarget: same-host slug → clean /verify/<slug>', () => {
  const url = `${DEFAULT_HOST}/api/evidence/noise-trends-in-nyc-2026/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), '/verify/noise-trends-in-nyc-2026');
});

test('deriveShareTarget: same-host 64-hex hash → clean /verify/<hash>', () => {
  const hash = 'e'.repeat(64);
  const url = `${DEFAULT_HOST}/api/evidence/${hash}/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify/${hash}`);
});

// REWRITTEN from the pre-ruling test (#44 B7). It used to assert that a cross-host
// commitment URL must NOT collapse to a short link — `assert.doesNotMatch(target,
// /^\/verify\/some-slug$/)` — because the only short link that existed was the
// single-segment `/verify/<id>`, which re-resolves against the anchor host and would
// have 404'd for anyone else. That constraint was real, but it was the FINDING, not
// the requirement: the clean link was earned only by the reference publisher, and
// every other publisher's result was shareable only as an opaque `?url=` blob. The
// two-segment `/verify/<host>/<id>` form carries the origin IN the link, so the
// collapse is now correct — and the old defense is preserved by the round-trip
// assertion below: the link must rebuild THIS origin's commitment URL, never the
// anchor's.
test('deriveShareTarget: cross-host → /verify/<host>/<id>, carrying its own origin (B7)', () => {
  const url = 'https://data-concierge.dathere.com/api/evidence/some-slug/commitment';
  const target = deriveShareTarget(mkResolved(url));
  assert.equal(target, '/verify/data-concierge.dathere.com/some-slug');
  // The origin is preserved, which is what the old `doesNotMatch` was protecting:
  // reading the link back must rebuild THIS host's commitment URL, not the anchor's.
  //
  // Post-settlement the rebuild is a candidate LIST rather than a single URL, and the
  // prior-era URL this link was minted from is still in it — as the fallback. So the
  // round-trip lands on the same commitment whether or not the publisher has cut
  // over: canonical first, and the exact original URL second.
  const parsed = parseVerifyTarget(['data-concierge.dathere.com', 'some-slug']);
  assert.deepEqual(bareIdCommitmentUrlCandidates(parsed!.id, parsed!.host), [
    'https://data-concierge.dathere.com/api/records/some-slug/commitment',
    url,
  ]);
  assert.notEqual(parsed!.host, DEFAULT_HOST);
});

test('deriveShareTarget: a host absent from the directory gets the SAME short link (B7)', () => {
  // Roster membership must not gate the link shape — recognition is a separate
  // dimension, and gating here would rebuild the privilege this removes.
  const url = 'https://example-publisher.test/api/evidence/some-slug/commitment';
  assert.equal(deriveShareTarget(mkResolved(url)), '/verify/example-publisher.test/some-slug');
});

test('deriveShareTarget: non-https origin → /verify?url= fallback (B7)', () => {
  const url = 'http://insecure-publisher.test/api/evidence/some-slug/commitment';
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify?url=${encodeURIComponent(url)}`);
});

test('deriveShareTarget: ported origin → /verify?url= fallback (B7)', () => {
  const url = 'https://publisher.test:8443/api/evidence/some-slug/commitment';
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify?url=${encodeURIComponent(url)}`);
});

test('deriveShareTarget: cross-host id needing encoding round-trips through the segment (B7)', () => {
  const url = 'https://publisher.test/api/evidence/a%20b/commitment';
  const target = deriveShareTarget(mkResolved(url));
  assert.equal(target, '/verify/publisher.test/a%20b');
  // Next.js hands the route the DECODED segments. Re-encoding survives the era
  // widening: the original prior-era URL is still the fallback candidate, byte-exact.
  const parsed = parseVerifyTarget(['publisher.test', 'a b']);
  assert.deepEqual(bareIdCommitmentUrlCandidates(parsed!.id, parsed!.host), [
    'https://publisher.test/api/records/a%20b/commitment',
    url,
  ]);
});

test('deriveShareTarget: a package-blob deep-link ends in a clean short link (B5 + B7)', () => {
  // The whole B5 path, end to end. A badge `?url=<package-blob-url>` resolves through
  // the anchor, and the URL that answered is what the share link is rebuilt from — so
  // the opaque storage URL collapses to `/verify/<hash>`, which round-trips back to
  // the same commitment URL. Nothing downstream has to know a blob was involved.
  const hash = 'c3'.repeat(32);
  const blobUrl = `https://abcdef0123456789.public.blob.vercel-storage.com/evidence-packages/${hash}.json`;
  const commitmentUrl = deriveCommitmentUrl(blobUrl);
  assert.equal(commitmentUrl, `${DEFAULT_HOST}/api/records/${hash}/commitment`);
  const target = deriveShareTarget(mkResolved(commitmentUrl));
  assert.equal(target, `/verify/${hash}`);
  const parsed = parseVerifyTarget([hash]);
  assert.equal(bareIdCommitmentUrl(parsed!.id, parsed!.host ?? DEFAULT_HOST), commitmentUrl);
});

test('deriveShareTarget: a blob resolved on a PICKED host shares as /verify/<host>/<id> (B5 + B7)', () => {
  const hash = 'd4'.repeat(32);
  const commitmentUrl = deriveCommitmentUrl(
    `https://cdn.example-storage.test/${hash}.json`,
    'https://example-publisher.test',
  );
  assert.equal(
    deriveShareTarget(mkResolved(commitmentUrl)),
    `/verify/example-publisher.test/${hash}`,
  );
});

test('deriveShareTarget: undefined url (bundle) → null', () => {
  assert.equal(deriveShareTarget(mkResolved(undefined)), null);
});

test('deriveShareTarget: same-host non-canonical path → /verify?url=<encoded> fallback', () => {
  // No `/api/` prefix — routes to the safe fallback rather than a short link.
  const url = `${DEFAULT_HOST}/evidence/some-slug/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify?url=${encodeURIComponent(url)}`);
});

test('deriveShareTarget: percent-encoded id round-trips → /verify/a%20b', () => {
  const url = `${DEFAULT_HOST}/api/evidence/a%20b/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), '/verify/a%20b');
});

test('deriveShareTarget: decoded id with a slash (%2F) → /verify?url= fallback', () => {
  // %2F decodes to "/", which no single path segment can carry.
  const url = `${DEFAULT_HOST}/api/evidence/a%2Fb/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify?url=${encodeURIComponent(url)}`);
});

// --- /verify/… route shape: parseVerifyTarget + the round-trip (#44 B7) ----
//
// deriveShareTarget MINTS these paths and parseVerifyTarget READS them back;
// bareIdCommitmentUrl closes the loop. The pair is tested here without Next in the
// loop — the route file does nothing but call parseVerifyTarget and 404 on undefined.

test('parseVerifyTarget: BACK-COMPAT — a pre-existing /verify/<id> link still resolves', () => {
  // The load-bearing back-compat check. Every short link minted before the
  // two-segment form existed is a single segment with no origin in it; it must keep
  // resolving exactly as it did, against the directory's declared anchor.
  const parsed = parseVerifyTarget(['noise-trends-in-nyc-2026']);
  assert.deepEqual(parsed, { id: 'noise-trends-in-nyc-2026' });
  assert.equal(parsed?.host, undefined, 'no host in the link ⇒ the anchor decides');
  // Post-settlement the link resolves canonical-first, with the URL it was originally
  // minted against still reachable as the fallback — so the pre-existing link keeps
  // working against a publisher at EITHER stage of its cutover.
  assert.deepEqual(bareIdCommitmentUrlCandidates(parsed!.id, parsed!.host ?? DEFAULT_HOST), [
    `${DEFAULT_HOST}/api/records/noise-trends-in-nyc-2026/commitment`,
    `${DEFAULT_HOST}/api/evidence/noise-trends-in-nyc-2026/commitment`,
  ]);
});

test('parseVerifyTarget: BACK-COMPAT — a 64-hex hash link still resolves against the anchor', () => {
  const hash = 'e'.repeat(64);
  const parsed = parseVerifyTarget([hash]);
  assert.deepEqual(parsed, { id: hash });
  assert.deepEqual(bareIdCommitmentUrlCandidates(parsed!.id, parsed!.host ?? DEFAULT_HOST), [
    `${DEFAULT_HOST}/api/records/${hash}/commitment`,
    `${DEFAULT_HOST}/api/evidence/${hash}/commitment`,
  ]);
});

test('parseVerifyTarget: BACK-COMPAT — the old share link round-trips end to end', () => {
  // Mint with today's code from an anchor-origin PRIOR-ERA commitment URL — which is
  // what every publisher answers with today — read back, rebuild. The link shape is
  // unchanged, and the URL it was minted from is still in the rebuilt candidate list.
  const url = `${DEFAULT_HOST}/api/evidence/noise-trends-in-nyc-2026/commitment`;
  const target = deriveShareTarget(mkResolved(url));
  assert.equal(target, '/verify/noise-trends-in-nyc-2026', 'still the single-segment form');
  const segments = target!.slice('/verify/'.length).split('/').map(decodeURIComponent);
  const parsed = parseVerifyTarget(segments);
  assert.ok(
    bareIdCommitmentUrlCandidates(parsed!.id, parsed!.host ?? DEFAULT_HOST).includes(url),
    'the URL the link was minted from must still be reachable from the rebuilt link',
  );
});

test('parseVerifyTarget: two segments name the host to resolve against', () => {
  assert.deepEqual(parseVerifyTarget(['data-concierge.dathere.com', 'some-slug']), {
    id: 'some-slug',
    host: 'https://data-concierge.dathere.com',
  });
});

test('parseVerifyTarget: an id that LOOKS like a host is still an id at depth 1', () => {
  // No ambiguity between the depths: one segment is always the identifier.
  assert.deepEqual(parseVerifyTarget(['example.com']), { id: 'example.com' });
});

test('parseVerifyTarget: rejects zero, three+, empty, and malformed-host paths', () => {
  assert.equal(parseVerifyTarget([]), undefined);
  assert.equal(parseVerifyTarget(['a', 'b', 'c']), undefined);
  assert.equal(parseVerifyTarget(['']), undefined);
  assert.equal(parseVerifyTarget(['publisher.test', '']), undefined);
  assert.equal(parseVerifyTarget(['..', 'some-slug']), undefined);
});

test('parseHostSegment: accepts a plain https host, canonicalized', () => {
  assert.equal(parseHostSegment('data-concierge.dathere.com'), 'https://data-concierge.dathere.com');
  assert.equal(parseHostSegment('EXAMPLE.com'), 'https://example.com');
  // Shape, NOT roster membership — an unlisted publisher parses the same.
  assert.equal(parseHostSegment('example-publisher.test'), 'https://example-publisher.test');
});

test('parseHostSegment: rejects everything a host segment must not carry', () => {
  for (const bad of [
    '',
    'a@b.com', // userinfo — `new URL` would silently drop it and keep b.com
    'publisher.test:8443', // explicit port
    'publisher.test?x=1', // query
    'publisher.test#x', // fragment
    '.', // not a hostname
    '..',
    '-bad.example', // leading-hyphen label
    'trailing-dot.example.', // empty final label
    '[::1]', // IPv6 literal
    'foo bar', // not parseable as a host at all
  ]) {
    assert.equal(parseHostSegment(bad), undefined, `${JSON.stringify(bad)} must be rejected`);
  }
});

// --- The `host=` origin hint on /verify (typedstandards#58) ---------------
//
// `/verify?hash=<id>` is an ORIGIN-LESS deep-link: a bare identifier resolves against
// the directory's declared anchor — right for the anchor's own readers, one picker
// click away for everybody else. `host=` lets a link close that gap directly.
//
// ADDITIVE, and the first thing asserted below: a `hash=`-only link behaves exactly
// as it does today. That matters because a second publisher has already frozen
// `?hash=` links into published artifacts; nothing about their meaning moves.
//
// The hint is the SAME grammar as the `/verify/<host>/<id>` path segment, by
// DELEGATION rather than by copy — parseHostHint strips the documented `https://` and
// hands the rest to parseHostSegment. So these tests assert the delegation (same
// origin, same #50 www-normalization, same rejections) instead of restating the
// hardening, which is what keeps the two entry points from drifting apart.
//
// TRUST CLASS, for the record: unchanged. The verifier already fetches from any host
// `?url=` or `/verify/<host>/<id>` names, shape-validated and never roster-gated.

test('parseHostHint: the one documented form resolves to the canonical origin', () => {
  assert.equal(
    parseHostHint('https://data-concierge.dathere.com'),
    'https://data-concierge.dathere.com',
  );
  // Shape, NOT roster membership — an unlisted publisher parses the same, exactly as
  // the path segment does. That is the whole point: the publishers who need a hint
  // are the ones not (yet) listed.
  assert.equal(parseHostHint('https://example-publisher.test'), 'https://example-publisher.test');
});

test('parseHostHint: DELEGATES to parseHostSegment — one grammar, two entry points', () => {
  for (const host of [
    'data-concierge.dathere.com',
    'example-publisher.test',
    'www.example-publisher.test', // the #50 normalization arrives through the delegate
    'EXAMPLE.com',
  ]) {
    assert.equal(
      parseHostHint(`https://${host}`),
      parseHostSegment(host),
      `?host=https://${host} must agree with /verify/${host}/<id>`,
    );
  }
});

test('parseHostHint: a www hint resolves against the canonical origin (#50)', () => {
  assert.equal(parseHostHint('https://www.example-publisher.test'), 'https://example-publisher.test');
});

test('parseHostHint: ignores everything that is not the documented form', () => {
  for (const bad of [
    '',
    '   ',
    'data-concierge.dathere.com', // a bare host — the path form's spelling, not this one
    'http://data-concierge.dathere.com', // not https
    'ftp://data-concierge.dathere.com', // another scheme
    '//data-concierge.dathere.com', // scheme-relative
    'https://', // scheme only
    'https://a@evil.example', // userinfo
    'https://publisher.test:8443', // explicit port
    'https://publisher.test/some/path', // path
    'https://publisher.test?x=1', // query
    'https://publisher.test#x', // fragment
    'https://-bad.example', // leading-hyphen label
    'https://trailing-dot.example.', // empty final label
    'https://[::1]', // IPv6 literal
    'https://..',
    'https://foo bar',
    'https://https://publisher.test', // the scheme written twice
    'javascript:alert(1)',
  ]) {
    assert.equal(parseHostHint(bad), undefined, `${JSON.stringify(bad)} must be ignored`);
  }
});

test('parseHostHint: IGNORED means anchor, never a resolved unvalidated string', () => {
  // The ignore path lands in exactly the state a bare `?hash=` link is in: no host
  // named, so the page passes no initialHost and the flow uses DEFAULT_HOST. There is
  // no branch in which an unparsed hint reaches a fetched URL.
  const ignored = parseHostHint('http://attacker.example');
  assert.equal(ignored, undefined);
  assert.equal(
    bareIdCommitmentUrl('some-slug', ignored ?? DEFAULT_HOST),
    `${DEFAULT_HOST}/api/records/some-slug/commitment`,
  );
});

test('parseHostHint: the percent-encoded spelling resolves identically', () => {
  // Next.js decodes searchParams, so `host=https%3A%2F%2F…` — which a publisher's link
  // emitter may well produce — arrives already decoded. Assert both spellings land on
  // the same origin, through an actual query-string parse rather than by assumption.
  const plain = 'https://data-concierge.dathere.com';
  assert.equal(encodeURIComponent(plain), 'https%3A%2F%2Fdata-concierge.dathere.com');
  const encodedParams = new URLSearchParams(`hash=some-slug&host=${encodeURIComponent(plain)}`);
  const plainParams = new URLSearchParams(`hash=some-slug&host=${plain}`);
  assert.equal(parseHostHint(encodedParams.get('host') ?? ''), plain);
  assert.equal(parseHostHint(plainParams.get('host') ?? ''), plain);
});

test('host hint: a hinted link resolves ON the hint; a bare ?hash= link is UNCHANGED', () => {
  const id = 'median-household-income-for-manhattan-255b8e';
  const hinted = parseHostHint('https://data-concierge.dathere.com');
  assert.deepEqual(bareIdCommitmentUrlCandidates(id, hinted ?? DEFAULT_HOST), [
    `https://data-concierge.dathere.com/api/records/${id}/commitment`,
    `https://data-concierge.dathere.com/api/evidence/${id}/commitment`,
  ]);
  // THE CONTROL CASE. No `host=` at all: the same candidates today's `?hash=` link
  // produces, on the anchor, in the same order.
  assert.deepEqual(bareIdCommitmentUrlCandidates(id, parseHostHint('') ?? DEFAULT_HOST), [
    `${DEFAULT_HOST}/api/records/${id}/commitment`,
    `${DEFAULT_HOST}/api/evidence/${id}/commitment`,
  ]);
});

test('host hint: the disclosure line takes its LINK-NAMED branch, not the anchor branch', () => {
  // Verifier.tsx's IdentifierResolutionNote branches on `host === DEFAULT_HOST`: the
  // anchor branch reads "— the host the published directory names for identifiers
  // with no origin of their own", the other "— the host this link named." No new
  // prose was needed for `host=`; what this pins is the PREDICATE that selects the
  // branch. This suite renders no React, so the rendered-markup measurement is in the
  // phase report (server-rendered production build), not here.
  const id = 'median-household-income-for-manhattan-255b8e';
  const hinted = parseHostHint('https://data-concierge.dathere.com');
  assert.equal(hinted, 'https://data-concierge.dathere.com');
  assert.notEqual(hinted, DEFAULT_HOST, 'a hinted host selects the "this link named" branch');
  // A bare `?hash=` names nothing, so the component falls back to the anchor branch.
  assert.equal(parseHostHint('') ?? DEFAULT_HOST, DEFAULT_HOST);
  // …and the note renders at all only for an origin-less input, which is what a
  // hinted link carries.
  assert.equal(identifierResolutionKind('hash', id), 'bare');
});

// --- www-normalization at the resolution entry points (#50) ----------------
//
// A browser fetch dies at a cross-origin redirect hop whose response carries no
// CORS headers, and a platform-default `www.` → apex redirect commonly carries
// none (measured live 2026-08-17). So every point where a publisher host enters
// resolution — a hosted URL's kept origin (deriveCommitmentUrl), the
// `/verify/<host>/<id>` segment (parseHostSegment), and the bare-identifier host
// (bareIdCommitmentUrl) — re-spells it canonically, and the verifier fetches the
// canonical origin directly instead of riding the publisher's domain redirect.
// canonicalPublisherOrigin itself is unit-tested in host-directory.test.ts.

test('deriveCommitmentUrl: a www commitment URL is fetched on the canonical origin (#50)', () => {
  assert.equal(
    deriveCommitmentUrl('https://www.civicaitools.org/api/evidence/some-slug/commitment'),
    'https://civicaitools.org/api/evidence/some-slug/commitment',
  );
  // Only the origin is re-spelled — path and query come through untouched, listed or not.
  assert.equal(
    deriveCommitmentUrl('https://www.example-publisher.test/api/evidence/x/commitment?v=2'),
    'https://example-publisher.test/api/evidence/x/commitment?v=2',
  );
});

test('deriveCommitmentUrl: a www record-page URL mints its commitment on the canonical origin (#50)', () => {
  assert.equal(
    deriveCommitmentUrl('https://www.example-publisher.test/records/some-slug'),
    'https://example-publisher.test/api/records/some-slug/commitment',
  );
  // www-normalization applies to the prior-era page segment too, and to BOTH
  // candidates — a `www.` host must never leak into either era's fallback.
  assert.deepEqual(
    deriveCommitmentUrlCandidates('https://www.example-publisher.test/evidence/some-slug'),
    [
      'https://example-publisher.test/api/records/some-slug/commitment',
      'https://example-publisher.test/api/evidence/some-slug/commitment',
    ],
  );
});

test('deriveCommitmentUrl: an opaque www URL is fetched on the canonical origin (#50)', () => {
  assert.equal(
    deriveCommitmentUrl('https://www.example-publisher.test/some/page'),
    'https://example-publisher.test/some/page',
  );
});

test('bareIdCommitmentUrl: a www resolution host is normalized before the URL is minted (#50)', () => {
  assert.equal(
    bareIdCommitmentUrl('some-slug', 'https://www.civicaitools.org'),
    `${DEFAULT_HOST}/api/records/some-slug/commitment`,
  );
  // Both candidates, not just the canonical one.
  assert.deepEqual(bareIdCommitmentUrlCandidates('some-slug', 'https://www.civicaitools.org'), [
    `${DEFAULT_HOST}/api/records/some-slug/commitment`,
    `${DEFAULT_HOST}/api/evidence/some-slug/commitment`,
  ]);
});

test('parseHostSegment: a www host segment canonicalizes — resolution, display, and share all see the real origin (#50)', () => {
  assert.equal(parseHostSegment('www.civicaitools.org'), DEFAULT_HOST);
  // Canonicalization, NOT roster gating: an unlisted www host normalizes too and
  // still resolves.
  assert.equal(parseHostSegment('www.example-publisher.test'), 'https://example-publisher.test');
});

test('a /verify/www.<host>/<id> link resolves canonically and re-mints the canonical share link (#50)', () => {
  const parsed = parseVerifyTarget(['www.example-publisher.test', 'some-slug']);
  assert.equal(parsed?.host, 'https://example-publisher.test');
  const commitmentUrl = bareIdCommitmentUrl(parsed!.id, parsed!.host);
  assert.equal(commitmentUrl, 'https://example-publisher.test/api/records/some-slug/commitment');
  // The share link minted from the URL that answered carries the canonical host —
  // a www link heals to its canonical form on the first round-trip.
  assert.equal(deriveShareTarget(mkResolved(commitmentUrl)), '/verify/example-publisher.test/some-slug');
});

// --- New-then-old RESOLUTION against a live publisher (spec Appendix J) ----
//
// The candidate-list tests above pin what is CONSTRUCTED. These pin what is
// FETCHED, which is the property the settlement actually promises: a verifier
// that adopts the canonical vocabulary today, against publishers that serve only
// the prior-era one today, with nothing ceasing to resolve on either side of any
// publisher's cutover.
//
// Each test stands up a synthetic publisher that serves exactly the segments it
// names and 404s everything else, then records the request order.

const PUBLISHER = 'https://example-publisher.test';
/** Minimal §9.2.1 commitment body — `packageHash` is what makes it a commitment.
 *  Hex-letter range, no digit runs (the repo's guard-safe fixture convention). */
const COMMITMENT_BODY = { protocolVersion: '0.1.0', packageHash: 'ab'.repeat(32) };

/** Serve `served` (200 JSON commitment) and 404 everything else, recording the
 *  URL of every request in order. Returns the log and a restore function. */
function stubPublisher(
  served: RegExp,
  body: unknown = COMMITMENT_BODY,
): { requested: string[]; restore: () => void } {
  const requested: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const url = String(input);
    requested.push(url);
    return Promise.resolve(
      served.test(url)
        ? new Response(JSON.stringify(body), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        : new Response('<!doctype html><title>404</title>', {
            status: 404,
            headers: { 'content-type': 'text/html' },
          }),
    );
  }) as typeof globalThis.fetch;
  return { requested, restore: () => { globalThis.fetch = real; } };
}

test('resolution: a publisher serving ONLY prior-era segments still verifies (the phase’s core guarantee)', async () => {
  // TODAY'S WORLD, including the reference publisher: `/api/records/` does not exist
  // anywhere yet. A canonical-only verifier would break every verification on earth
  // the day it shipped; this is the fallback that makes the expand safe to land
  // before any publisher has cut over.
  const pub = stubPublisher(/\/api\/evidence\//);
  try {
    const { commitment, url } = await resolveCommitment('hash', 'some-slug', undefined, {
      host: PUBLISHER,
    });
    assert.equal(commitment.packageHash, COMMITMENT_BODY.packageHash, 'the commitment resolved');
    assert.deepEqual(
      pub.requested,
      [
        `${PUBLISHER}/api/records/some-slug/commitment`,
        `${PUBLISHER}/api/evidence/some-slug/commitment`,
      ],
      'canonical is tried FIRST, prior-era is the fallback',
    );
    assert.equal(
      url,
      `${PUBLISHER}/api/evidence/some-slug/commitment`,
      'the reported URL is the one that ANSWERED, not the one first tried',
    );
    // …and that URL is what the share link is rebuilt from, so a result verified
    // through the fallback is as shareable as one verified through the canonical form.
    assert.equal(
      deriveShareTarget(mkResolved(url)),
      '/verify/example-publisher.test/some-slug',
    );
  } finally {
    pub.restore();
  }
});

test('resolution: a publisher that HAS cut over answers on the first request', async () => {
  // The other side of the migration. No wasted request, and no lingering preference
  // for the prior era once a publisher has moved.
  const pub = stubPublisher(/\/api\/records\//);
  try {
    const { url } = await resolveCommitment('hash', 'some-slug', undefined, { host: PUBLISHER });
    assert.equal(url, `${PUBLISHER}/api/records/some-slug/commitment`);
    assert.equal(pub.requested.length, 1, 'the canonical form answered — no fallback request');
  } finally {
    pub.restore();
  }
});

test('resolution: when a publisher serves BOTH, the canonical segment wins', async () => {
  // The ordering assertion proper. A publisher mid-cutover serves both segments; the
  // verifier must settle on the canonical one, or the rename never actually lands.
  const pub = stubPublisher(/\/api\/(records|evidence)\//);
  try {
    const { url } = await resolveCommitment('hash', 'some-slug', undefined, { host: PUBLISHER });
    assert.equal(url, `${PUBLISHER}/api/records/some-slug/commitment`);
    assert.deepEqual(pub.requested, [`${PUBLISHER}/api/records/some-slug/commitment`]);
  } finally {
    pub.restore();
  }
});

test('resolution: a canonical-segment 200 that is NOT a commitment falls through', async () => {
  // `/api/records/…` is a plausible path for an unrelated records API on some
  // publisher, and such a path can answer 200 with perfectly valid JSON. Treating
  // only 404 as "not here" would abort a verification that the prior-era segment
  // would have completed — so "no `packageHash`" is a candidate failure too.
  const real = globalThis.fetch;
  const requested: string[] = [];
  globalThis.fetch = ((input: unknown) => {
    const url = String(input);
    requested.push(url);
    const body = url.includes('/api/records/') ? { items: [] } : COMMITMENT_BODY;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
  }) as typeof globalThis.fetch;
  try {
    const { commitment, url } = await resolveCommitment('hash', 'some-slug', undefined, {
      host: PUBLISHER,
    });
    assert.equal(commitment.packageHash, COMMITMENT_BODY.packageHash);
    assert.equal(url, `${PUBLISHER}/api/evidence/some-slug/commitment`);
    assert.equal(requested.length, 2, 'the non-commitment 200 was tried and fell through');
  } finally {
    globalThis.fetch = real;
  }
});

test('resolution: when NO segment answers, the prior-era error surfaces (today’s message, unchanged)', async () => {
  // The canonical-form 404 is expected migration traffic and must never reach the
  // user. What they see is the message about the endpoint that actually exists —
  // byte-for-byte what they saw before this change.
  const pub = stubPublisher(/\/api\/nothing\//);
  try {
    await assert.rejects(
      resolveCommitment('hash', 'no-such-id', undefined, { host: PUBLISHER }),
      (err: unknown) => {
        assert.ok(err instanceof VerifyFlowError);
        assert.match(err.message, /\/api\/evidence\/no-such-id\/commitment/);
        assert.doesNotMatch(
          err.message,
          /\/api\/records\//,
          'the canonical-form miss is migration noise, not a user-facing failure',
        );
        return true;
      },
    );
    assert.equal(pub.requested.length, 2, 'both candidates were tried before giving up');
  } finally {
    pub.restore();
  }
});

test('resolution: a prior-era PAGE URL resolves through the same ordered fallback', async () => {
  // Not just bare identifiers: a publisher's own record-page URL carries its origin
  // but not its API era, so it takes the identical canonical-first path.
  const pub = stubPublisher(/\/api\/evidence\//);
  try {
    const { url } = await resolveCommitment('url', `${PUBLISHER}/evidence/some-slug`);
    assert.equal(url, `${PUBLISHER}/api/evidence/some-slug/commitment`);
    assert.deepEqual(pub.requested, [
      `${PUBLISHER}/api/records/some-slug/commitment`,
      `${PUBLISHER}/api/evidence/some-slug/commitment`,
    ]);
  } finally {
    pub.restore();
  }
});

test('resolution: a complete commitment URL is fetched verbatim — one request, no era rewrite', async () => {
  // A caller-supplied resource URL is never re-segmented. Every commitment URL in the
  // wild today is prior-era, and rewriting one onto a segment its publisher may not
  // serve would break the input that works best.
  const pub = stubPublisher(/\/api\/evidence\//);
  try {
    const direct = `${PUBLISHER}/api/evidence/some-slug/commitment`;
    const { url } = await resolveCommitment('url', direct);
    assert.equal(url, direct);
    assert.deepEqual(pub.requested, [direct], 'exactly what was handed to us, once');
  } finally {
    pub.restore();
  }
});

test('resolution: a cancelled verification does not issue the fallback request', async () => {
  // Abort is not "this segment did not answer" — trying the next candidate would
  // issue a request the user already asked us to stop making.
  const controller = new AbortController();
  const requested: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    requested.push(String(input));
    controller.abort();
    return Promise.reject(new DOMException('The operation was aborted.', 'AbortError'));
  }) as typeof globalThis.fetch;
  try {
    await assert.rejects(
      resolveCommitment('hash', 'some-slug', controller.signal, { host: PUBLISHER }),
    );
    assert.equal(requested.length, 1, 'no fallback request after cancellation');
  } finally {
    globalThis.fetch = real;
  }
});

// --- Self-certifying signers on the site (hub ADR-0030 §4 rule 3, §10) -----
//
// Wave N14 P6. The question every test below answers: does any path show a
// self-certified signer as more than a check established?
//
// The packages are minted in process (Ed25519 via node:crypto, signed over the
// package-hash string exactly as q15-offline-bundle.test.ts's synthetic bundle
// is). The key-derived identifier is computed at run time by verify-core's own
// `deriveKeyDerivedIdentifier`, so no identifier or key is committed here. Each
// package runs through the real flow: resolveInput → buildVerifyInput →
// runVerify (verify-core's verifyRecord) → buildCheckRows / rollupVerdict /
// buildPreview.

const SC_REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const SC_COMMITMENT_URL = 'https://registry-host.test/api/records/sc-fixture/commitment';
const PROVIDER_NAME = 'Provider Display Name';
const SELF_NAME = 'Self Described Name';

interface MintOptions {
  /** 'key-derived' uses the identifier derived from the signing key;
   *  'key-derived-other' uses one derived from a DIFFERENT key (a mismatch);
   *  'urn' uses an opaque, non-key-derived identifier. */
  identifier: 'key-derived' | 'key-derived-other' | 'urn';
  bindingTier: string;
  /** Carry the registry inline in the bundle (`trustRegistry`). */
  inlineRegistry: boolean;
  /** Declare `trustRegistryUrl` on the view. */
  declareUrl: boolean;
  /** Carry the §8.8.1 informational provider block. */
  signerIdentityBlock?: boolean;
}

interface Minted {
  commitment: Record<string, unknown>;
  registry: Record<string, unknown>;
  identifier: string;
}

function spkiB64(publicKey: ReturnType<typeof generateKeyPairSync>['publicKey']): string {
  return Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
}

function mintSigned(o: MintOptions): Minted {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = spkiB64(publicKey);
  const identifier =
    o.identifier === 'key-derived'
      ? deriveKeyDerivedIdentifier(publicKeyB64)
      : o.identifier === 'key-derived-other'
        ? deriveKeyDerivedIdentifier(spkiB64(generateKeyPairSync('ed25519').publicKey))
        : 'urn:civic-record:platform:synthetic-publisher';
  // ADR-0030 §5: under a key-derived identifier `kid` SHOULD be the identifier.
  const kid = o.identifier === 'urn' ? 'test:synthetic-2026' : identifier;
  const signer = { bindingTier: o.bindingTier, identifier, displayName: SELF_NAME };
  const pkg: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    type: 'analysis/datHere/v1',
    signer,
    metadata: { signingKeyId: kid },
    subject: { title: 'Synthetic self-certifying fixture' },
    output: 'A minted record package for the site-side self-certifying tests.',
  };
  const packageHash = recomputePackageHash(pkg);
  const signature = {
    algorithm: 'Ed25519',
    publicKey: publicKeyB64,
    signature: Buffer.from(nodeSign(null, Buffer.from(packageHash, 'utf8'), privateKey)).toString('base64'),
    kid,
  };
  // The registry lists the envelope's (kid, publicKey) as ACTIVE, recording the
  // signer's own identifier — the most a registry could say for it.
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      {
        kid,
        publicKey: publicKeyB64,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: signer,
      },
    ],
  };
  const commitment: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    packageHash,
    package: pkg,
    signer: { bindingTier: o.bindingTier, identifier, displayName: SELF_NAME },
    signature,
    ...(o.inlineRegistry ? { trustRegistry: registry } : {}),
    ...(o.declareUrl ? { trustRegistryUrl: SC_REGISTRY_URL } : {}),
    ...(o.signerIdentityBlock
      ? { signerIdentity: { provider: 'example-provider', providerId: 'abcdef', displayName: PROVIDER_NAME } }
      : {}),
  };
  return { commitment, registry, identifier };
}

interface FlowRun {
  result: VerifyResult;
  rows: CheckRow[];
  steps: ResolveStep[];
  provenance: string | undefined;
  preview: ReturnType<typeof buildPreview>;
  verdict: ReturnType<typeof rollupVerdict>;
}

/** Run the site's flow. `bundle` reads everything inline with a fetch stub that
 *  throws; `hosted` serves the commitment (without an inline registry) and the
 *  registry at its declared URL, and 404s everything else. */
async function runFlow(m: Minted, mode: 'bundle' | 'hosted'): Promise<FlowRun> {
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const url = String(input);
    if (mode === 'bundle') throw new Error(`NETWORK BLOCKED in bundle mode: ${url}`);
    const json = (body: unknown) =>
      Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    if (url === SC_COMMITMENT_URL) return json(m.commitment);
    if (url === SC_REGISTRY_URL) return json(m.registry);
    return Promise.resolve(new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  }) as typeof globalThis.fetch;
  try {
    const steps: ResolveStep[] = [];
    const resolved =
      mode === 'bundle'
        ? await resolveInput('bundle', JSON.stringify(m.commitment), undefined, (s) => steps.push(s))
        : await resolveInput('url', SC_COMMITMENT_URL, undefined, (s) => steps.push(s));
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg);
    const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    const rows = buildCheckRows(result, vinput, resolved.commitment, registryMetaOf(resolved));
    return {
      result,
      rows,
      steps,
      provenance: resolved.registryProvenance,
      preview: buildPreview(resolved.pkg, resolved.commitment),
      verdict: rollupVerdict(result),
    };
  } finally {
    globalThis.fetch = real;
  }
}

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

/** Every string the check rows, verdict, preview and resolution steps put on the page. */
function renderedText(run: FlowRun): string {
  const parts: string[] = [];
  for (const r of run.rows) {
    parts.push(r.name, r.signal.label, r.signal.detail ?? '', r.depthNote ?? '');
    for (const m of r.math) parts.push(m.label, m.value, m.full ?? '');
  }
  parts.push(run.verdict.headline, run.verdict.detail);
  for (const s of run.steps) parts.push(s.label, s.url ?? '');
  for (const v of Object.values(run.preview)) if (typeof v === 'string') parts.push(v);
  return parts.join('\n');
}

test('registryProvenanceOf: inline → bundle; fetched from a declared URL → declared-url; no registry → none claimed', () => {
  const reg = { keys: [] } as unknown as Parameters<typeof registryProvenanceOf>[0];
  assert.equal(registryProvenanceOf(reg, { kind: 'inline' }), 'bundle');
  assert.equal(registryProvenanceOf(reg, { kind: 'fetched', url: SC_REGISTRY_URL }), 'declared-url');
  assert.equal(registryProvenanceOf(undefined, { kind: 'fetched' }), undefined);
  assert.equal(registryProvenanceOf(undefined, { kind: 'inline' }), undefined);
});

test('provenance: a key-derived pseudonymous signer whose BUNDLE registry lists its key active renders self_certified, not "active registered key"', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.provenance, 'bundle');
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  assert.equal(run.result.keyTrust?.verified, false);
  const kt = rowOf(run.rows, '5');
  assert.equal(kt.signal.label, KEY_TRUST_SIGNALS.self_certified.label);
  assert.equal(kt.signal.tier, 'normal');
  assert.notEqual(kt.signal.label, KEY_TRUST_SIGNALS.active.label);
  assert.doesNotMatch(renderedText(run), /registered key/i);
  // The registry's source is stated beside the status.
  assert.deepEqual(
    kt.math.find((x) => x.label === 'Registry source')?.value,
    'carried in the bundle (can lower this signer’s key status, never raise it)',
  );
  assert.notEqual(run.verdict.tier, 'verified');
  assert.equal(run.verdict.tier, 'normal');
});

test('provenance: the SAME key-derived signer with the registry fetched from its declared URL renders active', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: true });
  const run = await runFlow(m, 'hosted');
  assert.equal(run.provenance, 'declared-url');
  assert.equal(run.result.keyTrust?.status, 'active');
  const kt = rowOf(run.rows, '5');
  assert.equal(kt.signal.label, KEY_TRUST_SIGNALS.active.label);
  assert.equal(
    kt.math.find((x) => x.label === 'Registry source')?.value,
    'fetched from the registry URL the record declares',
  );
  // Check #14 never reports `ok` under a key-derived identifier, whatever the source.
  assert.equal(rowOf(run.rows, '14').signal.label, SIGNER_IDENTITY_SIGNALS.key_derived_match.label);
});

test('provenance: a signer whose identifier is NOT key-derived keeps its byline in both modes, and the registered-key reading only from its declared https: URL (#78)', async () => {
  for (const mode of ['bundle', 'hosted'] as const) {
    const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: mode === 'bundle', declareUrl: true });
    const run = await runFlow(m, mode);
    assert.equal(run.result.keyTrust?.status, 'active', `${mode}: verify-core’s status is unchanged`);
    const kt = rowOf(run.rows, '5');
    assert.equal(kt.signal.label === KEY_TRUST_SIGNALS.active.label, mode === 'hosted', mode);
    // The #5 row states where the registry came from, as it does for a key-derived signer.
    assert.deepEqual(kt.math.map((x) => x.label), ['kid', 'Registry status', 'Registry source'], mode);
    assert.equal(rowOf(run.rows, '14').signal.label === SIGNER_IDENTITY_SIGNALS.ok.label, mode === 'hosted', mode);
    // displayName keeps the byline position for a non-key-derived signer.
    assert.equal(run.preview.signerDisplayName, SELF_NAME, mode);
    assert.equal(run.preview.signerSelfDescribedName, undefined, mode);
    const registryStep = run.steps.find((s) => s.key === 'registry');
    assert.equal(
      registryStep?.label,
      mode === 'bundle' ? 'Read trust registry from bundle' : 'Fetched publisher trust registry',
    );
  }
});

test('key_derived_match: the #14 row for a derived match, with the derived identifier in the math', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.result.signerIdentity?.status, 'key_derived_match');
  const si = rowOf(run.rows, '14');
  assert.equal(si.signal.label, 'Signer identifier matches the signing key');
  assert.equal(si.signal.tier, 'normal');
  assert.equal(si.math.find((x) => x.label === 'Derived from the signing key')?.value, m.identifier);
  assert.equal(si.math.find((x) => x.label === 'Claimed signer')?.value, m.identifier);
});

test('key_derived_mismatch: a wrong key-derived identifier renders the fatal #14 row and the verdict alarms', async () => {
  const m = mintSigned({ identifier: 'key-derived-other', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.result.signatureValid, true, 'the signature itself verifies');
  assert.equal(run.result.signerIdentity?.status, 'key_derived_mismatch');
  const si = rowOf(run.rows, '14');
  assert.equal(si.signal.label, SIGNER_IDENTITY_SIGNALS.key_derived_mismatch.label);
  assert.equal(si.signal.tier, 'alarm');
  assert.notEqual(si.math.find((x) => x.label === 'Derived from the signing key')?.value, m.identifier);
  assert.equal(run.verdict.tier, 'alarm');
  assert.equal(run.verdict.headline, 'Verification failed');
});

test('self_certified with no registry: no provenance claimed, the registry step says none was fetched', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.provenance, undefined);
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  const kt = rowOf(run.rows, '5');
  assert.equal(kt.signal.label, KEY_TRUST_SIGNALS.self_certified.label);
  assert.equal(kt.math.find((x) => x.label === 'Registry source')?.value, 'none supplied');
  assert.equal(kt.depthNote, undefined, 'no registry snapshot caveat when no registry was used');
  const step = run.steps.find((s) => s.key === 'registry');
  assert.equal(step?.label, 'No trust registry declared — none fetched');
  assert.equal(step?.state, 'skipped');
  assert.equal(run.verdict.tier, 'normal');
});

// --- fullyOffline for a self-certified bundle (Wave N14 P7) ----------------
//
// `fullyOffline` is true for exactly one new case: bundle mode, the package inline, a
// key-derived `signer.identifier`, and neither `trustRegistryUrl` nor
// `trustRegistryUrlLegacy` declared. Every other case keeps today's rule (an inline
// package AND an inline registry, in bundle mode).

/** Resolve a commitment and report `fullyOffline` plus the fetches attempted. The
 *  stub serves the registry at its declared URL so a declared URL resolves. */
async function resolveOfflineFlag(
  commitment: Record<string, unknown>,
  registry: Record<string, unknown>,
  mode: 'bundle' | 'url' = 'bundle',
): Promise<{ fullyOffline: boolean; fetches: number }> {
  const real = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = ((input: unknown) => {
    fetches += 1;
    const url = String(input);
    const json = (body: unknown) =>
      Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    if (url === SC_COMMITMENT_URL) return json(commitment);
    if (url === SC_REGISTRY_URL) return json(registry);
    return Promise.resolve(new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  }) as typeof globalThis.fetch;
  try {
    const resolved =
      mode === 'bundle'
        ? await resolveInput('bundle', JSON.stringify(commitment))
        : await resolveInput('url', SC_COMMITMENT_URL);
    return { fullyOffline: resolved.fullyOffline, fetches };
  } finally {
    globalThis.fetch = real;
  }
}

test('fullyOffline: a self-certified bundle (inline package, key-derived signer, no registry URL) is fully offline', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const r = await resolveOfflineFlag(m.commitment, m.registry);
  assert.equal(r.fetches, 0);
  assert.equal(r.fullyOffline, true);
});

test('fullyOffline: the other side of the line — each departure from the self-certified case stays not fully offline', async () => {
  const keyDerived = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });

  // A declared trustRegistryUrl: the registry is fetched, so not offline.
  const withUrl = await resolveOfflineFlag({ ...keyDerived.commitment, trustRegistryUrl: SC_REGISTRY_URL }, keyDerived.registry);
  assert.equal(withUrl.fetches, 1, 'the declared registry is fetched');
  assert.equal(withUrl.fullyOffline, false, 'trustRegistryUrl declared');

  // A declared trustRegistryUrlLegacy alone: fetched too.
  const withLegacy = await resolveOfflineFlag(
    { ...keyDerived.commitment, trustRegistryUrlLegacy: SC_REGISTRY_URL },
    keyDerived.registry,
  );
  assert.equal(withLegacy.fetches, 1);
  assert.equal(withLegacy.fullyOffline, false, 'trustRegistryUrlLegacy declared');

  // A signer whose identifier is not key-derived, with no registry and no URL:
  // unchanged, not fully offline.
  const urn = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const urnRun = await resolveOfflineFlag(urn.commitment, urn.registry);
  assert.equal(urnRun.fetches, 0);
  assert.equal(urnRun.fullyOffline, false, 'not key-derived');

  // The package not inline (a location to fetch instead): not offline.
  const noInlinePkg: Record<string, unknown> = { ...keyDerived.commitment };
  delete noInlinePkg['package'];
  const pkgFetched = await resolveOfflineFlag(
    { ...noInlinePkg, packageUrl: 'https://registry-host.test/pkg.json' },
    keyDerived.registry,
  );
  assert.equal(pkgFetched.fullyOffline, false, 'package not inline');

  // Not bundle mode (a hosted URL), even with the package inline: not offline.
  const hosted = await resolveOfflineFlag(keyDerived.commitment, keyDerived.registry, 'url');
  assert.equal(hosted.fullyOffline, false, 'hosted mode');
});

test('fullyOffline: the existing rule is unchanged — an inline registry with an inline package is fully offline for any signer', async () => {
  for (const identifier of ['key-derived', 'urn'] as const) {
    const m = mintSigned({ identifier, bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
    const r = await resolveOfflineFlag(m.commitment, m.registry);
    assert.equal(r.fetches, 0, identifier);
    assert.equal(r.fullyOffline, true, identifier);
  }
});

test('registry_unavailable under a SET-ASIDE bundle registry: the #5 detail says the bundle registry was not used', async () => {
  // A key-derived identifier at a tier other than pseudonymous: verify-core sets
  // the bundle registry's `active` aside and returns registry_unavailable.
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'platform', inlineRegistry: true, declareUrl: true });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.result.keyTrust?.status, 'registry_unavailable');
  assert.equal(run.result.keyTrust?.verified, false);
  const kt = rowOf(run.rows, '5');
  assert.equal(kt.signal.label, KEY_TRUST_BUNDLE_REGISTRY_NOT_USED.label);
  assert.equal(kt.signal.detail, KEY_TRUST_BUNDLE_REGISTRY_NOT_USED.detail);
  assert.equal(kt.signal.tier, KEY_TRUST_SIGNALS.registry_unavailable.tier, 'same tier, no new status');
  assert.doesNotMatch(kt.signal.detail ?? '', /could not be loaded/);
  assert.notEqual(run.verdict.tier, 'verified');
});

test('registry_unavailable with NO registry at all keeps its own sentence', () => {
  const rows = buildCheckRows(
    mkResult({ keyTrust: { status: 'registry_unavailable', verified: false } as VerifyResult['keyTrust'] }),
    buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {
      signer: { bindingTier: 'platform', identifier: `${KEY_DERIVED_IDENTIFIER_PREFIX}zfixture` },
    }),
    { packageHash: 'ab'.repeat(32) },
    { kind: 'fetched', available: false },
  );
  assert.equal(rowOf(rows, '5').signal.label, KEY_TRUST_SIGNALS.registry_unavailable.label);
});

test('§10 displayName: under a key-derived identifier it is self-description, never the signer byline', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.preview.signerDisplayName, undefined, 'not in the byline position');
  assert.equal(run.preview.signerSelfDescribedName, SELF_NAME);
  // Never beside a check mark: no verified-tier row carries the name.
  for (const r of run.rows.filter((x) => x.signal.tier === 'verified')) {
    for (const line of r.math) assert.doesNotMatch(line.value, new RegExp(SELF_NAME), `row #${r.num}`);
  }
});

test('§10 signerIdentity block: never rendered for a self-certified signer', async () => {
  const m = mintSigned({
    identifier: 'key-derived',
    bindingTier: 'pseudonymous',
    inlineRegistry: false,
    declareUrl: false,
    signerIdentityBlock: true,
  });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  assert.doesNotMatch(renderedText(run), new RegExp(PROVIDER_NAME));
  assert.doesNotMatch(renderedText(run), /example-provider/);
});

test('§10 bindingTier: the tier value is not rendered as anything a check established', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
  const run = await runFlow(m, 'bundle');
  assert.doesNotMatch(renderedText(run), /pseudonymous/i);
});

test('§10 kid: shown as the envelope key label only, never as a registered key', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
  const run = await runFlow(m, 'bundle');
  const kt = rowOf(run.rows, '5');
  assert.deepEqual(kt.math.map((x) => x.label), ['Envelope key label (kid)', 'Key-trust status', 'Registry source']);
  assert.equal(kt.math[0].value, m.identifier);
  assert.doesNotMatch(renderedText(run), /registered key|Registry status/i);
});

test('§10 continuity: the self-certified run says "same key", never "same publisher" or "same person"', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const text = renderedText(await runFlow(m, 'bundle'));
  assert.match(text, /same key/);
  assert.doesNotMatch(text, /same (publisher|person)/i);
});

test('rollupVerdict: a self-certified package that passes every other check reads normal, never verified', () => {
  const v = rollupVerdict(
    mkResult({
      keyTrust: { status: 'self_certified', verified: false } as VerifyResult['keyTrust'],
      signerIdentity: { status: 'key_derived_match' } as VerifyResult['signerIdentity'],
      contentProfile: { status: 'ok' } as VerifyResult['contentProfile'],
    }),
  );
  assert.equal(v.tier, 'normal');
  assert.equal(v.headline, 'Signature valid — self-certified signer');
  assert.doesNotMatch(v.headline, /^Verified/);
});

test('rollupVerdict: key_derived_mismatch alarms even when everything else is green', () => {
  const v = rollupVerdict(
    mkResult({ signerIdentity: { status: 'key_derived_mismatch' } as VerifyResult['signerIdentity'] }),
  );
  assert.equal(v.tier, 'alarm');
});

test('#16 content profile: each status renders its ADR-0029 §5 tier in row #16', () => {
  const expected = {
    ok: 'verified',
    contentProfile_absent: 'normal',
    contentProfile_unknown: 'attention',
    contentProfile_inconsistent: 'attention',
  } as const;
  for (const [status, tier] of Object.entries(expected)) {
    const rows = buildCheckRows(
      mkResult({
        contentProfile: {
          status,
          ...(status === 'contentProfile_absent' ? {} : { contentProfile: 'default' }),
          producerProfile: 'scripted-recomputation/eval-run',
        } as VerifyResult['contentProfile'],
      }),
      buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {}),
      { packageHash: 'ab'.repeat(32) },
    );
    const r = rowOf(rows, '16');
    assert.equal(r.name, 'Content profile');
    assert.equal(r.signal.tier, tier, status);
    assert.equal(r.signal.label, CONTENT_PROFILE_SIGNALS[status as keyof typeof expected].label);
    assert.equal(r.math.find((x) => x.label === 'producerProfile')?.value, 'scripted-recomputation/eval-run');
  }
});

test('#16 content profile: the verdict treats it by tier — inconsistent never alarms, absent keeps a green package verified', () => {
  const inconsistent = rollupVerdict(
    mkResult({ contentProfile: { status: 'contentProfile_inconsistent' } as VerifyResult['contentProfile'] }),
  );
  assert.notEqual(inconsistent.tier, 'alarm');
  const absent = rollupVerdict(
    mkResult({ contentProfile: { status: 'contentProfile_absent' } as VerifyResult['contentProfile'] }),
  );
  assert.equal(absent.tier, 'verified');
});

test('#16 content profile: a real package with no contentProfile key renders the calm absent row', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const run = await runFlow(m, 'bundle');
  assert.equal(run.result.contentProfile?.status, 'contentProfile_absent');
  const r = rowOf(run.rows, '16');
  assert.equal(r.signal.tier, 'normal');
  assert.equal(r.math[0].value, 'absent (read as default)');
});

test('#4 content_bytes_unavailable: rendered attention with its own label, never verified', () => {
  const rows = buildCheckRows(
    mkResult({ contentHash: { status: 'content_bytes_unavailable' } as VerifyResult['contentHash'] }),
    buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {}),
    { packageHash: 'ab'.repeat(32) },
  );
  const r = rowOf(rows, '4');
  assert.equal(r.signal.label, CONTENT_HASH_SIGNALS.content_bytes_unavailable.label);
  assert.equal(r.signal.tier, 'attention');
});

test('#15 capture-method labels: script-run and tool-emitted render their plain-language readings', () => {
  for (const method of ['script-run', 'tool-emitted'] as const) {
    const rows = buildCheckRows(
      mkResult({ captureMethodVocab: { status: 'ok', captureMethod: method, profileType: 'scripted-recomputation' } as VerifyResult['captureMethodVocab'] }),
      buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {}),
      { packageHash: 'ab'.repeat(32) },
    );
    const r = rowOf(rows, '15');
    assert.equal(r.math.find((x) => x.label === 'How it was captured')?.value, CAPTURE_METHOD_LABELS[method]);
  }
});

// --- Registry provenance and recognition for a key-derived signer (Wave N14 P9) ---
//
// A trust registry counts as declared only when fetched from an https: URL. A
// declared registry that does not list a self-certified signer's key disavows it in
// the recognition card. A bundle registry that is not valid is described as such.
// Every signer whose identifier is not key-derived keeps today's behaviour.

const LISTED_REGISTRY_URL = `${HOST_DIRECTORY.publishers[0].registryOrigin}/.well-known/typed-publisher.json`;
const HTTP_REGISTRY_URL = 'http://registry-host.test/trust-registry.json';
const EMPTY_REGISTRY = { generatedAt: '2026-09-21T00:00:00.000Z', keys: [] };
const dataUrlOf = (doc: unknown): string => `data:application/json,${encodeURIComponent(JSON.stringify(doc))}`;

/** Install a fetch stub serving `routes` (URL → JSON body); a `data:` URL is read by
 *  the platform fetch; anything else 404s. Returns the restore function. */
function stubFetch(routes: Record<string, unknown>): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith('data:')) return real(url, init);
    if (url in routes) {
      return Promise.resolve(
        new Response(JSON.stringify(routes[url]), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    }
    return Promise.resolve(new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  }) as typeof globalThis.fetch;
  return () => {
    globalThis.fetch = real;
  };
}

/** Resolve and verify `commitment` in bundle mode, or from SC_COMMITMENT_URL in url
 *  mode, with `routes` served. */
async function runWith(
  commitment: Record<string, unknown>,
  routes: Record<string, unknown>,
  mode: 'bundle' | 'url' = 'bundle',
) {
  const restore = stubFetch({ ...routes, [SC_COMMITMENT_URL]: commitment });
  try {
    const steps: ResolveStep[] = [];
    const resolved =
      mode === 'bundle'
        ? await resolveInput('bundle', JSON.stringify(commitment), undefined, (s) => steps.push(s))
        : await resolveInput('url', SC_COMMITMENT_URL, undefined, (s) => steps.push(s));
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    const rows = buildCheckRows(result, vinput, resolved.commitment, registryMetaOf(resolved));
    return { resolved, vinput, result, rows, steps, registryStep: steps.find((s) => s.key === 'registry') };
  } finally {
    restore();
  }
}

test('registryProvenanceOf: a registry counts as declared only when fetched from an https: URL', () => {
  const reg = { keys: [] } as unknown as Parameters<typeof registryProvenanceOf>[0];
  assert.equal(registryProvenanceOf(reg, { kind: 'fetched', url: 'https://registry-host.test/r.json' }), 'declared-url');
  for (const url of [HTTP_REGISTRY_URL, dataUrlOf({ keys: [] }), 'blob:https://registry-host.test/abc', '/r.json']) {
    assert.equal(registryProvenanceOf(reg, { kind: 'fetched', url }), 'bundle', url.slice(0, 20));
  }
});

test('recognition: a declared https: registry at a listed origin that does not list a self-certified signer’s key reads "Unknown publisher"', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const run = await runWith(commitment, { [LISTED_REGISTRY_URL]: EMPTY_REGISTRY }, 'url');
  assert.equal(run.resolved.registryProvenance, 'declared-url');
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  // The key-trust row keeps ADR-0030's calm self_certified reading.
  assert.equal(rowOf(run.rows, '5').signal.label, KEY_TRUST_SIGNALS.self_certified.label);
  assert.equal(rowOf(run.rows, '5').signal.tier, 'normal');
  const rec = resolveHostRecognition(
    run.resolved.commitment,
    run.result.keyTrust,
    HOST_DIRECTORY,
    run.resolved.registryProvenance,
  );
  assert.equal(rec.status, 'unknown_publisher');
  assert.equal(rec.signal.label, 'Unknown publisher');
  assert.match(rec.signal.detail ?? '', /does not vouch for this signer/);
  assert.equal(rec.publisher, undefined);
});

test('recognition: a self-certified signer whose registry came from the bundle keeps "Host recognized — signing key not registry-confirmed"', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const run = await runWith(commitment, {});
  assert.equal(run.resolved.registryProvenance, 'bundle');
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  const rec = resolveHostRecognition(
    run.resolved.commitment,
    run.result.keyTrust,
    HOST_DIRECTORY,
    run.resolved.registryProvenance,
  );
  assert.equal(rec.status, 'host_recognized_key_unconfirmed');
});

test('recheck: a key-derived signer is never re-checked to active from a registry URL that is not https:', async () => {
  for (const which of ['data', 'http'] as const) {
    const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: false });
    const url = which === 'data' ? dataUrlOf(m.registry) : HTTP_REGISTRY_URL;
    const commitment = { ...m.commitment, trustRegistryUrl: url };
    const run = await runWith(commitment, {});
    assert.equal(run.result.keyTrust?.status, 'self_certified', which);
    // Not offered: only an https: URL is the declared registry.
    assert.equal(
      canRecheckKeyTrust(registryMetaOf(run.resolved), {
        ...run.result,
        keyTrust: { status: 'revoked', verified: false },
      } as VerifyResult),
      false,
      `${which}: no recheck offered`,
    );
    // And the recheck itself treats it as carried in the bundle.
    const restore = stubFetch({ [HTTP_REGISTRY_URL]: m.registry });
    try {
      const live = await recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput);
      assert.equal(live.status, 'self_certified', which);
      assert.equal(live.verified, false, which);
      assert.equal(live.changed, false, which);
    } finally {
      restore();
    }
  }
});

test('recheck: a key-derived signer re-checked against its https: registry applies the key-derived rule', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: true, declareUrl: true });
  const run = await runWith(m.commitment, {});
  assert.equal(run.result.keyTrust?.status, 'self_certified');
  assert.equal(
    canRecheckKeyTrust(registryMetaOf(run.resolved), {
      ...run.result,
      keyTrust: { status: 'revoked', verified: false },
    } as VerifyResult),
    true,
    'offered for an https: URL',
  );
  // The live https: registry does not list the key: self_certified, not unknown_key.
  let restore = stubFetch({ [SC_REGISTRY_URL]: EMPTY_REGISTRY });
  try {
    const live = await recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput);
    assert.equal(live.status, 'self_certified');
    assert.equal(live.verified, false);
  } finally {
    restore();
  }
  // The live https: registry lists the key active: active (ADR-0030 §4 rule 3).
  restore = stubFetch({ [SC_REGISTRY_URL]: m.registry });
  try {
    const live = await recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput);
    assert.equal(live.status, 'active');
    assert.equal(live.verified, true);
  } finally {
    restore();
  }
});

test('recheck: a signer that is not key-derived is re-checked only against an https: registry URL (#78)', async () => {
  for (const which of ['data', 'http'] as const) {
    const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
    const url = which === 'data' ? dataUrlOf(m.registry) : HTTP_REGISTRY_URL;
    const run = await runWith({ ...m.commitment, trustRegistryUrl: url }, {});
    assert.equal(run.result.keyTrust?.status, 'active', which);
    assert.equal(canRecheckKeyTrust(registryMetaOf(run.resolved), run.result), false, `${which}: no recheck offered`);
    // Called anyway, it refuses rather than confirming the key from the same bytes.
    const restore = stubFetch({ [HTTP_REGISTRY_URL]: m.registry });
    try {
      await assert.rejects(
        recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput),
        VerifyFlowError,
        which,
      );
    } finally {
      restore();
    }
  }
  // An https: URL: offered, and the live registry decides.
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: true });
  const run = await runWith(m.commitment, {});
  assert.equal(canRecheckKeyTrust(registryMetaOf(run.resolved), run.result), true, 'https: offered');
  let restore = stubFetch({ [SC_REGISTRY_URL]: EMPTY_REGISTRY });
  try {
    const live = await recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput);
    assert.equal(live.status, 'unknown_key');
    assert.equal(live.verified, false);
    assert.equal(live.changed, true);
  } finally {
    restore();
  }
  restore = stubFetch({ [SC_REGISTRY_URL]: m.registry });
  try {
    const live = await recheckKeyTrustLive(run.resolved.commitment as Commitment, run.result, run.vinput);
    assert.equal(live.status, 'active');
    assert.equal(live.verified, true);
    assert.equal(live.changed, false);
  } finally {
    restore();
  }
});

test('registry step: a key-derived signer whose bundle registry is not valid is told so, not "No trust registry declared"', async () => {
  const m = mintSigned({ identifier: 'key-derived', bindingTier: 'pseudonymous', inlineRegistry: false, declareUrl: false });
  const run = await runWith({ ...m.commitment, trustRegistry: { keys: 'not a list' } }, {});
  assert.equal(run.resolved.registry, undefined);
  assert.equal(run.registryStep?.label, 'Trust registry in bundle is not valid — not used');
  assert.equal(run.registryStep?.kind, 'inline');
  assert.equal(run.registryStep?.state, 'skipped');
  assert.equal(
    rowOf(run.rows, '5').math.find((x) => x.label === 'Registry source')?.value,
    'carried in the bundle, not valid — not used',
  );
  assert.equal(run.result.keyTrust?.status, 'self_certified');
});

test('registry step: a signer that is not key-derived gets the same registry steps as a key-derived one (#78)', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const invalid = await runWith({ ...m.commitment, trustRegistry: { keys: 'not a list' } }, {});
  assert.equal(invalid.registryStep?.label, 'Trust registry in bundle is not valid — not used');
  assert.equal(invalid.registryStep?.state, 'skipped');
  const none = await runWith(m.commitment, {});
  assert.equal(none.registryStep?.label, 'No trust registry declared — none fetched');
  assert.equal(none.registryStep?.state, 'skipped');
  const http = await runWith({ ...m.commitment, trustRegistryUrl: HTTP_REGISTRY_URL }, { [HTTP_REGISTRY_URL]: m.registry });
  assert.equal(http.registryStep?.label, 'Read trust registry from a URL that is not https: — it can lower key trust, never raise it');
  assert.equal(http.result.keyTrust?.status, 'active');
  assert.notEqual(rollupVerdict(http.result, registryMetaOf(http.resolved)).headline, 'Verified');
  const https = await runWith({ ...m.commitment, trustRegistryUrl: SC_REGISTRY_URL }, { [SC_REGISTRY_URL]: m.registry });
  assert.equal(https.registryStep?.label, 'Fetched publisher trust registry');
  assert.equal(rollupVerdict(https.result, registryMetaOf(https.resolved)).headline, 'Verified');
});

// --- A registry or publisher directory the signer supplied (#78) -------------
//
// A trust registry carried in the record, or read from a URL that is not https:, is
// supplied by whoever made the record; so is a publisher directory carried in it.
// For every signer, neither earns what a registry fetched from the declared https:
// URL, or the typedstandards.org directory, earns:
//   - key trust from such a registry is not shown with the registered-key label or
//     tier, and the #5 row says where the registry came from;
//   - the headline does not read an unqualified "Verified";
//   - the recognition card never reads "Known publisher" or the curated name;
//   - the live re-check confirms key trust only from an https: URL.
// verify-core's statuses are unchanged; what the page shows is the site's. Every key
// is generated at test time and no record file is committed.

const BRAND = HOST_DIRECTORY.publishers[0].displayName;
const DIRECTORY_ROUTE = { [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };
const SUPPLIED_SOURCE = 'carried in the bundle (can lower this signer’s key status, never raise it)';
const NOT_HTTPS_SOURCE = 'read from a registry URL that is not https: (can lower this signer’s key status, never raise it)';
const NOT_HTTPS_STEP = 'Read trust registry from a URL that is not https: — it can lower key trust, never raise it';

/** What the page shows for a run, computed as the <Verifier> computes it. */
function pageOf(run: Awaited<ReturnType<typeof runWith>>) {
  return {
    keyTrust: rowOf(run.rows, '5'),
    signerIdentity: run.rows.find((r) => r.num === '14'),
    verdict: rollupVerdict(run.result, registryMetaOf(run.resolved)),
    recognition: resolveHostRecognition(
      run.resolved.commitment,
      run.result.keyTrust,
      run.resolved.directory,
      run.resolved.registryProvenance,
    ),
  };
}

type Page = ReturnType<typeof pageOf>;

function assertNotRegistered(p: Page, label: string): void {
  assert.notEqual(p.keyTrust.signal.label, KEY_TRUST_SIGNALS.active.label, `${label}: #5 label`);
  assert.equal(p.keyTrust.signal.tier, 'attention', `${label}: #5 tier`);
  assert.match(p.keyTrust.signal.detail ?? '', /not checked against the publisher’s domain/, `${label}: #5 detail`);
  assert.notEqual(p.verdict.tier, 'verified', `${label}: headline tier`);
  assert.notEqual(p.verdict.headline, 'Verified', `${label}: headline`);
  assert.match(p.verdict.detail, /not checked against the publisher’s domain/, `${label}: headline detail`);
}

function assertNoBrand(p: Page, label: string): void {
  assert.notEqual(p.recognition.status, 'known_publisher', `${label}: recognition`);
  assert.notEqual(p.recognition.signal.tier, 'verified', `${label}: recognition tier`);
  assert.equal(p.recognition.publisher, undefined, `${label}: no curated entry`);
  assert.doesNotMatch(`${p.recognition.signal.label}\n${p.recognition.signal.detail ?? ''}`, new RegExp(BRAND), `${label}: no curated name`);
}

test('a registry carried in the record never earns the registered-key reading, the Verified headline or Known publisher, in any mode', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const runs = [
    { label: 'bundle', run: await runWith(commitment, {}), recognition: 'directory_unavailable' },
    {
      label: 'bundle carrying the curated directory',
      run: await runWith({ ...commitment, hostDirectory: HOST_DIRECTORY }, {}),
      recognition: 'directory_unavailable',
    },
    { label: 'url, curated directory', run: await runWith(commitment, DIRECTORY_ROUTE, 'url'), recognition: 'host_recognized_key_unconfirmed' },
  ];
  for (const { label, run, recognition } of runs) {
    assert.equal(run.result.keyTrust?.status, 'active', `${label}: verify-core’s status is unchanged`);
    assert.equal(run.resolved.registryProvenance, 'bundle', label);
    const p = pageOf(run);
    assertNotRegistered(p, label);
    assert.equal(p.keyTrust.math.find((x) => x.label === 'Registry source')?.value, SUPPLIED_SOURCE, label);
    assertNoBrand(p, label);
    assert.equal(p.recognition.status, recognition, label);
  }
});

test('a registry read from a URL that is not https: is supplied by the record too, for a signer that is not key-derived', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const cases = [
    { label: 'data:, bundle', url: dataUrlOf(m.registry), mode: 'bundle' as const },
    { label: 'data:, url', url: dataUrlOf(m.registry), mode: 'url' as const },
    { label: 'http:, url', url: HTTP_REGISTRY_URL, mode: 'url' as const },
  ];
  for (const c of cases) {
    const run = await runWith(
      { ...m.commitment, trustRegistryUrl: c.url },
      { [HTTP_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE },
      c.mode,
    );
    assert.equal(run.result.keyTrust?.status, 'active', `${c.label}: verify-core’s status is unchanged`);
    assert.equal(run.resolved.registryProvenance, 'bundle', c.label);
    const p = pageOf(run);
    assertNotRegistered(p, c.label);
    assert.equal(p.keyTrust.math.find((x) => x.label === 'Registry source')?.value, NOT_HTTPS_SOURCE, c.label);
    assert.equal(p.keyTrust.depthNote, undefined, `${c.label}: no "live registry" note`);
    assert.equal(run.registryStep?.label, NOT_HTTPS_STEP, c.label);
    assertNoBrand(p, c.label);
  }
});

test('#14: an identity only a supplied registry records is not shown as matching the registry', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: true });
  const supplied = pageOf(await runWith(m.commitment, {}));
  assert.equal(supplied.signerIdentity?.signal.tier, 'normal');
  assert.notEqual(supplied.signerIdentity?.signal.label, SIGNER_IDENTITY_SIGNALS.ok.label);
  assert.match(supplied.signerIdentity?.signal.detail ?? '', /not checked against the publisher’s domain/);
  // The same identity in a registry fetched from the declared https: URL still matches.
  const hosted = { ...m.commitment };
  delete hosted['trustRegistry'];
  const declared = pageOf(await runWith(hosted, { [SC_REGISTRY_URL]: m.registry }, 'url'));
  assert.equal(declared.signerIdentity?.signal.label, SIGNER_IDENTITY_SIGNALS.ok.label);
  // A supplied registry that records a DIFFERENT identity still alarms: it can lower.
  const other = { ...m.registry, keys: [{ ...(m.registry.keys as Record<string, unknown>[])[0], signerIdentity: { identifier: 'urn:civic-record:platform:other' } }] };
  const lowered = await runWith({ ...m.commitment, trustRegistry: other }, {});
  assert.equal(lowered.result.signerIdentity?.status, 'signer_identity_mismatch');
  assert.equal(pageOf(lowered).signerIdentity?.signal.tier, 'alarm');
  assert.equal(pageOf(lowered).verdict.tier, 'alarm');
});

test('a supplied registry still lowers: a key it lists as revoked alarms, as before', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const revoked = {
    ...m.registry,
    keys: [{ ...(m.registry.keys as Record<string, unknown>[])[0], status: 'revoked', revokedAt: '2026-02-01T00:00:00.000Z' }],
  };
  for (const commitment of [
    { ...m.commitment, trustRegistry: revoked },
    { ...m.commitment, trustRegistryUrl: dataUrlOf(revoked) },
  ]) {
    const p = pageOf(await runWith(commitment, {}));
    assert.equal(p.keyTrust.signal.label, KEY_TRUST_SIGNALS.revoked.label);
    assert.equal(p.keyTrust.signal.tier, 'alarm');
    assert.equal(p.verdict.tier, 'alarm');
  }
});

test('the headline: content-private, and deprecated_valid, from a supplied registry never read verified', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const sealed: Record<string, unknown> = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  delete sealed['package'];
  const run = await runWith(sealed, {});
  assert.equal(run.result.envelopeIntegrity.status, 'unavailable');
  assert.equal(run.result.keyTrust?.status, 'active');
  const v = rollupVerdict(run.result, registryMetaOf(run.resolved));
  assert.notEqual(v.tier, 'verified');
  assert.notEqual(v.headline, 'Commitment verified — content private');

  const supplied = { kind: 'inline', available: true, provenance: 'bundle' } as const;
  const declared = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;
  const deprecatedValid = { keyTrust: { status: 'deprecated_valid', verified: true } as VerifyResult['keyTrust'] };
  assert.equal(rollupVerdict(mkResult(), declared).headline, 'Verified', 'control: the declared registry');
  assert.notEqual(rollupVerdict(mkResult(), supplied).tier, 'verified');
  const rows = buildCheckRows(mkResult(deprecatedValid), buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {}), { packageHash: 'ab'.repeat(32) }, supplied);
  assert.notEqual(rowOf(rows, '5').signal.label, KEY_TRUST_SIGNALS.deprecated_valid.label);
  assert.equal(rowOf(rows, '5').signal.tier, 'attention');
  const declaredRows = buildCheckRows(mkResult(deprecatedValid), buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {}), { packageHash: 'ab'.repeat(32) }, declared);
  assert.equal(rowOf(declaredRows, '5').signal.label, KEY_TRUST_SIGNALS.deprecated_valid.label, 'control');
});

test('a publisher directory carried in the record is never read: recognition uses only the typedstandards.org directory', async () => {
  // The signer's own https: registry lists its key, so key trust is earned on its own
  // origin; the directory it carries names that origin with the curated name.
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: true });
  const ownOrigin = new URL(SC_REGISTRY_URL).origin;
  const carried = {
    ...m.commitment,
    hostDirectory: { version: 1, updated: '2026-09-21', publishers: [{ registryOrigin: ownOrigin, displayName: BRAND, profileUrl: ownOrigin }] },
  };
  for (const mode of ['bundle', 'url'] as const) {
    const run = await runWith(carried, { [SC_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE }, mode);
    const p = pageOf(run);
    assertNoBrand(p, mode);
    assert.equal(p.recognition.status, mode === 'url' ? 'unknown_publisher' : 'directory_unavailable', mode);
    assert.equal(run.steps.some((s) => s.label === 'Read publisher directory from bundle'), false, `${mode}: not read`);
    const carriedStep = run.steps.find((s) => /directory/i.test(s.label) && /not used/.test(s.label));
    assert.equal(carriedStep?.state, 'skipped', `${mode}: the page says the carried directory was not used`);
  }
  // An entry for an opaque (data:) origin cannot match a data: registry URL either.
  const d = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const opaque = {
    ...d.commitment,
    trustRegistryUrl: dataUrlOf(d.registry),
    hostDirectory: { version: 1, updated: '2026-09-21', publishers: [{ registryOrigin: 'data:,x', displayName: BRAND }] },
  };
  assertNoBrand(pageOf(await runWith(opaque, {})), 'data: origin');
});

test('control: a signer that is not key-derived, its registry fetched from the declared https: URL, keeps the registered key, Verified and Known publisher', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: false, declareUrl: false });
  const run = await runWith(
    { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL },
    { [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE },
    'url',
  );
  assert.equal(run.resolved.registryProvenance, 'declared-url');
  const p = pageOf(run);
  assert.equal(p.keyTrust.signal.label, KEY_TRUST_SIGNALS.active.label);
  assert.equal(p.keyTrust.signal.tier, 'verified');
  assert.equal(p.keyTrust.math.find((x) => x.label === 'Registry source')?.value, 'fetched from the registry URL the record declares');
  assert.equal(p.signerIdentity?.signal.label, SIGNER_IDENTITY_SIGNALS.ok.label);
  assert.equal(p.verdict.headline, 'Verified');
  assert.equal(p.recognition.status, 'known_publisher');
  assert.equal(p.recognition.publisher?.displayName, BRAND);
  assert.equal(run.registryStep?.label, 'Fetched publisher trust registry');
});

test('presentVerification is what the page renders: its rows, headline and recognition read the registry’s provenance', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const supplied = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const declared: Record<string, unknown> = { ...supplied };
  delete declared['trustRegistry'];
  const suppliedRun = await runWith(supplied, DIRECTORY_ROUTE, 'url');
  const declaredRun = await runWith(declared, { [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE }, 'url');
  for (const run of [suppliedRun, declaredRun]) {
    const shown = presentVerification(run.resolved, run.vinput, run.result);
    const p = pageOf(run);
    assert.deepEqual(shown.rows, run.rows);
    assert.deepEqual(shown.verdict, p.verdict);
    assert.deepEqual(shown.recognition, p.recognition);
  }
  const shown = presentVerification(suppliedRun.resolved, suppliedRun.vinput, suppliedRun.result);
  assert.deepEqual(rowOf(shown.rows, '5').signal, { ...KEY_TRUST_SUPPLIED_REGISTRY, icon: 'warning' });
  assert.equal(rowOf(shown.rows, '14').signal.label, SIGNER_IDENTITY_SUPPLIED_REGISTRY.label);
  assert.equal(shown.verdict.headline, 'Verified, with caveats');
  assert.equal(shown.recognition.status, 'host_recognized_key_unconfirmed');
});

test('a carried publisher directory is reported as its own skipped step, beside the curated directory when that loads', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const run = await runWith({ ...m.commitment, hostDirectory: HOST_DIRECTORY }, DIRECTORY_ROUTE, 'url');
  const keys = run.steps.map((s) => s.key);
  assert.equal(new Set(keys).size, keys.length, 'one step per key');
  const carried = run.steps.find((s) => s.key === 'bundle-directory');
  assert.equal(carried?.label, 'Publisher directory in the bundle — not used');
  assert.equal(carried?.state, 'skipped');
  assert.equal(run.steps.find((s) => s.key === 'directory')?.label, 'Loaded the typedstandards.org publisher directory');
});

// --- Follow-ons from #78 (#93), and attention-tier checks in the headline (#86) ---

const DECLARED_META = { kind: 'fetched', available: true, provenance: 'declared-url' } as const;
const SUPPLIED_META = { kind: 'inline', available: true, provenance: 'bundle' } as const;

/** Install a fetch stub that records every URL and serves `routes`; anything else 404s. */
function recordFetch(routes: Record<string, unknown>): { calls: string[]; restore: () => void } {
  const calls: string[] = [];
  const restore = stubFetch(routes);
  const stubbed = globalThis.fetch;
  globalThis.fetch = ((input: unknown, init?: RequestInit) => {
    calls.push(String(input));
    return stubbed(input as string, init);
  }) as typeof globalThis.fetch;
  return { calls, restore };
}

test('#93 item 1: online, a record carrying its own registry whose key the declared https: registry does not list reads "Unknown publisher"', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const routes = { [LISTED_REGISTRY_URL]: EMPTY_REGISTRY, ...DIRECTORY_ROUTE };
  for (const mode of ['url', 'hash'] as const) {
    const { restore } = recordFetch({ ...routes, [SC_COMMITMENT_URL]: commitment });
    try {
      const resolved =
        mode === 'url'
          ? await resolveInput('url', SC_COMMITMENT_URL)
          : await resolveInput('hash', 'sc-fixture', undefined, undefined, { host: new URL(SC_COMMITMENT_URL).origin });
      const vinput = buildVerifyInput(resolved.commitment, resolved.pkg);
      const result = await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
      const shown = presentVerification(resolved, vinput, result);
      assert.equal(resolved.registryProvenance, 'declared-url', `${mode}: the declared registry is read`);
      assert.equal(result.keyTrust?.status, 'unknown_key', mode);
      assert.equal(shown.recognition.status, 'unknown_publisher', mode);
      assert.equal(shown.recognition.signal.label, 'Unknown publisher', mode);
      assert.match(shown.recognition.signal.detail ?? '', /does not vouch for this signer/, mode);
      assert.notEqual(shown.verdict.headline, 'Verified', mode);
    } finally {
      restore();
    }
  }
});

test('#93 item 1: a genuine ?inline=1 bundle verified by URL reads as its declared registry says', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  // The producer's ?inline=1 view carries the same registry it declares.
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const run = await runWith(commitment, { [LISTED_REGISTRY_URL]: m.registry, ...DIRECTORY_ROUTE }, 'url');
  assert.equal(run.resolved.registryProvenance, 'declared-url');
  assert.equal(run.registryStep?.label, 'Fetched publisher trust registry');
  const shown = presentVerification(run.resolved, run.vinput, run.result);
  assert.equal(rowOf(shown.rows, '5').signal.label, KEY_TRUST_SIGNALS.active.label);
  assert.equal(shown.verdict.headline, 'Verified');
  assert.equal(shown.recognition.status, 'known_publisher');
  assert.equal(canRecheckKeyTrust(registryMetaOf(run.resolved), run.result), false, 'nothing left to re-check');
});

test('#93 item 1: online, a declared registry that cannot be fetched falls back to the one the record carries, which only lowers', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const run = await runWith(commitment, DIRECTORY_ROUTE, 'url');
  assert.equal(run.resolved.registryProvenance, 'bundle');
  assert.equal(
    run.registryStep?.label,
    'The declared trust registry could not be fetched — read the one in the record, which can lower key trust, never raise it',
  );
  const shown = presentVerification(run.resolved, run.vinput, run.result);
  assert.notEqual(shown.verdict.headline, 'Verified');
  assert.equal(shown.recognition.status, 'host_recognized_key_unconfirmed');
});

test('#93 item 1: bundle mode makes no network call, even when the record declares an https: registry', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const { calls, restore } = recordFetch({ [LISTED_REGISTRY_URL]: EMPTY_REGISTRY, ...DIRECTORY_ROUTE });
  try {
    const resolved = await resolveInput('bundle', JSON.stringify(commitment));
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    await runVerify(vinput, resolved.registry, undefined, resolved.registryProvenance);
    assert.equal(resolved.registryProvenance, 'bundle');
    assert.equal(resolved.fullyOffline, true);
    assert.deepEqual(calls, [], 'no request in bundle mode');
  } finally {
    restore();
  }
});

test('#93 item 2: rollupVerdict with no registry reads it as carried in the bundle', () => {
  const active = mkResult({ hasTimestamp: false });
  assert.equal(rollupVerdict(active, DECLARED_META).headline, 'Verified', 'control: the declared registry');
  const omitted = rollupVerdict(active);
  assert.notEqual(omitted.tier, 'verified');
  assert.notEqual(omitted.headline, 'Verified');
  assert.deepEqual(omitted, rollupVerdict(active, SUPPLIED_META));
  const privateContent = mkResult({ hasTimestamp: false, envelopeIntegrity: { status: 'unavailable', reason: 'private' }, recomputedHash: null });
  assert.notEqual(rollupVerdict(privateContent).tier, 'verified', 'content private too');
});

/** A result whose only non-green check is the one `over` sets. mkResult's timestamp
 *  is present but unverified (an alarm-tier #7 row), so it is set absent here. */
const onlyOne = (over: Partial<VerifyResult> = {}): VerifyResult =>
  mkResult({ hasTimestamp: false, contentProfile: { status: 'ok' } as VerifyResult['contentProfile'], ...over });

/** Every attention-tier status in trust-signal.ts, each as the only non-green
 *  result, with the check whose row it amber-tiers. */
const ATTENTION_CASES: { status: string; check: string; over: Partial<VerifyResult>; meta?: typeof SUPPLIED_META }[] = [
  { status: '#1 unavailable (unfetchable)', check: '1', over: { envelopeIntegrity: { status: 'unavailable', reason: 'unfetchable' }, recomputedHash: null } },
  { status: '#3 unknown_canonicalization_rule', check: '3', over: { contentCanonicalization: { status: 'unknown_canonicalization_rule', rule: 'x' } as VerifyResult['contentCanonicalization'] } },
  { status: '#4 unresolved_rule', check: '4', over: { contentHash: { status: 'unresolved_rule' } as VerifyResult['contentHash'] } },
  { status: '#4 contentHash_no_supported_algorithm', check: '4', over: { contentHash: { status: 'contentHash_no_supported_algorithm' } as VerifyResult['contentHash'] } },
  { status: '#4 content_bytes_unavailable', check: '4', over: { contentHash: { status: 'content_bytes_unavailable' } as VerifyResult['contentHash'] } },
  { status: '#5 unknown_key', check: '5', over: { keyTrust: { status: 'unknown_key', verified: false } as VerifyResult['keyTrust'] } },
  { status: '#5 registry_unavailable', check: '5', over: { keyTrust: { status: 'registry_unavailable', verified: false } as VerifyResult['keyTrust'] } },
  { status: '#5 KEY_TRUST_SUPPLIED_REGISTRY', check: '5', over: {}, meta: SUPPLIED_META },
  { status: '#8 unconfirmed', check: '8', over: { rekorVerified: false } },
  { status: '#12 unknown_type', check: '12', over: { typeResolution: { status: 'unknown_type', type: 'x/y/v1' } as VerifyResult['typeResolution'] } },
  { status: '#15 captureMethod_unknown', check: '15', over: { captureMethodVocab: { status: 'captureMethod_unknown', profileType: 'x' } as VerifyResult['captureMethodVocab'] } },
  { status: '#16 contentProfile_unknown', check: '16', over: { contentProfile: { status: 'contentProfile_unknown' } as VerifyResult['contentProfile'] } },
  { status: '#16 contentProfile_inconsistent', check: '16', over: { contentProfile: { status: 'contentProfile_inconsistent' } as VerifyResult['contentProfile'] } },
];
const ROW_INPUT = buildVerifyInput({ packageHash: 'ab'.repeat(32) }, {});
const ROW_COMMITMENT = { packageHash: 'ab'.repeat(32) };

test('#86: control — with every check green the headline is the unqualified "Verified"', () => {
  const rows = buildCheckRows(onlyOne(), ROW_INPUT, ROW_COMMITMENT, DECLARED_META);
  assert.deepEqual(rows.filter((r) => r.signal.tier === 'attention' || r.signal.tier === 'alarm').map((r) => r.num), []);
  assert.equal(rollupVerdict(onlyOne(), DECLARED_META).headline, 'Verified');
});

test('#86: a package whose only non-green result is an attention-tier check does not get the unqualified headline', () => {
  for (const c of ATTENTION_CASES) {
    const result = onlyOne(c.over);
    const meta = c.meta ?? DECLARED_META;
    const rows = buildCheckRows(result, ROW_INPUT, ROW_COMMITMENT, meta);
    const amber = rows.filter((r) => r.signal.tier !== 'verified' && r.signal.tier !== 'normal');
    assert.deepEqual(amber.map((r) => `${r.num}:${r.signal.tier}`), [`${c.check}:attention`], `${c.status}: the only non-green row`);
    const v = rollupVerdict(result, meta);
    assert.equal(v.tier, 'attention', c.status);
    assert.notEqual(v.headline, 'Verified', c.status);
    assert.notEqual(v.headline, 'Commitment verified — content private', c.status);
    assert.ok(v.detail.includes(`#${amber[0].num} ${amber[0].name}`), `${c.status}: the headline names the amber check (${v.detail})`);
  }
});

test('#86: the self-certified and content-private branches follow the same guard', () => {
  const selfCertified = {
    keyTrust: { status: 'self_certified', verified: false } as VerifyResult['keyTrust'],
    signerIdentity: { status: 'key_derived_match' } as VerifyResult['signerIdentity'],
  };
  const privateContent = { envelopeIntegrity: { status: 'unavailable', reason: 'private' } as EnvelopeIntegrityResult, recomputedHash: null };
  // Controls: green apart from the branch's own reading.
  assert.equal(rollupVerdict(onlyOne(selfCertified), DECLARED_META).headline, 'Signature valid — self-certified signer');
  assert.equal(rollupVerdict(onlyOne(privateContent), DECLARED_META).headline, 'Commitment verified — content private');
  for (const c of ATTENTION_CASES) {
    if (c.check === '1' || c.check === '5') continue; // each replaces the branch's own reading
    const sc = rollupVerdict(onlyOne({ ...selfCertified, ...c.over }), DECLARED_META);
    assert.equal(sc.tier, 'attention', `self-certified, ${c.status}`);
    assert.doesNotMatch(sc.headline, /^Verified/, `self-certified, ${c.status}`);
    assert.match(sc.headline, /self-certified signer/, `self-certified, ${c.status}`);
    assert.match(sc.detail, new RegExp(`#${c.check} `), `self-certified, ${c.status}`);
    if (c.check === '3' || c.check === '4') continue; // no content, so no content checks
    const pc = rollupVerdict(onlyOne({ ...privateContent, ...c.over }), DECLARED_META);
    assert.equal(pc.tier, 'attention', `content private, ${c.status}`);
    assert.equal(pc.headline, 'Commitment verified, with caveats — content private', `content private, ${c.status}`);
    assert.match(pc.detail, new RegExp(`#${c.check} `), `content private, ${c.status}`);
  }
});

test('#93 item 4: bundle-mode recognition says the directory was not fetched, not that it could not be loaded', async () => {
  const m = mintSigned({ identifier: 'urn', bindingTier: 'platform', inlineRegistry: true, declareUrl: false });
  const commitment = { ...m.commitment, trustRegistryUrl: LISTED_REGISTRY_URL };
  const offline = pageOf(await runWith(commitment, {}));
  assert.equal(offline.recognition.status, 'directory_unavailable');
  assert.doesNotMatch(offline.recognition.signal.detail ?? '', /could not be loaded/);
  assert.match(offline.recognition.signal.detail ?? '', /offline/);
  // Online, a directory that fails to load still says so.
  const online = pageOf(await runWith(commitment, {}, 'url'));
  assert.equal(online.recognition.status, 'directory_unavailable');
  assert.match(online.recognition.signal.detail ?? '', /could not be loaded/);
});

test('#93 item 4: the independence note states the offline bundle’s key-trust limit', () => {
  const source = readFileSync(new URL('../components/Verifier.tsx', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  assert.ok(!source.includes('zero trust in the host'), 'the old advice is gone');
  assert.ok(
    source.includes('To verify the package and proofs without trusting the host, download and verify an offline bundle. Its signing key stays unconfirmed until you re-check it against the publisher’s live registry.'),
    'the note states its limit',
  );
});
