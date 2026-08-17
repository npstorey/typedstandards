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
import type { VerifyResult, EnvelopeIntegrityResult } from '@typedstandards/verify-core';
import {
  rollupVerdict,
  buildVerifyInput,
  buildPreview,
  deriveShareTarget,
  deriveCommitmentUrl,
  bareIdCommitmentUrl,
  identifierResolutionKind,
  parseHostSegment,
  parseVerifyTarget,
  DEFAULT_HOST,
  type Commitment,
  type ResolvedInput,
} from './verify-flow.ts';

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
// origin has no evidence API at all. Measured on the live deployment: the blob itself
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
  assert.equal(deriveCommitmentUrl(url), `${DEFAULT_HOST}/api/evidence/${hash}/commitment`);
  // The old assertion, now the thing being ruled out: the blob's own origin.
  assert.notEqual(
    deriveCommitmentUrl(url),
    `https://data-concierge.dathere.com/api/evidence/${hash}/commitment`,
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
    `${DEFAULT_HOST}/api/evidence/${listed}/commitment`,
  );
  assert.equal(
    deriveCommitmentUrl(`https://example-publisher.test/blobs/${unlisted}.json`),
    `${DEFAULT_HOST}/api/evidence/${unlisted}/commitment`,
  );
});

test('deriveCommitmentUrl: DETACHED STORAGE — a blob host with no evidence API resolves to the anchor (B5)', () => {
  // The case the original premise could not survive, and the reference publisher's
  // actual deployment shape: package bytes on third-party object storage whose origin
  // serves no evidence API. Preserving that origin produced a guaranteed 404.
  const hash = 'c3'.repeat(32);
  for (const blobUrl of [
    `https://abcdef0123456789.public.blob.vercel-storage.com/evidence-packages/${hash}.json`,
    // A bucket layout whose path contains an `/evidence/` SEGMENT. This one caught a
    // real branch-ordering hazard: the `/evidence/<id>` probe used to match first and
    // captured an id of literally `<hash>.json`, yielding `…/api/evidence/<hash>.json
    // /commitment`. The `<64-hex>.json` filename is the more specific signal and now
    // wins — see classifyHostedUrl.
    `https://packages.s3.amazonaws.com/evidence/${hash}.json`,
    `https://cdn.example-storage.test/${hash}.json`,
  ]) {
    assert.equal(
      deriveCommitmentUrl(blobUrl),
      `${DEFAULT_HOST}/api/evidence/${hash}/commitment`,
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
    `https://example-publisher.test/api/evidence/${hash}/commitment`,
  );
});

test('deriveCommitmentUrl: URLs that DO carry a publisher origin still keep it (B5)', () => {
  // The other three branches are unchanged. A publisher's own evidence URL and an
  // already-resolved commitment URL both name their publisher, so nothing is
  // re-anchored — the fix is scoped to the one shape that does not.
  const commitment = 'https://example-publisher.test/api/evidence/some-slug/commitment';
  assert.equal(deriveCommitmentUrl(commitment), commitment);
  assert.equal(
    deriveCommitmentUrl('https://example-publisher.test/evidence/some-slug'),
    'https://example-publisher.test/api/evidence/some-slug/commitment',
  );
  // Neither is origin-less, so neither triggers the disclosure line.
  assert.equal(identifierResolutionKind('url', commitment), undefined);
  assert.equal(
    identifierResolutionKind('url', 'https://example-publisher.test/evidence/some-slug'),
    undefined,
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
  // reading the link back must rebuild the SAME URL, not the anchor's.
  const parsed = parseVerifyTarget(['data-concierge.dathere.com', 'some-slug']);
  assert.equal(bareIdCommitmentUrl(parsed!.id, parsed!.host), url);
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
  // Next.js hands the route the DECODED segments.
  const parsed = parseVerifyTarget(['publisher.test', 'a b']);
  assert.equal(bareIdCommitmentUrl(parsed!.id, parsed!.host), url);
});

test('deriveShareTarget: a package-blob deep-link ends in a clean short link (B5 + B7)', () => {
  // The whole B5 path, end to end. A badge `?url=<package-blob-url>` resolves through
  // the anchor, and the URL that answered is what the share link is rebuilt from — so
  // the opaque storage URL collapses to `/verify/<hash>`, which round-trips back to
  // the same commitment URL. Nothing downstream has to know a blob was involved.
  const hash = 'c3'.repeat(32);
  const blobUrl = `https://abcdef0123456789.public.blob.vercel-storage.com/evidence-packages/${hash}.json`;
  const commitmentUrl = deriveCommitmentUrl(blobUrl);
  assert.equal(commitmentUrl, `${DEFAULT_HOST}/api/evidence/${hash}/commitment`);
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
  assert.equal(
    bareIdCommitmentUrl(parsed!.id, parsed!.host ?? DEFAULT_HOST),
    `${DEFAULT_HOST}/api/evidence/noise-trends-in-nyc-2026/commitment`,
  );
});

test('parseVerifyTarget: BACK-COMPAT — a 64-hex hash link still resolves against the anchor', () => {
  const hash = 'e'.repeat(64);
  const parsed = parseVerifyTarget([hash]);
  assert.deepEqual(parsed, { id: hash });
  assert.equal(
    bareIdCommitmentUrl(parsed!.id, parsed!.host ?? DEFAULT_HOST),
    `${DEFAULT_HOST}/api/evidence/${hash}/commitment`,
  );
});

test('parseVerifyTarget: BACK-COMPAT — the old share link round-trips end to end', () => {
  // Mint with today's code from an anchor-origin commitment URL, read back, rebuild.
  const url = `${DEFAULT_HOST}/api/evidence/noise-trends-in-nyc-2026/commitment`;
  const target = deriveShareTarget(mkResolved(url));
  assert.equal(target, '/verify/noise-trends-in-nyc-2026', 'still the single-segment form');
  const segments = target!.slice('/verify/'.length).split('/').map(decodeURIComponent);
  const parsed = parseVerifyTarget(segments);
  assert.equal(bareIdCommitmentUrl(parsed!.id, parsed!.host ?? DEFAULT_HOST), url);
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
