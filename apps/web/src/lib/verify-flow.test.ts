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

// deriveCommitmentUrl — B5 regression (#44). The package-blob branch must derive
// the commitment URL on the BLOB'S OWN origin, exactly like the adjacent
// `/evidence/<id>` branch one line above it does. Before the fix, this branch
// discarded the URL's origin and re-pointed at DEFAULT_HOST (civicaitools.org),
// so a badge deep-link for a package blob hosted by any OTHER publisher would
// resolve against the wrong host and 404. Two hosts are used so the fix is
// proven independent of host-directory roster membership: one listed publisher
// (data-concierge.dathere.com) and one that is not listed anywhere.
test('deriveCommitmentUrl: package-blob URL preserves origin — a directory-listed second host (B5)', () => {
  const hash = 'a1'.repeat(32); // 64 hex chars
  const url = `https://data-concierge.dathere.com/blobs/${hash}.json`;
  assert.equal(
    deriveCommitmentUrl(url),
    `https://data-concierge.dathere.com/api/evidence/${hash}/commitment`,
  );
});

test('deriveCommitmentUrl: package-blob URL preserves origin — a host absent from the directory (B5)', () => {
  const hash = 'b2'.repeat(32); // 64 hex chars
  const url = `https://example-publisher.test/blobs/${hash}.json`;
  assert.equal(
    deriveCommitmentUrl(url),
    `https://example-publisher.test/api/evidence/${hash}/commitment`,
  );
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
