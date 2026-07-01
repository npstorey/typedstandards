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

test('deriveShareTarget: cross-host (datHere) → /verify?url=<encoded>, NOT collapsed to /verify/<id>', () => {
  const url = 'https://data-concierge.dathere.com/api/evidence/some-slug/commitment';
  const target = deriveShareTarget(mkResolved(url));
  assert.equal(target, `/verify?url=${encodeURIComponent(url)}`);
  // The cross-host origin MUST be preserved — a short link would re-resolve against
  // DEFAULT_HOST and 404.
  assert.doesNotMatch(target ?? '', /^\/verify\/some-slug$/);
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
  // %2F decodes to "/", which would break the single-segment /verify/[hash] route.
  const url = `${DEFAULT_HOST}/api/evidence/a%2Fb/commitment`;
  assert.equal(deriveShareTarget(mkResolved(url)), `/verify?url=${encodeURIComponent(url)}`);
});
