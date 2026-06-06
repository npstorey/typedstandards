// Unit tests for the embeddable verify badge (#116 WS3 Phase E, ADR-0013 / Q46).
// Two properties are load-bearing and locked here:
//
//   1. THE HONESTY CONSTRAINT — the badge is a CALL TO ACTION, never a verdict.
//      renderBadgeSvg must carry the "Verify with Typed Standards" CTA and must
//      NEVER contain a verdict signal ("verified" / "valid" / a checkmark). A
//      future style edit must not be able to quietly turn the badge into an
//      (unbackable, forgeable) trust claim.
//   2. INJECTION SAFETY — buildVerifyHref percent-encodes the package input, so a
//      hostile paste (quotes / angle brackets / a `javascript:` scheme) cannot
//      break out of the href attribute or become an executable URL; and the
//      Markdown embed survives a `)` in the URL.
//
// Pure, no network. Run with: npm test  (Node 22; node --test strip-types).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BADGE_ALT,
  CANONICAL_ORIGIN,
  classifyBadgeInput,
  buildVerifyHref,
  buildEmbedHtml,
  buildEmbedMarkdown,
  renderBadgeSvg,
} from './badge-asset.ts';

// --- 1. Honesty constraint: CTA, never a verdict -------------------------

const VERDICT_SIGNALS = [/verified/i, /\bvalid\b/i, /validated/i, /\bpass(ed)?\b/i, /✓/, /✔/, /checkmark/i];

for (const theme of ['light', 'dark'] as const) {
  test(`renderBadgeSvg(${theme}) is a call to action, never a verdict`, () => {
    const svg = renderBadgeSvg(theme);
    assert.ok(svg.startsWith('<svg'), 'is an SVG');
    // The visible label is split across two <tspan>s ("Verify with " + the
    // brand-colored "Typed Standards"), so assert the parts + the contiguous
    // accessible label rather than the joined visible string.
    assert.ok(svg.includes('Verify'), 'carries the verify CTA verb');
    assert.ok(svg.includes('Typed Standards'), 'carries the brand');
    assert.ok(svg.includes(BADGE_ALT), 'accessible label describes the action, not a verdict');
    for (const sig of VERDICT_SIGNALS) {
      assert.equal(sig.test(svg), false, `badge must not contain a verdict signal (${sig})`);
    }
  });
}

// --- classifyBadgeInput ---------------------------------------------------

test('classifyBadgeInput distinguishes url / hash / bundle / empty', () => {
  assert.equal(classifyBadgeInput('https://x/api/evidence/y/commitment'), 'url');
  assert.equal(classifyBadgeInput('http://x'), 'url');
  assert.equal(classifyBadgeInput('a'.repeat(64)), 'hash');
  assert.equal(classifyBadgeInput('noise-trends-in-nyc-last-week-da9246'), 'hash'); // slug
  assert.equal(classifyBadgeInput('{"packageHash":"x"}'), 'bundle');
  assert.equal(classifyBadgeInput('   '), 'empty');
});

// --- 2a. buildVerifyHref: param routing + injection safety ---------------

test('buildVerifyHref routes url→?url= and hash/slug→?hash=', () => {
  assert.ok(buildVerifyHref('', 'https://h/api/evidence/s/commitment').startsWith('/verify?url='));
  assert.ok(buildVerifyHref('', 'abc-slug').startsWith('/verify?hash='));
});

test('buildVerifyHref honours the origin (relative preview vs canonical snippet)', () => {
  assert.ok(buildVerifyHref('', 'x').startsWith('/verify?'));
  assert.ok(buildVerifyHref(CANONICAL_ORIGIN, 'x').startsWith(`${CANONICAL_ORIGIN}/verify?`));
});

test('buildVerifyHref percent-encodes hostile input (no breakout, no executable scheme)', () => {
  const href = buildVerifyHref(CANONICAL_ORIGIN, 'https://evil.example/"><script>alert(1)</script>');
  for (const ch of ['"', '<', '>']) {
    assert.equal(href.includes(ch), false, `raw ${ch} must not survive into the href`);
  }
  // A javascript: paste becomes an inert hash param of a /verify URL, not a scheme.
  const js = buildVerifyHref('', 'javascript:alert(1)');
  assert.ok(js.startsWith('/verify?hash='));
  assert.equal(/^javascript:/i.test(js), false);
  assert.ok(js.includes('javascript%3A'), 'the scheme colon is encoded');
});

// --- 2b. buildEmbedHtml: attribute-safe ----------------------------------

test('buildEmbedHtml percent-encodes hostile input (no attribute/markup breakout)', () => {
  const html = buildEmbedHtml(CANONICAL_ORIGIN, 'x"><img src=z onerror=alert(1)>', 'light');
  assert.ok(html.includes('<a href="'));
  assert.ok(html.includes(BADGE_ALT));
  // The hostile quote/brackets/equals survive only in encoded form.
  assert.ok(html.includes('%22') && html.includes('%3C') && html.includes('%3E'));
  // Exactly the one legitimate badge <img>; no injected element, no live handler.
  assert.equal((html.match(/<img/g) ?? []).length, 1);
  assert.equal(html.toLowerCase().includes('onerror='), false);
});

// --- 2c. buildEmbedMarkdown: survives a ) in the URL ---------------------

test('buildEmbedMarkdown wraps the href in <> so a ) cannot truncate the link', () => {
  const md = buildEmbedMarkdown(CANONICAL_ORIGIN, 'https://h/p(a)th/commitment', 'light');
  assert.ok(md.includes('](<'), 'uses the CommonMark angle-bracket destination form');
  assert.ok(md.trimEnd().endsWith('>)'), 'closes the angle-bracket destination');
  // the parenthesised path is preserved verbatim inside the destination
  assert.ok(md.includes('p(a)th'));
});
