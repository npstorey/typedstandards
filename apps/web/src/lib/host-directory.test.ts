// Unit tests for resolveHostRecognition — the load-bearing impersonation gate
// (#116 WS3 Phase D, Q47). The whole security claim of Phase D is "✓ Known
// publisher" is awarded iff (a) the declared trustRegistryUrl ORIGIN is listed in
// the directory AND (b) keyTrust confirms the signing key in that registry; every
// other outcome withholds the green badge and the curated brand name. These tests
// lock that invariant against accidental regression.
//
// Pure, no network: the verify-core imports are type-only and strip cleanly, and
// host-directory's only runtime relative import (./trust-signal.ts) is itself
// type-only-importing. Run with: npm test  (Node 22; node --test strip-types).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveHostRecognition,
  originOf,
  validateHostDirectory,
  bareIdentifierHostOf,
  canonicalPublisherOrigin,
  HOST_DIRECTORY,
  BARE_ID_ANCHOR,
  type HostDirectory,
  type HostRecognition,
} from './host-directory.ts';
import type { KeyTrustResult, KeyTrustStatus } from '@typedstandards/verify-core';

// --- fixtures -------------------------------------------------------------

const BRAND = HOST_DIRECTORY.publishers[0].displayName; // "Civic AI Tools"
const LISTED_ORIGIN = HOST_DIRECTORY.publishers[0].registryOrigin; // https://civicaitools.org

/** A commitment that declares the listed registry origin (full well-known path). */
const listed = { trustRegistryUrl: `${LISTED_ORIGIN}/.well-known/typed-publisher.json` };
/** A commitment that declares an UNLISTED origin. */
const unlisted = { trustRegistryUrl: 'https://evil-lookalike.example/.well-known/typed-publisher.json' };

const kt = (status: KeyTrustStatus, verified: boolean): KeyTrustResult => ({ status, verified });

function mentionsBrand(r: HostRecognition): boolean {
  return r.signal.label.includes(BRAND) || (r.signal.detail ?? '').includes(BRAND);
}

// --- the six outcomes -----------------------------------------------------

test('active + listed origin → known_publisher (green), brand + profile exposed', () => {
  const r = resolveHostRecognition(listed, kt('active', true), HOST_DIRECTORY);
  assert.equal(r.status, 'known_publisher');
  assert.equal(r.signal.tier, 'verified');
  assert.ok(r.publisher, 'publisher entry must be set for the earned state');
  assert.equal(r.publisher?.displayName, BRAND);
  assert.ok(mentionsBrand(r), 'the green badge is the one place the brand appears');
});

test('deprecated_valid + listed origin → known_publisher (key was valid at signing)', () => {
  const r = resolveHostRecognition(listed, kt('deprecated_valid', true), HOST_DIRECTORY);
  assert.equal(r.status, 'known_publisher');
  assert.equal(r.signal.tier, 'verified');
});

test('legacy_embedded + listed origin → host_recognized_key_unconfirmed (amber), NOT green', () => {
  const r = resolveHostRecognition(listed, kt('legacy_embedded', false), HOST_DIRECTORY);
  assert.equal(r.status, 'host_recognized_key_unconfirmed');
  assert.equal(r.signal.tier, 'attention');
  assert.notEqual(r.signal.tier, 'verified');
  assert.equal(r.publisher, undefined, 'non-green must not expose the curated entry');
});

test('unknown_key + listed origin → unknown_publisher (disavowed), NOT green, publisher unset', () => {
  const r = resolveHostRecognition(listed, kt('unknown_key', false), HOST_DIRECTORY);
  assert.equal(r.status, 'unknown_publisher');
  assert.equal(r.signal.tier, 'normal');
  assert.notEqual(r.status, 'known_publisher');
  assert.equal(r.publisher, undefined);
});

test('active + UNLISTED origin → unknown_publisher (entry-check precedes keyTrust)', () => {
  // The ordering lock: verified:true must NOT yield green when the origin is not
  // listed. A package validly signed against its OWN registry is still unknown.
  const r = resolveHostRecognition(unlisted, kt('active', true), HOST_DIRECTORY);
  assert.equal(r.status, 'unknown_publisher');
  assert.notEqual(r.status, 'known_publisher');
  assert.equal(r.publisher, undefined);
});

test('revoked + listed origin → host_recognized_key_unconfirmed (amber)', () => {
  const r = resolveHostRecognition(listed, kt('revoked', false), HOST_DIRECTORY);
  assert.equal(r.status, 'host_recognized_key_unconfirmed');
  assert.equal(r.signal.tier, 'attention');
});

test("directory 'unavailable' (and undefined) → directory_unavailable", () => {
  for (const dir of ['unavailable', undefined] as const) {
    const r = resolveHostRecognition(listed, kt('active', true), dir);
    assert.equal(r.status, 'directory_unavailable');
    assert.equal(r.signal.tier, 'normal');
    assert.equal(r.publisher, undefined);
  }
});

test('missing trustRegistryUrl → no_publisher_declared', () => {
  const r = resolveHostRecognition({}, kt('active', true), HOST_DIRECTORY);
  assert.equal(r.status, 'no_publisher_declared');
  assert.equal(r.signal.tier, 'normal');
});

// --- R1 lock: the curated brand appears ONLY in the green state -----------

test('R1: displayName ("Civic AI Tools") appears ONLY for known_publisher', () => {
  // Every non-green outcome, including the ones whose origin IS listed.
  const nonGreen: HostRecognition[] = [
    resolveHostRecognition(listed, kt('legacy_embedded', false), HOST_DIRECTORY),
    resolveHostRecognition(listed, kt('unknown_key', false), HOST_DIRECTORY),
    resolveHostRecognition(listed, kt('revoked', false), HOST_DIRECTORY),
    resolveHostRecognition(listed, kt('deprecated_invalid', false), HOST_DIRECTORY),
    resolveHostRecognition(listed, kt('registry_unavailable', false), HOST_DIRECTORY),
    resolveHostRecognition(unlisted, kt('active', true), HOST_DIRECTORY),
    resolveHostRecognition(listed, kt('active', true), 'unavailable'),
    resolveHostRecognition({}, kt('active', true), HOST_DIRECTORY),
  ];
  for (const r of nonGreen) {
    assert.equal(mentionsBrand(r), false, `brand leaked into ${r.status}: ${r.signal.label} / ${r.signal.detail}`);
    assert.equal(r.publisher, undefined, `publisher leaked into ${r.status}`);
  }
  const green = resolveHostRecognition(listed, kt('active', true), HOST_DIRECTORY);
  assert.equal(mentionsBrand(green), true);
});

// --- originOf spoof cases: lookalike origins must not match ---------------

test('originOf canonicalization defeats lookalike origins', () => {
  // Subdomain suffix, userinfo trick, and explicit port are all DISTINCT origins.
  assert.equal(originOf('https://civicaitools.org.evil.com'), 'https://civicaitools.org.evil.com');
  assert.equal(originOf('https://civicaitools.org@evil.com'), 'https://evil.com');
  assert.equal(originOf('https://civicaitools.org:8443'), 'https://civicaitools.org:8443');
  for (const o of [
    'https://civicaitools.org.evil.com',
    'https://civicaitools.org@evil.com',
    'https://civicaitools.org:8443',
  ]) {
    assert.notEqual(originOf(o), LISTED_ORIGIN, `${o} must not canonicalize to the listed origin`);
  }
});

test('spoofed origins + active key → unknown_publisher (never green)', () => {
  for (const url of [
    'https://civicaitools.org.evil.com/.well-known/typed-publisher.json',
    'https://civicaitools.org@evil.com/.well-known/typed-publisher.json',
    'https://civicaitools.org:8443/.well-known/typed-publisher.json',
  ]) {
    const r = resolveHostRecognition({ trustRegistryUrl: url }, kt('active', true), HOST_DIRECTORY);
    assert.equal(r.status, 'unknown_publisher', `${url} must be unknown_publisher`);
    assert.notEqual(r.status, 'known_publisher');
    assert.equal(mentionsBrand(r), false);
  }
});

// --- B6: the bare-identifier anchor is DECLARED, not positional (#44) -----
//
// `BARE_ID_ANCHOR` used to be `HOST_DIRECTORY.publishers[0].registryOrigin` — the
// resolution host for an origin-less identifier chosen by array position at build
// time, so the reference publisher won by being listed first. It is now an explicit
// field in the directory document, additive to the public well-known schema.

test('B6: the published directory DECLARES its anchor, and the constant reads it', () => {
  assert.equal(typeof HOST_DIRECTORY.bareIdentifierHost, 'string');
  assert.ok(HOST_DIRECTORY.bareIdentifierHost.length > 0);
  assert.equal(BARE_ID_ANCHOR, HOST_DIRECTORY.bareIdentifierHost);
  // Well-formed origin: no path, no trailing slash.
  assert.equal(originOf(BARE_ID_ANCHOR), BARE_ID_ANCHOR);
});

test('B6: roster ORDER no longer decides the anchor', () => {
  // The lock on the removed defect. Reversing the roster leaves the anchor alone;
  // under the old positional derivation this would have handed it to another host.
  const reversed: HostDirectory = {
    ...HOST_DIRECTORY,
    publishers: [...HOST_DIRECTORY.publishers].reverse(),
  };
  assert.equal(bareIdentifierHostOf(reversed), BARE_ID_ANCHOR);
  assert.notEqual(reversed.publishers[0].registryOrigin, HOST_DIRECTORY.publishers[0].registryOrigin);
});

test('B6: the SERVED document carries the field and reads back through validation', () => {
  // The well-known route serves `JSON.stringify(HOST_DIRECTORY)` verbatim, so this is
  // the served bytes' round-trip: serialize → parse → validate → anchor intact.
  const served = JSON.parse(JSON.stringify(HOST_DIRECTORY)) as unknown;
  assert.equal((served as { bareIdentifierHost?: string }).bareIdentifierHost, BARE_ID_ANCHOR);
  const validated = validateHostDirectory(served);
  assert.ok(validated);
  assert.equal(bareIdentifierHostOf(validated!), BARE_ID_ANCHOR);
  assert.equal(validated!.publishers.length, HOST_DIRECTORY.publishers.length);
});

test('B6: BACK-COMPAT — a directory document LACKING the field still validates', () => {
  // A fork's roster, or a copy cached before the field existed. It must validate in
  // full; only the anchor is absent.
  const withoutAnchor = {
    version: 1,
    updated: '2026-06-16',
    publishers: [
      { registryOrigin: 'https://example-publisher.test', displayName: 'A Prospective Adopter' },
    ],
  };
  const validated = validateHostDirectory(withoutAnchor);
  assert.ok(validated, 'the document must still validate');
  assert.equal(validated!.publishers.length, 1);
  assert.equal(validated!.publishers[0].displayName, 'A Prospective Adopter');
  assert.equal(bareIdentifierHostOf(validated!), undefined, 'no declaration ⇒ no anchor');
  // NOT publishers[0] — re-deriving positionally is the defect this replaced.
  assert.notEqual(bareIdentifierHostOf(validated!), validated!.publishers[0].registryOrigin);
});

test('B6: a malformed anchor is dropped, not fatal', () => {
  for (const bad of [42, null, '', 'not a url', {}]) {
    const validated = validateHostDirectory({
      version: 1,
      updated: '2026-06-16',
      bareIdentifierHost: bad,
      publishers: [{ registryOrigin: 'https://example-publisher.test', displayName: 'X' }],
    });
    assert.ok(validated, `document must survive bareIdentifierHost=${JSON.stringify(bad)}`);
    assert.equal(bareIdentifierHostOf(validated!), undefined);
  }
});

test('B6: a declared anchor is canonicalized to an origin', () => {
  const validated = validateHostDirectory({
    version: 1,
    updated: '2026-06-16',
    bareIdentifierHost: 'https://EXAMPLE-publisher.test/some/path?q=1',
    publishers: [{ registryOrigin: 'https://example-publisher.test', displayName: 'X' }],
  });
  assert.equal(bareIdentifierHostOf(validated!), 'https://example-publisher.test');
});

test('B6: unknown fields are tolerated — the schema addition is additive', () => {
  // The consumer-compatibility claim in both directions: a parser that does not know
  // `bareIdentifierHost` ignores it (it is JSON), and this parser ignores fields a
  // future directory adds.
  const validated = validateHostDirectory({
    version: 2,
    updated: '2026-06-16',
    bareIdentifierHost: 'https://example-publisher.test',
    somethingNobodyHasShippedYet: { nested: true },
    publishers: [
      {
        registryOrigin: 'https://example-publisher.test',
        displayName: 'X',
        futurePublisherField: 'ignored',
      },
    ],
  });
  assert.ok(validated);
  assert.equal(validated!.version, 2);
  assert.equal(bareIdentifierHostOf(validated!), 'https://example-publisher.test');
  assert.equal(validated!.publishers[0].displayName, 'X');
  assert.equal(
    (validated!.publishers[0] as unknown as Record<string, unknown>).futurePublisherField,
    undefined,
    'validation returns a known-shape entry, unknown keys dropped',
  );
});

test('B6: anchoring confers NO recognition — the (a)+(b) invariant is untouched', () => {
  // Being the anchor is a resolution decision, not a trust one. A commitment whose
  // registry origin happens to equal the anchor still needs both conditions, and a
  // commitment on an unlisted origin is unaffected by what the anchor is.
  const atAnchor = { trustRegistryUrl: `${BARE_ID_ANCHOR}/.well-known/typed-publisher.json` };
  assert.equal(
    resolveHostRecognition(atAnchor, kt('unknown_key', false), HOST_DIRECTORY).status,
    'unknown_publisher',
  );
  assert.equal(
    resolveHostRecognition(unlisted, kt('active', true), HOST_DIRECTORY).status,
    'unknown_publisher',
  );
});

// --- canonicalPublisherOrigin (#50) ----------------------------------------
//
// The verifier must fetch a publisher's CANONICAL origin directly — a browser
// fetch dies at a cross-origin redirect hop whose response carries no CORS
// headers, and a platform-default `www.` → apex redirect commonly carries none
// (measured live 2026-08-17). Directory spelling first, generic www-strip second.

test('canonicalPublisherOrigin: a listed origin is already canonical', () => {
  assert.equal(canonicalPublisherOrigin(LISTED_ORIGIN), LISTED_ORIGIN);
  assert.equal(
    canonicalPublisherOrigin('https://data-concierge.dathere.com'),
    'https://data-concierge.dathere.com',
  );
});

test('canonicalPublisherOrigin: the www variant of a listed publisher → the listed spelling', () => {
  assert.equal(canonicalPublisherOrigin('https://www.civicaitools.org'), LISTED_ORIGIN);
  assert.equal(
    canonicalPublisherOrigin('https://www.data-concierge.dathere.com'),
    'https://data-concierge.dathere.com',
  );
});

test('canonicalPublisherOrigin: the DIRECTORY spelling wins — a listed www-canonical publisher is never stripped', () => {
  // No such entry exists today; this locks the mechanism that would protect one.
  const dir: HostDirectory = {
    version: 1,
    updated: '',
    publishers: [{ registryOrigin: 'https://www.example-publisher.test', displayName: 'X' }],
  };
  assert.equal(
    canonicalPublisherOrigin('https://www.example-publisher.test', dir),
    'https://www.example-publisher.test',
  );
  // …and its APEX variant resolves TO the listed www spelling, not away from it.
  assert.equal(
    canonicalPublisherOrigin('https://example-publisher.test', dir),
    'https://www.example-publisher.test',
  );
});

test('canonicalPublisherOrigin: an unlisted www host has ONE leading www. label stripped', () => {
  assert.equal(
    canonicalPublisherOrigin('https://www.example-publisher.test'),
    'https://example-publisher.test',
  );
  assert.equal(canonicalPublisherOrigin('http://www.example-publisher.test'), 'http://example-publisher.test', 'scheme kept — no silent https upgrade');
  assert.equal(canonicalPublisherOrigin('https://www.example-publisher.test:8443'), 'https://example-publisher.test:8443', 'explicit port kept');
  assert.equal(canonicalPublisherOrigin('https://www.www.example-publisher.test'), 'https://www.example-publisher.test', 'one label only');
});

test('canonicalPublisherOrigin: scheme mismatch never borrows a listed spelling', () => {
  // http://www.civicaitools.org is NOT a variant of the listed https origin — it
  // falls to the generic strip, keeping its own scheme.
  assert.equal(canonicalPublisherOrigin('http://www.civicaitools.org'), 'http://civicaitools.org');
});

test('canonicalPublisherOrigin: leaves everything else alone', () => {
  assert.equal(canonicalPublisherOrigin('https://evidence.example-publisher.test'), 'https://evidence.example-publisher.test', 'a non-www subdomain is not touched');
  assert.equal(canonicalPublisherOrigin('https://wwwexample.test'), 'https://wwwexample.test', 'www without a dot is part of the name');
  assert.equal(canonicalPublisherOrigin('https://www.com'), 'https://www.com', 'the remainder must stay a dotted name, never a bare TLD');
  assert.equal(canonicalPublisherOrigin('not a url'), 'not a url', 'non-URL input passes through for callers to validate');
});
