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
  HOST_DIRECTORY,
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
