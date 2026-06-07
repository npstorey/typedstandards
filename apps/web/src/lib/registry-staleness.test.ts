// Honesty contract for the #5 registry-staleness note + online recheck (#119 P4
// PR-C). The note must make the offline-revocation limit legible without overclaiming:
//   - inline snapshot  ⇒ a snapshot note WITH the offline-revocation caveat, and the
//                        recheck is OFFERED when a live URL is known;
//   - fetched (live)   ⇒ a "current" note, no gap, no recheck;
//   - legacy_embedded  ⇒ NO staleness note (never registry-vouched);
//   - missing generatedAt ⇒ dateless but still honest, never a throw.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  keyTrustStalenessNote,
  canRecheckKeyTrust,
  registryMetaOf,
  registryGeneratedAt,
  type RegistryMeta,
} from './verify-flow.ts';
import type { VerifyResult, KeyTrustStatus } from '@typedstandards/verify-core';

const meta = (over: Partial<RegistryMeta>): RegistryMeta => ({
  kind: 'fetched',
  available: true,
  ...over,
});
/** Minimal VerifyResult — canRecheckKeyTrust only reads keyTrust.status. */
const resultWith = (status: KeyTrustStatus): VerifyResult =>
  ({ keyTrust: { status, verified: status === 'active' } }) as unknown as VerifyResult;

test('inline snapshot ⇒ snapshot note with the offline-revocation caveat + as-of date', () => {
  const note = keyTrustStalenessNote(
    'active',
    meta({ kind: 'inline', generatedAt: '2026-06-07T00:00:00.000Z', url: 'https://x/reg.json' }),
  );
  assert.ok(note);
  assert.match(note!, /snapshot carried in this bundle/);
  assert.match(note!, /as of 2026-06-07/);
  assert.match(note!, /revoked after that date cannot be reflected offline/);
});

test('fetched (live) ⇒ current note, no offline-revocation caveat', () => {
  const note = keyTrustStalenessNote(
    'active',
    meta({ kind: 'fetched', generatedAt: '2026-06-07T00:00:00.000Z' }),
  );
  assert.ok(note);
  assert.match(note!, /live registry \(as of 2026-06-07\)/);
  assert.doesNotMatch(note!, /cannot be reflected offline/);
});

test('legacy_embedded ⇒ NO staleness note (was never registry-vouched)', () => {
  assert.equal(keyTrustStalenessNote('legacy_embedded', meta({ kind: 'inline' })), undefined);
  // registry_unavailable likewise has no registry to be stale.
  assert.equal(keyTrustStalenessNote('registry_unavailable', meta({ kind: 'fetched' })), undefined);
});

test('a registry-backed status with NO generatedAt ⇒ dateless but honest, no throw', () => {
  const inline = keyTrustStalenessNote('revoked', meta({ kind: 'inline' }));
  assert.ok(inline);
  assert.match(inline!, /date not stated/);
  assert.match(inline!, /cannot be reflected offline/);
  const fetched = keyTrustStalenessNote('deprecated_valid', meta({ kind: 'fetched' }));
  assert.ok(fetched);
  assert.match(fetched!, /live registry\./); // no parenthetical date
});

test('an unavailable registry ⇒ no note even for a backed status', () => {
  assert.equal(keyTrustStalenessNote('unknown_key', meta({ kind: 'fetched', available: false })), undefined);
});

test('canRecheckKeyTrust: offered only for an inline snapshot + URL + registry-backed verdict', () => {
  const inlineUrl = meta({ kind: 'inline', url: 'https://x/reg.json' });
  assert.equal(canRecheckKeyTrust(inlineUrl, resultWith('active')), true);
  assert.equal(canRecheckKeyTrust(inlineUrl, resultWith('revoked')), true);
  // not offered: no URL to re-fetch.
  assert.equal(canRecheckKeyTrust(meta({ kind: 'inline' }), resultWith('active')), false);
  // not offered: live source is already current.
  assert.equal(canRecheckKeyTrust(meta({ kind: 'fetched', url: 'https://x/reg.json' }), resultWith('active')), false);
  // not offered: verdict didn't rely on the registry.
  assert.equal(canRecheckKeyTrust(inlineUrl, resultWith('legacy_embedded')), false);
});

test('registryMetaOf: URL falls back to the commitment, generatedAt is read through', () => {
  const resolved = {
    registry: { keys: [], generatedAt: '2026-06-07T00:00:00.000Z' },
    commitment: { trustRegistryUrl: 'https://x/reg.json' },
    sources: { registry: { kind: 'inline' as const } },
  } as unknown as Parameters<typeof registryMetaOf>[0];
  const m = registryMetaOf(resolved);
  assert.equal(m.kind, 'inline');
  assert.equal(m.available, true);
  assert.equal(m.url, 'https://x/reg.json', 'inline snapshot still gets a URL from the commitment');
  assert.equal(m.generatedAt, '2026-06-07T00:00:00.000Z');
});

test('registryGeneratedAt: present-and-string only; absent/non-string ⇒ undefined', () => {
  assert.equal(registryGeneratedAt({ keys: [], generatedAt: '2026-06-07' } as never), '2026-06-07');
  assert.equal(registryGeneratedAt({ keys: [] } as never), undefined);
  assert.equal(registryGeneratedAt(undefined), undefined);
  assert.equal(registryGeneratedAt({ keys: [], generatedAt: 123 } as never), undefined);
});
