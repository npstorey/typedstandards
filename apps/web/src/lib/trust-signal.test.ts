// Honesty contract for the #7/#8 trust signals (#119 P4). Once verify-core 0.6.0
// makes the RFC 3161 timestamp and the Rekor entry FULL offline crypto, the row
// verdict must follow the cryptographic result, not mere presence/parity:
//   - a present-but-unverified (forged/broken) token reads ALARM, not green;
//   - an absent token / no log entry stays CALM (normal) — legacy packages are fine;
//   - the deep "verified offline" verdicts are distinct from the shallow fallbacks.
// These guard against silently re-introducing the old "looks verified on presence".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as signals from './trust-signal.ts';
import {
  resolveTimestamp,
  resolveRekor,
  resolveEnvelopeIntegrity,
  resolveKeyTrust,
  resolveCaptureMethodLabel,
  KEY_TRUST_SIGNALS,
  KEY_TRUST_BUNDLE_REGISTRY_NOT_USED,
  SIGNER_IDENTITY_SIGNALS,
  CONTENT_HASH_SIGNALS,
  CONTENT_PROFILE_SIGNALS,
} from './trust-signal.ts';

const detailOf = (d: { detail?: string }): string => {
  assert.ok(d.detail, 'descriptor carries a detail string');
  return d.detail;
};

test('resolveTimestamp: tier follows the cryptographic verdict, not presence', () => {
  assert.equal(resolveTimestamp(false, null).tier, 'normal', 'no token ⇒ calm');
  assert.equal(resolveTimestamp(true, true).tier, 'verified', 'present + chain-verified ⇒ green');
  assert.match(detailOf(resolveTimestamp(true, true)), /chain-verified to the pinned FreeTSA root/);
  assert.equal(resolveTimestamp(true, false).tier, 'alarm', 'present but unverified ⇒ alarm (not green)');
  assert.equal(resolveTimestamp(true, null).tier, 'alarm', 'present but not evaluated ⇒ alarm, never green');
});

test('resolveRekor: deep offline inclusion is distinct from parity / outage / absence', () => {
  // deep: an offline-recomputed inclusion proof against a signed checkpoint.
  const deep = resolveRekor(true, true, null);
  assert.equal(deep.tier, 'verified');
  assert.match(detailOf(deep), /Merkle inclusion verified offline/);

  // parity fallback: no carried proof, but an online hash match.
  const parity = resolveRekor(true, false, true);
  assert.equal(parity.tier, 'verified');
  assert.match(detailOf(parity), /entry-hash parity/);

  // present but neither deep nor parity-confirmed ⇒ Attention (likely outage), not green.
  assert.equal(resolveRekor(true, false, false).tier, 'attention');
  assert.equal(resolveRekor(true, false, null).tier, 'attention');

  // no entry at all ⇒ calm.
  assert.equal(resolveRekor(false, false, null).tier, 'normal');
});

test('resolveEnvelopeIntegrity: tri-state — content-unavailable is NOT tampering (#21)', () => {
  // bytes present + hash matches ⇒ green.
  assert.equal(resolveEnvelopeIntegrity({ status: 'verified' }).tier, 'verified');

  // bytes present + hash MISMATCHES ⇒ the one alarm. No-regression guardrail:
  // a fetched, tampered package must still read "Contents changed since signing".
  const altered = resolveEnvelopeIntegrity({ status: 'altered' });
  assert.equal(altered.tier, 'alarm');
  assert.match(altered.label, /changed since signing/);

  // content private by design ⇒ NEUTRAL/calm (same family as "no timestamp"),
  // never amber/red.
  const priv = resolveEnvelopeIntegrity({ status: 'unavailable', reason: 'private' });
  assert.equal(priv.tier, 'normal', 'content-private is calm, not an alarm');
  // Vocabulary-neutral copy: says "content private", NOT "sealed" (the committed→
  // sealed UI rename is a separate post-demo sweep).
  assert.match(priv.label, /private/i);
  assert.doesNotMatch(priv.label, /sealed/i);
  assert.doesNotMatch(detailOf(priv), /sealed/i);

  // present-but-unfetchable location ⇒ Attention (unconfirmed), not a false altered.
  const unfetchable = resolveEnvelopeIntegrity({ status: 'unavailable', reason: 'unfetchable' });
  assert.equal(unfetchable.tier, 'attention');
  assert.doesNotMatch(unfetchable.label, /changed since signing/);
});

// --- Wave N14 rows (hub ADR-0029, ADR-0030 §10) ----------------------------

test('self_certified: tier normal, never verified; says what the key proves and what it does not', () => {
  const d = resolveKeyTrust({ status: 'self_certified' });
  assert.equal(d.tier, 'normal');
  assert.equal(d.label, 'Signed with a self-certifying key');
  assert.equal(
    detailOf(d),
    "The signer's identifier is derived from the signing key, so it proves that the same key signed everything under this identifier — not who holds the key. No registry vouches for it, and the key cannot be rotated or revoked.",
  );
  assert.doesNotMatch(d.label, /registered/i);
});

test('key_derived_match: its own #14 row, tier normal, never the registry-match label', () => {
  const d = SIGNER_IDENTITY_SIGNALS.key_derived_match;
  assert.equal(d.tier, 'normal');
  assert.equal(d.label, 'Signer identifier matches the signing key');
  assert.equal(
    detailOf(d),
    'The identifier is derived from the key that signed this package. This shows the same key signed anything else under this identifier, and nothing about who holds it.',
  );
  assert.notEqual(d.label, SIGNER_IDENTITY_SIGNALS.ok.label);
});

test('key_derived_mismatch: fatal (alarm), and says the identifier does not name the signing key', () => {
  const d = SIGNER_IDENTITY_SIGNALS.key_derived_mismatch;
  assert.equal(d.tier, 'alarm');
  assert.equal(d.label, 'Signer identifier does not match the signing key');
  assert.match(detailOf(d), /do not trust/);
});

test('content_bytes_unavailable: attention, says the bytes were not checked — never verified, never alarm', () => {
  const d = CONTENT_HASH_SIGNALS.content_bytes_unavailable;
  assert.equal(d.tier, 'attention');
  assert.equal(d.label, 'Content file not checked');
  assert.match(detailOf(d), /not hashed/);
});

test('content-profile statuses: ADR-0029 §5 tiers, and no status is alarm', () => {
  assert.equal(CONTENT_PROFILE_SIGNALS.ok.tier, 'verified');
  assert.equal(CONTENT_PROFILE_SIGNALS.contentProfile_absent.tier, 'normal');
  assert.equal(CONTENT_PROFILE_SIGNALS.contentProfile_unknown.tier, 'attention');
  assert.equal(CONTENT_PROFILE_SIGNALS.contentProfile_inconsistent.tier, 'attention');
  assert.match(detailOf(CONTENT_PROFILE_SIGNALS.contentProfile_inconsistent), /malformed/);
  for (const d of Object.values(CONTENT_PROFILE_SIGNALS)) assert.notEqual(d.tier, 'alarm');
});

test('capture-method labels: script-run and tool-emitted each have a plain-language reading', () => {
  assert.equal(
    resolveCaptureMethodLabel('script-run'),
    'Read into the package by a packaging program from files that already existed on disk.',
  );
  assert.equal(
    resolveCaptureMethodLabel('tool-emitted'),
    'Written into the package by the program that computed the content.',
  );
});

test('set-aside bundle registry: same tier as registry_unavailable, and says the registry was not used', () => {
  assert.equal(KEY_TRUST_BUNDLE_REGISTRY_NOT_USED.tier, KEY_TRUST_SIGNALS.registry_unavailable.tier);
  assert.match(detailOf(KEY_TRUST_BUNDLE_REGISTRY_NOT_USED), /came with this bundle/);
  assert.match(detailOf(KEY_TRUST_BUNDLE_REGISTRY_NOT_USED), /cannot raise/);
  assert.doesNotMatch(detailOf(KEY_TRUST_BUNDLE_REGISTRY_NOT_USED), /could not be loaded/);
});

test('continuity: no signal anywhere says "same publisher" or "same person"', () => {
  const texts: string[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === 'string') texts.push(v);
    else if (v && typeof v === 'object') for (const x of Object.values(v)) visit(x);
  };
  visit(signals);
  assert.ok(texts.length > 50, 'the scan reached the signal maps');
  for (const t of texts) assert.doesNotMatch(t, /same (publisher|person)/i, t);
});

test('#78: the supplied-registry readings never take the tier or label a declared registry earns', () => {
  assert.equal(signals.KEY_TRUST_SUPPLIED_REGISTRY.tier, 'attention');
  assert.notEqual(signals.KEY_TRUST_SUPPLIED_REGISTRY.label, KEY_TRUST_SIGNALS.active.label);
  assert.doesNotMatch(signals.KEY_TRUST_SUPPLIED_REGISTRY.label, /registered/i);
  assert.match(detailOf(signals.KEY_TRUST_SUPPLIED_REGISTRY), /not checked against the publisher’s domain/);
  assert.equal(signals.SIGNER_IDENTITY_SUPPLIED_REGISTRY.tier, 'normal');
  assert.notEqual(signals.SIGNER_IDENTITY_SUPPLIED_REGISTRY.label, SIGNER_IDENTITY_SIGNALS.ok.label);
  assert.match(detailOf(signals.SIGNER_IDENTITY_SUPPLIED_REGISTRY), /not checked against the publisher’s domain/);
});
