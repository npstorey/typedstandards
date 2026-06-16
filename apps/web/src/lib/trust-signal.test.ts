// Honesty contract for the #7/#8 trust signals (#119 P4). Once verify-core 0.6.0
// makes the RFC 3161 timestamp and the Rekor entry FULL offline crypto, the row
// verdict must follow the cryptographic result, not mere presence/parity:
//   - a present-but-unverified (forged/broken) token reads ALARM, not green;
//   - an absent token / no log entry stays CALM (normal) — legacy packages are fine;
//   - the deep "verified offline" verdicts are distinct from the shallow fallbacks.
// These guard against silently re-introducing the old "looks verified on presence".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTimestamp, resolveRekor, resolveEnvelopeIntegrity } from './trust-signal.ts';

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
