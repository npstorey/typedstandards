// Q15 — the offline-bundle DEMONSTRATION (#119). This is the test that graduates
// spec §9.4 from a target into a demonstrated property: a self-contained commitment
// bundle verifies at FULL depth with ZERO civicaitools.org network.
//
// Two layers:
//   1. REAL fixtures — `/api/evidence/<slug>/commitment?inline=1` responses captured
//      from production (Q15a): top-level packageHash, the package + the stamped trust
//      registry inline, and the rfc3161 / rekor / lifecycle proofs already inline.
//      The route segment is AS CAPTURED: under the 2026-08-19 vocabulary settlement
//      the canonical segment became `/api/records/`, with `/api/evidence/` a permanent
//      alias (spec Appendix J). These bytes are signed, so they are frozen where they
//      are and are permanently this suite's PRIOR-ERA leg — see the era note further
//      down for how the settlement era is covered. They span the matrix:
//        - d67b8e — full-depth headline: #5 active, #7 chain, #8 Merkle inclusion, AND
//          #10 at attestation-chain depth (2 carried nodes: withdraws -> reinstates).
//        - 255b8e — prod-parity: #5/#7/#8 all deep; #10 honestly calm (no transitions).
//        - da9246 — legacy/calm: #7 deep, NO rekor (#8 calm-absent), legacy_embedded #5,
//          withdrawn lifecycle — the verifier stays CALM offline, no false alarm.
//      The real FreeTSA RFC 3161 token and Rekor inclusion proof in these fixtures are
//      the only way to exercise #7/#8 at real crypto depth, so the captured fixtures
//      carry that.
//   2. A SYNTHETIC minted fixture — a self-contained commitment constructed in-process
//      (Ed25519, no prod data) so CI's offline-plumbing regression doesn't depend on
//      prod-captured material drifting. It proves the inline-bundle PLUMBING + #1/#13
//      hash, #2 signature, #5 key-trust (against the minted inline registry), and #10 at
//      attestation-chain depth, all network-blocked. It deliberately omits a TSA token /
//      Rekor proof (those need real CA/log material) → #7/#8 read calm-absent. It is
//      minted in BOTH vocabulary eras (see ERAS below), which is what gives this suite
//      settlement-era coverage at all: the captured fixtures cannot be re-minted, so
//      the synthetic bundle is the only leg that can carry the new wire key and URN
//      scheme and still be self-consistent under its own signatures.
//
// Every fixture runs through the FULL verify-flow in bundle mode with a `fetch` stub
// that THROWS on any call: we assert zero fetch, `fullyOffline`, and the verdict.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import {
  resolveInput,
  buildVerifyInput,
  resolveCarriedLifecycle,
  runVerify,
  rollupVerdict,
} from './verify-flow.ts';
import { recomputePackageHash, type VerifyResult } from '@typedstandards/verify-core';

const fixture = (short: string): string =>
  readFileSync(new URL(`./__fixtures__/q15-${short}.json`, import.meta.url), 'utf8');

/** Run the full verify-flow over a self-contained commitment (bundle mode) with a
 *  `fetch` stub that THROWS on any call (so a single attempted fetch both fails the
 *  assertion and is counted). Returns the verdict + the number of fetches attempted. */
async function runOffline(raw: string): Promise<{ result: VerifyResult; fetches: number; fullyOffline: boolean }> {
  const realFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = ((...args: unknown[]) => {
    fetches += 1;
    throw new Error(`NETWORK BLOCKED — offline bundle attempted a fetch: ${String(args[0])}`);
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('bundle', raw);
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const lifecycle = resolveCarriedLifecycle(resolved.commitment);
    const result = await runVerify(vinput, resolved.registry, lifecycle);
    return { result, fetches, fullyOffline: resolved.fullyOffline };
  } finally {
    globalThis.fetch = realFetch;
  }
}

// Shared by every fixture: zero network, self-contained, intact + signed, never an
// integrity ALARM (the §9.4 property is full-depth verification with no fetch).
async function assertOfflineAndCalm(raw: string, label: string): Promise<VerifyResult> {
  const { result, fetches, fullyOffline } = await runOffline(raw);
  assert.equal(fetches, 0, `${label}: a self-contained bundle must verify with ZERO network`);
  assert.equal(fullyOffline, true, `${label}: every input was read from the bundle`);
  assert.equal(result.hashMatch, true, `${label}: bytes intact`);
  assert.equal(result.signatureValid, true, `${label}: signature verifies offline`);
  assert.notEqual(result.contentHash?.status, 'content_hash_mismatch', `${label}: no content alarm`);
  assert.notEqual(rollupVerdict(result).tier, 'alarm', `${label}: never a false alarm offline`);
  return result;
}

test('Q15 d67b8e: FULL depth offline — #5 active, #7 chain, #8 inclusion, #10 attestation-chain', async () => {
  const r = await assertOfflineAndCalm(fixture('d67b8e'), 'd67b8e');
  assert.equal(r.contentHash?.status, 'ok');
  assert.equal(r.keyTrust?.status, 'active', 'key trust ACTIVE via the inline registry');
  assert.equal(r.rfc3161?.verified, true);
  assert.equal(r.rfc3161?.chainVerified, true, 'TSA cert chain to the pinned root');
  assert.equal(r.rfc3161?.ekuTimestamping, true);
  assert.equal(r.rekorInclusion?.inclusionVerified, true, 'Rekor Merkle inclusion (offline)');
  assert.equal(r.rekorInclusion?.checkpointVerified, true, 'signed checkpoint (offline)');
  // The headline: #10 resolved at attestation-chain depth from the 2 carried signed
  // nodes (withdraws -> reinstates), each verified in-process — not a state column.
  assert.equal(r.lifecycle.source, 'attestation-chain', '#10 at full (attestation-chain) depth');
  assert.equal(r.lifecycle.status, 'active', 'withdrawn then reinstated ⇒ active');
});

test('Q15 255b8e: prod-parity offline — #5/#7/#8 deep; #10 calm (no transitions)', async () => {
  const r = await assertOfflineAndCalm(fixture('255b8e'), '255b8e');
  assert.equal(r.keyTrust?.status, 'active', 'key trust ACTIVE via the inline registry');
  assert.equal(r.rfc3161?.verified, true);
  assert.equal(r.rfc3161?.chainVerified, true);
  assert.equal(r.rekorInclusion?.inclusionVerified, true);
  assert.equal(r.rekorInclusion?.checkpointVerified, true);
  // No lifecycle history at all ⇒ source 'none', resolved calm/active (not a gap).
  assert.equal(r.lifecycle.source, 'none');
  assert.equal(r.lifecycle.status, 'active');
});

test('Q15 da9246: legacy/calm offline — #7 deep, NO rekor (calm-absent), legacy_embedded, withdrawn', async () => {
  const r = await assertOfflineAndCalm(fixture('da9246'), 'da9246');
  assert.equal(r.keyTrust?.status, 'legacy_embedded', 'pre-registry key — neutral, not failed');
  assert.equal(r.rfc3161?.verified, true, 'RFC 3161 still deep on a legacy package');
  // No Rekor entry at all: inclusion is honestly null (calm-absent), zero network.
  assert.equal(r.rekorInclusion, null, 'no transparency-log entry ⇒ calm-absent, not alarm');
  assert.equal(r.hasRekor, false);
  // Withdrawn is a lifecycle STATE (legacy columns), surfaced calmly — not an alarm.
  assert.equal(r.lifecycle.status, 'withdrawn');
  assert.equal(r.lifecycle.source, 'legacy-columns');
});

// --- Synthetic minted self-contained commitment (drift-proof CI) -----------

/**
 * The two vocabulary eras a conformant verifier must treat as equally valid
 * (spec Appendix J §J.4 rule 2; the 2026-08-19 settlement).
 *
 * The three CAPTURED fixtures above are permanently the prior-era leg — they are
 * real production bytes whose signatures cover their own key names, so they can
 * never be re-minted into the settlement era and are not touched. The synthetic
 * bundle is what makes the SETTLEMENT era testable at all: it is minted in
 * process, so it can carry the new key and the new URN scheme and still be
 * self-consistent under the same hashes and signatures.
 *
 * What varies between the eras here is EXACTLY the surface the settlement
 * renamed and nothing else:
 *   - `protocolVersion` vs `evidenceProtocolVersion` — the §8.8.1 wire key;
 *   - `urn:civic-record:` vs `urn:civic-evidence:` — the §8.1.4 URN scheme,
 *     carried on the signer identifier, where it is covered by the envelope hash
 *     and cross-checked against the trust registry.
 *
 * Both legs must reach an identical verdict at identical depth. That is the
 * substantive claim: era is not a trust signal, and no check may branch on it.
 */
const ERAS = [
  {
    label: 'settlement-era',
    protocolVersionKey: 'protocolVersion',
    urnScheme: 'urn:civic-record:',
  },
  {
    label: 'prior-era',
    protocolVersionKey: 'evidenceProtocolVersion',
    urnScheme: 'urn:civic-evidence:',
  },
] as const;

type Era = (typeof ERAS)[number];

/** The signer identity for an era — the URN scheme is the only difference, and it
 *  travels through the envelope, the attestation node, and the trust registry
 *  together (they must agree, or #6 signer-identity fails). */
function signerFor(era: Era): { bindingTier: string; identifier: string; displayName: string } {
  return {
    bindingTier: 'platform',
    identifier: `${era.urnScheme}platform:synthetic-publisher`,
    displayName: 'Synthetic Test Publisher',
  };
}

/** Mint a self-contained commitment in-process, in the given vocabulary era: inline
 *  package + minted inline registry + Ed25519 signature + a signer-matched `withdraws`
 *  lifecycle node. No TSA token / Rekor proof (those need real CA/log material) ⇒
 *  #7/#8 read calm-absent. The package hash and every node id come from verify-core's
 *  own `recomputePackageHash`, and signatures are Ed25519 over that hash string —
 *  exactly what the verifier checks (`verifySignature` / `verifyAttestationNode`), so
 *  the bundle is self-consistent in either era. */
function mintSyntheticCommitment(era: Era = ERAS[0]): string {
  const SIGNER = signerFor(era);
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const kid = 'test:synthetic-2026';
  const signOverHash = (hashHex: string): string =>
    Buffer.from(nodeSign(null, Buffer.from(hashHex, 'utf8'), privateKey)).toString('base64');
  const sigEnvelope = (hashHex: string) => ({
    algorithm: 'Ed25519',
    publicKey: publicKeyB64,
    signature: signOverHash(hashHex),
  });

  const pkg: Record<string, unknown> = {
    [era.protocolVersionKey]: '0.1.0',
    type: 'analysis/datHere/v1',
    signer: { identifier: SIGNER.identifier, displayName: SIGNER.displayName },
    subject: { title: 'Synthetic offline-bundle fixture' },
    output: 'A minted, self-contained record package for the hermetic Q15 test.',
  };
  const packageHash = recomputePackageHash(pkg);

  // Signer-matched withdrawal attestation → #10 resolves 'withdrawn' at chain depth.
  const node: Record<string, unknown> = {
    type: 'attestation/withdraws/v1',
    targetNodeId: packageHash,
    signer: SIGNER,
    metadata: { createdAt: '2026-06-08T00:00:00.000Z' },
    effectiveAt: '2026-06-08T00:00:00.000Z',
    reason: 'synthetic withdrawal',
  };
  const nodeId = recomputePackageHash(node);

  const commitment = {
    [era.protocolVersionKey]: '0.1.0',
    packageHash,
    package: pkg,
    signer: { identifier: SIGNER.identifier, displayName: SIGNER.displayName },
    signature: { ...sigEnvelope(packageHash), kid },
    trustRegistry: {
      generatedAt: '2026-06-08T00:00:00.000Z',
      keys: [
        {
          kid,
          publicKey: publicKeyB64,
          status: 'active',
          activatedAt: '2026-01-01T00:00:00.000Z',
          deprecatedAt: null,
          revokedAt: null,
          signerIdentity: SIGNER,
        },
      ],
    },
    lifecycleAttestations: [{ node, nodeId, signature: sigEnvelope(nodeId) }],
    // no rfc3161Timestamp / rekor* ⇒ #7/#8 calm-absent
  };
  return JSON.stringify(commitment);
}

// Run the whole synthetic leg once per era. The assertions are identical by
// construction — that identity IS the dual-era guarantee, so they are deliberately
// not weakened for the prior-era pass.
for (const era of ERAS) {
  test(`Q15 synthetic (${era.label}): a minted self-contained bundle verifies offline at full plumbing depth`, async () => {
    const r = await assertOfflineAndCalm(mintSyntheticCommitment(era), `synthetic/${era.label}`);
    // #5 active via the minted inline registry (no network).
    assert.equal(r.keyTrust?.status, 'active', 'minted key is active in the inline registry');
    // #10 at attestation-chain depth from the minted signed node — withdrawn.
    assert.equal(r.lifecycle.source, 'attestation-chain', '#10 verified from the minted signed chain');
    assert.equal(r.lifecycle.status, 'withdrawn', 'a signer-matched withdraws node ⇒ withdrawn');
    // #6 signer identity resolves against the era's URN scheme — the identifier is an
    // OPAQUE string to every check, which is exactly why both eras pass here.
    assert.equal(r.signerIdentity?.status, 'ok', 'the era’s URN scheme is carried, not parsed');
    // #7/#8 are honestly calm-absent (no TSA token / Rekor proof minted).
    assert.equal(r.rfc3161, null, 'no minted TSA token ⇒ #7 calm-absent');
    assert.equal(r.rekorInclusion, null, 'no minted Rekor proof ⇒ #8 calm-absent');
    assert.equal(r.hasTimestamp, false);
    assert.equal(r.hasRekor, false);
  });
}

test('Q15 dual-era: the two eras differ ONLY in the renamed surface, and verify identically', async () => {
  // The settlement's normative rule 2 (§J.4): "verifiers treat both eras as valid …
  // era is not a trust signal." Asserted as an identity between the two verdicts
  // rather than as two independent green runs, so a future change that starts
  // branching on era — even to something equally green — fails here.
  const [settlement, prior] = ERAS;
  const s = JSON.parse(mintSyntheticCommitment(settlement)) as Record<string, unknown>;
  const p = JSON.parse(mintSyntheticCommitment(prior)) as Record<string, unknown>;

  assert.equal(s['protocolVersion'], '0.1.0', 'settlement era carries the new wire key');
  assert.equal(s['evidenceProtocolVersion'], undefined, 'and not the prior-era key');
  assert.equal(p['evidenceProtocolVersion'], '0.1.0', 'prior era carries the old wire key');
  assert.equal(p['protocolVersion'], undefined, 'and not the new key');

  const sr = await runOffline(JSON.stringify(s));
  const pr = await runOffline(JSON.stringify(p));
  assert.equal(sr.fetches, 0);
  assert.equal(pr.fetches, 0);
  assert.deepEqual(
    rollupVerdict(sr.result),
    rollupVerdict(pr.result),
    'the rolled-up verdict must be identical across eras',
  );
  for (const key of ['hashMatch', 'signatureValid', 'hasRekor', 'hasTimestamp'] as const) {
    assert.equal(sr.result[key], pr.result[key], `${key} must not differ by era`);
  }
  assert.equal(sr.result.keyTrust?.status, pr.result.keyTrust?.status);
  assert.equal(sr.result.signerIdentity?.status, pr.result.signerIdentity?.status);
  // Lifecycle is compared at STATUS and SOURCE, not by deep equality: the chain's
  // node ids and signer identifier legitimately differ between the eras, because the
  // URN scheme is part of the SIGNED content and therefore part of what is hashed.
  // That difference is the settlement working as designed — the verdict is what must
  // not move.
  assert.equal(sr.result.lifecycle.status, pr.result.lifecycle.status);
  assert.equal(sr.result.lifecycle.source, pr.result.lifecycle.source);
  assert.notEqual(
    sr.result.nodeId,
    pr.result.nodeId,
    'sanity: the two eras really are different signed bytes, not the same bundle twice',
  );
});
