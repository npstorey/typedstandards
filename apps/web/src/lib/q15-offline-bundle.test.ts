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
//   3. A MINTED, COMMITTED self-certified fixture (Wave N14 P7) — `q15-self-certified.json`,
//      the fixture an independent implementation can test against: a package under hub
//      ADR-0029's `scripted-recomputation` profile, canonicalized under `raw-bytes/v1` with
//      an inline `output` (the committed `q15-self-certified.output.csv`), signed by a
//      self-certifying signer under ADR-0030 (`did:key` identifier, no trust registry and
//      no `trustRegistryUrl`). It is minted by `__fixtures__/q15-self-certified.mint.ts`
//      with the shipped cores from a seed the fixtures README documents, and the test
//      below re-mints it and asserts the committed bytes equal the result. No TSA token /
//      Rekor proof ⇒ #7/#8 calm-absent. See `__fixtures__/README.md`.
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
  buildCheckRows,
  registryMetaOf,
  canRecheckKeyTrust,
  recheckKeyTrustLive,
  resolveHostRecognition,
  HOST_DIRECTORY,
  type CheckRow,
  type ResolveStep,
} from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';
import { KEY_TRUST_SIGNALS } from './trust-signal.ts';
import {
  recomputePackageHash,
  computeEnvelopeHash,
  deriveKeyDerivedIdentifier,
  sha256Hex,
  RAW_BYTES_CANONICALIZATION,
  type VerifyResult,
} from '@typedstandards/verify-core';
import { createHash } from 'node:crypto';
import {
  mintSelfCertifiedBundle,
  readContentFile,
  BUNDLE_FILE,
  CONTENT_FILE,
} from './__fixtures__/q15-self-certified.mint.ts';

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

// --- The committed self-certified fixture (Wave N14 P7) --------------------
//
// `q15-self-certified.json`: a `scripted-recomputation/interop-fixture` package whose
// content is the committed CSV beside it, fingerprinted under raw-bytes/v1 as its
// exact bytes and carried inline as `output`; signed by a self-certifying signer
// (hub ADR-0030: `bindingTier: "pseudonymous"`, a `did:key` identifier that is also
// the `kid` and `metadata.signingKeyId`); no trust registry and no registry URL.
// What each check reports on it is listed in `__fixtures__/README.md`.

const selfCertifiedRaw = (): string =>
  readFileSync(new URL(`./__fixtures__/${BUNDLE_FILE}`, import.meta.url), 'utf8');

test('Q15 self-certified: a raw-bytes/v1 scripted-recomputation bundle with no registry verifies fully offline', async () => {
  const raw = selfCertifiedRaw();
  const { result: r, fetches, fullyOffline } = await runOffline(raw);
  assert.equal(fetches, 0, 'zero network calls');
  assert.equal(fullyOffline, true, 'no registry is needed, so every input came from the bundle');

  // #1 envelope integrity and #13 node id.
  assert.equal(r.hashMatch, true, '#1 hashMatch');
  assert.deepEqual(r.envelopeIntegrity, { status: 'verified' }, '#1 envelope integrity');
  const bundle = JSON.parse(raw) as { packageHash: string };
  assert.equal(r.recomputedHash, bundle.packageHash, '#1 recomputed hash');
  assert.equal(r.nodeId, bundle.packageHash, '#13 node id');
  // #2 signature.
  assert.equal(r.hasSigning, true, '#2 hasSigning');
  assert.equal(r.signatureValid, true, '#2 signature valid');
  // #3 the rule resolves; #4 the inline output's bytes hash to contentHash.sha256.
  assert.deepEqual(r.contentCanonicalization, { status: 'ok', rule: RAW_BYTES_CANONICALIZATION }, '#3');
  assert.equal(r.contentHash?.status, 'ok', '#4 content hash');
  assert.equal(r.contentHash?.matched, 'sha256', '#4 matched algorithm');
  // #5 key trust: self-certified, never verified.
  assert.equal(r.keyTrust?.status, 'self_certified', '#5 key trust');
  assert.equal(r.keyTrust?.verified, false, '#5 not verified: no registry vouches for the key');
  // #7 / #8 calm-absent: no RFC 3161 token, no Rekor entry.
  assert.equal(r.rfc3161, null, '#7 calm-absent');
  assert.equal(r.hasTimestamp, false);
  assert.equal(r.rekorInclusion, null, '#8 calm-absent');
  assert.equal(r.hasRekor, false);
  // #12 type.
  assert.deepEqual(r.typeResolution, { status: 'ok', type: 'content/analysis/v1' }, '#12 type');
  // #14 the identifier is the one derived from the signing key.
  assert.equal(r.signerIdentity?.status, 'key_derived_match', '#14');
  // #15 script-run is in the scripted-recomputation vocabulary.
  assert.equal(r.captureMethodVocab?.status, 'ok', '#15');
  assert.equal(r.captureMethodVocab?.profileType, 'scripted-recomputation', '#15 profile type');
  assert.equal(r.captureMethodVocab?.captureMethod, 'script-run', '#15 capture method');
  // #16 no metadata.contentProfile key.
  assert.equal(r.contentProfile?.status, 'contentProfile_absent', '#16');

  // The site's verdict: normal, never verified.
  const verdict = rollupVerdict(r);
  assert.equal(verdict.tier, 'normal');
  assert.notEqual(verdict.tier, 'verified');
  assert.equal(verdict.headline, 'Signature valid — self-certified signer');
});

test('Q15 self-certified: re-minting from the documented seed and inputs with the shipped cores is byte-identical to the committed bundle', () => {
  const committed = selfCertifiedRaw();
  const reminted = mintSelfCertifiedBundle(readContentFile());
  // The load-bearing provenance check: string equality over the whole file.
  assert.equal(reminted, committed, `${BUNDLE_FILE} is byte-identical to a fresh mint`);
  assert.equal(
    Buffer.from(reminted, 'utf8').equals(readFileSync(new URL(`./__fixtures__/${BUNDLE_FILE}`, import.meta.url))),
    true,
    'byte-equal at the byte level too',
  );
});

test('Q15 self-certified: the committed content file, the hashes and the identifier agree with each other', () => {
  const bundle = JSON.parse(selfCertifiedRaw()) as Record<string, unknown> & {
    packageHash: string;
    signer: { bindingTier: string; identifier: string };
    signature: { publicKey: string; kid: string; algorithm: string };
    contentHash: { sha256: string };
    package: Record<string, unknown> & {
      metadata: Record<string, unknown>;
      output: string;
      contentHash: { sha256: string };
      signer: { bindingTier: string; identifier: string };
    };
  };
  const pkg = bundle.package;
  const fileBytes = readFileSync(new URL(`./__fixtures__/${CONTENT_FILE}`, import.meta.url));

  // raw-bytes/v1: the file's ordinary SHA-256 is the signed content hash, and the
  // inline output is exactly the file's bytes.
  const fileSha256 = createHash('sha256').update(fileBytes).digest('hex');
  assert.equal(pkg.contentHash.sha256, fileSha256, 'contentHash.sha256 is the file digest');
  assert.equal(bundle.contentHash.sha256, fileSha256, 'the view carries the same digest');
  assert.equal(sha256Hex(pkg.output), fileSha256, 'output hashes to the same digest');
  assert.equal(Buffer.from(pkg.output, 'utf8').equals(fileBytes), true, 'output is the file, byte for byte');

  // The envelope hash is SHA-256 over the JCS of the package (the unsigned envelope).
  assert.equal(computeEnvelopeHash(pkg), bundle.packageHash);
  assert.equal(recomputePackageHash(pkg), bundle.packageHash);

  // ADR-0030 §2 and §5: the identifier derives from the envelope's publicKey, and it
  // names the key in all three places.
  const derived = deriveKeyDerivedIdentifier(bundle.signature.publicKey);
  assert.equal(pkg.signer.identifier, derived);
  assert.equal(bundle.signer.identifier, derived);
  assert.equal(bundle.signature.kid, derived);
  assert.equal(pkg.metadata['signingKeyId'], derived);
  assert.equal(pkg.signer.bindingTier, 'pseudonymous');
  assert.equal(bundle.signature.algorithm, 'Ed25519ph');

  // What the fixture must NOT carry.
  for (const absent of ['trustRegistryUrl', 'trustRegistryUrlLegacy', 'trustRegistry', 'signerIdentity', 'rfc3161Timestamp', 'rekorEntryId', 'rekorInclusionProof', 'rekorEntryBody', 'hostDirectory', 'packageUrl']) {
    assert.equal(absent in bundle, false, `no ${absent}`);
  }
  assert.equal('contentProfile' in pkg.metadata, false, 'no metadata.contentProfile');
});

// --- Registry provenance for the self-certified fixture (Wave N14 P9) ----------
//
// Hub ADR-0030 §4 rule 3: for a key-derived signer, only a registry from the
// declared registry URL can raise the key status. A trust registry counts as
// declared only when it is fetched from an https: URL; one read from any other URL
// counts as carried in the bundle, so it can lower the status and never raise it.
// Each case adds a registry URL to the committed fixture's view (outside the signed
// package) and serves a registry that lists the fixture's own (kid, publicKey) as
// active.

const SC_HTTPS_REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const SC_HTTP_REGISTRY_URL = 'http://registry-host.test/trust-registry.json';

function registryListingFixtureKey(): Record<string, unknown> {
  const bundle = JSON.parse(selfCertifiedRaw()) as { signature: { kid: string; publicKey: string } };
  return {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      {
        kid: bundle.signature.kid,
        publicKey: bundle.signature.publicKey,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
      },
    ],
  };
}

const dataUrlOf = (doc: unknown): string => `data:application/json,${encodeURIComponent(JSON.stringify(doc))}`;

/** Run the site's flow over the fixture with `field` set to `url` on the view. The
 *  fetch stub reads a `data:` URL with the platform fetch, serves the registry at
 *  the two test registry URLs, and throws on anything else. */
async function runWithRegistryUrl(field: 'trustRegistryUrl' | 'trustRegistryUrlLegacy', url: string) {
  const bundle = JSON.parse(selfCertifiedRaw()) as Record<string, unknown>;
  bundle[field] = url;
  const registry = registryListingFixtureKey();
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: unknown, init?: RequestInit) => {
    const u = String(input);
    if (u.startsWith('data:')) return realFetch(u, init);
    if (u === SC_HTTPS_REGISTRY_URL || u === SC_HTTP_REGISTRY_URL) {
      return Promise.resolve(
        new Response(JSON.stringify(registry), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    }
    throw new Error(`NETWORK BLOCKED: ${u}`);
  }) as typeof globalThis.fetch;
  try {
    const steps: ResolveStep[] = [];
    const resolved = await resolveInput('bundle', JSON.stringify(bundle), undefined, (s) => steps.push(s));
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(
      vinput,
      resolved.registry,
      resolveCarriedLifecycle(resolved.commitment),
      resolved.registryProvenance,
    );
    const rows = buildCheckRows(result, vinput, resolved.commitment, registryMetaOf(resolved));
    return {
      resolved,
      result,
      rows,
      verdict: rollupVerdict(result),
      registryStep: steps.find((s) => s.key === 'registry'),
      keyTrustRow: rows.find((r) => r.num === '5'),
    };
  } finally {
    globalThis.fetch = realFetch;
  }
}

for (const c of [
  { name: 'a data: trustRegistryUrl', field: 'trustRegistryUrl' as const, url: () => dataUrlOf(registryListingFixtureKey()) },
  { name: 'an http: trustRegistryUrl', field: 'trustRegistryUrl' as const, url: () => SC_HTTP_REGISTRY_URL },
  { name: 'a data: trustRegistryUrlLegacy', field: 'trustRegistryUrlLegacy' as const, url: () => dataUrlOf(registryListingFixtureKey()) },
]) {
  test(`Q15 self-certified: a registry read from ${c.name} counts as carried in the bundle — self_certified, never Verified`, async () => {
    const run = await runWithRegistryUrl(c.field, c.url());
    assert.ok(run.resolved.registry, 'the registry was read');
    assert.equal(run.resolved.registryProvenance, 'bundle', 'not a declared registry');
    assert.equal(run.result.keyTrust?.status, 'self_certified');
    assert.equal(run.result.keyTrust?.verified, false);
    assert.equal(run.verdict.tier, 'normal');
    assert.notEqual(run.verdict.headline, 'Verified');
    assert.equal(run.keyTrustRow?.signal.label, KEY_TRUST_SIGNALS.self_certified.label);
    assert.notEqual(run.keyTrustRow?.signal.label, KEY_TRUST_SIGNALS.active.label);
    assert.equal(
      run.keyTrustRow?.math.find((m) => m.label === 'Registry source')?.value,
      'read from a registry URL that is not https: (can lower this signer’s key status, never raise it)',
    );
    assert.equal(run.keyTrustRow?.depthNote, undefined, 'no "live registry" note');
    assert.notEqual(run.registryStep?.label, 'Fetched publisher trust registry');
    assert.equal(
      run.registryStep?.label,
      'Read trust registry from a URL that is not https: — it can lower key trust, never raise it',
    );
  });
}

test('Q15 self-certified: a registry fetched from an https: trustRegistryUrl that lists the key active yields active (ADR-0030 §4 rule 3)', async () => {
  const run = await runWithRegistryUrl('trustRegistryUrl', SC_HTTPS_REGISTRY_URL);
  assert.equal(run.resolved.registryProvenance, 'declared-url');
  assert.equal(run.result.keyTrust?.status, 'active');
  assert.equal(run.result.keyTrust?.verified, true);
  assert.equal(run.keyTrustRow?.signal.label, KEY_TRUST_SIGNALS.active.label);
  assert.equal(
    run.keyTrustRow?.math.find((m) => m.label === 'Registry source')?.value,
    'fetched from the registry URL the record declares',
  );
  assert.equal(run.registryStep?.label, 'Fetched publisher trust registry');
});

// --- What the page shows for the captured bundles (#78) ----------------------
//
// The three captured bundles carry the publisher's registry inline, beside a
// trustRegistryUrl on its https: domain. Offline, that registry came from the bundle:
// the page says so, and says it was not checked against the publisher's domain. The
// signature, content, timestamp and log rows are what they were, and the only rows
// that depend on where the registry came from are #5 and #14. Online, the re-check
// fetches the declared https: registry and confirms the key; verifying the record by
// hash or URL fetches that registry itself and reads Verified.

const CAPTURED = ['d67b8e', '255b8e', 'da9246'] as const;

/** The page for a captured bundle, offline (every fetch throws). */
async function capturedPage(short: (typeof CAPTURED)[number]) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    throw new Error(`NETWORK BLOCKED: ${String(input)}`);
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput('bundle', fixture(short));
    const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
    const result = await runVerify(vinput, resolved.registry, resolveCarriedLifecycle(resolved.commitment), resolved.registryProvenance);
    const meta = registryMetaOf(resolved);
    return {
      resolved,
      vinput,
      result,
      meta,
      rows: buildCheckRows(result, vinput, resolved.commitment, meta),
      verdict: rollupVerdict(result, meta),
    };
  } finally {
    globalThis.fetch = realFetch;
  }
}

const rowIn = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

test('Q15 captured bundles offline: the signature, content, timestamp and log rows are unchanged', async () => {
  for (const short of CAPTURED) {
    const page = await capturedPage(short);
    const tierLabel = (num: string) => {
      const r = page.rows.find((x) => x.num === num);
      return r ? `${r.signal.tier} ${r.signal.label}` : 'absent';
    };
    // Measured on main at ed087b1 before the #78 change.
    assert.equal(tierLabel('1'), 'verified Contents unchanged since signing', `${short} #1`);
    assert.equal(tierLabel('2'), 'verified Valid cryptographic signature', `${short} #2`);
    assert.equal(
      tierLabel('4'),
      short === 'd67b8e' ? 'verified Content matches its fingerprint' : 'normal Earlier-format content fingerprint',
      `${short} #4`,
    );
    assert.equal(tierLabel('7'), 'verified Timestamped', `${short} #7`);
    assert.equal(
      tierLabel('8'),
      short === 'da9246' ? 'absent' : 'verified Recorded in a public transparency log',
      `${short} #8`,
    );
    // Every row except #5 and #14 reads the same whatever the registry's provenance.
    const asDeclared = buildCheckRows(page.result, page.vinput, page.resolved.commitment, {
      ...page.meta,
      provenance: 'declared-url',
    });
    assert.deepEqual(
      page.rows.filter((r) => r.num !== '5' && r.num !== '14'),
      asDeclared.filter((r) => r.num !== '5' && r.num !== '14'),
      `${short}: only #5 and #14 depend on the registry's provenance`,
    );
  }
});

test('Q15 captured bundles offline: the page says the registry came from the bundle and was not checked against the publisher’s domain', async () => {
  for (const short of ['d67b8e', '255b8e'] as const) {
    const page = await capturedPage(short);
    assert.equal(page.resolved.registryProvenance, 'bundle', short);
    assert.equal(page.result.keyTrust?.status, 'active', `${short}: verify-core’s status is unchanged`);
    const kt = rowIn(page.rows, '5');
    assert.notEqual(kt.signal.label, KEY_TRUST_SIGNALS.active.label, short);
    assert.equal(kt.signal.tier, 'attention', short);
    assert.equal(
      kt.math.find((m) => m.label === 'Registry source')?.value,
      'carried in the bundle (can lower this signer’s key status, never raise it)',
      short,
    );
    assert.match(kt.depthNote ?? '', /snapshot carried in this bundle, as of 2026-06-07/, short);
    assert.match(kt.depthNote ?? '', /not checked against the publisher’s domain/, short);
    assert.equal(page.verdict.tier, 'attention', short);
    assert.equal(page.verdict.headline, 'Verified, with caveats', short);
    assert.match(page.verdict.detail, /not checked against the publisher’s domain/, short);
    // The re-check is offered: the view names an https: registry URL.
    assert.equal(canRecheckKeyTrust(page.meta, page.result), true, short);
  }
  // da9246 was signed with an embedded key the registry was never consulted for.
  const legacy = await capturedPage('da9246');
  const kt = rowIn(legacy.rows, '5');
  assert.equal(kt.signal.label, KEY_TRUST_SIGNALS.legacy_embedded.label);
  assert.equal(legacy.verdict.headline, 'Verified, with caveats');
  assert.equal(canRecheckKeyTrust(legacy.meta, legacy.result), false);
});

test('Q15 captured bundles online: the re-check fetches the declared https: registry, and a hosted run reads Verified', async () => {
  for (const short of ['d67b8e', '255b8e'] as const) {
    const page = await capturedPage(short);
    const bundle = JSON.parse(fixture(short)) as Record<string, unknown> & { trustRegistryUrl: string; trustRegistry: unknown };
    assert.equal(new URL(bundle.trustRegistryUrl).protocol, 'https:');
    const realFetch = globalThis.fetch;
    const requested: string[] = [];
    const serve = (routes: Record<string, unknown>) => {
      globalThis.fetch = ((input: unknown) => {
        const u = String(input);
        requested.push(u);
        return Promise.resolve(
          u in routes
            ? new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } })
            : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }),
        );
      }) as typeof globalThis.fetch;
    };
    try {
      // The live registry lists the key: confirmed, from the declared https: URL.
      serve({ [bundle.trustRegistryUrl]: bundle.trustRegistry });
      const live = await recheckKeyTrustLive(page.resolved.commitment, page.result, page.vinput);
      assert.deepEqual(requested, [bundle.trustRegistryUrl], `${short}: the declared https: URL, nothing else`);
      assert.equal(live.status, 'active', short);
      assert.equal(live.verified, true, short);
      assert.equal(live.changed, false, short);

      // Verified by URL: the commitment without the inline registry, the registry
      // fetched from its declared https: URL, the curated directory loaded.
      const hosted = { ...bundle };
      delete hosted['trustRegistry'];
      const hostedUrl = `${new URL(bundle.trustRegistryUrl).origin}/api/records/q15-hosted/commitment`;
      serve({
        [hostedUrl]: hosted,
        [bundle.trustRegistryUrl]: bundle.trustRegistry,
        [HOST_DIRECTORY_PATH]: HOST_DIRECTORY,
      });
      const resolved = await resolveInput('url', hostedUrl);
      const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, { offline: resolved.fullyOffline });
      const result = await runVerify(vinput, resolved.registry, resolveCarriedLifecycle(resolved.commitment), resolved.registryProvenance);
      assert.equal(resolved.registryProvenance, 'declared-url', short);
      const rows = buildCheckRows(result, vinput, resolved.commitment, registryMetaOf(resolved));
      assert.equal(rowIn(rows, '5').signal.label, KEY_TRUST_SIGNALS.active.label, short);
      assert.equal(rollupVerdict(result, registryMetaOf(resolved)).headline, 'Verified', short);
      const rec = resolveHostRecognition(resolved.commitment, result.keyTrust, resolved.directory, resolved.registryProvenance);
      assert.equal(rec.status, 'known_publisher', short);
    } finally {
      globalThis.fetch = realFetch;
    }
  }
});
