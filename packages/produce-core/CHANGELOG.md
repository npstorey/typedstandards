# Changelog — @typedstandards/produce-core

Factual record of what changed per published version. Check numbers (#1–#15)
refer to the Typed Standards specification §9.2 verification sequence.

## Unreleased

Vocabulary settlement (spec v0.1.5 Appendix J; registry Q50/Q66, ADR-0025,
anchored at `civic-ai-tools#160`). "Evidence" is retired from the artifact and
infrastructure brand role and retained only for the epistemic
Question/Evidence/Claim role. **A minor bump** — a new export plus one wire-key
change on newly built views; nothing already published is affected.

- **`RecordPackage` is the canonical envelope type.** `EvidencePackage` remains
  exported as a **deprecated type alias** of it — a pure alias, so the two names
  are interchangeable in every position and no consumer typed against the old
  name has to change. Removed no earlier than the next MAJOR version. Migration
  class `alias-and-deprecate` (Appendix J). A compile-time assertion in
  `envelope.ts` fails `tsc` if the two names ever stop being the same type.
- **`buildCommitmentView` emits `protocolVersion`** instead of
  `evidenceProtocolVersion` (spec §8.8.1). **Wire change on NEW emissions
  only.** The key is `frozen-in-signed-artifacts`: every already-published view
  keeps `evidenceProtocolVersion` forever — rewriting it would change the
  envelope hash and invalidate the signature — and conformant verifiers MUST
  accept both keys for both eras (Appendix J §J.4 rules 1–2), so a corpus mixing
  the two verifies uniformly. New emissions carry the new key **alone**, not
  both: emitting both would place a redundant second assertion inside every
  freshly signed artifact and give the prior-era key an indefinite life on the
  producing side. Value unchanged (`0.1.0`); field position in the view
  unchanged (still first); no other key moved. A consumer that reads the field
  by its literal old name from a view built by THIS version will not find it —
  the fix is to accept either key, which the spec already requires. Reaches
  production only when a publisher adopts this minor.
- Package `description` and one `keywords` entry now say "record packages"
  rather than "evidence packages"; the README gains a vocabulary section with
  the old→new table and imports `verifyRecord` in its walkthrough.
- New regression guard in `commitment.test.ts`: a built view must carry
  `protocolVersion` and must NOT carry `evidenceProtocolVersion`.
- No change to envelope assembly, hashing, canonicalization, signing, or the
  external-proof codecs. Every byte-golden fixture passes unchanged.

## 0.2.1 — 2026-08-12

- **`buildCommitmentView` no longer defaults `visibility`; an absent value is
  now an error.** **Behavior change:** a caller that omitted the field
  previously got `visibility: 'published'` in the returned view and now gets a
  thrown `Error`. This is a defect fix, not a removed feature: the commitment
  view is the artifact a third party resolves while verifying (spec §9.2.1),
  the spec marks `visibility` required and defines no default (§8.8.1), and
  the old default both asserted a disclosure state nobody supplied and failed
  *open* — a producer who meant `sealed` and omitted the field emitted a view
  telling every reader the content was publicly disclosed. Absent is now
  refused at the call, matching the `trustRegistryUrl` guard beside it; the
  field stays optional in the TypeScript type, so this is a runtime change
  only and a future minor makes it required in the type as well. The
  vocabulary of record is `sealed` / `public`; the pre-ADR-0016 spellings
  `committed` / `published` remain accepted inputs, carried verbatim — the
  core still normalizes nothing. `contentProfile`'s `'default'` is unaffected
  and deliberately kept: §8.8.1 defines that value for a package carrying no
  profile, so it states an honest not-applicable rather than a fact about the
  record. The rule is civic-ai-tools ADR-0024.
- Removed the `prepare` (install-time build) script (typedstandards#39).
  A fresh `npm ci` at the monorepo root previously failed here: npm runs
  workspace `prepare` scripts in location order, so this package's tsc ran
  before `@typedstandards/verify-core`'s dist existed — and npm 10.x runs
  workspace `prepare` even under `--ignore-scripts`. Builds are now explicit
  (`npm run build:verify-core`, then `npm run build`; CI does the same).
  Published tarballs are unchanged — `prepublishOnly` still builds at
  publish — but installing this package from git no longer auto-builds
  `dist`.

## 0.2.0 — 2026-08-01

- **Re-exports from `@typedstandards/verify-core`** so a producer-side
  consumer needs a single import and a single declared dependency:
  `sha256Hex`, `isBlobRef`, `DATHERE_AG_JUPYTER_CANONICALIZATION`,
  `PROFILE_CAPTURE_VOCAB` (the Q32 captureMethod vocabulary table), and the
  `CaptureMethod` type. Flagged in civic-ai-tools#116 P1: the S2 harness
  consumed these from verify-core transitively, undeclared. Joins the
  existing `LEGACY_JSON_CANONICALIZATION` / `computeEnvelopeHash` /
  `computeContentHashSha256` re-exports; no behavior change.
- **`ED25519_SPKI_PREFIX` de-duplicated** (typedstandards#36) — `signing.ts`
  now imports the constant verify-core 0.8.0 exports instead of declaring a
  byte-identical local copy; `@typedstandards/verify-core` dependency range
  bumped to `^0.8.0` accordingly. No behavior change.

## 0.1.0 — 2026-07-31

- **Declared `@noble/curves` as a direct dependency** (`^2.2.0`, aligned with
  verify-core's range) — `signing.ts` imports it directly, so it must not be
  a phantom dependency reached through verify-core; strict-layout consumers
  (pnpm, Yarn PnP) would otherwise fail to resolve it.

Initial release: the format-neutral, I/O-free producer core, extracted from
the reference application's producer path (Q59 resolved via option (a); the
format/domain line is recorded in civic-ai-tools ADR-0021).

- **Envelope assembly** (`buildEnvelope`) — spec §8.1/§8.2 `content/*`
  packages on both chains (legacy `JSON.stringify` and v0.1 RFC 8785 JCS),
  with the reference implementation's conditional-spread byte discipline and
  caller-supplied determinism inputs (`packageId`, `createdAt`,
  `signingKeyId`). Unsigned results are first-class (ADR-0020): a complete
  package + envelope hash, no signature, no status label.
- **Attestation assembly** (`buildAttestationNode`) — spec §8.12
  `attestation/*` envelopes (withdraws / reinstates / publishes / locatedAt /
  evaluates) with nodeId = JCS envelope hash.
- **Signing mechanism** (`signEnvelopeHash`, `derivePublicKeySpki`) —
  Ed25519ph over the UTF-8 envelope-hash hex string (§8.3.1), key and kid
  caller-supplied; key handling re-implemented off `node:crypto` (raw seed or
  PKCS8 DER via a strict ASN.1 read, `@noble/curves` public-key derivation).
- **Pure external-proof codecs** — RFC 3161 `TimeStampReq` DER builder, Rekor
  `hashedrekord` v0.0.1 proposal body + response parser. No `fetch` anywhere;
  submission stays caller-side.
- **Commitment view** (`buildCommitmentView`) — the §8.8.1 proof sidecar from
  caller-supplied fields; `trustRegistryUrl` is required configuration, never
  a constant.
- **Generic PROV-O helpers** — §8.9 graph/context/node/edge builders; domain
  namespaces and graph walking stay caller-side.
- **Proof harness** — a byte-golden fixture suite captured from the reference
  implementation (each fixture attributed to its source test; byte-identical
  serialized JSON, content hashes, envelope hashes for equivalent inputs); an
  offline produce→verify round-trip asserting §9.2 checks #1–#6 and #11–#15
  against `@typedstandards/verify-core`; codec round-trips against
  verify-core's RFC 3161 / Rekor parsers (including a real TSA token).
- **Discipline** — browser-safe, `sideEffects: false`, no Node built-ins, no
  environment reads, no clock, no RNG (ESLint rule + browser-safety and
  determinism guard tests). Runtime dependency: `@typedstandards/verify-core`
  only.
