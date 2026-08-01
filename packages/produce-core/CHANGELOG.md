# Changelog — @typedstandards/produce-core

Factual record of what changed per published version. Check numbers (#1–#15)
refer to the Typed Standards specification §9.2 verification sequence.

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
