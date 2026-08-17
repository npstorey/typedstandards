# Changelog — @typedstandards/verify-core

Factual record of what changed per published version. Check numbers (#1–#15)
refer to the Typed Standards specification §9.2 verification sequence. Issue
references are to `npstorey/civic-ai-tools-website` (#119 is the offline-crypto
hardening arc; #116 is the standalone-verifier arc this package was extracted
in).

## 0.8.1 — 2026-08-17

- Removed the `prepare` (install-time build) script (typedstandards#39).
  A fresh `npm ci` at the monorepo root previously failed in workspace
  `prepare` ordering (produce-core's tsc ran before this package's dist
  existed), and npm 10.x runs workspace `prepare` even under
  `--ignore-scripts`. Builds are now explicit (`npm run build:verify-core`,
  then `npm run build`; CI does the same). Published tarballs are unchanged —
  `prepublishOnly` still builds at publish — but installing this package from
  git no longer auto-builds `dist`.
- Docs only, no behavior change: removed reference-deployment framing from
  published JSDoc/README (typedstandards#44 P3, findings B10/B11). Four
  sites — `verifyBlobRef`'s JSDoc, the exported `FetchLike` type's JSDoc, the
  README's Fetch note, and `trust-registry.ts` — no longer treat
  civicaitools.org as the rule's rationale or "the platform" as the sole
  publisher. The plain-GET/no-custom-headers requirement now derives from
  CORS behavior itself (a custom header triggers a preflight, rejectable at
  a redirecting host), with the reference redirect kept as a named example;
  `trust-registry.ts`'s header states its actual contract (pure, registry
  passed in, loading is the caller's job) instead of pointing at an unshipped
  server file; each publisher is understood to have its own registry, named
  by `trustRegistryUrl`. No exported type, signature, or runtime behavior
  changed — most consumer-visible via `FetchLike`'s JSDoc in the published
  `.d.ts`.
- Docs correction, no behavior change: scopes the plain-GET/CORS claim above
  by execution environment (typedstandards#44 P4). The unscoped version was
  disproved during a live browser session: a cross-origin redirect response
  must itself carry CORS headers, or a browser's fetch fails regardless of
  how simple the triggering request was — a plain GET only avoids the
  *preflight* rejection, it does not make a redirect chain transparent in a
  browser. The claim had been verified only from Node/curl, where that
  constraint does not exist, then stated unconditionally. Now scoped: a
  plain GET avoids the preflight failure mode (kept, unchanged); a browser
  additionally needs the redirect response itself to carry CORS headers
  (the missing half, now stated); server-side/Node fetches follow redirects
  without that constraint (why the unscoped claim read true when written).
  Same three verify-core sites P3 touched for this class — `verifyBlobRef`'s
  JSDoc (`blob-ref.ts`), the exported `FetchLike` type's JSDoc (`types.ts`),
  and the README's Fetch note — plus the equivalent explanation and its
  cross-reference in typedstandards.org's client-side verify flow
  (`apps/web`, outside this published package). No exported type, signature,
  or runtime behavior changed — consumer-visible via `FetchLike`'s JSDoc in
  the published `.d.ts` and the README.

## 0.8.0 — 2026-08-01

- New export: `ED25519_SPKI_PREFIX` (`signature.ts`) — the fixed 12-byte
  Ed25519 SPKI DER prefix this module asserts in `extractRawPublicKey`.
  Previously duplicated locally by `@typedstandards/produce-core`'s
  `derivePublicKeySpki`, which now imports it (typedstandards#36). No behavior
  change; the bytes are identical.

## 0.7.0 — 2026-06-16

- #1 envelope integrity is now TRI-STATE. `VerifyResult` gains an
  `envelopeIntegrity: { status: 'verified' | 'altered' | 'unavailable'; reason? }`
  field. A null `package` (content not fetched) previously surfaced only as
  `hashMatch: false`, which a consumer could not distinguish from real tampering;
  it now resolves to `status: 'unavailable'`, distinct from the `altered`
  (bytes-present, hash-mismatch) case. `VerifyInput` gains an optional
  `contentUnavailableReason: 'private' | 'unfetchable'` so the caller can say WHY
  the content is absent — `private` (the commitment redacted the location for a
  sealed/committed record, integrity N/A) vs. `unfetchable` (a present location
  whose bytes could not be retrieved). Fixes the verifier false-alarming
  "Contents changed since signing" on a perfectly valid content-private package
  (npstorey/typedstandards#21). Additive and back-compatible: `hashMatch` is
  unchanged (still `false` in both the `altered` and `unavailable` cases), so
  existing consumers reading only `hashMatch` are unaffected.

## 0.6.1 — 2026-06-10

- Documentation only; no code changes. Corrects the README's stale "Check
  depth (v1)" section — checks #7/#8/#10 have run at full cryptographic depth
  since 0.2.0–0.6.0, not presence/hash-parity/state depth as previously
  described. Adds this changelog.

## 0.6.0 — 2026-06-07

- #7 hardening: strict RFC 5280 certificate-chain validation (#119 P4).
- Shared `parseInclusionProof` guard for #8 consumers (#119 P4).

## 0.5.0 — 2026-06-07

- #10 at full depth: independent verification of the signed lifecycle
  attestation chain, including reachability from the package node, replacing
  host-reported state (#119 P3).

## 0.4.0 — 2026-06-07

- #7 deepened: TSA certificate-chain verification to a pinned FreeTSA root;
  token `genTime` surfaced to check #5 (#119 P2b).

## 0.3.1 — 2026-06-07

- Fix: accept high-S ECDSA signatures (`lowS: false`) from third-party
  signers.

## 0.3.0 — 2026-06-07

- #7 at cryptographic depth: RFC 3161 token parsing, message-imprint match,
  and TSA signature verification, FreeTSA profile (#119 P2a).

## 0.2.0 — 2026-06-06

- #8 at cryptographic depth: Rekor Merkle inclusion-proof verification from
  the carried proof, against Rekor's pinned public key; carried-offline
  integration test (#119 P1).

## 0.1.0 — 2026-06-05

- Initial release (#116 WS2/WS3): the spec §9.2 check suite, browser-safe (no
  Node built-ins). #7 at presence depth, #8 at hash-parity depth, #10 at state
  depth; all other checks fully client-side.
