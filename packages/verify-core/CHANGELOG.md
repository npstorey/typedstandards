# Changelog — @typedstandards/verify-core

Factual record of what changed per published version. Check numbers (#1–#16)
refer to the Typed Standards specification §9.2 verification sequence. Issue
references are to `npstorey/civic-ai-tools-website` (#119 is the offline-crypto
hardening arc; #116 is the standalone-verifier arc this package was extracted
in).

## Unreleased

Not yet released; no version is assigned. **A minor-bump item** — new exports, and `VerifyResult`
gains a field, so a consumer that builds a `VerifyResult` literal (a test double, say) needs it.

- **Check #6, `metadata.signingKeyId` consistency (`checkSigningKeyIdConsistency`,
  `SIGNING_KEY_ID_CONSISTENCY_STATUSES`; typedstandards#88).** Specification §9.2 check #6 was
  implemented nowhere. It compares the signature envelope's `kid` with the package's
  `metadata.signingKeyId` and reports one of:
  - `ok` — both present and equal;
  - `signingKeyId_mismatch` — both present and different; the one failing status (§8.3.1: the field
    MUST equal the envelope `kid`). The result carries `kid` and `signingKeyId`;
  - `kid_absent` — the envelope carries no `kid`; legitimate under a key-derived identifier, and on
    legacy packages, which carry neither field;
  - `signingKeyId_absent` — a `kid` that the signed bytes do not name, so the check cannot confirm
    it.

  `signer.identifier` is not compared: under a key-derived identifier the `kid` SHOULD be the
  identifier, which is not a condition of this check. `VerifyResult` gains `signingKeyIdConsistency`,
  null when there is no package, no signature envelope, or a malformed one. The captured and
  published packages measured for this change (the three captured commitment bundles, the
  self-certified interop fixture, the two ADR-0028 eval-run packages, and two published example
  bundles under a key-derived identifier) read `ok`, except the legacy capture, which carries neither
  field and reads `kid_absent`.
- **Check #12 registers `attestation/revises/v1` (typedstandards#96).** The ratified set is sixteen
  attestation sub-types plus `content/analysis/v1`; a node of that type read `unknown_type` and now
  reads `ok`.
- **One fetch per BlobRef URL per `verifyRecord` (typedstandards#90).** Under `raw-bytes/v1` with a
  BlobRef `output`, checks #9 and #4 each fetched the file. They now share one request per URL within a
  `verifyRecord` call, and report exactly what they reported before, including when the fetch fails and
  when the bytes do not match. No public signature changes, and no request is added.

## 0.10.0 — 2026-09-22

Specification v0.1.9 (hub ADR-0029 and ADR-0030, anchored at `typedstandards#77`): a Producer Profile
for deterministic tool output, a raw-bytes content rule, a content-profile check, and a self-certifying
signer. **A minor bump** — new exports, and every type-level union below gains members, so a consumer
with an exhaustive `switch` or `Record` over one of them needs the new cases.

- **The `scripted-recomputation` Producer Profile (ADR-0029).** `PROFILE_CAPTURE_VOCAB` gains
  `scripted-recomputation: ['script-run', 'tool-emitted']`, a second stand-in entry under hub Q32, and
  `CaptureMethod` gains both values. Check #15 now resolves a `scripted-recomputation/<subtype>`
  package's capture method instead of reporting `producerProfile_bundle_unresolved`. The two signed
  ADR-0028 eval-run packages read `ok`.
- **`raw-bytes/v1` (`RAW_BYTES_CANONICALIZATION`).** A third content-canonicalization rule, in
  `KNOWN_CANONICALIZATION_RULES`: `contentHash` fingerprints the exact bytes of `output`.
  - With inline `output`, check #4 hashes its UTF-8 bytes.
  - With a BlobRef `output`, check #4 hashes the file's bytes obtained through the injected fetcher
    (`verifyContentHashWithFetch`; `verifyRecord` runs it):
    - `content_hash_mismatch` when they differ, or when `contentHash.sha256` differs from the hex of
      `output.ref`;
    - the new status `content_bytes_unavailable` when the bytes cannot be obtained. It is never `ok`
      without hashing.
  - `verifyContentHash` stays synchronous and I/O-free, with an optional `outputBytes` argument.
- **Check #16, the content-profile label (`checkContentProfile`, `CONTENT_PROFILE_STATUSES`,
  `KNOWN_CONTENT_PROFILES`).** Reads `metadata.contentProfile` and reports one of:
  - `ok`;
  - `contentProfile_absent` (read as `"default"`);
  - `contentProfile_unknown`;
  - `contentProfile_inconsistent` (compared with `producerProfile` only when both are present).

  `VerifyResult` gains `contentProfile`.
- **The self-certifying signer (ADR-0030).**
  - **The identifier.** `deriveKeyDerivedIdentifier` derives `did:key:z…` from an Ed25519 SPKI
    `publicKey`. `isKeyDerivedIdentifier` and `KEY_DERIVED_IDENTIFIER_PREFIX` recognize one.
  - **Key trust.** `KEY_TRUST_STATUSES` gains `self_certified` (`verified: false`) for a
    `pseudonymous` signer whose identifier matches its signing key.
  - **Check #14.** It gains `key_derived_match` and `key_derived_mismatch` (fatal; the result carries
    `claimed` and `derived`), and never reports `ok` under a key-derived identifier.
    `checkSignerIdentity` takes an optional `publicKey`.
  - **Registry provenance.** `VerifyDeps.registryProvenance` (`TRUST_REGISTRY_PROVENANCES`:
    `'declared-url' | 'bundle'`; absent is treated as `'bundle'`) states where the caller's registry
    came from.
    - For a key-derived identifier, only a `'declared-url'` registry can raise the status.
    - A bundle-carried registry contributes only `revoked` and `deprecated_invalid`.
    - This holds at every tier, and under a mismatch too.
  - **Base-58.** The encoder is written in place; there is no new runtime dependency.
- **Signers whose identifier is not key-derived are unchanged.** Already-signed packages verify
  exactly as before, apart from checks #15 and #16, which now resolve a `scripted-recomputation`
  profile and report a content profile.

## 0.9.0 — 2026-08-19

Vocabulary settlement (spec v0.1.5 Appendix J; registry Q50/Q66, ADR-0025,
anchored at `civic-ai-tools#160`). "Evidence" is retired from the artifact and
infrastructure brand role and retained only for the epistemic
Question/Evidence/Claim role. **A minor bump** — a new export, no removals, no
behavior change.

- **`verifyRecord` is the canonical §9.2 entry point.** `verifyEvidence` remains
  exported as a **deprecated alias**, and it is the same function object
  (`verifyEvidence === verifyRecord`), not a wrapper — every existing caller
  keeps working unchanged and gets byte-identical results. The alias is removed
  no earlier than the next MAJOR version. Migration class `alias-and-deprecate`
  (Appendix J).
- Package `description` and one `keywords` entry now say "record packages"
  rather than "evidence packages"; the README's usage example imports
  `verifyRecord` and states the alias explicitly. Present-tense references to
  the entry point in published JSDoc (`VerifyInput`, `lifecycle.ts`) name
  `verifyRecord`; past-tense historical narration of what the function did at
  earlier versions is left as written, since it remains accurate.
- New regression guard in `package-exports.test.ts`: both names must resolve
  and must be the same function object, so the alias cannot silently become a
  second implementation or disappear.
- No wire, algorithm, check-depth, or result-shape change. Already-signed
  packages are byte-identical and verify exactly as before.

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
