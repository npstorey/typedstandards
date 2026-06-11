# Changelog — @typedstandards/verify-core

Factual record of what changed per published version. Check numbers (#1–#15)
refer to the Typed Standards specification §9.2 verification sequence. Issue
references are to `npstorey/civic-ai-tools-website` (#119 is the offline-crypto
hardening arc; #116 is the standalone-verifier arc this package was extracted
in).

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
