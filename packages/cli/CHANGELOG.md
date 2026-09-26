# Changelog — @typedstandards/cli

Factual record of what changed per published version. Check numbers (#1–#16)
refer to the Typed Standards specification §9.2 verification sequence.

## Unreleased

- **A lifecycle attestation moves status only when its signing key is bound to the signer it names
  (typedstandards#113).**
  - `withdraw`: a `did:key` signer identifier must be derived from the seed, as check #14 requires of
    `sign`; a `did:key` naming another key fails verify-before-print, exit 1 with nothing on stdout.
    Any other identifier prints; a verifier binds it only through the target record's own signing key
    or a trust registry fetched from its declared URL.
  - `view` and `verify` resolve carried lifecycle attestations with the record's own signing key, as
    verify-core's `verifyLifecycleChain` now binds them: a node whose key is not bound stays in the
    chain and does not move the record's status.

## 0.1.0 — 2026-09-26

The first release (typedstandards#109): a command line over
`@typedstandards/produce-core` `^0.7.0` and `@typedstandards/verify-core` `^0.12.0`,
its only runtime dependencies.

- **`sign`** builds and signs a record from an envelope input (produce-core's
  `EnvelopeInput`, as JSON). The output is the input's own, a file inline under
  `raw-bytes/v1`, or a BlobRef to a file. It fills `packageId`, `createdAt`,
  `signingKeyId` and `signer.identifier` only when absent, refuses a key produce-core
  would drop, refuses `vcsRef` by name, and verifies its result offline before
  printing.
- **`withdraw`** signs an `attestation/withdraws/v1` on the same key path.
- **`view`** builds the commitment view a host serves, with the package inline, and
  omits `trustRegistryUrl` under a self-certifying `did:key` signer.
- **`verify`** runs verify-core's checks offline and exits 1 on the checks
  typedstandards.org's verifier reads as alarm; `--json` prints every check and the
  lifecycle resolution.
- The signing seed comes from `TYPEDSTANDARDS_SIGNING_SEED_B64` only. No command
  makes a network request or writes a file. Exit codes: 0 ok, 1 verification failed,
  2 usage or input, 3 seed missing or malformed, 4 internal.
- Replays every envelope case of produce-core's `reference-golden.json`, and its
  withdraws case, byte for byte through the built binary.
