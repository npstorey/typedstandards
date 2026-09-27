# Changelog — @typedstandards/cli

Factual record of what changed per published version. Check numbers (#1–#16)
refer to the Typed Standards specification §9.2 verification sequence.

## 0.2.0 — 2026-09-27

The core-minors release (typedstandards#113, shipped in #114, #115, #116, #117 and #118). **A minor
bump** — `attest`, `view --attestation`, `vcsRef` and raw-bytes/v1 by reference, over
`@typedstandards/produce-core` `^0.8.0` and `@typedstandards/verify-core` `^0.13.0`. One behaviour
change from 0.1.0, the rule a file signed by reference defaults to, is recorded below.

- **A lifecycle attestation moves status only when its signing key is bound to the signer it names
  (typedstandards#113).**
  - `withdraw`: a `did:key` signer identifier must be derived from the seed, as check #14 requires of
    `sign`; a `did:key` naming another key fails verify-before-print, exit 1 with nothing on stdout.
    Any other identifier prints; a verifier binds it only through the target record's own signing key
    or a trust registry fetched from its declared URL.
  - `view` and `verify` resolve carried lifecycle attestations with the record's own signing key, as
    verify-core's `verifyLifecycleChain` now binds them: a node whose key is not bound stays in the
    chain and does not move the record's status.
- **`view` carries a `superseded` status (typedstandards#113, G0 D2)** into the view's `lifecycle`,
  with `supersededAt` and `successorNodeId`, when a carried `supersedes` signer-matches the record.
- **`verify` reads each carried lifecycle node's signer (typedstandards#113, G0 D6 as corrected).** For
  a `withdraws`, `reinstates`, `supersedes` or `revises` node that is intact and validly signed:
  `authorized` (verified); `other_signer`, a third party's event (normal); or
  `publisher_key_unbound`, an event naming the record's signer under a key not bound to it
  (attention, printed on stderr, exit 0). The tiers are copied from typedstandards.org's
  `ATTESTATION_AUTHORIZATION_SIGNALS`.
- **A carried lifecycle node that lacks a required payload field moves no status (typedstandards#113,
  spec §8.12.3).** `view` and `verify` resolve the chain with verify-core's `verifyLifecycleChain`, so a
  `withdraws` with no `reason`, a `reinstates` with no `priorWithdrawalNodeId`, or a `supersedes` or
  `revises` with no `successorNodeId` stays in the chain and does not move the record's status. Each
  such field gets a reading naming it. On a node that names the record's signer it reads `attention`,
  and `verify` (and `view`) prints it on stderr, for example
  `#10 lifecycleAttestations[0].reason: missing_required_field (attention)`, and exits 0. On a third
  party's node it reads `normal`, as any third-party event does, and nothing is printed (the owner's
  correction at the P5-fix gate, per G0 D6 as corrected). The tiers are copied from
  typedstandards.org's `LIFECYCLE_ATTESTATION_MISSING_FIELD_SIGNALS`. Each lifecycle view in
  `verify --json`'s `lifecycle.chain` gains `missingFields`.
- **`attest --input <file|->` (typedstandards#113, G0 D10 as corrected)** signs an
  `attestation/supersedes/v1`, `revises/v1`, `corroborates/v1` or `contradicts/v1` from one JSON
  object: `type`, `targetNodeId`, `signer` and the type's §8.12.1 payload (`successorNodeId`; or
  `scope` and an optional `reasoning`, a string or an object). Each type takes only its own fields,
  and any other key exits 2 naming it; `withdraws` stays `withdraw`'s, and `endorses` is refused
  (G0 D1). It fills `packageId`, `createdAt`, `signingKeyId` and `signer.identifier` as `withdraw`
  does, and verifies the node with verify-core's `checkAttestationNode` before printing
  `{node, nodeId, signature}`: integrity and the signature must hold, and a `did:key` identifier the
  seed does not derive exits 1 with nothing on stdout. A reading other than `authorized` prints on
  stderr at its tier and exits 0.
- **`view --attestation <file>...`** carries any lifecycle node (`withdraws`, `reinstates`,
  `supersedes`, `revises`) into `lifecycleAttestations`. `--withdrawal` stays as an alias, and both
  may be given together. A `corroborates` or `contradicts` node given to either exits 2 (G0 D6).
- **`sign` signs `vcsRef` (G0 D7)** on an input with a `type`: `repoUrl` and `commitSha` required,
  non-empty strings; `path` and `ref` optional strings; any other key exits 2 naming it. A `vcsRef`
  on an input with no `type` exits 2. This replaces 0.1.0's refusal of `vcsRef` by name.
- **`sign --output-file --output-url` under `raw-bytes/v1` (G0 D8).** A file signed by reference on
  an input with a `type` may name `raw-bytes/v1`, which 0.1.0 refused; `contentHash.sha256` is then
  the hex of the BlobRef's `ref`, the file's SHA-256. An input naming another rule keeps it.
- **Behaviour change from 0.1.0: the rule a file signed by reference defaults to.** In 0.1.0, a
  typed input signed with `--output-file --output-url` and no `contentCanonicalization` was signed
  under `legacy-json/v1`, produce-core's default. In 0.2.0 it defaults to `raw-bytes/v1`, as a file
  signed inline does, so the same input and file produce a different envelope and envelope hash.
  An input with no `type` is unchanged: it is signed on the legacy chain, which carries no rule.

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
