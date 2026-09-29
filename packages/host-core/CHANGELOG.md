# Changelog — @typedstandards/host-core

Factual record of what changed per published version. Check numbers (#1–#16)
refer to the Typed Standards specification §9.2 verification sequence.

## 0.1.0 — 2026-09-29

The first version (typedstandards#125, HOST CORE P1): a static-host library and the
`typedstandards-host` bin over `@typedstandards/produce-core` `^0.8.0` and
`@typedstandards/verify-core` `^0.13.0`, with no third runtime dependency. Node ≥ 22.

- **`buildHost`** builds each bundle with produce-core's `buildCommitmentView` from
  what the CLI's `sign` and `withdraw` print, plus the registry copy when a registry
  is served and the package; no `lifecycle` summary (G0 D1, D2). It writes the key
  registry (one signer per registry in 0.1.0) and the index v1, `records.json`,
  whose statuses are verify-core's `verifyLifecycleChain` reading of the carried
  attestations (G0 D6, D12). Input is one host manifest, `host.json`; `visibility`
  is host-wide.
- **`checkServed`** compares a fresh build with the served directory byte for byte.
- **`verifyServed`** verifies every served record offline with verify-core's
  `verifyRecord`, with the global and the injected fetch blocked and counted. Its
  first line names no Node or core version.
- **`displayOf` and `parsePolicy`**: a JSON display policy matching on `signer`,
  `type`, `status` and named `extensions` keys; a status outside
  `LIFECYCLE_STATUSES` and an unmatched record are refused, and `superseded` is
  displayed only when a rule names it (G0 D5, D9).
- **`linksFor`**: verifier links and HTML and Markdown badge snippets in
  typedstandards.org's percent-encoded `?url=` form, with the builders copied from
  `apps/web/src/lib/badge-asset.ts` (G0 D14).
- **The bin**, `typedstandards-host`: `build`, `check`, `verify` and `links`. Its one
  Node entry, `node/main.ts`, is pinned in the purity guard's `NODE_ENTRIES`.
- Verified against a fixture captured from a public worked example: 52 of 52 served
  bundles and its registry rebuild byte for byte.
