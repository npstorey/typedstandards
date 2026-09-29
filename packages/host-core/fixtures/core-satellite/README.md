# The core-satellite oracle fixture

Captured from the public worked example `npstorey/typedstandards-core-satellite-example`
at `b40c30f`, from its served `docs/` only, by [`capture.mjs`](capture.mjs):

```sh
git -C <example checkout> archive b40c30f docs | tar -x -C <tmp>
node packages/host-core/fixtures/core-satellite/capture.mjs <tmp>/docs packages/host-core/fixtures/core-satellite
```

Nothing in the capture runs host-core. Per file:

| Path | Provenance |
|---|---|
| `input/host.json` | Written by the capture. `origin` is `docs/records.json`'s `host` without its final `/`; `visibility` is `public`, as every served view states; `registry.$comment` is copied from `docs/.well-known/typed-publisher.json`, and `index.$comment` from `docs/records.json`. Each record's `title` is its served bundle's `subjectTitle`, and its `extensions` are `file`, `role`, `edgeId` and `step` from `docs/records.json`. Records follow `docs/records.json`'s order. |
| `input/signed/<name>.signed.json` (52) | `{package, envelopeHash, signature}`, the shape the CLI's `sign` prints: the served bundle's `package` and `signature`, and its `packageHash` as `envelopeHash`. |
| `input/withdrawals/<name>.withdrawal.json` (15) | `{node, nodeId, signature}`, the shape the CLI's `withdraw` prints: each served bundle's carried `lifecycleAttestations` entry, verbatim. |
| `expected/bundles/<name>.bundle.json` (52) | `docs/bundles/<name>.bundle.json`, byte for byte. |
| `expected/.well-known/typed-publisher.json` | `docs/.well-known/typed-publisher.json`, byte for byte. |
| `expected/records.json` | The index v1 the build must write: `docs/records.json` reshaped by the capture, with `version: 1` first, the example-only `file`, `role`, `edgeId` and `step` moved under `extensions`, and every other field unchanged. |
| `example-records.json` | `docs/records.json`, byte for byte, for the record-by-record comparison of every field outside `extensions`. |
| `verify-output.txt` | What `typedstandards-host verify --out expected` must print, written from `expected/records.json`'s names and statuses in the specified format before `verify` was implemented. It names no Node or core version. |
