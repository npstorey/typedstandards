# Layout fixtures

Provenance of the `content/layout/v1` fixtures (hub ADR-0034, spec v0.1.12
§8.14) and of the publication attestation fixtures beside them. The other files
in this directory carry their provenance in their own `_meta` blocks or tests.

Every `*.node.json` file is one node serialized as
`JSON.stringify(node, null, 2) + '\n'` (UTF-8, two-space indent, one trailing
newline). The tests compare the file's text with the builder's output serialized
the same way, so the assertion is on bytes, not on a parsed object.

## `layout-s8141-payload.json`

The example payload of spec §8.14.1, copied without change from lines 1493-1505
of `docs/architecture/typed-standards-specification.md` at hub commit
`35d94f38381224ce83b1ff3dfc426c7deeb18f6e` (the lines between the json fence and
its closing fence), with one trailing newline. SHA-256 of the file:
`fd5f37945cd5d1af0736aa72fcc2799e972aa619e1891530f60fd7b236e22745`.

## `layout-golden-inputs.json`

The fixed determinism inputs (`packageId`, `createdAt`, `signingKeyId`) and
signer for the layout node (`layout`), and the full `buildAttestationNode` input
for the publication attestation (`publishes`), without `layoutNodeId`. The ids
are in the hex-letter range and no value holds a run of 13 or more decimal
digits. No key material.

## `layout-golden.node.json`

`buildLayoutNode({ ...inputs.layout, ...payload })`, where `inputs` is
`layout-golden-inputs.json` and `payload` is `layout-s8141-payload.json` parsed.
Built by this package's `src/layout.ts` at the commit that adds it; no earlier
implementation of the sub-type exists. Its `nodeId` is
`66e55ff06b7cd66b85ab38c6297a71e0e0d04301432c0141155529a21b368ef4`.
`layout.test.ts` asserts the builder emits these bytes, that the payload inside
the node deep-equals the §8.14.1 block, and that `contentHash` is legacy-json/v1
over the node minus `contentHash`; `produce-verify-roundtrip.test.ts` signs it
with a key made in the test and verifies it offline.

## `publishes-layout-golden.node.json`

`buildAttestationNode({ ...inputs.publishes, layoutNodeId })`, where
`layoutNodeId` is the nodeId of `layout-golden.node.json`. Built by this
package's `src/attestation.ts` at the same commit. Its `nodeId` is
`92a294d2f5df0619c42f2a145a33dccea09ba8dd31675b7bd907c8e85625bb4d`.
`attestation.test.ts` asserts the builder emits these bytes, that `layoutNodeId`
sits directly after `releasedAt` and before `contentHash`, and that deleting it
and recomputing `contentHash` gives the bytes of
`publishes-0.8.0-reference.node.json`.

## `publishes-0.8.0-reference.node.json`

The node the published `@typedstandards/produce-core@0.8.0` builds from the
`publishes` inputs: `buildAttestationNode(inputs.publishes).node`, run from that
version's `dist/` installed from the npm registry into a directory outside this
repository with `npm install --ignore-scripts`. Tarball
`https://registry.npmjs.org/@typedstandards/produce-core/-/produce-core-0.8.0.tgz`,
`dist.integrity`
`sha512-5d5xYi3XdfHEFERJ4K7/gtPUwpxhIzzEQqZI9/dYrlBZJQqFgarARVRXUbbHXaPO+1PQ3gFY/1nHjBEw6sD5Gg==`;
its dependency `@typedstandards/verify-core@0.13.0` came from the registry too
(`sha512-//bMjEiJH0+zSJg6LT3nEjQnFelbpOHPuD6T1ITygLeuS6QMFU1DChB+hFW8QLzxL02UhiUFwoCiLoOVcE2Aew==`).
Its `nodeId` is
`32568b2b8af86cf7472bb4b86c32da8191be87a40848a4e4e75815869684e283`.
`attestation.test.ts` asserts that this branch's builder, given the same inputs,
emits these bytes.
