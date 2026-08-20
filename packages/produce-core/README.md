# @typedstandards/produce-core

The portable, **I/O-free** producer core for [Typed Standards][ts] record
packages — envelope and attestation assembly (spec §8.1, §8.12), the Ed25519ph
signing mechanism (§8.3.1), pure external-proof codecs (RFC 3161
`TimeStampReq`, Rekor `hashedrekord`), the §8.8.1 commitment view, and generic
PROV-O helpers. Its verification counterpart is
[`@typedstandards/verify-core`][vc] — a load-bearing runtime dependency
(joined only by `@noble/curves`, the curve suite both packages use): producer
and verifier share a single canonicalization/hash implementation, so both
sides compute one envelope hash by construction.

> Extracted from the reference application's producer path (Q59, resolved via
> option (a)): an independent implementation can emit packages that verify
> under spec §9.2 without depending on the reference application. A
> byte-golden fixture suite in this package pins the extraction to the
> reference implementation's exact output.

## The format/domain line

This core knows the **format**: envelope shapes, key order, conditional-spread
byte discipline, the §8.2 dual-chain hashing rules, and the signing mechanism.
Everything **domain-shaped** — capture vocabulary, profile derivations, source
registries, provenance graph walking — is the caller's: derived values arrive
as explicit inputs (`dataSources`, `provenance`, `producerProfile`,
`extensions`, …) and the core assembles them under the reference byte rules.

The verify-core primitives a producer-side layer consumes (`sha256Hex`,
`isBlobRef`, the canonicalization-rule URIs, the Q32 captureMethod vocabulary
table) are re-exported here, so such a layer needs a single declared
dependency.

## Vocabulary (2026-08-19 settlement)

The artifact this core builds is a **record package**. "Evidence" is retired
from the artifact/infrastructure brand role — a signed record shows *how* an
answer was produced, not that it is correct — and retained only for the
epistemic Question/Evidence/Claim role (spec §6.3, Appendix J).

Nothing existing breaks:

| Prior-era name | Canonical name | Status |
|---|---|---|
| `EvidencePackage` (type) | `RecordPackage` | `EvidencePackage` remains a **deprecated type alias** of `RecordPackage` — interchangeable in every position; removed no earlier than the next MAJOR. |
| `verifyEvidence` (verify-core) | `verifyRecord` | Still exported as a deprecated alias of the same function object. |

`buildCommitmentView` emits the §8.8.1 version field under its settlement-era
key, `protocolVersion`. Views published before a producer adopted this version
carry the same value under `evidenceProtocolVersion`, and that key stays valid
**forever** — it is frozen inside already-signed artifacts, where rewriting it
would invalidate the signature. Conformant verifiers accept either key, so a
mixed corpus verifies uniformly.

## Install

```sh
npm install @typedstandards/produce-core
```

## I/O-free contract

This package depends on **no Node built-ins** and performs **no I/O**: no
network, no filesystem, no environment reads, no clock, no RNG (an ESLint
`no-restricted-imports` rule plus a browser-safety/determinism test enforce
it). It runs unchanged in a browser, on the edge, and in Node.

- **Determinism inputs are caller-supplied** — `packageId`, `createdAt`, and
  `signingKeyId` are arguments, which is what makes byte-golden testing (and
  reproducible pipelines) possible.
- **Key custody is the caller's** — `signEnvelopeHash` takes the private key
  (raw 32-byte seed or PKCS8 DER) and the `kid` as arguments. There is no
  environment probe and no default identity.
- **Not signing is first-class** — `buildEnvelope` returns a complete package
  plus its envelope hash with no signature; nothing in this package labels an
  unsigned result `sealed`/`public` or anything else.
- **Submission stays caller-side** — the RFC 3161 / Rekor codecs build request
  bytes and parse responses; POSTing them to a TSA or transparency log is the
  caller's I/O.

## Independent-producer walkthrough

A prospective adopter can emit a conformant, verifiable package with the two
published packages alone — no reference-application imports. The sequence
below builds a package, signs it with a locally held key, carries the proofs
in a §8.8.1 commitment view, and passes verify-core's §9.2 checks offline.

```js
import crypto from 'node:crypto'; // the CALLER's key custody, outside the core
import {
  buildEnvelope,
  signEnvelopeHash,
  buildCommitmentView,
} from '@typedstandards/produce-core';
import { verifyRecord } from '@typedstandards/verify-core';

// 1. The adopter's key and identity (custody is yours; the core never reads
//    an environment or embeds a default).
const seed = crypto.randomBytes(32); // Ed25519 seed
const kid = 'adopter:key-2026-07';
const signer = {
  bindingTier: 'organization',
  identifier: 'adopter:example-publisher',
  displayName: 'Example Publisher',
};

// 2. Assemble the envelope from your pipeline's data. Derived values
//    (dataSources, provenance, extensions, …) are yours to compute; the core
//    assembles them under the reference byte rules and hashes the result.
const { pkg, envelopeHash } = buildEnvelope({
  packageId: crypto.randomUUID(),
  createdAt: new Date().toISOString(),
  signingKeyId: kid,
  prompt: 'How many service requests were filed last year?',
  promptVisibility: 'full_text',
  queries: [
    {
      tool: 'get_data',
      operationType: 'query',
      arguments: { select: 'count(*)', dataset_id: 'abcd-1234' },
      datasetId: 'abcd-1234',
      portal: 'data.example.gov',
    },
  ],
  dataSources: [
    {
      sourceId: 'open-data-portal',
      catalogType: 'catalog',
      portalUrl: 'https://data.example.gov',
      datasetId: 'abcd-1234',
      accessTimestamp: new Date().toISOString(),
    },
  ],
  cost: { promptTokens: 100, completionTokens: 20, totalTokens: 120, model: 'example/model-1' },
  skillMetadata: {},
  output: 'Around 400,000.',
  trace: { resourceSpans: [] },
  captureMethod: 'chat-flow-stream',
  producerProfile: 'ai-assisted-analysis/example-adopter',
  type: 'content/analysis/v1',
  signer,
});

// 3. Sign — or don't. Skipping this step leaves a complete unsigned package.
const signed = signEnvelopeHash(envelopeHash, seed, kid);

// 4. Publish your trust registry (an HTTPS JSON document you host) and carry
//    the proofs in the commitment view.
const registry = {
  keys: [
    {
      kid,
      publicKey: signed.publicKey,
      status: 'active',
      activatedAt: new Date().toISOString(),
      deprecatedAt: null,
      revokedAt: null,
      signerIdentity: signer,
    },
  ],
};
const sidecar = buildCommitmentView({
  packageHash: envelopeHash,
  signature: { ...signed },
  // Required, and never defaulted: the view is what a verifier resolves, so
  // the core will not assert a disclosure state you did not supply.
  visibility: 'public',
  captureMethod: 'chat-flow-stream',
  producerProfile: pkg.producerProfile,
  type: pkg.type,
  signer: pkg.signer,
  contentHash: pkg.contentHash,
  contentCanonicalization: pkg.contentCanonicalization,
  trustRegistryUrl: 'https://your-host.example/.well-known/typed-publisher.json',
});

// 5. Verify — any consumer runs the same §9.2 checks offline.
const result = await verifyRecord(
  { package: JSON.parse(JSON.stringify(pkg)), packageHash: sidecar.packageHash, signature: sidecar.signature },
  { registry },
);
console.log(result.hashMatch, result.signatureValid, result.keyTrust.status);
// -> true true active
```

Optional external proofs use the pure codecs the same way: POST
`buildTimestampRequest(envelopeHash)` to your TSA and store the token; POST
`JSON.stringify(buildRekorProposal(envelopeHash, signed.signature,
signed.publicKey))` to a transparency log and keep `parseRekorResponse`'s
fields in the commitment view so inclusion verifies offline.

## Non-goals

- **No key custody** — keys are arguments, never stored, generated, or probed.
- **No storage** — nothing is persisted; the caller owns rows, blobs, hosting.
- **No submission I/O** — no `fetch` anywhere; TSA/transparency-log submission
  is caller-side (the codecs are pure request/response builders/parsers).
- **No domain vocabulary** — profile labels, capture methods, and namespaces
  are opaque strings/values here; their vocabularies live in profiles (spec
  §8.6) and in the caller's domain layer.

## License

MIT © Nathan Storey

[ts]: https://typedstandards.org
[vc]: https://www.npmjs.com/package/@typedstandards/verify-core
