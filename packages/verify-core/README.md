# @typedstandards/verify-core

The portable, **browser-safe** verification core for [Typed Standards][ts] evidence
packages — the spec §9.2 check suite, factored so it runs **identically** on a
server (e.g. civicaitools.org's verify route) and in the browser (the
typedstandards.org client-side verifier). One implementation, so a tampered
package fails the same way wherever it is checked.

> Originally extracted from `civic-ai-tools-website` (#116 WS2) and published here
> (#116 WS3) so every consumer depends on **one versioned source** that cannot
> drift.

## Install

```sh
npm install @typedstandards/verify-core
```

## Browser-safety contract

This package depends on **no Node built-ins**. There is no `node:crypto` / `fs` /
`path` / `process` / `Buffer` anywhere in the source (an upstream ESLint
`no-restricted-imports` rule enforces it). It runs unchanged in a browser, on the
edge, and in Node.

- **Hashing** — [`@noble/hashes`][nh] (SHA-256/512). Digests are byte-identical to
  Node's `crypto.createHash`.
- **Signatures** — [`@noble/curves`][nc] Ed25519 / Ed25519ph, with algorithm
  dispatch (a signature verifies only under the scheme it was made with). Raw key
  bytes come from a fixed-prefix SPKI slice, not `crypto.createPublicKey`.
- **Canonicalization** — RFC 8785 JCS via [`canonicalize`][cz].
- **Network is injected** — every check that touches the network takes a
  `FetchLike` (defaulting to `globalThis.fetch`, read at call time). The server
  injects its `fetch`, the browser injects `window.fetch`, tests inject a stub.

> **Fetch note.** A `FetchLike` should issue **plain GETs with no custom request
> headers**. A custom header triggers a CORS preflight, and a preflight `OPTIONS`
> hitting civicaitools.org's site-wide 307 to its canonical host can be rejected.
> A simple GET follows the 307 transparently.

## Usage

```ts
import { verifyEvidence, type VerifyInput, type TrustRegistry } from '@typedstandards/verify-core';

const input: VerifyInput = {
  package: pkg,            // the parsed package JSON
  packageHash,            // the claimed envelope hash
  signature,              // { signature, publicKey, algorithm?, kid? }
  rfc3161Timestamp,       // optional
  rekorEntryId,           // optional
  lifecycle,              // optional sidecar lifecycle state
};

const result = await verifyEvidence(input, {
  registry,               // a TrustRegistry (fetched from the package's trustRegistryUrl)
  fetch: globalThis.fetch,
});
// result carries the per-check verdicts: hashMatch, signatureValid, keyTrust,
// contentHash, typeResolution, signerIdentity, lifecycle, ...
```

The barrel (`.`) also exports the individual check functions
(`recomputePackageHash`, `verifySignature`, `verifyKeyTrust`, `verifyContentHash`,
…), the canonicalization primitives (`computeEnvelopeHash`,
`computeContentHashSha256`), and every status vocabulary type — so a consumer can
drive the checks one-at-a-time and render the math as it resolves.

## Check depth (v1)

Fully client-side: #1 envelope hash, #2 signature, #3 canonicalization, #4 content
hash, #5 key trust, #6 kid consistency, #9 blob refs, #12 type, #13 nodeId, #14
signer identity, #15 captureMethod vocab. **Presence** only for #7 (RFC 3161).
**Hash-parity** only for #8 (Rekor). **State** depth for #10 (lifecycle).

The deeper offline crypto — TSA-chain verification, Rekor Merkle-inclusion,
independent lifecycle-chain verification, and the authoritative bundle-mode test —
is a fast-follow (#119), not in this release. The UI built on this should be
honest about what is presence vs. full-crypto.

## License

MIT © Nathan Storey

[ts]: https://typedstandards.org
[nh]: https://github.com/paulmillr/noble-hashes
[nc]: https://github.com/paulmillr/noble-curves
[cz]: https://github.com/erdtman/canonicalize
