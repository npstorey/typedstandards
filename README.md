# Typed Standards

The home of [Typed Standards][ts] — the standard for verifiable, signed evidence
packages, its reference verification core, and the typedstandards.org site.

**Where the specification text lives:** the Typed Standards Specification is
maintained in the hub repo at
[`civic-ai-tools/docs/architecture/typed-standards-specification.md`](https://github.com/npstorey/civic-ai-tools/blob/main/docs/architecture/typed-standards-specification.md)
(v0.1 Working Draft, CC BY 4.0). This repo holds the reference
*implementations* of it and the site that serves it.

This is an npm-workspaces monorepo.

> **Repo status (as of the current `main`).** This monorepo now contains both
> published packages — [`@typedstandards/verify-core`](packages/verify-core)
> and [`@typedstandards/produce-core`](packages/produce-core) — **and** the
> typedstandards.org site at [`apps/web`](apps/web), which serves the
> client-side `/verify` verifier, `/roadmap`, and the host directory at
> `/.well-known/typed-host-directory.json`. The "later phase" note below
> predates that and is retained pending a fuller README revision.

## The host directory

`/.well-known/typed-host-directory.json` is the public, CORS-open document the
verifier reads. It is served verbatim from one constant in
[`apps/web/src/lib/host-directory.ts`](apps/web/src/lib/host-directory.ts),
which is where the schema is specified in full.

```json
{
  "version": 1,
  "updated": "2026-06-16",
  "bareIdentifierHost": "https://civicaitools.org",
  "publishers": [
    {
      "registryOrigin": "https://civicaitools.org",
      "displayName": "Civic AI Tools",
      "profileUrl": "https://civicaitools.org"
    }
  ]
}
```

| field | meaning |
| --- | --- |
| `version` | Schema version of the document. |
| `updated` | ISO date the roster was last edited — editorial provenance, not a proof. |
| `bareIdentifierHost` | **Optional.** The origin a *bare identifier* — a package hash or slug, which carries no origin of its own — is resolved against. A declared editorial choice by whoever publishes the directory, not a property of any listed publisher. |
| `publishers[]` | The recognition roster: `registryOrigin` (the identity key — the origin of that publisher's trust registry), `displayName`, and an optional `profileUrl`. **Order carries no meaning.** |

Two properties the schema is meant to keep:

- **Additive.** A consumer that does not know a field ignores it, and the
  verifier's own parser drops fields it does not know rather than rejecting the
  document. `bareIdentifierHost` was added this way: a fork's roster or a copy
  cached before it existed still validates in full, just without a declared
  anchor, and consumers then fall back to their own.
- **Listing is not validation.** A roster entry grants only *recognition* —
  and only condition (a) of it; the "known publisher" badge additionally
  requires the signing key to be confirmed in that publisher's registry. An
  unlisted publisher's package verifies exactly the same, resolves through the
  same short links, and is expected rather than faulted.

### Verifier links

`/verify/<id>` resolves a bare identifier against `bareIdentifierHost`.
`/verify/<host>/<id>` resolves it against `https://<host>` instead, so every
publisher gets the same clean share link; the host segment is validated for
shape only, never for roster membership. Shapes a path segment cannot carry —
a non-https origin, an explicit port, an identifier containing `/` — use
`/verify?url=<encoded>`, which is also what the embeddable badge's `?url=`
form produces.

## Packages

| Package | Description |
| --- | --- |
| [`packages/verify-core`](packages/verify-core) | [`@typedstandards/verify-core`](https://www.npmjs.com/package/@typedstandards/verify-core) — the portable, browser-safe §9.2 verification core. Published to npm so every consumer (civicaitools.org server, typedstandards.org browser client) depends on one versioned source that cannot drift. |
| [`packages/produce-core`](packages/produce-core) | [`@typedstandards/produce-core`](https://www.npmjs.com/package/@typedstandards/produce-core) — the I/O-free **producer** core: envelope and attestation assembly (§8.1, §8.12), Ed25519ph signing (§8.3.1), RFC 3161 / Rekor proof codecs, and the §8.8.1 commitment view. Shares one canonicalization implementation with `verify-core`, so producer and verifier compute the same envelope hash by construction. |

Apps (the typedstandards.org Next.js site and its `/verify` client-side verifier)
land in a later phase under `apps/`.

## Develop

```sh
npm install            # installs all workspaces
npm run build          # build every workspace that defines a build
npm test               # run every workspace's tests
```

Per-package:

```sh
npm run build --workspace @typedstandards/verify-core
npm run test  --workspace @typedstandards/verify-core
```

## Publishing `@typedstandards/verify-core`

The package publishes to the public npm registry under the `@typedstandards`
scope. Requires the `typedstandards` npm org and `npm login`:

```sh
npm run build --workspace @typedstandards/verify-core
npm publish   --workspace @typedstandards/verify-core   # publishConfig.access = public
```

## Contact routing

Every contact / express-interest entry point on typedstandards.org (landing
page and footer) reads one constant: `EXPRESS_INTEREST_URL` in
[`apps/web/src/lib/site-config.ts`](apps/web/src/lib/site-config.ts). When a
project inbox exists, changing that one constant re-routes every entry point —
no other edit needed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — getting started, the branch-and-PR
rule (main auto-deploys to production, so no direct pushes), and the DCO
sign-off requirement. This repo is one of four in the Civic AI Tools / Typed
Standards project; the
[hub CONTRIBUTING guide](https://github.com/npstorey/civic-ai-tools/blob/main/CONTRIBUTING.md)
maps all four and where to file what.

## License

MIT © Nathan Storey

[ts]: https://typedstandards.org
