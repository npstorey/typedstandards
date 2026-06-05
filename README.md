# Typed Standards

The home of [Typed Standards][ts] — the standard for verifiable, signed evidence
packages, its reference verification core, and the typedstandards.org site.

This is an npm-workspaces monorepo.

## Packages

| Package | Description |
| --- | --- |
| [`packages/verify-core`](packages/verify-core) | [`@typedstandards/verify-core`](https://www.npmjs.com/package/@typedstandards/verify-core) — the portable, browser-safe §9.2 verification core. Published to npm so every consumer (civicaitools.org server, typedstandards.org browser client) depends on one versioned source that cannot drift. |

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

## License

MIT © Nathan Storey

[ts]: https://typedstandards.org
