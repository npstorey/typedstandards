---
paths:
  - "packages/*/src/**"
---

# Core purity

You are in shipped core source. Both cores are **browser-safe and I/O-free**; test
files (`*.test.ts`) are exempt from all of it.

Both cores, in shipped `src/`:

- no `node:*` imports, and no bare specifiers that resolve to Node built-ins
  (`crypto`, `fs`, `fs/promises`, `path`, `process`);
- no `process` / environment reads — configuration is caller-supplied;
- no `Buffer` — use `Uint8Array` / `atob` / `btoa` / verify-core primitives.

`produce-core` additionally has **no network, no clock, no RNG**. verify-core's
network-touching helpers do not call `fetch` themselves either: they take an injected
`FetchLike`.
<!-- the injected-FetchLike shape is what lets verify-core run in a browser, a worker, and a test with a stub; a direct fetch call would silently retire that -->

## What enforces it

Three checks, and they are not redundant: each covers something another does not.

- **Typecheck** (`npm run typecheck`, both cores). Each build config sets
  `"types": []`, so shipped source resolves no Node type definitions: a
  `process` or `Buffer` read is `TS2591`, and an import of a Node built-in is
  `TS2307`, anywhere under `src/`, unless a shipped file carries
  `/// <reference types="node" />`, which loads them and lets all three type-check.
  `scripts/type-check-universe.test.mjs` fails if a build program loads
  `@types/node`, by config or by that reference, or if a config stops reddening on
  those three probes.
- **Lint** (`npm run lint --workspace @typedstandards/produce-core`, produce-core
  only). `packages/produce-core/eslint.config.mjs`: `no-restricted-imports` and
  `no-restricted-globals` (`process`, `Buffer`), at edit and lint time.
  verify-core has no lint.
- **`src/browser-safety.test.ts`** (each core, under `node --test`). Import
  specifiers and `Buffer` usage, by regex; produce-core's copy also bars
  `Date.now`, `new Date(`, `Math.random`, `randomUUID` and `getRandomValues`. It
  reads the top level of `src/` only, not subdirectories.

Per rule, per core:

| Rule | produce-core | verify-core |
|---|---|---|
| no Node built-in import | typecheck, lint, browser-safety test | typecheck, browser-safety test |
| no `process` read | typecheck, lint | typecheck |
| no `Buffer` | typecheck, lint, browser-safety test | typecheck, browser-safety test |
| no clock, no RNG | browser-safety test | not a verify-core rule |
| no direct network call | nothing mechanical | nothing mechanical |

Both build configs keep the DOM lib, so the typecheck does not see `fetch`,
`crypto.getRandomValues` or `Date`.

Don't weaken any of it. A diff that touches the lint config, or a build config's
`types`, must say so explicitly in its PR body: each is part of the enforcement, so a
quiet edit there retires the rule it enforces while the other checks still look green.
<!-- the standing CLAUDE.md rule since the lint config was written. The typecheck leg was added with typedstandards#68: before it, verify-core's "two independent checks" were one for imports and Buffer and none for `process`, and a `process.env` read in verify-core/src/index.ts passed every CI step -->

## Build order

Workspace consumers resolve verify-core's **built dist**, not its source. After
changing verify-core, run `npm run build:verify-core` before produce-core or web
tests and typechecks, or you are testing the previous build.
<!-- PR #39: a fresh-tree install built produce-core before verify-core's dist existed and died there -->
