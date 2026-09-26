---
paths:
  - "packages/*/src/**"
---

# Purity

You are in shipped source of a published package: one of the two cores, or the
command logic of a Node program (`packages/cli/src`). All of it is **browser-safe
and I/O-free**; test files (`*.test.ts`) are exempt from all of it.

Every published package, in shipped `src/`:

- no `node:*` imports, and no bare specifiers that resolve to Node built-ins
  (`crypto`, `fs`, `fs/promises`, `path`, `process`);
- no `process` / environment reads — configuration is caller-supplied;
- no `Buffer` — use `Uint8Array` / `atob` / `btoa` / verify-core primitives.

`produce-core` additionally has **no network, no clock, no RNG**. verify-core's
network-touching helpers do not call `fetch` themselves either: they take an injected
`FetchLike`.
<!-- the injected-FetchLike shape is what lets verify-core run in a browser, a worker, and a test with a stub; a direct fetch call would silently retire that -->

## Node programs (typedstandards#109)

A published package that must touch the machine (read a file, an environment
variable, standard input) keeps its logic in `src/`, under every rule above, and
does its I/O in **one entry outside `src/`**, built by a config of its own. The
CLI's is `packages/cli/node/main.ts`, built by `packages/cli/tsconfig.node.json`
(`types: ["node"]`); it builds the `Io` object the commands in `src/` receive, and
reaches them through the package's `#core` imports map. The seed, the files and
stdout exist only there.

`scripts/type-check-universe.test.mjs` pins each such config in `NODE_ENTRIES`:
its program's source files exactly, and the Node built-ins those files may import.
A second Node program (the planned host package, an I/O-free library over
in-memory files with disk access only in its own `node/` entry) joins by adding
its config there, in the diff that adds it; the pinned set is asserted exactly,
both ways, so a core that adds a Node config fails. The ruling: #109, G0 D1.

## What enforces it

Three checks, and they are not redundant: each covers something another does not.

- **Typecheck** (`npm run typecheck`, every published package). Each build config
  of `src/` sets
  `"types": []`, so shipped source resolves no Node type definitions: a
  `process` or `Buffer` read is `TS2591`, and an import of a Node built-in is
  `TS2307`, anywhere under `src/`, unless a shipped file carries
  `/// <reference types="node" />`, which loads them and lets all three type-check.
  `scripts/type-check-universe.test.mjs` fails if a build program loads
  `@types/node`, by config or by that reference, or if a config stops reddening on
  those three probes, the pinned Node entries excepted. It also fails if a
  published package would pack a script none of its guarded configs emitted.
- **Lint** (`npm run lint --workspace @typedstandards/produce-core`, produce-core
  only). `packages/produce-core/eslint.config.mjs`: `no-restricted-imports` and
  `no-restricted-globals` (`process`, `Buffer`), at edit and lint time.
  verify-core has no lint.
- **`src/browser-safety.test.ts`** (each core, under `node --test`). Import
  specifiers and `Buffer` usage, by regex; produce-core's copy also bars
  `Date.now`, `new Date(`, `Math.random`, `randomUUID` and `getRandomValues`. It
  reads the top level of `src/` only, not subdirectories.

Per rule, per package (`src/`):

| Rule | produce-core | verify-core | cli |
|---|---|---|---|
| no Node built-in import | typecheck, lint, browser-safety test | typecheck, browser-safety test | typecheck |
| no `process` read | typecheck, lint | typecheck | typecheck |
| no `Buffer` | typecheck, lint, browser-safety test | typecheck, browser-safety test | typecheck |
| no clock, no RNG | browser-safety test | not a verify-core rule | not a cli rule (both arrive through `Io`) |
| no direct network call | nothing mechanical | nothing mechanical | nothing mechanical; its tests assert no call |

The CLI's Node entry is held instead to its pin: its program is `node/main.ts`
alone, importing only `node:fs`, `node:process`, `node:util` and `#core`.

The build configs of `src/` keep the DOM lib, so the typecheck does not see `fetch`,
`crypto.getRandomValues` or `Date`.

Don't weaken any of it. A diff that touches the lint config, a build config's
`types`, or `NODE_ENTRIES`, must say so explicitly in its PR body: each is part of
the enforcement, so a quiet edit there retires the rule it enforces while the other
checks still look green.
<!-- the standing CLAUDE.md rule since the lint config was written. The typecheck leg was added with typedstandards#68: before it, verify-core's "two independent checks" were one for imports and Buffer and none for `process`, and a `process.env` read in verify-core/src/index.ts passed every CI step -->

## Build order

Workspace consumers resolve verify-core's **built dist**, not its source. After
changing verify-core, run `npm run build:verify-core` before produce-core or web
tests and typechecks, or you are testing the previous build.
<!-- PR #39: a fresh-tree install built produce-core before verify-core's dist existed and died there -->
