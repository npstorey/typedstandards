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

Two independent checks, and they are not redundant:

- `packages/produce-core/eslint.config.mjs` — `no-restricted-imports` /
  `no-restricted-globals`, at edit and lint time
  (`npm run lint --workspace @typedstandards/produce-core`);
- each core's dependency-free `src/browser-safety.test.ts`, mechanically, under
  `node --test` in CI.

Don't weaken either. A diff that touches the lint config must say so explicitly in
its PR body — that config is half the enforcement, so a quiet edit there retires the
rule it enforces while the test still looks green.
<!-- the standing CLAUDE.md rule since the config was written; it is the only reason a purity regression cannot land as a silent config relaxation -->

## Build order

Workspace consumers resolve verify-core's **built dist**, not its source. After
changing verify-core, run `npm run build:verify-core` before produce-core or web
tests and typechecks, or you are testing the previous build.
<!-- PR #39: a fresh-tree install built produce-core before verify-core's dist existed and died there -->
