# Contributing to typedstandards

This repo holds the [typedstandards.org](https://typedstandards.org) site (`apps/web`) and the [`@typedstandards/verify-core`](https://www.npmjs.com/package/@typedstandards/verify-core) verification library (`packages/verify-core`). It is one part of the Civic AI Tools / Typed Standards multi-repo project — the [hub CONTRIBUTING guide](https://github.com/npstorey/civic-ai-tools/blob/main/CONTRIBUTING.md) has the overview of all four repos and where to file what. The Typed Standards Specification itself lives in the hub repo (`docs/architecture/typed-standards-specification.md`), not here.

## Getting started

1. Fork and clone; `npm install` (npm-workspaces monorepo)
2. `npm run build` and `npm test` (see the README for per-package commands)
3. Create a branch for your changes — all changes go through branches and PRs; no direct pushes to `main` (it auto-deploys to production)
4. Open a pull request

## Guidelines

- Keep changes focused — one fix or feature per PR
- `verify-core` is the portable §9.2 verification core consumed by multiple sites — changes there need tests and must stay browser-safe with no host-specific dependencies
- Be respectful in issues and pull requests

## Legal: sign-off and IPR

- Every contribution requires a Developer Certificate of Origin sign-off: commit with `git commit -s`, which adds a `Signed-off-by: Your Name <email>` line. What that certifies, and the project-wide policy: [IPR.md](https://github.com/npstorey/civic-ai-tools/blob/main/IPR.md) (hub repo; adopted per [ADR-0017](https://github.com/npstorey/civic-ai-tools/blob/main/docs/adr/0017-ipr-posture-dco-rf-statement.md)).
- The project's patent posture is the royalty-free statement at [PATENTS.md](https://github.com/npstorey/civic-ai-tools/blob/main/PATENTS.md); contributions of normative Typed Standards Specification text (in the hub repo) carry its § Contributions terms.

## Questions?

Open an issue here, or at the [hub repo](https://github.com/npstorey/civic-ai-tools/issues) if you're unsure where it belongs.
