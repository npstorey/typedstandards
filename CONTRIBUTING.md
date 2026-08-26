# Contributing to typedstandards

This repo holds the [typedstandards.org](https://typedstandards.org) site (`apps/web`) and the [`@typedstandards/verify-core`](https://www.npmjs.com/package/@typedstandards/verify-core) verification library (`packages/verify-core`). It also holds [`@typedstandards/produce-core`](https://www.npmjs.com/package/@typedstandards/produce-core) (`packages/produce-core`), the producer counterpart to `verify-core`. It is one part of the Civic AI Tools / Typed Standards multi-repo project — the [hub CONTRIBUTING guide](https://github.com/npstorey/civic-ai-tools/blob/main/CONTRIBUTING.md) has the overview of all four repos and where to file what. The Typed Standards Specification itself lives in the hub repo (`docs/architecture/typed-standards-specification.md`), not here.

## Getting started

1. Fork and clone; `npm install` (npm-workspaces monorepo)
2. `npm run build` and `npm test` (see the README for per-package commands)
3. Create a branch for your changes — all changes go through branches and PRs; no direct pushes to `main` (it auto-deploys to production)
4. Open a pull request

## If you use Claude Code

Cloning this repo installs its checked-in Claude Code configuration: `.claude/settings.json` (a network allowlist and a sandbox block), plus the agent definitions in `.claude/agents/` and the path-scoped rules in `.claude/rules/`.

Those files are ordinary JSON and Markdown — read them before you trust them, the same as any other code you clone. Personal overrides belong in `.claude/settings.local.json`, which is gitignored.

## Guidelines

- Keep changes focused — one fix or feature per PR
- `verify-core` is the portable §9.2 verification core consumed by multiple sites — changes there need tests and must stay browser-safe with no host-specific dependencies
- Be respectful in issues and pull requests — this repo follows the project's [Code of Conduct](CODE_OF_CONDUCT.md)

## Commits, signing, and how we merge

This repository follows the project-wide contribution policy in the
[hub CONTRIBUTING guide](https://github.com/npstorey/civic-ai-tools/blob/main/CONTRIBUTING.md#commits-signing-and-how-we-merge), which is the canonical
text. In short:

- **Sign off every commit — required.** `git commit -s` appends a `Signed-off-by:` line (DCO 1.1;
  what it certifies is in [IPR.md](https://github.com/npstorey/civic-ai-tools/blob/main/IPR.md), adopted per
  [ADR-0017](https://github.com/npstorey/civic-ai-tools/blob/main/docs/adr/0017-ipr-posture-dco-rf-statement.md)). A required `DCO` status check
  enforces it. Forgot? `git rebase --signoff main` fixes a whole branch at once.
- **Sign your commits — encouraged, not required.** SSH or GPG, with the public key registered on your
  GitHub account. Not enforced on any branch
  ([Q74](https://github.com/npstorey/civic-ai-tools/blob/main/docs/architecture/open-questions.md#q74--should-the-default-branches-require-signed-commits)
  records why), but because we never rewrite your commits, your signature is what stays on `main`.
- **Rebase into atomic commits before requesting review.** Each commit should build and pass tests on
  its own. We do not squash at merge time, so your branch lands exactly as you shaped it — and that is
  what keeps `git bisect` useful.
- **We merge with merge commits — never squash, never rebase.** Squash and rebase merges rewrite
  commits, so what lands on `main` is a new object: your signature is replaced by GitHub's and your
  per-commit sign-offs collapse into one commit body. A merge commit is the only method that leaves
  your commits on `main` as the objects you actually made and signed. Reasoning and costs:
  [ADR-0027](https://github.com/npstorey/civic-ai-tools/blob/main/docs/adr/0027-merge-commit-only-vcs-policy.md). To read `main` as one entry per
  pull request, use `git log --first-parent`.

The project's patent posture is the royalty-free statement at [PATENTS.md](https://github.com/npstorey/civic-ai-tools/blob/main/PATENTS.md).

## Questions?

Open an issue here, or at the [hub repo](https://github.com/npstorey/civic-ai-tools/issues) if you're unsure where it belongs.
