# CLAUDE.md

Typed Standards monorepo: the spec site (`apps/web`, typedstandards.org) and
the reference cores — `packages/verify-core` (the spec §9.2 verification
suite) and `packages/produce-core` (the I/O-free producer core). npm
workspaces; Node ≥ 22 at the root (packages support ≥ 18); `npm ci` at the
root installs everything.

## Build / test

- `npm test`, `npm run build`, `npm run typecheck` run across all workspaces;
  `npm run lint` runs inside `packages/produce-core`.
- Workspace consumers resolve verify-core's **built dist**, not its source:
  after changing verify-core, run `npm run build:verify-core` before running
  produce-core or web tests/typecheck.

## Purity discipline

Both cores are browser-safe and I/O-free in shipped `src/`: no `node:*`
imports, no `process`/environment reads, no `Buffer`; produce-core
additionally allows no network, no clock, no RNG (verify-core's
network-touching helpers take an injected `FetchLike`). Enforced by
produce-core's ESLint `no-restricted-imports`/`no-restricted-globals` config
and each core's dependency-free `browser-safety.test.ts`; test files are
exempt. Don't weaken any of it; a diff touching the lint config should say so
explicitly.

## Evidence protocol (gated sprint phases)

The convention set by the S1 (#32) and S2 (civic-ai-tools#116) gate records.
Every phase report (PR body + anchor-issue comment) carries:

- the phase **branch** and **diff stat**, with the blast zone stated
  explicitly (paths touched; read-only repos/paths untouched);
- **full workspace test output** — all packages, not just the one touched;
- **purity-lint proof** (a clean lint run);
- **fixture provenance** — which source test or capture each fixture derives
  from; byte-equal assertions are the load-bearing checks;
- the **model** the phase ran on.

ORCH re-verifies evidence independently before merging; IMPL-reported numbers
alone don't pass a gate.

## Rollback tags

Bracket every phase merge: `rollback/pre-<sprint>-p<n>` at the pre-merge
anchor, `rollback/<sprint>-p<n>-merged` at the squash-merge (the S2 form; S1
used a `pre-…-merged` spelling). Pushed by the orchestrator, not by IMPL
sessions.

## Push guard + guard-safe fixtures

A global pre-push guard (gitleaks + a keyword list) scans the **added lines
of every outgoing commit**, so a fix-on-top commit cannot clear an earlier
one. Standing fixture convention, set across three false positives (S1 P1: a
19-digit synthetic Rekor tree id; S1 P2: FreeTSA's public P-384 SPKI key in
an unused fixture field; S2 P1: 19-digit synthetic OTel timestamps):

- no bare 13–19-digit decimal runs — keep synthetic numeric values ≤ 12
  digits (timestamps included);
- seed synthetic ids into the hex-letter range;
- no base64 blobs in key-named fields unless a test actually reads them.

If the guard blocks: reshape the fixture to guard-safe values, regenerate any
goldens from the reference implementation, and rebuild the branch history so
the flagged bytes never appear in an outgoing commit. Never bypass
(`--no-verify`, `PUSH_GUARD_SKIP=1`) and never tune the guard's patterns
unilaterally.

## Phrasing, merges, publishing

- Neutral phrasing in commits, PRs, and issue comments: "a prospective
  adopter" — no stakeholder names, orgs, or cities.
- Work lands via PRs to `main` (protect-main ruleset). Merging is the
  orchestrator's call on evidence-pass in gated sprints, the owner's
  otherwise.
- `npm publish` is always an owner-only decision; a session ends at
  branch/PR (or merged-and-tagged in a sprint), never at published.
- CHANGELOGs are factual per-version records; a new export is a minor bump.
