# CLAUDE.md

Typed Standards monorepo: the spec site (`apps/web`, typedstandards.org) and the
reference cores — `packages/verify-core` (the spec §9.2 verification suite) and
`packages/produce-core` (the I/O-free producer core). npm workspaces; Node ≥ 22 at
the root (packages support ≥ 18); `npm ci` at the **repo root** installs everything.

## Build / test

Under a Node version manager, a non-interactive shell has no `node` on `PATH` — load
it first: `eval "$(fnm env)" && fnm use 22`, or your equivalent.

The CI gates below, in the order `.github/workflows/ci.yml` runs them. Workspace
consumers resolve verify-core's **built dist**, not its source, so it builds first.

- `npm run build:verify-core` — `tsc -p tsconfig.json`; silent on success.
- `npm run build` — all workspaces; the web build ends with its `Route (app)` table.
- `npm test` — all workspaces; `# pass` 97 produce-core / 64 verify-core / 116 web, `# fail 0`.
- `npm run typecheck` — all workspaces; `tsc --noEmit`, silent on success.
- `npm run lint --workspace @typedstandards/produce-core` — the purity config. There
  is **no root `npm run lint`**.
- `node --test scripts/check-dependency-budget.test.mjs` — `# pass 8`, `# fail 0`.
- `npm run check:budgets` — two `OK` lines, then `Dependency-budget check passed.`

## Purity discipline

Both cores stay browser-safe and I/O-free in shipped `src/`; test files are exempt.
Enumerated rules and enforcement: [`.claude/rules/purity.md`](.claude/rules/purity.md).
Don't weaken any of it — and a diff touching produce-core's ESLint config must say so.
<!-- that config is half the enforcement (browser-safety.test.ts is the other half), so a quiet edit there retires the rule it enforces -->

## Secret hygiene

Never `cat`/`head`/`tail`/dump `.env*`, `auth.json`, `credentials*`, `*.pem`, `*.key`,
`~/.ssh`, `~/.aws`. Read only by key **name** (`grep`/`jq` a field, never a value) or a
command the tool exposes; never load-and-print a credentials file, even redacted.
<!-- civic-ai-tools#174: an ORCH session's redaction filter ran at the wrong nesting level and a live bearer token reached tool output; the rule lived in one repo's CLAUDE.md only -->

## Evidence protocol (gated sprint phases)

The convention set by the S1 (#32) and S2 (civic-ai-tools#116) gate records. Every
phase report (PR body + anchor-issue comment) carries:

- the phase **branch** and **diff stat**, with the blast zone stated explicitly;
- **full workspace test output** — all packages, not just the one touched;
- **purity-lint proof** (a clean lint run);
- **fixture provenance** — which source test or capture each fixture derives from;
  byte-equal assertions are the load-bearing checks;
- the **model** the phase ran on.

ORCH re-verifies evidence independently before merging; IMPL-reported numbers alone
don't pass a gate.

## Rollback tags

Bracket every phase merge: `rollback/pre-<sprint>-p<n>` at the pre-merge anchor,
`rollback/<sprint>-p<n>-merged` at the squash-merge (the S2 form; S1 used a
`pre-…-merged` spelling). Pushed by the orchestrator, not by IMPL sessions.

## Push guard

A global pre-push guard scans the **added lines of every outgoing commit**, so a
fix-on-top commit cannot clear an earlier one — the flagged bytes have to be absent
from all pushed history. On a block: reshape the content, regenerate goldens from the
reference implementation, and rebuild the branch history. Never bypass, never tune the
guard's patterns unilaterally. Shapes: [`.claude/rules/fixtures.md`](.claude/rules/fixtures.md).

## Phrasing, merges, publishing

- Neutral phrasing everywhere: "a prospective adopter" — no stakeholder names, orgs,
  or cities. This repo is public and its history is permanent; scrub strategic context
  out of a task prompt before it reaches a file, a commit message, or an issue body.
- `git commit -s` on every commit; the `Signed-off-by:` email must match the commit
  author email exactly — a mismatch fails DCO, absence is not the only way to fail it.
- Work lands via PRs to `main` (protect-main ruleset); never push to `main`. Merging
  is the orchestrator's call on evidence-pass in gated sprints, the owner's otherwise.
- `npm publish` is always an owner-only decision; a session ends at branch/PR (or
  merged-and-tagged in a sprint), never at published.
- CHANGELOGs are factual per-version records; a new export is a minor bump. Bump with
  `npm version --workspace <name>`.
