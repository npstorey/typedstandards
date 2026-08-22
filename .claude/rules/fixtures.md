---
paths:
  - "**/fixtures/**"
  - "**/*.test.*"
---

# Guard-safe fixtures

A global pre-push guard (gitleaks plus a keyword list) scans the **added lines of
every outgoing commit**, not just the tip. A fix-on-top commit therefore does not
clear a block — the flagged bytes have to be absent from all pushed history.

Shape synthetic fixture values so the guard stays quiet:

- **No bare 13–19-digit decimal runs.** Keep synthetic numeric values at ≤ 12 digits,
  timestamps included. Hex hashes are fine — adjacent letters break the word boundary
  the pattern needs.
  <!-- S1 P1: a 19-digit synthetic Rekor tree id. S2 P1: 19-digit synthetic OTel timestamps. Same pattern, two sprints apart -->
- **Seed synthetic ids into the hex-letter range** so they cannot read as account- or
  card-shaped decimals.
- **No base64 blobs in `key`-named fields** unless a test actually reads the value.
  Drop the field instead.
  <!-- S1 P2: gitleaks generic-api-key fired on FreeTSA's *public* P-384 SPKI key sitting in an unused fixture field -->

## When the guard blocks

Reshape the fixture to guard-safe values, regenerate any goldens from the reference
implementation, and rebuild the branch history so the flagged bytes never appear in
an outgoing commit — `git rebase -i` is unavailable here, so use a soft-reset squash
or a cherry-pick rebuild.

Never bypass, and never tune the guard's patterns or add a gitleaks allowlist on your
own initiative. Surface the block and resolve it with the owner.
<!-- both S1 false positives were first met with a fix commit on top, which the guard rejected again -->

## Fixture provenance

Every fixture names which source test or capture it derives from, in the PR body.
Byte-equal assertions against that source are the load-bearing checks — a fixture
with no stated provenance is a fixture nobody can re-derive.
<!-- the S1/S2 evidence protocol; see CLAUDE.md -->
