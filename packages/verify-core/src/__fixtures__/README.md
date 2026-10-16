# Fixtures

## `repeated-member-name.bundle.json`, a negative vector

A signed commitment bundle whose package's JSON text repeats a member name within an
object, which a verifier refuses (specification §8.2, §9.2 check #1;
typedstandards#145).

- **Source:** `apps/web/src/lib/__fixtures__/q15-self-certified.json`, the minted
  interop bundle: a package under `raw-bytes/v1`, signed by a self-certifying key
  generated for that fixture (its README and mint program are beside it).
- **Derivation:** one line inserted before the source's line 66, the package's
  `summary` member: a second `summary` member with other text, in the package object.
  Nothing else changes; the vector is the source plus that one line (72 lines, 71 in
  the source).
- **What it keeps:** parsed by `JSON.parse`, which keeps the last occurrence of a
  repeated name, it is the source's value, so its package gives the source's envelope
  hash (`9a53cd8ee701f2361cdcf353604bbcde43679f9a55c7cd3759db64d2b7e31dde`, the
  bundle's `packageHash`, which its signature covers) and the source's content hash
  (`f189b442e23fbdb0b3f0d1b065a2afb59172f0d6b4a1e7bb661b0b940cc59928`). Under
  `raw-bytes/v1` the content hash covers `output` alone; the envelope hash covers the
  whole package, `summary` included.
- **What a strict parse reports:** `parseStrictJson` throws `RepeatedMemberNameError`
  with the member name `summary` and the JSON Pointer `/package`.

`repeated-member-name.test.ts` asserts each of these, and pins the file's SHA-256. The
CLI, host-core and web tests read the vector from here.
