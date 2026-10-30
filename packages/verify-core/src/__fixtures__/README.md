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

## `civicaitools-v1-guidance-bundle.json`, the subtype's guidance bundle

A byte-identical copy of the `ai-assisted-analysis/civicaitools-v1` guidance bundle,
revision 1 (2026-10-30), whose address and SHA-256 the subtype table's row pins
(`PRODUCER_PROFILE_SUBTYPES` in `src/profiles.ts`; specification §8.6, hub ADR-0038 §5).

- **Source:** `docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json` in the hub
  repository (`npstorey/civic-ai-tools`) at tree `7060f5e32b2a4e429c8b6df317153bc4fc7c57c6`,
  the tree of merge commit `b2bb304cbf7063e84e260d725b7727b9ff85e38c`, which the tag
  `v0.1.13-typed-standards-spec` names. The row's URL is that file's raw address at the tag.
- **Derivation:** none. The bytes are the source's, written with
  `git show 7060f5e32b2a4e429c8b6df317153bc4fc7c57c6:docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json`;
  the git blob is the source's (`00c91578c02a7b3fb370808f45a09ee6112cf7b2`), 32,785 bytes.
- **What it pins:** SHA-256 `724e399e02db8993041b64982eec731505084bec2ec5e6ca58fda2de8087a281`,
  the digest ADR-0038 §5 records and the row carries.

`producer-profile-subtypes.test.ts` asserts the copy's SHA-256 against the row, and its
`subtype`, `url` and `contentProfiles.admits` against the row's key, URL and admitted set.
No test fetches the URL. A later revision of the bundle replaces this copy and the row's
pin in one change.
