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
revision 2 (2026-11-02), whose address and SHA-256 the subtype table's row pins
(`PRODUCER_PROFILE_SUBTYPES` in `src/profiles.ts`; specification §8.6, hub ADR-0038's
amendment of 2026-11-02).

- **Source:** `docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json` in the hub
  repository (`npstorey/civic-ai-tools`): revision 2 at hub tree
  `bcd06c5fa43696db3b7576c93f829eed686d13af`, to be tagged `v0.1.14-typed-standards-spec`
  at its merge commit. The row's URL is that file's raw address at the tag.
- **Derivation:** none. The bytes are the source's, written with
  `git show bcd06c5fa43696db3b7576c93f829eed686d13af:docs/profiles/ai-assisted-analysis/civicaitools-v1/bundle.json`;
  the git blob is the source's (`204e564bcf60ecf4025149c24b7ba9133cee65fa`), 35,491 bytes.
- **What it pins:** SHA-256 `45bf3ab479325a791829ed9987f5f291fea44238b54bfb598f32f306f574eb9b`,
  the digest ADR-0038's amendment of 2026-11-02 records and the row carries. Revision 1's
  (`724e399e…a281`, at tag `v0.1.13-typed-standards-spec`) is the one ADR-0038 §5 records.

`producer-profile-subtypes.test.ts` asserts the copy's SHA-256 against the row, and its
`subtype`, `url` and `contentProfiles.admits` against the row's key, URL and admitted set.
No test fetches the URL. A later revision of the bundle replaces this copy and the row's
pin in one change.
