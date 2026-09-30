# @typedstandards/host-core

Serve signed Typed Standards records from a static host. Host Core takes what the
[CLI](../cli)'s `sign` and `withdraw` print and writes what a static host serves:

- one bundle per record, the commitment view plus the signed package;
- the key registry, at `.well-known/typed-publisher.json`;
- a versioned index, `records.json`;
- verifier links and badge snippets.

It checks what is served against a fresh build, verifies it offline with
[`@typedstandards/verify-core`](../verify-core), and gives a host a display seam,
`displayOf`. **Host Core never holds a key**: signing, key generation and
withdrawal stay with the CLI.

It is a library (`import … from '@typedstandards/host-core'`) and a command,
`typedstandards-host`. Node ≥ 22.

## The host manifest, `host.json`

```json
{
  "origin": "https://records.example.org",
  "visibility": "public",
  "registry": { "$comment": "Our statement about our signing key." },
  "index": { "$comment": "The records this host serves." },
  "records": [
    {
      "name": "report-2026",
      "signed": "signed/report-2026.signed.json",
      "attestations": [],
      "title": "Annual report, 2026",
      "extensions": { "role": "report" }
    }
  ]
}
```

- Every path is relative to `host.json`.
- `origin` is `https://…` with no trailing `/`; a path prefix is allowed.
- `visibility` is the views' disclosure state. **It is host-wide in 0.1.0**, and it
  is never defaulted: produce-core refuses a view without one.
- `registry` serves a key registry, or `null` serves none. With `null`, produce-core
  builds a view only for a key-derived `did:key` signer at `bindingTier:
  "pseudonymous"`; host-core surfaces its refusal otherwise.
- In 0.1.0, **every record under a registry has one signer** (one identifier,
  binding tier, display name and key); anything else is refused.
- `signed` is what `sign` printed, `{package, envelopeHash, signature}`.
  `attestations` are what `withdraw` (or `attest`) printed, `{node, nodeId,
  signature}`, each aimed at this record. A claim-to-claim node is refused.
- `title` is the view's `subjectTitle`. `extensions` is copied into the index
  record, where a display policy can read it.
- `$comment` strings are allowed at the top level and on each record.

## What is served

`build` writes to the served directory, `--out`, which defaults to `docs/` beside
`host.json`. It refuses a manifest or input file inside it: inputs stay out of what
is served.

| Path | What |
|---|---|
| `bundles/<name>.bundle.json` | `{...view, trustRegistry, package}` when a registry is served, else `{...view, package}`. The view is produce-core's `buildCommitmentView` over the signed document and its carried attestations. |
| `.well-known/typed-publisher.json` | The registry: one key, the signer's, `active` from the earliest `createdAt` among the records. |
| `records.json` | The index, version 1. |

`build` overwrites these paths and deletes nothing: `check` reports a served bundle
the manifest no longer lists.

**No `lifecycle` summary in 0.1.0.** A bundle carries the signed attestations and
no summary of them. A summary can come later as a host-core minor: a rebuild of the
bundles, with no re-signing. The index, the display seam and the verifier already
carry each record's status.

### Index v1

```json
{
  "version": 1,
  "$comment": "…",
  "host": "https://records.example.org/",
  "trustRegistryUrl": "https://records.example.org/.well-known/typed-publisher.json",
  "records": [
    {
      "name": "report-2026",
      "bundle": "bundles/report-2026.bundle.json",
      "packageHash": "…",
      "createdAt": "…",
      "type": "content/analysis/v1",
      "signer": "did:key:…",
      "status": "withdrawn",
      "withdrawn": { "at": "…", "reason": "…" },
      "extensions": { "role": "report" }
    }
  ]
}
```

Records follow the manifest's order. `bundle` is a path relative to `host`, or an
absolute URL. `status`, `withdrawn {at, reason}` and `superseded {at,
successorNodeId}` are verify-core's `verifyLifecycleChain` reading of the
attestations each bundle carries, bound by the record's own signing key as the CLI
binds them. They are never read from input. `$comment` and `trustRegistryUrl` are
present when the manifest gives a comment and serves a registry.

`type` is the type verify-core's `resolvePackageType` resolves for the package. A
package signed with no `type`, on the legacy chain, is listed as
`content/analysis/v1`: spec §8.8.1 says "Absence is interpreted as
`content/analysis/v1`". A display rule naming `content/analysis/v1` therefore
displays it, and `verify` compares the index's `type` with the same resolution.
`createdAt` and `signer` are the package's `metadata.createdAt` and
`signer.identifier`; `build` refuses a package that lacks either, naming the record
and the field, so it never writes an index that its own `parseIndex` refuses.

## Commands

```
typedstandards-host build  [--manifest host.json] [--out docs]
typedstandards-host check  [--manifest host.json] [--out docs]
typedstandards-host verify [--out docs]
typedstandards-host links  [--out docs] [--theme light|dark]
```

- `build` builds in memory and writes the served files.
- `check` builds in memory and compares with `--out` byte for byte: every built
  file must be served unchanged, and no other bundle, registry or index served.
- `verify` verifies every record `records.json` lists, offline (below).
- `links` prints, as JSON, each record's served URL, its verifier link
  (`https://typedstandards.org/verify?url=<percent-encoded URL>`, the site's own
  form) and the HTML and Markdown badge snippets.

Exit codes: 0 ok, 1 `check` or `verify` failed, 2 usage or input error, 4 internal
error. `verify` and `links` read `--out` only; `--out` still defaults to `docs/`
beside `--manifest`.

### What `verify` checks

For each record, verify-core's `verifyRecord` runs over the served bundle with the
network blocked: the global `fetch` is replaced for the run by a stub that throws
and counts, and the fetch injected into verify-core throws and counts too. The
served registry is read as the file a verifier fetches from the declared
`trustRegistryUrl`. A record is `ok` when:

- #1 reads `verified` and #2 `true`;
- no check reads alarm, and #5 reads `active` when a registry is served;
- every carried attestation targets the record, is intact and validly signed;
- the status the carried attestations give equals the index's;
- the index's `packageHash`, `createdAt`, `type` and `signer` are the bundle's, the
  view's copied fields equal its package's, and the view names the index's
  `trustRegistryUrl` and carries the served registry.

The run fails when any record fails, the registry does not validate, or either
fetch count is not 0. A record whose checks need the network (a BlobRef output)
therefore fails `verify` in 0.1.0.

Its first line names no Node or core version:

```
typedstandards-host verify: records.json lists 52 records, each verified offline by @typedstandards/verify-core with the network blocked
```

so a committed copy of the output stays equal across Node patches and core
releases. **To regenerate a committed golden** after a change that alters it,
rerun `typedstandards-host verify > verify-output.txt` and review the diff.

## The display seam

```js
import { displayOf, parsePolicy } from '@typedstandards/host-core';
const policy = parsePolicy(JSON.parse(policyText));
displayOf(indexRecord, policy); // → { as: 'current', rule: 0 }, or throws
```

A display policy is the host's own rule for what a page shows. It is not signed
and nothing verifies it. It is JSON, with `$comment` strings allowed:

```json
{
  "signer": "did:key:…",
  "type": "content/analysis/v1",
  "display": [
    { "status": "active", "extensions": { "role": ["report"] }, "as": "current" },
    { "status": "withdrawn", "as": "withdrawn" }
  ],
  "unmatched": "refuse"
}
```

- `signer`, `type` and a rule's `status` are a string or a list of strings.
  `extensions` maps an index `extensions` key to the values it admits; a host's
  roles become such a key.
- A record is displayed by the first rule it matches.
- It is refused when its status is not one of verify-core's `LIFECYCLE_STATUSES`
  (`active`, `withdrawn`, `superseded`), when the top-level `signer` or `type`
  does not name it, or when no rule matches: `unmatched: "refuse"` is the only mode
  in 0.1.0.
- Every rule names its statuses, so `superseded` is displayed only when a rule
  names it.

A policy kept as YAML is converted with any YAML-to-JSON tool first, for example
`yq -o=json host-policy.yaml > host-policy.json`. Host Core reads JSON only.

## The library

- `buildHost(manifest, files)` → `{files, index, registry}`: `files` in is a map of
  paths (relative to `host.json`) to bytes; `files` out maps served paths to bytes.
- `checkServed(built, served)` → `{ok, lines}`.
- `verifyServed(served, options?)` → `{ok, lines, totals, fetch}`.
- `linksFor(index, theme?)` → one `{name, url, verify, html, markdown}` per record.
- `parsePolicy(value)`, `displayOf(record, policy)`.
- `parseManifest(value)`, `parseIndex(value)`, `serialize(value)`, and the served
  paths `INDEX_PATH`, `REGISTRY_PATH`, `bundlePathOf(name)`.

Inputs it refuses throw `HostError`. The library is I/O-free and browser-safe: no
Node built-in, no `process`, no `Buffer`. The bin's one Node entry, `node/main.ts`,
does the reading and writing.

## License

MIT
