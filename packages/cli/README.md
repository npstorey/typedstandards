# @typedstandards/cli

Sign, withdraw, attest to, build a commitment view for, and verify
[Typed Standards](https://typedstandards.org) records from the command line. It is a
thin program over the two reference cores, [`@typedstandards/produce-core`](https://www.npmjs.com/package/@typedstandards/produce-core)
and [`@typedstandards/verify-core`](https://www.npmjs.com/package/@typedstandards/verify-core):
every hash and signature comes from them, so a record this CLI signs is byte for byte
the record produce-core builds from the same input.

It is non-interactive and has no domain vocabulary. You supply the record's type,
producer profile, capture method, extensions and sources as input values. It reads
JSON, prints one JSON document on stdout, prints diagnostics on stderr, makes no
network request, and writes no file.

## Install

Node 20.19 or later.

```sh
npm install --global @typedstandards/cli   # then: typedstandards <command>
npx @typedstandards/cli <command>           # or without installing
```

## The signing key

`sign`, `withdraw` and `attest` read the signing seed from one environment variable:

```
TYPEDSTANDARDS_SIGNING_SEED_B64   the standard base64 of a 32-byte Ed25519 seed (44 characters, ending in "=")
```

The seed is never an argument. The CLI never prints it and never writes it. A missing
or malformed variable exits 3 with a message that names the variable and not its
value. `view` and `verify` never read it.

The CLI derives the signer's key-derived identifier (a `did:key`) from the seed. Keep
the seed in a secret store, and let the store put it into the environment of the one
command that needs it. With 1Password's CLI, an env file holds a reference and never a
value:

```sh
# sign.env
TYPEDSTANDARDS_SIGNING_SEED_B64=op://<vault>/<item>/<field>
```

```sh
op run --env-file=sign.env -- typedstandards sign --input record.json --output-file notebook.ipynb
```

A new seed is 32 random bytes, for example `openssl rand -base64 32`, stored straight
into the secret store.

The [core-satellite example](https://github.com/npstorey/typedstandards-core-satellite-example)'s
env file names its variable `SIGNING_SEED_B64`; this CLI reads
`TYPEDSTANDARDS_SIGNING_SEED_B64`.

A program that wraps the CLI (a Python package, a notebook helper) spawns it with the
inherited environment and never holds the seed itself.

## Commands

### `sign`

```sh
typedstandards sign --input <file|-> [--output-file <path> [--output-url <url> [--content-type <type>]]]
```

`--input` is an envelope input as JSON: the shape produce-core's `buildEnvelope`
takes (`EnvelopeInput`), so produce-core's reference fixtures drive this command's
tests. The record's output comes from one of three places:

- **the input's own `output`**, a string or a BlobRef, used as given;
- **`--output-file <path>`**, the file's bytes as inline text under `raw-bytes/v1`.
  The input must have a `type`, since `raw-bytes/v1` is a v0.1 rule. The file must be
  exact UTF-8 (a byte-order mark is kept), and its SHA-256 is the record's
  `contentHash.sha256`;
- **`--output-file <path> --output-url <url>`**, a BlobRef to the file's bytes
  (`ref` is their SHA-256, `size` their length, `contentType` from `--content-type`,
  default `application/octet-stream`). The file need not be text. On an input with a
  `type`, the rule is `raw-bytes/v1` unless the input names another: the record's
  `contentHash.sha256` is the hex of the BlobRef's `ref`, the file's SHA-256, as when
  it is signed inline. `verify --blob <path>` then checks the file's bytes against the
  reference. An input naming another rule keeps it, and an input with no `type` is
  signed on the legacy chain, which carries no rule. This default is a change from
  0.1.0, which signed a typed input by reference with no rule named under
  `legacy-json/v1`.

The CLI fills these fields only when the input omits them:

| Field | Filled with |
|---|---|
| `packageId` | a random UUID |
| `createdAt` | the current UTC time |
| `signingKeyId` | the seed's `did:key` |
| `signer.identifier` (when `signer` is given) | the seed's `did:key` |

The printed package carries every filled value, so running again with the same
values and the same seed reproduces the output byte for byte. Supply `packageId` and
`createdAt` to make a CI run reproducible in advance. Everything else is signed as
given.

A key that produce-core would drop is refused, not signed around: an unknown key at
the top level, or in `queries[]`, `cost` or `skillMetadata`, exits 2 and names the
key. `extensions` are opaque and signed as given.

**`vcsRef`** names the source revision the record was produced from, and is signed
as given at the envelope's top level:

```json
"vcsRef": {
  "repoUrl": "https://git.example.com/example/analysis",
  "commitSha": "0123456789abcdef0123456789abcdef01234567",
  "path": "notebooks/analysis.ipynb",
  "ref": "refs/heads/main"
}
```

`repoUrl` and `commitSha` are required non-empty strings; `path` and `ref` are
optional strings; any other key exits 2 and names it. `vcsRef` is signed on v0.1
envelopes only, so an input with no `type` that carries it exits 2. The signature
covers the assertion, not that the revision exists.

`sign` verifies its own result offline with verify-core before printing
`{package, envelopeHash, signature}`. If that verification fails, it exits 1 and
prints nothing on stdout.

### `withdraw`

```sh
typedstandards withdraw --input <file|->
```

Signs an `attestation/withdraws/v1` for a record with the same key path. The input
names `targetNodeId` (the record's envelope hash), `reason` and `signer`. It may also
name `effectiveAt`, `packageId`, `createdAt` and `signingKeyId`, filled as for `sign`
when absent. For the withdrawal to change the record's status, `signer.identifier`
must be the record's own. Prints `{node, nodeId, signature}`, the shape `view`
carries. A correction is a withdrawal plus a new record.

`attest` signs the other lifecycle and claim-to-claim sub-types.

### `attest`

```sh
typedstandards attest --input <file|->
```

Signs an `attestation/supersedes/v1`, `attestation/revises/v1`,
`attestation/corroborates/v1` or `attestation/contradicts/v1` on the same key path.
The input is one JSON object naming `type`, `targetNodeId` (the record's envelope
hash), `signer` and that type's payload (spec §8.12.1):

| `type` | Payload | Authorization rule |
|---|---|---|
| `attestation/supersedes/v1` | `successorNodeId`, the new record's envelope hash | publisher-only; the record reads `superseded` |
| `attestation/revises/v1` | `successorNodeId`, this revision's envelope hash | publisher-only; the status does not change |
| `attestation/corroborates/v1` | `scope`, a non-empty string; `reasoning`, optional, a string or an object | any signer with a bound key |
| `attestation/contradicts/v1` | `scope`; `reasoning`, optional | any signer with a bound key |

For example:

```json
{
  "type": "attestation/supersedes/v1",
  "targetNodeId": "<the old record's envelope hash>",
  "successorNodeId": "<the new record's envelope hash>",
  "signer": { "bindingTier": "pseudonymous", "displayName": "Example signer" }
}
```

It may also name `packageId`, `createdAt` and `signingKeyId`, filled as for `sign`
when absent. Each type takes only its own fields: any other key exits 2 and names it.
`withdraws` is `withdraw`'s. `endorses` is not signed: it stays reserved until the
specification defines its role check. `reinstates` is not signed by this version.

`attest` verifies the node offline with verify-core's `checkAttestationNode` before
printing `{node, nodeId, signature}`, the shape `view` carries. The node's integrity
and signature must hold, and a `did:key` signer identifier must be the seed's own:
one naming another key exits 1 with nothing on stdout. Any other identifier prints.
A publisher-only node is checked with the seed's key as the record's; an
any-with-binding node is checked with no trust registry, so a non-`did:key`
identifier reads `key_unbound` (attention), printed on stderr, exit 0: a verifier binds
it only through a registry fetched from its declared URL. A `supersedes` moves the
record's status only when `signer.identifier` is the record's own and a verifier can
bind the signing key to it: by derivation for a `did:key`, and otherwise through the
record's own signing key or a registry fetched from its declared URL.

### `view`

```sh
typedstandards view --signed <file> --visibility <state> [--attestation <file>]... [--withdrawal <file>]...
                    [--trust-registry-url <url>] [--package-url <url>] [--title <text>]
```

Builds the commitment view a host serves, with produce-core's `buildCommitmentView`,
and prints it with the signed package inline. Every signed claim in the view is copied
from the package; the flags supply only what a host decides. `--visibility` is
required and never defaulted. For a self-certifying signer (a `did:key` at
`bindingTier` `pseudonymous`) the view omits `trustRegistryUrl`; any other signer
needs `--trust-registry-url`. `--attestation` carries a lifecycle attestation that
`withdraw` or `attest` printed (`withdraws`, `reinstates`, `supersedes` or `revises`)
into the view's `lifecycleAttestations`; `--withdrawal` is an alias, and both may be
given. Each must target this record. A `corroborates` or `contradicts` node exits 2:
this version carries no claim-to-claim node in a view. The view's `lifecycle` is what
verify-core's `verifyLifecycleChain` reads from the carried nodes: `active`,
`withdrawn`, or `superseded` with the successor's envelope hash. `view` builds no view
of a record that does not verify.

### `verify`

```sh
typedstandards verify --input <file|-> [--blob <file>]... [--json]
```

Runs verify-core's checks offline over what `sign` or `view` printed, and prints
`{ok, nodeId, failures}`. `--json` adds `checks` (verify-core's full result, every
check's fields) and `lifecycle` (the lifecycle resolution from the carried
lifecycle attestations). `--blob` supplies a referenced file's bytes. Files are matched to the
record's BlobRefs by SHA-256; when exactly one file and one reference are left over,
they are paired, so a changed file reads as a mismatch.

`verify` reads only what `sign` and `view` print. Nothing either prints carries an
RFC 3161 token or a transparency-log entry, so checks #7 and #8 do not arise, and an
input with such keys is refused.

**The exit rule.** `verify` exits 1 when any check reads **alarm** on
typedstandards.org's verifier, and 0 otherwise. The tiers are copied from the site's
`apps/web/src/lib/trust-signal.ts` at `0bb0527`, table by table, and a test in this
package compares the copy with the site's file:

| Check | Alarm on | Site table (trust-signal.ts) |
|---|---|---|
| #1 envelope integrity | `altered` | `ENVELOPE_INTEGRITY_ALTERED`, :141 |
| #2 signature | invalid | `SIGNATURE_SIGNALS`, :185 |
| #4 content hash | `content_hash_mismatch` | `CONTENT_HASH_SIGNALS`, :228 |
| #5 key trust | `revoked`, `deprecated_invalid` | `KEY_TRUST_SIGNALS`, :283 |
| #6 key id | `signingKeyId_mismatch` | `SIGNING_KEY_ID_SIGNALS`, :402 |
| #9 referenced files | `invalid_ref`, `size_mismatch`, `hash_mismatch` | `BLOB_REF_REASON_SIGNALS`, :678 |
| #10 carried lifecycle nodes | altered, or a signature that does not verify | `LIFECYCLE_ATTESTATION_NODE_ID_SIGNALS`, :763; `LIFECYCLE_ATTESTATION_SIGNATURE_SIGNALS`, :750 |
| #14 signer identity | `signer_identity_mismatch`, `key_derived_mismatch` | `SIGNER_IDENTITY_SIGNALS`, :855 |

**Attention** readings print on stderr and do not fail. Examples: a signer whose key
no registry was consulted for (`registry_unavailable`; `verify` runs offline), and a
referenced file that was not supplied. Exit 0 means the record is intact and signed,
and that no check contradicts it. It does not mean a registry vouches for the key:
that is `checks.keyTrust` in `--json`. A withdrawn record still verifies; its status
is `lifecycle.status`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | verification failed: `sign`'s, `withdraw`'s or `attest`'s own result, `view`'s input, or `verify`'s record |
| 2 | usage or input error |
| 3 | the signing seed's variable is missing or malformed |
| 4 | internal error |

## Use from CI

The job's secret store sets the variable for the one step that signs. For example,
in GitHub Actions:

```yaml
- name: Sign the notebook
  env:
    TYPEDSTANDARDS_SIGNING_SEED_B64: ${{ secrets.TYPEDSTANDARDS_SIGNING_SEED_B64 }}
  run: |
    npx --yes @typedstandards/cli@0.1.0 sign --input record.json --output-file analysis.ipynb > signed.json
    npx --yes @typedstandards/cli@0.1.0 view --signed signed.json --visibility public > bundle.json
    npx --yes @typedstandards/cli@0.1.0 verify --input bundle.json
```

A checked-in input template plus the file's bytes describe the record fully. Pin the
CLI's version, since a produce-core minor that changes an input rule reaches callers
as a CLI release.

## License

MIT
