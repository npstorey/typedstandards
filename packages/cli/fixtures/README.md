# CLI test fixtures

Neither directory is published: `package.json` `files` lists `dist` and the docs only.

## `host-served/`

A platform-signed layout node, as a host serves it, and its proofs. Copied byte for byte
from `npstorey/civic-ai-tools-website` at `4777b79`:

| File | Source | SHA-256 |
|---|---|---|
| `770ed52e2abfc0c7d4626953c9f715c11a50e63bd911fa2bed56b77a76fe0ee7.json` | `public/.well-known/layouts/<nodeId>.json`: the node's commitment view with its package inline | `01548e1dc3b4bb6fdd2c83d43c9a6cd1816fb14760516113b63d888291700b6d` |
| `770ed52e2abfc0c7d4626953c9f715c11a50e63bd911fa2bed56b77a76fe0ee7.proofs.json` | `public/.well-known/layouts/<nodeId>.proofs.json`: its RFC 3161 token and its transparency-log entry, inclusion proof and entry body | `e193701eea342b520cbee8dd667d63fdefc579aef42bc408f276eb1e23bd77f9` |

`src/host-served.test.ts` asserts both digests, and that produce-core's
`buildCommitmentView` over the node's fields gives the served view. Its tests build
a host-served commitment view from these files with produce-core: the proofs, the
keys a host adds, and a carried attestation signed in the test.

## `no-change/verify-0.2.2.json`

What 0.2.2's `verify` printed for each input it accepts (stdout and stderr as SHA-256,
and the exit code), written by `src/no-change.test.ts` with
`UPDATE_NO_CHANGE_GOLDEN=1` from the source of 0.2.2. That test holds every later
version to it.
