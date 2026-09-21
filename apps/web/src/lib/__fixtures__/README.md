# Offline-bundle fixtures

Fixtures for `../q15-offline-bundle.test.ts`, which verifies each one through the
site's full verify flow in bundle mode with a `fetch` stub that throws on any call.

| File | What it is | Source |
|---|---|---|
| `q15-d67b8e.json` | Captured commitment bundle, full depth: key `active`, RFC 3161 chain, Rekor inclusion, a two-node lifecycle chain | Captured from the reference implementation's production `/api/evidence/<slug>/commitment?inline=1` endpoint (Q15a), committed in `fbc6eff` (2026-06-08). Package hash `d67b8e01…770a` |
| `q15-255b8e.json` | Captured commitment bundle, production parity: key `active`, RFC 3161, Rekor inclusion, no lifecycle history | Same capture, same commit. Package hash `255b8e73…b9e4` |
| `q15-da9246.json` | Captured commitment bundle, legacy: `legacy_embedded` key, RFC 3161, no Rekor entry, withdrawn | Same capture, same commit. Package hash `da9246cd…af7f` |
| `q15-self-certified.json` | Minted commitment bundle: a `scripted-recomputation` package under `raw-bytes/v1`, signed by a self-certifying `did:key` signer, with no trust registry | Minted by `q15-self-certified.mint.ts` with the shipped cores (below) |
| `q15-self-certified.output.csv` | The content file that bundle fingerprints and carries inline as `output` | Written by hand for this fixture (Wave N14 P7) |
| `q15-self-certified.mint.ts` | The program that mints `q15-self-certified.json` | Wave N14 P7 |

The three captured bundles are signed production bytes. They cannot be re-minted,
and they stay as captured. The `/api/evidence/` route segment is as captured; the
canonical segment is now `/api/records/`, with `/api/evidence/` a permanent alias.
The test file's header says what each one exercises.

## `q15-self-certified.json`

A self-contained commitment bundle (the §8.8 `?inline=1` shape: the §8.8.1
commitment view plus the package inline) that an independent implementation can
verify with no network and no Typed Standards code. It exercises two additions in
specification v0.1.9 at once:

- **hub ADR-0029**: the `scripted-recomputation` producer profile and the
  `raw-bytes/v1` content rule, under which `contentHash.sha256` is the ordinary
  SHA-256 of one file's bytes;
- **hub ADR-0030**: a self-certifying signer whose identifier is `did:key` derived
  from the signing key, checked with no trust registry.

It is for implementers outside this repository. An external command-line tool's
published plan uses this project's byte-golden fixtures as interop tests: the qsv
project by datHere, in [dathere/qsv#4448](https://github.com/dathere/qsv/issues/4448),
lists under "Phase 2 (signing)" in its
[investigation comment](https://github.com/dathere/qsv/issues/4448#issuecomment-5440060941):
"vendor produce-core's byte-golden fixtures as interop tests so the Rust producer
provably emits packages `verify-core` accepts."

### The key proves nothing about anyone

The signing key was generated for this fixture from a published seed, so anyone can
compute its private half. A signature by it shows only that the bytes were not
changed after signing by someone who ran the steps below. It says nothing about who
signed, and it must never be trusted for anything else.

### What it contains

| Field | Value |
|---|---|
| `producerProfile` | `scripted-recomputation/interop-fixture` (the subtype names this fixture) |
| `metadata.captureMethod` | `script-run`: the mint program reads a file that already exists on disk (the committed CSV) and packages its bytes. It did not compute those bytes in the same process, which is what `tool-emitted` would claim (ADR-0029 §2) |
| `metadata.contentProfile` | absent (ADR-0029 §3 item 6) |
| `type` | `content/analysis/v1` |
| `contentCanonicalization` | `https://typedstandards.org/canonicalization/raw-bytes/v1` |
| `output` | the text of `q15-self-certified.output.csv`, inline (valid UTF-8, so it round-trips through a JSON string byte for byte) |
| `contentHash.sha256` | the SHA-256 of that file's bytes |
| `prompt` | the task the program performed, `visibility: "full_text"` |
| `queries` | one entry naming the mint program, with the input file and its SHA-256 in `arguments` |
| `cost` | `{"model": "none"}` |
| `skillMetadata` | `{}` |
| `trace` | `{"resourceSpans": []}` |
| `signer` | `bindingTier: "pseudonymous"`, `identifier` the `did:key` string, a `displayName` that describes the fixture |
| `kid` and `metadata.signingKeyId` | the same `did:key` string (ADR-0030 §5) |
| `packageId`, `createdAt` | `abcdefab-cdef-4abc-8def-abcdefabcdef`, `2026-09-21T00:00:00.000Z` |
| signature | Ed25519ph over the UTF-8 bytes of the envelope-hash hex string (spec §8.3.1) |

The bundle carries no `trustRegistryUrl`, no `trustRegistry`, no `signerIdentity`
block, no `packageUrl`, no RFC 3161 token and no Rekor entry. The view's
`contentProfile: "default"` is the §8.8.1 view's value for a package that carries no
content-profile key.

### The seed

The 32-byte Ed25519 seed is the SHA-256 of the 45-byte ASCII string
`typedstandards/fixtures/q15-self-certified/v1`, with no trailing newline:

```sh
printf %s 'typedstandards/fixtures/q15-self-certified/v1' | shasum -a 256
```

The mint program derives it at run time. It is not written into the bundle or any
other file.

### Re-minting

From the repository root, with Node 22:

```sh
npm ci
npm run build:verify-core
npm run build --workspace @typedstandards/produce-core
node --experimental-strip-types \
  apps/web/src/lib/__fixtures__/q15-self-certified.mint.ts \
  > apps/web/src/lib/__fixtures__/q15-self-certified.json
git diff --exit-code apps/web/src/lib/__fixtures__/q15-self-certified.json
```

The program reads the CSV beside it and prints the bundle as
`JSON.stringify(bundle, null, 2)` plus a newline. It uses produce-core's
`buildEnvelope`, `signEnvelopeHash`, `buildCommitmentView` (with no
`trustRegistryUrl`) and `deriveKeyDerivedIdentifierFromKey`. Ed25519 signatures are
deterministic and every input is fixed, so the output is the same bytes on every run.
`q15-offline-bundle.test.ts` re-mints it and asserts byte equality with the
committed file.

### Checking it without this repository's code

The content hash is the file's ordinary SHA-256:

```sh
shasum -a 256 q15-self-certified.output.csv
jq -r '.package.contentHash.sha256' q15-self-certified.json
```

The signer identifier, per ADR-0030 §2: base64-decode the envelope's `publicKey` to
44 bytes of SPKI DER, check the 12-byte prefix `302a300506032b6570032100`, take the
remaining 32 raw bytes, prefix `ed 01`, base58btc-encode (Bitcoin alphabet) and
prepend `did:key:z`. The result must equal `signer.identifier` byte for byte.

The envelope hash (`packageHash`) is the SHA-256 of the RFC 8785 (JCS) serialization
of `package`, which is the unsigned envelope: the signature is carried beside it, not
inside it.

Both, in Python 3 with the standard library only:

```python
import base64, hashlib, json
b = json.load(open("q15-self-certified.json", encoding="utf-8"))
der = base64.b64decode(b["signature"]["publicKey"])
assert len(der) == 44 and der[:12] == bytes.fromhex("302a300506032b6570032100")
mc = bytes.fromhex("ed01") + der[12:]
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n, s = int.from_bytes(mc, "big"), ""
while n:
    n, r = divmod(n, 58); s = A[r] + s
print("did:key", "did:key:z" + s == b["package"]["signer"]["identifier"])

def jcs(v):  # RFC 8785 for this fixture: it holds no numbers
    if isinstance(v, dict):
        return "{" + ",".join(jcs(k) + ":" + jcs(v[k])
                              for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)
print("envelope hash",
      hashlib.sha256(jcs(b["package"]).encode()).hexdigest() == b["packageHash"])
```

The signature is Ed25519ph (RFC 8032 §5.1, SHA-512 prehash, empty context), so a
plain Ed25519 verifier rejects it; use an Ed25519ph verifier over the UTF-8 bytes of
the `packageHash` hex string.

### What each check reports

Measured with `@typedstandards/verify-core` at this commit, through the site's flow
in bundle mode, with zero network calls:

| Check | Result |
|---|---|
| #1 envelope integrity | `verified` (recomputed hash equals `packageHash`) |
| #2 signature | valid (Ed25519ph) |
| #3 canonicalization rule | `ok`, `raw-bytes/v1` |
| #4 content hash | `ok`, `sha256` matched, from the inline `output` |
| #5 key trust | `self_certified`, `verified: false` |
| #6 `kid` and `metadata.signingKeyId` | equal |
| #7 RFC 3161 timestamp | absent (no token), calm |
| #8 Rekor inclusion | absent (no entry), calm |
| #9 BlobRefs | none |
| #10 lifecycle | `active`, source `none` |
| #12 type | `ok`, `content/analysis/v1` |
| #13 node id | equals `packageHash` |
| #14 signer identity | `key_derived_match` |
| #15 capture method | `ok`, profile type `scripted-recomputation`, `script-run` |
| #16 content profile | `contentProfile_absent` |
| site verdict | tier `normal`, "Signature valid — self-certified signer"; never `verified` |
| site `fullyOffline` | `true` |
