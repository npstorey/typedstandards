// The raw-bytes/v1 content rule (hub ADR-0029 §4): checks #3 and #4.
//   - #3 resolves the raw-bytes/v1 URI `ok`.
//   - #4, inline `output`: the SHA-256 of its UTF-8 bytes.
//   - #4, BlobRef `output`: the bytes obtained through the injected fetcher are
//     hashed. `ok` on a match; `content_hash_mismatch` when they differ, and when
//     `contentHash.sha256` differs from `output.ref`'s hex (decided from the
//     package alone); `content_bytes_unavailable` when the bytes cannot be
//     obtained. Never `ok` without hashing.
//
// Synthetic packages; every digest below is computed in the test from the bytes
// it names, and one is pinned against `shasum -a 256` output (see FILE_SHA256).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveContentCanonicalization,
  verifyContentHash,
  verifyContentHashWithFetch,
  verifyRecord,
  computeContentHashSha256,
  sha256Hex,
  utf8ToBytes,
  RAW_BYTES_CANONICALIZATION,
  KNOWN_CANONICALIZATION_RULES,
  CONTENT_HASH_STATUSES,
  type FetchLike,
} from './index.ts';

// The file the BlobRef cases fingerprint. Includes a non-ASCII character, a CRLF
// and a trailing newline, none of which the rule normalizes.
const FILE_TEXT = 'column_a,column_b\r\nvalue é,2\n';
const FILE_BYTES = utf8ToBytes(FILE_TEXT);
// `printf 'column_a,column_b\r\nvalue \xc3\xa9,2\n' | shasum -a 256`
const FILE_SHA256 = 'd8e8736d78b0fc601d3f247b6a7e33936b3fcba46832acaf2303ada0c1055698';

const OTHER_SHA256 = 'c'.repeat(64);

function stubFetch(body: Uint8Array | null, status = 200): FetchLike & { calls: string[] } {
  const calls: string[] = [];
  const f: FetchLike = async (url) => {
    calls.push(url);
    if (body === null) throw new Error('unreachable');
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      json: async () => JSON.parse(new TextDecoder().decode(body)) as unknown,
      text: async () => new TextDecoder().decode(body),
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
    };
  };
  return Object.assign(f, { calls });
}

function inlinePkg(output: string, sha256: string): Record<string, unknown> {
  return {
    metadata: { captureMethod: 'script-run' },
    producerProfile: 'scripted-recomputation/example',
    contentCanonicalization: RAW_BYTES_CANONICALIZATION,
    output,
    contentHash: { sha256 },
  };
}

function blobPkg(refHex: string, sha256: string): Record<string, unknown> {
  return {
    metadata: { captureMethod: 'script-run' },
    producerProfile: 'scripted-recomputation/example',
    contentCanonicalization: RAW_BYTES_CANONICALIZATION,
    output: {
      ref: `blob:sha256:${refHex}`,
      url: 'https://blobs.example.test/file.csv',
      contentType: 'text/csv',
      size: FILE_BYTES.byteLength,
    },
    contentHash: { sha256 },
  };
}

test('the fixture file digest equals the one shasum prints (no normalization)', () => {
  assert.equal(sha256Hex(FILE_BYTES), FILE_SHA256);
});

test('#3: the raw-bytes/v1 URI is registered and resolves ok', () => {
  assert.equal(
    RAW_BYTES_CANONICALIZATION,
    'https://typedstandards.org/canonicalization/raw-bytes/v1',
  );
  assert.ok(KNOWN_CANONICALIZATION_RULES.includes(RAW_BYTES_CANONICALIZATION));
  assert.deepEqual(resolveContentCanonicalization(inlinePkg(FILE_TEXT, FILE_SHA256)), {
    status: 'ok',
    rule: RAW_BYTES_CANONICALIZATION,
  });
});

test('#4 status list gains content_bytes_unavailable', () => {
  assert.ok((CONTENT_HASH_STATUSES as readonly string[]).includes('content_bytes_unavailable'));
});

test('#4 inline: ok when the UTF-8 bytes of output hash to contentHash.sha256', () => {
  const pkg = inlinePkg(FILE_TEXT, FILE_SHA256);
  assert.equal(computeContentHashSha256(pkg, RAW_BYTES_CANONICALIZATION), FILE_SHA256);
  const r = verifyContentHash(pkg, resolveContentCanonicalization(pkg));
  assert.equal(r.status, 'ok');
  assert.equal(r.matched, 'sha256');
});

test('#4 inline: content_hash_mismatch when one byte differs (no normalization)', () => {
  // CRLF → LF: a text-normalizing rule would call these equal; raw-bytes does not.
  const pkg = inlinePkg(FILE_TEXT.replace('\r\n', '\n'), FILE_SHA256);
  assert.equal(verifyContentHash(pkg, resolveContentCanonicalization(pkg)).status, 'content_hash_mismatch');
});

test('#4 BlobRef: ok when the fetched bytes hash to contentHash.sha256', async () => {
  const pkg = blobPkg(FILE_SHA256, FILE_SHA256);
  const fetch = stubFetch(FILE_BYTES);
  const r = await verifyContentHashWithFetch(pkg, resolveContentCanonicalization(pkg), undefined, {
    fetch,
  });
  assert.equal(r.status, 'ok');
  assert.equal(r.matched, 'sha256');
  assert.deepEqual(fetch.calls, ['https://blobs.example.test/file.csv']);
});

test('#4 BlobRef: content_hash_mismatch when the fetched bytes differ', async () => {
  const pkg = blobPkg(FILE_SHA256, FILE_SHA256);
  const altered = utf8ToBytes(FILE_TEXT.replace('2', '3'));
  const r = await verifyContentHashWithFetch(pkg, resolveContentCanonicalization(pkg), undefined, {
    fetch: stubFetch(altered),
  });
  assert.equal(r.status, 'content_hash_mismatch');
});

test('#4 BlobRef: content_hash_mismatch when contentHash.sha256 differs from output.ref, without fetching', async () => {
  const pkg = blobPkg(OTHER_SHA256, FILE_SHA256);
  // Decided from the package alone: the sync check, holding no bytes, reports it.
  assert.equal(
    verifyContentHash(pkg, resolveContentCanonicalization(pkg)).status,
    'content_hash_mismatch',
  );
  // Even with bytes that match contentHash.sha256, the two signed digests conflict.
  const fetch = stubFetch(FILE_BYTES);
  const r = await verifyContentHashWithFetch(pkg, resolveContentCanonicalization(pkg), undefined, {
    fetch,
  });
  assert.equal(r.status, 'content_hash_mismatch');
  assert.deepEqual(fetch.calls, [], 'no fetch is needed to decide it');
});

test('#4 BlobRef: content_bytes_unavailable when the fetch throws, or answers non-2xx', async () => {
  const pkg = blobPkg(FILE_SHA256, FILE_SHA256);
  const res = resolveContentCanonicalization(pkg);
  assert.equal(
    (await verifyContentHashWithFetch(pkg, res, undefined, { fetch: stubFetch(null) })).status,
    'content_bytes_unavailable',
  );
  assert.equal(
    (await verifyContentHashWithFetch(pkg, res, undefined, { fetch: stubFetch(FILE_BYTES, 404) }))
      .status,
    'content_bytes_unavailable',
  );
});

test('#4 BlobRef: the synchronous check never reports ok without the bytes', () => {
  const pkg = blobPkg(FILE_SHA256, FILE_SHA256);
  const res = resolveContentCanonicalization(pkg);
  assert.equal(verifyContentHash(pkg, res).status, 'content_bytes_unavailable');
  assert.equal(verifyContentHash(pkg, res, undefined, FILE_BYTES).status, 'ok');
});

test('verifyRecord: #4 hashes a raw-bytes BlobRef through deps.fetch; #9 is unchanged', async () => {
  const pkg = blobPkg(FILE_SHA256, FILE_SHA256);
  const ok = await verifyRecord(
    { package: pkg, packageHash: 'a'.repeat(64) },
    { registry: undefined, fetch: stubFetch(FILE_BYTES) },
  );
  assert.equal(ok.contentCanonicalization?.status, 'ok');
  assert.equal(ok.contentHash?.status, 'ok');
  assert.equal(ok.blobRefsVerified, true);

  const unavailable = await verifyRecord(
    { package: pkg, packageHash: 'a'.repeat(64) },
    { registry: undefined, fetch: stubFetch(null) },
  );
  assert.equal(unavailable.contentHash?.status, 'content_bytes_unavailable');
  // Check #9 reports the same unfetchable blob as it always has.
  assert.equal(unavailable.blobRefsVerified, false);
  assert.equal(unavailable.blobRefs[0]?.reason, 'fetch_failed');
});
