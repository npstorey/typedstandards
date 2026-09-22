// One fetch per BlobRef URL per `verifyRecord` (typedstandards#90).
//
// Under raw-bytes/v1 with a BlobRef `output`, check #9 (BlobRef integrity) and
// check #4 (content hash) both need the file's bytes. Each case below counts
// the requests a `verifyRecord` call makes, per URL, and asserts what checks #4
// and #9 report, which must be what they reported when each check fetched on
// its own: the status assertions come first, the count last.
//
// Synthetic packages; the file digest is computed in the test from the bytes
// it names, and pinned against `shasum -a 256` output in raw-bytes.test.ts
// (FILE_SHA256 there; the same text).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyRecord,
  sha256Hex,
  utf8ToBytes,
  RAW_BYTES_CANONICALIZATION,
  LEGACY_JSON_CANONICALIZATION,
  type FetchLike,
  type VerifyResult,
} from './index.ts';

const FILE_TEXT = 'column_a,column_b\r\nvalue é,2\n';
const FILE_BYTES = utf8ToBytes(FILE_TEXT);
const FILE_SHA256 = sha256Hex(FILE_BYTES);
const OUTPUT_URL = 'https://blobs.example.test/file.csv';
const TRACE_URL = 'https://blobs.example.test/trace.json';
const TRACE_BYTES = utf8ToBytes('{"resourceSpans":[]}');

type Reply = Uint8Array | 'throw' | 'body-throws' | { status: number };

/** A fetch that records every URL it is asked for and answers from `replies`. */
function countingFetch(replies: Record<string, Reply>): FetchLike & { calls: string[] } {
  const calls: string[] = [];
  const f: FetchLike = async (url) => {
    calls.push(url);
    const reply = replies[url];
    if (reply === undefined || reply === 'throw') throw new Error('network unavailable');
    const status = reply instanceof Uint8Array || reply === 'body-throws' ? 200 : reply.status;
    const body = reply instanceof Uint8Array ? reply : new Uint8Array(0);
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      json: async () => JSON.parse(new TextDecoder().decode(body)) as unknown,
      text: async () => new TextDecoder().decode(body),
      arrayBuffer: async () => {
        if (reply === 'body-throws') throw new Error('body stream failed');
        return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
      },
    };
  };
  return Object.assign(f, { calls });
}

function countOf(calls: string[], url: string): number {
  return calls.filter((c) => c === url).length;
}

function rawBytesBlobPkg(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    metadata: { captureMethod: 'script-run' },
    producerProfile: 'scripted-recomputation/example',
    contentCanonicalization: RAW_BYTES_CANONICALIZATION,
    output: {
      ref: `blob:sha256:${FILE_SHA256}`,
      url: OUTPUT_URL,
      contentType: 'text/csv',
      size: FILE_BYTES.byteLength,
    },
    contentHash: { sha256: FILE_SHA256 },
    ...extra,
  };
}

async function run(pkg: Record<string, unknown>, fetch: FetchLike): Promise<VerifyResult> {
  return verifyRecord({ package: pkg, packageHash: 'a'.repeat(64) }, { registry: undefined, fetch });
}

test('#90: a raw-bytes/v1 BlobRef output is fetched once; #4 ok and #9 ok', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: FILE_BYTES });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'ok');
  assert.equal(r.blobRefsVerified, true);
  assert.equal(r.blobRefs[0]?.ok, true);
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: when the fetch throws, it is tried once; #4 content_bytes_unavailable, #9 fetch_failed', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: 'throw' });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'content_bytes_unavailable');
  assert.equal(r.blobRefsVerified, false);
  assert.equal(r.blobRefs[0]?.reason, 'fetch_failed');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: when the fetch answers 404, it is tried once; #4 content_bytes_unavailable, #9 fetch_failed', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: { status: 404 } });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'content_bytes_unavailable');
  assert.equal(r.blobRefs[0]?.reason, 'fetch_failed');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: when the body cannot be read, it is fetched once; #4 content_bytes_unavailable, #9 fetch_failed', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: 'body-throws' });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'content_bytes_unavailable');
  assert.equal(r.blobRefs[0]?.reason, 'fetch_failed');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: bytes of the right size that differ: fetched once; #4 content_hash_mismatch, #9 hash_mismatch', async () => {
  const altered = utf8ToBytes(FILE_TEXT.replace('2', '3'));
  assert.equal(altered.byteLength, FILE_BYTES.byteLength);
  const fetch = countingFetch({ [OUTPUT_URL]: altered });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'content_hash_mismatch');
  assert.equal(r.blobRefsVerified, false);
  assert.equal(r.blobRefs[0]?.reason, 'hash_mismatch');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: bytes of another size: fetched once; #4 content_hash_mismatch, #9 size_mismatch', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: utf8ToBytes(FILE_TEXT + 'x') });
  const r = await run(rawBytesBlobPkg(), fetch);
  assert.equal(r.contentHash?.status, 'content_hash_mismatch');
  assert.equal(r.blobRefs[0]?.reason, 'size_mismatch');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});

test('#90: each BlobRef URL is fetched once: output and trace', async () => {
  const trace = {
    ref: `blob:sha256:${sha256Hex(TRACE_BYTES)}`,
    url: TRACE_URL,
    contentType: 'application/json',
    size: TRACE_BYTES.byteLength,
  };
  const fetch = countingFetch({ [OUTPUT_URL]: FILE_BYTES, [TRACE_URL]: TRACE_BYTES });
  const r = await run(rawBytesBlobPkg({ trace }), fetch);
  assert.equal(r.contentHash?.status, 'ok');
  assert.deepEqual(
    r.blobRefs.map((b) => [b.field, b.ok]),
    [
      ['output', true],
      ['trace', true],
    ],
  );
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
  assert.equal(countOf(fetch.calls, TRACE_URL), 1);
  assert.equal(fetch.calls.length, 2);
});

test('#90: the once-per-URL scope is one verifyRecord call; a second call fetches again', async () => {
  const fetch = countingFetch({ [OUTPUT_URL]: FILE_BYTES });
  const first = await run(rawBytesBlobPkg(), fetch);
  const second = await run(rawBytesBlobPkg(), fetch);
  assert.equal(first.contentHash?.status, 'ok');
  assert.equal(second.contentHash?.status, 'ok');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 2);
});

test('#90 control: a legacy-json/v1 package with a BlobRef output is fetched once, by #9 only', async () => {
  const pkg = { ...rawBytesBlobPkg(), contentCanonicalization: LEGACY_JSON_CANONICALIZATION };
  const fetch = countingFetch({ [OUTPUT_URL]: FILE_BYTES });
  const r = await run(pkg, fetch);
  assert.equal(r.blobRefsVerified, true);
  assert.notEqual(r.contentHash?.status, 'content_bytes_unavailable');
  assert.equal(countOf(fetch.calls, OUTPUT_URL), 1);
});
