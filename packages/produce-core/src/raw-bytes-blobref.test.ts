// raw-bytes/v1 over a BlobRef on `buildEnvelope` (typedstandards#113, G0 D8;
// spec §8.2, SPEC:565): when the rule is raw-bytes/v1 and `output` is a BlobRef,
// `contentHash.sha256` MUST equal the hex part of `output.ref`, so the package
// is built without the file's bytes. A malformed reference throws. An inline
// string output, and a BlobRef under any other rule, keep their hashes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  buildEnvelope,
  computeContentHashSha256,
  computeEnvelopeHash,
  LEGACY_JSON_CANONICALIZATION,
  RAW_BYTES_CANONICALIZATION,
  type BlobRef,
  type EnvelopeInput,
  type RecordPackage,
} from './index.ts';

const golden = JSON.parse(
  readFileSync(new URL('./__fixtures__/reference-golden.json', import.meta.url), 'utf8'),
) as { envelopeCases: Array<{ name: string; input: Record<string, unknown> }> };

const captured = (name: string) => structuredClone(golden.envelopeCases.find((c) => c.name === name)!.input);
const v01 = () => captured('v01-default') as unknown as EnvelopeInput;
/** The captured BlobRef; the bytes it names are the 7 bytes of `content`. */
const BLOB = captured('legacy-blobref-output')['output'] as BlobRef;

function build(input: EnvelopeInput): { pkg: RecordPackage; envelopeHash: string } {
  let built: { pkg: RecordPackage; envelopeHash: string } | undefined;
  assert.doesNotThrow(() => {
    built = buildEnvelope(input);
  });
  return built!;
}

test('raw-bytes/v1 with a BlobRef output signs: contentHash.sha256 is the hex of output.ref', () => {
  const { pkg, envelopeHash } = build({ ...v01(), contentCanonicalization: RAW_BYTES_CANONICALIZATION, output: BLOB });
  const hex = BLOB.ref.slice('blob:sha256:'.length);
  assert.equal(pkg.contentHash?.sha256, hex);
  assert.equal(hex, createHash('sha256').update('content').digest('hex'), 'the ref names the bytes of "content"');
  assert.deepEqual(pkg.output, BLOB);
  assert.equal(pkg.contentCanonicalization, RAW_BYTES_CANONICALIZATION);
  assert.equal(envelopeHash, computeEnvelopeHash(pkg as unknown as Record<string, unknown>));
});

test('raw-bytes/v1 with a malformed BlobRef reference throws', () => {
  const malformed = [
    { ...BLOB, ref: 'blob:sha256:XYZ' },
    { ...BLOB, ref: `blob:sha1:${'a'.repeat(40)}` },
    { ...BLOB, ref: `blob:sha256:${'A'.repeat(64)}` },
  ];
  for (const output of malformed) {
    assert.throws(
      () => buildEnvelope({ ...v01(), contentCanonicalization: RAW_BYTES_CANONICALIZATION, output: output as BlobRef }),
      /Invalid blob reference/,
      output.ref,
    );
  }
});

test('raw-bytes/v1 with an object output that is not a BlobRef throws', () => {
  const { url: _url, ...noUrl } = BLOB;
  for (const output of [noUrl, { ...BLOB, size: '7' }, {}]) {
    assert.throws(
      () => buildEnvelope({ ...v01(), contentCanonicalization: RAW_BYTES_CANONICALIZATION, output: output as unknown as BlobRef }),
      /raw-bytes\/v1 needs output to be an inline string or a BlobRef/,
    );
  }
});

test('raw-bytes/v1 with an inline string output keeps its hash: the SHA-256 of the UTF-8 bytes', () => {
  const { pkg } = build({ ...v01(), contentCanonicalization: RAW_BYTES_CANONICALIZATION, output: 'Around 400,000.' });
  assert.equal(pkg.contentHash?.sha256, createHash('sha256').update('Around 400,000.', 'utf8').digest('hex'));
});

test('legacy-json/v1 with a BlobRef output keeps its hash: the package minus contentHash', () => {
  const { pkg } = build({ ...v01(), output: BLOB });
  assert.equal(pkg.contentCanonicalization, LEGACY_JSON_CANONICALIZATION);
  const { contentHash: _c, ...rest } = pkg;
  assert.equal(pkg.contentHash?.sha256, computeContentHashSha256(rest as unknown as Record<string, unknown>, LEGACY_JSON_CANONICALIZATION));
  assert.notEqual(pkg.contentHash?.sha256, BLOB.ref.slice('blob:sha256:'.length));
});
