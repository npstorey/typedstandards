// #105, ruled A: bundle mode requests nothing. A fully offline run over a package that
// references content stored separately (a BlobRef) sends no request for it; check #9,
// and check #4 under raw-bytes/v1, read "not checked offline" (attention), and the
// offline note says a check by URL covers the referenced file. The registry and the
// directory already follow the rule (#93, #97).
//
// The package is minted in process, as blob-ref-verdict.test.ts mints it: Ed25519 via
// node:crypto, signed over the package-hash string, raw-bytes/v1 with a BlobRef
// `output` and a BlobRef `trace`, each digest computed here from the bytes it names.
// The stub answers every request with the right bytes and records it, so a request is
// what fails the offline test, not a file that could not be fetched.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { recomputePackageHash, sha256Hex, utf8ToBytes, RAW_BYTES_CANONICALIZATION } from '@typedstandards/verify-core';
import { resolveInput, verifyResolved, presentVerification, HOST_DIRECTORY, type CheckRow } from './verify-flow.ts';
import { HOST_DIRECTORY_PATH } from './host-directory.ts';

const REGISTRY_URL = 'https://registry-host.test/trust-registry.json';
const COMMITMENT_URL = 'https://registry-host.test/api/records/p105-blob/commitment';
const OUTPUT_URL = 'https://blobs.registry-host.test/output.csv';
const TRACE_URL = 'https://blobs.registry-host.test/trace.json';
const OUTPUT_BYTES = utf8ToBytes('column_a,column_b\r\nvalue,2\n');
const TRACE_BYTES = utf8ToBytes('{"resourceSpans":[]}');

const blobRef = (bytes: Uint8Array, url: string, contentType: string) => ({
  ref: `blob:sha256:${sha256Hex(bytes)}`,
  url,
  contentType,
  size: bytes.byteLength,
});

/** A signed commitment carrying its package and its registry (a bundle), for a package
 *  under raw-bytes/v1 whose `output` and `trace` are BlobRefs — or, with `refs: false`,
 *  a package whose output is inline and which references nothing. */
function mintBundle(opts: { refs: boolean; rekorEntryId?: string } = { refs: true }) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  const kid = 'test:synthetic-2026';
  const signer = { bindingTier: 'platform', identifier: 'urn:civic-record:platform:synthetic-publisher' };
  const pkg: Record<string, unknown> = {
    protocolVersion: '0.1.0',
    type: 'content/analysis/v1',
    signer,
    metadata: { signingKeyId: kid },
    ...(opts.refs
      ? {
          contentCanonicalization: RAW_BYTES_CANONICALIZATION,
          output: blobRef(OUTPUT_BYTES, OUTPUT_URL, 'text/csv'),
          contentHash: { sha256: sha256Hex(OUTPUT_BYTES) },
          trace: blobRef(TRACE_BYTES, TRACE_URL, 'application/json'),
        }
      : { output: 'inline output' }),
  };
  const packageHash = recomputePackageHash(pkg);
  const registry = {
    generatedAt: '2026-09-21T00:00:00.000Z',
    keys: [
      {
        kid,
        publicKey: publicKeyB64,
        status: 'active',
        activatedAt: '2026-01-01T00:00:00.000Z',
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: signer,
      },
    ],
  };
  const commitment = {
    protocolVersion: '0.1.0',
    packageHash,
    package: pkg,
    signer,
    signature: {
      algorithm: 'Ed25519',
      publicKey: publicKeyB64,
      signature: Buffer.from(nodeSign(null, Buffer.from(packageHash, 'utf8'), privateKey)).toString('base64'),
      kid,
    },
    trustRegistryUrl: REGISTRY_URL,
    trustRegistry: registry,
    ...(opts.rekorEntryId ? { rekorEntryId: opts.rekorEntryId } : {}),
  };
  return { commitment, registry };
}

/** Run the page on `raw` in `mode`, every request answered correctly and recorded. */
async function pageWith(mode: 'bundle' | 'url', raw: string, m: ReturnType<typeof mintBundle>) {
  const json: Record<string, unknown> = { [COMMITMENT_URL]: m.commitment, [REGISTRY_URL]: m.registry, [HOST_DIRECTORY_PATH]: HOST_DIRECTORY };
  const files: Record<string, Uint8Array> = { [OUTPUT_URL]: OUTPUT_BYTES, [TRACE_URL]: TRACE_BYTES };
  const calls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const u = String(input);
    calls.push(u);
    if (u in json) {
      return Promise.resolve(new Response(JSON.stringify(json[u]), { status: 200, headers: { 'content-type': 'application/json' } }));
    }
    if (u in files) return Promise.resolve(new Response(new Blob([new Uint8Array(files[u])]), { status: 200 }));
    return Promise.resolve(new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  }) as typeof globalThis.fetch;
  try {
    const resolved = await resolveInput(mode, raw);
    const { input, result } = await verifyResolved(resolved);
    const shown = presentVerification(resolved, input, result);
    return { resolved, result, ...shown, calls };
  } finally {
    globalThis.fetch = real;
  }
}

const rowOf = (rows: CheckRow[], num: string): CheckRow => {
  const r = rows.find((x) => x.num === num);
  assert.ok(r, `row #${num} is rendered`);
  return r;
};

test('#105: bundle mode over a package with a BlobRef requests nothing; the reference reads "not checked offline" and the note says a URL check covers it', async () => {
  const m = mintBundle();
  const page = await pageWith('bundle', JSON.stringify(m.commitment), m);
  assert.equal(page.resolved.fullyOffline, true, 'a fully offline run');
  assert.deepEqual(page.calls, [], 'bundle mode sends no request');

  const row9 = rowOf(page.rows, '9');
  assert.equal(row9.signal.tier, 'attention');
  assert.equal(row9.signal.label, 'Referenced content not checked offline');
  for (const field of ['output', 'trace']) {
    assert.equal(row9.math.find((l) => l.label === field)?.value, 'Not checked offline', field);
  }
  const row4 = rowOf(page.rows, '4');
  assert.equal(row4.signal.tier, 'attention');
  assert.equal(row4.signal.label, 'Content file not checked offline');
  assert.notEqual(page.verdict.headline, 'Verification failed');
  assert.ok(page.verdict.detail.includes('#9 Referenced content'), page.verdict.detail);

  const note = page.independence.parts.map((p) => p.text).join('');
  assert.equal(page.independence.lead, 'Fully offline.');
  assert.ok(note.includes('nothing was fetched'), note);
  assert.match(note, /references content stored separately, which was not requested, so it was not checked\. Verifying the record by its URL checks it\./);
});

test('#105 control: the same record by URL requests each referenced file once, and both verify', async () => {
  const m = mintBundle();
  const page = await pageWith('url', COMMITMENT_URL, m);
  assert.equal(page.resolved.fullyOffline, false);
  assert.deepEqual(page.calls.filter((u) => u === OUTPUT_URL || u === TRACE_URL).sort(), [OUTPUT_URL, TRACE_URL].sort());
  assert.equal(page.result.blobRefsVerified, true);
  assert.equal(rowOf(page.rows, '9').signal.tier, 'verified');
  assert.equal(rowOf(page.rows, '4').signal.tier, 'verified');
  const note = page.independence.parts.map((p) => p.text).join('');
  assert.doesNotMatch(note, /not requested/);
});

test('#105: a bundle with no referenced content keeps the offline note as it was', async () => {
  const m = mintBundle({ refs: false });
  const page = await pageWith('bundle', JSON.stringify(m.commitment), m);
  assert.deepEqual(page.calls, []);
  assert.equal(page.result.signatureValid, true);
  assert.equal(page.result.blobRefsVerified, null);
  const note = page.independence.parts.map((p) => p.text).join('');
  assert.doesNotMatch(note, /not requested/);
});

test('#105: a bundle carrying a transparency-log entry id without its inclusion proof sends no lookup either', async () => {
  // The online lookup is the one other request verify-core can make; a bundle that
  // carries the proof never makes it (#119 Q15). This one names an entry and no proof.
  const m = mintBundle({ refs: true, rekorEntryId: 'ab'.repeat(40) });
  const page = await pageWith('bundle', JSON.stringify(m.commitment), m);
  assert.equal(page.resolved.fullyOffline, true);
  assert.deepEqual(page.calls, [], 'no request to the log or for a referenced file');
  assert.equal(page.result.rekorVerified, false);
  assert.equal(rowOf(page.rows, '8').signal.tier, 'attention');
});
