// A JSON text that repeats a member name within an object is not I-JSON (RFC 7493),
// and the public verifier refuses it before any hash is computed (specification
// §8.2, §9.2 check #1; typedstandards#145), on each path a package arrives by: a
// pasted or uploaded bundle, a commitment fetched by address (which can carry the
// package inline), and a package fetched from the commitment's `packageUrl`. The
// refusal stops the verification: it is not "Content could not be fetched" (check #1
// `unavailable`), and the candidate loop does not try the next address past it.
//
// Fixture: verify-core's negative vector,
// `packages/verify-core/src/__fixtures__/repeated-member-name.bundle.json`
// (provenance in that directory's README.md): `q15-self-certified.json` in this
// directory's __fixtures__, with a second, earlier `summary` member in its package.
// Served by a stubbed fetch, as verify-flow.test.ts's stubPublisher does; the
// package alone is the vector's text of its package, sliced out unchanged.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NotIJsonError, resolveCommitment, resolveInput, VerifyFlowError, type ResolveStep } from './verify-flow.ts';

const VECTOR_TEXT = readFileSync(
  new URL('../../../../packages/verify-core/src/__fixtures__/repeated-member-name.bundle.json', import.meta.url),
  'utf8',
);
/** The package's text in the vector: from the `{` after `"package": ` to the brace before the bundle's last. */
const PACKAGE_TEXT = VECTOR_TEXT.slice(
  VECTOR_TEXT.indexOf('{', VECTOR_TEXT.indexOf('\n  "package": ')),
  VECTOR_TEXT.lastIndexOf('}', VECTOR_TEXT.lastIndexOf('}') - 1) + 1,
);
const PACKAGE_HASH = '9a53cd8ee701f2361cdcf353604bbcde43679f9a55c7cd3759db64d2b7e31dde';
const PUBLISHER = 'https://example-publisher.test';
const PACKAGE_URL = `${PUBLISHER}/packages/record.json`;

/** The refusal names its source, the member name, its pointer, and the rule. */
function refusal(source: RegExp, pointer: string): (err: unknown) => boolean {
  return (err: unknown) => {
    assert.ok(err instanceof VerifyFlowError, `a VerifyFlowError, not ${String(err)}`);
    assert.match(err.message, source);
    assert.ok(
      err.message.includes(`is not I-JSON (RFC 7493): the member name "summary" is repeated in the object at JSON Pointer "${pointer}"`),
      err.message,
    );
    assert.doesNotMatch(err.message, /could not be fetched|altered/i);
    assert.ok(err instanceof NotIJsonError, 'its own VerifyFlowError');
    assert.equal(err.name, 'NotIJsonError');
    assert.equal(err.memberName, 'summary');
    assert.equal(err.pointer, pointer);
    return true;
  };
}

/** Serve `routes` (URL → body text, as JSON) and 404 everything else, recording each URL requested. */
function stub(routes: Record<string, string>): { requested: string[]; restore: () => void } {
  const requested: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = ((input: unknown) => {
    const url = String(input);
    requested.push(url);
    const body = routes[url];
    return Promise.resolve(
      body !== undefined
        ? new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('<!doctype html><title>404</title>', { status: 404, headers: { 'content-type': 'text/html' } }),
    );
  }) as typeof globalThis.fetch;
  return { requested, restore: () => { globalThis.fetch = real; } };
}

test('PREMISE: the vector and its package text parse under JSON.parse, keeping the signed summary', () => {
  const bundle = JSON.parse(VECTOR_TEXT) as { packageHash: string; package: { summary: string } };
  assert.equal(bundle.packageHash, PACKAGE_HASH);
  assert.match(bundle.package.summary, /^A four-row CSV /);
  assert.deepEqual(JSON.parse(PACKAGE_TEXT), bundle.package);
  assert.equal((PACKAGE_TEXT.match(/\n {4}"summary": /g) ?? []).length, 2);
});

test('a pasted bundle whose package repeats a member name is refused', async () => {
  await assert.rejects(resolveCommitment('bundle', VECTOR_TEXT), refusal(/^That bundle /, '/package'));
});

test('a commitment fetched by address whose text repeats a member name is refused, and no other address is tried', async () => {
  const records = `${PUBLISHER}/api/records/some-slug/commitment`;
  const evidence = `${PUBLISHER}/api/evidence/some-slug/commitment`;
  const pub = stub({
    [records]: VECTOR_TEXT,
    [evidence]: JSON.stringify({ protocolVersion: '0.1.0', packageHash: PACKAGE_HASH }),
  });
  try {
    await assert.rejects(
      resolveCommitment('hash', 'some-slug', undefined, { host: PUBLISHER }),
      refusal(/^The commitment at example-publisher\.test\/api\/records\/some-slug\/commitment /, '/package'),
    );
    assert.deepEqual(pub.requested, [records]);
  } finally {
    pub.restore();
  }
});

test('a package fetched from packageUrl whose text repeats a member name is refused, not read as unavailable', async () => {
  const records = `${PUBLISHER}/api/records/some-slug/commitment`;
  const pub = stub({
    [records]: JSON.stringify({ protocolVersion: '0.1.0', packageHash: PACKAGE_HASH, packageUrl: PACKAGE_URL }),
    [PACKAGE_URL]: PACKAGE_TEXT,
  });
  const steps: ResolveStep[] = [];
  try {
    await assert.rejects(
      resolveInput('hash', 'some-slug', undefined, (s) => steps.push(s), { host: PUBLISHER }),
      refusal(/^The package at example-publisher\.test\/packages\/record\.json /, ''),
    );
    assert.deepEqual(pub.requested, [records, PACKAGE_URL]);
    assert.deepEqual(
      steps.map((s) => s.key),
      ['commitment'],
      'no package step: neither "Content could not be fetched" nor a package read',
    );
  } finally {
    pub.restore();
  }
});
