// Check #17 — the content-profile system prompt (spec §9.2 check 17; hub
// ADR-0038 §6). Three statuses:
//   - `ok`               `metadata.contentProfile` is "datHere" and
//                        `skillMetadata.skillText` is a non-empty string or a BlobRef;
//   - `skillText_absent` "datHere", and the key is absent, empty, or neither a
//                        string nor a BlobRef (attention, never a failure);
//   - `not_applicable`   any other content profile: absent, "default" or unknown.
// The check does not resolve a BlobRef (check #9 does).
//
// Synthetic packages only: each is the minimal object the check reads.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkContentProfile,
  checkSystemPrompt,
  verifyRecord,
  SYSTEM_PROMPT_STATUSES,
  type FetchLike,
} from './index.ts';

const failFetch: FetchLike = async () => {
  throw new Error('no network in this test');
};

const BLOB_REF = {
  ref: `blob:sha256:${'c0'.repeat(32)}`,
  url: 'https://blobs.example/skill-text',
  size: 2048,
  contentType: 'text/plain; charset=utf-8',
};

const ABSENT = Symbol('absent');

/** A package with this content profile and these skillMetadata members. */
function pkgWith(
  contentProfile: unknown,
  skillMetadata: Record<string, unknown> | typeof ABSENT = {},
): Record<string, unknown> {
  const metadata: Record<string, unknown> = { captureMethod: 'chat-flow-stream' };
  if (contentProfile !== ABSENT) metadata['contentProfile'] = contentProfile;
  return {
    metadata,
    producerProfile: 'ai-assisted-analysis/datHere',
    ...(skillMetadata !== ABSENT ? { skillMetadata } : {}),
  };
}

test('the status list is exactly the three ADR-0038 §6 statuses', () => {
  assert.deepEqual([...SYSTEM_PROMPT_STATUSES], ['ok', 'skillText_absent', 'not_applicable']);
});

test('datHere: the skillText key absent reads skillText_absent', () => {
  assert.equal(checkSystemPrompt(pkgWith('datHere', { systemPromptHash: 'ab'.repeat(32) })).status, 'skillText_absent');
});

test('datHere: an empty skillMetadata ({}) reads skillText_absent', () => {
  assert.equal(checkSystemPrompt(pkgWith('datHere', {})).status, 'skillText_absent');
});

test('datHere: no skillMetadata at all, or one that is not an object, reads skillText_absent', () => {
  assert.equal(checkSystemPrompt(pkgWith('datHere', ABSENT)).status, 'skillText_absent');
  const notObject = { ...pkgWith('datHere', ABSENT), skillMetadata: 'text' };
  assert.equal(checkSystemPrompt(notObject).status, 'skillText_absent');
});

test('datHere: an empty string reads skillText_absent', () => {
  assert.equal(checkSystemPrompt(pkgWith('datHere', { skillText: '' })).status, 'skillText_absent');
});

test('datHere: a non-empty string reads ok', () => {
  assert.deepEqual(checkSystemPrompt(pkgWith('datHere', { skillText: 'You are a careful analyst.' })), {
    status: 'ok',
    form: 'string',
  });
});

test('datHere: a BlobRef reads ok, and the check fetches nothing', () => {
  assert.deepEqual(checkSystemPrompt(pkgWith('datHere', { skillText: BLOB_REF })), {
    status: 'ok',
    form: 'blobRef',
  });
});

test('datHere: a value that is neither a string nor a BlobRef reads skillText_absent', () => {
  for (const value of [42, true, null, [], ['text'], {}, { ref: 'not-a-blob-ref' }, { ...BLOB_REF, size: '2048' }]) {
    assert.equal(
      checkSystemPrompt(pkgWith('datHere', { skillText: value })).status,
      'skillText_absent',
      JSON.stringify(value),
    );
  }
});

test('not_applicable: "default", absent and unknown content profiles, whatever skillText holds', () => {
  for (const contentProfile of ['default', ABSENT, 'adopter-profile', 'dathere', '', 7, null]) {
    for (const skillMetadata of [{}, { skillText: '' }, { skillText: 'text' }, { skillText: BLOB_REF }, ABSENT] as const) {
      assert.deepEqual(
        checkSystemPrompt(pkgWith(contentProfile, skillMetadata)),
        { status: 'not_applicable' },
        `${String(contentProfile)} / ${JSON.stringify(skillMetadata)}`,
      );
    }
  }
  assert.deepEqual(checkSystemPrompt({}), { status: 'not_applicable' });
});

test('the check reads metadata.contentProfile, not producerProfile', () => {
  const pkg = { ...pkgWith(ABSENT, {}), producerProfile: 'ai-assisted-analysis/datHere' };
  assert.equal(checkSystemPrompt(pkg).status, 'not_applicable');
  const civic = { ...pkgWith('datHere', {}), producerProfile: 'ai-assisted-analysis/civicaitools-v1' };
  assert.equal(checkSystemPrompt(civic).status, 'skillText_absent');
});

test('verifyRecord carries check #17 beside check #16; it never fails the record', async () => {
  const absent = await verifyRecord(
    { package: pkgWith('datHere', {}), packageHash: 'a'.repeat(64) },
    { registry: undefined, fetch: failFetch },
  );
  assert.deepEqual(absent.systemPrompt, { status: 'skillText_absent' });
  const present = await verifyRecord(
    { package: pkgWith('datHere', { skillText: 'You are a careful analyst.' }), packageHash: 'a'.repeat(64) },
    { registry: undefined, fetch: failFetch },
  );
  assert.deepEqual(present.systemPrompt, { status: 'ok', form: 'string' });
  // Every other field reads the same whether or not the prompt is carried.
  const strip = (r: Record<string, unknown>) => {
    const { systemPrompt: _drop, ...rest } = r;
    return rest;
  };
  const presentPkg = pkgWith('datHere', { skillText: 'You are a careful analyst.' });
  const absentPkg = pkgWith('datHere', {});
  assert.deepEqual(checkContentProfile(presentPkg), checkContentProfile(absentPkg));
  const a = strip({ ...absent } as unknown as Record<string, unknown>);
  const p = strip({ ...present } as unknown as Record<string, unknown>);
  // The two packages differ in bytes, so the recomputed hash differs; nothing else does.
  for (const key of ['recomputedHash', 'nodeId']) {
    delete a[key];
    delete p[key];
  }
  assert.deepEqual(a, p);
});

test('verifyRecord reports null for #17 when the package is unavailable', async () => {
  const result = await verifyRecord(
    { package: null, packageHash: 'a'.repeat(64), contentUnavailableReason: 'private' },
    { registry: undefined, fetch: failFetch },
  );
  assert.equal(result.systemPrompt, null);
});
