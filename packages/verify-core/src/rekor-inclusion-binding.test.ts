// Check 8's inclusion verdict is bound to the record (spec §9.2 check #8).
//
// The rule: `rekorInclusion.inclusionVerified` (and so `checkpointVerified`) is true
// only when the log entry records this record's hash: the entry body's
// `spec.data.hash` is `sha512` with the value `rekorHashForPackage(packageHash)`.
// It holds for both sources of a verdict: an entry body and proof the input
// carries, and an entry `verifyRekorEntry` fetches. A proof that folds and a
// checkpoint that verifies are not enough on their own.
//
// The genuine pairings are two captured commitment bundles from
// `apps/web/src/lib/__fixtures__/` (their README gives the capture); each carries
// its own log entry and proof. `__fixtures__/rekor-inclusion.json` is a real log
// entry that records no package of this project.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseInclusionProof,
  verifyRecord,
  verifyRekorEntry,
  type FetchLike,
  type RekorInclusionProof,
  type VerifyInput,
} from './index.ts';

interface CarriedView {
  packageHash: string;
  rekorEntryId: string;
  rekorEntryBody: string;
  rekorInclusionProof: string;
}

function view(name: string): CarriedView {
  const raw = JSON.parse(
    readFileSync(new URL(`../../../apps/web/src/lib/__fixtures__/${name}`, import.meta.url), 'utf8'),
  ) as CarriedView;
  return raw;
}

const A = view('q15-255b8e.json');
const B = view('q15-d67b8e.json');
const OTHER = JSON.parse(
  readFileSync(new URL('./__fixtures__/rekor-inclusion.json', import.meta.url), 'utf8'),
) as { body: string; inclusionProof: RekorInclusionProof };

const proofOf = (v: CarriedView): RekorInclusionProof => {
  const proof = parseInclusionProof(v.rekorInclusionProof);
  assert.ok(proof, 'the captured view carries a usable proof');
  return proof;
};

const failFetch = (() => {
  throw new Error('verify-core touched the network when it should not have');
}) as unknown as FetchLike;

/** Carried entry and proof, no entry id, so nothing is fetched. */
function carried(packageHash: string, body: string, proof: RekorInclusionProof): VerifyInput {
  return {
    package: null,
    packageHash,
    rekorEntryId: null,
    rekorEntryBody: body,
    rekorInclusionProof: proof,
    lifecycle: null,
  };
}

/** A log response holding one entry, with its body and proof, under `entryId`. */
function logResponse(entryId: string, body: string, proof: RekorInclusionProof): FetchLike {
  const json = { [entryId]: { body, logIndex: 7, integratedTime: 1700000000, verification: { inclusionProof: proof } } };
  return async () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(json)).buffer as ArrayBuffer,
    text: async () => JSON.stringify(json),
    json: async () => json,
  });
}

// --- carried ------------------------------------------------------------------

test('check 8, carried: an entry that records this record\'s hash keeps its verdict', async () => {
  for (const v of [A, B]) {
    const r = await verifyRecord(carried(v.packageHash, v.rekorEntryBody, proofOf(v)), {
      registry: undefined,
      fetch: failFetch,
    });
    assert.equal(r.rekorInclusion?.inclusionVerified, true, v.packageHash);
    assert.equal(r.rekorInclusion?.checkpointVerified, true, v.packageHash);
    assert.equal(r.rekorInclusion?.origin, 'rekor.sigstore.dev');
  }
});

test('check 8, carried: an entry that records another hash is not verified', async () => {
  const cases: Array<[string, string, string, RekorInclusionProof]> = [
    ['another record\'s entry', B.packageHash, A.rekorEntryBody, proofOf(A)],
    ['another record\'s entry', A.packageHash, B.rekorEntryBody, proofOf(B)],
    ['an entry of no record here', A.packageHash, OTHER.body, OTHER.inclusionProof],
    ['no record hash', '', A.rekorEntryBody, proofOf(A)],
  ];
  for (const [label, packageHash, body, proof] of cases) {
    const r = await verifyRecord(carried(packageHash, body, proof), { registry: undefined, fetch: failFetch });
    assert.ok(r.rekorInclusion, `${label}: a carried proof still yields a verdict`);
    assert.equal(r.rekorInclusion.inclusionVerified, false, label);
    assert.equal(r.rekorInclusion.checkpointVerified, false, label);
    assert.equal(r.rekorInclusion.origin, undefined, label);
    assert.equal(r.rekorInclusion.treeSize, proof.treeSize, label);
    assert.equal(r.rekorInclusion.leafIndex, proof.logIndex, label);
  }
});

// --- fetched ------------------------------------------------------------------

test('check 8, fetched: an entry that records this record\'s hash keeps its verdict', async () => {
  for (const v of [A, B]) {
    const fetch = logResponse(v.rekorEntryId, v.rekorEntryBody, proofOf(v));
    const entry = await verifyRekorEntry(v.rekorEntryId, v.packageHash, { fetch });
    assert.equal(entry.verified, true);
    assert.equal(entry.inclusion?.inclusionVerified, true);
    assert.equal(entry.inclusion?.checkpointVerified, true);

    const r = await verifyRecord(
      { package: null, packageHash: v.packageHash, rekorEntryId: v.rekorEntryId, lifecycle: null },
      { registry: undefined, fetch },
    );
    assert.equal(r.rekorVerified, true);
    assert.equal(r.rekorInclusion?.inclusionVerified, true);
    assert.equal(r.rekorInclusion?.checkpointVerified, true);
  }
});

test('check 8, fetched: an entry that records another hash is not verified', async () => {
  const cases: Array<[string, string, string, RekorInclusionProof]> = [
    ['another record\'s entry', B.packageHash, A.rekorEntryBody, proofOf(A)],
    ['an entry of no record here', A.packageHash, OTHER.body, OTHER.inclusionProof],
  ];
  for (const [label, packageHash, body, proof] of cases) {
    const fetch = logResponse(A.rekorEntryId, body, proof);
    const entry = await verifyRekorEntry(A.rekorEntryId, packageHash, { fetch });
    assert.equal(entry.verified, false, label);
    assert.ok(entry.inclusion, `${label}: a fetched proof still yields a verdict`);
    assert.equal(entry.inclusion.inclusionVerified, false, label);
    assert.equal(entry.inclusion.checkpointVerified, false, label);

    const r = await verifyRecord(
      { package: null, packageHash, rekorEntryId: A.rekorEntryId, lifecycle: null },
      { registry: undefined, fetch },
    );
    assert.equal(r.rekorVerified, false, label);
    assert.equal(r.rekorInclusion?.inclusionVerified, false, label);
    assert.equal(r.rekorInclusion?.checkpointVerified, false, label);
  }
});
