// `vcsRef` on `buildEnvelope` (typedstandards#113, G0 D7; hub ADR-0016 §B, spec
// §8.1.1). An optional top-level envelope field beside `producerProfile`, `type`
// and `signer`, emitted verbatim on v0.1 envelopes only, and covered by the JCS
// envelope hash and, under legacy-json/v1, by the content hash (spec §8.2). A
// legacy input (no `type`) carrying it throws. No shape validation beyond the
// type: the CLI checks the shape (P3).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildEnvelope, type EnvelopeInput, type VcsRef } from './index.ts';

const golden = JSON.parse(
  readFileSync(new URL('./__fixtures__/reference-golden.json', import.meta.url), 'utf8'),
) as { envelopeCases: Array<{ name: string; input: Record<string, unknown>; expected: { serializedJson: string; envelopeHash: string } }> };

const captured = (name: string) => golden.envelopeCases.find((c) => c.name === name)!;
const v01 = () => structuredClone(captured('v01-default').input) as unknown as EnvelopeInput;
const legacy = () => structuredClone(captured('legacy-inline').input) as unknown as EnvelopeInput;

const VCS_REF: VcsRef = {
  repoUrl: 'https://git.example.com/analyses/example.git',
  commitSha: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
  path: 'notebooks/analysis.ipynb',
  ref: 'main',
};

test('v0.1: vcsRef is in the package, verbatim, and changes the envelope hash and the content hash', () => {
  const without = buildEnvelope(v01());
  const withRef = buildEnvelope({ ...v01(), vcsRef: VCS_REF });
  assert.deepEqual(withRef.pkg.vcsRef, VCS_REF);
  assert.notEqual(withRef.envelopeHash, without.envelopeHash);
  assert.notEqual(withRef.pkg.contentHash?.sha256, without.pkg.contentHash?.sha256);
});

test('v0.1: the two required sub-fields alone are emitted as given', () => {
  const minimal: VcsRef = { repoUrl: VCS_REF.repoUrl, commitSha: VCS_REF.commitSha };
  const { pkg } = buildEnvelope({ ...v01(), vcsRef: minimal });
  assert.deepEqual(pkg.vcsRef, minimal);
  assert.deepEqual(Object.keys(pkg.vcsRef ?? {}), ['repoUrl', 'commitSha']);
});

test('v0.1: vcsRef is a top-level field after signer and before contentCanonicalization', () => {
  const signer = { bindingTier: 'pseudonymous', identifier: 'example:publisher', displayName: 'Example publisher' };
  const { pkg } = buildEnvelope({ ...v01(), producerProfile: 'scripted-recomputation/example', signer, vcsRef: VCS_REF });
  const keys = Object.keys(pkg);
  assert.deepEqual(keys.slice(0, 6), ['metadata', 'producerProfile', 'type', 'signer', 'vcsRef', 'contentCanonicalization']);
  assert.ok(!('vcsRef' in pkg.metadata));
});

test('v0.1: the same input without vcsRef is byte-identical to the captured case', () => {
  const c = captured('v01-default');
  const { pkg, envelopeHash } = buildEnvelope(v01());
  assert.ok(!('vcsRef' in pkg));
  assert.equal(JSON.stringify(pkg), c.expected.serializedJson);
  assert.equal(envelopeHash, c.expected.envelopeHash);
});

test('v0.1: vcsRef is emitted verbatim, with no shape check beyond the type', () => {
  const extra = { ...VCS_REF, provider: 'example-vcs' } as unknown as VcsRef;
  const { pkg } = buildEnvelope({ ...v01(), vcsRef: extra });
  assert.deepEqual(pkg.vcsRef, extra);
});

test('legacy: an input with no type carrying vcsRef throws, naming the rule', () => {
  assert.throws(
    () => buildEnvelope({ ...legacy(), vcsRef: VCS_REF }),
    /vcsRef is emitted on v0\.1 envelopes only/,
  );
  // Without vcsRef the legacy input builds, byte-identical to its capture.
  const c = captured('legacy-inline');
  assert.equal(JSON.stringify(buildEnvelope(legacy()).pkg), c.expected.serializedJson);
});
