// Acceptance 4 (typedstandards#109): under a did:key signer, `view` omits
// trustRegistryUrl and `verify` passes on it; a view built with a withdrawal
// reads `withdrawn` under verify-core's verifyLifecycleChain.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyLifecycleChain, type CarriedLifecycleNode } from '@typedstandards/verify-core';
import { EXIT } from './errors.ts';
import { SEED_VARIABLE, cli, fileInput, golden, newSeed, scratch } from './harness.test.ts';

const FILE = 'A signed file.\n';
const SIGNER = { bindingTier: 'pseudonymous', displayName: 'Example signer' };

function signed(dir: ReturnType<typeof scratch>, env: Record<string, string>) {
  const r = cli(['sign', '--input', dir.write('input.json', JSON.stringify(fileInput())), '--output-file', dir.write('file.txt', FILE)], { env });
  assert.equal(r.code, 0, r.err);
  return { path: dir.write('signed.json', r.out), doc: r.json() as { envelopeHash: string; package: Record<string, unknown> } };
}

test('view under a did:key signer: no trustRegistryUrl, the package inline, and verify passes', () => {
  const dir = scratch();
  try {
    const s = signed(dir, { [SEED_VARIABLE]: newSeed().b64 });
    const r = cli(['view', '--signed', s.path, '--visibility', 'public', '--title', 'A signed file']);
    assert.equal(r.code, 0, r.err);
    const view = r.json();
    assert.ok(!('trustRegistryUrl' in view), 'a self-certifying view carries no trustRegistryUrl');
    assert.equal(view['packageHash'], s.doc.envelopeHash);
    assert.equal(view['visibility'], 'public');
    assert.equal(view['subjectTitle'], 'A signed file');
    assert.deepEqual(view['package'], s.doc.package);
    // Signed claims are copied from the package, never from flags.
    assert.deepEqual(view['signer'], s.doc.package['signer']);
    assert.equal(view['type'], s.doc.package['type']);
    assert.equal(view['captureMethod'], (s.doc.package['metadata'] as Record<string, unknown>)['captureMethod']);

    const v = cli(['verify', '--input', dir.write('view.json', r.out), '--json']);
    assert.equal(v.code, 0, v.err);
    const out = v.json() as { ok: boolean; checks: { keyTrust: { status: string } } };
    assert.equal(out.ok, true);
    assert.equal(out.checks.keyTrust.status, 'self_certified');
  } finally {
    dir.cleanup();
  }
});

test('withdraw, then a view carrying it reads withdrawn under verifyLifecycleChain', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const s = signed(dir, env);
    const w = cli(['withdraw', '--input', '-'], {
      env,
      stdin: JSON.stringify({ targetNodeId: s.doc.envelopeHash, reason: 'superseded by a corrected file', signer: SIGNER }),
    });
    assert.equal(w.code, 0, w.err);
    const withdrawal = w.json() as { node: Record<string, unknown>; nodeId: string };
    assert.equal(withdrawal.node['type'], 'attestation/withdraws/v1');
    assert.equal(withdrawal.node['targetNodeId'], s.doc.envelopeHash);

    const r = cli(['view', '--signed', s.path, '--visibility', 'public', '--withdrawal', dir.write('withdrawal.json', w.out)]);
    assert.equal(r.code, 0, r.err);
    const view = r.json() as { packageHash: string; package: { signer: { identifier: string } }; lifecycleAttestations: CarriedLifecycleNode[]; lifecycle: { status: string } };
    const life = verifyLifecycleChain(view.lifecycleAttestations, view.packageHash, view.package.signer.identifier);
    assert.equal(life.status, 'withdrawn');
    assert.equal(life.source, 'attestation-chain');
    assert.equal(life.withdrawnReason, 'superseded by a corrected file');
    assert.equal(view.lifecycle.status, 'withdrawn');

    const v = cli(['verify', '--input', dir.write('view.json', r.out), '--json']);
    assert.equal(v.code, 0, 'a withdrawn record still verifies');
    assert.equal((v.json()['lifecycle'] as { status: string }).status, 'withdrawn');
  } finally {
    dir.cleanup();
  }
});

test('a carried withdrawal that was altered makes verify exit 1 (#10)', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const s = signed(dir, env);
    const w = cli(['withdraw', '--input', '-'], { env, stdin: JSON.stringify({ targetNodeId: s.doc.envelopeHash, reason: 'r', signer: SIGNER }) });
    const view = cli(['view', '--signed', s.path, '--visibility', 'public', '--withdrawal', dir.write('w.json', w.out)]).json() as {
      lifecycleAttestations: Array<{ node: Record<string, unknown> }>;
    };
    view.lifecycleAttestations[0].node['reason'] = 'another reason';
    const v = cli(['verify', '--input', dir.write('view.json', JSON.stringify(view))]);
    assert.equal(v.code, 1);
    assert.ok((v.json()['failures'] as Array<{ check: string }>).some((f) => f.check === '#10'), v.out);
  } finally {
    dir.cleanup();
  }
});

test('view refuses: no --visibility, a withdrawal of another record, a registry-bound signer without --trust-registry-url', () => {
  const dir = scratch();
  try {
    const env = { [SEED_VARIABLE]: newSeed().b64 };
    const s = signed(dir, env);
    assert.equal(cli(['view', '--signed', s.path]).code, EXIT.usage);

    const other = cli(['withdraw', '--input', '-'], { env, stdin: JSON.stringify({ targetNodeId: 'b'.repeat(64), reason: 'r', signer: SIGNER }) });
    const r = cli(['view', '--signed', s.path, '--visibility', 'public', '--withdrawal', dir.write('other.json', other.out)]);
    assert.equal(r.code, EXIT.usage);
    assert.match(r.err, /not this record/);

    // A platform signer is not self-certifying: produce-core requires the registry URL.
    const c = golden.envelopeCases.find((x) => x.name === 'v01-signer-producer-capture')!;
    const platform = cli(['sign', '--input', dir.write('platform.json', JSON.stringify(c.input))], { env });
    assert.equal(platform.code, 0, platform.err);
    const p = cli(['view', '--signed', dir.write('p.json', platform.out), '--visibility', 'public']);
    assert.equal(p.code, EXIT.usage);
    assert.match(p.err, /requires trustRegistryUrl/);
    const ok = cli(['view', '--signed', dir.write('p2.json', platform.out), '--visibility', 'public', '--trust-registry-url', 'https://registry.example/.well-known/typed-publisher.json']);
    assert.equal(ok.code, 0, ok.err);
    assert.equal(ok.json()['trustRegistryUrl'], 'https://registry.example/.well-known/typed-publisher.json');
  } finally {
    dir.cleanup();
  }
});

test('view refuses to build a view of a record that does not verify (exit 1, nothing on stdout)', () => {
  const dir = scratch();
  try {
    const s = signed(dir, { [SEED_VARIABLE]: newSeed().b64 });
    const tampered = dir.write('t.json', JSON.stringify({ ...s.doc, package: { ...s.doc.package, output: 'changed' } }));
    const r = cli(['view', '--signed', tampered, '--visibility', 'public']);
    assert.equal(r.code, EXIT.verificationFailed);
    assert.equal(r.stdout.length, 0);
  } finally {
    dir.cleanup();
  }
});
