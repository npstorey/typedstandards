// The bin's build and check, driven as a child process over a copy of the oracle
// fixture's inputs (fixtures/core-satellite/README.md), and its refusals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXPECTED, INPUT, host, loadDir, text } from './harness.test.ts';

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), 'host-core-'));
  cpSync(INPUT, join(dir, 'site'), { recursive: true });
  return dir;
}

test('bin: build writes exactly the expected served files, byte for byte', () => {
  const dir = scratch();
  try {
    const r = host(['build', '--manifest', join(dir, 'site', 'host.json')]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^build: wrote 52 bundles, \.well-known\/typed-publisher\.json and records\.json to /);
    const written = loadDir(join(dir, 'site', 'docs'));
    const expected = loadDir(EXPECTED);
    assert.deepEqual([...written.keys()].sort(), [...expected.keys()].sort());
    for (const [path, bytes] of expected) assert.equal(text(written.get(path)), text(bytes), path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bin: check passes on a fresh build and fails on a changed, missing or unlisted served file', () => {
  const dir = scratch();
  try {
    const manifest = join(dir, 'site', 'host.json');
    const out = join(dir, 'served');
    assert.equal(host(['build', '--manifest', manifest, '--out', out]).code, 0);
    const clean = host(['check', '--manifest', manifest, '--out', out]);
    assert.equal(clean.code, 0, clean.out + clean.err);
    assert.equal(clean.out, 'check: all 54 served files equal a fresh build\n');

    const core = join(out, 'bundles', 'core.bundle.json');
    writeFileSync(core, readFileSync(core, 'utf8').replace('"visibility": "public"', '"visibility": "sealed"'));
    rmSync(join(out, 'records.json'));
    mkdirSync(join(out, 'bundles', 'extra'), { recursive: true });
    writeFileSync(join(out, 'bundles', 'extra', 'x.bundle.json'), '{}\n');
    const r = host(['check', '--manifest', manifest, '--out', out]);
    assert.equal(r.code, 1);
    assert.equal(
      r.out,
      [
        '  FAIL  bundles/core.bundle.json: differs from a fresh build',
        '  FAIL  records.json: not served',
        '  FAIL  bundles/extra/x.bundle.json: served, but host.json lists no such record',
        'check: FAILED; 52 of 54 built files are served unchanged',
        '',
      ].join('\n'),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bin: build refuses an input inside the served directory, and writes nothing', () => {
  const dir = scratch();
  try {
    const r = host(['build', '--manifest', join(dir, 'site', 'host.json'), '--out', join(dir, 'site', 'signed')]);
    assert.equal(r.code, 2);
    assert.match(r.err, /is inside the served directory .*keep inputs out of what is served/);
    assert.equal(existsSync(join(dir, 'site', 'signed', 'records.json')), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bin: build refuses a manifest without visibility, and a record under the registry with another signer', () => {
  const dir = scratch();
  try {
    const path = join(dir, 'site', 'host.json');
    const manifest = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown> & { records: Array<Record<string, unknown>> };
    const { visibility: _v, ...noVisibility } = manifest;
    writeFileSync(path, JSON.stringify(noVisibility));
    const r1 = host(['build', '--manifest', path]);
    assert.equal(r1.code, 2);
    assert.match(r1.err, /visibility is required/);

    // A signed document whose signer differs from the first record's.
    const signedPath = join(dir, 'site', manifest.records[1]['signed'] as string);
    const signed = JSON.parse(readFileSync(signedPath, 'utf8')) as { package: { signer: { displayName: string } } };
    signed.package.signer.displayName = 'another signer';
    writeFileSync(signedPath, JSON.stringify(signed));
    writeFileSync(path, JSON.stringify(manifest));
    const r2 = host(['build', '--manifest', path]);
    assert.equal(r2.code, 2);
    assert.match(r2.err, /record map: its signer or signing key differs from record core's; in 0\.1\.0 every record under a registry has one signer/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bin: without a registry, the view is refused unless produce-core accepts the signer, and the refusal is surfaced', () => {
  const dir = scratch();
  try {
    const path = join(dir, 'site', 'host.json');
    const manifest = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown> & { records: Array<Record<string, unknown>> };
    // The fixture's signer is a did:key at bindingTier "pseudonymous": produce-core accepts it with no registry.
    writeFileSync(path, JSON.stringify({ ...manifest, registry: null }));
    const ok = host(['build', '--manifest', path]);
    assert.equal(ok.code, 0, ok.err);
    const core = JSON.parse(readFileSync(join(dir, 'site', 'docs', 'bundles', 'core.bundle.json'), 'utf8')) as Record<string, unknown>;
    assert.equal('trustRegistryUrl' in core, false);
    assert.equal('trustRegistry' in core, false);
    const index = JSON.parse(readFileSync(join(dir, 'site', 'docs', 'records.json'), 'utf8')) as Record<string, unknown>;
    assert.equal('trustRegistryUrl' in index, false);

    const signedPath = join(dir, 'site', manifest.records[0]['signed'] as string);
    const signed = JSON.parse(readFileSync(signedPath, 'utf8')) as { package: { signer: { bindingTier: string } } };
    signed.package.signer.bindingTier = 'verified-organization';
    writeFileSync(signedPath, JSON.stringify(signed));
    const refused = host(['build', '--manifest', path]);
    assert.equal(refused.code, 2);
    assert.match(refused.err, /record core: produce-core refused the view: buildCommitmentView requires trustRegistryUrl/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bin: usage errors and --version', () => {
  assert.equal(host([]).code, 2);
  assert.equal(host(['serve']).code, 2);
  assert.equal(host(['build', '--bogus']).code, 2);
  assert.equal(host(['verify', '--theme', 'dark']).code, 2);
  const v = host(['--version']);
  assert.equal(v.code, 0);
  assert.equal((JSON.parse(v.out) as { name: string }).name, '@typedstandards/host-core');
});
