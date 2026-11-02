// `verify` reads the commitment view a host serves (typedstandards#166, ruling A):
// produce-core's `buildCommitmentView` with the host's additions, its package inline
// or named with `--package`. Checks #7 and #8 run offline through verify-core from
// the view's RFC 3161 token and log inclusion proof. The view's transparency-log
// entry id is not passed to verify-core offline, and its hash is reported as not
// checked. A carried attestation's `hasTimestamp` and `hasRekor`, `trustRegistry`,
// `signerIdentity` and `trustRegistryUrlLegacy` are accepted and not read.
//
// The real-proof fixture is a platform-signed layout node a host serves, and its
// proofs (fixtures/host-served/README.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCommitmentView } from '@typedstandards/produce-core';
import { EXIT } from './errors.ts';
import { run } from './run.ts';
import { RFC8032_TEST_1_B64, SEED_VARIABLE, cli, memoryIo, scratch } from './harness.test.ts';

const NODE_ID = '770ed52e2abfc0c7d4626953c9f715c11a50e63bd911fa2bed56b77a76fe0ee7';
const FIXTURES = fileURLToPath(new URL('../fixtures/host-served/', import.meta.url));
const LAYOUT_BYTES = readFileSync(join(FIXTURES, `${NODE_ID}.json`));
const PROOFS_BYTES = readFileSync(join(FIXTURES, `${NODE_ID}.proofs.json`));

type Json = Record<string, unknown>;
const layout = JSON.parse(LAYOUT_BYTES.toString('utf8')) as Json & { package: Json; signature: { kid: string; publicKey: string } };
const proofs = JSON.parse(PROOFS_BYTES.toString('utf8')) as {
  packageHash: string;
  rfc3161Timestamp: string;
  rekorEntryId: string;
  rekorInclusionProof: string;
  rekorEntryBody: string;
};

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

/** The layout node's own view fields, as produce-core's builder takes them. */
function layoutViewInput() {
  return {
    packageHash: layout['packageHash'] as string,
    visibility: layout['visibility'] as string,
    captureMethod: layout['captureMethod'] as string | null,
    contentProfile: layout['contentProfile'] as string | null,
    type: layout['type'] as string,
    signer: layout['signer'] as never,
    contentHash: layout['contentHash'] as Record<string, string>,
    contentCanonicalization: layout['contentCanonicalization'] as string,
    signature: layout['signature'] as Json,
    trustRegistryUrl: layout['trustRegistryUrl'] as string,
  };
}

/** A host's informational identity block about the record's creator: not a check's subject. */
const SIGNER_IDENTITY = {
  provider: 'example',
  providerId: 'a1b2c3',
  displayName: 'Example host account',
  profileUrl: 'https://host.example/accounts/a1b2c3',
};

/**
 * A withdrawal of the layout node by a third party, as a host carries it. Signed in
 * the test under the public RFC 8032 test seed and the harness's fixed clock, so it
 * is the same node every time.
 */
async function thirdPartyWithdrawal(): Promise<Json> {
  const io = memoryIo(
    { 'w.json': JSON.stringify({ targetNodeId: NODE_ID, reason: 'An example third party withdraws its reading.', signer: { bindingTier: 'pseudonymous', displayName: 'Example third party' } }) },
    { [SEED_VARIABLE]: RFC8032_TEST_1_B64 },
  );
  assert.equal(await run(['withdraw', '--input', 'w.json'], io), EXIT.ok, io.err.join(''));
  return JSON.parse(io.out.join('')) as Json;
}

/**
 * The commitment view a host serves for the layout node, built by produce-core:
 * its proofs, the six keys `view` does not emit, and a carried attestation with
 * the host's two flags. `package` inline unless `withPackage` is false.
 */
async function hostServed(options: { withPackage?: boolean; flags?: boolean } = {}): Promise<Json> {
  const withdrawal = await thirdPartyWithdrawal();
  const view = buildCommitmentView({
    ...layoutViewInput(),
    signerIdentity: SIGNER_IDENTITY,
    rfc3161Timestamp: proofs.rfc3161Timestamp,
    rekorEntryId: proofs.rekorEntryId,
    rekorInclusionProof: proofs.rekorInclusionProof,
    rekorEntryBody: proofs.rekorEntryBody,
    lifecycleAttestations: [options.flags === false ? withdrawal : { ...withdrawal, hasTimestamp: true, hasRekor: true }] as never,
    trustRegistryUrlLegacy: 'https://host.example/.well-known/legacy-registry.json',
    subjectTitle: 'An example host-served record',
    subjectSummary: null,
  });
  return JSON.parse(JSON.stringify(options.withPackage === false ? view : { ...view, package: layout.package })) as Json;
}

async function verify(files: Record<string, unknown>, args: string[]) {
  const io = memoryIo(Object.fromEntries(Object.entries(files).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)])));
  const code = await run(['verify', ...args], io);
  const out = io.out.join('');
  return { code, out, err: io.err.join(''), json: () => JSON.parse(out) as Json };
}

test('the fixtures are the website\'s layout node and its proofs, byte for byte, and the node is produce-core\'s view', () => {
  // civic-ai-tools-website 4777b79: public/.well-known/layouts/<nodeId>.json and .proofs.json.
  assert.equal(sha256(LAYOUT_BYTES), '01548e1dc3b4bb6fdd2c83d43c9a6cd1816fb14760516113b63d888291700b6d');
  assert.equal(sha256(PROOFS_BYTES), 'e193701eea342b520cbee8dd667d63fdefc579aef42bc408f276eb1e23bd77f9');
  assert.equal(layout['packageHash'], NODE_ID);
  assert.equal(proofs.packageHash, NODE_ID);
  const { package: _pkg, ...served } = layout;
  assert.deepEqual(JSON.parse(JSON.stringify(buildCommitmentView(layoutViewInput()))), served);
});

test('a host-served commitment view with its package verifies offline: exit 0, ok, the node\'s nodeId', async () => {
  const view = await hostServed();
  for (const key of ['signerIdentity', 'rfc3161Timestamp', 'rekorEntryId', 'rekorInclusionProof', 'rekorEntryBody', 'trustRegistryUrlLegacy']) {
    assert.ok(key in view, `the view lacks ${key}`);
  }
  const carried = (view['lifecycleAttestations'] as Json[])[0];
  assert.equal(carried['hasTimestamp'], true);
  assert.equal(carried['hasRekor'], true);
  const r = await verify({ 'view.json': view }, ['--input', 'view.json']);
  assert.equal(r.code, EXIT.ok, r.err);
  assert.deepEqual(r.json(), { ok: true, nodeId: NODE_ID, failures: [] });
});

test('--json shows checks #7 and #8 as verify-core reports them offline; the log entry\'s hash is reported not checked', async () => {
  const r = await verify({ 'view.json': await hostServed() }, ['--input', 'view.json', '--json']);
  assert.equal(r.code, EXIT.ok, r.err);
  const checks = r.json()['checks'] as Json & { rfc3161: Json; rekorInclusion: Json };
  assert.equal(checks['hasTimestamp'], true);
  assert.equal(checks.rfc3161['verified'], true);
  assert.equal(checks.rekorInclusion['inclusionVerified'], true);
  assert.equal(checks.rekorInclusion['checkpointVerified'], true);
  // The entry id is not passed offline, so the hash parity is not checked: null, not false.
  assert.equal(checks['rekorVerified'], null);
  assert.match(r.err, new RegExp(`not checked offline: log entry ${proofs.rekorEntryId} against this record's hash`));
  assert.doesNotMatch(r.err, /#7|#8/);
});

test('the built bin: a host-served view requests nothing and writes nothing outside its own stderr lines', async () => {
  const dir = scratch();
  try {
    const r = cli(['verify', '--input', dir.write('view.json', JSON.stringify(await hostServed()))]);
    assert.equal(r.code, 0, r.err);
    for (const line of r.err.trim().split('\n')) assert.match(line, /^typedstandards verify: /);
  } finally {
    dir.cleanup();
  }
});

test('a timestamp token that does not verify for the package reads alarm: exit 1, a check #7 failure', async () => {
  const view = await hostServed();
  const token = Buffer.from(view['rfc3161Timestamp'] as string, 'base64');
  token[token.length - 1] ^= 0x01;
  view['rfc3161Timestamp'] = token.toString('base64');
  const r = await verify({ 'view.json': view }, ['--input', 'view.json']);
  assert.equal(r.code, EXIT.verificationFailed, r.err);
  const failures = r.json()['failures'] as Array<{ check: string; field: string }>;
  assert.deepEqual(failures.map((f) => `${f.check} ${f.field}`), ['#7 rfc3161']);
});

test('an inclusion proof that does not verify reads attention, never alarm', async () => {
  const view = await hostServed();
  const proof = JSON.parse(view['rekorInclusionProof'] as string) as { hashes: string[] };
  proof.hashes[0] = proof.hashes[0].replace(/^./, (c) => (c === '0' ? '1' : '0'));
  view['rekorInclusionProof'] = JSON.stringify(proof);
  const r = await verify({ 'view.json': view }, ['--input', 'view.json']);
  assert.equal(r.code, EXIT.ok, r.err);
  assert.match(r.err, /#8 rekorInclusion: root_mismatch \(attention\)/);
});

test('a log entry id with no inclusion proof reads attention, and its hash is reported not checked', async () => {
  const view = await hostServed();
  delete view['rekorInclusionProof'];
  delete view['rekorEntryBody'];
  const r = await verify({ 'view.json': view }, ['--input', 'view.json']);
  assert.equal(r.code, EXIT.ok, r.err);
  assert.match(r.err, /#8 rekorInclusion: not_carried \(attention\)/);
  assert.match(r.err, /not checked offline: log entry /);
});

test('a carried attestation\'s hasTimestamp and hasRekor are accepted, and no output derives from them', async () => {
  const flagged = await verify({ 'view.json': await hostServed() }, ['--input', 'view.json', '--json']);
  const bare = await verify({ 'view.json': await hostServed({ flags: false }) }, ['--input', 'view.json', '--json']);
  assert.equal(flagged.code, EXIT.ok, flagged.err);
  assert.equal(bare.code, EXIT.ok, bare.err);
  assert.equal(flagged.out, bare.out);
  assert.equal(flagged.err, bare.err);
  const doc = JSON.parse(flagged.out) as { lifecycle: { chain: Json[] } };
  assert.equal(doc.lifecycle.chain.length, 1);
  assert.equal(doc.lifecycle.chain[0]['hasTimestamp'], false);
  assert.equal(doc.lifecycle.chain[0]['hasRekor'], false);

  const view = await hostServed();
  (view['lifecycleAttestations'] as Json[])[0]['hasRekor'] = 'yes';
  const bad = await verify({ 'view.json': view }, ['--input', 'view.json']);
  assert.equal(bad.code, EXIT.usage);
  assert.match(bad.err, /lifecycleAttestations\[0\]\.hasRekor must be a boolean/);
});

test('trustRegistry, as a host serves it beside the package, is accepted and not read', async () => {
  const view = await hostServed();
  // A registry that would make the key active if verify read it.
  view['trustRegistry'] = {
    keys: [{ kid: layout.signature.kid, publicKey: layout.signature.publicKey, status: 'active', activatedAt: '2026-01-01T00:00:00Z', deprecatedAt: null, revokedAt: null }],
  };
  const r = await verify({ 'view.json': view }, ['--input', 'view.json', '--json']);
  assert.equal(r.code, EXIT.ok, r.err);
  assert.equal((r.json()['checks'] as { keyTrust: { status: string } }).keyTrust.status, 'registry_unavailable');
});

test('host-core\'s served bundles, which carry trustRegistry, verify', async () => {
  const root = fileURLToPath(new URL('../../host-core/fixtures/core-satellite/expected/bundles/', import.meta.url));
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? walk(path) : name.endsWith('.bundle.json') ? [path] : [];
    });
  const bundles = walk(root);
  assert.equal(bundles.length, 52);
  for (const path of bundles) {
    const bundle = JSON.parse(readFileSync(path, 'utf8')) as Json;
    assert.ok('trustRegistry' in bundle, path);
    const r = await verify({ 'b.json': bundle }, ['--input', 'b.json']);
    assert.equal(r.code, EXIT.ok, `${path}: ${r.err}`);
    assert.deepEqual(r.json(), { ok: true, nodeId: bundle['packageHash'], failures: [] }, path);
  }
});

test('--package names the package\'s file when the view does not carry it', async () => {
  const inline = await verify({ 'view.json': await hostServed() }, ['--input', 'view.json']);
  const named = await verify({ 'view.json': await hostServed({ withPackage: false }), 'package.json': layout.package }, ['--input', 'view.json', '--package', 'package.json']);
  assert.equal(named.code, EXIT.ok, named.err);
  assert.equal(named.out, inline.out);

  const both = await verify({ 'view.json': await hostServed(), 'package.json': layout.package }, ['--input', 'view.json', '--package', 'package.json']);
  assert.equal(both.code, EXIT.usage);
  assert.match(both.err, /--package: the view already carries a package/);

  const signed = { package: layout.package, envelopeHash: NODE_ID, signature: layout.signature };
  const signShape = await verify({ 'signed.json': signed, 'package.json': layout.package }, ['--input', 'signed.json', '--package', 'package.json']);
  assert.equal(signShape.code, EXIT.usage);
  assert.match(signShape.err, /--package: the input is what sign prints, which carries its package/);

  const stdin = await verify({}, ['--input', '-', '--package', '-']);
  assert.equal(stdin.code, EXIT.usage);
  assert.match(stdin.err, /--input and --package cannot both read standard input/);
});

test('evidenceProtocolVersion, the prior-era key, is accepted and not read', async () => {
  const view = await hostServed({ flags: false });
  const current = await verify({ 'view.json': view }, ['--input', 'view.json', '--json']);
  const { protocolVersion, ...rest } = view;
  const prior = await verify({ 'view.json': { evidenceProtocolVersion: protocolVersion, ...rest } }, ['--input', 'view.json', '--json']);
  assert.equal(prior.code, EXIT.ok, prior.err);
  assert.equal(prior.out, current.out);
});

test('a key outside the commitment view is still refused', async () => {
  const r = await verify({ 'view.json': { ...(await hostServed()), notAViewKey: 1 } }, ['--input', 'view.json']);
  assert.equal(r.code, EXIT.usage);
  assert.match(r.err, /notAViewKey: not part of a commitment view/);
});
