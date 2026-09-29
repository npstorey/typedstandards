// The P3 fix (typedstandards#125, finding F1): `build` never writes an index its own
// `parseIndex` refuses.
//
// - A legacy-chain package (signed with no `type`) is listed with the type
//   verify-core's `resolvePackageType` resolves, `content/analysis/v1`, which is
//   spec §8.8.1's "Absence is interpreted as `content/analysis/v1`". `verify`
//   compares the index with the same resolution, and a display rule naming that
//   type displays the record.
// - A package with no `metadata.createdAt` or no `signer.identifier` is refused by
//   `build`, naming the record and the field, instead of being listed with `''`.
//
// Fixture provenance: no committed fixture. Each package is signed in the test by
// the CLI's own path (packages/cli/src/sign.ts at 034fc8c): the fields `sign` fills
// when an input omits them (`packageId`, `createdAt`, `signingKeyId`,
// `signer.identifier`, the last two the seed's did:key), then produce-core's
// `buildEnvelope` and `signEnvelopeHash`, then the JSON round trip `sign` prints.
// The seed is a throwaway from `crypto.getRandomValues`, zeroed after signing and
// never written. The oracle fixture (fixtures/core-satellite/) is read in place.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildEnvelope, deriveKeyDerivedIdentifierFromKey, signEnvelopeHash, type EnvelopeInput } from '@typedstandards/produce-core';
import { resolvePackageType } from '@typedstandards/verify-core';
import { HostError, buildHost, displayOf, parseIndex, parsePolicy, type HostIndex } from './index.ts';
import { INPUT, host, loadDir, readJson } from './harness.test.ts';

type Json = Record<string, unknown>;
interface Signed {
  package: Json & { metadata: Json; signer?: Json };
  envelopeHash: string;
  signature: Json;
}

const ORIGIN = 'https://records.example.org';
const IMPLICIT_TYPE = 'content/analysis/v1';

/** What `sign` prints for each input, all signed with one throwaway seed. */
function signAll(inputs: Json[]): Signed[] {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  try {
    const identifier = deriveKeyDerivedIdentifierFromKey(seed);
    return inputs.map((input, i) => {
      const signer = input['signer'] as Json | undefined;
      const filled = {
        ...input,
        packageId: `a0000000-0000-4000-8000-00000000000${i.toString(16)}`,
        createdAt: `2026-09-0${i + 1}T00:00:00.000Z`,
        signingKeyId: identifier,
        ...(signer && !('identifier' in signer) ? { signer: { ...signer, identifier } } : {}),
      } as unknown as EnvelopeInput;
      const built = buildEnvelope(filled);
      const signature = signEnvelopeHash(built.envelopeHash, seed, filled.signingKeyId);
      return JSON.parse(JSON.stringify({ package: built.pkg, envelopeHash: built.envelopeHash, signature })) as Signed;
    });
  } finally {
    seed.fill(0);
  }
}

/** An envelope input `sign` accepts; with no `type`, it is signed on the legacy chain. */
const inputOf = (extra: Json = {}): Json => ({
  prompt: 'Sign a short note.',
  promptVisibility: 'full_text',
  queries: [],
  dataSources: [],
  cost: { model: 'none' },
  skillMetadata: {},
  output: 'A short note.',
  trace: {},
  signer: { bindingTier: 'pseudonymous', displayName: 'Test signer' },
  ...extra,
});

const [LEGACY, TYPED] = signAll([inputOf(), inputOf({ type: IMPLICIT_TYPE, producerProfile: 'scripted-recomputation/test' })]);

type Registry = Json | null;

function manifestOf(registry: Registry, records: Array<[name: string, file: string]>): Json {
  return {
    origin: ORIGIN,
    visibility: 'public',
    registry,
    index: {},
    records: records.map(([name, signed]) => ({ name, signed, attestations: [], title: `The ${name} record` })),
  };
}

const enc = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));

function buildOne(signed: Signed, registry: Registry) {
  return buildHost(manifestOf(registry, [['legacy', 'legacy.signed.json']]), new Map([['legacy.signed.json', enc(signed)]]));
}

/** A copy of the legacy package with `mutate` applied. Its envelopeHash is stale: build refuses before anything reads it. */
function legacyWith(mutate: (pkg: Signed['package']) => void): Signed {
  const copy = structuredClone(LEGACY);
  mutate(copy.package);
  return copy;
}

/** The HostError message a call refuses with, or '(no refusal)'. */
function refusal(run: () => unknown): string {
  try {
    run();
    return '(no refusal)';
  } catch (err) {
    return err instanceof HostError ? err.message : `(not a HostError) ${String(err)}`;
  }
}

/** Every case's refusal matches `expected`; a red prints each case's actual message. */
function assertRefusals(cases: Array<[string, () => unknown]>, expected: RegExp): void {
  const got = cases.map(([label, run]) => `${label} -> ${refusal(run)}`);
  const wrong = got.filter((line) => !expected.test(line.slice(line.indexOf(' -> ') + 4)));
  assert.deepEqual(wrong, [], `expected ${expected} for every case; got:\n${got.join('\n')}`);
}

const REGISTRIES: Array<[string, Registry]> = [
  ['a registry', {}],
  ['no registry', null],
];

test('PREMISE: the legacy input is signed on the legacy chain with no type, and verify-core resolves it as content/analysis/v1', () => {
  assert.equal('type' in LEGACY.package, false);
  assert.equal('contentHash' in LEGACY.package, false, 'a legacy package carries no contentHash');
  assert.deepEqual(resolvePackageType(LEGACY.package), { status: 'implicit', type: IMPLICIT_TYPE });
  assert.equal(TYPED.package['type'], IMPLICIT_TYPE);
});

test('legacy chain (bin): build states content/analysis/v1, check passes, verify gives ok with 0 fetches, and links prints its link', () => {
  for (const [label, registry] of REGISTRIES) {
    const dir = mkdtempSync(join(tmpdir(), 'host-core-legacy-'));
    try {
      mkdirSync(join(dir, 'records'));
      writeFileSync(join(dir, 'records', 'legacy.signed.json'), `${JSON.stringify(LEGACY, null, 2)}\n`);
      const manifest = join(dir, 'host.json');
      writeFileSync(manifest, JSON.stringify(manifestOf(registry, [['legacy', 'records/legacy.signed.json']])));

      const build = host(['build', '--manifest', manifest]);
      const written = build.code === 0 ? (JSON.parse(readFileSync(join(dir, 'docs', 'records.json'), 'utf8')) as HostIndex) : undefined;
      const check = host(['check', '--manifest', manifest]);
      const verify = host(['verify', '--manifest', manifest]);
      const links = host(['links', '--manifest', manifest]);
      // Every command first, then one comparison: a red shows all four.
      assert.deepEqual(
        { build: build.code, type: written?.records[0].type, check: check.code, verify: verify.code, links: links.code, stderr: verify.err + links.err },
        { build: 0, type: IMPLICIT_TYPE, check: 0, verify: 0, links: 0, stderr: '' },
        label,
      );

      const lines = verify.out.split('\n');
      assert.ok(lines.includes('  ok    active     legacy'), `${label}: ${verify.out}`);
      assert.ok(lines.includes('records: 1 listed, 1 ok, 0 failed; active 1, withdrawn 0, superseded 0'), `${label}: ${verify.out}`);
      assert.ok(lines.includes('network: global fetch calls 0; injected fetch calls 0'), `${label}: ${verify.out}`);
      assert.ok(lines.includes('result: all checks passed'), `${label}: ${verify.out}`);

      const url = `${ORIGIN}/bundles/legacy.bundle.json`;
      const printed = JSON.parse(links.out) as { records: Array<{ name: string; url: string; verify: string }> };
      assert.deepEqual(
        printed.records.map((r) => [r.name, r.url, r.verify]),
        [['legacy', url, `https://typedstandards.org/verify?url=${encodeURIComponent(url)}`]],
        label,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('property: parseIndex accepts every index build returns, the legacy-chain case included', () => {
  const fixtureManifest = readJson(join(INPUT, 'host.json'));
  const cases: Array<[string, () => ReturnType<typeof buildHost>]> = [
    ['the oracle fixture', () => buildHost(fixtureManifest, loadDir(INPUT))],
    ...REGISTRIES.flatMap(([label, registry]): Array<[string, () => ReturnType<typeof buildHost>]> => [
      [`a legacy-chain record, ${label}`, () => buildOne(LEGACY, registry)],
      [`a package whose type is "", ${label}`, () => buildOne(legacyWith((p) => { p['type'] = ''; }), registry)],
      [
        `a legacy-chain and a typed record, ${label}`,
        () =>
          buildHost(
            manifestOf(registry, [['legacy', 'legacy.signed.json'], ['typed', 'typed.signed.json']]),
            new Map([['legacy.signed.json', enc(LEGACY)], ['typed.signed.json', enc(TYPED)]]),
          ),
      ],
    ]),
  ];
  // Every case first, then one comparison: a red shows each case's refusal.
  const got = cases.map(([label, run]) => {
    const built = run();
    const served = JSON.parse(new TextDecoder().decode(built.files.get('records.json'))) as unknown;
    const types = built.index.records
      .filter((r) => r.name === 'legacy' || r.name === 'typed')
      .map((r) => [r.name, r.type, resolvePackageType((r.name === 'typed' ? TYPED : LEGACY).package).type]);
    return { label, served: refusal(() => parseIndex(served)), returned: refusal(() => parseIndex(built.index)), typesResolved: types.every(([, t, resolved]) => t === resolved) };
  });
  const parses = '(no refusal)';
  assert.deepEqual(
    got,
    cases.map(([label]) => ({ label, served: parses, returned: parses, typesResolved: true })),
  );
});

test('property: build refuses a package with no metadata.createdAt, naming the record and the field', () => {
  const variants: Array<[string, Signed]> = [
    ['absent', legacyWith((p) => { delete p.metadata['createdAt']; })],
    ['empty', legacyWith((p) => { p.metadata['createdAt'] = ''; })],
  ];
  assertRefusals(
    REGISTRIES.flatMap(([label, registry]) => variants.map(([how, signed]): [string, () => unknown] => [`${how} createdAt, ${label}`, () => buildOne(signed, registry)])),
    /^record legacy: the package has no metadata\.createdAt/,
  );
});

test('property: build refuses a package with no signer.identifier, naming the record and the field', () => {
  const variants: Array<[string, Signed]> = [
    ['no signer', legacyWith((p) => { delete p['signer']; })],
    ['a signer with no identifier', legacyWith((p) => { delete p.signer!['identifier']; })],
    ['an empty identifier', legacyWith((p) => { p.signer!['identifier'] = ''; })],
  ];
  assertRefusals(
    REGISTRIES.flatMap(([label, registry]) => variants.map(([how, signed]): [string, () => unknown] => [`${how}, ${label}`, () => buildOne(signed, registry)])),
    /^record legacy: the package has no signer\.identifier/,
  );
});

test('property (bin): a refused createdAt or signer exits 2 and writes nothing', () => {
  const cases: Array<[string, Signed, RegExp]> = [
    ['createdAt', legacyWith((p) => { delete p.metadata['createdAt']; }), /record legacy: the package has no metadata\.createdAt/],
    ['signer', legacyWith((p) => { delete p['signer']; }), /record legacy: the package has no signer\.identifier/],
  ];
  const got = cases.map(([field, signed, message]) => {
    const dir = mkdtempSync(join(tmpdir(), 'host-core-refuse-'));
    try {
      writeFileSync(join(dir, 'legacy.signed.json'), JSON.stringify(signed));
      const manifest = join(dir, 'host.json');
      writeFileSync(manifest, JSON.stringify(manifestOf(null, [['legacy', 'legacy.signed.json']])));
      const r = host(['build', '--manifest', manifest]);
      return { field, code: r.code, named: message.test(r.err), written: [...loadDirIfAny(join(dir, 'docs')).keys()], stderr: r.err };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  assert.deepEqual(
    got.map(({ stderr: _s, ...rest }) => rest),
    cases.map(([field]) => ({ field, code: 2, named: true, written: [] })),
    got.map((g) => `${g.field}: ${g.stderr.trim()}`).join('\n'),
  );
});

function loadDirIfAny(dir: string): Map<string, Uint8Array> {
  try {
    return loadDir(dir);
  } catch {
    return new Map();
  }
}

test('display: a rule naming type content/analysis/v1 displays the legacy-chain record', () => {
  const policy = parsePolicy({
    type: IMPLICIT_TYPE,
    display: [{ status: 'active', type: IMPLICIT_TYPE, as: 'current' }],
    unmatched: 'refuse',
  });
  for (const [label, registry] of REGISTRIES) {
    const record = buildOne(LEGACY, registry).index.records[0];
    assert.deepEqual(displayOf(record, policy), { as: 'current', rule: 0 }, label);
  }
});
