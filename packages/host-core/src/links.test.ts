// Acceptance 4 (typedstandards#125 G0 D14): `links` prints, for each record, the
// verifier link and the HTML and Markdown badge snippets in typedstandards.org's own
// form, which percent-encodes the `?url=` value.
//
// Fixture provenance: fixtures/core-satellite/links.golden.json, captured from
// apps/web/src/lib/badge-asset.ts's own functions at 41c43c9 over expected/
// records.json by fixtures/core-satellite/capture-links.mjs (its header gives the
// command). The example writes its verifier link unencoded (site/generate.mjs at
// b40c30f, :43 and :789); the golden is not that form.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { linksFor, type HostIndex } from './index.ts';
import { EXPECTED, FIXTURE, host, readJson } from './harness.test.ts';

const GOLDEN_TEXT = readFileSync(join(FIXTURE, 'links.golden.json'), 'utf8');
const golden = JSON.parse(GOLDEN_TEXT) as { records: Array<{ name: string; url: string; verify: string; html: string; markdown: string }> };
const index = readJson(join(EXPECTED, 'records.json')) as HostIndex;

// The example's form: site/generate.mjs:43 (`VERIFIER`) and :789 (`verifyHref`).
const unencoded = (r: { bundle: string }) => `https://typedstandards.org/verify?url=${index.host}${r.bundle}`;

test('links (bin): the fixture prints the golden captured from the site\'s own builders', () => {
  const r = host(['links', '--out', EXPECTED]);
  assert.equal(r.err, '');
  assert.equal(r.code, 0);
  assert.equal(r.out, GOLDEN_TEXT);
});

test('links: linksFor equals the golden, record by record', () => {
  assert.equal(golden.records.length, 52);
  assert.deepEqual(linksFor(index), golden.records);
});

test('links: the golden\'s verifier links percent-encode ?url=, unlike the example\'s unencoded form', () => {
  index.records.forEach((r, i) => {
    const g = golden.records[i];
    assert.notEqual(g.verify, unencoded(r), `${r.name}: the golden is the unencoded form`);
    assert.equal(g.verify, `https://typedstandards.org/verify?url=${encodeURIComponent(g.url)}`);
    assert.equal(decodeURIComponent(g.verify), unencoded(r), `${r.name}: the two forms name different bundles`);
  });
});

test('links: the dark theme selects the dark badge, and an absolute bundle URL is used as given', () => {
  const [first] = linksFor(index, 'dark');
  assert.match(first.html, /src="https:\/\/typedstandards\.org\/badge\/typed-standards-verify\.svg\?theme=dark"/);
  const elsewhere = 'https://mirror.example/bundles/core.bundle.json';
  const [moved] = linksFor({ ...index, records: [{ ...index.records[0], bundle: elsewhere }] });
  assert.equal(moved.url, elsewhere);
  assert.equal(moved.verify, `https://typedstandards.org/verify?url=${encodeURIComponent(elsewhere)}`);
});
