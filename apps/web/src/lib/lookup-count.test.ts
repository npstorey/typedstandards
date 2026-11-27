// typedstandards#143 by (i), IMPL TS-143 Part 2: the verifier's lookup count, taken
// on the server from the routes that receive a target, per host per UTC day.
// Rulings: hub #335 7226545429 (per-publisher counts, Yes by (i)); this issue's
// premises report 7226900499 and the seat's ruling 7227111427 (storage 1, Neon; the
// non-public rule; bots skipped; each lookup adds one to its host's row for the day;
// totals published on /privacy; S162[1] on the record page too).
//
// WHAT IS DRIVEN.
//   - `lookupHost`: the host a lookup counts under, read as the verifier reads its
//     input (`Verifier.run`: trim, `detectInputMode`, the commitment candidates
//     against the hinted host or the anchor), and the non-public rule.
//   - `recordLookup`: the one writer. What reaches the store is (day, host) and
//     nothing else; a bot, a prefetch, a bundle, a non-public host write nothing; a
//     failed or slow write is logged as a class and never thrown.
//   - `sqlLookupStore`: the two statements, against a query function that records them.
//   - The table (`apps/web/lookup-counts.sql`): three columns.
//   - The routes, read as text: only the two verify pages count, after the
//     response; the verifier sends this site nothing for a typed or pasted lookup.
//   - The words, rendered: S160[1], S161[1], S162[1], S163[1] in its totals-only
//     form (W7), W8 and W9; and the page unchanged without the count.
//
// The modules are loaded per test through a specifier the type checker does not
// resolve, so the red commit failed test by test and every commit type-checks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createElement, type FunctionComponent } from 'react';
import { markup, source, SRC } from './tsx-render.test-support.ts';

interface Totals {
  firstDay: string;
  lastDay: string;
  lookups: number;
}
interface Store {
  increment(day: string, host: string): Promise<void>;
  totals(): Promise<Totals | null>;
}
type Query = (text: string, params: unknown[]) => Promise<Record<string, unknown>[]>;
interface CountModule {
  LOOKUP_WRITE_TIMEOUT_MS: number;
  INCREMENT_SQL: string;
  TOTALS_SQL: string;
  isPublicHost(hostname: string): boolean;
  lookupHost(input: string, hintedHost?: string): string | null;
  utcDay(ms: number): string;
  recordLookup(opts: {
    input: string;
    hintedHost?: string;
    headers: Headers;
    store: Store | null;
    now?: number;
    log?: (line: string) => void;
    timeoutMs?: number;
  }): Promise<'counted' | 'not-counted' | 'failed'>;
  sqlLookupStore(query: Query): Store;
}

const COUNT_MODULE = './lookup-count.ts';
async function count(): Promise<CountModule> {
  return (await import(COUNT_MODULE)) as CountModule;
}

type Component = FunctionComponent<Record<string, unknown>>;
async function component(specifier: string, name: string): Promise<Component> {
  const mod = (await import(specifier)) as Record<string, Component>;
  assert.equal(typeof mod[name], 'function', `${specifier} exports ${name}`);
  return mod[name];
}

const { PrivacyStatement } = (await import('@/components/PrivacyStatement')) as unknown as {
  PrivacyStatement: Component;
};

const ID = 'c0ffee00'.repeat(8);
const ANCHOR = 'civicaitools.org'; // host-directory.ts: bareIdentifierHost
const READER = new Headers({
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
});
const NOV_27 = Date.UTC(2026, 10, 27, 23, 59, 59);

function recordingStore() {
  const calls: unknown[][] = [];
  const store: Store = {
    async increment(...args: [string, string]) {
      calls.push(args);
    },
    async totals() {
      return null;
    },
  };
  return { store, calls };
}

// --- The host a lookup counts under -------------------------------------------------

test('a link lookup counts under the host the verifier fetches from', async () => {
  const { lookupHost } = await count();
  const cases: [string, string | undefined, string][] = [
    // /verify?url=<commitment URL>
    [`https://example.org/api/records/${ID}/commitment`, undefined, 'example.org'],
    [`  https://www.example.org/api/records/${ID}/commitment  `, undefined, 'example.org'],
    [`https://example.org/api/evidence/${ID}/commitment`, undefined, 'example.org'],
    // /verify?hash=<id>, and /verify/<id>: the anchor
    [ID, undefined, ANCHOR],
    ['a-record-slug', undefined, ANCHOR],
    // ?hash=<id>&host=https://<host>, and /verify/<host>/<id>: the host the link names
    [ID, 'https://example.org', 'example.org'],
  ];
  for (const [input, hint, expected] of cases) {
    assert.equal(lookupHost(input, hint), expected, `${input} ${hint ?? ''}`);
  }
});

test('not counted: no input, a bundle, an address that does not parse', async () => {
  const { lookupHost } = await count();
  for (const input of ['', '   ', '{"packageHash":"ab"}', '  {"x":1}', 'https://']) {
    assert.equal(lookupHost(input), null, JSON.stringify(input));
  }
});

test('non-public hosts are not counted (the seat\'s ruling 7227111427, reading 2)', async () => {
  const { lookupHost, isPublicHost } = await count();
  const commitment = (origin: string) => `${origin}/api/records/${ID}/commitment`;
  for (const origin of [
    'http://localhost:3000',
    'https://localhost',
    'https://127.0.0.1',
    'https://10.0.0.2',
    'https://192.168.1.1',
    'https://172.16.5.4',
    'https://8.8.8.8',
    'http://[::1]',
    'https://[2001:db8::1]',
    'https://intranet',
    'https://printer.local',
    'https://app.localhost',
    'https://db.internal',
    'https://nas.home.arpa',
    'https://site.test',
    'https://site.invalid',
    'https://site.example',
  ]) {
    assert.equal(lookupHost(commitment(origin)), null, origin);
  }
  // A host hint names a host the same way.
  assert.equal(lookupHost(ID, 'https://localhost'), null);
  assert.equal(lookupHost(ID, 'https://192.168.1.1'), null);
  for (const host of ['example.org', 'civicaitools.org', 'records.example.net', 'xn--bcher-kva.example.com']) {
    assert.equal(isPublicHost(host), true, host);
  }
});

test('the host is all of the lookup that is kept: never the record', async () => {
  const { lookupHost } = await count();
  for (const [input, hint] of [
    [`https://example.org/api/records/${ID}/commitment`, undefined],
    [ID, undefined],
    [ID, 'https://example.org'],
  ] as const) {
    const host = lookupHost(input, hint) as string;
    assert.ok(!host.includes(ID.slice(0, 8)), host);
    assert.ok(!host.includes('/'), host);
  }
});

// --- The one writer ------------------------------------------------------------------

test('a link lookup adds one to its host\'s row for that UTC day, and nothing else reaches the store', async () => {
  const { recordLookup, utcDay } = await count();
  assert.equal(utcDay(NOV_27), '2026-11-27');
  assert.equal(utcDay(NOV_27 + 1000), '2026-11-28');
  const { store, calls } = recordingStore();
  assert.equal(await recordLookup({ input: ID, headers: READER, store, now: NOV_27 }), 'counted');
  assert.equal(await recordLookup({ input: ID, headers: READER, store, now: NOV_27 }), 'counted');
  assert.equal(await recordLookup({ input: ID, hintedHost: 'https://example.org', headers: READER, store, now: NOV_27 + 1000 }), 'counted');
  assert.deepEqual(calls, [
    ['2026-11-27', ANCHOR],
    ['2026-11-27', ANCHOR],
    ['2026-11-28', 'example.org'],
  ]);
});

test('not counted: a bot or a link preview, a prefetch, a bundle, a non-public host', async () => {
  const { recordLookup } = await count();
  const { store, calls } = recordingStore();
  const requests: [string, Headers][] = [
    [ID, new Headers({ 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' })],
    [ID, new Headers({ 'user-agent': 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' })],
    [ID, new Headers({ 'user-agent': 'facebookexternalhit/1.1' })],
    [ID, new Headers({ ...Object.fromEntries(READER), 'next-router-prefetch': '1' })],
    [ID, new Headers({ ...Object.fromEntries(READER), 'sec-purpose': 'prefetch' })],
    [ID, new Headers({ ...Object.fromEntries(READER), purpose: 'prefetch' })],
    ['{"packageHash":"ab"}', READER],
    [`http://localhost:3000/api/records/${ID}/commitment`, READER],
  ];
  for (const [input, headers] of requests) {
    assert.equal(await recordLookup({ input, headers, store, now: NOV_27 }), 'not-counted', JSON.stringify([...headers]));
  }
  assert.deepEqual(calls, []);
});

test('a failed or slow write is logged as a class, never thrown, and the reader never waits on it', async () => {
  const { recordLookup, LOOKUP_WRITE_TIMEOUT_MS } = await count();
  assert.equal(LOOKUP_WRITE_TIMEOUT_MS, 10_000);
  const lines: string[] = [];
  // An error message can carry what the store was given; the log must never print it.
  const marker = 'TEXT-OF-THE-MESSAGE';
  const failing: Store = {
    async increment() {
      throw Object.assign(new Error(`could not connect: ${marker}`), { name: 'NeonDbError', code: '53000' });
    },
    async totals() {
      return null;
    },
  };
  assert.equal(await recordLookup({ input: ID, headers: READER, store: failing, now: NOV_27, log: (l) => lines.push(l) }), 'failed');
  const hanging: Store = { increment: () => new Promise(() => {}), totals: async () => null };
  assert.equal(await recordLookup({ input: ID, headers: READER, store: hanging, now: NOV_27, log: (l) => lines.push(l), timeoutMs: 20 }), 'failed');
  assert.equal(await recordLookup({ input: ID, headers: READER, store: null, now: NOV_27, log: (l) => lines.push(l) }), 'failed');
  assert.deepEqual(lines, [
    'lookup count: write failed (NeonDbError 53000)',
    'lookup count: write failed (timeout)',
    'lookup count: write failed (no store)',
  ]);
  for (const line of lines) assert.ok(!line.includes(marker) && !line.includes(ID.slice(0, 8)) && !line.includes(ANCHOR), line);
});

// --- The store -----------------------------------------------------------------------

test('the store: one upsert of (day, host), and a totals read that names no host', async () => {
  const { sqlLookupStore, INCREMENT_SQL, TOTALS_SQL } = await count();
  assert.equal(
    INCREMENT_SQL,
    'INSERT INTO lookup_counts (day, host, lookups) VALUES ($1::date, $2, 1) ' +
      'ON CONFLICT (day, host) DO UPDATE SET lookups = lookup_counts.lookups + 1',
  );
  assert.equal(
    TOTALS_SQL,
    "SELECT to_char(min(day), 'YYYY-MM-DD') AS first_day, to_char(max(day), 'YYYY-MM-DD') AS last_day, " +
      'coalesce(sum(lookups), 0)::text AS lookups FROM lookup_counts',
  );
  assert.doesNotMatch(TOTALS_SQL, /\bhost\b/);
  const seen: [string, unknown[]][] = [];
  let rows: Record<string, unknown>[] = [];
  const store = sqlLookupStore(async (text, params) => {
    seen.push([text, params]);
    return rows;
  });
  await store.increment('2026-11-27', 'example.org');
  assert.deepEqual(seen, [[INCREMENT_SQL, ['2026-11-27', 'example.org']]]);
  rows = [{ first_day: null, last_day: null, lookups: '0' }];
  assert.equal(await store.totals(), null, 'nothing counted yet');
  rows = [{ first_day: '2026-11-27', last_day: '2026-12-02', lookups: '1234' }];
  assert.deepEqual(await store.totals(), { firstDay: '2026-11-27', lastDay: '2026-12-02', lookups: 1234 });
});

test('the table keeps three columns: the day, the host, the count', () => {
  const sql = fs.readFileSync(path.join(SRC, '..', 'lookup-counts.sql'), 'utf8');
  const create = sql.slice(sql.indexOf('CREATE TABLE'), sql.indexOf(');', sql.indexOf('CREATE TABLE')));
  const columns = [...create.matchAll(/^\s+([a-z_]+)\s+(date|text|integer)\b/gm)].map((m) => `${m[1]} ${m[2]}`);
  assert.deepEqual(columns, ['day date', 'host text', 'lookups integer']);
  assert.match(create, /PRIMARY KEY \(day, host\)/);
  assert.match(sql, /DROP TABLE IF EXISTS lookup_counts;/, 'the reversal');
});

// --- The routes ----------------------------------------------------------------------

test('only the two verify routes count, with the input the verifier gets, after the response', () => {
  assert.match(source('app/verify/page.tsx'), /await countLookup\(initial, hintedHost\);/);
  assert.match(source('app/verify/[...target]/page.tsx'), /await countLookup\(id, host\);/);
  const callers: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.tsx?$/.test(entry.name) && !/\.test(-support)?\.ts$|test-support/.test(entry.name)) {
        const text = fs.readFileSync(full, 'utf8');
        if (/\b(countLookup|recordLookup)\(/.test(text)) callers.push(path.relative(SRC, full));
      }
    }
  };
  walk(SRC);
  assert.deepEqual(callers.sort(), [
    path.join('app', 'verify', '[...target]', 'page.tsx'),
    path.join('app', 'verify', 'page.tsx'),
    path.join('lib', 'count-lookup.ts'),
    path.join('lib', 'lookup-count.ts'),
  ]);
  const server = source('lib/count-lookup.ts');
  assert.match(server, /after\(/, 'the write is after the response');
  assert.match(server, /if \(!SITE_LOOKUP_COUNT\) return;/);
});

test('a typed or pasted lookup sends this site nothing: the verifier runs in place', () => {
  const verifier = source('components/Verifier.tsx');
  assert.doesNotMatch(verifier, /useRouter|router\.(push|replace)|location\.(assign|replace)|location\.href\s*=/);
  assert.equal((verifier.match(/history\.(pushState|replaceState)/g) ?? []).join(), 'history.replaceState');
});

test('the count is on only where its database is set, and the address is never written into a bundle', () => {
  const config = source('../next.config.ts');
  const env = config.slice(config.indexOf('env: {'), config.indexOf('}', config.indexOf('env: {')));
  assert.match(env, /TYPEDSTANDARDS_LOOKUP_COUNT: process\.env\.LOOKUP_COUNT_DATABASE_URL \? "on" : "",/);
  assert.doesNotMatch(env, /LOOKUP_COUNT_DATABASE_URL:/);
  assert.match(source('lib/site-lookup-count.ts'), /export const SITE_LOOKUP_COUNT = process\.env\.TYPEDSTANDARDS_LOOKUP_COUNT === "on";/);
});

// --- The words -----------------------------------------------------------------------

const S161_1 =
  'Typed Standards — signed records you can verify yourself. Verification runs in your browser; nothing is uploaded. ' +
  'This site counts records you verify from links you open, by website and day; see the privacy page.';
const TODAY_FOOTER = 'Typed Standards — signed records you can verify yourself. Verification runs in your browser; nothing is uploaded.';
const S162_1 =
  'This site counts, each day, the website of a record you verify from a link you open, never the record. ' +
  'Dropping in a saved bundle, or verifying offline, is not counted.';

function text(html: string): string {
  return html.replace(/<[^>]+>/g, '').replace(/&#x27;/g, "'").replace(/\s+/g, ' ').trim();
}

test('the footer: S161[1] with the count, today\'s words without it', async () => {
  const FooterLine = await component('@/components/FooterLine', 'FooterLine');
  const on = markup(createElement(FooterLine, { lookupCount: true }));
  assert.equal(text(on), S161_1);
  assert.match(on, /<a href="\/privacy#lookups"[^>]*>the privacy page<\/a>/);
  assert.equal(text(markup(createElement(FooterLine, { lookupCount: false }))), TODAY_FOOTER);
  assert.match(source('app/layout.tsx'), /<FooterLine lookupCount=\{SITE_LOOKUP_COUNT\} \/>/);
});

test('the verify page and the record page: S162[1] after the intro, only with the count', async () => {
  const LookupCountLine = await component('@/components/LookupCountLine', 'LookupCountLine');
  const html = markup(createElement(LookupCountLine, {}));
  assert.equal(text(html), S162_1);
  assert.match(html, /^<p data-statement="lookup-count"/);
  assert.match(html, /<a href="\/privacy#lookups"[^>]*>This site counts<\/a>/);
  for (const page of ['app/verify/page.tsx', 'app/verify/[...target]/page.tsx']) {
    assert.match(source(page), /\{SITE_LOOKUP_COUNT && <LookupCountLine \/>\}/, page);
  }
});

const TOTALS = { firstDay: '2026-11-27', lastDay: '2026-12-02', lookups: 1234 };

test('/privacy with the count: S160[1], S163[1] totals-only (W7) under W9, and the totals (W8)', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: null, lookupCount: { totals: TOTALS } }));
  const statement = (id: string) => {
    const at = html.indexOf(`data-statement="${id}"`);
    assert.ok(at !== -1, id);
    return text(html.slice(html.indexOf('>', at) + 1, html.indexOf('</p>', at)));
  };
  assert.equal(
    statement('hosting'),
    "Requests your browser sends to this site reach the service that hosts it, as requests to any website do. This site's own code keeps no record of them beyond the daily count described below.",
  );
  assert.equal(
    statement('verify-count'),
    'This site counts, each day, the website of a record you verify from a link you open, and the count keeps nothing else.',
  );
  assert.ok(html.indexOf('data-statement="verify-count"') > html.indexOf('data-statement="verify-links"'), 'after verify-links');
  assert.match(html, /<section id="lookups" class="mt-10"><h2[^>]*>What this site counts<\/h2>/);
  assert.equal(
    statement('lookups'),
    'This site counts the website of each record you verify from a link you open, and the day. ' +
      'The count keeps no network address, no cookie, no identifier, and never the record. ' +
      'This site publishes only the totals across all websites. ' +
      'To verify without being counted, drop in a saved bundle, or verify offline with the command-line tool. ' +
      "When any verifier fetches a record, that record's own server sees the fetch. " +
      'Only verifying a saved bundle offline avoids that.',
  );
  assert.equal(statement('lookup-totals'), 'Lookups counted across all websites from November 27, 2026 to December 2, 2026: 1,234.');
  assert.doesNotMatch(html, /publisher index/, 'the index does not exist yet (#142)');
});

test('/privacy with the count and nothing counted yet: no totals line', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: null, lookupCount: { totals: null } }));
  assert.match(html, /<section id="lookups"/);
  assert.doesNotMatch(html, /lookup-totals/);
});

test('/privacy without the count: today\'s words, and no word of a count', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: null, lookupCount: null }));
  const at = html.indexOf('data-statement="hosting"');
  assert.equal(
    text(html.slice(html.indexOf('>', at) + 1, html.indexOf('</p>', at))),
    "Requests your browser sends to this site reach the service that hosts it, as requests to any website do. This site's own code keeps no record of them.",
  );
  assert.doesNotMatch(html, /verify-count|id="lookups"|lookup-totals|daily count/);
});
