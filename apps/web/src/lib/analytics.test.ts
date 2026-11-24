// typedstandards#85: Plausible's tag, built switched off, and the redaction it
// applies before anything is sent.
//
// WHAT IS DRIVEN.
//   - `resolveAnalytics`, the rule (the reference application's, without its
//     prior-era variable).
//   - `PLAUSIBLE_INIT`, the initializer the page renders, run in a `vm` context
//     beside a transcription of the vendor script's start-up
//     (plausible/analytics `tracker/src/plausible.js:58-65` at 0855e286), in
//     both orders the two scripts can run in. The `transformRequest` that the
//     vendor's `init` receives is the function every redaction case below
//     drives, so what is tested is the bytes the browser runs. The context holds
//     `URL` and nothing else, so the function cannot read `location`.
//   - `AnalyticsTags` and `PrivacyStatement`, the real components, rendered to
//     static markup with `react-dom/server`. The test runner does not load TSX,
//     so a load hook transpiles `.tsx` files with the TypeScript compiler, and a
//     resolve hook maps the `@/` alias to `src/`. Nothing is stubbed.
//   - `layout.tsx` and `privacy/page.tsx`, read as text and parsed: both render
//     from `SITE_ANALYTICS`, the one constant `site-analytics.ts` resolves; and
//     `next.config.ts`, which fixes both variables at build.
// What Next emits from these is measured against a built `.next/`, with the
// variables set and unset, in the pull request; not here.
//
// THE VENDOR'S PAYLOAD (`tracker/src/track.js:86-157` at 0855e286): `n` the
// event name, `v` the script version, `u` the page address, `d` the site
// domain, `r` the referrer or null, `p` properties when an event has them.
// Synthetic values below: example.org is reserved; ids are hex.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { registerHooks } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  ANALYTICS_SERVICES,
  PLAUSIBLE_INIT,
  PLAUSIBLE_QUEUE,
  PLAUSIBLE_REDACT,
  plausibleScriptSrc,
  resolveAnalytics,
  type AnalyticsConfig,
} from './analytics.ts';

const SRC = fileURLToPath(new URL('..', import.meta.url));

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@/')) {
      const base = path.join(SRC, specifier.slice(2));
      for (const candidate of [base, `${base}.ts`, `${base}.tsx`]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return { url: pathToFileURL(candidate).href, shortCircuit: true };
        }
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith('file:') && url.endsWith('.tsx')) {
      const file = fileURLToPath(url);
      const out = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
        fileName: file,
        compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
      });
      return { format: 'module', source: out.outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});

// Imported after the hooks are registered: they are what load these two files.
const { AnalyticsTags } = await import('@/components/AnalyticsTags');
const { PrivacyStatement } = await import('@/components/PrivacyStatement');

const SERVICE = 'NEXT_PUBLIC_ANALYTICS_SERVICE';
const ID = 'NEXT_PUBLIC_ANALYTICS_ID';
const TEST_ID = 'pa-testkeyabcdef0123456';
const TEST_CONFIG: AnalyticsConfig = { service: 'plausible', id: TEST_ID };

// --- The rule ---------------------------------------------------------------

test('the rule: nothing unless both are set and the service is known', () => {
  assert.deepEqual([...ANALYTICS_SERVICES], ['plausible']);
  const cases: [Record<string, string>, AnalyticsConfig | null][] = [
    [{}, null],
    [{ [SERVICE]: '', [ID]: '' }, null],
    [{ [SERVICE]: '   ', [ID]: '\t' }, null],
    [{ [SERVICE]: 'plausible' }, null],
    [{ [ID]: TEST_ID }, null],
    [{ [SERVICE]: 'plausible', [ID]: '  ' }, null],
    [{ [SERVICE]: 'google-analytics', [ID]: TEST_ID }, null],
    [{ [SERVICE]: 'Plausible', [ID]: TEST_ID }, null],
    [{ [SERVICE]: 'plausible', [ID]: TEST_ID }, TEST_CONFIG],
    [{ [SERVICE]: ' plausible ', [ID]: ` ${TEST_ID} ` }, TEST_CONFIG],
  ];
  for (const [env, expected] of cases) {
    assert.deepEqual(resolveAnalytics(env), expected, JSON.stringify(env));
  }
});

// --- The initializer --------------------------------------------------------

// plausible/analytics lib/plausible_web/live/installation/instructions.ex:181 at
// 0855e286, the first line of the vendor's inline initializer.
const VENDOR_QUEUE_LINE =
  'window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};';

// tracker/src/plausible.js:58-65 at 0855e286, the web script's start-up, with
// its `init` replaced by one that records the options it is given.
const VENDOR_STARTUP = 'window.plausible=(window.plausible||{});if(plausible.o){__init(plausible.o)}plausible.init=__init;';

type Payload = Record<string, unknown>;
type Transform = (payload: Payload) => Payload | null;

/** Run the initializer and the vendor's start-up in `order`; the options `init` received. */
function initOptions(order: 'initializer first' | 'script first'): unknown[] {
  const received: unknown[] = [];
  const sandbox: Record<string, unknown> = { URL, __init: (options: unknown) => received.push(options) };
  sandbox.window = sandbox;
  const context = vm.createContext(sandbox);
  const scripts = order === 'initializer first' ? [PLAUSIBLE_INIT, VENDOR_STARTUP] : [VENDOR_STARTUP, PLAUSIBLE_INIT];
  for (const script of scripts) vm.runInContext(script, context);
  return received;
}

function shippedTransform(): Transform {
  const [options] = initOptions('initializer first');
  const transform = (options as { transformRequest?: unknown }).transformRequest;
  assert.equal(typeof transform, 'function');
  return transform as Transform;
}

test("the initializer is the vendor's first line, then init with transformRequest", () => {
  assert.equal(PLAUSIBLE_QUEUE, VENDOR_QUEUE_LINE);
  assert.equal(PLAUSIBLE_INIT, `${VENDOR_QUEUE_LINE}\nplausible.init({transformRequest:${PLAUSIBLE_REDACT}})`);
  assert.ok(!PLAUSIBLE_INIT.includes('<'), 'nothing in it can close the script element');
});

for (const order of ['initializer first', 'script first'] as const) {
  test(`${order}: the vendor's init runs once, with transformRequest, so the first pageview is redacted`, () => {
    const received = initOptions(order);
    assert.equal(received.length, 1);
    const options = received[0] as Record<string, unknown>;
    assert.deepEqual(Object.keys(options), ['transformRequest']);
    assert.equal(typeof options.transformRequest, 'function');
  });
}

// --- The redaction ----------------------------------------------------------

const SITE = 'https://typedstandards.org';
const HASH = 'a3f1c0de'.repeat(8);
const COMMITMENT = `https://example.org/api/records/${HASH}/commitment`;

function pageview(u: string, r: string | null = null): Payload {
  return { n: 'pageview', v: 1, u, d: 'typedstandards.org', r };
}

test('a record page, at either depth, is sent as /verify/[record]', () => {
  const transform = shippedTransform();
  for (const address of [`${SITE}/verify/${HASH}`, `${SITE}/verify/example.org/${HASH}`]) {
    assert.deepEqual(transform(pageview(address)), pageview(`${SITE}/verify/[record]`), address);
  }
});

test('/verify with each query form is sent as /verify', () => {
  const transform = shippedTransform();
  for (const query of [
    `?url=${encodeURIComponent(COMMITMENT)}`,
    `?hash=${HASH}`,
    `?hash=${HASH}&host=${encodeURIComponent('https://example.org')}`,
  ]) {
    assert.deepEqual(transform(pageview(`${SITE}/verify${query}`)), pageview(`${SITE}/verify`), query);
  }
});

test('a referrer on this site’s /verify is redacted the same way', () => {
  const transform = shippedTransform();
  const cases: [string, string][] = [
    [`${SITE}/verify?url=${encodeURIComponent(COMMITMENT)}`, `${SITE}/verify`],
    [`${SITE}/verify?hash=${HASH}&host=${encodeURIComponent('https://example.org')}`, `${SITE}/verify`],
    [`${SITE}/verify/${HASH}`, `${SITE}/verify/[record]`],
    [`${SITE}/verify/example.org/${HASH}`, `${SITE}/verify/[record]`],
    [`http://typedstandards.org/verify/${HASH}`, 'http://typedstandards.org/verify/[record]'],
  ];
  for (const [referrer, expected] of cases) {
    assert.deepEqual(transform(pageview(`${SITE}/badge`, referrer)), pageview(`${SITE}/badge`, expected), referrer);
  }
});

test('decoys: another page of this site, and an outside referrer, are sent as the script built them', () => {
  const transform = shippedTransform();
  const decoys: Payload[] = [
    pageview(`${SITE}/`),
    pageview(`${SITE}/badge?utm_source=newsletter&ref=example`),
    pageview(`${SITE}/examples#top`),
    pageview(`${SITE}/verifying`),
    pageview(`${SITE}/badge`, `${SITE}/roadmap?utm_campaign=launch`),
    pageview(`${SITE}/`, `https://example.org/verify/${HASH}?url=x`),
    { n: 'Outbound Link: Click', v: 1, u: `${SITE}/examples`, d: 'typedstandards.org', r: null, p: { url: 'https://example.org/' } },
  ];
  for (const decoy of decoys) {
    const expected = structuredClone(decoy);
    assert.deepEqual(transform(decoy), expected, JSON.stringify(decoy));
  }
});

test('a verify page and an outside referrer: the page is redacted, the referrer is not', () => {
  const transform = shippedTransform();
  const outside = `https://example.org/post?id=${HASH}`;
  assert.deepEqual(transform(pageview(`${SITE}/verify/${HASH}`, outside)), pageview(`${SITE}/verify/[record]`, outside));
});

test("an event from a verify page carries no properties, so no link's address", () => {
  const transform = shippedTransform();
  const click = {
    n: 'Outbound Link: Click',
    v: 1,
    u: `${SITE}/verify/example.org/${HASH}`,
    d: 'typedstandards.org',
    r: null,
    p: { url: COMMITMENT },
  };
  assert.deepEqual(transform(click), {
    n: 'Outbound Link: Click',
    v: 1,
    u: `${SITE}/verify/[record]`,
    d: 'typedstandards.org',
    r: null,
  });
});

test('every path under /verify, any case, with its fragment, is redacted', () => {
  const transform = shippedTransform();
  const cases: [string, string][] = [
    [`${SITE}/verify`, `${SITE}/verify`],
    [`${SITE}/verify#${HASH}`, `${SITE}/verify`],
    [`${SITE}/Verify/${HASH}`, `${SITE}/verify/[record]`],
    [`${SITE}/verify/a/b/${HASH}`, `${SITE}/verify/[record]`],
    [`${SITE}/verify/${HASH}?utm_source=x#frag`, `${SITE}/verify/[record]`],
  ];
  for (const [address, expected] of cases) {
    assert.deepEqual(transform(pageview(address)), pageview(expected), address);
  }
});

test('an address that does not parse: the page drops the event, the referrer is dropped', () => {
  const transform = shippedTransform();
  assert.equal(transform(pageview('not a url')), null);
  assert.deepEqual(transform(pageview(`${SITE}/badge`, 'not a url')), pageview(`${SITE}/badge`, null));
});

// --- The tag ----------------------------------------------------------------

function markup(element: unknown): string {
  return renderToStaticMarkup(element as Parameters<typeof renderToStaticMarkup>[0]);
}

test('unset: the tag renders nothing', () => {
  assert.equal(markup(createElement(AnalyticsTags, { config: resolveAnalytics({}) })), '');
});

test('set: the vendor script and the initializer carrying transformRequest', () => {
  const config = resolveAnalytics({ [SERVICE]: 'plausible', [ID]: TEST_ID });
  const html = markup(createElement(AnalyticsTags, { config }));
  assert.equal(plausibleScriptSrc(TEST_ID), `https://plausible.io/js/${TEST_ID}.js`);
  assert.equal(
    html,
    `<script async="" src="https://plausible.io/js/${TEST_ID}.js"></script>` +
      `<script id="plausible-init">${PLAUSIBLE_INIT}</script>`,
  );
  assert.ok(html.includes('plausible.init({transformRequest:function(payload){'));
});

// --- Wiring: one constant, read by the layout and by /privacy ---------------

function parse(relative: string): ts.SourceFile {
  const file = path.join(SRC, relative);
  return ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

/** The names a file imports from `module`. */
function importsFrom(source: ts.SourceFile, module: string): string[] {
  const names: string[] = [];
  for (const statement of source.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      statement.moduleSpecifier.text === module &&
      statement.importClause?.namedBindings &&
      ts.isNamedImports(statement.importClause.namedBindings)
    ) {
      for (const element of statement.importClause.namedBindings.elements) names.push(element.name.text);
    }
  }
  return names;
}

/** Each `<tag attribute={identifier} />` in the file, with the tag names of its JSX ancestors. */
function usages(source: ts.SourceFile, tag: string, attribute: string): { value: string; ancestors: string[] }[] {
  const found: { value: string; ancestors: string[] }[] = [];
  const visit = (node: ts.Node, ancestors: string[]): void => {
    if (ts.isJsxSelfClosingElement(node) && node.tagName.getText(source) === tag) {
      for (const property of node.attributes.properties) {
        if (
          ts.isJsxAttribute(property) &&
          property.name.getText(source) === attribute &&
          property.initializer &&
          ts.isJsxExpression(property.initializer) &&
          property.initializer.expression
        ) {
          found.push({ value: property.initializer.expression.getText(source), ancestors });
        }
      }
    }
    const next = ts.isJsxElement(node) ? [...ancestors, node.openingElement.tagName.getText(source)] : ancestors;
    ts.forEachChild(node, (child) => visit(child, next));
  };
  visit(source, []);
  return found;
}

test('the root layout, the only layout, renders the tag from SITE_ANALYTICS inside <body>', () => {
  const layouts: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/^layout\.(tsx|ts|jsx|js)$/.test(entry.name)) layouts.push(path.relative(SRC, full));
    }
  };
  walk(path.join(SRC, 'app'));
  assert.deepEqual(layouts, [path.join('app', 'layout.tsx')]);

  const layout = parse('app/layout.tsx');
  assert.deepEqual(importsFrom(layout, '@/lib/site-analytics'), ['SITE_ANALYTICS']);
  const tags = usages(layout, 'AnalyticsTags', 'config');
  assert.equal(tags.length, 1);
  assert.equal(tags[0].value, 'SITE_ANALYTICS');
  assert.deepEqual(tags[0].ancestors.slice(0, 2), ['html', 'body']);
});

test('/privacy renders its statement from the same SITE_ANALYTICS, and the footer links to it', () => {
  const page = parse('app/privacy/page.tsx');
  assert.deepEqual(importsFrom(page, '@/lib/site-analytics'), ['SITE_ANALYTICS']);
  const statements = usages(page, 'PrivacyStatement', 'analytics');
  assert.deepEqual(statements.map((s) => s.value), ['SITE_ANALYTICS']);

  const layout = fs.readFileSync(path.join(SRC, 'app/layout.tsx'), 'utf8');
  const footer = layout.slice(layout.indexOf('<footer'), layout.indexOf('</footer>'));
  assert.match(footer, /<Link href="\/privacy"[^>]*>\s*Privacy\s*<\/Link>/);
});

test('site-analytics reads each variable by its literal name', () => {
  const source = fs.readFileSync(path.join(SRC, 'lib/site-analytics.ts'), 'utf8');
  assert.match(source, /NEXT_PUBLIC_ANALYTICS_SERVICE: process\.env\.NEXT_PUBLIC_ANALYTICS_SERVICE,/);
  assert.match(source, /NEXT_PUBLIC_ANALYTICS_ID: process\.env\.NEXT_PUBLIC_ANALYTICS_ID,/);
});

// Without these, Next 16's server build leaves `process.env.NEXT_PUBLIC_…` as a
// read at render time, so the dynamic /verify routes decide per request while
// /privacy, prerendered, keeps the build's values (measured: a build without
// the variables, served with them set, rendered the tag on six /verify
// responses and on no prerendered page).
test('next.config.ts fixes both variables at build, unset as ""', () => {
  const source = fs.readFileSync(path.join(SRC, '..', 'next.config.ts'), 'utf8');
  const env = source.slice(source.indexOf('env: {'), source.indexOf('}', source.indexOf('env: {')));
  assert.match(env, /NEXT_PUBLIC_ANALYTICS_SERVICE: process\.env\.NEXT_PUBLIC_ANALYTICS_SERVICE \?\? "",/);
  assert.match(env, /NEXT_PUBLIC_ANALYTICS_ID: process\.env\.NEXT_PUBLIC_ANALYTICS_ID \?\? "",/);
  assert.equal(resolveAnalytics({ [SERVICE]: '', [ID]: '' }), null);
});

// --- The privacy page's analytics section -----------------------------------

test('/privacy, unset: no analytics section, and no word of Plausible', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: resolveAnalytics({}) }));
  assert.ok(html.includes('data-statement="storage"'), 'the page renders');
  assert.doesNotMatch(html, /plausible/i);
  assert.doesNotMatch(html, /id="analytics"/);
  assert.doesNotMatch(html, /data-statement="analytics-/);
  assert.match(html, /Apart from the requests the verifier makes for a record you check, this site&#x27;s pages ask/);
});

test('/privacy, one variable without the other: still no analytics section', () => {
  for (const env of [{ [SERVICE]: 'plausible' }, { [ID]: TEST_ID }, { [SERVICE]: 'other', [ID]: TEST_ID }]) {
    const html = markup(createElement(PrivacyStatement, { analytics: resolveAnalytics(env) }));
    assert.doesNotMatch(html, /plausible/i, JSON.stringify(env));
  }
});

test('/privacy, set: the analytics section names the redaction and a way to object', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: resolveAnalytics({ [SERVICE]: 'plausible', [ID]: TEST_ID }) }));
  assert.match(html, /<section id="analytics"/);
  for (const id of ['analytics-what', 'analytics-redaction', 'analytics-vendor', 'analytics-objection']) {
    assert.ok(html.includes(`data-statement="${id}"`), id);
  }
  const redaction = html.slice(html.indexOf('data-statement="analytics-redaction"'));
  assert.match(redaction, /<code class="font-mono">\/verify<\/code>/);
  assert.match(redaction, /<code class="font-mono">\/verify\/\[record\]<\/code>/);
  assert.match(html, /href="https:\/\/plausible\.io\/data-policy"/);
  assert.match(html, /href="https:\/\/plausible\.io\/docs\/excluding-localstorage"/);
  assert.match(html, /and the analytics described below, this site&#x27;s pages ask/);
  assert.doesNotMatch(html, new RegExp(TEST_ID), 'the page does not print the script key');
});
