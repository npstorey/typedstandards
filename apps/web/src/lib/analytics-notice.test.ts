// typedstandards#85 and #143, IMPL TS-143 Part 1: the analytics notice on
// typedstandards.org, under the owner's NA-2 B (tell, with a one-click off, for
// a service that sets no cookie), ND-2 A (fixed at the lower left on its
// conditions), ND-X-2 A (a hide control at every state), ND-M-2 B (six months,
// in the browser's own storage) and ND-H-2 A (per host). Rulings: hub #335
// 7226362407 and 7226545429; this issue's 7227111427 (the seat, on the
// premises report 7226900499).
//
// WHAT IS DRIVEN.
//   - The words, by the row each one is (planning `temp/s4/w0/words.md`
//     79f8556b…, `memo2/words2.md` 0e9f5a37…), and the drafted words W1-W9
//     of the premises report, which the words check reads.
//   - The browser script the layout renders before the page is interactive
//     (`ANALYTICS_CHOICE_SCRIPT`): it keeps the hide and the off, decides the
//     notice's place, and is the one implementation the notice, the privacy
//     page's control, the tag's loader and its send gate all call. It is run
//     in a `vm` context with a storage and a document of plain objects, so
//     what is tested is the bytes the browser runs.
//   - `AnalyticsNotice`, `AnalyticsChoice` and `PrivacyStatement`, rendered to
//     static markup.
//
// WHY THE IMPORTS ARE DYNAMIC. The modules this file drives did not exist on
// the base. Each test loads them through a specifier the type checker does not
// resolve, so the red commit failed test by test (a static import of a missing
// module fails the whole file at link time) and every commit type-checks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createElement, type FunctionComponent } from 'react';
import { markup, source } from './tsx-render.test-support.ts';
import { resolveAnalytics } from './analytics.ts';

// --- Loading the modules under test -------------------------------------------

interface NoticeModule {
  ANALYTICS_MEMORY_KEY: string;
  MEMORY_MONTHS: number;
  ANALYTICS_API: string;
  NOTICE_PLACE_RULE: string;
  ANALYTICS_CHOICE_SCRIPT: string;
  holderOf(config: { service: string }): string;
  noticeWords(holder: string): {
    heading: string;
    telling: string[];
    turnOff: string;
    hide: string;
    privacyLink: string;
    off: string[];
  };
  choiceWords(holder: string): { on: string; off: string; turnOff: string; turnOn: string };
}

const NOTICE_MODULE = './analytics-notice.ts';
const NOTICE_COMPONENT = '@/components/AnalyticsNotice';
const CHOICE_COMPONENT = '@/components/AnalyticsChoice';

async function notice(): Promise<NoticeModule> {
  return (await import(NOTICE_MODULE)) as NoticeModule;
}

type Component = FunctionComponent<Record<string, unknown>>;

async function component(specifier: string, name: string): Promise<Component> {
  const mod = (await import(specifier)) as Record<string, Component>;
  assert.equal(typeof mod[name], 'function', `${specifier} exports ${name}`);
  return mod[name];
}

const { PrivacyStatement } = await import('@/components/PrivacyStatement');

const PLAUSIBLE = resolveAnalytics({ NEXT_PUBLIC_ANALYTICS_SERVICE: 'plausible', NEXT_PUBLIC_ANALYTICS_ID: 'pa-testkeyabcdef0123456' });

// --- The words, by row -----------------------------------------------------------

test('the notice says what the ruled rows say, for Plausible', async () => {
  const { noticeWords, holderOf } = await notice();
  assert.equal(holderOf({ service: 'plausible' }), 'Plausible');
  const words = noticeWords('Plausible');
  assert.equal(words.heading, 'Site analytics'); // S145[1]
  assert.deepEqual(words.telling, [
    // S49[1]
    'Your browser sends the address of each page you visit on this site to Plausible, an analytics service.',
    // S49's correction for this site (premises report, section 2), in the words check's rewrite
    "A verify page's address is sent without what you verify.",
  ]);
  assert.equal(words.turnOff, 'Turn analytics off'); // S59[1]
  assert.equal(words.hide, 'Hide this message'); // S53[1]
  assert.equal(words.privacyLink, 'Full privacy page'); // the owner's words, in S52[1]'s place
  assert.deepEqual(words.off, [
    // S60[1]
    'Analytics is off in this browser. Nothing is sent to Plausible from the next page you open.',
    // W1, in S58's place: passed by the words check
    'You can change this on the privacy page.',
  ]);
});

test("the privacy page's control says what W2 and S60 say", async () => {
  const { choiceWords } = await notice();
  assert.deepEqual(choiceWords('Plausible'), {
    on: 'Analytics is on in this browser.', // W2
    off: 'Analytics is off in this browser. Nothing is sent to Plausible from the next page you open.', // S60[1]
    turnOff: 'Turn analytics off', // S59[1]
    turnOn: 'Turn analytics on', // W3's button
  });
});

// --- The notice's markup -----------------------------------------------------------

test('the notice: its heading names it, and it tells, with the off, the hide and the link', async () => {
  const AnalyticsNotice = await component(NOTICE_COMPONENT, 'AnalyticsNotice');
  const html = markup(createElement(AnalyticsNotice, { holder: 'Plausible' }));
  assert.match(html, /^<aside id="analytics-notice" class="analytics-notice" aria-labelledby="analytics-notice-heading">/);
  assert.match(html, /<h2 id="analytics-notice-heading"[^>]*>Site analytics<\/h2>/);
  const on = html.slice(html.indexOf('analytics-when-on'), html.indexOf('analytics-when-off'));
  assert.match(on, /Your browser sends the address of each page you visit on this site to Plausible, an analytics service\./);
  assert.match(on, /A verify page&#x27;s address is sent without what you verify\./);
  assert.match(html, /class="analytics-when-off"[^>]*>[\s\S]*Analytics is off in this browser\. Nothing is sent to Plausible from the next page you open\./);
  assert.match(html, /You can change this on the privacy page\./);
  // The two buttons, in one style, the off first (S59 "beside Hide this message and in its style").
  const buttons = [...html.matchAll(/<button type="button" class="([^"]*)"[^>]*>([^<]*)<\/button>/g)];
  assert.deepEqual(buttons.map((b) => b[2]), ['Turn analytics off', 'Hide this message']);
  const style = (cls: string) => cls.split(' ').filter((c) => !c.startsWith('analytics-')).join(' ');
  assert.equal(style(buttons[0][1]), style(buttons[1][1]), 'the same style');
  assert.match(buttons[0][1], /analytics-when-on/, 'the off shows only while analytics is on');
  assert.match(buttons[0][1], /analytics-needs-storage/, 'and only where the off can be kept');
  assert.match(html, /<a href="\/privacy" class="[^"]*analytics-when-on"[^>]*>Full privacy page<\/a>/);
  // After the off, the link opens the page at the control (the words check, note on W1).
  assert.match(html, /<a href="\/privacy#analytics" class="[^"]*analytics-when-off"[^>]*>Full privacy page<\/a>/);
  assert.doesNotMatch(html, /cookie/i);
});

// --- The browser script: memory, state and place -----------------------------------

const MONTH = 30 * 24 * 3600 * 1000;
const T0 = Date.UTC(2026, 10, 27, 12, 0, 0); // 2026-11-27T12:00:00Z
const SIX_MONTHS_AFTER_T0 = Date.UTC(2027, 4, 27, 12, 0, 0);

class MemoryStorage {
  data = new Map<string, string>();
  getItem(key: string) {
    return this.data.has(key) ? (this.data.get(key) as string) : null;
  }
  setItem(key: string, value: string) {
    this.data.set(key, String(value));
  }
  removeItem(key: string) {
    this.data.delete(key);
  }
}

class BlockedStorage {
  getItem(): string | null {
    throw new Error('SecurityError');
  }
  setItem(): void {
    throw new Error('SecurityError');
  }
  removeItem(): void {
    throw new Error('SecurityError');
  }
}

interface Rect {
  left: number;
  right: number;
  top: number;
  bottom: number;
  width: number;
  height: number;
}

function rect(left: number, top: number, width: number, height: number): Rect {
  return { left, top, width, height, right: left + width, bottom: top + height };
}

interface Page {
  clock: { now: number };
  storage: MemoryStorage | BlockedStorage | undefined;
  attrs: Map<string, string>;
  styles: Map<string, string>;
  cookieTouched: boolean;
  api(): {
    read(): { usable: boolean; hidden: boolean; off: boolean };
    hide(): boolean;
    off(): boolean;
    on(): boolean;
    place(): void;
  };
  loads: number;
}

/** A page: a document of plain objects, a storage, a clock; the script run in it. */
async function page(opts: {
  storage?: MemoryStorage | BlockedStorage;
  now?: number;
  notice?: Rect;
  controls?: Rect[];
  scrollY?: number;
}): Promise<Page> {
  const { ANALYTICS_CHOICE_SCRIPT, ANALYTICS_API } = await notice();
  const clock = { now: opts.now ?? T0 };
  const attrs = new Map<string, string>();
  const styles = new Map<string, string>();
  const state = { cookieTouched: false, loads: 0 };
  class ClockDate extends Date {
    constructor(...args: unknown[]) {
      if (args.length === 0) super(clock.now);
      else super(...(args as [string]));
    }
    static now() {
      return clock.now;
    }
  }
  const noticeElement = opts.notice
    ? {
        getBoundingClientRect: () => opts.notice as Rect,
        contains: (el: unknown) => el === noticeElement,
      }
    : null;
  const controls = (opts.controls ?? []).map((r) => ({ getBoundingClientRect: () => r }));
  const document = {
    documentElement: {
      setAttribute: (k: string, v: string) => attrs.set(k, String(v)),
      getAttribute: (k: string) => attrs.get(k) ?? null,
      style: { setProperty: (k: string, v: string) => styles.set(k, String(v)) },
    },
    getElementById: (id: string) => (id === 'analytics-notice' ? noticeElement : null),
    querySelectorAll: () => (noticeElement ? [noticeElement, ...controls] : controls),
    get cookie(): string {
      state.cookieTouched = true;
      return '';
    },
    set cookie(_v: string) {
      state.cookieTouched = true;
    },
  };
  const sandbox: Record<string, unknown> = {
    document,
    Date: ClockDate,
    JSON,
    Math,
    isNaN,
    scrollY: opts.scrollY ?? 0,
    __typedstandardsAnalyticsLoad: () => {
      state.loads++;
    },
  };
  sandbox.window = sandbox;
  if (opts.storage) sandbox.localStorage = opts.storage;
  vm.runInContext(ANALYTICS_CHOICE_SCRIPT, vm.createContext(sandbox));
  return {
    clock,
    storage: opts.storage,
    attrs,
    styles,
    get cookieTouched() {
      return state.cookieTouched;
    },
    get loads() {
      return state.loads;
    },
    // `read()` returns an object of the script's realm; it is copied into this one so
    // that `deepEqual`, which compares prototypes, reads only its values.
    api: () => {
      const api = sandbox[ANALYTICS_API] as ReturnType<Page['api']>;
      return { ...api, read: () => ({ ...api.read() }) };
    },
  };
}

test('the memory: the key, the period, and nothing in a cookie', async () => {
  const { ANALYTICS_MEMORY_KEY, MEMORY_MONTHS, ANALYTICS_API, ANALYTICS_CHOICE_SCRIPT } = await notice();
  assert.equal(ANALYTICS_MEMORY_KEY, 'typedstandards-analytics');
  assert.equal(MEMORY_MONTHS, 6);
  assert.equal(ANALYTICS_API, '__typedstandardsAnalytics');
  assert.doesNotMatch(ANALYTICS_CHOICE_SCRIPT, /cookie/i);
  assert.ok(!ANALYTICS_CHOICE_SCRIPT.includes('</'), 'nothing in it can close the script element');
  const storage = new MemoryStorage();
  const p = await page({ storage });
  assert.equal(p.api().hide(), true);
  assert.equal(p.api().off(), true);
  assert.deepEqual([...storage.data.keys()], ['typedstandards-analytics'], 'one key, the probe removed');
  assert.deepEqual(JSON.parse(storage.data.get('typedstandards-analytics') as string), {
    hidden: '2026-11-27T12:00:00.000Z',
    off: '2026-11-27T12:00:00.000Z',
  });
  assert.equal(p.cookieTouched, false);
});

test('the hide is kept six months, then forgotten', async () => {
  const storage = new MemoryStorage();
  const p = await page({ storage });
  assert.deepEqual(p.api().read(), { usable: true, hidden: false, off: false });
  p.api().hide();
  assert.equal(p.attrs.get('data-analytics-notice'), 'none', 'hidden at once');
  p.clock.now = SIX_MONTHS_AFTER_T0 - 1;
  assert.equal(p.api().read().hidden, true, 'a moment before six months');
  p.clock.now = SIX_MONTHS_AFTER_T0;
  assert.equal(p.api().read().hidden, false, 'at six months');
  assert.equal(storage.data.has('typedstandards-analytics'), false, 'and the expired entry is removed');
});

test('the off is kept six months, then forgotten, and the hide keeps its own date', async () => {
  const storage = new MemoryStorage();
  const p = await page({ storage });
  p.api().off();
  assert.equal(p.attrs.get('data-analytics-state'), 'off');
  p.clock.now = T0 + 3 * MONTH;
  p.api().hide();
  p.clock.now = SIX_MONTHS_AFTER_T0;
  assert.deepEqual(p.api().read(), { usable: true, hidden: true, off: false });
  assert.deepEqual(Object.keys(JSON.parse(storage.data.get('typedstandards-analytics') as string)), ['hidden']);
});

test('per host: what one host keeps, another does not read', async () => {
  const here = new MemoryStorage();
  const elsewhere = new MemoryStorage();
  (await page({ storage: here })).api().off();
  assert.equal((await page({ storage: elsewhere })).api().read().off, false);
  assert.equal((await page({ storage: here })).api().read().off, true);
});

test('the off can be undone, and turning it on loads the tag at once', async () => {
  const storage = new MemoryStorage();
  const p = await page({ storage });
  p.api().off();
  assert.equal(p.api().on(), true);
  assert.equal(p.api().read().off, false);
  assert.equal(p.attrs.get('data-analytics-state'), 'on');
  assert.equal(p.loads, 1);
  assert.equal(storage.data.has('typedstandards-analytics'), false, 'nothing left to keep');
});

test('a browser that keeps nothing: nothing is claimed, and the off is not offered', async () => {
  for (const storage of [new BlockedStorage(), undefined]) {
    const p = await page({ storage });
    assert.deepEqual(p.api().read(), { usable: false, hidden: false, off: false });
    assert.equal(p.attrs.get('data-analytics-storage'), 'none');
    assert.equal(p.api().off(), false, 'the off cannot be kept, so it does not happen');
    assert.equal(p.attrs.get('data-analytics-state'), 'on');
    assert.equal(p.api().hide(), false);
    assert.equal(p.attrs.get('data-analytics-notice'), 'none', 'the hide still hides this page');
  }
});

test('stored values that are not ours are read as nothing', async () => {
  for (const value of ['not json', '[]', '{"off":"not a date"}', '{"off":12}', 'null']) {
    const storage = new MemoryStorage();
    storage.setItem('typedstandards-analytics', value);
    const p = await page({ storage });
    assert.deepEqual(p.api().read(), { usable: true, hidden: false, off: false }, value);
  }
});

// --- The place (ND-2 A's first condition, as the seat ruled it: 7227111427 reading 1) --

test('the rule: fixed unless a control is under its box; touching is not under', async () => {
  const { NOTICE_PLACE_RULE } = await notice();
  const rule = vm.runInNewContext(`(${NOTICE_PLACE_RULE})`, { Math }) as (box: Rect, controls: Rect[]) => string;
  // The notice as measured at 1,280 by 800 on main a59453c1: 360 by 216 px, 24 px from the left and the foot.
  const box = rect(24, 560, 360, 216);
  assert.equal(rule(box, []), 'fixed');
  assert.equal(rule(box, [rect(400, 560, 100, 40)]), 'fixed', 'beside it');
  assert.equal(rule(box, [rect(24, 520, 360, 40)]), 'fixed', 'its foot touching the top');
  assert.equal(rule(box, [rect(384, 600, 100, 40)]), 'fixed', 'its left touching the right');
  // /verify at 1,280: the verifier's input, 38 px of it under the notice and 87 px wide.
  assert.equal(rule(box, [rect(297, 548, 704, 50)]), 'flow');
  assert.equal(rule(box, [rect(383, 775, 10, 10)]), 'flow', 'one pixel over a corner');
});

test('the place, as the page decides it before first paint', async () => {
  const box = rect(24, 560, 360, 216);
  const clear = await page({ storage: new MemoryStorage(), notice: box, controls: [rect(400, 100, 100, 40)] });
  assert.equal(clear.attrs.get('data-analytics-notice'), 'show');
  assert.equal(clear.attrs.get('data-analytics-place'), 'fixed');
  assert.equal(clear.styles.get('--analytics-notice-h'), '216px');

  const covered = await page({ storage: new MemoryStorage(), notice: box, controls: [rect(297, 548, 704, 50)] });
  assert.equal(covered.attrs.get('data-analytics-place'), 'flow');
  assert.equal(covered.attrs.get('data-analytics-notice'), 'show');

  // The rule reads the first screen at the top of the page, whatever the scroll when the
  // script runs: a control 548 px down the page is under the box even when the page
  // opened scrolled 400 px, where it shows at 148 px.
  const below = await page({ storage: new MemoryStorage(), notice: box, controls: [rect(297, 548 - 400, 704, 50)], scrollY: 400 });
  assert.equal(below.attrs.get('data-analytics-place'), 'flow');

  const hidden = new MemoryStorage();
  (await page({ storage: hidden })).api().hide();
  const again = await page({ storage: hidden, notice: box });
  assert.equal(again.attrs.get('data-analytics-notice'), 'none');

  const off = new MemoryStorage();
  (await page({ storage: off })).api().off();
  const later = await page({ storage: off, notice: box });
  assert.equal(later.attrs.get('data-analytics-notice'), 'none', 'the off is an answer: the notice does not return');
  assert.equal(later.attrs.get('data-analytics-state'), 'off');
});

// --- The focus rule and the foot margin (ND-2 A's second condition) --------------------

test('while the notice is fixed, the page keeps a foot margin and a scroll padding as tall as it', () => {
  const css = source('app/globals.css');
  const fixed = 'html[data-analytics-notice="show"][data-analytics-place="fixed"]';
  assert.ok(css.includes(`${fixed} {`), 'the rule on the root');
  const rule = css.slice(css.indexOf(`${fixed} {`), css.indexOf('}', css.indexOf(`${fixed} {`)));
  assert.match(rule, /scroll-padding-bottom: calc\(var\(--analytics-notice-h\) \+ 2 \* var\(--analytics-notice-gap\)\);/);
  const body = css.slice(css.indexOf(`${fixed} body {`), css.indexOf('}', css.indexOf(`${fixed} body {`)));
  assert.match(body, /padding-bottom: calc\(var\(--analytics-notice-h\) \+ 2 \* var\(--analytics-notice-gap\)\);/);
  assert.match(css, /\.analytics-notice \{\s*display: none;/, 'nothing shows before the script decides');
});

// --- Wiring ---------------------------------------------------------------------------

test('the layout renders the notice and its script only when the tag renders, the script before the tag', () => {
  const layout = source('app/layout.tsx');
  assert.match(layout, /\{SITE_ANALYTICS && \(\s*<AnalyticsNotice holder=\{holderOf\(SITE_ANALYTICS\)\} \/>\s*\)\}/);
  assert.match(layout, /<main className="flex-1">\s*\{SITE_ANALYTICS && \(/, 'at the top of <main>');
  const script = layout.indexOf('ANALYTICS_CHOICE_SCRIPT }}');
  assert.ok(script > layout.indexOf('</footer>'), 'after the page, so it can see every control');
  assert.ok(script < layout.indexOf('<AnalyticsTags'), 'before the tag, whose loader and gate call it');
  assert.match(layout, /<html lang="en" suppressHydrationWarning>/, 'the script sets attributes on <html> before hydration');
});

// --- The privacy page -------------------------------------------------------------------

test('/privacy with the tag: the storage statement says what is kept, where, and for how long (W6)', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: PLAUSIBLE }));
  const at = html.indexOf('data-statement="storage"');
  const statement = html.slice(at, html.indexOf('</p>', at));
  assert.match(
    statement,
    /This site sets no cookies\. It remembers that you hid its message, and that you turned analytics off if you did\. It keeps both in your browser&#x27;s storage for this site, under the name <code class="font-mono">typedstandards-analytics<\/code>, and uses them for\s+six months\./,
  );
  assert.doesNotMatch(statement, /stores nothing in your browser/);
  assert.match(html, /data-statement="storage" class="analytics-with-storage"/);
  // Where the browser keeps nothing (and without JavaScript), today's statement, which is true there.
  const plain = html.indexOf('data-statement="storage-no-storage"');
  assert.equal(
    html.slice(plain, html.indexOf('</p>', plain)),
    'data-statement="storage-no-storage" class="analytics-without-storage">This site sets no cookies, and its code stores nothing in your browser.',
  );
});

test('/privacy without the tag: the storage statement is unchanged', () => {
  const html = markup(createElement(PrivacyStatement, { analytics: null }));
  const at = html.indexOf('data-statement="storage"');
  assert.equal(
    html.slice(at, html.indexOf('</p>', at)),
    'data-statement="storage">This site sets no cookies, and its code stores nothing in your browser.',
  );
  assert.doesNotMatch(html, /analytics-choice/);
});

test('/privacy with the tag: the way back, after the way to object (W2, W3, W5)', async () => {
  const html = markup(createElement(PrivacyStatement, { analytics: PLAUSIBLE }));
  // W5 in the words check's rewrite, two whole forms: the one naming the control shows only
  // where the browser keeps the off (and so shows the control); the other, today's, elsewhere.
  const objection = html.slice(html.indexOf('data-statement="analytics-objection"'));
  assert.match(
    objection,
    /^data-statement="analytics-objection" class="analytics-with-storage">To object, turn analytics off below\. You can also use an ad blocker or\s+other content blocker that blocks/,
  );
  const plain = html.slice(html.indexOf('data-statement="analytics-objection-no-storage"'));
  assert.match(
    plain,
    /^data-statement="analytics-objection-no-storage" class="analytics-without-storage">To object, use an ad blocker or other content blocker that blocks/,
  );
  const css = source('app/globals.css');
  assert.match(css, /\.analytics-with-storage,\s*html\[data-analytics-storage="kept"\] \.analytics-without-storage \{\s*display: none;/);
  assert.match(css, /html\[data-analytics-storage="kept"\] \.analytics-with-storage \{\s*display: block;/);
  const choice = html.indexOf('data-statement="analytics-choice"');
  assert.ok(choice > html.indexOf('data-statement="analytics-objection-no-storage"'), 'after the way to object');
  const block = html.slice(choice, html.indexOf('</section>', choice));
  assert.match(block, /class="analytics-when-on"[^>]*>Analytics is on in this browser\./);
  assert.match(block, /class="analytics-when-off"[^>]*>Analytics is off in this browser\. Nothing is sent to Plausible from the next page you open\./);
  const buttons = [...block.matchAll(/<button type="button" class="([^"]*)"[^>]*>([^<]*)<\/button>/g)];
  assert.deepEqual(buttons.map((b) => b[2]), ['Turn analytics off', 'Turn analytics on']);
  assert.match(buttons[0][1], /analytics-when-on/);
  assert.match(buttons[1][1], /analytics-when-off/);

  const AnalyticsChoice = await component(CHOICE_COMPONENT, 'AnalyticsChoice');
  assert.ok(markup(createElement(AnalyticsChoice, { holder: 'Plausible' })).includes('Turn analytics on'));
});
