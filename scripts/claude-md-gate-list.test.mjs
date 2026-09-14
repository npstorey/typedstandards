// Guard: CLAUDE.md's gate list pins no count, and it names exactly the steps
// ci.yml runs, in ci.yml's order; and every other markdown passage that lists
// the CI gates names exactly ci.yml's gate steps, in ci.yml's order (second
// section below). Run: node --test scripts/claude-md-gate-list.test.mjs
//
// WHAT WAS MEASURED. At 1d24991 the list pinned `# pass 97 produce-core / 64
// verify-core / 116 web` and `# pass 8`. produce-core already passed 99 there,
// so the pin was stale by 2 the day it was measured; a pass total rises with
// every test added. `# fail 0` is the gate, and it stays true as tests are added.
//
// WHERE THE CELLS COME FROM. The guard reads CLAUDE.md itself: every bullet
// under its `## Build / test` heading is a gate, the bullet's first code span is
// the command, and the rest of the bullet is the cell. No line numbers and no
// list of which bullets to check: a bullet added to that section is checked the
// moment it is written. ci.yml's steps come from its `run:` keys.
//
// WHAT COUNTS AS A PINNED COUNT. A standalone non-zero integer, or a spelled
// cardinal from one to twenty. `0` is allowed (`# fail 0`). An issue reference
// (`#68`, no space after the `#`) and a digit inside a word (`ES2022`) are not
// counts. Both extractors are driven over samples with the answers written out,
// so an extractor that returns nothing cannot pass.
//
// Blind spots, stated: a count written as a range or a fraction ("half") is not
// recognised; a multi-line `run: |` step is refused rather than read.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SECTION = 'Build / test';

// ---------------------------------------------------------------------------
// Extractors

/** Every bullet under `## <section>`: its first code span (command) and the rest (cell). */
export function gateListOf(markdown, section = SECTION) {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.trim() === `## ${section}`);
  if (start === -1) throw new Error(`no "## ${section}" heading`);
  const bullets = [];
  for (const line of lines.slice(start + 1)) {
    if (/^#{1,2} /.test(line)) break;
    if (line.startsWith('- ')) bullets.push(line.slice(2).trim());
    else if (bullets.length && /^\s+\S/.test(line) && !line.trimStart().startsWith('- ')) {
      bullets[bullets.length - 1] += ` ${line.trim()}`;
    }
  }
  return bullets.map((text) => {
    const m = /^`([^`]+)`\s*(?:—\s*)?(.*)$/.exec(text);
    if (!m) throw new Error(`a bullet in "## ${section}" does not open with a command code span: ${text}`);
    return { command: m[1], cell: m[2] };
  });
}

/** The `run:` command of every step in a workflow, in file order. */
export function ciRunsOf(yaml) {
  return [...yaml.matchAll(/^\s*(?:-\s+)?run:[ \t]*(.*?)[ \t]*$/gm)].map((m) => {
    if (m[1] === '' || /^[|>]/.test(m[1])) throw new Error(`a multi-line run step is not read by this guard: "${m[0].trim()}"`);
    return m[1];
  });
}

const CARDINALS =
  'one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty';
const COUNT_RE = new RegExp(`(?<!#|\\w|\\d\\.)[1-9]\\d*(?!\\w|\\.\\d)|\\b(?:${CARDINALS})\\b`, 'gi');

/** The non-zero counts a cell pins. */
export function pinnedCounts(cell) {
  return cell.match(COUNT_RE) ?? [];
}

// ---------------------------------------------------------------------------
// The extractors, driven over samples with the answers written out

test('extractor: gateListOf reads every bullet of the section, continuation lines included, and nothing outside it', () => {
  const sample = [
    '# Title',
    '## Build / test',
    'Intro paragraph with `a code span`.',
    '',
    '- `npm run a` — `# pass` 3, `# fail 0`.',
    '- `node --test b.mjs` — first line',
    '  second line.',
    '- `npm run c`',
    '',
    '## Next',
    '- `npm run d` — outside the section',
  ].join('\n');
  assert.deepEqual(gateListOf(sample), [
    { command: 'npm run a', cell: '`# pass` 3, `# fail 0`.' },
    { command: 'node --test b.mjs', cell: 'first line second line.' },
    { command: 'npm run c', cell: '' },
  ]);
  assert.throws(() => gateListOf('## Other\n- `x` — y'), /no "## Build \/ test" heading/);
  assert.throws(() => gateListOf('## Build / test\n- no code span'), /does not open with a command code span/);
});

test('extractor: ciRunsOf reads every single-line run step in order, and refuses a block scalar', () => {
  const sample = [
    'jobs:',
    '  ci:',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - name: Install',
    '        run: npm ci --ignore-scripts',
    '      - run: npm run build   ',
    '      # run: a comment is not a step',
  ].join('\n');
  assert.deepEqual(ciRunsOf(sample), ['npm ci --ignore-scripts', 'npm run build']);
  assert.throws(() => ciRunsOf('      - run: |\n          npm test'), /multi-line/);
});

test('extractor: pinnedCounts finds integers and spelled cardinals, and not zero, issue refs or digits in words', () => {
  assert.deepEqual(pinnedCounts('`# pass` 97 produce-core / 64 verify-core / 116 web, `# fail 0`.'), ['97', '64', '116']);
  assert.deepEqual(pinnedCounts('`# pass 8`, `# fail 0`'), ['8']);
  assert.deepEqual(pinnedCounts('two `OK` lines, then `Dependency-budget check passed.`'), ['two']);
  assert.deepEqual(pinnedCounts('`# fail 0`; see #68, target ES2022, tsconfig.json'), []);
  assert.deepEqual(pinnedCounts('an `OK` line per budgeted package'), []);
  assert.deepEqual(pinnedCounts('stale by 2. Three more, version 1.2'), ['2', 'Three']);
});

// ---------------------------------------------------------------------------
// The real files

const gates = () => gateListOf(readFileSync(join(ROOT, 'CLAUDE.md'), 'utf8'));
const runs = () => ciRunsOf(readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8'));

test('PREMISE: the real CLAUDE.md and ci.yml both yield a non-empty gate sequence', () => {
  assert.ok(gates().length > 0, 'CLAUDE.md yielded no gate');
  assert.ok(runs().length > 0, 'ci.yml yielded no run step');
});

test('no gate cell in CLAUDE.md pins a non-zero count', () => {
  const pinned = gates()
    .map(({ command, cell }) => ({ command, counts: pinnedCounts(cell) }))
    .filter((g) => g.counts.length > 0);
  assert.deepEqual(pinned, [], 'a pass total moves with every test added; state the invariant (`# fail 0`) instead');
});

test('CLAUDE.md names exactly the steps ci.yml runs, in both directions and in the same order', () => {
  const listed = gates().map((g) => g.command);
  const ran = runs();
  assert.deepEqual(listed.filter((c) => !ran.includes(c)), [], 'CLAUDE.md names commands ci.yml does not run');
  assert.deepEqual(ran.filter((c) => !listed.includes(c)), [], 'ci.yml runs steps CLAUDE.md does not name');
  assert.deepEqual(listed, ran, 'CLAUDE.md says its list is in the order ci.yml runs the steps');
});

// ---------------------------------------------------------------------------
// Every gate list in the repository, derived
//
// WHAT WAS MEASURED. At 7b4fe19 `.claude/agents/impl.md` listed seven commands
// "in this order" where ci.yml ran nine gate steps after its install: it left
// out both `node --test scripts/...` guards and said `npm test` for
// `npm run test`. The checks above read CLAUDE.md only, and main's CI went green
// with that list.
//
// THE UNIVERSE. Every markdown file git tracks or would track
// (`git ls-files --cached --others --exclude-standard`), split into heading
// sections. No path is named: a doc that lists the gates is checked the moment
// it is written, committed or not.
//
// WHAT COUNTS AS A GATE LIST. A section that names three or more distinct gate
// steps (ci.yml's run steps other than the `npm ci` install), each as a code
// span holding the step's command. One or two is a passage citing the checks it
// is about, not a list of CI's gates: `.claude/rules/purity.md` names the
// typecheck and lint commands in "What enforces it", one per enforcing check,
// and the verify-core build in "Build order"; CONTRIBUTING.md's getting-started
// steps name the build and the tests; a CHANGELOG names the build order. Three
// or more is an enumeration of CI's gates, which is a claim to be the list.
// npm's aliases for a run (`npm test`, `npm t`, `npm run-script x`) count as
// naming that step, so a misspelt gate is recognised and then fails. The test
// prints every section it classified, either way.
//
// WHAT A GATE LIST MUST SAY. The gate steps it names, in document order, are
// exactly ci.yml's gate steps in ci.yml's order. The install step is a
// precondition, not a gate, and is not compared: CLAUDE.md lists it first,
// impl.md tells the reader to run `npm ci` after stating its list. (The
// CLAUDE.md check above does hold CLAUDE.md's install bullet to ci.yml.)
//
// Blind spots, stated: a gate list split across headings so that no one section
// names three gate steps is not recognised; a command inside a gate list that is
// neither a gate step nor an alias of one is not flagged (the CLAUDE.md bullet
// check above does flag it there); fenced code blocks and non-markdown files
// are not read. The rule errs loud the other way: a section that names three
// gate steps without meaning to list CI's gates fails, and the fix is to name
// all of them in order or to point at CLAUDE.md's list instead.

export const GATE_LIST_MIN = 3;
const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/;
const HEADING_RE = /^ {0,3}#{1,6}(?:[ \t]|$)/;
const isInstall = (command) => /^npm ci(?:\s|$)/.test(command);
const quoted = (commands) => commands.map((c) => `\`${c}\``).join(', ');

/** A markdown file's heading sections, with frontmatter and fenced code removed. */
export function sectionsOf(markdown) {
  const lines = markdown.split('\n');
  let i = 0;
  if (lines[0] === '---') {
    const end = lines.indexOf('---', 1);
    if (end !== -1) i = end + 1;
  }
  const sections = [{ heading: '', lines: [] }];
  let fence = null;
  for (; i < lines.length; i++) {
    const line = lines[i];
    const f = FENCE_RE.exec(line);
    if (fence) {
      if (f && f[1][0] === fence[0] && f[1].length >= fence.length) fence = null;
      continue;
    }
    if (f) {
      fence = f[1];
      continue;
    }
    if (HEADING_RE.test(line)) sections.push({ heading: line.trim(), lines: [] });
    else sections[sections.length - 1].lines.push(line);
  }
  return sections.map(({ heading, lines: body }) => ({ heading, text: body.join('\n').trim() }));
}

/** A passage's code spans, whitespace inside each collapsed the way markdown renders it. */
export function codeSpansOf(text) {
  return [...text.matchAll(/`([^`]+)`/g)].map((m) => m[1].replace(/\s+/g, ' ').trim());
}

/** The ci.yml run step a command names, directly or through an npm run alias; undefined if none. */
export function stepNamedBy(command, runs) {
  const canonical = command.replace(/^npm (?:test|tst|t)(?=\s|$)/, 'npm run test').replace(/^npm run-script(?=\s)/, 'npm run');
  return runs.find((r) => r === canonical);
}

/** Every section that names at least one ci.yml step: the commands it names, and how many distinct gate steps. */
export function passagesNamingSteps(markdown, runs) {
  const out = [];
  for (const { heading, text } of sectionsOf(markdown)) {
    const named = codeSpansOf(text).filter((span) => stepNamedBy(span, runs) !== undefined);
    if (named.length === 0) continue;
    const gateSteps = new Set(named.map((span) => stepNamedBy(span, runs)).filter((s) => !isInstall(s)));
    out.push({ heading, listed: named, gateSteps: gateSteps.size });
  }
  return out;
}

/** What a gate list gets wrong against ci.yml's run steps; [] when it is exactly right. */
export function gateListProblems(listed, runs) {
  const gates = runs.filter((r) => !isInstall(r));
  const body = listed.filter((c) => !isInstall(c));
  const missing = gates.filter((g) => !body.includes(g));
  const extra = body.filter((c) => !gates.includes(c));
  const problems = [];
  if (missing.length) problems.push(`omits ${quoted(missing)}`);
  if (extra.length) problems.push(`names ${quoted(extra)}, which is not a gate step as ci.yml spells it`);
  if (!missing.length && !extra.length && body.join('\n') !== gates.join('\n')) {
    problems.push(`names the gate steps in a different order or more than once: ${quoted(body)}`);
  }
  return problems;
}

/** Every markdown file git tracks, or would track, that is on disk. */
function markdownUniverse() {
  return execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: ROOT, encoding: 'utf8' })
    .split('\0')
    .filter((f) => /\.md$/i.test(f) && existsSync(join(ROOT, f)))
    .sort();
}

test('extractor: sectionsOf splits on headings, and reads neither frontmatter nor fenced code', () => {
  const sample = [
    '---',
    'name: `npm run z`',
    '---',
    'intro `npm run a`',
    '# One',
    '`npm run b`',
    '```sh',
    '# not a heading',
    '`npm run c`',
    '```',
    '## Two',
    'text',
  ].join('\n');
  assert.deepEqual(sectionsOf(sample), [
    { heading: '', text: 'intro `npm run a`' },
    { heading: '# One', text: '`npm run b`' },
    { heading: '## Two', text: 'text' },
  ]);
});

test('extractor: codeSpansOf joins a span broken across lines; stepNamedBy follows npm run aliases and nothing looser', () => {
  const runs = ['npm ci --ignore-scripts', 'npm run a', 'npm run test', 'node --test x.mjs'];
  assert.deepEqual(codeSpansOf('`npm run a`, `node --test\n  x.mjs` and `y`.'), ['npm run a', 'node --test x.mjs', 'y']);
  assert.equal(stepNamedBy('npm run a', runs), 'npm run a');
  assert.equal(stepNamedBy('npm test', runs), 'npm run test');
  assert.equal(stepNamedBy('npm t', runs), 'npm run test');
  assert.equal(stepNamedBy('npm run-script a', runs), 'npm run a');
  assert.equal(stepNamedBy('npm testx', runs), undefined);
  assert.equal(stepNamedBy('npm ci', runs), undefined);
  assert.equal(stepNamedBy('npm run lint', runs), undefined);
});

test('extractor: passagesNamingSteps counts distinct gate steps per section, the install step not among them', () => {
  const runs = ['npm ci --ignore-scripts', 'npm run a', 'npm run test', 'node --test x.mjs', 'npm run d'];
  const sample = [
    '# Cites',
    '`npm ci --ignore-scripts`, `npm run a`, then `npm run a` again, and `npm run d`.',
    '# Lists',
    '`npm run a`, `npm test`,',
    '`node --test x.mjs`, `npm run lint`.',
    '# Silent',
    '`npm run lint`',
  ].join('\n');
  assert.deepEqual(passagesNamingSteps(sample, runs), [
    { heading: '# Cites', listed: ['npm ci --ignore-scripts', 'npm run a', 'npm run a', 'npm run d'], gateSteps: 2 },
    { heading: '# Lists', listed: ['npm run a', 'npm test', 'node --test x.mjs'], gateSteps: 3 },
  ]);
});

test('extractor: gateListProblems accepts exactly the gate steps in order, wherever the install step is named', () => {
  const runs = ['npm ci --ignore-scripts', 'npm run a', 'npm run test', 'node --test x.mjs'];
  const gates = ['npm run a', 'npm run test', 'node --test x.mjs'];
  assert.deepEqual(gateListProblems(gates, runs), []);
  assert.deepEqual(gateListProblems(['npm ci --ignore-scripts', ...gates], runs), []);
  assert.deepEqual(gateListProblems([...gates, 'npm ci --ignore-scripts'], runs), []);
  assert.deepEqual(gateListProblems(['npm run a', 'npm test', 'node --test x.mjs'], runs), [
    'omits `npm run test`',
    'names `npm test`, which is not a gate step as ci.yml spells it',
  ]);
  assert.deepEqual(gateListProblems(['npm run a', 'npm run test'], runs), ['omits `node --test x.mjs`']);
  assert.deepEqual(gateListProblems(['npm run test', 'npm run a', 'node --test x.mjs'], runs), [
    'names the gate steps in a different order or more than once: `npm run test`, `npm run a`, `node --test x.mjs`',
  ]);
  assert.deepEqual(gateListProblems([...gates, 'npm run a'], runs), [
    'names the gate steps in a different order or more than once: `npm run a`, `npm run test`, `node --test x.mjs`, `npm run a`',
  ]);
});

test('PREMISE: the markdown universe is derived from git and holds at least one gate list', () => {
  const files = markdownUniverse();
  assert.ok(files.length > 0, 'git listed no markdown file: the instrument saw nothing');
  const lists = files.flatMap((f) =>
    passagesNamingSteps(readFileSync(join(ROOT, f), 'utf8'), runs()).filter((p) => p.gateSteps >= GATE_LIST_MIN),
  );
  assert.ok(lists.length > 0, `no gate list among ${files.length} markdown files: the comparison below would be vacuous`);
});

test("every gate list in the repository's markdown names exactly ci.yml's gate steps, in ci.yml's order", (t) => {
  const ran = runs();
  const problems = [];
  for (const file of markdownUniverse()) {
    for (const { heading, listed, gateSteps } of passagesNamingSteps(readFileSync(join(ROOT, file), 'utf8'), ran)) {
      const where = `${file}${heading ? ` § ${heading}` : ''}`;
      if (gateSteps < GATE_LIST_MIN) {
        t.diagnostic(`not a gate list (names ${gateSteps} of fewer than ${GATE_LIST_MIN} gate steps): ${where}`);
        continue;
      }
      t.diagnostic(`gate list (names ${gateSteps} gate steps): ${where}`);
      for (const problem of gateListProblems(listed, ran)) problems.push(`${where}: ${problem}`);
    }
  }
  assert.deepEqual(problems, [], 'a passage that lists CI gates must name exactly the steps ci.yml runs, in its order');
});
