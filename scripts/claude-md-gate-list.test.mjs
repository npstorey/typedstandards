// Guard: CLAUDE.md's gate list pins no count, and it names exactly the steps
// ci.yml runs, in ci.yml's order. Run: node --test scripts/claude-md-gate-list.test.mjs
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
import { readFileSync } from 'node:fs';
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
