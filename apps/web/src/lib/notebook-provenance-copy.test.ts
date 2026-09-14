// The skeleton notebook's reading, in the reader's words (ruling D7 = B,
// civic-ai-tools-website#434).
//
// This file's vocabulary is a port of the reference app's
// (`src/lib/evidence/trust-signal.ts` there). The reference app moved the label
// from "Skeleton notebook (not executed)" to "Analysis notebook (not executed)":
// "Skeleton" names the code path that writes the notebook, and a reader has no
// reason to know it. "executed" stays, the word the other reading uses.
//
// What this file pins:
//   - the ruled words, through the constant that owns them;
//   - the same words in the vocabulary copy's source text, and the old words
//     absent from it;
//   - that the copy no longer calls a provenance value reserved or unwritten:
//     the reference producer has written both values since
//     civic-ai-tools-website#401.
// The provenance VALUE `skeleton` is unchanged and is not pinned here: it is in
// a package's signed bytes, and the label is not.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NOTEBOOK_PROVENANCE_SIGNALS, NOTEBOOK_PROVENANCE_VALUES } from './trust-signal.ts';

const SOURCE = readFileSync(new URL('./trust-signal.ts', import.meta.url), 'utf8');

/** The copy's notebookProvenance section: from its `// --- notebookProvenance` header to the next header. */
function notebookProvenanceSection(source: string): string {
  const start = source.indexOf('// --- notebookProvenance');
  assert.ok(start !== -1, 'trust-signal.ts has no notebookProvenance section header');
  const end = source.indexOf('\n// ---', start + 1);
  assert.ok(end !== -1, 'the notebookProvenance section has no following header');
  return source.slice(start, end);
}

test('D7 = B: the skeleton reading is "Analysis notebook (not executed)"', () => {
  const skeleton = NOTEBOOK_PROVENANCE_SIGNALS.skeleton;
  assert.equal(skeleton.label, 'Analysis notebook (not executed)');
  assert.equal(skeleton.tier, 'normal', 'a skeleton is not a failure');
  assert.doesNotMatch(skeleton.label, /skeleton/i, 'the label names no code path');
});

test('D7 = B: the vocabulary copy spells the ruled words, and not the old ones', () => {
  const section = notebookProvenanceSection(SOURCE);
  assert.match(section, /label: 'Analysis notebook \(not executed\)'/);
  assert.doesNotMatch(SOURCE, /Skeleton notebook \(not executed\)/);
});

test('the vocabulary copy calls no provenance value reserved or unwritten', () => {
  const section = notebookProvenanceSection(SOURCE);
  assert.ok(NOTEBOOK_PROVENANCE_VALUES.length > 0, 'the vocabulary declares no provenance value');
  for (const value of NOTEBOOK_PROVENANCE_VALUES) {
    assert.ok(section.includes(`'${value}'`), `the section does not mention '${value}'`);
  }
  assert.doesNotMatch(section, /\breserved\b/i);
  assert.doesNotMatch(section, /no code path writes/i);
  assert.doesNotMatch(section, /only value emitted/i);
});
