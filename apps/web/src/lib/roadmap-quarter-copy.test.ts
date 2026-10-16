// The roadmap's quarter-dated items state their facts in literals.
//
// A quarter-dated item records what happened in that quarter, so it stays
// true only if the words it renders do not move. `SPECIFICATION.version`
// moves at every spec tag (site-config.ts), so a quarter-dated item that
// renders it changes its claim each time the constant does. The 2026 Q3 item
// once read "v0.1.4 through {SPECIFICATION.version}", and so named two
// revisions tagged in the fourth quarter.
//
// What this file pins:
//   - no `MILESTONES` item with a `quarter` reads `SPECIFICATION.version` in
//     its body;
//   - the 2026 Q3 specification item's revision range, in its rendered words.
// Items without a `quarter`, and the specification link's `SPECIFICATION.url`,
// are not pinned here.
//
// The page is TSX, which the test runner does not load, so the test reads it
// as text and parses it with the TypeScript compiler, walking `MILESTONES` one
// object literal at a time.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const PAGE = 'roadmap/page.tsx';
const SOURCE = readFileSync(new URL('../app/roadmap/page.tsx', import.meta.url), 'utf8');
const FILE = ts.createSourceFile(PAGE, SOURCE, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

type Item = { title: string; quarter: string | undefined; body: ts.Expression };

/** A property of an object literal by name, or undefined. */
function property(object: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  for (const p of object.properties) {
    if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === name) {
      return p.initializer;
    }
  }
  return undefined;
}

/** The `MILESTONES` array's items, each with its title, quarter and body. */
function milestones(): Item[] {
  let array: ts.ArrayLiteralExpression | undefined;
  const find = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'MILESTONES' &&
      node.initializer !== undefined &&
      ts.isArrayLiteralExpression(node.initializer)
    ) {
      array = node.initializer;
      return;
    }
    ts.forEachChild(node, find);
  };
  find(FILE);
  assert.ok(array, `${PAGE} declares no MILESTONES array`);

  return array.elements.map((element, i) => {
    assert.ok(ts.isObjectLiteralExpression(element), `MILESTONES[${i}] is not an object literal`);
    const title = property(element, 'title');
    assert.ok(title && ts.isStringLiteral(title), `MILESTONES[${i}] has no string title`);
    const quarter = property(element, 'quarter');
    assert.ok(
      quarter === undefined || ts.isStringLiteral(quarter),
      `MILESTONES[${i}] ("${title.text}") has a quarter that is not a string literal`,
    );
    const body = property(element, 'body');
    assert.ok(body, `MILESTONES[${i}] ("${title.text}") has no body`);
    return { title: title.text, quarter: quarter?.text, body };
  });
}

/** True when `node` reads `SPECIFICATION.version` (by dot or by bracket). */
function readsSpecificationVersion(node: ts.Node): boolean {
  if (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'SPECIFICATION' &&
    node.name.text === 'version'
  ) {
    return true;
  }
  if (
    ts.isElementAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'SPECIFICATION' &&
    ts.isStringLiteralLike(node.argumentExpression) &&
    node.argumentExpression.text === 'version'
  ) {
    return true;
  }
  return ts.forEachChild(node, readsSpecificationVersion) ?? false;
}

/** JSX text as React renders it: lines trimmed, blank lines dropped, the rest joined by one space. */
function jsxText(raw: string): string {
  const lines = raw.split(/\r\n|\n|\r/);
  return lines
    .map((line, i) => {
      let out = line;
      if (i > 0) out = out.replace(/^[ \t]+/, '');
      if (i < lines.length - 1) out = out.replace(/[ \t]+$/, '');
      return out;
    })
    .filter((line) => line !== '')
    .join(' ');
}

/**
 * The words a body renders. A string body is itself; in JSX, text is
 * collapsed as React does, string-literal expressions are inlined, elements
 * contribute their children, and any other expression stays as `{source}`.
 */
function rendered(body: ts.Node): string {
  if (ts.isStringLiteralLike(body)) return body.text;
  if (ts.isParenthesizedExpression(body)) return rendered(body.expression);
  if (ts.isJsxText(body)) return body.containsOnlyTriviaWhiteSpaces ? '' : jsxText(body.text);
  if (ts.isJsxExpression(body)) {
    if (body.expression === undefined) return '';
    if (ts.isStringLiteralLike(body.expression)) return body.expression.text;
    return `{${body.expression.getText(FILE)}}`;
  }
  if (ts.isJsxFragment(body) || ts.isJsxElement(body)) {
    return body.children.map(rendered).join('');
  }
  if (ts.isJsxSelfClosingElement(body)) return '';
  return `{${body.getText(FILE)}}`;
}

test('the roadmap source parses into quarter-dated items', () => {
  const items = milestones();
  assert.ok(items.length > 0, 'MILESTONES is empty');
  assert.ok(
    items.some((item) => item.quarter !== undefined),
    'no MILESTONES item has a quarter, so the rule below would pass vacuously',
  );
});

test('no quarter-dated roadmap item reads SPECIFICATION.version', () => {
  const offenders = milestones()
    .filter((item) => item.quarter !== undefined && readsSpecificationVersion(item.body))
    .map((item) => `the ${item.quarter} item "${item.title}"`);
  assert.deepEqual(
    offenders,
    [],
    `a quarter-dated item renders the moving SPECIFICATION.version: ${offenders.join('; ')}`,
  );
});

test('the 2026 Q3 specification item names the quarter’s revisions in literals', () => {
  const item = milestones().find(
    (m) => m.quarter === '2026 Q3' && m.title === 'Public specification',
  );
  assert.ok(item, 'the roadmap has no 2026 Q3 "Public specification" item');
  const words = rendered(item.body);
  assert.ok(
    words.includes('Seven revisions were tagged in the quarter, v0.1.4 through v0.1.10.'),
    `the 2026 Q3 item "Public specification" reads: ${words}`,
  );
});
