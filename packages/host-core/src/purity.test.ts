// The purity rule for host-core's shipped src/ (typedstandards#125 G0 D3;
// .claude/rules/purity.md): no Node built-in import, no `process`, no `Buffer`.
// The typecheck already reddens on all three (its build config sets `types: []`,
// and scripts/type-check-universe.test.mjs probes it); this test reads the source
// itself, with TypeScript's parser, so a `/// <reference types="node" />` that
// would let the typecheck pass cannot hide one. Test files are exempt.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { builtinModules } from 'node:module';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const SRC = dirname(fileURLToPath(import.meta.url));
const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

function shipped(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return shipped(full);
    return e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [full] : [];
  });
}

/** Every Node built-in import, `process` or `Buffer` identifier, and Node type reference in a file. */
export function impurities(fileName: string, text: string): string[] {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.ES2022, true);
  const out: string[] = [];
  for (const ref of sf.typeReferenceDirectives) out.push(`/// <reference types="${ref.fileName}" />`);
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      if (BUILTINS.has(node.moduleSpecifier.text)) out.push(`import '${node.moduleSpecifier.text}'`);
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const [arg] = node.arguments;
      if (arg && ts.isStringLiteral(arg) && BUILTINS.has(arg.text)) out.push(`import('${arg.text}')`);
    }
    if (ts.isIdentifier(node) && (node.text === 'process' || node.text === 'Buffer')) out.push(node.text);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

test('purity: the instrument finds a built-in import, process and Buffer in a probe', () => {
  const probe = "import { readFileSync } from 'node:fs';\nimport 'path';\nexport const e = process.env.X;\nexport const b = Buffer.from('x');\n";
  assert.deepEqual(impurities('probe.ts', probe), ["import 'node:fs'", "import 'path'", 'process', 'Buffer']);
});

test('purity: host-core\'s shipped src/ imports no Node built-in and reads no process or Buffer', () => {
  const files = shipped(SRC);
  assert.ok(files.length >= 10, `derived ${files.length} shipped files`);
  const found = files.flatMap((f) => impurities(f, readFileSync(f, 'utf8')).map((what) => `${relative(SRC, f)}: ${what}`));
  assert.deepEqual(found, []);
});
