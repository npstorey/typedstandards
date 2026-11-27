// Test support, not a test: lets a `node --test` file import the site's `.tsx`
// components and render them to static markup, as `analytics.test.ts` does
// inline. A load hook transpiles `.tsx` with the TypeScript compiler, and a
// resolve hook maps the `@/` alias to `src/`. Nothing is stubbed.
//
// Import this module before any `.tsx` import, and import the components with
// `await import(...)` after it, so the hooks are registered first.

import fs from 'node:fs';
import path from 'node:path';
import { registerHooks } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { renderToStaticMarkup } from 'react-dom/server';

export const SRC = fileURLToPath(new URL('..', import.meta.url));

registerHooks({
  resolve(specifier, context, nextResolve) {
    // `next` has no exports map, so Node's ESM resolver needs the file name of a
    // subpath the bundler resolves bare.
    if (/^next\/[a-z-]+$/.test(specifier)) return nextResolve(`${specifier}.js`, context);
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

export function markup(element: unknown): string {
  return renderToStaticMarkup(element as Parameters<typeof renderToStaticMarkup>[0]);
}

/** A file under `src/`, read as text. */
export function source(relative: string): string {
  return fs.readFileSync(path.join(SRC, relative), 'utf8');
}
