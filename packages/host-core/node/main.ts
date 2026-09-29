#!/usr/bin/env node
// host-core's one Node entry (typedstandards#125 G0 D3 + D11): the only file in the
// package that touches the machine. It builds the `Io` the commands in `#cli` run
// on, and nothing else. scripts/type-check-universe.test.mjs pins this file as its
// config's whole program and holds its imports to node:fs, node:path,
// node:process, node:util and #cli.

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import process from 'node:process';
import { parseArgs } from 'node:util';
import { run, type ParseArgs } from '#cli';

const manifest = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };

const toSlash = (path: string): string => path.split(sep).join('/');

function listFiles(dir: string): string[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return [];
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(toSlash(relative(dir, full)));
    }
  };
  walk(dir);
  return out.sort();
}

process.exitCode = await run(process.argv.slice(2), {
  readFile: (path) => new Uint8Array(readFileSync(path)),
  exists: (path) => existsSync(path) && statSync(path).isFile(),
  listFiles,
  writeFile: (path, bytes) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
  },
  resolve: (path) => toSlash(resolve(path)),
  stdout: (text) => void process.stdout.write(text),
  stderr: (text) => void process.stderr.write(text),
  parseArgs: parseArgs as ParseArgs,
  version: manifest.version,
});
