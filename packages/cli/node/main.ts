#!/usr/bin/env node
// The CLI's one Node entry (typedstandards#109 G0 D1): the only file in the
// package that touches the machine. It builds the `Io` the commands in `#core`
// run on, and nothing else. scripts/type-check-universe.test.mjs pins this file
// as its config's whole program and holds its imports to node:fs, node:process,
// node:util and #core.

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { parseArgs } from 'node:util';
import { run, type ParseArgs } from '#core';

const manifest = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };

process.exitCode = await run(process.argv.slice(2), {
  env: process.env,
  // `-` is standard input (file descriptor 0).
  readFile: (path) => new Uint8Array(readFileSync(path === '-' ? 0 : path)),
  stdout: (text) => void process.stdout.write(text),
  stderr: (text) => void process.stderr.write(text),
  parseArgs: parseArgs as ParseArgs,
  now: () => new Date(),
  uuid: () => globalThis.crypto.randomUUID(),
  version: manifest.version,
});
