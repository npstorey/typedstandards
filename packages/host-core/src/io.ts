// What the commands need from the machine, supplied by `node/main.ts`
// (typedstandards#125 G0 D3): `src/` opens no file and writes nothing itself. Tests
// build an `Io` in memory.

import type { verifyRecord } from '@typedstandards/verify-core';

/** The subset of `node:util`'s `parseArgs` the commands call. */
export type ParseArgs = (config: {
  args: string[];
  options: Record<string, { type: 'string' | 'boolean' }>;
  strict: true;
  allowPositionals: false;
}) => { values: Record<string, string | boolean | undefined> };

export interface Io {
  /** A file's bytes. Throws when the file cannot be read. */
  readFile(path: string): Uint8Array;
  /** Whether a regular file exists at `path`. */
  exists(path: string): boolean;
  /** Every regular file under `dir`, recursively, as `/`-separated paths relative to it; [] when `dir` is absent. */
  listFiles(dir: string): string[];
  /** Write a file, creating its parent directories. */
  writeFile(path: string, bytes: Uint8Array): void;
  /** An absolute, `/`-separated form of `path`. */
  resolve(path: string): string;
  stdout(text: string): void;
  stderr(text: string): void;
  parseArgs: ParseArgs;
  /** The package version, for `--version`. */
  version: string;
  /** verify-core's `verifyRecord`, replaceable so a test can make a check fetch. */
  verifyRecord?: typeof verifyRecord;
}
