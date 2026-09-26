// What the commands need from the machine, supplied by `node/main.ts`
// (typedstandards#109 G0 D1): `src/` reads no environment, opens no file and
// writes nothing itself. Tests build an `Io` in memory.

import type { verifyRecord } from '@typedstandards/verify-core';

/** The subset of `node:util`'s `parseArgs` the commands call. */
export type ParseArgs = (config: {
  args: string[];
  options: Record<string, { type: 'string' | 'boolean'; multiple?: boolean }>;
  strict: true;
  allowPositionals: false;
}) => { values: Record<string, string | boolean | Array<string | boolean> | undefined> };

export interface Io {
  /** The environment. The CLI reads one variable from it, in `sign` and `withdraw` only. */
  env: Readonly<Record<string, string | undefined>>;
  /** A file's bytes; `-` is standard input. Throws when the file cannot be read. */
  readFile(path: string): Uint8Array;
  stdout(text: string): void;
  stderr(text: string): void;
  parseArgs: ParseArgs;
  /** The current time, for a `createdAt` the input omits. */
  now(): Date;
  /** A random UUID, for a `packageId` the input omits. */
  uuid(): string;
  /** The package version, for `--version`. */
  version: string;
  /** verify-core's `verifyRecord`, replaceable so a test can make the self-check fail. */
  verifyRecord?: typeof verifyRecord;
}
