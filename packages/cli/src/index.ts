// @typedstandards/cli's command logic, I/O-free (typedstandards#109 G0 D1). The
// Node entry, node/main.ts, imports this as `#core` and supplies the `Io`.

export { run, USAGE } from './run.ts';
export { EXIT, type ExitCode } from './errors.ts';
export type { Io, ParseArgs } from './io.ts';
export { SEED_VARIABLE } from './seed.ts';
