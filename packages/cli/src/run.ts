// The command dispatcher (typedstandards#109 G0 D3). JSON on stdout, one document,
// written only when the command succeeds or `verify` has a verdict to report;
// diagnostics on stderr; a stated exit code.

import { CliError, EXIT, type ExitCode } from './errors.ts';
import type { Io } from './io.ts';
import { SEED_VARIABLE } from './seed.ts';
import { SIGN_OPTIONS, signCommand, type SignValues } from './sign.ts';
import { VERIFY_OPTIONS, verifyCommand, type VerifyValues } from './verify.ts';
import { VIEW_OPTIONS, viewCommand, type ViewValues } from './view.ts';
import { WITHDRAW_OPTIONS, withdrawCommand, type WithdrawValues } from './withdraw.ts';

export const USAGE = `Usage: typedstandards <command> [options]

  sign      --input <file|->  [--output-file <path> [--output-url <url> [--content-type <type>]]]
            Build and sign a record from an envelope input (JSON). Verifies the result
            offline before printing {package, envelopeHash, signature}.
  withdraw  --input <file|->
            Sign an attestation/withdraws/v1 for a record. Prints {node, nodeId, signature}.
  view      --signed <file> --visibility <state> [--withdrawal <file>]... [--trust-registry-url <url>]
            [--package-url <url>] [--title <text>]
            Build the commitment view a host serves, with the package inline.
  verify    --input <file|-> [--blob <file>]... [--json]
            Verify what sign or view printed, offline. Prints {ok, nodeId, failures};
            --json adds every check's fields and the lifecycle resolution.

sign and withdraw read the signing seed from ${SEED_VARIABLE}
(the standard base64 of a 32-byte Ed25519 seed). It is never an argument.

Exit codes: 0 ok, 1 verification failed, 2 usage or input error,
3 signing seed missing or malformed, 4 internal error.
`;

type Command = (values: Record<string, unknown>, io: Io) => Promise<{ document: unknown; code: number }>;

const printed = (document: unknown) => ({ document, code: EXIT.ok });

const COMMANDS: Record<string, { options: Record<string, { type: 'string' | 'boolean'; multiple?: boolean }>; run: Command }> = {
  sign: { options: SIGN_OPTIONS, run: async (v, io) => printed(await signCommand(v as SignValues, io)) },
  withdraw: { options: WITHDRAW_OPTIONS, run: async (v, io) => printed(await withdrawCommand(v as WithdrawValues, io)) },
  view: { options: VIEW_OPTIONS, run: async (v, io) => printed(await viewCommand(v as ViewValues, io)) },
  verify: { options: VERIFY_OPTIONS, run: (v, io) => verifyCommand(v as VerifyValues, io) },
};

/** Run one command line; returns the exit code. Never throws. */
export async function run(argv: readonly string[], io: Io): Promise<ExitCode> {
  const [name, ...args] = argv;
  if (name === '--help' || name === '-h' || name === 'help') {
    io.stdout(USAGE);
    return EXIT.ok;
  }
  if (name === '--version') {
    io.stdout(`${JSON.stringify({ name: '@typedstandards/cli', version: io.version })}\n`);
    return EXIT.ok;
  }
  const command = name === undefined ? undefined : COMMANDS[name];
  if (command === undefined) {
    io.stderr(`${name === undefined ? 'no command given' : `unknown command: ${name}`}\n\n${USAGE}`);
    return EXIT.usage;
  }
  try {
    let values: Record<string, unknown>;
    try {
      values = io.parseArgs({ args, options: command.options, strict: true, allowPositionals: false }).values;
    } catch (err) {
      throw new CliError(EXIT.usage, (err as Error).message);
    }
    const { document, code } = await command.run(values, io);
    io.stdout(`${JSON.stringify(document, null, 2)}\n`);
    return code as ExitCode;
  } catch (err) {
    if (err instanceof CliError) {
      io.stderr(`typedstandards ${name}: ${err.message}\n`);
      return err.code;
    }
    // A bug. The message only: a stack trace is not needed to report it.
    io.stderr(`typedstandards ${name}: internal error: ${(err as Error)?.message ?? String(err)}\n`);
    return EXIT.internal;
  }
}
