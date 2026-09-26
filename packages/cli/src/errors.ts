// Exit codes and the one error type the commands throw (typedstandards#109 G0 D3).

export const EXIT = {
  ok: 0,
  /** A record, or the CLI's own result, did not verify. */
  verificationFailed: 1,
  /** An argument or an input file is wrong. */
  usage: 2,
  /** The signing seed's variable is missing or malformed. */
  seed: 3,
  /** Anything else: a bug in the CLI. */
  internal: 4,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/** An error whose message is safe to print and whose exit code is stated. */
export class CliError extends Error {
  readonly code: ExitCode;

  constructor(code: ExitCode, message: string) {
    super(message);
    this.code = code;
  }
}

export function usageError(message: string): CliError {
  return new CliError(EXIT.usage, message);
}
