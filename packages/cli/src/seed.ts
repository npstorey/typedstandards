// The signing seed (typedstandards#109 G0 D3): the standard base64 of a 32-byte
// Ed25519 seed, from one environment variable. It is never an argument, never
// printed and never written; every message here names the variable, never its
// value.

import { base64ToBytes } from '@typedstandards/verify-core';
import { CliError, EXIT } from './errors.ts';

export const SEED_VARIABLE = 'TYPEDSTANDARDS_SIGNING_SEED_B64';

// 32 bytes are 43 base64 characters and one "=" of padding.
const BASE64_OF_32_BYTES = /^[A-Za-z0-9+/]{43}=$/;

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** The seed's bytes. The caller zeroes them when done. */
export function readSeed(env: Readonly<Record<string, string | undefined>>): Uint8Array {
  const value = env[SEED_VARIABLE];
  if (value === undefined || value.trim() === '') {
    throw new CliError(EXIT.seed, `${SEED_VARIABLE} is not set; sign and withdraw read the signing seed from it`);
  }
  const text = value.trim();
  const malformed = new CliError(
    EXIT.seed,
    `${SEED_VARIABLE} is not the standard base64 of a 32-byte seed (44 characters, ending in "=")`,
  );
  if (!BASE64_OF_32_BYTES.test(text)) throw malformed;
  const seed = base64ToBytes(text);
  // A non-canonical final character decodes to the same bytes; refuse it, so
  // one seed has one spelling.
  if (seed.length !== 32 || toBase64(seed) !== text) {
    seed.fill(0);
    throw malformed;
  }
  return seed;
}
