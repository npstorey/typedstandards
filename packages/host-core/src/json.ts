// JSON and byte helpers shared by the host stages (typedstandards#125).

import { parseStrictJson, RepeatedMemberNameError } from '@typedstandards/verify-core';

export type JsonObject = Record<string, unknown>;

/** In-memory files: a path, relative to some root and `/`-separated, to its bytes. */
export type FileMap = ReadonlyMap<string, Uint8Array>;

export const isObject = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);

/** How every file host-core writes is serialized: two-space JSON and a final newline. */
export const serialize = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (text: string): Uint8Array => encoder.encode(text);

/** Decode UTF-8, refusing malformed bytes rather than replacing them. */
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

/** Key-order-sensitive equality of two JSON values, as their serializations. */
export const sameJson = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Parse a file's bytes as JSON, naming the file in the error. The text must be
 * I-JSON (RFC 7493; specification §8.2): one that repeats a member name within an
 * object is refused, before any hash is computed over what it holds
 * (typedstandards#145). host-core's own serialization never writes one.
 */
export function parseJsonFile(bytes: Uint8Array, where: string): unknown {
  let text: string;
  try {
    text = fromUtf8(bytes);
  } catch {
    throw new HostError(`${where} is not UTF-8`);
  }
  try {
    return parseStrictJson(text);
  } catch (err) {
    if (err instanceof RepeatedMemberNameError) {
      throw new HostError(
        `${where} is not I-JSON (RFC 7493): the member name ${JSON.stringify(err.memberName)} is repeated in the object at JSON Pointer ${JSON.stringify(err.pointer)}`,
      );
    }
    throw new HostError(`${where} is not JSON: ${(err as Error).message}`);
  }
}

/** An input or policy error whose message is safe to print. */
export class HostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HostError';
  }
}
