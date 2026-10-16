// The strict parse of a record's JSON text (typedstandards#145; specification §8.2,
// §9.2 check #1; hub ADR-0035).
//
// A record package's JSON text is I-JSON (RFC 7493), the input RFC 8785 JCS
// requires, and I-JSON allows no member name to repeat within an object. The
// platform's `JSON.parse` keeps the last occurrence of a repeated name and drops
// the earlier ones without a word, and the envelope hash is computed over the
// parsed object, so a text with a repeated name hashes as the text without it while
// a reader that keeps another occurrence sees other content. `parseStrictJson`
// refuses such a text, and otherwise returns exactly what `JSON.parse` returns.
//
// Pure: no I/O, no dependency, browser-safe. The walk keeps its own stack, so any
// nesting the platform parser accepts is walked without recursion.

/** A JSON text repeats a member name within one object, so it is not I-JSON (RFC 7493). */
export class RepeatedMemberNameError extends Error {
  /** The repeated member name, unescaped. */
  readonly memberName: string;
  /** The JSON Pointer (RFC 6901) of the object that holds it: `""` for the top-level value. */
  readonly pointer: string;

  constructor(memberName: string, pointer: string) {
    super(
      `JSON text is not I-JSON (RFC 7493): the member name ${JSON.stringify(memberName)} is repeated in the object at JSON Pointer ${JSON.stringify(pointer)}`,
    );
    this.name = 'RepeatedMemberNameError';
    this.memberName = memberName;
    this.pointer = pointer;
  }
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const OPEN_OBJECT = 0x7b;
const CLOSE_OBJECT = 0x7d;
const OPEN_ARRAY = 0x5b;
const CLOSE_ARRAY = 0x5d;
const COMMA = 0x2c;

interface Frame {
  /** The member names seen so far, for an object; null for an array. */
  names: Set<string> | null;
  /** The next string read is a member name (an object, after `{` or `,`). */
  expectName: boolean;
  /** The current member's name (an object) or element index (an array): the next child's pointer segment. */
  segment: string;
  index: number;
}

const escapeSegment = (s: string): string => s.replace(/~/g, '~0').replace(/\//g, '~1');

/** The index of the quote that closes the string opening at `start`, in text known to be JSON. */
function stringEnd(text: string, start: number): number {
  let i = start + 1;
  for (;;) {
    const c = text.charCodeAt(i);
    if (c === BACKSLASH) i += 2;
    else if (c === QUOTE) return i;
    else i += 1;
  }
}

/** Throw `RepeatedMemberNameError` at the first repeated name, in text `JSON.parse` has accepted. */
function refuseRepeatedNames(text: string): void {
  const stack: Frame[] = [];
  const segments: string[] = [];
  const n = text.length;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (c === QUOTE) {
      const end = stringEnd(text, i);
      const top = stack[stack.length - 1];
      if (top?.names && top.expectName) {
        const raw = text.slice(i + 1, end);
        const name = raw.includes('\\') ? (JSON.parse(text.slice(i, end + 1)) as string) : raw;
        if (top.names.has(name)) throw new RepeatedMemberNameError(name, segments.map((s) => `/${escapeSegment(s)}`).join(''));
        top.names.add(name);
        top.segment = name;
        top.expectName = false;
      }
      i = end;
    } else if (c === OPEN_OBJECT || c === OPEN_ARRAY) {
      const parent = stack[stack.length - 1];
      if (parent) segments.push(parent.names ? parent.segment : String(parent.index));
      stack.push({ names: c === OPEN_OBJECT ? new Set() : null, expectName: c === OPEN_OBJECT, segment: '', index: 0 });
    } else if (c === CLOSE_OBJECT || c === CLOSE_ARRAY) {
      stack.pop();
      if (stack.length > 0) segments.pop();
    } else if (c === COMMA) {
      const top = stack[stack.length - 1]!;
      if (top.names) top.expectName = true;
      else top.index += 1;
    }
  }
}

/**
 * Parse a record's JSON text strictly: refuse a text that repeats a member name
 * within an object (I-JSON, RFC 7493; specification §8.2), before any hash is
 * computed over what it holds.
 *
 * - Bytes are decoded as UTF-8 with `fatal`, so malformed UTF-8 throws the
 *   decoder's `TypeError` rather than being replaced. A leading byte order mark is
 *   removed, as the decoder does by default.
 * - A text that is not JSON throws what `JSON.parse` throws, unchanged.
 * - A text that repeats a member name within one object throws
 *   `RepeatedMemberNameError`, naming the member and the JSON Pointer of the
 *   object. Names compare after unescaping, so `"a"` repeats `"a"`; the same
 *   name in two different objects is not a repeat.
 * - Otherwise it returns `JSON.parse`'s value.
 */
export function parseStrictJson(text: string | Uint8Array): unknown {
  const source = typeof text === 'string' ? text : new TextDecoder('utf-8', { fatal: true }).decode(text);
  const value = JSON.parse(source) as unknown;
  refuseRepeatedNames(source);
  return value;
}
