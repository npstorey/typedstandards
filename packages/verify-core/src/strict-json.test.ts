// parseStrictJson (typedstandards#145; specification §8.2, §9.2 check #1): a JSON
// text that repeats a member name within an object is refused, and every other text
// parses exactly as `JSON.parse` parses it.
//
// Goldens: produce-core's `reference-golden.json` and `derived-golden.json`, and this
// package's `adr-0028-recomputation.package.json`, read as committed; each parses to
// the value `JSON.parse` gives (deepEqual), so the strict parse changes nothing for
// a text with no repeated name.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseStrictJson, RepeatedMemberNameError } from './index.ts';

function refused(text: string | Uint8Array, memberName: string, pointer: string): void {
  assert.throws(
    () => parseStrictJson(text),
    (err: unknown) => {
      assert.ok(err instanceof RepeatedMemberNameError, String(err));
      assert.equal(err.name, 'RepeatedMemberNameError');
      assert.equal(err.memberName, memberName);
      assert.equal(err.pointer, pointer);
      assert.match(err.message, /not I-JSON \(RFC 7493\)/);
      return true;
    },
  );
}

test('a repeat at the top level is refused, with the name and the pointer ""', () => {
  refused('{"a":1,"b":2,"a":3}', 'a', '');
  assert.equal(JSON.parse('{"a":1,"b":2,"a":3}').a, 3, 'JSON.parse keeps the last');
});

test('a repeat in a nested object is refused, with that object\'s pointer', () => {
  refused('{"outer":{"inner":{"x":true,"x":false}}}', 'x', '/outer/inner');
});

test('a repeat in an object inside an array is refused, with the element\'s index in the pointer', () => {
  refused('{"list":[{"k":1},{"k":2,"j":0,"k":3}]}', 'k', '/list/1');
  refused('[[],[0,{"a":0,"a":0}]]', 'a', '/1/1');
});

test('the pointer escapes ~ and / in a segment (RFC 6901)', () => {
  refused('{"a/b":{"c~d":{"e":0,"e":1}}}', 'e', '/a~1b/c~0d');
});

test('names compare after unescaping: an escaped name equal to a plain one is a repeat', () => {
  refused('{"ab":1,"\\u0061b":2}', 'ab', '');
  refused('{"a\\"b":1,"a\\u0022b":2}', 'a"b', '');
  refused('{"\\/":1,"/":2}', '/', '');
});

test('the same name in two sibling objects is not a repeat', () => {
  const text = '{"x":{"id":1,"v":"a"},"y":{"id":2,"v":"b"},"z":[{"id":3},{"id":4}]}';
  assert.deepEqual(parseStrictJson(text), JSON.parse(text));
});

test('a name that also appears as a string value, or nested under itself, is not a repeat', () => {
  const text = '{"a":"a","b":{"a":{"a":["a",{"a":"a"}]}},"c":"\\"a\\":"}';
  assert.deepEqual(parseStrictJson(text), JSON.parse(text));
});

test('deep nesting is accepted without a stack overflow', () => {
  const depth = 200_000;
  const arrays = `${'['.repeat(depth)}${']'.repeat(depth)}`;
  assert.ok(Array.isArray(parseStrictJson(arrays)));
  const objects = `${'{"a":'.repeat(depth)}0${'}'.repeat(depth)}`;
  let v = parseStrictJson(objects) as { a: unknown } | number;
  let levels = 0;
  while (typeof v === 'object') {
    v = v.a as typeof v;
    levels += 1;
  }
  assert.equal(levels, depth);
  refused(`${'{"a":'.repeat(depth)}{"b":0,"b":1}${'}'.repeat(depth)}`, 'b', '/a'.repeat(depth));
});

test('a text that is not JSON throws what JSON.parse throws, unchanged', () => {
  for (const text of ['', '{', '{"a":1,}', "{'a':1}", '{"a":1} x', 'NaN']) {
    let expected: unknown;
    try {
      JSON.parse(text);
    } catch (err) {
      expected = err;
    }
    assert.ok(expected instanceof SyntaxError, text);
    assert.throws(
      () => parseStrictJson(text),
      (err: unknown) => err instanceof SyntaxError && err.message === (expected as SyntaxError).message,
      text,
    );
  }
});

test('bytes that are not UTF-8 are refused; UTF-8 bytes parse as their text does', () => {
  assert.throws(() => parseStrictJson(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])), TypeError);
  const text = '{"name":"café","n":[1,2]}';
  assert.deepEqual(parseStrictJson(new TextEncoder().encode(text)), JSON.parse(text));
  refused(new TextEncoder().encode('{"é":1,"\\u00e9":2}'), 'é', '');
});

test('primitives, empty containers and whitespace parse as JSON.parse parses them', () => {
  for (const text of ['0', '-1.5e3', '"s"', 'true', 'null', '{}', '[]', ' \n{ "a" : [ ] , "b" : { } }\t']) {
    assert.deepEqual(parseStrictJson(text), JSON.parse(text), text);
  }
});

const GOLDENS: Array<[string, URL]> = [
  ['reference-golden.json', new URL('../../produce-core/src/__fixtures__/reference-golden.json', import.meta.url)],
  ['derived-golden.json', new URL('../../produce-core/src/__fixtures__/derived-golden.json', import.meta.url)],
  ['adr-0028-recomputation.package.json', new URL('./__fixtures__/adr-0028-recomputation.package.json', import.meta.url)],
];

for (const [name, url] of GOLDENS) {
  test(`golden ${name}: the strict parse equals JSON.parse, from text and from bytes`, () => {
    const bytes = new Uint8Array(readFileSync(url));
    const expected = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    assert.deepEqual(parseStrictJson(bytes), expected);
    assert.deepEqual(parseStrictJson(new TextDecoder().decode(bytes)), expected);
  });
}
