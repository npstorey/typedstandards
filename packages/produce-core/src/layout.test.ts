// Layout-builder tests (spec §8.14, hub ADR-0034): the golden bytes of the
// §8.14.1 example payload, the node's key order, a refusal for every rule the
// §8.14.1 table states, and part names left unchecked (§8.14.4).
//
// Fixtures (provenance: `__fixtures__/README.md`): `layout-s8141-payload.json`
// is the spec's example payload, copied from the hub; `layout-golden-inputs.json`
// holds the fixed determinism inputs; `layout-golden.node.json` is the node,
// serialized as `JSON.stringify(node, null, 2) + '\n'`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  computeContentHashSha256,
  computeEnvelopeHash,
  CONTENT_LAYOUT as VERIFY_CORE_CONTENT_LAYOUT,
  LEGACY_JSON_CANONICALIZATION,
  resolvePackageType,
} from '@typedstandards/verify-core';
import { buildLayoutNode, CONTENT_LAYOUT, type LayoutInput } from './layout.ts';

const fixtureText = (name: string): string =>
  readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf8');
const serialize = (node: unknown): string => JSON.stringify(node, null, 2) + '\n';

const PAYLOAD_TEXT = fixtureText('layout-s8141-payload.json');
const PAYLOAD = JSON.parse(PAYLOAD_TEXT) as Record<string, unknown>;
const INPUTS = JSON.parse(fixtureText('layout-golden-inputs.json')) as {
  layout: Pick<LayoutInput, 'packageId' | 'createdAt' | 'signingKeyId' | 'signer'>;
};
const GOLDEN_TEXT = fixtureText('layout-golden.node.json');

/** The golden input: the fixed determinism inputs plus the §8.14.1 payload. */
function goldenInput(): LayoutInput {
  return { ...INPUTS.layout, ...(structuredClone(PAYLOAD) as unknown as LayoutInput) };
}

/** The golden input with one change applied to a fresh copy. */
function inputWith(change: (input: Record<string, unknown>) => void): LayoutInput {
  const input = goldenInput() as unknown as Record<string, unknown>;
  change(input);
  return input as unknown as LayoutInput;
}

function refusedWith(input: LayoutInput, message: string): void {
  assert.throws(
    () => buildLayoutNode(input),
    (err: unknown) => err instanceof Error && err.message === message,
    message,
  );
}

// --- The payload fixture is the hub's §8.14.1 block -------------------------

test('payload fixture: the bytes of spec §8.14.1 (hub 35d94f3, lines 1493-1505)', () => {
  assert.equal(
    crypto.createHash('sha256').update(PAYLOAD_TEXT).digest('hex'),
    'fd5f37945cd5d1af0736aa72fcc2799e972aa619e1891530f60fd7b236e22745',
  );
  // The block as the specification prints it, parsed.
  assert.deepEqual(PAYLOAD, {
    name: 'answer-first',
    version: 1,
    appliesTo: ['default', 'datHere'],
    order: ['status', 'answer', 'citation', 'steps', 'sources', 'disclosure', 'actions'],
    disclosure: {
      label: 'Learn more about how this analysis was produced',
      order: ['A', 'B', 'C', 'D', 'E', 'G', 'signers', 'attestations', 'verification'],
      openByDefault: false,
    },
    steps: { placement: 'beside', openByDefault: true },
    rendererVersion: 'answer-view/1',
  });
});

// --- Golden bytes ------------------------------------------------------------

test('golden: the §8.14.1 payload under the fixed inputs builds the committed bytes', () => {
  const { node, nodeId } = buildLayoutNode(goldenInput());
  assert.equal(serialize(node), GOLDEN_TEXT);
  assert.equal(nodeId, computeEnvelopeHash(JSON.parse(GOLDEN_TEXT) as Record<string, unknown>));
  assert.equal(nodeId, '66e55ff06b7cd66b85ab38c6297a71e0e0d04301432c0141155529a21b368ef4');
});

test('golden: the payload inside the committed node deep-equals the §8.14.1 block', () => {
  const golden = JSON.parse(GOLDEN_TEXT) as Record<string, unknown>;
  const payload = Object.fromEntries(Object.keys(PAYLOAD).map((k) => [k, golden[k]]));
  assert.deepEqual(payload, PAYLOAD);
});

test('golden: contentHash is legacy-json/v1 over the node minus contentHash', () => {
  const golden = JSON.parse(GOLDEN_TEXT) as Record<string, unknown>;
  const { contentHash, ...rest } = golden;
  assert.deepEqual(contentHash, {
    sha256: computeContentHashSha256(rest, LEGACY_JSON_CANONICALIZATION),
  });
});

test('deterministic: identical inputs, identical bytes and nodeId', () => {
  const a = buildLayoutNode(goldenInput());
  const b = buildLayoutNode(goldenInput());
  assert.equal(serialize(a.node), serialize(b.node));
  assert.equal(a.nodeId, b.nodeId);
});

// --- Shape -------------------------------------------------------------------

test('key order: metadata, type, signer, contentCanonicalization, the seven payload fields, contentHash', () => {
  const { node } = buildLayoutNode(goldenInput());
  assert.deepEqual(Object.keys(node), [
    'metadata',
    'type',
    'signer',
    'contentCanonicalization',
    'name',
    'version',
    'appliesTo',
    'order',
    'disclosure',
    'steps',
    'rendererVersion',
    'contentHash',
  ]);
  assert.deepEqual(Object.keys(node.metadata), [
    'schemaVersion',
    'packageId',
    'createdAt',
    'signingKeyId',
  ]);
  assert.deepEqual(Object.keys(node.disclosure), ['label', 'order', 'openByDefault']);
  assert.deepEqual(Object.keys(node.steps), ['placement', 'openByDefault']);
});

test('shape: type content/layout/v1, schemaVersion 0.1.0, legacy-json/v1, no targetNodeId, no output', () => {
  const { node } = buildLayoutNode(goldenInput());
  assert.equal(node.type, 'content/layout/v1');
  assert.equal(node.metadata.schemaVersion, '0.1.0');
  assert.equal(node.contentCanonicalization, LEGACY_JSON_CANONICALIZATION);
  assert.ok(!('targetNodeId' in node));
  assert.ok(!('output' in node));
  assert.deepEqual(resolvePackageType(node as unknown as Record<string, unknown>), {
    status: 'ok',
    type: 'content/layout/v1',
  });
});

test('CONTENT_LAYOUT is verify-core\'s constant, re-exported', () => {
  assert.equal(CONTENT_LAYOUT, 'content/layout/v1');
  assert.equal(CONTENT_LAYOUT, VERIFY_CORE_CONTENT_LAYOUT);
});

test('sub-members are emitted in the table order whatever order the input gives them', () => {
  const reordered = inputWith((i) => {
    i['disclosure'] = { openByDefault: false, order: ['x'], label: 'Details' };
    i['steps'] = { openByDefault: true, placement: 'below' };
  });
  const { node } = buildLayoutNode(reordered);
  assert.deepEqual(Object.keys(node.disclosure), ['label', 'order', 'openByDefault']);
  assert.deepEqual(Object.keys(node.steps), ['placement', 'openByDefault']);
});

test('the node holds copies: changing the input after the build leaves the node unchanged', () => {
  const input = goldenInput();
  const { node } = buildLayoutNode(input);
  const before = serialize(node);
  input.order.push('extra');
  input.appliesTo.push('extra');
  input.disclosure.order.push('extra');
  input.disclosure.label = 'changed';
  input.steps.placement = 'changed';
  assert.equal(serialize(node), before);
});

// --- Part names are the renderer's vocabulary (D2 = A, §8.14.4) ----------------

test('part names are not checked: any string passes in order, disclosure.order, steps.placement, rendererVersion', () => {
  const unknownNames = inputWith((i) => {
    i['order'] = ['not-a-known-part', '', 'ünïcode part'];
    i['disclosure'] = { label: '', order: ['zzz', 'zzz', ''], openByDefault: true };
    i['steps'] = { placement: 'nowhere-a-renderer-knows', openByDefault: false };
    i['rendererVersion'] = 'some-other-renderer/99';
    i['appliesTo'] = ['a-profile-no-one-defined'];
    i['name'] = '';
  });
  const { node } = buildLayoutNode(unknownNames);
  assert.deepEqual(node.order, ['not-a-known-part', '', 'ünïcode part']);
  assert.deepEqual(node.disclosure.order, ['zzz', 'zzz', '']);
  assert.equal(node.steps.placement, 'nowhere-a-renderer-knows');
  assert.equal(node.rendererVersion, 'some-other-renderer/99');
});

test('version: any integer of at least 1 passes', () => {
  for (const version of [1, 2, 1000]) {
    assert.equal(buildLayoutNode(inputWith((i) => (i['version'] = version))).node.version, version);
  }
});

// --- Refusals: every rule of the §8.14.1 table -----------------------------------

const PAYLOAD_FIELDS = [
  'name',
  'version',
  'appliesTo',
  'order',
  'disclosure',
  'steps',
  'rendererVersion',
];

test('refuses a missing top-level payload field', () => {
  for (const field of PAYLOAD_FIELDS) {
    refusedWith(
      inputWith((i) => delete i[field]),
      `buildLayoutNode: ${field} is required`,
    );
  }
});

test('refuses a top-level payload field given as undefined', () => {
  for (const field of PAYLOAD_FIELDS) {
    refusedWith(
      inputWith((i) => (i[field] = undefined)),
      `buildLayoutNode: ${field} is required`,
    );
  }
});

test('refuses name that is not a string', () => {
  for (const bad of [1, null, true, ['answer-first'], {}]) {
    refusedWith(inputWith((i) => (i['name'] = bad)), 'buildLayoutNode: name must be a string');
  }
});

test('refuses version that is not an integer of at least 1', () => {
  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '1', null, true]) {
    refusedWith(
      inputWith((i) => (i['version'] = bad)),
      'buildLayoutNode: version must be an integer of at least 1',
    );
  }
});

test('refuses appliesTo that is not an array of strings', () => {
  for (const bad of ['default', null, { 0: 'default' }]) {
    refusedWith(
      inputWith((i) => (i['appliesTo'] = bad)),
      'buildLayoutNode: appliesTo must be an array of strings',
    );
  }
});

test('refuses an empty appliesTo', () => {
  refusedWith(inputWith((i) => (i['appliesTo'] = [])), 'buildLayoutNode: appliesTo must not be empty');
});

test('refuses an appliesTo entry that is not a string', () => {
  refusedWith(
    inputWith((i) => (i['appliesTo'] = ['default', 7])),
    'buildLayoutNode: appliesTo[1] must be a string',
  );
});

test('refuses order that is not an array of strings', () => {
  for (const bad of ['status', null, {}]) {
    refusedWith(
      inputWith((i) => (i['order'] = bad)),
      'buildLayoutNode: order must be an array of strings',
    );
  }
});

test('refuses an empty order', () => {
  refusedWith(inputWith((i) => (i['order'] = [])), 'buildLayoutNode: order must not be empty');
});

test('refuses an order entry that is not a string, a sparse array\'s hole included', () => {
  refusedWith(
    inputWith((i) => (i['order'] = ['status', null])),
    'buildLayoutNode: order[1] must be a string',
  );
  const sparse: string[] = ['status'];
  sparse[2] = 'answer';
  refusedWith(inputWith((i) => (i['order'] = sparse)), 'buildLayoutNode: order[1] must be a string');
});

test('refuses a repeated order entry', () => {
  refusedWith(
    inputWith((i) => (i['order'] = ['status', 'answer', 'citation', 'answer'])),
    'buildLayoutNode: order must not repeat an entry: "answer" at 1 and 3',
  );
});

test('refuses disclosure that is not an object', () => {
  for (const bad of ['details', null, [], 1]) {
    refusedWith(
      inputWith((i) => (i['disclosure'] = bad)),
      'buildLayoutNode: disclosure must be an object',
    );
  }
});

test('refuses a disclosure with a sub-member missing', () => {
  for (const member of ['label', 'order', 'openByDefault']) {
    refusedWith(
      inputWith((i) => delete (i['disclosure'] as Record<string, unknown>)[member]),
      `buildLayoutNode: disclosure.${member} is required`,
    );
  }
});

test('refuses disclosure.label that is not a string', () => {
  refusedWith(
    inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['label'] = 3)),
    'buildLayoutNode: disclosure.label must be a string',
  );
});

test('refuses disclosure.order that is not an array of strings', () => {
  refusedWith(
    inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['order'] = 'A,B')),
    'buildLayoutNode: disclosure.order must be an array of strings',
  );
  refusedWith(
    inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['order'] = ['A', false])),
    'buildLayoutNode: disclosure.order[1] must be a string',
  );
});

test('disclosure.order may be empty (the table gives no non-empty rule for it)', () => {
  const { node } = buildLayoutNode(
    inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['order'] = [])),
  );
  assert.deepEqual(node.disclosure.order, []);
});

test('refuses disclosure.openByDefault that is not a boolean', () => {
  for (const bad of ['false', 0, null]) {
    refusedWith(
      inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['openByDefault'] = bad)),
      'buildLayoutNode: disclosure.openByDefault must be a boolean',
    );
  }
});

test('refuses a disclosure member outside the table', () => {
  refusedWith(
    inputWith((i) => ((i['disclosure'] as Record<string, unknown>)['icon'] = 'chevron')),
    'buildLayoutNode: disclosure has a member outside §8.14.1: "icon"',
  );
});

test('refuses steps that is not an object', () => {
  for (const bad of ['beside', null, [], true]) {
    refusedWith(inputWith((i) => (i['steps'] = bad)), 'buildLayoutNode: steps must be an object');
  }
});

test('refuses a steps with a sub-member missing', () => {
  for (const member of ['placement', 'openByDefault']) {
    refusedWith(
      inputWith((i) => delete (i['steps'] as Record<string, unknown>)[member]),
      `buildLayoutNode: steps.${member} is required`,
    );
  }
});

test('refuses steps.placement that is not a string', () => {
  refusedWith(
    inputWith((i) => ((i['steps'] as Record<string, unknown>)['placement'] = 1)),
    'buildLayoutNode: steps.placement must be a string',
  );
});

test('refuses steps.openByDefault that is not a boolean', () => {
  refusedWith(
    inputWith((i) => ((i['steps'] as Record<string, unknown>)['openByDefault'] = 'true')),
    'buildLayoutNode: steps.openByDefault must be a boolean',
  );
});

test('refuses a steps member outside the table', () => {
  refusedWith(
    inputWith((i) => ((i['steps'] as Record<string, unknown>)['collapsible'] = true)),
    'buildLayoutNode: steps has a member outside §8.14.1: "collapsible"',
  );
});

test('refuses rendererVersion that is not a string', () => {
  refusedWith(
    inputWith((i) => (i['rendererVersion'] = 1)),
    'buildLayoutNode: rendererVersion must be a string',
  );
});

test('refuses a top-level input member outside the table, targetNodeId and output among them', () => {
  for (const extra of ['targetNodeId', 'output', 'theme']) {
    refusedWith(
      inputWith((i) => (i[extra] = 'x')),
      `buildLayoutNode: input has a member outside §8.14.1: "${extra}"`,
    );
  }
});
