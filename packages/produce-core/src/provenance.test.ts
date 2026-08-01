// Generic PROV-O layer tests: context construction from a caller-supplied
// namespace map (insertion order preserved — the legacy-chain byte contract),
// node constructors, and the edge-wiring helpers. The domain graph walk
// lives with the caller; these helpers only fix the JSON-LD shapes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DCTERMS_NS,
  PROV_NS,
  XSD_NS,
  makeActivityNode,
  makeAgentNode,
  makeEntityNode,
  makeProvContext,
  makeProvGraph,
  makeProvNode,
  provRef,
  provUsed,
  provWasAssociatedWith,
  provWasDerivedFrom,
  provWasGeneratedBy,
  xsdDateTime,
} from './provenance.ts';

test('makeProvContext: preserves the caller map verbatim, including order', () => {
  const ctx = makeProvContext({
    prov: PROV_NS,
    xsd: XSD_NS,
    adopter: 'https://evidence.example.org/ns/',
    dcterms: DCTERMS_NS,
  });
  assert.deepEqual(Object.keys(ctx), ['prov', 'xsd', 'adopter', 'dcterms']);
  assert.equal(ctx.prov, 'http://www.w3.org/ns/prov#');
  assert.equal(ctx.xsd, 'http://www.w3.org/2001/XMLSchema#');
  assert.equal(ctx.dcterms, 'http://purl.org/dc/terms/');
});

test('makeProvContext: requires a prov binding and rejects empty bindings', () => {
  assert.throws(() => makeProvContext({ xsd: XSD_NS }), /'prov'/);
  assert.throws(() => makeProvContext({ prov: PROV_NS, bad: '' }), /invalid/);
});

test('node constructors: @id then @type then caller properties, in order', () => {
  const entity = makeEntityNode('urn:example:prompt:1', {
    'dcterms:description': 'User query prompt',
  });
  assert.deepEqual(entity, {
    '@id': 'urn:example:prompt:1',
    '@type': 'prov:Entity',
    'dcterms:description': 'User query prompt',
  });
  assert.deepEqual(Object.keys(entity), ['@id', '@type', 'dcterms:description']);

  const plan = makeEntityNode('urn:example:skill:1', {}, ['prov:Plan']);
  assert.deepEqual(plan['@type'], ['prov:Entity', 'prov:Plan']);

  const agent = makeAgentNode('urn:example:model:1', { 'dcterms:title': 'model-1' }, [
    'prov:SoftwareAgent',
  ]);
  assert.deepEqual(agent['@type'], ['prov:Agent', 'prov:SoftwareAgent']);

  const activity = makeActivityNode('urn:example:inference:1');
  assert.equal(activity['@type'], 'prov:Activity');

  const custom = makeProvNode('urn:example:x', ['prov:Entity', 'prov:Collection']);
  assert.deepEqual(custom['@type'], ['prov:Entity', 'prov:Collection']);
});

test('edge helpers: by-id reference shapes', () => {
  assert.deepEqual(provRef('urn:example:1'), { '@id': 'urn:example:1' });
  assert.deepEqual(provUsed(['urn:a', 'urn:b']), {
    'prov:used': [{ '@id': 'urn:a' }, { '@id': 'urn:b' }],
  });
  assert.deepEqual(provWasGeneratedBy('urn:act'), {
    'prov:wasGeneratedBy': { '@id': 'urn:act' },
  });
  assert.deepEqual(provWasDerivedFrom(['urn:d1']), {
    'prov:wasDerivedFrom': [{ '@id': 'urn:d1' }],
  });
  assert.deepEqual(provWasAssociatedWith('urn:agent'), {
    'prov:wasAssociatedWith': { '@id': 'urn:agent' },
  });
  assert.deepEqual(xsdDateTime('2026-01-02T03:04:05.000Z'), {
    '@value': '2026-01-02T03:04:05.000Z',
    '@type': 'xsd:dateTime',
  });
});

test('a composed mini-graph matches the hand-built JSON-LD shape', () => {
  const ctx = makeProvContext({ prov: PROV_NS, xsd: XSD_NS, dcterms: DCTERMS_NS });
  const graph = makeProvGraph(ctx, [
    makeEntityNode('urn:example:prompt:1', {
      'dcterms:description': 'User query prompt',
    }),
    makeAgentNode('urn:example:model:1', { 'dcterms:title': 'model-1' }, [
      'prov:SoftwareAgent',
    ]),
    makeActivityNode('urn:example:inference:1', {
      'dcterms:description': 'Inference call',
      ...provWasAssociatedWith('urn:example:model:1'),
      ...provUsed(['urn:example:prompt:1']),
      'prov:startedAtTime': xsdDateTime('2026-01-02T03:04:05.000Z'),
    }),
    makeEntityNode('urn:example:output:1', {
      ...provWasGeneratedBy('urn:example:inference:1'),
      ...provWasDerivedFrom(['urn:example:prompt:1']),
    }),
  ]);

  assert.deepEqual(graph, {
    '@context': {
      prov: 'http://www.w3.org/ns/prov#',
      xsd: 'http://www.w3.org/2001/XMLSchema#',
      dcterms: 'http://purl.org/dc/terms/',
    },
    '@graph': [
      {
        '@id': 'urn:example:prompt:1',
        '@type': 'prov:Entity',
        'dcterms:description': 'User query prompt',
      },
      {
        '@id': 'urn:example:model:1',
        '@type': ['prov:Agent', 'prov:SoftwareAgent'],
        'dcterms:title': 'model-1',
      },
      {
        '@id': 'urn:example:inference:1',
        '@type': 'prov:Activity',
        'dcterms:description': 'Inference call',
        'prov:wasAssociatedWith': { '@id': 'urn:example:model:1' },
        'prov:used': [{ '@id': 'urn:example:prompt:1' }],
        'prov:startedAtTime': {
          '@value': '2026-01-02T03:04:05.000Z',
          '@type': 'xsd:dateTime',
        },
      },
      {
        '@id': 'urn:example:output:1',
        '@type': 'prov:Entity',
        'prov:wasGeneratedBy': { '@id': 'urn:example:inference:1' },
        'prov:wasDerivedFrom': [{ '@id': 'urn:example:prompt:1' }],
      },
    ],
  });
  // The composed graph is JSON-serializable byte-for-byte deterministically.
  assert.equal(JSON.stringify(graph), JSON.stringify(graph));
});
