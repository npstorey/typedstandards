// Regression guards for the package manifest + public API surface. Cloned
// from verify-core's package-exports test and extended with the produce-core
// contract checks: the runtime dependency budget (verify-core ONLY — the
// single-sourcing of the canonicalization/hash chain) and the exported names
// the producer API promises.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as {
  exports: Record<string, Record<string, string>>;
  dependencies?: Record<string, string>;
  sideEffects?: boolean;
  engines?: Record<string, string>;
};

test('the `.` export resolves under generic conditions (default present, last)', () => {
  const dot = pkg.exports['.'];
  assert.ok(dot, 'package must export "."');
  assert.equal(dot.default, './dist/index.js', 'a `default` condition must resolve to dist');
  // Node matches conditions in order and requires `default` to be last.
  assert.equal(Object.keys(dot).at(-1), 'default', '`default` must be the last condition');
});

test('runtime dependency budget: the shared verification core + the curve suite it already uses', () => {
  assert.deepEqual(
    Object.keys(pkg.dependencies ?? {}),
    ['@noble/curves', '@typedstandards/verify-core'],
    'produce-core runtime deps are exactly verify-core plus @noble/curves — the one ' +
      'package shipped src imports directly (signing.ts); declared so strict-layout ' +
      'consumers (pnpm, Yarn PnP) can resolve it',
  );
  assert.equal(pkg.sideEffects, false, 'sideEffects must stay false');
  assert.equal(pkg.engines?.node, '>=18', 'engines.node must stay >=18');
});

test('index exports the produce-core API surface', async () => {
  const api = (await import('./index.ts')) as Record<string, unknown>;

  const fns = [
    // envelope + attestation assembly
    'buildEnvelope',
    'buildAttestationNode',
    // signing mechanism (caller-supplied key + kid)
    'signEnvelopeHash',
    'derivePublicKeySpki',
    'derPublicKeyToPemBase64',
    // pure external-proof codecs
    'buildTimestampRequest',
    'buildRekorProposal',
    'parseRekorResponse',
    // proof carrier
    'buildCommitmentView',
    // generic PROV-O helpers
    'makeProvContext',
    'makeProvGraph',
    'makeProvNode',
    'makeEntityNode',
    'makeActivityNode',
    'makeAgentNode',
    'provRef',
    'provUsed',
    'provWasGeneratedBy',
    'provWasDerivedFrom',
    'provWasAssociatedWith',
    'xsdDateTime',
    // shared chain re-exports
    'computeEnvelopeHash',
    'computeContentHashSha256',
    // primitives a producer-side harness consumes (0.2.0, civic-ai-tools#116 P1)
    'sha256Hex',
    'isBlobRef',
  ];
  for (const name of fns) {
    assert.equal(typeof api[name], 'function', `expected exported function ${name}`);
  }

  const constants = [
    'DEFAULT_CONTENT_TYPE',
    'SIGNING_ALGORITHM',
    'ATTESTATION_WITHDRAWS',
    'ATTESTATION_REINSTATES',
    'ATTESTATION_PUBLISHES',
    'ATTESTATION_LOCATED_AT',
    'ATTESTATION_EVALUATES',
    'LEGACY_JSON_CANONICALIZATION',
    'DATHERE_AG_JUPYTER_CANONICALIZATION',
    'PROV_NS',
    'XSD_NS',
    'DCTERMS_NS',
  ];
  for (const name of constants) {
    assert.equal(typeof api[name], 'string', `expected exported string constant ${name}`);
  }

  // The Q32 captureMethod vocabulary table (an object, not a string).
  assert.equal(
    typeof api['PROFILE_CAPTURE_VOCAB'],
    'object',
    'expected exported vocabulary table PROFILE_CAPTURE_VOCAB',
  );
});

// The signing-status contract: signing is explicit and unsigned results are
// first-class — the API surface must not carry sealed/publish-status helpers
// or default identity/key constants that could label an unsigned result.
test('no export labels signing status or embeds a default identity', async () => {
  const api = (await import('./index.ts')) as Record<string, unknown>;
  for (const name of Object.keys(api)) {
    assert.ok(
      !/sealed/i.test(name),
      `export "${name}" must not suggest a sealed/unsealed status`,
    );
    assert.ok(
      !/^(DEFAULT_KEY_ID|PLATFORM_)/.test(name),
      `export "${name}" must not embed a default key or platform identity (caller-supplied per the no-custody rule)`,
    );
    assert.ok(
      !/getActive/i.test(name),
      `export "${name}" must not probe for an "active" key/signer — configuration is caller-supplied`,
    );
  }
});
