// Minting program for `q15-self-certified.json` — the self-contained commitment
// bundle an independent implementation can test against (Wave N14 P7). See
// README.md in this directory for what it is, how to re-mint it, and what each
// check reports on it.
//
// Everything is built with the shipped cores: produce-core's `buildEnvelope`,
// `signEnvelopeHash`, `buildCommitmentView` and
// `deriveKeyDerivedIdentifierFromKey`. The inputs are fixed, so the output is
// byte-identical on every run: Ed25519ph signatures are deterministic, and no
// clock or random value enters.
//
// The signing seed is the SHA-256 of the ASCII string SEED_LABEL, derived here at
// run time and never written anywhere. It is public by construction, so a
// signature made with it proves nothing about anyone (hub ADR-0030 §9: a key
// generated for the fixture).
//
// Run from the repository root, after `npm run build:verify-core` and
// `npm run build --workspace @typedstandards/produce-core`:
//
//   node --experimental-strip-types \
//     apps/web/src/lib/__fixtures__/q15-self-certified.mint.ts \
//     > apps/web/src/lib/__fixtures__/q15-self-certified.json
//
// It reads the committed content file beside it and prints the bundle. It prints
// no private material.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  buildCommitmentView,
  buildEnvelope,
  deriveKeyDerivedIdentifierFromKey,
  DEFAULT_CONTENT_TYPE,
  sha256Hex,
  signEnvelopeHash,
} from '@typedstandards/produce-core';
import { RAW_BYTES_CANONICALIZATION } from '@typedstandards/verify-core';

/** The ASCII string whose SHA-256 is the fixture's 32-byte Ed25519 seed. */
export const SEED_LABEL = 'typedstandards/fixtures/q15-self-certified/v1';

/** The content file the package fingerprints under raw-bytes/v1. */
export const CONTENT_FILE = 'q15-self-certified.output.csv';

/** The bundle this program prints. */
export const BUNDLE_FILE = 'q15-self-certified.json';

/** Fixed inputs. Ids sit in the hex-letter range (`.claude/rules/fixtures.md`). */
const PACKAGE_ID = 'abcdefab-cdef-4abc-8def-abcdefabcdef';
const CREATED_AT = '2026-09-21T00:00:00.000Z';
const PRODUCER_PROFILE = 'scripted-recomputation/interop-fixture';
// `script-run`: this program reads a file that already exists on disk (the
// committed CSV) and packages its bytes. It did not compute them in the same
// process, which is what `tool-emitted` would claim (hub ADR-0029 §2).
const CAPTURE_METHOD = 'script-run';
const DISPLAY_NAME = 'Typed Standards interop fixture (public test key)';

/** The 32-byte seed: SHA-256 of the UTF-8 (here ASCII) bytes of SEED_LABEL. */
function fixtureSeed(): Uint8Array {
  return new Uint8Array(createHash('sha256').update(SEED_LABEL, 'utf8').digest());
}

/**
 * Mint the bundle from the content file's text. Returns the serialized bundle:
 * `JSON.stringify(bundle, null, 2)` plus one trailing newline.
 */
export function mintSelfCertifiedBundle(content: string): string {
  const seed = fixtureSeed();
  const identifier = deriveKeyDerivedIdentifierFromKey(seed);
  const signer = { bindingTier: 'pseudonymous', identifier, displayName: DISPLAY_NAME };

  const { pkg, envelopeHash } = buildEnvelope({
    packageId: PACKAGE_ID,
    createdAt: CREATED_AT,
    // hub ADR-0030 §5: the key is named by the identifier, in the envelope's
    // `kid` and in `metadata.signingKeyId` alike.
    signingKeyId: identifier,
    prompt: `Package the committed file ${CONTENT_FILE} as the output of a scripted-recomputation record under raw-bytes/v1, signed by a self-certifying fixture key.`,
    promptVisibility: 'full_text',
    // hub ADR-0029 §3 item 7: one entry for the step that produced the package,
    // naming the program and pinning the input it read by SHA-256.
    queries: [
      {
        tool: 'q15-self-certified.mint.ts',
        operationType: 'package-file',
        arguments: { inputFile: CONTENT_FILE, inputSha256: sha256Hex(content) },
      },
    ],
    dataSources: [],
    cost: { model: 'none' },
    skillMetadata: {},
    output: content,
    trace: { resourceSpans: [] },
    summary:
      'A four-row CSV packaged under raw-bytes/v1 and signed by a self-certifying key generated for this fixture. The key is public, so the signature proves nothing about anyone.',
    captureMethod: CAPTURE_METHOD,
    producerProfile: PRODUCER_PROFILE,
    type: DEFAULT_CONTENT_TYPE,
    signer,
    contentCanonicalization: RAW_BYTES_CANONICALIZATION,
  });

  const signed = signEnvelopeHash(envelopeHash, seed, identifier);

  // No trustRegistryUrl: legal for a key-derived signer at `pseudonymous`, and
  // buildCommitmentView checks the identifier against signature.publicKey.
  const view = buildCommitmentView({
    packageHash: envelopeHash,
    visibility: 'public',
    captureMethod: pkg.metadata.captureMethod ?? null,
    producerProfile: pkg.producerProfile,
    type: pkg.type,
    signer: pkg.signer,
    contentHash: pkg.contentHash,
    contentCanonicalization: pkg.contentCanonicalization,
    signature: { ...signed },
    subjectTitle: 'Interop fixture: self-certified raw-bytes record',
    subjectSummary: pkg.summary ?? null,
  });

  // The §8.8 `?inline=1` shape: the view plus the package inline. No
  // trustRegistry, no hostDirectory, no RFC 3161 token, no Rekor entry.
  const bundle = { ...view, package: pkg };
  return `${JSON.stringify(bundle, null, 2)}\n`;
}

/** The committed content file's text. */
export function readContentFile(): string {
  return readFileSync(new URL(`./${CONTENT_FILE}`, import.meta.url), 'utf8');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.stdout.write(mintSelfCertifiedBundle(readContentFile()));
}
