// `sign` (typedstandards#109 G0 D3): an envelope input in, a signed record out,
// verified offline before anything is printed.

import {
  RAW_BYTES_CANONICALIZATION,
  buildEnvelope,
  deriveKeyDerivedIdentifierFromKey,
  sha256Hex,
  signEnvelopeHash,
  type BlobRef,
  type EnvelopeInput,
} from '@typedstandards/produce-core';
import { CliError, EXIT, usageError } from './errors.ts';
import { checkEnvelopeInput, isObject, readBytes, readJson, type JsonObject } from './input.ts';
import type { Io } from './io.ts';
import { readSeed } from './seed.ts';
import { checkSignedDocument, failureSummary, reportVerdict, verifyOffline } from './verify.ts';

export const SIGN_OPTIONS = {
  input: { type: 'string' },
  'output-file': { type: 'string' },
  'output-url': { type: 'string' },
  'content-type': { type: 'string' },
} as const;

export interface SignValues {
  input?: string;
  'output-file'?: string;
  'output-url'?: string;
  'content-type'?: string;
}

/**
 * The file's bytes as `output`: inline UTF-8 text under raw-bytes/v1, or, when a
 * URL is given, a BlobRef to them under the input's own rule. produce-core 0.7.0
 * computes a raw-bytes/v1 content hash only over an inline string ("raw-bytes/v1
 * content hash over a package alone requires an inline string output"), so a
 * referenced file is covered by the rule that fingerprints the envelope, which
 * carries the BlobRef and with it the file's SHA-256.
 */
function outputFromFile(io: Io, values: SignValues, input: JsonObject): { output: string | BlobRef; bytes: Uint8Array; inline: boolean } {
  const path = values['output-file'] as string;
  const url = values['output-url'];
  const rule = input['contentCanonicalization'];
  if (url !== undefined) {
    if (rule === RAW_BYTES_CANONICALIZATION) {
      throw usageError(
        `a file signed by reference with --output-url cannot use ${RAW_BYTES_CANONICALIZATION}: produce-core computes that rule only over inline text. ` +
          'Omit contentCanonicalization, or sign the file inline without --output-url',
      );
    }
    const bytes = readBytes(io, path, '--output-file');
    return {
      output: { ref: `blob:sha256:${sha256Hex(bytes)}`, url, contentType: values['content-type'] ?? 'application/octet-stream', size: bytes.length },
      bytes,
      inline: false,
    };
  }
  if (typeof input['type'] !== 'string') {
    throw usageError('--output-file signs the file inline under raw-bytes/v1, which needs a v0.1 envelope, and the input has no type');
  }
  if (rule !== undefined && rule !== RAW_BYTES_CANONICALIZATION) {
    throw usageError(`--output-file signs the file inline under ${RAW_BYTES_CANONICALIZATION}, and the input names ${String(rule)}`);
  }
  const bytes = readBytes(io, path, '--output-file');
  let text: string;
  try {
    // ignoreBOM keeps a byte-order mark as text, so it stays in what is signed.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw usageError(`--output-file ${path} is not UTF-8 text, so it cannot be signed inline; sign it by reference with --output-url`);
  }
  if (sha256Hex(new TextEncoder().encode(text)) !== sha256Hex(bytes)) {
    throw usageError(`--output-file ${path} does not survive a UTF-8 round trip; sign it by reference with --output-url`);
  }
  return { output: text, bytes, inline: true };
}

export async function signCommand(values: SignValues, io: Io): Promise<JsonObject> {
  if (values.input === undefined) throw usageError('--input is required: the envelope input as JSON, or - for standard input');
  if (values['output-url'] !== undefined && values['output-file'] === undefined) {
    throw usageError('--output-url names where the bytes of --output-file are served; give --output-file too');
  }
  if (values['content-type'] !== undefined && values['output-url'] === undefined) {
    throw usageError('--content-type describes the BlobRef --output-url makes; give --output-url too');
  }
  const input = checkEnvelopeInput(readJson(io, values.input, '--input'), values['output-file'] !== undefined);
  for (const key of ['packageId', 'createdAt', 'signingKeyId']) {
    if (input[key] === '') throw usageError(`${key} must not be empty; omit it to have it filled`);
  }
  const fromFile = values['output-file'] !== undefined ? outputFromFile(io, values, input) : undefined;
  const local = new Map<string, Uint8Array>();
  if (fromFile && !fromFile.inline) local.set((fromFile.output as BlobRef).url, fromFile.bytes);

  const seed = readSeed(io.env);
  let printed: JsonObject;
  try {
    // Filled from the seed only when absent (G0 D3): the key-derived identifier
    // names the key in metadata.signingKeyId, the kid and signer.identifier.
    const identifier = deriveKeyDerivedIdentifierFromKey(seed);
    const signer = input['signer'];
    const filled = {
      ...input,
      packageId: input['packageId'] ?? io.uuid(),
      createdAt: input['createdAt'] ?? io.now().toISOString(),
      signingKeyId: input['signingKeyId'] ?? identifier,
      ...(isObject(signer) && !('identifier' in signer) ? { signer: { ...signer, identifier } } : {}),
      ...(fromFile ? { output: fromFile.output } : {}),
      ...(fromFile?.inline ? { contentCanonicalization: RAW_BYTES_CANONICALIZATION } : {}),
    } as unknown as EnvelopeInput;
    let built: ReturnType<typeof buildEnvelope>;
    try {
      built = buildEnvelope(filled);
    } catch (err) {
      throw usageError(`produce-core could not build the envelope: ${(err as Error).message}`);
    }
    const signature = signEnvelopeHash(built.envelopeHash, seed, filled.signingKeyId);
    // What is printed is what is verified: the JSON round trip drops the
    // undefined keys buildEnvelope leaves, exactly as printing does.
    printed = JSON.parse(JSON.stringify({ package: built.pkg, envelopeHash: built.envelopeHash, signature })) as JsonObject;
  } finally {
    seed.fill(0);
  }

  const signed = checkSignedDocument(printed, 'the signed record');
  const verdict = await verifyOffline(io, { package: signed.package, packageHash: signed.envelopeHash, signature: signed.signature, carried: [], local });
  const verified =
    verdict.ok &&
    verdict.checks.envelopeIntegrity.status === 'verified' &&
    verdict.checks.signatureValid === true &&
    verdict.nodeId === signed.envelopeHash;
  if (!verified) {
    reportVerdict(io, 'sign', verdict);
    throw new CliError(EXIT.verificationFailed, `the signed record did not verify offline, so nothing was printed: ${failureSummary(verdict)}`);
  }
  reportVerdict(io, 'sign', verdict);
  return printed;
}
