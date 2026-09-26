// Reading and checking the commands' JSON inputs (typedstandards#109 G0 D3).
//
// produce-core's `buildEnvelope` copies only the input keys it names, and rebuilds
// `queries[]`, `cost` and `skillMetadata` key by key, so an unknown key there is
// dropped from what is signed with no error (envelope.ts:279-345 at 0bb0527). The
// CLI refuses such a key instead of signing without it. The field tables below are
// checked against produce-core's input types at compile time, in both directions.

import {
  ATTESTATION_WITHDRAWS,
  isBlobRef,
  type AttestationInput,
  type EnvelopeCost,
  type EnvelopeInput,
  type EnvelopeQuery,
  type SkillMetadata,
} from '@typedstandards/produce-core';
import { usageError } from './errors.ts';
import type { Io } from './io.ts';

type Kind = 'string' | 'number' | 'boolean' | 'object' | 'array' | 'string|BlobRef';

const ENVELOPE_FIELDS = {
  packageId: 'string',
  createdAt: 'string',
  signingKeyId: 'string',
  prompt: 'string',
  promptVisibility: 'string',
  queries: 'array',
  dataSources: 'array',
  cost: 'object',
  skillMetadata: 'object',
  output: 'string|BlobRef',
  trace: 'object',
  summary: 'string',
  captureMethod: 'string',
  contentProfile: 'string',
  producerProfile: 'string',
  type: 'string',
  signer: 'object',
  contentCanonicalization: 'string',
  provenance: 'object',
  extensions: 'object',
} as const satisfies Record<keyof EnvelopeInput, Kind>;

const QUERY_FIELDS = {
  tool: 'string',
  operationType: 'string',
  arguments: 'object',
  datasetId: 'string',
  portal: 'string',
  duration_ms: 'number',
  resultRows: 'number',
  resultColumns: 'number',
  failed: 'boolean',
  failureKind: 'string',
} as const satisfies Record<keyof EnvelopeQuery, Kind>;

const COST_FIELDS = {
  promptTokens: 'number',
  completionTokens: 'number',
  totalTokens: 'number',
  model: 'string',
  durationMs: 'number',
} as const satisfies Record<keyof EnvelopeCost, Kind>;

const SKILL_METADATA_FIELDS = {
  systemPromptHash: 'string',
  mcpServerUrl: 'string',
  skillText: 'string|BlobRef',
} as const satisfies Record<keyof SkillMetadata, Kind>;

const WITHDRAW_FIELDS = {
  packageId: 'string',
  createdAt: 'string',
  signingKeyId: 'string',
  type: 'string',
  targetNodeId: 'string',
  signer: 'object',
  reason: 'string',
  effectiveAt: 'string',
} as const satisfies Partial<Record<keyof AttestationInput, Kind>>;

// A JSON object: not null, not an array.
export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasKind(value: unknown, kind: Kind): boolean {
  switch (kind) {
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'object':
      return isObject(value);
    case 'array':
      return Array.isArray(value);
    case 'string|BlobRef':
      return typeof value === 'string' || isBlobRef(value);
  }
}

const KIND_WORDS: Record<Kind, string> = {
  string: 'a string',
  number: 'a finite number',
  boolean: 'true or false',
  object: 'an object',
  array: 'an array',
  'string|BlobRef': 'a string or a BlobRef',
};

/** Refuse a key the table does not name, a value of the wrong kind (null included), and a missing required key. */
function checkFields(
  value: JsonObject,
  fields: Readonly<Record<string, Kind>>,
  required: readonly string[],
  where: string,
  what: string,
): void {
  for (const [key, v] of Object.entries(value)) {
    const kind = fields[key];
    if (kind === undefined) {
      throw usageError(`${where}${key} is not a field of ${what}, so it would not be signed; remove it`);
    }
    if (!hasKind(v, kind)) throw usageError(`${where}${key} must be ${KIND_WORDS[kind]}`);
  }
  for (const key of required) {
    if (!(key in value)) throw usageError(`${where}${key} is required`);
  }
}

function checkSigner(signer: JsonObject, where: string): void {
  for (const key of ['bindingTier', 'displayName']) {
    if (typeof signer[key] !== 'string') throw usageError(`${where}signer.${key} must be a string`);
  }
  for (const key of ['identifier', 'verifiedAt']) {
    if (key in signer && typeof signer[key] !== 'string') throw usageError(`${where}signer.${key} must be a string`);
  }
}

/** Check an envelope input; `outputFromFile` when `--output-file` supplies `output`. */
export function checkEnvelopeInput(value: unknown, outputFromFile: boolean): JsonObject {
  if (!isObject(value)) throw usageError('the input must be a JSON object: the envelope input produce-core\'s buildEnvelope takes');
  if ('vcsRef' in value) {
    throw usageError(
      'vcsRef is not supported yet: produce-core 0.7.0 has no vcsRef field, so it would not be signed. ' +
        'It arrives with a produce-core minor (typedstandards#109); do not carry it in extensions meanwhile',
    );
  }
  const required = ['prompt', 'promptVisibility', 'queries', 'dataSources', 'cost', 'skillMetadata', 'trace'];
  checkFields(value, ENVELOPE_FIELDS, outputFromFile ? required : [...required, 'output'], '', 'the envelope input');
  if (outputFromFile && 'output' in value) {
    throw usageError('the input has an output and --output-file supplies another; give one');
  }
  if (value['promptVisibility'] !== 'full_text' && value['promptVisibility'] !== 'hash_only') {
    throw usageError('promptVisibility must be "full_text" or "hash_only"');
  }
  (value['queries'] as unknown[]).forEach((q, i) => {
    if (!isObject(q)) throw usageError(`queries[${i}] must be an object`);
    checkFields(q, QUERY_FIELDS, ['tool', 'operationType', 'arguments'], `queries[${i}].`, 'a query');
  });
  (value['dataSources'] as unknown[]).forEach((d, i) => {
    if (!isObject(d)) throw usageError(`dataSources[${i}] must be an object`);
  });
  checkFields(value['cost'] as JsonObject, COST_FIELDS, ['model'], 'cost.', 'cost');
  checkFields(value['skillMetadata'] as JsonObject, SKILL_METADATA_FIELDS, [], 'skillMetadata.', 'skillMetadata');
  if ('signer' in value) checkSigner(value['signer'] as JsonObject, '');
  return value;
}

/** Check a withdrawal input: the fields of an attestation/withdraws/v1 produce-core takes. */
export function checkWithdrawInput(value: unknown): JsonObject {
  if (!isObject(value)) throw usageError('the input must be a JSON object naming targetNodeId, reason and signer');
  checkFields(value, WITHDRAW_FIELDS, ['targetNodeId', 'reason', 'signer'], '', 'a withdrawal');
  if ('type' in value && value['type'] !== ATTESTATION_WITHDRAWS) {
    throw usageError(`type must be ${ATTESTATION_WITHDRAWS} when present; withdraw signs nothing else`);
  }
  if (!/^[0-9a-f]{64}$/.test(value['targetNodeId'] as string)) {
    throw usageError('targetNodeId must be a record\'s envelope hash: 64 lowercase hex characters');
  }
  if ((value['reason'] as string).trim() === '') throw usageError('reason must not be empty');
  checkSigner(value['signer'] as JsonObject, '');
  return value;
}

/** A file's bytes, or a usage error naming the flag. */
export function readBytes(io: Io, path: string, flag: string): Uint8Array {
  try {
    return io.readFile(path);
  } catch (err) {
    throw usageError(`${flag} ${path} cannot be read: ${(err as Error).message}`);
  }
}

/** A JSON file's value, or a usage error naming the flag. */
export function readJson(io: Io, path: string, flag: string): unknown {
  const bytes = readBytes(io, path, flag);
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw usageError(`${flag} ${path} is not UTF-8 text`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (err) {
    throw usageError(`${flag} ${path} is not JSON: ${(err as Error).message}`);
  }
}
