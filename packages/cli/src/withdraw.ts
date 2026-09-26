// `withdraw` (typedstandards#109 G0 D3): an attestation/withdraws/v1 for a target
// record, signed with the same key path as `sign`. A correction is a withdrawal
// plus a new record.

import {
  ATTESTATION_WITHDRAWS,
  buildAttestationNode,
  deriveKeyDerivedIdentifierFromKey,
  signEnvelopeHash,
  type AttestationInput,
} from '@typedstandards/produce-core';
import { verifyAttestationNode, verifyLifecycleChain } from '@typedstandards/verify-core';
import { CliError, EXIT, usageError } from './errors.ts';
import { checkWithdrawInput, readJson, type JsonObject } from './input.ts';
import type { Io } from './io.ts';
import { readSeed } from './seed.ts';
import { checkCarriedNode } from './verify.ts';

export const WITHDRAW_OPTIONS = {
  input: { type: 'string' },
} as const;

export interface WithdrawValues {
  input?: string;
}

export async function withdrawCommand(values: WithdrawValues, io: Io): Promise<JsonObject> {
  if (values.input === undefined) throw usageError('--input is required: targetNodeId, reason and signer as JSON, or - for standard input');
  const input = checkWithdrawInput(readJson(io, values.input, '--input'));
  for (const key of ['packageId', 'createdAt', 'signingKeyId']) {
    if (input[key] === '') throw usageError(`${key} must not be empty; omit it to have it filled`);
  }

  const seed = readSeed(io.env);
  let printed: JsonObject;
  try {
    const identifier = deriveKeyDerivedIdentifierFromKey(seed);
    const signer = input['signer'] as JsonObject;
    const filled = {
      ...input,
      type: ATTESTATION_WITHDRAWS,
      packageId: input['packageId'] ?? io.uuid(),
      createdAt: input['createdAt'] ?? io.now().toISOString(),
      signingKeyId: input['signingKeyId'] ?? identifier,
      signer: 'identifier' in signer ? signer : { ...signer, identifier },
    } as unknown as AttestationInput;
    const { node, nodeId } = buildAttestationNode(filled);
    const signature = signEnvelopeHash(nodeId, seed, filled.signingKeyId);
    printed = JSON.parse(JSON.stringify({ node, nodeId, signature })) as JsonObject;
  } finally {
    seed.fill(0);
  }

  // Before printing: the node recomputes to its id, the signature verifies, and a
  // record carrying it reads withdrawn under verify-core's lifecycle resolution.
  const carried = checkCarriedNode(printed, 'the signed withdrawal');
  const check = verifyAttestationNode(carried.node, carried.nodeId, carried.signature ?? null);
  const target = carried.node['targetNodeId'] as string;
  const signerId = (carried.node['signer'] as { identifier: string }).identifier;
  const life = verifyLifecycleChain([carried], target, signerId);
  if (!check.nodeIdMatches || check.signatureValid !== true || life.status !== 'withdrawn' || life.chain.length !== 1) {
    throw new CliError(
      EXIT.verificationFailed,
      `the signed withdrawal did not verify offline, so nothing was printed: nodeId ${check.nodeIdMatches ? 'matches' : 'does not match'}, ` +
        `signature ${String(check.signatureValid)}, lifecycle ${life.status}`,
    );
  }
  return printed;
}
